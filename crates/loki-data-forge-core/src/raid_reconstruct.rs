use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{LokiDataForgeError, Result};
use crate::raid::{RaidMode, RaidParityLayout};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidReconstructOptions {
    pub mode: RaidMode,
    pub stripe_size: u64,
    pub members: Vec<Option<PathBuf>>,
    pub output: PathBuf,
    pub parity_layout: RaidParityLayout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidReconstructReport {
    pub mode: RaidMode,
    pub output: PathBuf,
    pub bytes_written: u64,
    pub reconstructed_missing_members: usize,
}

pub fn reconstruct_array(options: &RaidReconstructOptions) -> Result<RaidReconstructReport> {
    if options.members.is_empty() {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "RAID reconstruction requires at least one member".to_string(),
        ));
    }
    if options.stripe_size == 0 {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "stripe_size must be greater than zero".to_string(),
        ));
    }

    let mut output = std::fs::File::create(&options.output)?;

    let bytes_written = match options.mode {
        RaidMode::Raid0 => reconstruct_raid0(options, &mut output)?,
        RaidMode::Raid1 => reconstruct_raid1(options, &mut output)?,
        RaidMode::Raid5 => reconstruct_raid5(options, &mut output)?,
        _ => {
            return Err(LokiDataForgeError::UnsupportedFormat(format!(
                "RAID reconstruction mode not implemented: {:?}",
                options.mode
            )));
        }
    };

    let reconstructed_missing_members = options.members.iter().filter(|m| m.is_none()).count();

    Ok(RaidReconstructReport {
        mode: options.mode,
        output: options.output.clone(),
        bytes_written,
        reconstructed_missing_members,
    })
}

fn reconstruct_raid0(options: &RaidReconstructOptions, out: &mut std::fs::File) -> Result<u64> {
    let mut members = open_members(&options.members)?;
    if members.is_empty() {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "RAID0 requires at least one available member".to_string(),
        ));
    }

    let stripe = options.stripe_size as usize;
    let min_len = members
        .iter()
        .filter_map(|f| f.as_ref())
        .filter_map(|f| f.metadata().ok().map(|m| m.len()))
        .min()
        .unwrap_or(0);

    let mut offset = 0u64;
    let mut written = 0u64;
    while offset < min_len {
        for member in &mut members {
            if let Some(file) = member {
                let to_read = (min_len - offset).min(options.stripe_size) as usize;
                if to_read == 0 {
                    continue;
                }
                let mut buf = vec![0u8; to_read];
                file.seek(SeekFrom::Start(offset))?;
                let read = file.read(&mut buf)?;
                if read == 0 {
                    continue;
                }
                out.write_all(&buf[..read])?;
                written += read as u64;
            }
        }
        offset += stripe as u64;
    }

    Ok(written)
}

fn reconstruct_raid1(options: &RaidReconstructOptions, out: &mut std::fs::File) -> Result<u64> {
    let mut members = open_members(&options.members)?;
    let Some(Some(primary)) = members.iter_mut().find(|m| m.is_some()) else {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "RAID1 requires at least one available member".to_string(),
        ));
    };

    primary.seek(SeekFrom::Start(0))?;
    let mut written = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = primary.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        written += n as u64;
    }

    Ok(written)
}

fn reconstruct_raid5(options: &RaidReconstructOptions, out: &mut std::fs::File) -> Result<u64> {
    let disk_count = options.members.len();
    if disk_count < 3 {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "RAID5 requires at least 3 members".to_string(),
        ));
    }

    let missing = options.members.iter().filter(|m| m.is_none()).count();
    if missing > 1 {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "RAID5 reconstruction supports at most one missing member".to_string(),
        ));
    }

    let mut members = open_members(&options.members)?;
    let min_len = members
        .iter()
        .filter_map(|f| f.as_ref())
        .filter_map(|f| f.metadata().ok().map(|m| m.len()))
        .min()
        .unwrap_or(0);

    let stripe = options.stripe_size;
    let stripes = if stripe == 0 { 0 } else { min_len / stripe };
    let mut written = 0u64;

    for stripe_idx in 0..stripes {
        let parity_disk = parity_disk_index(stripe_idx, disk_count, options.parity_layout);
        let data_order = (1..disk_count)
            .map(|k| (parity_disk + k) % disk_count)
            .collect::<Vec<_>>();

        let mut stripe_chunks = Vec::with_capacity(disk_count);
        for disk_idx in 0..disk_count {
            stripe_chunks.push(read_stripe(members[disk_idx].as_mut(), stripe_idx, stripe)?);
        }

        let missing_disk = stripe_chunks.iter().position(|chunk| chunk.is_none());
        if let Some(missing_idx) = missing_disk {
            let recovered = xor_reconstruct_missing(&stripe_chunks, stripe as usize)?;
            stripe_chunks[missing_idx] = Some(recovered);
        }

        for disk_idx in data_order {
            if let Some(chunk) = &stripe_chunks[disk_idx] {
                out.write_all(chunk)?;
                written += chunk.len() as u64;
            }
        }
    }

    Ok(written)
}

fn open_members(members: &[Option<PathBuf>]) -> Result<Vec<Option<std::fs::File>>> {
    let mut files = Vec::with_capacity(members.len());
    for member in members {
        if let Some(path) = member {
            files.push(Some(std::fs::File::open(path)?));
        } else {
            files.push(None);
        }
    }
    Ok(files)
}

fn read_stripe(
    file: Option<&mut std::fs::File>,
    stripe_index: u64,
    stripe_size: u64,
) -> Result<Option<Vec<u8>>> {
    let Some(file) = file else {
        return Ok(None);
    };

    let offset = stripe_index.saturating_mul(stripe_size);
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; stripe_size as usize];
    let read = file.read(&mut buf)?;
    if read == 0 {
        return Ok(Some(Vec::new()));
    }
    buf.truncate(read);
    Ok(Some(buf))
}

fn xor_reconstruct_missing(chunks: &[Option<Vec<u8>>], stripe_size: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; stripe_size];
    let mut present = 0usize;

    for chunk in chunks {
        let Some(chunk) = chunk else {
            continue;
        };
        present += 1;
        for (i, b) in chunk.iter().enumerate() {
            out[i] ^= *b;
        }
    }

    if present + 1 < chunks.len() {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "cannot reconstruct missing RAID5 member with multiple unavailable chunks".to_string(),
        ));
    }

    Ok(out)
}

fn parity_disk_index(stripe_idx: u64, disk_count: usize, layout: RaidParityLayout) -> usize {
    match layout {
        RaidParityLayout::RightSymmetric | RaidParityLayout::RightAsymmetric => {
            (stripe_idx as usize) % disk_count
        }
        RaidParityLayout::LeftSymmetric
        | RaidParityLayout::LeftAsymmetric
        | RaidParityLayout::Unknown => {
            (disk_count - 1usize).wrapping_sub((stripe_idx as usize) % disk_count)
        }
    }
}
