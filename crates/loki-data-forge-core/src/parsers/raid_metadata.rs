use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::Result;

const READ_WINDOW: usize = 8 * 1024 * 1024;
const MDADM_MAGIC_LE: [u8; 4] = [0xfc, 0x4e, 0x2b, 0xa9];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidFamilyHint {
    Mdadm,
    SynologyShr,
    WindowsDynamic,
    WindowsStorageSpaces,
    HardwareDdf,
    AppleRaid,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct RaidMetadataProbe {
    pub path: PathBuf,
    pub family: RaidFamilyHint,
    pub array_id: Option<String>,
    pub expected_members: Option<usize>,
    pub member_index: Option<usize>,
    pub stripe_size: Option<u64>,
    pub level_code: Option<i32>,
    pub parity_layout_code: Option<u32>,
    pub notes: Vec<String>,
}

impl RaidMetadataProbe {
    fn unknown(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            family: RaidFamilyHint::Unknown,
            array_id: None,
            expected_members: None,
            member_index: None,
            stripe_size: None,
            level_code: None,
            parity_layout_code: None,
            notes: Vec::new(),
        }
    }
}

pub fn probe_raid_metadata(path: &Path) -> Result<RaidMetadataProbe> {
    let mut probe = RaidMetadataProbe::unknown(path);

    let metadata = std::fs::metadata(path)?;
    let mut file = File::open(path)?;

    let mut head = vec![0u8; READ_WINDOW.min(metadata.len() as usize)];
    let mut tail = vec![0u8; READ_WINDOW.min(metadata.len() as usize)];

    if metadata.len() > 0 {
        if !head.is_empty() {
            file.read_exact(&mut head)?;
        }

        if !tail.is_empty() {
            let from = metadata.len().saturating_sub(tail.len() as u64);
            file.seek(SeekFrom::Start(from))?;
            file.read_exact(&mut tail)?;
        }
    } else {
        // Some block devices report size=0 through metadata APIs; read opportunistically.
        head.resize(READ_WINDOW, 0);
        let read = file.read(&mut head)?;
        head.truncate(read);
        tail.clear();
    }

    if let Some(mdadm) = parse_mdadm_superblock(path, &head, &tail) {
        return Ok(mdadm);
    }

    // Signature-based fallbacks for common metadata headers.
    if contains_any(&head, &[b"PRIVHEAD", b"LDM_DATABASE"])
        || contains_any(&tail, &[b"PRIVHEAD", b"LDM_DATABASE"])
    {
        probe.family = RaidFamilyHint::WindowsDynamic;
        probe
            .notes
            .push("Windows Dynamic Disk metadata signature detected".to_string());
        return Ok(probe);
    }

    if contains_any(
        &head,
        &[b"Storage Spaces", b"MSFT Storage Spaces", b"SPACES"],
    ) || contains_any(
        &tail,
        &[b"Storage Spaces", b"MSFT Storage Spaces", b"SPACES"],
    ) {
        probe.family = RaidFamilyHint::WindowsStorageSpaces;
        probe
            .notes
            .push("Windows Storage Spaces metadata signature detected".to_string());
        return Ok(probe);
    }

    if contains_any(&head, &[b"SNIA DDF", b"DDF_Header"])
        || contains_any(&tail, &[b"SNIA DDF", b"DDF_Header"])
    {
        probe.family = RaidFamilyHint::HardwareDdf;
        probe
            .notes
            .push("Hardware DDF metadata signature detected".to_string());
        return Ok(probe);
    }

    if contains_any(&head, &[b"Apple_RAID", b"AppleRAID"])
        || contains_any(&tail, &[b"Apple_RAID", b"AppleRAID"])
    {
        probe.family = RaidFamilyHint::AppleRaid;
        probe
            .notes
            .push("Apple RAID metadata signature detected".to_string());
        return Ok(probe);
    }

    Ok(probe)
}

fn parse_mdadm_superblock(path: &Path, head: &[u8], tail: &[u8]) -> Option<RaidMetadataProbe> {
    // Most common mdadm v1.2 offset
    if let Some(block) = slice_at(head, 4096, 256)
        && block.starts_with(&MDADM_MAGIC_LE)
    {
        return Some(build_mdadm_probe(path, block, true));
    }

    // Fallback: scan windows for magic.
    if let Some((idx, block)) = find_magic_block(head, 256) {
        // Prefer metadata-like offsets (4k alignment) to reduce false positives.
        if idx % 4096 == 0 {
            return Some(build_mdadm_probe(path, block, true));
        }
    }

    if let Some((_idx, block)) = find_magic_block(tail, 256) {
        return Some(build_mdadm_probe(path, block, false));
    }

    None
}

fn build_mdadm_probe(path: &Path, block: &[u8], from_head: bool) -> RaidMetadataProbe {
    let level_code = read_i32_le(block, 0x48);
    let layout = read_u32_le(block, 0x4c);
    let chunk_size = read_u32_le(block, 0x58).map(|v| v as u64 * 1024);
    let raid_disks = read_u32_le(block, 0x5c)
        .map(|v| v as usize)
        .filter(|v| *v > 0);
    let dev_number = read_u32_le(block, 0x90).map(|v| v as usize);

    let set_uuid = block.get(0x10..0x20).map(format_uuid_hex);
    let set_name = block
        .get(0x20..0x40)
        .map(parse_c_string)
        .unwrap_or_default();

    let mut notes = Vec::new();
    notes.push(
        if from_head {
            "mdadm superblock detected in header window"
        } else {
            "mdadm superblock detected in tail window"
        }
        .to_string(),
    );

    if !set_name.is_empty() {
        notes.push(format!("set_name={set_name}"));
    }

    let mut family = RaidFamilyHint::Mdadm;
    if set_name.to_ascii_lowercase().contains("syno")
        || path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("synology")
    {
        family = RaidFamilyHint::SynologyShr;
        notes.push("Synology SHR hint inferred from mdadm metadata".to_string());
    }

    RaidMetadataProbe {
        path: path.to_path_buf(),
        family,
        array_id: set_uuid,
        expected_members: raid_disks,
        member_index: dev_number,
        stripe_size: chunk_size,
        level_code,
        parity_layout_code: layout,
        notes,
    }
}

fn find_magic_block(data: &[u8], block_len: usize) -> Option<(usize, &[u8])> {
    let idx = data
        .windows(MDADM_MAGIC_LE.len())
        .position(|w| w == MDADM_MAGIC_LE)?;
    let end = idx + block_len;
    if end <= data.len() {
        Some((idx, &data[idx..end]))
    } else {
        None
    }
}

fn slice_at(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(len)?;
    if end <= data.len() {
        Some(&data[offset..end])
    } else {
        None
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_i32_le(data: &[u8], offset: usize) -> Option<i32> {
    read_u32_le(data, offset).map(|v| i32::from_le_bytes(v.to_le_bytes()))
}

fn parse_c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn format_uuid_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle))
    })
}
