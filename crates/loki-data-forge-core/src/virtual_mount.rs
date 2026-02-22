use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{LokiDataForgeError, Result};
use crate::models::{ContainerType, VirtualContainer, VirtualEntry};
use crate::parsers::vpk::parse_vpk_entries;

pub fn detect_container(path: &Path) -> Result<ContainerType> {
    let mut f = File::open(path)?;
    let mut header = vec![0u8; 1024 * 1024];
    let read = f.read(&mut header)?;
    header.truncate(read);

    if header.len() >= 4 && &header[..4] == b"KDMV" {
        return Ok(ContainerType::Vmdk);
    }
    if header.len() >= 8 && &header[..8] == b"vhdxfile" {
        return Ok(ContainerType::Vhdx);
    }
    if header.len() >= 4 && &header[..4] == b"QFI\xfb" {
        return Ok(ContainerType::Qcow2);
    }
    if header.len() >= 4
        && u32::from_le_bytes([header[0], header[1], header[2], header[3]]) == 0x55AA1234
    {
        return Ok(ContainerType::Vpk);
    }
    if header.len() >= 8 && &header[..8] == b"MSWIM\0\0\0" {
        return Ok(ContainerType::Wim);
    }

    if header.len() > 265 && &header[257..262] == b"ustar" {
        // OVA is a TAR that typically includes .ovf + disk blobs.
        return Ok(ContainerType::Ova);
    }

    if header.len() > 0x80
        && header
            .windows(46)
            .any(|w| w == b"<<< Oracle VM VirtualBox Disk Image >>>")
    {
        return Ok(ContainerType::Vdi);
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if ext == "vmdk" {
        return Ok(ContainerType::Vmdk);
    }
    if ext == "vhdx" {
        return Ok(ContainerType::Vhdx);
    }
    if ext == "vhd" {
        return Ok(ContainerType::Vhd);
    }
    if ext == "qcow2" {
        return Ok(ContainerType::Qcow2);
    }
    if ext == "vdi" {
        return Ok(ContainerType::Vdi);
    }
    if ext == "ova" {
        return Ok(ContainerType::Ova);
    }
    if ext == "vpk" {
        return Ok(ContainerType::Vpk);
    }
    if ext == "wim" {
        return Ok(ContainerType::Wim);
    }
    if ext == "tib" {
        return Ok(ContainerType::AcronisTib);
    }
    if ext == "tibx" {
        return Ok(ContainerType::AcronisTibx);
    }
    if ext == "bak" {
        return Ok(ContainerType::Bak);
    }
    if ext == "sql" || ext == "dump" {
        return Ok(ContainerType::SqlDump);
    }
    if ["zip", "7z", "rar", "tar", "gz", "bz2", "xz"].contains(&ext.as_str()) {
        return Ok(ContainerType::Archive);
    }

    // VHD footer is typically 512 bytes from EOF.
    if f.seek(SeekFrom::End(-512)).is_ok() {
        let mut footer = [0u8; 8];
        if f.read_exact(&mut footer).is_ok() && &footer == b"conectix" {
            return Ok(ContainerType::Vhd);
        }
    }

    Ok(ContainerType::Unknown)
}

pub fn mount_container(path: &Path) -> Result<VirtualContainer> {
    let kind = detect_container(path)?;

    match kind {
        ContainerType::Vmdk => mount_vmdk(path),
        ContainerType::Vhdx => mount_vhdx(path),
        ContainerType::Vhd => mount_vhd(path),
        ContainerType::Qcow2 => mount_qcow2(path),
        ContainerType::Vdi => mount_vdi(path),
        ContainerType::Ova => mount_ova(path),
        ContainerType::Vpk => mount_vpk(path),
        ContainerType::Archive => mount_archive(path),
        _ => Ok(VirtualContainer {
            source: path.to_path_buf(),
            container_type: kind,
            entries: vec![VirtualEntry {
                name: path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("container")
                    .to_string(),
                path_hint: Some(path.to_path_buf()),
                offset: 0,
                size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                encrypted: false,
                archive_index: None,
            }],
            descriptor: Some("Container detected (TODO: parser expansion)".to_string()),
        }),
    }
}

fn mount_vmdk(path: &Path) -> Result<VirtualContainer> {
    let content = std::fs::read(path)?;

    if content.starts_with(b"KDMV") {
        return Ok(VirtualContainer {
            source: path.to_path_buf(),
            container_type: ContainerType::Vmdk,
            entries: vec![VirtualEntry {
                name: path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("disk.vmdk")
                    .to_string(),
                path_hint: Some(path.to_path_buf()),
                offset: 0,
                size: content.len() as u64,
                encrypted: false,
                archive_index: None,
            }],
            descriptor: Some("Sparse VMDK detected via KDMV magic".to_string()),
        });
    }

    let descriptor = String::from_utf8_lossy(&content).to_string();
    if !descriptor.contains("Disk DescriptorFile") && !descriptor.contains("createType") {
        return Err(LokiDataForgeError::ContainerParse(
            "VMDK descriptor not found".to_string(),
        ));
    }

    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut entries = Vec::new();

    for line in descriptor.lines() {
        let line = line.trim();
        if line.starts_with("RW ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let sectors = parts[1].parse::<u64>().unwrap_or(0);
                let extent_path = parts[3].trim_matches('"');
                let mut resolved = PathBuf::from(extent_path);
                if resolved.is_relative() {
                    resolved = base_dir.join(resolved);
                }

                entries.push(VirtualEntry {
                    name: extent_path.to_string(),
                    path_hint: Some(resolved),
                    offset: 0,
                    size: sectors.saturating_mul(512),
                    encrypted: false,
                    archive_index: None,
                });
            }
        }
    }

    if entries.is_empty() {
        entries.push(VirtualEntry {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("disk.vmdk")
                .to_string(),
            path_hint: Some(path.to_path_buf()),
            offset: 0,
            size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            encrypted: false,
            archive_index: None,
        });
    }

    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Vmdk,
        entries,
        descriptor: Some(descriptor),
    })
}

fn mount_ova(path: &Path) -> Result<VirtualContainer> {
    let f = File::open(path)?;
    let mut archive = tar::Archive::new(f);
    let mut entries = Vec::new();

    for item in archive.entries()? {
        let file = item?;
        let p = file.path()?.to_string_lossy().to_string();
        let size = file.header().size().unwrap_or(0);

        entries.push(VirtualEntry {
            name: p,
            path_hint: None,
            offset: 0,
            size,
            encrypted: false,
            archive_index: None,
        });
    }

    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Ova,
        entries,
        descriptor: Some("OVA tar entries enumerated".to_string()),
    })
}

fn mount_vpk(path: &Path) -> Result<VirtualContainer> {
    let entries = parse_vpk_entries(path)?;

    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Vpk,
        entries,
        descriptor: Some("Valve Pak v1/v2 tree parsed".to_string()),
    })
}

fn mount_vhdx(path: &Path) -> Result<VirtualContainer> {
    let mut f = File::open(path)?;
    let mut hdr = [0u8; 4096];
    f.read_exact(&mut hdr)?;

    if &hdr[..8] != b"vhdxfile" {
        return Err(LokiDataForgeError::ContainerParse(
            "invalid VHDX signature".to_string(),
        ));
    }

    let creator_raw = &hdr[8..520];
    let creator_utf16 = creator_raw
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|c| *c != 0)
        .collect::<Vec<_>>();
    let creator = String::from_utf16(&creator_utf16).unwrap_or_else(|_| "unknown".to_string());

    let size = std::fs::metadata(path)?.len();
    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Vhdx,
        entries: vec![VirtualEntry {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("disk.vhdx")
                .to_string(),
            path_hint: Some(path.to_path_buf()),
            offset: 0,
            size,
            encrypted: false,
            archive_index: None,
        }],
        descriptor: Some(format!("VHDX container detected, creator={creator}")),
    })
}

fn mount_vhd(path: &Path) -> Result<VirtualContainer> {
    let mut f = File::open(path)?;
    let file_size = std::fs::metadata(path)?.len();
    if file_size < 512 {
        return Err(LokiDataForgeError::ContainerParse(
            "VHD file too small".to_string(),
        ));
    }

    f.seek(SeekFrom::End(-512))?;
    let mut footer = [0u8; 512];
    f.read_exact(&mut footer)?;
    if &footer[..8] != b"conectix" {
        return Err(LokiDataForgeError::ContainerParse(
            "VHD footer not found".to_string(),
        ));
    }

    let current_size = u64::from_be_bytes([
        footer[48], footer[49], footer[50], footer[51], footer[52], footer[53], footer[54],
        footer[55],
    ]);

    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Vhd,
        entries: vec![VirtualEntry {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("disk.vhd")
                .to_string(),
            path_hint: Some(path.to_path_buf()),
            offset: 0,
            size: file_size,
            encrypted: false,
            archive_index: None,
        }],
        descriptor: Some(format!(
            "VHD footer parsed, virtual_size={current_size} bytes"
        )),
    })
}

fn mount_qcow2(path: &Path) -> Result<VirtualContainer> {
    let mut f = File::open(path)?;
    let mut hdr = [0u8; 72];
    f.read_exact(&mut hdr)?;
    if &hdr[..4] != b"QFI\xfb" {
        return Err(LokiDataForgeError::ContainerParse(
            "invalid QCOW2 signature".to_string(),
        ));
    }

    let version = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let backing_file_offset = u64::from_be_bytes([
        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
    ]);
    let backing_file_size = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
    let virtual_size = u64::from_be_bytes([
        hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31],
    ]);

    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Qcow2,
        entries: vec![VirtualEntry {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("disk.qcow2")
                .to_string(),
            path_hint: Some(path.to_path_buf()),
            offset: 0,
            size: virtual_size.max(std::fs::metadata(path)?.len()),
            encrypted: false,
            archive_index: None,
        }],
        descriptor: Some(format!(
            "QCOW2 header parsed, version={version}, backing_file_offset={backing_file_offset}, backing_file_size={backing_file_size}, virtual_size={virtual_size}"
        )),
    })
}

fn mount_vdi(path: &Path) -> Result<VirtualContainer> {
    let mut f = File::open(path)?;
    let mut hdr = vec![0u8; 512];
    f.read_exact(&mut hdr)?;

    if !hdr
        .windows(46)
        .any(|w| w == b"<<< Oracle VM VirtualBox Disk Image >>>")
    {
        return Err(LokiDataForgeError::ContainerParse(
            "invalid VDI marker".to_string(),
        ));
    }

    // VDI 1.1 header fields
    let header_size = u32::from_le_bytes([hdr[0x40], hdr[0x41], hdr[0x42], hdr[0x43]]);
    let image_type = u32::from_le_bytes([hdr[0x4c], hdr[0x4d], hdr[0x4e], hdr[0x4f]]);

    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Vdi,
        entries: vec![VirtualEntry {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("disk.vdi")
                .to_string(),
            path_hint: Some(path.to_path_buf()),
            offset: 0,
            size: std::fs::metadata(path)?.len(),
            encrypted: false,
            archive_index: None,
        }],
        descriptor: Some(format!(
            "VDI header parsed, header_size={header_size}, image_type={image_type}"
        )),
    })
}

fn mount_archive(path: &Path) -> Result<VirtualContainer> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if ext == "zip" {
        let f = File::open(path)?;
        let mut archive = zip::ZipArchive::new(f)
            .map_err(|e| LokiDataForgeError::ContainerParse(format!("ZIP open failed: {e}")))?;
        let mut entries = Vec::new();
        for i in 0..archive.len() {
            let file = archive.by_index(i).map_err(|e| {
                LokiDataForgeError::ContainerParse(format!("ZIP entry read failed: {e}"))
            })?;
            entries.push(VirtualEntry {
                name: file.name().to_string(),
                path_hint: None,
                offset: file.data_start(),
                size: file.size(),
                encrypted: file.encrypted(),
                archive_index: None,
            });
        }

        return Ok(VirtualContainer {
            source: path.to_path_buf(),
            container_type: ContainerType::Archive,
            entries,
            descriptor: Some("ZIP archive entries enumerated".to_string()),
        });
    }

    if ["tar", "ova"].contains(&ext.as_str()) {
        let f = File::open(path)?;
        let mut archive = tar::Archive::new(f);
        let mut entries = Vec::new();
        for item in archive.entries()? {
            let file = item?;
            let p = file.path()?.to_string_lossy().to_string();
            let size = file.header().size().unwrap_or(0);

            entries.push(VirtualEntry {
                name: p,
                path_hint: None,
                offset: 0,
                size,
                encrypted: false,
                archive_index: None,
            });
        }

        return Ok(VirtualContainer {
            source: path.to_path_buf(),
            container_type: ContainerType::Archive,
            entries,
            descriptor: Some("TAR archive entries enumerated".to_string()),
        });
    }

    Ok(VirtualContainer {
        source: path.to_path_buf(),
        container_type: ContainerType::Archive,
        entries: vec![VirtualEntry {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("archive")
                .to_string(),
            path_hint: Some(path.to_path_buf()),
            offset: 0,
            size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            encrypted: false,
            archive_index: None,
        }],
        descriptor: Some("Archive detected (TODO: add parser for this extension)".to_string()),
    })
}
