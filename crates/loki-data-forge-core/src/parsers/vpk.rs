use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{LokiDataForgeError, Result};
use crate::models::VirtualEntry;

#[derive(Debug, Clone)]
pub struct VpkHeader {
    pub signature: u32,
    pub version: u32,
    pub tree_size: u32,
    pub file_data_section_size: Option<u32>,
    pub archive_md5_section_size: Option<u32>,
    pub other_md5_section_size: Option<u32>,
    pub signature_section_size: Option<u32>,
}

pub fn parse_vpk_entries(path: &Path) -> Result<Vec<VirtualEntry>> {
    let mut f = File::open(path)?;
    let header = read_header(&mut f)?;
    if header.signature != 0x55AA1234 {
        return Err(LokiDataForgeError::ContainerParse(
            "invalid VPK signature".to_string(),
        ));
    }
    if header.version != 1 && header.version != 2 {
        return Err(LokiDataForgeError::ContainerParse(format!(
            "unsupported VPK version: {}",
            header.version
        )));
    }

    let tree_start = if header.version == 2 { 28u64 } else { 12u64 };
    let tree_end = tree_start
        .checked_add(header.tree_size as u64)
        .ok_or_else(|| LokiDataForgeError::ContainerParse("VPK tree size overflow".to_string()))?;
    let embedded_data_base = tree_end;
    f.seek(SeekFrom::Start(tree_start))?;

    let mut cursor = tree_start;
    let mut entries = Vec::new();

    while cursor < tree_end {
        let extension = read_cstring(&mut f)?;
        cursor += (extension.len() + 1) as u64;
        if extension.is_empty() {
            break;
        }

        loop {
            let path_part = read_cstring(&mut f)?;
            cursor += (path_part.len() + 1) as u64;
            if path_part.is_empty() {
                break;
            }

            loop {
                let filename = read_cstring(&mut f)?;
                cursor += (filename.len() + 1) as u64;
                if filename.is_empty() {
                    break;
                }

                let mut meta = [0u8; 18];
                f.read_exact(&mut meta)?;
                cursor += 18;

                let _crc = u32::from_le_bytes([meta[0], meta[1], meta[2], meta[3]]);
                let preload_bytes = u16::from_le_bytes([meta[4], meta[5]]);
                let archive_index = u16::from_le_bytes([meta[6], meta[7]]);
                let entry_offset = u32::from_le_bytes([meta[8], meta[9], meta[10], meta[11]]);
                let entry_length = u32::from_le_bytes([meta[12], meta[13], meta[14], meta[15]]);
                let terminator = u16::from_le_bytes([meta[16], meta[17]]);

                if terminator != 0xFFFF {
                    return Err(LokiDataForgeError::ContainerParse(
                        "invalid VPK entry terminator".to_string(),
                    ));
                }

                if preload_bytes > 0 {
                    f.seek(SeekFrom::Current(preload_bytes as i64))?;
                    cursor += preload_bytes as u64;
                }

                let normalized_path = if path_part == " " {
                    String::new()
                } else {
                    path_part.clone()
                };

                let full_name = if normalized_path.is_empty() {
                    format!("{filename}.{extension}")
                } else {
                    format!("{normalized_path}/{filename}.{extension}")
                };

                let offset = if archive_index == 0x7fff {
                    embedded_data_base.saturating_add(entry_offset as u64)
                } else {
                    entry_offset as u64
                };

                entries.push(VirtualEntry {
                    name: full_name,
                    path_hint: None,
                    offset,
                    size: entry_length as u64,
                    encrypted: false,
                    archive_index: Some(archive_index),
                });
            }
        }
    }

    Ok(entries)
}

fn read_header(f: &mut File) -> Result<VpkHeader> {
    let mut base = [0u8; 12];
    f.read_exact(&mut base)?;
    let signature = u32::from_le_bytes([base[0], base[1], base[2], base[3]]);
    let version = u32::from_le_bytes([base[4], base[5], base[6], base[7]]);
    let tree_size = u32::from_le_bytes([base[8], base[9], base[10], base[11]]);

    let mut file_data_section_size = None;
    let mut archive_md5_section_size = None;
    let mut other_md5_section_size = None;
    let mut signature_section_size = None;

    if version == 2 {
        let mut v2 = [0u8; 16];
        f.read_exact(&mut v2)?;
        file_data_section_size = Some(u32::from_le_bytes([v2[0], v2[1], v2[2], v2[3]]));
        archive_md5_section_size = Some(u32::from_le_bytes([v2[4], v2[5], v2[6], v2[7]]));
        other_md5_section_size = Some(u32::from_le_bytes([v2[8], v2[9], v2[10], v2[11]]));
        signature_section_size = Some(u32::from_le_bytes([v2[12], v2[13], v2[14], v2[15]]));
    }

    Ok(VpkHeader {
        signature,
        version,
        tree_size,
        file_data_section_size,
        archive_md5_section_size,
        other_md5_section_size,
        signature_section_size,
    })
}

fn read_cstring<R: Read>(reader: &mut R) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        if b[0] == 0 {
            break;
        }
        bytes.push(b[0]);
    }

    String::from_utf8(bytes)
        .map_err(|_| LokiDataForgeError::ContainerParse("invalid UTF-8 in VPK tree".to_string()))
}
