use std::path::Path;

use crate::identity::build_finding_id;
use crate::models::{EncryptionState, FoundFile, ReconstructionContext, ScanMode, VolumeLayer};

const MFT_RECORD_MAGIC: &[u8; 4] = b"FILE";
const MFT_RECORD_SIZE: usize = 1024;
const ATTR_TYPE_FILE_NAME: u32 = 0x30;
const ATTR_END: u32 = 0xffff_ffff;

pub fn parse_mft_markers(
    chunk: &[u8],
    base_offset: u64,
    source_path: &Path,
    source_fingerprint: &str,
    mode: ScanMode,
) -> Vec<FoundFile> {
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx + MFT_RECORD_MAGIC.len() <= chunk.len() {
        if &chunk[idx..idx + MFT_RECORD_MAGIC.len()] == MFT_RECORD_MAGIC {
            let absolute = base_offset + idx as u64;
            let record = &chunk[idx..(idx + MFT_RECORD_SIZE).min(chunk.len())];
            if let Some(found) =
                parse_mft_record(record, absolute, source_path, source_fingerprint, mode)
            {
                out.push(found);
            }
            idx += MFT_RECORD_MAGIC.len();
        } else {
            idx += 1;
        }
    }

    out
}

fn parse_mft_record(
    record: &[u8],
    absolute: u64,
    source_path: &Path,
    source_fingerprint: &str,
    mode: ScanMode,
) -> Option<FoundFile> {
    if record.len() < 0x30 {
        return None;
    }

    let usa_offset = read_u16(record, 0x04)? as usize;
    let first_attr_offset = read_u16(record, 0x14)? as usize;
    let flags = read_u16(record, 0x16)?;
    let used_size = read_u32(record, 0x18).unwrap_or(MFT_RECORD_SIZE as u32) as usize;
    let record_number =
        read_u32(record, 0x2c).unwrap_or((absolute / MFT_RECORD_SIZE as u64) as u32);

    if usa_offset < 0x28 || usa_offset >= record.len() || first_attr_offset < 0x20 {
        return None;
    }

    let bounded_len = used_size.clamp(0x30, record.len());
    let bounded = &record[..bounded_len];
    let file_name = parse_file_name_attribute(bounded, first_attr_offset);

    let in_use = (flags & 0x1) != 0;
    let is_directory = (flags & 0x2) != 0;
    let signature_id = if in_use {
        "ntfs-mft-active-entry"
    } else {
        "ntfs-mft-deleted-entry"
    };

    let display_name = file_name
        .clone()
        .unwrap_or_else(|| format!("ntfs_mft_record_{record_number:08x}_{absolute:016x}"));

    let extension = if let Some(name) = &file_name {
        extension_from_name(name, is_directory)
    } else if is_directory {
        "dir".to_string()
    } else {
        "mft".to_string()
    };

    let (confidence, validation_score) = if in_use { (0.74, 0.74) } else { (0.89, 0.89) };
    let status = if in_use { "active" } else { "deleted" };
    let dir_note = if is_directory { "directory" } else { "file" };

    Some(FoundFile {
        id: build_finding_id(source_fingerprint, None, absolute, signature_id, mode),
        display_name,
        extension,
        signature_id: signature_id.to_string(),
        source_path: source_path.to_path_buf(),
        source_fingerprint: source_fingerprint.to_string(),
        evidence_path: source_path.to_path_buf(),
        container_path: None,
        offset: absolute,
        size: bounded_len as u64,
        confidence,
        validation_score,
        category: "filesystem_metadata".to_string(),
        encrypted: false,
        encryption_state: EncryptionState::Unencrypted,
        reconstruction_context: Some(ReconstructionContext {
            volume_layer: VolumeLayer::Filesystem,
            reconstructed_path: file_name.clone(),
            notes: Some(format!(
                "NTFS MFT {status} {dir_note} entry (flags=0x{flags:04x})"
            )),
        }),
        notes: Some(format!(
            "Quick metadata recovery from NTFS MFT record #{record_number} ({status})"
        )),
    })
}

fn parse_file_name_attribute(record: &[u8], first_attr_offset: usize) -> Option<String> {
    if first_attr_offset >= record.len() {
        return None;
    }

    let mut attr_offset = first_attr_offset;
    while attr_offset + 16 <= record.len() {
        let attr_type = read_u32(record, attr_offset)?;
        if attr_type == ATTR_END {
            break;
        }

        let attr_len = read_u32(record, attr_offset + 4)? as usize;
        if attr_len < 24 || attr_offset + attr_len > record.len() {
            break;
        }

        let non_resident = *record.get(attr_offset + 8).unwrap_or(&1) != 0;
        if attr_type == ATTR_TYPE_FILE_NAME && !non_resident {
            let value_len = read_u32(record, attr_offset + 16)? as usize;
            let value_offset = read_u16(record, attr_offset + 20)? as usize;
            let value_start = attr_offset + value_offset;
            let value_end = value_start.saturating_add(value_len).min(record.len());
            if value_end > value_start + 66 {
                let name_len = record.get(value_start + 64).copied().unwrap_or(0) as usize;
                let name_start = value_start + 66;
                let name_bytes_len = name_len.saturating_mul(2);
                let name_end = name_start.saturating_add(name_bytes_len);
                if name_end <= value_end
                    && let Some(name) = decode_utf16le(record.get(name_start..name_end)?)
                    && !name.is_empty()
                {
                    return Some(name);
                }
            }
        }

        attr_offset += attr_len;
    }

    None
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }

    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();

    let decoded = std::char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .trim_matches('\u{0}')
        .to_string();
    Some(decoded)
}

fn extension_from_name(name: &str, is_directory: bool) -> String {
    if is_directory {
        return "dir".to_string();
    }

    let lower = name.to_ascii_lowercase();
    if let Some((_, ext)) = lower.rsplit_once('.')
        && !ext.is_empty()
    {
        return ext.to_string();
    }
    "mft".to_string()
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes: [u8; 2] = data.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::parse_mft_markers;
    use crate::models::ScanMode;

    #[test]
    fn parses_deleted_mft_entry_and_extracts_filename() {
        let mut record = vec![0u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        write_u16(&mut record, 0x04, 0x30);
        write_u16(&mut record, 0x14, 0x38);
        write_u16(&mut record, 0x16, 0x0000); // deleted
        write_u32(&mut record, 0x18, 0x200);
        write_u32(&mut record, 0x2c, 42);

        let attr_offset = 0x38usize;
        let name = "secret.docx";
        let name_utf16 = to_utf16le(name);
        let value_len = 66 + name_utf16.len();
        let attr_len = 24 + value_len;

        write_u32(&mut record, attr_offset, 0x30);
        write_u32(&mut record, attr_offset + 4, attr_len as u32);
        record[attr_offset + 8] = 0; // resident
        write_u32(&mut record, attr_offset + 16, value_len as u32);
        write_u16(&mut record, attr_offset + 20, 24);

        let value_start = attr_offset + 24;
        record[value_start + 64] = name.chars().count() as u8;
        record[value_start + 65] = 0x01;
        record[value_start + 66..value_start + 66 + name_utf16.len()].copy_from_slice(&name_utf16);

        let end_offset = attr_offset + attr_len;
        write_u32(&mut record, end_offset, 0xffff_ffff);

        let source = std::path::Path::new("/tmp/ntfs.img");
        let findings = parse_mft_markers(&record, 0, source, "src-fp", ScanMode::Quick);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.signature_id, "ntfs-mft-deleted-entry");
        assert_eq!(finding.display_name, "secret.docx");
        assert_eq!(finding.extension, "docx");
        assert!(
            finding
                .reconstruction_context
                .as_ref()
                .and_then(|ctx| ctx.reconstructed_path.as_deref())
                .is_some_and(|name| name == "secret.docx")
        );
    }

    #[test]
    fn parses_active_mft_entry_without_filename() {
        let mut record = vec![0u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        write_u16(&mut record, 0x04, 0x30);
        write_u16(&mut record, 0x14, 0x38);
        write_u16(&mut record, 0x16, 0x0001); // in use
        write_u32(&mut record, 0x18, 0x200);
        write_u32(&mut record, 0x2c, 7);
        write_u32(&mut record, 0x38, 0xffff_ffff);

        let source = std::path::Path::new("/tmp/ntfs.img");
        let findings = parse_mft_markers(&record, 0x1000, source, "src-fp", ScanMode::Quick);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.signature_id, "ntfs-mft-active-entry");
        assert!(finding.display_name.starts_with("ntfs_mft_record_"));
        assert_eq!(finding.offset, 0x1000);
    }

    fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn to_utf16le(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<_>>()
    }
}
