use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionKind {
    BitLocker,
    Luks,
    FileVault,
    SynologyRkey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionContext {
    pub kind: EncryptionKind,
    pub key_reference: Option<String>,
}

pub fn detect_encryption_context(path: &Path) -> Result<Option<EncryptionContext>> {
    if !path.exists() || !path.is_file() {
        return Ok(None);
    }

    let mut f = std::fs::File::open(path)?;
    let mut header = vec![0u8; 8192];
    let read = f.read(&mut header)?;
    header.truncate(read);

    if is_bitlocker_signature(&header) {
        return Ok(Some(EncryptionContext {
            kind: EncryptionKind::BitLocker,
            key_reference: None,
        }));
    }

    if is_luks_signature(&header) {
        return Ok(Some(EncryptionContext {
            kind: EncryptionKind::Luks,
            key_reference: None,
        }));
    }

    if is_filevault_signature(&header) {
        return Ok(Some(EncryptionContext {
            kind: EncryptionKind::FileVault,
            key_reference: None,
        }));
    }

    if path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|n| n.to_ascii_lowercase().contains("rkey"))
        .unwrap_or(false)
    {
        return Ok(Some(EncryptionContext {
            kind: EncryptionKind::SynologyRkey,
            key_reference: Some(path.to_string_lossy().to_string()),
        }));
    }

    // BitLocker metadata may appear away from the initial bytes on some disk images.
    if f.seek(SeekFrom::Start(0x1000)).is_ok() {
        let mut probe = [0u8; 16];
        if f.read(&mut probe).is_ok() && probe.windows(8).any(|w| w == b"-FVE-FS-") {
            return Ok(Some(EncryptionContext {
                kind: EncryptionKind::BitLocker,
                key_reference: None,
            }));
        }
    }

    Ok(None)
}

fn is_bitlocker_signature(header: &[u8]) -> bool {
    (header.len() >= 11 && &header[3..11] == b"-FVE-FS-")
        || header.windows(8).any(|w| w == b"-FVE-FS-")
}

fn is_luks_signature(header: &[u8]) -> bool {
    header.starts_with(&[0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe])
}

fn is_filevault_signature(header: &[u8]) -> bool {
    // Best-effort marker search for known FileVault/CoreStorage/APFS metadata strings.
    header
        .windows(9)
        .any(|w| w.eq_ignore_ascii_case(b"filevault"))
        || header
            .windows(11)
            .any(|w| w.eq_ignore_ascii_case(b"corestorage"))
}
