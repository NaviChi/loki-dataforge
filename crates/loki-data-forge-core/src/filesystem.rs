use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemSupport {
    Ntfs,
    Refs,
    Ext4,
    Btrfs,
    Apfs,
    HfsPlus,
    Xfs,
    Zfs,
}

pub fn supported_filesystems() -> Vec<FilesystemSupport> {
    vec![
        FilesystemSupport::Ntfs,
        FilesystemSupport::Refs,
        FilesystemSupport::Ext4,
        FilesystemSupport::Btrfs,
        FilesystemSupport::Apfs,
        FilesystemSupport::HfsPlus,
        FilesystemSupport::Xfs,
        FilesystemSupport::Zfs,
    ]
}

// TODO: Expand per-filesystem parsers for full metadata-aware recovery.
