use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

// TODO: implement unlock adapters for BitLocker/LUKS/FileVault/Synology rkey.
