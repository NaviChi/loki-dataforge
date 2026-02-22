use std::path::Path;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::ScanMode;

const FINDING_NAMESPACE: Uuid = Uuid::from_u128(0x58f573f18a7a4f77b59879db7d4f4ff2);

pub fn compute_source_fingerprint(path: &Path) -> String {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let meta = std::fs::metadata(path).ok();

    let descriptor = format!(
        "{}|{}|{}",
        canonical.to_string_lossy(),
        meta.as_ref().map(|m| m.len()).unwrap_or(0),
        meta.as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );

    let mut hasher = Sha256::new();
    hasher.update(descriptor.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn build_finding_id(
    source_fingerprint: &str,
    container_path: Option<&str>,
    offset: u64,
    signature_id: &str,
    mode: ScanMode,
) -> String {
    let name = format!(
        "{}|{}|{}|{}|{:?}",
        source_fingerprint,
        container_path.unwrap_or_default(),
        offset,
        signature_id,
        mode
    );
    Uuid::new_v5(&FINDING_NAMESPACE, name.as_bytes()).to_string()
}
