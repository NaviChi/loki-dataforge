use std::path::Path;

use tokio::io::AsyncReadExt;

use crate::error::Result;
use crate::models::{FoundFile, ScanOptions};
use crate::parsers::ntfs::parse_mft_markers;
use crate::progress::{ProgressCallback, ProgressTracker};

pub async fn quick_scan(
    source: &Path,
    options: &ScanOptions,
    source_fingerprint: &str,
    cb: Option<ProgressCallback>,
) -> Result<Vec<FoundFile>> {
    let mut file = tokio::fs::File::open(source).await?;
    let metadata = file.metadata().await?;
    let total = metadata.len();

    let tracker = ProgressTracker::new("quick_scan", total, cb);
    let mut findings = Vec::new();
    let mut carry = Vec::new();

    let chunk_size = options.chunk_size.max(1024);
    let mut offset = 0u64;

    loop {
        let mut chunk = vec![0u8; chunk_size];
        let bytes = file.read(&mut chunk).await?;
        if bytes == 0 {
            break;
        }
        chunk.truncate(bytes);

        let mut combined = Vec::with_capacity(carry.len() + chunk.len());
        combined.extend_from_slice(&carry);
        combined.extend_from_slice(&chunk);

        let combined_start = offset.saturating_sub(carry.len() as u64);
        findings.extend(parse_mft_markers(
            &combined,
            combined_start,
            source,
            source_fingerprint,
            options.mode,
        ));

        if combined.len() > 16 {
            carry = combined[combined.len() - 16..].to_vec();
        } else {
            carry = combined;
        }

        tracker.add(bytes as u64, format!("quick scan at offset {offset}"));
        offset += bytes as u64;
    }

    tracker.finish("quick scan complete");
    Ok(findings)
}
