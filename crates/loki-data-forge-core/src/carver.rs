use memmap2::MmapOptions;
use rayon::prelude::*;
use std::fs::File;
use std::path::Path;
use tokio::io::AsyncReadExt;

use crate::error::Result;
use crate::models::{FoundFile, ScanOptions};
use crate::progress::{ProgressCallback, ProgressTracker};
use crate::signatures::SignatureSet;

pub async fn deep_carve(
    source: &Path,
    options: &ScanOptions,
    signatures: &SignatureSet,
    cb: Option<ProgressCallback>,
) -> Result<Vec<FoundFile>> {
    let metadata = std::fs::metadata(source)?;
    let total = metadata.len();

    if metadata.is_file() {
        match try_memmap(source) {
            Ok(mapped) => deep_carve_mmap(source, mapped, total, options, signatures, cb),
            Err(_) => deep_carve_streaming(source, options, signatures, cb).await,
        }
    } else {
        deep_carve_streaming(source, options, signatures, cb).await
    }
}

fn deep_carve_mmap(
    source: &Path,
    mapped: memmap2::Mmap,
    total: u64,
    options: &ScanOptions,
    signatures: &SignatureSet,
    cb: Option<ProgressCallback>,
) -> Result<Vec<FoundFile>> {
    let tracker = ProgressTracker::new("deep_carve", total, cb);
    let chunk_size = options.chunk_size.max(1024 * 1024);
    let overlap = signatures.max_len.max(8);
    let source_buf: &[u8] = &mapped;

    let ranges = build_ranges(source_buf.len(), chunk_size, overlap);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads.max(1))
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut findings = pool.install(|| {
        ranges
            .par_iter()
            .flat_map(|(start, end)| {
                let chunk = &source_buf[*start..*end];
                let local = scan_chunk(chunk, *start as u64, source, options, signatures);
                let chunk_bytes = (end - start) as u64;
                tracker.add(chunk_bytes, format!("deep carving chunk {}-{}", start, end));
                local
            })
            .collect::<Vec<_>>()
    });

    findings.sort_by_key(|f| (f.offset, f.signature_id.clone()));
    findings.dedup_by(|a, b| a.offset == b.offset && a.signature_id == b.signature_id);

    tracker.finish("deep carving complete");
    Ok(findings)
}

async fn deep_carve_streaming(
    source: &Path,
    options: &ScanOptions,
    signatures: &SignatureSet,
    cb: Option<ProgressCallback>,
) -> Result<Vec<FoundFile>> {
    let mut f = tokio::fs::File::open(source).await?;
    let total = f.metadata().await?.len();
    let tracker = ProgressTracker::new("deep_carve", total, cb);

    let mut findings = Vec::new();
    let mut offset = 0u64;
    let chunk_size = options.chunk_size.max(1024 * 1024);
    let overlap = signatures.max_len.max(8);
    let mut carry = Vec::new();

    loop {
        let mut chunk = vec![0u8; chunk_size];
        let read = f.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        chunk.truncate(read);

        let mut merged = Vec::with_capacity(carry.len() + chunk.len());
        merged.extend_from_slice(&carry);
        merged.extend_from_slice(&chunk);

        let start = offset.saturating_sub(carry.len() as u64);
        findings.extend(scan_chunk(&merged, start, source, options, signatures));

        if merged.len() > overlap {
            carry = merged[merged.len() - overlap..].to_vec();
        } else {
            carry = merged;
        }

        offset += read as u64;
        tracker.add(read as u64, format!("deep carving stream offset {offset}"));
    }

    findings.sort_by_key(|f| (f.offset, f.signature_id.clone()));
    findings.dedup_by(|a, b| a.offset == b.offset && a.signature_id == b.signature_id);

    tracker.finish("deep carving complete");
    Ok(findings)
}

fn scan_chunk(
    chunk: &[u8],
    base_offset: u64,
    source: &Path,
    options: &ScanOptions,
    signatures: &SignatureSet,
) -> Vec<FoundFile> {
    let mut out = Vec::new();

    for idx in 0..chunk.len() {
        if let Some(candidates) = signatures.candidates_for_byte(chunk[idx]) {
            for sig_idx in candidates {
                let sig = &signatures.signatures()[*sig_idx];
                if !sig.matches(chunk, idx) {
                    continue;
                }

                let offset = match (base_offset + idx as u64).checked_sub(sig.definition.offset) {
                    Some(v) => v,
                    None => continue,
                };

                out.push(FoundFile {
                    id: format!("{}-{offset:016x}", sig.definition.id),
                    display_name: format!("{}_{}", sig.definition.name, offset),
                    extension: sig.definition.extension.clone(),
                    signature_id: sig.definition.id.clone(),
                    source_path: source.to_path_buf(),
                    container_path: None,
                    offset,
                    size: sig
                        .definition
                        .default_size
                        .unwrap_or(options.max_carve_size.min(16 * 1024 * 1024)),
                    confidence: 0.81,
                    category: sig.definition.category.clone(),
                    encrypted: false,
                    notes: sig.definition.description.clone(),
                });
            }
        }
    }

    out
}

fn build_ranges(total: usize, chunk_size: usize, overlap: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0usize;
    while start < total {
        let end = (start + chunk_size).min(total);
        let expanded_end = (end + overlap).min(total);
        ranges.push((start, expanded_end));
        if end == total {
            break;
        }
        start = end;
    }
    ranges
}

fn try_memmap(path: &Path) -> Result<memmap2::Mmap> {
    let file = File::open(path)?;
    // SAFETY: Mapping read-only file descriptor, no mutable aliasing is created.
    let map = unsafe { MmapOptions::new().map(&file)? };
    Ok(map)
}
