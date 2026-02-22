use chrono::Utc;
use std::path::{Path, PathBuf};

use crate::carver::deep_carve;
use crate::error::{LokiDataForgeError, Result};
use crate::models::{
    ContainerType, FoundFile, ScanMetadata, ScanMode, ScanOptions, ScanReport, VirtualContainer,
};
use crate::progress::ProgressCallback;
use crate::quick_scan::quick_scan;
use crate::signatures::SignatureSet;
use crate::synology::apply_synology_mode;
use crate::virtual_mount::mount_container;

pub async fn run_scan(
    options: ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport> {
    if !options.source.exists() {
        return Err(LokiDataForgeError::MissingPath(options.source.clone()));
    }

    if options.chunk_size < 1024 {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "chunk_size must be >= 1024 bytes".to_string(),
        ));
    }

    let started_at = Utc::now();
    let mut warnings = Vec::new();
    let mut findings = Vec::new();
    let mut metadata = ScanMetadata::default();
    let signatures = SignatureSet::builtin()?;
    let sources = enumerate_sources(&options.source)?;
    if sources.is_empty() {
        return Err(LokiDataForgeError::InvalidScanOptions(format!(
            "no readable files found under source {}",
            options.source.display()
        )));
    }
    let total_scan_bytes = sources
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok().map(|m| m.len()))
        .sum::<u64>();

    if options.source.is_dir() {
        warnings.push(format!(
            "Directory source detected: scanning {} file(s) recursively",
            sources.len()
        ));
    }

    if options.synology_mode {
        apply_synology_mode(&options, &mut warnings);
    }

    for source in &sources {
        let source_options = ScanOptions {
            source: source.clone(),
            ..options.clone()
        };

        let container = detect_and_mount_if_needed(
            &source_options.source,
            source_options.include_container_scan,
        )?;
        if metadata.container_type.is_none() {
            metadata.container_type = container.as_ref().map(|c| c.container_type.clone());
        }

        if matches!(source_options.mode, ScanMode::Quick | ScanMode::Hybrid) {
            let quick =
                quick_scan(&source_options.source, &source_options, progress.clone()).await?;
            metadata.quick_hits += quick.len();
            findings.extend(quick);
        }

        if matches!(source_options.mode, ScanMode::Deep | ScanMode::Hybrid) {
            let deep = deep_carve(
                &source_options.source,
                &source_options,
                &signatures,
                progress.clone(),
            )
            .await?;
            metadata.deep_hits += deep.len();
            findings.extend(deep);
        }

        if let Some(container) = container {
            let mut container_findings =
                scan_container_entries(&source_options, &container, &signatures, progress.clone())
                    .await?;
            metadata.container_hits += container_findings.len();
            findings.append(&mut container_findings);
        }
    }

    findings.sort_by(|a, b| {
        (
            a.source_path.to_string_lossy(),
            a.offset,
            a.signature_id.as_str(),
        )
            .cmp(&(
                b.source_path.to_string_lossy(),
                b.offset,
                b.signature_id.as_str(),
            ))
    });
    findings.dedup_by(|a, b| {
        a.source_path == b.source_path && a.offset == b.offset && a.signature_id == b.signature_id
    });

    let finished_at = Utc::now();
    metadata.elapsed_ms = (finished_at - started_at).num_milliseconds().max(0) as u128;
    metadata.bytes_scanned = total_scan_bytes;

    Ok(ScanReport {
        scan_id: format!("scan-{}", uuid::Uuid::new_v4()),
        started_at,
        finished_at,
        source: options.source,
        mode: options.mode,
        findings,
        warnings,
        metadata,
    })
}

fn detect_and_mount_if_needed(path: &Path, include: bool) -> Result<Option<VirtualContainer>> {
    if !include || !path.is_file() {
        return Ok(None);
    }

    let mounted = mount_container(path)?;
    if mounted.container_type == ContainerType::Unknown {
        Ok(None)
    } else {
        Ok(Some(mounted))
    }
}

async fn scan_container_entries(
    options: &ScanOptions,
    container: &VirtualContainer,
    signatures: &SignatureSet,
    progress: Option<ProgressCallback>,
) -> Result<Vec<FoundFile>> {
    let mut out = Vec::new();

    match container.container_type {
        ContainerType::Vmdk => {
            for entry in &container.entries {
                if let Some(path) = &entry.path_hint
                    && path.exists()
                {
                    let nested_options = ScanOptions {
                        source: path.clone(),
                        mode: ScanMode::Deep,
                        include_container_scan: false,
                        ..options.clone()
                    };
                    let nested =
                        deep_carve(path, &nested_options, signatures, progress.clone()).await?;
                    out.extend(nested.into_iter().map(|mut f| {
                        f.container_path = Some(entry.name.clone());
                        f
                    }));
                }
            }
        }
        ContainerType::Vpk => {
            for entry in &container.entries {
                out.push(FoundFile {
                    id: format!("vpk-entry-{}", uuid::Uuid::new_v4()),
                    display_name: entry.name.clone(),
                    extension: entry.name.rsplit('.').next().unwrap_or("bin").to_string(),
                    signature_id: "vpk-entry".to_string(),
                    source_path: container.source.clone(),
                    container_path: Some(entry.name.clone()),
                    offset: entry.offset,
                    size: entry.size,
                    confidence: 0.9,
                    category: "archive_entry".to_string(),
                    encrypted: entry.encrypted,
                    notes: Some("Recovered from Valve Pak virtual tree".to_string()),
                });
            }
        }
        _ => {
            for entry in &container.entries {
                out.push(FoundFile {
                    id: format!("container-entry-{}", uuid::Uuid::new_v4()),
                    display_name: entry.name.clone(),
                    extension: entry.name.rsplit('.').next().unwrap_or("bin").to_string(),
                    signature_id: "container-entry".to_string(),
                    source_path: container.source.clone(),
                    container_path: Some(entry.name.clone()),
                    offset: entry.offset,
                    size: entry.size,
                    confidence: 0.6,
                    category: "container_metadata".to_string(),
                    encrypted: entry.encrypted,
                    notes: Some("TODO: deep scan for this container type".to_string()),
                });
            }
        }
    }

    Ok(out)
}

fn enumerate_sources(source: &Path) -> Result<Vec<PathBuf>> {
    if source.is_file() {
        return Ok(vec![source.to_path_buf()]);
    }

    if source.is_dir() {
        let mut files = walkdir::WalkDir::new(source)
            .follow_links(false)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .collect::<Vec<_>>();
        files.sort();
        return Ok(files);
    }

    Err(LokiDataForgeError::InvalidScanOptions(format!(
        "unsupported source type: {}",
        source.display()
    )))
}
