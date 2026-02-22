use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::adapters::{AdapterRegistry, summarize_capabilities};
use crate::carver::deep_carve;
use crate::encryption::detect_encryption_context;
use crate::error::{LokiDataForgeError, Result};
use crate::identity::{build_finding_id, compute_source_fingerprint};
use crate::models::{
    ContainerErrorPolicy, ContainerType, EncryptionPolicy, EncryptionState, FoundFile,
    ReconstructionContext, ScanMetadata, ScanMode, ScanOptions, ScanReport, VirtualContainer,
    VolumeLayer,
};
use crate::progress::ProgressCallback;
use crate::quick_scan::quick_scan;
use crate::raid::detect_raid_configuration;
use crate::signatures::SignatureSet;
use crate::synology::apply_synology_mode;
use crate::virtual_mount::mount_container;

pub async fn run_scan(
    options: ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport> {
    if options.chunk_size < 1024 {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "chunk_size must be >= 1024 bytes".to_string(),
        ));
    }

    let roots = normalize_roots(&options)?;
    for root in &roots {
        if !root.exists() && !is_windows_raw_device_path(root) {
            return Err(LokiDataForgeError::MissingPath(root.clone()));
        }
    }

    let started_at = Utc::now();
    let mut warnings = Vec::new();
    let mut findings = Vec::new();
    let mut metadata = ScanMetadata::default();
    metadata.volume_layers.push(VolumeLayer::Physical);

    let adapter_registry = AdapterRegistry::new(options.adapter_policy);
    let capabilities = adapter_registry.probe(&roots);
    metadata.adapter_capabilities = capabilities
        .iter()
        .map(|cap| {
            format!(
                "{}:{}:{}",
                cap.name,
                if cap.available {
                    "available"
                } else {
                    "missing"
                },
                cap.version.clone().unwrap_or_else(|| "n/a".to_string())
            )
        })
        .collect();
    warnings.extend(summarize_capabilities(&capabilities));

    if options.synology_mode {
        apply_synology_mode(&options, &mut warnings);
        metadata.volume_layers.push(VolumeLayer::RaidVirtual);
    }

    let can_probe_raid = roots.len() > 1
        && roots
            .iter()
            .all(|root| root.exists() && (root.is_file() || is_special_scan_source(root)));
    if can_probe_raid {
        match detect_raid_configuration(&roots) {
            Ok(raid) if raid.detected => {
                metadata.volume_layers.push(VolumeLayer::RaidVirtual);
                warnings.push(format!(
                    "RAID topology detected: controller={:?}, mode={:?}, members={}/{}",
                    raid.controller, raid.mode, raid.detected_members, raid.expected_members
                ));
                if raid.degraded {
                    warnings.push(format!(
                        "RAID set is degraded: {}",
                        raid.missing_members.join(", ")
                    ));
                }
            }
            Ok(_) => {}
            Err(err) => warnings.push(format!("RAID topology probe skipped: {err}")),
        }
    }

    let signatures = SignatureSet::builtin_for_profile(options.signature_profile)?;
    let sources = enumerate_all_sources(&roots)?;
    if sources.is_empty() {
        return Err(LokiDataForgeError::InvalidScanOptions(format!(
            "no readable files found under source(s): {}",
            roots
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let total_scan_bytes = sources
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok().map(|m| m.len()))
        .sum::<u64>();

    if roots.iter().any(|r| r.is_dir()) {
        warnings.push(format!(
            "Directory source detected: scanning {} file(s) recursively",
            sources.len()
        ));
    }

    let mut encryption_contexts = HashMap::new();

    for source in &sources {
        let source_fingerprint = compute_source_fingerprint(source);

        let source_options = ScanOptions {
            source: source.clone(),
            ..options.clone()
        };

        let encryption_context = detect_encryption_context(source).ok().flatten();
        if let Some(ctx) = &encryption_context {
            metadata.volume_layers.push(VolumeLayer::EncryptedVolume);
            warnings.push(format!(
                "Encryption marker detected on {} ({:?})",
                source.display(),
                ctx.kind
            ));

            match &options.encryption_policy {
                EncryptionPolicy::DetectOnly => {}
                EncryptionPolicy::UnlockWithProvider { provider } => warnings.push(format!(
                    "Unlock requested with provider '{provider}', but unlock adapters are currently scaffold-only"
                )),
            }

            if options.enable_bypass {
                warnings.push(format!(
                    "Bypass mode requested for {} (scaffold mode: no automated bypass applied)",
                    source.display()
                ));
            }
        }
        encryption_contexts.insert(source.clone(), encryption_context);

        let container = detect_and_mount_if_needed(
            &source_options.source,
            source_options.include_container_scan,
            source_options.container_error_policy,
            &mut warnings,
        )?;
        if metadata.container_type.is_none() {
            metadata.container_type = container.as_ref().map(|c| c.container_type.clone());
        }

        if matches!(source_options.mode, ScanMode::Quick | ScanMode::Hybrid) {
            let quick = quick_scan(
                &source_options.source,
                &source_options,
                &source_fingerprint,
                progress.clone(),
            )
            .await?;
            metadata.quick_hits += quick.len();
            findings.extend(quick);
        }

        if matches!(source_options.mode, ScanMode::Deep | ScanMode::Hybrid) {
            let deep = deep_carve(
                &source_options.source,
                &source_options,
                &signatures,
                &source_fingerprint,
                progress.clone(),
            )
            .await?;
            metadata.deep_hits += deep.len();
            findings.extend(deep);
        }

        if let Some(container) = container {
            let mut container_findings = scan_container_entries(
                &source_options,
                &container,
                &signatures,
                &source_fingerprint,
                progress.clone(),
            )
            .await?;
            metadata.container_hits += container_findings.len();
            findings.append(&mut container_findings);
        }
    }

    if !findings.is_empty() {
        metadata.volume_layers.push(VolumeLayer::Filesystem);
    }

    for finding in &mut findings {
        if let Some(Some(_ctx)) = encryption_contexts.get(&finding.source_path) {
            finding.encrypted = true;
            finding.encryption_state = if options.enable_bypass {
                EncryptionState::BypassAttempted
            } else {
                EncryptionState::EncryptedDetected
            };
        } else if matches!(finding.encryption_state, EncryptionState::Unknown) {
            finding.encryption_state = EncryptionState::Unencrypted;
        }
    }

    findings.sort_by(|a, b| {
        (
            a.source_path.to_string_lossy(),
            a.offset,
            a.signature_id.as_str(),
            a.container_path.as_deref().unwrap_or_default(),
        )
            .cmp(&(
                b.source_path.to_string_lossy(),
                b.offset,
                b.signature_id.as_str(),
                b.container_path.as_deref().unwrap_or_default(),
            ))
    });
    findings.dedup_by(|a, b| {
        a.source_path == b.source_path
            && a.offset == b.offset
            && a.signature_id == b.signature_id
            && a.container_path == b.container_path
    });

    metadata.volume_layers = dedup_layers(&metadata.volume_layers);

    let finished_at = Utc::now();
    metadata.elapsed_ms = (finished_at - started_at).num_milliseconds().max(0) as u128;
    metadata.bytes_scanned = total_scan_bytes;

    let primary_source = roots.first().cloned().unwrap_or_else(PathBuf::new);

    Ok(ScanReport {
        scan_id: format!("scan-{}", uuid::Uuid::new_v4()),
        started_at,
        finished_at,
        source: primary_source,
        sources: roots,
        mode: options.mode,
        findings,
        warnings,
        metadata,
    })
}

fn detect_and_mount_if_needed(
    path: &Path,
    include: bool,
    policy: ContainerErrorPolicy,
    warnings: &mut Vec<String>,
) -> Result<Option<VirtualContainer>> {
    if !include || !path.is_file() {
        return Ok(None);
    }

    match mount_container(path) {
        Ok(mounted) => {
            if mounted.container_type == ContainerType::Unknown {
                Ok(None)
            } else {
                Ok(Some(mounted))
            }
        }
        Err(err) => match policy {
            ContainerErrorPolicy::WarnAndSkip => {
                warnings.push(format!(
                    "Container parse skipped for {}: {}",
                    path.display(),
                    err
                ));
                Ok(None)
            }
            ContainerErrorPolicy::StrictFail => Err(err),
        },
    }
}

async fn scan_container_entries(
    options: &ScanOptions,
    container: &VirtualContainer,
    signatures: &SignatureSet,
    source_fingerprint: &str,
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
                    let nested_fingerprint = compute_source_fingerprint(path);
                    let nested = deep_carve(
                        path,
                        &nested_options,
                        signatures,
                        &nested_fingerprint,
                        progress.clone(),
                    )
                    .await?;
                    out.extend(nested.into_iter().map(|mut f| {
                        f.container_path = Some(entry.name.clone());
                        f.id = build_finding_id(
                            source_fingerprint,
                            Some(&entry.name),
                            f.offset,
                            &f.signature_id,
                            options.mode,
                        );
                        f.source_fingerprint = source_fingerprint.to_string();
                        f.evidence_path = container.source.clone();
                        f
                    }));
                }
            }
        }
        ContainerType::Vpk => {
            for entry in &container.entries {
                out.push(FoundFile {
                    id: build_finding_id(
                        source_fingerprint,
                        Some(&entry.name),
                        entry.offset,
                        "vpk-entry",
                        options.mode,
                    ),
                    display_name: entry.name.clone(),
                    extension: entry.name.rsplit('.').next().unwrap_or("bin").to_string(),
                    signature_id: "vpk-entry".to_string(),
                    source_path: container.source.clone(),
                    source_fingerprint: source_fingerprint.to_string(),
                    evidence_path: container.source.clone(),
                    container_path: Some(entry.name.clone()),
                    offset: entry.offset,
                    size: entry.size,
                    confidence: 0.9,
                    validation_score: 0.8,
                    category: "archive_entry".to_string(),
                    encrypted: entry.encrypted,
                    encryption_state: if entry.encrypted {
                        EncryptionState::EncryptedDetected
                    } else {
                        EncryptionState::Unencrypted
                    },
                    reconstruction_context: Some(ReconstructionContext {
                        volume_layer: VolumeLayer::Filesystem,
                        reconstructed_path: Some(entry.name.clone()),
                        notes: Some("Recovered from Valve Pak virtual tree".to_string()),
                    }),
                    notes: Some("Recovered from Valve Pak virtual tree".to_string()),
                });
            }
        }
        _ => {
            for entry in &container.entries {
                out.push(FoundFile {
                    id: build_finding_id(
                        source_fingerprint,
                        Some(&entry.name),
                        entry.offset,
                        "container-entry",
                        options.mode,
                    ),
                    display_name: entry.name.clone(),
                    extension: entry.name.rsplit('.').next().unwrap_or("bin").to_string(),
                    signature_id: "container-entry".to_string(),
                    source_path: container.source.clone(),
                    source_fingerprint: source_fingerprint.to_string(),
                    evidence_path: container.source.clone(),
                    container_path: Some(entry.name.clone()),
                    offset: entry.offset,
                    size: entry.size,
                    confidence: 0.6,
                    validation_score: 0.4,
                    category: "container_metadata".to_string(),
                    encrypted: entry.encrypted,
                    encryption_state: if entry.encrypted {
                        EncryptionState::EncryptedDetected
                    } else {
                        EncryptionState::Unencrypted
                    },
                    reconstruction_context: Some(ReconstructionContext {
                        volume_layer: VolumeLayer::Filesystem,
                        reconstructed_path: Some(entry.name.clone()),
                        notes: Some("Container metadata only".to_string()),
                    }),
                    notes: Some(
                        "Container metadata only (deep scan pending for this type)".to_string(),
                    ),
                });
            }
        }
    }

    Ok(out)
}

fn normalize_roots(options: &ScanOptions) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();

    if !options.sources.is_empty() {
        roots.extend(options.sources.iter().cloned());
    }

    if !options.source.as_os_str().is_empty() {
        roots.push(options.source.clone());
    }

    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for root in roots {
        let normalized = normalize_source_key(&root);
        if seen.insert(normalized) {
            deduped.push(root);
        }
    }

    if deduped.is_empty() {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "no input source(s) were provided".to_string(),
        ));
    }

    Ok(deduped)
}

fn enumerate_all_sources(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for root in roots {
        out.extend(enumerate_sources(root)?);
    }

    let mut seen = HashSet::new();
    out.retain(|p| seen.insert(normalize_source_key(p)));
    out.sort();
    Ok(out)
}

fn enumerate_sources(source: &Path) -> Result<Vec<PathBuf>> {
    if source.is_file() || is_special_scan_source(source) || is_windows_raw_device_path(source) {
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

fn is_special_scan_source(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            let ft = meta.file_type();
            return ft.is_block_device() || ft.is_char_device();
        }
    }

    false
}

fn is_windows_raw_device_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    raw.starts_with(r"\\.\PhysicalDrive") || raw.starts_with(r"\\.\Volume{")
}

fn normalize_source_key(path: &Path) -> String {
    if cfg!(windows) {
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    } else {
        path.to_string_lossy().to_string()
    }
}

fn dedup_layers(layers: &[VolumeLayer]) -> Vec<VolumeLayer> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for layer in layers {
        if seen.insert(*layer) {
            out.push(*layer);
        }
    }
    out
}
