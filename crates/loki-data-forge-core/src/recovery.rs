use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{LokiDataForgeError, Result};
use crate::models::{FoundFile, RecoveredFile, RecoveryOptions};

const RECOVERY_MANIFEST_FILE: &str = ".loki-data-forge-recovery-manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RecoveryManifest {
    version: u8,
    entries: HashMap<String, RecoveryManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryManifestEntry {
    source_path: String,
    offset: u64,
    expected_size: u64,
    bytes_written: u64,
    output_path: String,
    completed: bool,
    sha256: Option<String>,
    updated_at: String,
}

pub fn recover_files(
    findings: &[FoundFile],
    options: &RecoveryOptions,
) -> Result<Vec<RecoveredFile>> {
    recover_files_with_policy(findings, options, true)
}

fn recover_files_with_policy(
    findings: &[FoundFile],
    options: &RecoveryOptions,
    enforce_separate_device: bool,
) -> Result<Vec<RecoveredFile>> {
    let mut safety_sources = HashSet::new();
    for finding in findings {
        let source_path = if finding.source_path.exists() {
            finding.source_path.clone()
        } else {
            options.source.clone()
        };
        safety_sources.insert(source_path);
    }
    if safety_sources.is_empty() {
        safety_sources.insert(options.source.clone());
    }
    for source in safety_sources {
        ensure_safe_destination(&source, &options.destination, enforce_separate_device)?;
    }
    std::fs::create_dir_all(&options.destination)?;

    let manifest_path = options.destination.join(RECOVERY_MANIFEST_FILE);
    let mut manifest = load_manifest(&manifest_path)?;
    if manifest.version == 0 {
        manifest.version = 1;
    }

    let mut recovered = Vec::new();

    for item in findings {
        let source_path = if item.source_path.exists() {
            item.source_path.clone()
        } else {
            options.source.clone()
        };

        if !source_path.exists() {
            return Err(LokiDataForgeError::MissingPath(source_path));
        }

        let output_path = build_output_path(item, &options.destination, options.preserve_paths);
        let manifest_key = manifest_key_for_item(item);

        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let source_len = std::fs::metadata(&source_path)?.len();
        if item.offset >= source_len {
            continue;
        }
        let expected_size = item.size.min(source_len.saturating_sub(item.offset));
        if expected_size == 0 {
            continue;
        }

        let existing_manifest_entry = manifest
            .entries
            .get(&manifest_key)
            .cloned()
            .or_else(|| manifest.entries.get(&item.id).cloned());
        let mut resume_written = 0u64;

        if let Some(entry) = &existing_manifest_entry {
            if entry.completed && PathBuf::from(&entry.output_path).exists() && !options.overwrite {
                recovered.push(RecoveredFile {
                    source_id: item.id.clone(),
                    output_path: PathBuf::from(&entry.output_path),
                    bytes_written: entry.bytes_written,
                    sha256: entry.sha256.clone().unwrap_or_else(|| {
                        compute_sha256(Path::new(&entry.output_path)).unwrap_or_default()
                    }),
                });
                continue;
            }

            if !entry.completed && Path::new(&entry.output_path).exists() && !options.overwrite {
                let current_size = std::fs::metadata(&entry.output_path)?.len();
                resume_written = current_size.min(entry.bytes_written).min(expected_size);
            }
        } else if output_path.exists() && !options.overwrite {
            // Existing unmanaged file: skip to avoid clobbering operator-owned output.
            continue;
        }

        if output_path.exists() && options.overwrite && resume_written == 0 {
            std::fs::remove_file(&output_path)?;
        }

        if resume_written > 0 {
            let existing = std::fs::OpenOptions::new().write(true).open(&output_path)?;
            existing.set_len(resume_written)?;
        }

        let mut src = std::fs::File::open(&source_path)?;
        src.seek(SeekFrom::Start(item.offset + resume_written))?;
        let mut remaining_reader =
            std::io::Read::by_ref(&mut src).take(expected_size - resume_written);

        let mut out = if resume_written > 0 {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&output_path)?
        } else {
            std::fs::File::create(&output_path)?
        };

        let mut hasher = Sha256::new();
        if resume_written > 0 {
            hash_existing_prefix(&output_path, resume_written, &mut hasher)?;
        }

        let mut written = resume_written;
        let mut buf = [0u8; 64 * 1024];

        loop {
            let n = remaining_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }

            if let Err(err) = out.write_all(&buf[..n]) {
                let entry = RecoveryManifestEntry {
                    source_path: source_path.to_string_lossy().to_string(),
                    offset: item.offset,
                    expected_size,
                    bytes_written: written,
                    output_path: output_path.to_string_lossy().to_string(),
                    completed: false,
                    sha256: None,
                    updated_at: Utc::now().to_rfc3339(),
                };
                manifest.entries.insert(manifest_key.clone(), entry);
                save_manifest(&manifest_path, &manifest)?;

                if is_disk_full(&err) {
                    return Err(LokiDataForgeError::Command(format!(
                        "destination appears full while writing '{}' ({} of {} bytes written). Free space and re-run to resume.",
                        output_path.display(),
                        written,
                        expected_size
                    )));
                }

                return Err(LokiDataForgeError::Io(err));
            }

            hasher.update(&buf[..n]);
            written += n as u64;
        }

        out.flush()?;

        let sha256 = format!("{:x}", hasher.finalize());
        manifest.entries.insert(
            manifest_key.clone(),
            RecoveryManifestEntry {
                source_path: source_path.to_string_lossy().to_string(),
                offset: item.offset,
                expected_size,
                bytes_written: written,
                output_path: output_path.to_string_lossy().to_string(),
                completed: true,
                sha256: Some(sha256.clone()),
                updated_at: Utc::now().to_rfc3339(),
            },
        );
        if manifest_key != item.id {
            manifest.entries.remove(&item.id);
        }

        recovered.push(RecoveredFile {
            source_id: item.id.clone(),
            output_path,
            bytes_written: written,
            sha256,
        });
    }

    save_manifest(&manifest_path, &manifest)?;
    Ok(recovered)
}

fn ensure_safe_destination(
    source: &Path,
    destination: &Path,
    enforce_separate_device: bool,
) -> Result<()> {
    if !source.exists() {
        return Err(LokiDataForgeError::MissingPath(source.to_path_buf()));
    }

    std::fs::create_dir_all(destination)?;

    let source_canon = std::fs::canonicalize(source)?;
    let destination_canon = std::fs::canonicalize(destination)?;

    if source_canon == destination_canon
        || destination_canon.starts_with(&source_canon)
        || (source_canon.is_dir() && source_canon.starts_with(&destination_canon))
    {
        return Err(LokiDataForgeError::UnsafeDestination(
            "recovery destination must be separate from source".to_string(),
        ));
    }

    if enforce_separate_device && is_same_storage_device(&source_canon, &destination_canon)? {
        return Err(LokiDataForgeError::UnsafeDestination(
            "recovery destination must be on a different drive/filesystem than the source"
                .to_string(),
        ));
    }

    Ok(())
}

fn is_same_storage_device(source: &Path, destination: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let src_dev = std::fs::metadata(source)?.dev();
        let dst_dev = std::fs::metadata(destination)?.dev();
        return Ok(src_dev == dst_dev);
    }

    #[cfg(windows)]
    {
        use std::path::Component;
        let src_prefix = source.components().find_map(|component| match component {
            Component::Prefix(prefix) => {
                Some(prefix.as_os_str().to_string_lossy().to_ascii_lowercase())
            }
            _ => None,
        });
        let dst_prefix = destination
            .components()
            .find_map(|component| match component {
                Component::Prefix(prefix) => {
                    Some(prefix.as_os_str().to_string_lossy().to_ascii_lowercase())
                }
                _ => None,
            });
        return Ok(src_prefix.is_some() && src_prefix == dst_prefix);
    }

    #[allow(unreachable_code)]
    Ok(false)
}

fn load_manifest(path: &Path) -> Result<RecoveryManifest> {
    if !path.exists() {
        return Ok(RecoveryManifest::default());
    }

    let data = std::fs::read_to_string(path)?;
    let parsed: RecoveryManifest = serde_json::from_str(&data).map_err(|err| {
        LokiDataForgeError::Command(format!(
            "invalid recovery manifest '{}': {err}",
            path.display()
        ))
    })?;
    Ok(parsed)
}

fn save_manifest(path: &Path, manifest: &RecoveryManifest) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| LokiDataForgeError::Command("manifest path has no parent".to_string()))?;
    std::fs::create_dir_all(parent)?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(manifest)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn hash_existing_prefix(path: &Path, bytes: u64, hasher: &mut Sha256) -> Result<()> {
    let mut f = std::fs::File::open(path)?;
    let mut take = std::io::Read::by_ref(&mut f).take(bytes);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = take.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(())
}

fn compute_sha256(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn is_disk_full(err: &std::io::Error) -> bool {
    if matches!(err.kind(), ErrorKind::WriteZero) {
        return true;
    }

    matches!(err.raw_os_error(), Some(28) | Some(112))
}

fn sanitize_name(name: &str, ext: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    let normalized_ext = ext.trim_matches('.').to_ascii_lowercase();
    if normalized_ext.is_empty() {
        return clean;
    }

    let with_dot = format!(".{normalized_ext}");
    if clean.to_ascii_lowercase().ends_with(&with_dot) {
        clean
    } else {
        format!("{clean}{with_dot}")
    }
}

fn manifest_key_for_item(item: &FoundFile) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        if item.source_fingerprint.is_empty() {
            "unknown-source"
        } else {
            &item.source_fingerprint
        },
        item.container_path.clone().unwrap_or_default(),
        item.offset,
        item.signature_id,
        item.id
    )
}

fn build_output_path(item: &FoundFile, destination: &Path, preserve_paths: bool) -> PathBuf {
    let filename = sanitize_name(&item.display_name, &item.extension);
    if !preserve_paths {
        return destination.join(filename);
    }

    let source_root = sanitize_component(if item.source_fingerprint.is_empty() {
        "unknown_source"
    } else {
        &item.source_fingerprint
    });

    let mut out = destination.join(source_root);
    let preserved_hint = item
        .reconstruction_context
        .as_ref()
        .and_then(|ctx| ctx.reconstructed_path.clone())
        .or_else(|| item.container_path.clone());

    if let Some(hint) = preserved_hint {
        let rel = sanitize_relative_path(&hint);
        if rel.as_os_str().is_empty() {
            out.push(filename);
            return out;
        }

        let last_is_file = rel
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.contains('.'))
            .unwrap_or(false);

        out.push(&rel);
        if !last_is_file {
            out.push(filename);
        }
        return out;
    }

    out.push(filename);
    out
}

fn sanitize_relative_path(value: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in Path::new(value).components() {
        if let Component::Normal(part) = component {
            let clean = sanitize_component(&part.to_string_lossy());
            if !clean.is_empty() {
                out.push(clean);
            }
        }
    }
    out
}

fn sanitize_component(component: &str) -> String {
    component
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::recover_files_with_policy;
    use crate::models::{EncryptionState, FoundFile, RecoveryOptions};

    #[test]
    fn resumes_recovery_from_manifest_partial_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("source.img");
        let destination = dir.path().join("dest");
        std::fs::create_dir_all(&destination).expect("dest dir");

        let payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::fs::write(&source, payload).expect("source");

        let finding = FoundFile {
            id: "sample-1".to_string(),
            display_name: "sample_payload".to_string(),
            extension: "bin".to_string(),
            signature_id: "test".to_string(),
            source_path: source.clone(),
            source_fingerprint: "test-source".to_string(),
            evidence_path: source.clone(),
            container_path: None,
            offset: 0,
            size: payload.len() as u64,
            confidence: 1.0,
            validation_score: 1.0,
            category: "test".to_string(),
            encrypted: false,
            encryption_state: EncryptionState::Unencrypted,
            reconstruction_context: None,
            notes: None,
        };

        let partial_path = destination.join("sample_payload.bin");
        {
            let mut partial = std::fs::File::create(&partial_path).expect("partial file");
            partial.write_all(&payload[..10]).expect("write partial");
        }

        let manifest_path = destination.join(super::RECOVERY_MANIFEST_FILE);
        let manifest = serde_json::json!({
            "version": 1,
            "entries": {
                "sample-1": {
                    "source_path": source.to_string_lossy(),
                    "offset": 0,
                    "expected_size": payload.len(),
                    "bytes_written": 10,
                    "output_path": partial_path.to_string_lossy(),
                    "completed": false,
                    "sha256": null,
                    "updated_at": chrono::Utc::now().to_rfc3339()
                }
            }
        });
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
        )
        .expect("write manifest");

        let options = RecoveryOptions {
            source: source.clone(),
            destination: destination.clone(),
            overwrite: false,
            preserve_paths: false,
        };

        let recovered = recover_files_with_policy(&[finding], &options, false).expect("recovery");
        assert_eq!(recovered.len(), 1);

        let final_data = std::fs::read(&partial_path).expect("final file");
        assert_eq!(final_data, payload);

        let manifest_data = std::fs::read_to_string(&manifest_path).expect("manifest");
        assert!(manifest_data.contains("\"completed\": true"));
    }

    #[test]
    fn preserve_paths_writes_under_source_fingerprint_root() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("source.img");
        let destination = dir.path().join("dest");
        std::fs::create_dir_all(&destination).expect("dest dir");
        std::fs::write(&source, b"hello-world").expect("source");

        let finding = FoundFile {
            id: "path-1".to_string(),
            display_name: "ignored_name".to_string(),
            extension: "txt".to_string(),
            signature_id: "test".to_string(),
            source_path: source.clone(),
            source_fingerprint: "src-fp-001".to_string(),
            evidence_path: source.clone(),
            container_path: Some("folderA/folderB/recovered.txt".to_string()),
            offset: 0,
            size: 11,
            confidence: 1.0,
            validation_score: 1.0,
            category: "test".to_string(),
            encrypted: false,
            encryption_state: EncryptionState::Unencrypted,
            reconstruction_context: None,
            notes: None,
        };

        let options = RecoveryOptions {
            source: source.clone(),
            destination: destination.clone(),
            overwrite: false,
            preserve_paths: true,
        };

        let recovered =
            recover_files_with_policy(&[finding], &options, false).expect("recovery with paths");
        assert_eq!(recovered.len(), 1);

        let expected = destination
            .join("src-fp-001")
            .join("folderA")
            .join("folderB")
            .join("recovered.txt");
        assert_eq!(recovered[0].output_path, expected);
        let data = std::fs::read(expected).expect("recovered bytes");
        assert_eq!(data, b"hello-world");
    }

    #[test]
    fn manifest_keys_do_not_collide_for_duplicate_finding_ids() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source_a = dir.path().join("source_a.img");
        let source_b = dir.path().join("source_b.img");
        let destination = dir.path().join("dest");
        std::fs::create_dir_all(&destination).expect("dest dir");
        std::fs::write(&source_a, b"AAAA").expect("source a");
        std::fs::write(&source_b, b"BBBB").expect("source b");

        let finding_a = FoundFile {
            id: "duplicate-id".to_string(),
            display_name: "sample".to_string(),
            extension: "bin".to_string(),
            signature_id: "sig".to_string(),
            source_path: source_a.clone(),
            source_fingerprint: "fp-a".to_string(),
            evidence_path: source_a.clone(),
            container_path: None,
            offset: 0,
            size: 4,
            confidence: 1.0,
            validation_score: 1.0,
            category: "test".to_string(),
            encrypted: false,
            encryption_state: EncryptionState::Unencrypted,
            reconstruction_context: None,
            notes: None,
        };
        let finding_b = FoundFile {
            id: "duplicate-id".to_string(),
            display_name: "sample".to_string(),
            extension: "bin".to_string(),
            signature_id: "sig".to_string(),
            source_path: source_b.clone(),
            source_fingerprint: "fp-b".to_string(),
            evidence_path: source_b.clone(),
            container_path: None,
            offset: 0,
            size: 4,
            confidence: 1.0,
            validation_score: 1.0,
            category: "test".to_string(),
            encrypted: false,
            encryption_state: EncryptionState::Unencrypted,
            reconstruction_context: None,
            notes: None,
        };

        let options = RecoveryOptions {
            source: source_a,
            destination: destination.clone(),
            overwrite: false,
            preserve_paths: true,
        };

        let recovered = recover_files_with_policy(&[finding_a, finding_b], &options, false)
            .expect("recovery with duplicate ids");
        assert_eq!(recovered.len(), 2);

        let manifest_path = destination.join(super::RECOVERY_MANIFEST_FILE);
        let manifest_data = std::fs::read_to_string(manifest_path).expect("manifest read");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_data).expect("manifest json");
        let entries = manifest["entries"].as_object().expect("entries object");
        assert_eq!(entries.len(), 2);
    }
}
