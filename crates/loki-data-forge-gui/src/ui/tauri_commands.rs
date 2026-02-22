use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::{
    DialogExt, FilePath, MessageDialogButtons, MessageDialogKind, MessageDialogResult,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::RwLock;

use loki_data_forge_core::models::{
    ProgressUpdate, RecoveryOptions, ScanMode, ScanOptions, ScanReport, VirtualContainer,
};
use loki_data_forge_core::raid::{RaidDetectionReport, detect_raid_configuration};
use loki_data_forge_core::recovery::recover_files;
use loki_data_forge_core::scan::run_scan;
use loki_data_forge_core::virtual_mount::mount_container;

#[derive(Default)]
pub struct GuiState {
    pub last_report: Arc<RwLock<Option<ScanReport>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub source: Option<String>,
    pub sources: Option<Vec<String>>,
    pub mode: String,
    pub threads: Option<usize>,
    pub chunk_size: Option<usize>,
    pub max_carve_size: Option<u64>,
    pub synology_mode: Option<bool>,
    pub include_container_scan: Option<bool>,
    pub degraded_mode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidDetectRequest {
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingRaidPromptRequest {
    pub expected_members: usize,
    pub detected_members: usize,
    pub missing_members: Vec<String>,
}

#[tauri::command]
pub async fn scan_command(
    request: ScanRequest,
    app: AppHandle,
    state: State<'_, GuiState>,
) -> Result<ScanReport, String> {
    let mode = match request.mode.as_str() {
        "quick" => ScanMode::Quick,
        "deep" => ScanMode::Deep,
        _ => ScanMode::Hybrid,
    };

    let sources = normalize_sources(request.source, request.sources);
    if sources.is_empty() {
        return Err("Set at least one source drive/image path first.".to_string());
    }

    let source_paths = sources.iter().map(PathBuf::from).collect::<Vec<_>>();
    if source_paths.len() > 1 {
        let raid = detect_raid_configuration(&source_paths).map_err(|e| e.to_string())?;
        let _ = app.emit("raid-detection", &raid);

        if raid.degraded && !request.degraded_mode.unwrap_or(false) {
            return Err(format!(
                "RAID set appears incomplete ({} of {} members). Add missing drives or enable degraded mode.",
                raid.detected_members, raid.expected_members
            ));
        }
    }

    let progress = {
        let app = app.clone();
        Arc::new(move |update: ProgressUpdate| {
            let _ = app.emit("scan-progress", update);
        })
    };
    let configured_threads = request.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let configured_chunk_size = request.chunk_size.unwrap_or(8 * 1024 * 1024);
    let configured_max_carve = request.max_carve_size.unwrap_or(16 * 1024 * 1024);

    let mut reports = Vec::new();
    for source in &source_paths {
        let options = ScanOptions {
            source: source.clone(),
            output: None,
            mode,
            threads: configured_threads.max(1),
            chunk_size: configured_chunk_size.max(1024),
            max_carve_size: configured_max_carve.max(1024),
            read_only: true,
            synology_mode: request.synology_mode.unwrap_or(false),
            include_container_scan: request.include_container_scan.unwrap_or(true),
        };

        reports.push(
            run_scan(options, Some(progress.clone()))
                .await
                .map_err(|e| e.to_string())?,
        );
    }

    let report = merge_reports(reports).map_err(|e| e.to_string())?;

    {
        let mut guard = state.last_report.write().await;
        *guard = Some(report.clone());
    }

    Ok(report)
}

#[tauri::command]
pub async fn mount_container_command(path: String) -> Result<VirtualContainer, String> {
    mount_container(PathBuf::from(path).as_path()).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub source: String,
    pub destination: String,
    pub overwrite: bool,
}

#[tauri::command]
pub async fn recover_command(
    request: RecoverRequest,
    state: State<'_, GuiState>,
) -> Result<Vec<loki_data_forge_core::models::RecoveredFile>, String> {
    let report = {
        let guard = state.last_report.read().await;
        guard
            .clone()
            .ok_or_else(|| "No scan report loaded in state".to_string())?
    };

    let options = RecoveryOptions {
        source: PathBuf::from(request.source),
        destination: PathBuf::from(request.destination),
        overwrite: request.overwrite,
        preserve_paths: false,
    };

    recover_files(&report.findings, &options).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn preview_bytes_command(
    source: String,
    offset: u64,
    length: u64,
) -> Result<String, String> {
    let mut file = tokio::fs::File::open(&source)
        .await
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().await.map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("Preview source must be a file".to_string());
    }

    let start = offset.min(metadata.len());
    let end = offset.saturating_add(length).min(metadata.len());
    let read_len = end.saturating_sub(start).min(usize::MAX as u64);
    if read_len == 0 {
        return Ok(String::new());
    }

    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(|e| e.to_string())?;
    let mut slice = vec![0u8; read_len as usize];
    file.read_exact(&mut slice)
        .await
        .map_err(|e| e.to_string())?;

    Ok(format_hex_preview(&slice, start))
}

#[tauri::command]
pub async fn detect_raid_command(
    request: RaidDetectRequest,
) -> Result<RaidDetectionReport, String> {
    if request.inputs.is_empty() {
        return Err("No input drives/images were provided for RAID detection".to_string());
    }

    let paths = request
        .inputs
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<PathBuf>>();

    detect_raid_configuration(&paths).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn browse_input_locations_command(app: AppHandle) -> Result<Vec<String>, String> {
    let choice = app
        .dialog()
        .message(
            "Choose source type:\n\n- Drives/Images/Files for RAID members and disk images\n- Folders for directory scans",
        )
        .title("Select Input Location")
        .kind(MessageDialogKind::Info)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Drives/Images/Files".to_string(),
            "Folders".to_string(),
        ))
        .blocking_show_with_result();

    let selected = match choice {
        MessageDialogResult::Ok | MessageDialogResult::Yes => app
            .dialog()
            .file()
            .set_title("Select drives/images/files")
            .add_filter(
                "Disk and Backup Formats",
                &[
                    "img", "dd", "e01", "vmdk", "vhd", "vhdx", "qcow2", "vdi", "ova", "vpk", "tib",
                    "tibx", "wim", "bak", "sql", "dump",
                ],
            )
            .blocking_pick_files()
            .unwrap_or_default(),
        MessageDialogResult::Cancel => Vec::new(),
        MessageDialogResult::No => app
            .dialog()
            .file()
            .set_title("Select input folders")
            .blocking_pick_folders()
            .unwrap_or_default(),
        MessageDialogResult::Custom(label) => {
            if label.eq_ignore_ascii_case("Drives/Images/Files") {
                app.dialog()
                    .file()
                    .set_title("Select drives/images/files")
                    .add_filter(
                        "Disk and Backup Formats",
                        &[
                            "img", "dd", "e01", "vmdk", "vhd", "vhdx", "qcow2", "vdi", "ova",
                            "vpk", "tib", "tibx", "wim", "bak", "sql", "dump",
                        ],
                    )
                    .blocking_pick_files()
                    .unwrap_or_default()
            } else {
                app.dialog()
                    .file()
                    .set_title("Select input folders")
                    .blocking_pick_folders()
                    .unwrap_or_default()
            }
        }
    };

    Ok(file_paths_to_strings(selected))
}

#[tauri::command]
pub async fn browse_output_location_command(app: AppHandle) -> Result<Option<String>, String> {
    let picked = app
        .dialog()
        .file()
        .set_title("Select Recovery Output Location")
        .set_can_create_directories(true)
        .blocking_pick_folder();

    Ok(picked.and_then(|p| p.into_path().ok()).map(path_to_string))
}

#[tauri::command]
pub async fn prompt_missing_raid_dialog_command(
    app: AppHandle,
    request: MissingRaidPromptRequest,
) -> Result<String, String> {
    let missing = if request.missing_members.is_empty() {
        "(No specific members identified)".to_string()
    } else {
        request
            .missing_members
            .iter()
            .map(|m| format!("- {m}"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let message = format!(
        "Some drives are missing for this RAID array ({} of {} detected). Recovery may be degraded or incomplete.\n\nMissing:\n{}",
        request.detected_members, request.expected_members, missing
    );

    let result = app
        .dialog()
        .message(message)
        .title("Missing RAID Drives")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Add Missing Drives".to_string(),
            "Skip & Continue (Degraded Mode)".to_string(),
        ))
        .blocking_show_with_result();

    let action = match result {
        MessageDialogResult::Ok | MessageDialogResult::Yes => "add_missing_drives",
        MessageDialogResult::Custom(label) if label.eq_ignore_ascii_case("Add Missing Drives") => {
            "add_missing_drives"
        }
        _ => "skip_degraded",
    };

    Ok(action.to_string())
}

fn normalize_sources(source: Option<String>, sources: Option<Vec<String>>) -> Vec<String> {
    let mut combined = Vec::new();

    if let Some(mut many) = sources {
        combined.append(&mut many);
    }

    if let Some(single) = source {
        combined.push(single);
    }

    combined
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .fold(Vec::<String>::new(), |mut acc, item| {
            let key = normalize_source_key(&item);
            if !acc
                .iter()
                .any(|existing| normalize_source_key(existing) == key)
            {
                acc.push(item);
            }
            acc
        })
}

fn file_paths_to_strings(paths: Vec<FilePath>) -> Vec<String> {
    paths
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .map(path_to_string)
        .collect()
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().to_string()
}

fn normalize_source_key(path: &str) -> String {
    if cfg!(windows) {
        path.replace('/', "\\").to_ascii_lowercase()
    } else {
        path.to_string()
    }
}

fn format_hex_preview(slice: &[u8], start_offset: u64) -> String {
    let mut out = String::new();
    for (i, chunk) in slice.chunks(16).enumerate() {
        let off = start_offset + (i as u64 * 16);
        let hex = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect::<String>();
        out.push_str(&format!("{off:08x}  {:<47}  {ascii}\n", hex));
    }
    out
}

fn merge_reports(
    reports: Vec<ScanReport>,
) -> Result<ScanReport, loki_data_forge_core::LokiDataForgeError> {
    let mut iter = reports.into_iter();
    let Some(mut merged) = iter.next() else {
        return Err(
            loki_data_forge_core::LokiDataForgeError::InvalidScanOptions(
                "scan produced no reports".to_string(),
            ),
        );
    };

    for report in iter {
        merged.finished_at = merged.finished_at.max(report.finished_at);
        merged.warnings.extend(report.warnings);
        merged.findings.extend(report.findings);
        merged.metadata.bytes_scanned += report.metadata.bytes_scanned;
        merged.metadata.quick_hits += report.metadata.quick_hits;
        merged.metadata.deep_hits += report.metadata.deep_hits;
        merged.metadata.container_hits += report.metadata.container_hits;
        merged.metadata.elapsed_ms += report.metadata.elapsed_ms;
        if merged.metadata.container_type.is_none() {
            merged.metadata.container_type = report.metadata.container_type;
        }
    }

    merged.findings.sort_by(|a, b| {
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
    merged.findings.dedup_by(|a, b| {
        a.source_path == b.source_path && a.offset == b.offset && a.signature_id == b.signature_id
    });
    merged.scan_id = format!("{}-merged", merged.scan_id);
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::normalize_sources;
    use loki_data_forge_core::models::ScanReport;
    use serde_json::json;

    #[test]
    fn normalizes_and_deduplicates_sources() {
        let normalized = normalize_sources(
            Some("/dev/sda".to_string()),
            Some(vec![
                "/dev/sda".to_string(),
                "  /dev/sdb ".to_string(),
                "".to_string(),
            ]),
        );
        assert_eq!(
            normalized,
            vec!["/dev/sda".to_string(), "/dev/sdb".to_string()]
        );
    }

    #[test]
    fn merges_reports_without_dropping_different_sources() {
        let report_a: ScanReport = serde_json::from_value(json!({
            "scan_id": "a",
            "started_at": "2026-02-22T00:00:00Z",
            "finished_at": "2026-02-22T00:00:01Z",
            "source": "/tmp/a.img",
            "mode": "deep",
            "findings": [{
                "id": "f1",
                "display_name": "file1",
                "extension": "bin",
                "signature_id": "sig",
                "source_path": "/tmp/a.img",
                "container_path": null,
                "offset": 100,
                "size": 16,
                "confidence": 1.0,
                "category": "test",
                "encrypted": false,
                "notes": null
            }],
            "warnings": [],
            "metadata": {
                "bytes_scanned": 1024,
                "elapsed_ms": 1,
                "quick_hits": 0,
                "deep_hits": 1,
                "container_hits": 0,
                "container_type": null
            }
        }))
        .expect("report_a");
        let report_b: ScanReport = serde_json::from_value(json!({
            "scan_id": "b",
            "started_at": "2026-02-22T00:00:00Z",
            "finished_at": "2026-02-22T00:00:02Z",
            "source": "/tmp/b.img",
            "mode": "deep",
            "findings": [{
                "id": "f2",
                "display_name": "file2",
                "extension": "bin",
                "signature_id": "sig",
                "source_path": "/tmp/b.img",
                "container_path": null,
                "offset": 100,
                "size": 16,
                "confidence": 1.0,
                "category": "test",
                "encrypted": false,
                "notes": null
            }],
            "warnings": [],
            "metadata": {
                "bytes_scanned": 2048,
                "elapsed_ms": 2,
                "quick_hits": 0,
                "deep_hits": 1,
                "container_hits": 0,
                "container_type": null
            }
        }))
        .expect("report_b");

        let merged = super::merge_reports(vec![report_a, report_b]).expect("merged");
        assert_eq!(merged.findings.len(), 2);
        assert_eq!(merged.metadata.bytes_scanned, 3072);
    }

    #[test]
    fn formats_hex_preview_output() {
        let preview = super::format_hex_preview(b"ABCD\x00\xff", 0x20);
        assert!(preview.contains("00000020"));
        assert!(preview.contains("41 42 43 44 00 ff"));
    }
}
