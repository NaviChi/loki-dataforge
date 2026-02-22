pub mod commands;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{io::Read, io::Seek};

use anyhow::Context;
use clap::{Parser, error::ErrorKind};
use sha2::{Digest, Sha256};

use loki_data_forge_core::models::{
    AdapterPolicy, ContainerErrorPolicy, EncryptionPolicy, ProgressUpdate, RecoveryOptions,
    ScanMode, ScanOptions, SignatureProfile,
};
use loki_data_forge_core::raid::{RaidMode, RaidParityLayout};
use loki_data_forge_core::raid_reconstruct::{RaidReconstructOptions, reconstruct_array};
use loki_data_forge_core::recovery::recover_files;
use loki_data_forge_core::scan::run_scan;
use loki_data_forge_core::virtual_mount::mount_container;

pub use commands::{Cli, Commands};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliExecution {
    NotRequested,
    Executed,
}

pub fn should_run_cli(args: &[String]) -> bool {
    if args.len() <= 1 {
        return false;
    }

    match Cli::try_parse_from(args) {
        Ok(_) => true,
        Err(err) => matches!(
            err.kind(),
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
        ),
    }
}

pub async fn run_args(args: Vec<String>) -> anyhow::Result<CliExecution> {
    if !should_run_cli(&args) {
        return Ok(CliExecution::NotRequested);
    }

    let cli = Cli::parse_from(args);
    tracing_subscriber::fmt()
        .with_env_filter(cli.log.clone())
        .without_time()
        .try_init()
        .ok();

    match cli.command {
        Commands::Scan(cmd) => {
            let scan_sources = resolve_scan_sources(&cmd)?;
            let primary_source = scan_sources
                .first()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("at least one --drive/--source is required"))?;

            if cmd.enable_bypass {
                let validation_result = validate_bypass_flags(&cmd.case_id, &cmd.legal_authority);
                append_bypass_audit_event(
                    &scan_sources,
                    cmd.case_id.as_deref(),
                    cmd.legal_authority.as_deref(),
                    validation_result.is_ok(),
                    validation_result.as_ref().err().map(|err| err.to_string()),
                )?;
                validation_result?;
            }

            if cmd.unlock_with.is_some() && cmd.encryption_detect_only {
                append_unlock_audit_event(
                    &scan_sources,
                    cmd.unlock_with.as_deref().unwrap_or(""),
                    false,
                    Some(
                        "--unlock-with cannot be combined with --encryption-detect-only in the same scan",
                    ),
                )?;
                anyhow::bail!(
                    "--unlock-with cannot be combined with --encryption-detect-only in the same scan"
                );
            }

            if let Some(provider) = cmd.unlock_with.as_deref() {
                append_unlock_audit_event(&scan_sources, provider, true, None)?;
            }

            let mode = match cmd.mode.as_str() {
                "quick" => ScanMode::Quick,
                "deep" => ScanMode::Deep,
                _ => ScanMode::Hybrid,
            };

            let signature_profile = match cmd.signature_profile.as_str() {
                "broad" => SignatureProfile::Broad,
                _ => SignatureProfile::Strict,
            };

            let container_error_policy = if cmd.strict_containers {
                ContainerErrorPolicy::StrictFail
            } else {
                ContainerErrorPolicy::WarnAndSkip
            };

            let encryption_policy = match cmd.unlock_with.clone() {
                Some(provider) => EncryptionPolicy::UnlockWithProvider { provider },
                None => EncryptionPolicy::DetectOnly,
            };

            let adapter_policy = match cmd.adapter_policy.as_str() {
                "native-only" => AdapterPolicy::NativeOnly,
                "external-preferred" => AdapterPolicy::ExternalPreferred,
                _ => AdapterPolicy::Hybrid,
            };

            let scan_options = ScanOptions {
                source: primary_source.clone(),
                sources: scan_sources.clone(),
                output: cmd.output.clone(),
                mode,
                threads: cmd.threads,
                chunk_size: cmd.chunk_size,
                max_carve_size: cmd.max_carve_size,
                read_only: !cmd.read_write,
                synology_mode: cmd.synology_mode,
                include_container_scan: !cmd.skip_containers,
                container_error_policy,
                signature_profile,
                encryption_policy,
                adapter_policy,
                enable_bypass: cmd.enable_bypass,
                case_id: cmd.case_id.clone(),
                legal_authority: cmd.legal_authority.clone(),
            };

            let progress = if cmd.quiet {
                None
            } else {
                Some(Arc::new(|p: ProgressUpdate| {
                    eprintln!(
                        "[{phase}] {percent:>3}% {processed}/{total} ETA={eta:?} {message}",
                        phase = p.phase,
                        percent = p.percent,
                        processed = p.processed_bytes,
                        total = p.total_bytes,
                        eta = p.eta_seconds,
                        message = p.message
                    );
                })
                    as Arc<dyn Fn(ProgressUpdate) + Send + Sync>)
            };

            let report = run_scan(scan_options, progress).await?;
            let json = serde_json::to_string_pretty(&report)?;

            if let Some(path) = cmd.report.as_ref() {
                std::fs::write(path, &json)
                    .with_context(|| format!("failed writing report to {}", path.display()))?;
                println!("report saved: {}", path.display());
            } else {
                println!("{json}");
            }

            if let Some(output) = cmd.output.as_ref() {
                let recovery_options = RecoveryOptions {
                    source: primary_source,
                    destination: output.clone(),
                    overwrite: cmd.overwrite,
                    preserve_paths: false,
                };
                let recovered = recover_files(&report.findings, &recovery_options)?;
                println!("recovered {} files", recovered.len());
            }
        }
        Commands::Recover(cmd) => {
            let report_data = std::fs::read_to_string(&cmd.report).with_context(|| {
                format!(
                    "failed to read report JSON from {}",
                    cmd.report.to_string_lossy()
                )
            })?;
            let report: loki_data_forge_core::models::ScanReport =
                serde_json::from_str(&report_data)?;

            let options = RecoveryOptions {
                source: cmd.source,
                destination: cmd.output,
                overwrite: cmd.overwrite,
                preserve_paths: cmd.preserve_paths,
            };

            let recovered = recover_files(&report.findings, &options)?;
            println!("recovered {} file(s)", recovered.len());
        }
        Commands::Reconstruct(cmd) => {
            if cmd.member.is_empty() {
                anyhow::bail!("at least one --member entry is required");
            }

            let mode = match cmd.mode.as_str() {
                "raid0" => RaidMode::Raid0,
                "raid1" => RaidMode::Raid1,
                "raid5" => RaidMode::Raid5,
                _ => anyhow::bail!("unsupported reconstruction mode"),
            };

            let parity_layout = match cmd.parity_layout.as_str() {
                "left_symmetric" => RaidParityLayout::LeftSymmetric,
                "right_symmetric" => RaidParityLayout::RightSymmetric,
                "left_asymmetric" => RaidParityLayout::LeftAsymmetric,
                "right_asymmetric" => RaidParityLayout::RightAsymmetric,
                _ => RaidParityLayout::Unknown,
            };

            let members = cmd
                .member
                .iter()
                .map(|member| {
                    let normalized = member.trim();
                    if normalized.eq_ignore_ascii_case("missing")
                        || normalized.eq_ignore_ascii_case("none")
                        || normalized == "-"
                    {
                        None
                    } else {
                        Some(PathBuf::from(normalized))
                    }
                })
                .collect::<Vec<_>>();

            let report = reconstruct_array(&RaidReconstructOptions {
                mode,
                stripe_size: cmd.stripe_size,
                members,
                output: cmd.output,
                parity_layout,
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Mount(cmd) => {
            let mounted = mount_container(&cmd.container)?;
            if cmd.json {
                println!("{}", serde_json::to_string_pretty(&mounted)?);
            } else {
                println!("container: {:?}", mounted.container_type);
                for e in mounted.entries {
                    println!("- {} ({} bytes)", e.name, e.size);
                }
            }
        }
        Commands::Signatures(cmd) => {
            let signatures = if let Some(path) = cmd.file {
                loki_data_forge_core::signatures::SignatureSet::from_json_file(&path)?
            } else {
                loki_data_forge_core::signatures::SignatureSet::builtin_for_profile(
                    SignatureProfile::Strict,
                )?
            };

            println!(
                "loaded {} signatures (max length: {} bytes)",
                signatures.signatures().len(),
                signatures.max_len
            );
        }
        Commands::Smart(cmd) => {
            println!(
                "SMART module placeholder for {} (TODO: platform smartctl and NVMe health integration)",
                cmd.device.display()
            );
        }
        Commands::Image(cmd) => {
            println!(
                "Imaging placeholder: source={} output={} (TODO: ddrescue-style bad-sector map)",
                cmd.source.display(),
                cmd.output.display()
            );
        }
        Commands::Hex(cmd) => {
            const MAX_HEX_READ: u64 = 16 * 1024 * 1024;
            let mut file = std::fs::File::open(&cmd.source)?;
            let file_len = file.metadata()?.len();
            let start = cmd.offset.min(file_len);
            let read_len = cmd
                .length
                .min(file_len.saturating_sub(start))
                .min(MAX_HEX_READ);
            file.seek(std::io::SeekFrom::Start(start))?;
            let mut slice = vec![0u8; read_len as usize];
            if read_len > 0 {
                file.read_exact(&mut slice)?;
            }
            println!("{}", hex_dump(&slice, start));
        }
        Commands::Gui => {
            // Handled by the unified binary (tauri app).
        }
    }

    Ok(CliExecution::Executed)
}

fn resolve_scan_sources(cmd: &commands::ScanArgs) -> anyhow::Result<Vec<PathBuf>> {
    let mut sources = Vec::new();
    if let Some(drive) = cmd.drive.clone() {
        sources.push(drive);
    }
    sources.extend(cmd.sources.clone());

    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for source in sources {
        let key = normalize_source_key(&source);
        if seen.insert(key) {
            deduped.push(source);
        }
    }

    if deduped.is_empty() {
        anyhow::bail!("at least one --drive or --source path is required");
    }
    Ok(deduped)
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

fn validate_bypass_flags(
    case_id: &Option<String>,
    legal_authority: &Option<String>,
) -> anyhow::Result<()> {
    if case_id.as_deref().unwrap_or_default().trim().is_empty() {
        anyhow::bail!("--enable-bypass requires --case-id");
    }
    if legal_authority
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        anyhow::bail!("--enable-bypass requires --legal-authority");
    }
    Ok(())
}

fn append_bypass_audit_event(
    targets: &[PathBuf],
    case_id: Option<&str>,
    legal_authority: Option<&str>,
    accepted: bool,
    rejection_reason: Option<String>,
) -> anyhow::Result<()> {
    let payload = serde_json::json!({
        "targets": targets
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        "case_id": case_id.unwrap_or(""),
        "legal_authority": legal_authority.unwrap_or(""),
        "accepted": accepted,
        "rejection_reason": rejection_reason,
    });

    append_security_audit_event("bypass_request", payload)
}

fn append_unlock_audit_event(
    targets: &[PathBuf],
    provider: &str,
    accepted: bool,
    rejection_reason: Option<&str>,
) -> anyhow::Result<()> {
    let payload = serde_json::json!({
        "targets": targets
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        "provider": provider,
        "accepted": accepted,
        "rejection_reason": rejection_reason,
    });
    append_security_audit_event("unlock_request", payload)
}

fn append_security_audit_event(event_type: &str, payload: serde_json::Value) -> anyhow::Result<()> {
    let path = PathBuf::from(".loki-data-forge-audit.log");
    let previous_hash = read_last_entry_hash(&path).unwrap_or_else(|| "genesis".to_string());

    let envelope = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event_type": event_type,
        "payload": payload,
        "prev_hash": previous_hash,
    });

    let envelope_serialized = serde_json::to_string(&envelope)?;
    let mut hasher = Sha256::new();
    hasher.update(envelope_serialized.as_bytes());
    let entry_hash = format!("{:x}", hasher.finalize());
    let (signature, signature_mode) = compute_audit_signature(&entry_hash, &envelope_serialized);

    let entry = serde_json::json!({
        "envelope": envelope,
        "entry_hash": entry_hash,
        "signature": signature,
        "signature_mode": signature_mode,
    });

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    use std::io::Write;
    writeln!(file, "{}", serde_json::to_string(&entry)?)?;
    Ok(())
}

fn compute_audit_signature(entry_hash: &str, envelope: &str) -> (String, &'static str) {
    const SIGNING_KEY_ENV: &str = "LOKI_AUDIT_SIGNING_KEY";
    if let Ok(key) = std::env::var(SIGNING_KEY_ENV)
        && !key.trim().is_empty()
    {
        let mut hasher = Sha256::new();
        hasher.update(b"keyed-sha256-v1|");
        hasher.update(key.as_bytes());
        hasher.update(b"|");
        hasher.update(entry_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(envelope.as_bytes());
        return (format!("{:x}", hasher.finalize()), "keyed-sha256-v1");
    }

    let mut hasher = Sha256::new();
    hasher.update(b"hash-chain-sha256-v1|");
    hasher.update(entry_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(envelope.as_bytes());
    (format!("{:x}", hasher.finalize()), "hash-chain-sha256-v1")
}

fn read_last_entry_hash(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let last_line = content.lines().rev().find(|line| !line.trim().is_empty())?;
    let parsed: serde_json::Value = serde_json::from_str(last_line).ok()?;
    parsed
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

fn hex_dump(bytes: &[u8], start_offset: u64) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
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

pub fn default_scan_output_path(source: &std::path::Path) -> PathBuf {
    let stem = source
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("scan");
    PathBuf::from(format!("{stem}.loki-data-forge.scan.json"))
}

#[cfg(test)]
mod tests {
    use super::{commands::ScanArgs, resolve_scan_sources};

    #[test]
    fn should_run_cli_accepts_global_log_before_subcommand() {
        let args = vec![
            "loki-data-forge".to_string(),
            "--log".to_string(),
            "debug".to_string(),
            "scan".to_string(),
            "--drive".to_string(),
            "/dev/null".to_string(),
        ];
        assert!(super::should_run_cli(&args));
    }

    #[test]
    fn should_run_cli_rejects_missing_subcommand() {
        let args = vec![
            "loki-data-forge".to_string(),
            "--log".to_string(),
            "debug".to_string(),
        ];
        assert!(!super::should_run_cli(&args));
    }

    #[test]
    fn should_run_cli_accepts_source_without_drive() {
        let args = vec![
            "loki-data-forge".to_string(),
            "scan".to_string(),
            "--source".to_string(),
            "/tmp/disk.img".to_string(),
        ];
        assert!(super::should_run_cli(&args));
    }

    #[test]
    fn resolve_scan_sources_deduplicates_drive_and_sources() {
        let args = ScanArgs {
            drive: Some("/tmp/a.img".into()),
            sources: vec!["/tmp/a.img".into(), "/tmp/b.img".into()],
            mode: "hybrid".to_string(),
            threads: 2,
            chunk_size: 1024,
            max_carve_size: 2048,
            output: None,
            report: None,
            overwrite: false,
            read_write: false,
            synology_mode: false,
            skip_containers: false,
            strict_containers: false,
            signature_profile: "strict".to_string(),
            encryption_detect_only: false,
            unlock_with: None,
            enable_bypass: false,
            case_id: None,
            legal_authority: None,
            adapter_policy: "hybrid".to_string(),
            quiet: false,
        };

        let resolved = resolve_scan_sources(&args).expect("sources");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], std::path::PathBuf::from("/tmp/a.img"));
        assert_eq!(resolved[1], std::path::PathBuf::from("/tmp/b.img"));
    }

    #[test]
    fn reconstruct_command_is_recognized() {
        let args = vec![
            "loki-data-forge".to_string(),
            "reconstruct".to_string(),
            "--mode".to_string(),
            "raid1".to_string(),
            "--member".to_string(),
            "/tmp/member0.img".to_string(),
            "--output".to_string(),
            "/tmp/out.img".to_string(),
        ];
        assert!(super::should_run_cli(&args));
    }

    #[test]
    fn bypass_validation_requires_case_and_authority() {
        assert!(super::validate_bypass_flags(&None, &None).is_err());
        assert!(super::validate_bypass_flags(&Some("CASE-1".to_string()), &None).is_err());
        assert!(super::validate_bypass_flags(&None, &Some("Warrant".to_string())).is_err());
        assert!(
            super::validate_bypass_flags(&Some("CASE-1".to_string()), &Some("Warrant".to_string()))
                .is_ok()
        );
    }
}
