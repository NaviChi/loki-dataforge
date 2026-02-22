pub mod commands;

use std::path::PathBuf;
use std::sync::Arc;
use std::{io::Read, io::Seek};

use anyhow::Context;
use clap::Parser;

use loki_data_forge_core::models::{ProgressUpdate, RecoveryOptions, ScanMode, ScanOptions};
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

    matches!(
        args[1].as_str(),
        "scan"
            | "recover"
            | "mount"
            | "signatures"
            | "smart"
            | "image"
            | "hex"
            | "gui"
            | "-h"
            | "--help"
            | "-V"
            | "--version"
    )
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
            let mode = match cmd.mode.as_str() {
                "quick" => ScanMode::Quick,
                "deep" => ScanMode::Deep,
                _ => ScanMode::Hybrid,
            };

            let scan_options = ScanOptions {
                source: cmd.drive.clone(),
                output: cmd.output.clone(),
                mode,
                threads: cmd.threads,
                chunk_size: cmd.chunk_size,
                max_carve_size: cmd.max_carve_size,
                read_only: !cmd.read_write,
                synology_mode: cmd.synology_mode,
                include_container_scan: !cmd.skip_containers,
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
                    source: cmd.drive,
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
                loki_data_forge_core::signatures::SignatureSet::builtin()?
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
