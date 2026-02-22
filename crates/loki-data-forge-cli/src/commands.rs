use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "loki-data-forge",
    version,
    about = "Loki Data Forge data recovery CLI",
    long_about = "Cross-platform data recovery toolkit with quick metadata scan, deep carving, and virtual container parsing"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, default_value = "info")]
    pub log: String,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan a drive/device/image and produce a recovery report
    Scan(ScanArgs),

    /// Recover files from an existing scan report
    Recover(RecoverArgs),

    /// Virtual-mount container formats like VMDK/VPK/OVA and inspect entries
    Mount(MountArgs),

    /// Validate/list signature database metadata
    Signatures(SignatureArgs),

    /// Query disk health (placeholder)
    Smart(SmartArgs),

    /// Create a forensic image (placeholder)
    Image(ImageArgs),

    /// Hex view helper
    Hex(HexArgs),

    /// Launch GUI mode (when compiled with gui feature)
    Gui,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[arg(long = "drive", value_name = "PATH")]
    pub drive: PathBuf,

    #[arg(long, default_value = "hybrid", value_parser = ["quick", "deep", "hybrid"])]
    pub mode: String,

    #[arg(long, default_value_t = default_threads())]
    pub threads: usize,

    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub chunk_size: usize,

    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub max_carve_size: u64,

    #[arg(long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,

    #[arg(long)]
    pub overwrite: bool,

    #[arg(long)]
    pub read_write: bool,

    #[arg(long)]
    pub synology_mode: bool,

    #[arg(long)]
    pub skip_containers: bool,

    #[arg(long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct RecoverArgs {
    #[arg(long, value_name = "SCAN_JSON")]
    pub report: PathBuf,

    #[arg(long, value_name = "SOURCE")]
    pub source: PathBuf,

    #[arg(long, value_name = "OUTPUT_DIR")]
    pub output: PathBuf,

    #[arg(long)]
    pub overwrite: bool,

    #[arg(long)]
    pub preserve_paths: bool,
}

#[derive(Debug, Args)]
pub struct MountArgs {
    #[arg(long, value_name = "FILE")]
    pub container: PathBuf,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SignatureArgs {
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SmartArgs {
    #[arg(long, value_name = "DEVICE")]
    pub device: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImageArgs {
    #[arg(long, value_name = "SOURCE")]
    pub source: PathBuf,

    #[arg(long, value_name = "OUTPUT")]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct HexArgs {
    #[arg(long, value_name = "SOURCE")]
    pub source: PathBuf,

    #[arg(long, default_value_t = 0)]
    pub offset: u64,

    #[arg(long, default_value_t = 256)]
    pub length: u64,
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
