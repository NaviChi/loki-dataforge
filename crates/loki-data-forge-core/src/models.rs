use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Quick,
    Deep,
    Hybrid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContainerErrorPolicy {
    #[default]
    WarnAndSkip,
    StrictFail,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureProfile {
    #[default]
    Strict,
    Broad,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionPolicy {
    #[default]
    DetectOnly,
    UnlockWithProvider {
        provider: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdapterPolicy {
    NativeOnly,
    #[default]
    Hybrid,
    ExternalPreferred,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum VolumeLayer {
    #[default]
    Physical,
    RaidVirtual,
    EncryptedVolume,
    Filesystem,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionState {
    #[default]
    Unknown,
    Unencrypted,
    EncryptedDetected,
    Unlocked,
    BypassRequired,
    BypassAttempted,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReconstructionContext {
    #[serde(default)]
    pub volume_layer: VolumeLayer,
    #[serde(default)]
    pub reconstructed_path: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub source: PathBuf,
    #[serde(default)]
    pub sources: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    pub mode: ScanMode,
    pub threads: usize,
    pub chunk_size: usize,
    pub max_carve_size: u64,
    pub read_only: bool,
    pub synology_mode: bool,
    pub include_container_scan: bool,
    #[serde(default)]
    pub container_error_policy: ContainerErrorPolicy,
    #[serde(default)]
    pub signature_profile: SignatureProfile,
    #[serde(default)]
    pub encryption_policy: EncryptionPolicy,
    #[serde(default)]
    pub adapter_policy: AdapterPolicy,
    #[serde(default)]
    pub enable_bypass: bool,
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub legal_authority: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            source: PathBuf::new(),
            sources: Vec::new(),
            output: None,
            mode: ScanMode::Hybrid,
            threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            chunk_size: 8 * 1024 * 1024,
            max_carve_size: 16 * 1024 * 1024,
            read_only: true,
            synology_mode: false,
            include_container_scan: true,
            container_error_policy: ContainerErrorPolicy::WarnAndSkip,
            signature_profile: SignatureProfile::Strict,
            encryption_policy: EncryptionPolicy::DetectOnly,
            adapter_policy: AdapterPolicy::Hybrid,
            enable_bypass: false,
            case_id: None,
            legal_authority: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryOptions {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub overwrite: bool,
    pub preserve_paths: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundFile {
    pub id: String,
    pub display_name: String,
    pub extension: String,
    pub signature_id: String,
    pub source_path: PathBuf,
    #[serde(default)]
    pub source_fingerprint: String,
    #[serde(default)]
    pub evidence_path: PathBuf,
    pub container_path: Option<String>,
    pub offset: u64,
    pub size: u64,
    pub confidence: f32,
    #[serde(default = "default_validation_score")]
    pub validation_score: f32,
    pub category: String,
    pub encrypted: bool,
    #[serde(default)]
    pub encryption_state: EncryptionState,
    #[serde(default)]
    pub reconstruction_context: Option<ReconstructionContext>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    pub source_id: String,
    pub output_path: PathBuf,
    pub bytes_written: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub source: PathBuf,
    #[serde(default)]
    pub sources: Vec<PathBuf>,
    pub mode: ScanMode,
    pub findings: Vec<FoundFile>,
    pub warnings: Vec<String>,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanMetadata {
    pub bytes_scanned: u64,
    pub elapsed_ms: u128,
    pub quick_hits: usize,
    pub deep_hits: usize,
    pub container_hits: usize,
    pub container_type: Option<ContainerType>,
    #[serde(default)]
    pub volume_layers: Vec<VolumeLayer>,
    #[serde(default)]
    pub adapter_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub phase: String,
    pub percent: u8,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub eta_seconds: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerType {
    Vmdk,
    Vhdx,
    Vhd,
    Qcow2,
    Vdi,
    Ova,
    Vpk,
    Wim,
    AcronisTib,
    AcronisTibx,
    Bak,
    SqlDump,
    Archive,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualContainer {
    pub source: PathBuf,
    pub container_type: ContainerType,
    pub entries: Vec<VirtualEntry>,
    pub descriptor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualEntry {
    pub name: String,
    pub path_hint: Option<PathBuf>,
    pub offset: u64,
    pub size: u64,
    pub encrypted: bool,
    pub archive_index: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDefinition {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub magic: String,
    pub offset: u64,
    pub category: String,
    pub description: Option<String>,
    pub default_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionProfile {
    BitLocker,
    Luks,
    FileVault,
    SynologyRkey,
}

fn default_validation_score() -> f32 {
    0.0
}
