use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, LokiDataForgeError>;

#[derive(Debug, Error)]
pub enum LokiDataForgeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("input path does not exist: {0}")]
    MissingPath(PathBuf),

    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("invalid signature database: {0}")]
    InvalidSignatureDb(String),

    #[error("unsafe recovery target: {0}")]
    UnsafeDestination(String),

    #[error("invalid scan options: {0}")]
    InvalidScanOptions(String),

    #[error("container parse error: {0}")]
    ContainerParse(String),

    #[error("command failed: {0}")]
    Command(String),
}
