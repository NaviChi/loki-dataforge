use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::models::AdapterPolicy;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterDomain {
    Filesystem,
    Encryption,
    Raid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterCapability {
    pub domain: AdapterDomain,
    pub name: String,
    pub source: String,
    pub available: bool,
    pub version: Option<String>,
    pub pinned_version: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AdapterRegistry {
    policy: AdapterPolicy,
    pinned_external_tools: Vec<PinnedTool>,
}

#[derive(Debug, Clone)]
struct PinnedTool {
    domain: AdapterDomain,
    name: &'static str,
    command: &'static str,
    args: &'static [&'static str],
    pinned_prefix: &'static str,
}

impl AdapterRegistry {
    pub fn new(policy: AdapterPolicy) -> Self {
        Self {
            policy,
            pinned_external_tools: vec![
                PinnedTool {
                    domain: AdapterDomain::Filesystem,
                    name: "sleuthkit-fls",
                    command: "fls",
                    args: &["-V"],
                    pinned_prefix: "The Sleuth Kit ver",
                },
                PinnedTool {
                    domain: AdapterDomain::Encryption,
                    name: "libbde-bdemount",
                    command: "bdemount",
                    args: &["-V"],
                    pinned_prefix: "bdemount",
                },
                PinnedTool {
                    domain: AdapterDomain::Encryption,
                    name: "cryptsetup",
                    command: "cryptsetup",
                    args: &["--version"],
                    pinned_prefix: "cryptsetup",
                },
                PinnedTool {
                    domain: AdapterDomain::Raid,
                    name: "mdadm",
                    command: "mdadm",
                    args: &["--version"],
                    pinned_prefix: "mdadm",
                },
            ],
        }
    }

    pub fn probe(&self, _sources: &[PathBuf]) -> Vec<AdapterCapability> {
        let mut out = vec![AdapterCapability {
            domain: AdapterDomain::Filesystem,
            name: "native-core".to_string(),
            source: "internal".to_string(),
            available: true,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            pinned_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            notes: Some("Rust-native recovery engine".to_string()),
        }];

        if matches!(self.policy, AdapterPolicy::NativeOnly) {
            return out;
        }

        out.extend(self.pinned_external_tools.iter().map(probe_tool));

        if matches!(self.policy, AdapterPolicy::ExternalPreferred) {
            out.push(AdapterCapability {
                domain: AdapterDomain::Filesystem,
                name: "adapter-policy".to_string(),
                source: "policy".to_string(),
                available: true,
                version: None,
                pinned_version: None,
                notes: Some("external adapters are preferred when available".to_string()),
            });
        }

        out
    }
}

pub fn summarize_capabilities(capabilities: &[AdapterCapability]) -> Vec<String> {
    let mut warnings = Vec::new();

    for cap in capabilities {
        if cap.available {
            continue;
        }
        warnings.push(format!(
            "Adapter '{}' unavailable ({}){}",
            cap.name,
            cap.source,
            cap.notes
                .as_deref()
                .map(|n| format!(": {n}"))
                .unwrap_or_default()
        ));
    }

    warnings
}

fn probe_tool(tool: &PinnedTool) -> AdapterCapability {
    match run_version(tool.command, tool.args) {
        Ok(output) => {
            let is_pinned = output.starts_with(tool.pinned_prefix);
            AdapterCapability {
                domain: tool.domain,
                name: tool.name.to_string(),
                source: "external".to_string(),
                available: true,
                version: Some(output.clone()),
                pinned_version: Some(tool.pinned_prefix.to_string()),
                notes: if is_pinned {
                    None
                } else {
                    Some("version output did not match pinned prefix".to_string())
                },
            }
        }
        Err(err) => AdapterCapability {
            domain: tool.domain,
            name: tool.name.to_string(),
            source: "external".to_string(),
            available: false,
            version: None,
            pinned_version: Some(tool.pinned_prefix.to_string()),
            notes: Some(err),
        },
    }
}

fn run_version(command: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|err| format!("command failed: {err}"))?;

    if !output.status.success() {
        return Err(format!("exit status {}", output.status));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return Ok(stdout);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return Ok(stderr);
    }

    Ok("unknown-version".to_string())
}

pub fn canonical_tool_path(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{AdapterPolicy, AdapterRegistry};

    #[test]
    fn native_only_registry_returns_internal_capability() {
        let registry = AdapterRegistry::new(AdapterPolicy::NativeOnly);
        let caps = registry.probe(&[]);
        assert!(caps.iter().any(|c| c.name == "native-core" && c.available));
        assert_eq!(caps.len(), 1);
    }
}
