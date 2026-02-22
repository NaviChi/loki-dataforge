use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{LokiDataForgeError, Result};
use crate::parsers::raid_metadata::{RaidFamilyHint, probe_raid_metadata};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RaidMode {
    Raid0,
    Raid1,
    Raid5,
    Raid6,
    Raid10,
    Jbod,
    SynologyShr,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RaidController {
    Mdadm,
    SynologyShr,
    WindowsDynamic,
    WindowsStorageSpaces,
    HardwareDdf,
    AppleRaid,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RaidParityLayout {
    LeftSymmetric,
    RightSymmetric,
    LeftAsymmetric,
    RightAsymmetric,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidLayout {
    pub mode: RaidMode,
    pub chunk_size: u64,
    pub disk_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidMemberInfo {
    pub source_path: PathBuf,
    pub member_index: Option<usize>,
    pub array_id: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaidDetectionReport {
    pub detected: bool,
    pub controller: RaidController,
    pub mode: Option<RaidMode>,
    pub stripe_size: Option<u64>,
    pub parity_layout: Option<RaidParityLayout>,
    pub expected_members: usize,
    pub detected_members: usize,
    pub missing_members: Vec<String>,
    pub degraded: bool,
    pub members: Vec<RaidMemberInfo>,
    pub notes: Vec<String>,
}

pub fn default_shr_layout(disks: usize) -> RaidLayout {
    RaidLayout {
        mode: RaidMode::SynologyShr,
        chunk_size: 64 * 1024,
        disk_count: disks,
    }
}

pub fn detect_raid_configuration(inputs: &[PathBuf]) -> Result<RaidDetectionReport> {
    if inputs.is_empty() {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "no input drives/images were provided for RAID detection".to_string(),
        ));
    }

    let mut probes = Vec::with_capacity(inputs.len());
    for input in inputs {
        if !input.exists() {
            return Err(LokiDataForgeError::MissingPath(input.clone()));
        }
        probes.push(probe_raid_metadata(input)?);
    }

    let controller = dominant_controller(&probes);
    let detected = controller != RaidController::Unknown;

    let mode = dominant_mode(&probes, controller);
    let stripe_size = probes.iter().filter_map(|p| p.stripe_size).max();
    let parity_layout = dominant_parity_layout(&probes);

    let expected_members = probes
        .iter()
        .filter_map(|p| p.expected_members)
        .max()
        .unwrap_or(inputs.len())
        .max(inputs.len());

    let detected_members = inputs.len();
    let missing_members = compute_missing_members(&probes, expected_members, detected_members);
    let degraded = !missing_members.is_empty();

    let mut notes = Vec::new();
    for probe in &probes {
        notes.extend(probe.notes.clone());
    }

    if degraded {
        notes.push(format!(
            "Some RAID members are missing ({} of {} detected)",
            detected_members, expected_members
        ));
    }

    let members = probes
        .into_iter()
        .map(|p| RaidMemberInfo {
            source_path: p.path,
            member_index: p.member_index,
            array_id: p.array_id,
            notes: p.notes,
        })
        .collect::<Vec<_>>();

    Ok(RaidDetectionReport {
        detected,
        controller,
        mode,
        stripe_size,
        parity_layout,
        expected_members,
        detected_members,
        missing_members,
        degraded,
        members,
        notes,
    })
}

fn dominant_controller(
    probes: &[crate::parsers::raid_metadata::RaidMetadataProbe],
) -> RaidController {
    let mut counts: HashMap<RaidController, usize> = HashMap::new();

    for probe in probes {
        let controller = match probe.family {
            RaidFamilyHint::Mdadm => RaidController::Mdadm,
            RaidFamilyHint::SynologyShr => RaidController::SynologyShr,
            RaidFamilyHint::WindowsDynamic => RaidController::WindowsDynamic,
            RaidFamilyHint::WindowsStorageSpaces => RaidController::WindowsStorageSpaces,
            RaidFamilyHint::HardwareDdf => RaidController::HardwareDdf,
            RaidFamilyHint::AppleRaid => RaidController::AppleRaid,
            RaidFamilyHint::Unknown => RaidController::Unknown,
        };

        *counts.entry(controller).or_insert(0) += 1;
    }

    counts
        .into_iter()
        .filter(|(controller, _)| *controller != RaidController::Unknown)
        .max_by_key(|(_, count)| *count)
        .map(|(controller, _)| controller)
        .unwrap_or(RaidController::Unknown)
}

fn dominant_mode(
    probes: &[crate::parsers::raid_metadata::RaidMetadataProbe],
    controller: RaidController,
) -> Option<RaidMode> {
    if controller == RaidController::SynologyShr {
        return Some(RaidMode::SynologyShr);
    }

    let mut counts: HashMap<RaidMode, usize> = HashMap::new();
    for probe in probes {
        if let Some(level_code) = probe.level_code
            && let Some(mode) = mode_from_level_code(level_code)
        {
            *counts.entry(mode).or_insert(0) += 1;
        }
    }

    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(mode, _)| mode)
}

fn dominant_parity_layout(
    probes: &[crate::parsers::raid_metadata::RaidMetadataProbe],
) -> Option<RaidParityLayout> {
    let mut counts: HashMap<RaidParityLayout, usize> = HashMap::new();

    for probe in probes {
        if let Some(layout_code) = probe.parity_layout_code {
            let layout = parity_from_code(layout_code);
            *counts.entry(layout).or_insert(0) += 1;
        }
    }

    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(layout, _)| layout)
}

fn compute_missing_members(
    probes: &[crate::parsers::raid_metadata::RaidMetadataProbe],
    expected_members: usize,
    detected_members: usize,
) -> Vec<String> {
    if expected_members <= detected_members {
        return Vec::new();
    }

    let indexed_members = probes
        .iter()
        .filter_map(|p| p.member_index)
        .collect::<std::collections::HashSet<_>>();

    if !indexed_members.is_empty() {
        return (0..expected_members)
            .filter(|slot| !indexed_members.contains(slot))
            .map(|slot| format!("Missing member slot #{slot}"))
            .collect();
    }

    ((detected_members + 1)..=expected_members)
        .map(|member| format!("Missing member #{member}"))
        .collect()
}

fn mode_from_level_code(level: i32) -> Option<RaidMode> {
    match level {
        0 => Some(RaidMode::Raid0),
        1 => Some(RaidMode::Raid1),
        5 => Some(RaidMode::Raid5),
        6 => Some(RaidMode::Raid6),
        10 => Some(RaidMode::Raid10),
        -1 => Some(RaidMode::Jbod),
        _ => None,
    }
}

fn parity_from_code(layout: u32) -> RaidParityLayout {
    match layout {
        0 => RaidParityLayout::LeftAsymmetric,
        1 => RaidParityLayout::RightAsymmetric,
        2 => RaidParityLayout::LeftSymmetric,
        3 => RaidParityLayout::RightSymmetric,
        _ => RaidParityLayout::Unknown,
    }
}

// TODO: expand parity reconstruction engine for incomplete arrays and mixed-vdev SHR transforms.
