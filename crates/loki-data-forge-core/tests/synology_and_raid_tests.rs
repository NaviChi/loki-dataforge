use loki_data_forge_core::models::ScanOptions;
use loki_data_forge_core::raid::{RaidController, detect_raid_configuration};
use loki_data_forge_core::synology::apply_synology_mode;

#[test]
fn synology_mode_adds_expected_warnings() {
    let options = ScanOptions {
        read_only: false,
        synology_mode: true,
        ..ScanOptions::default()
    };
    let mut warnings = Vec::new();
    apply_synology_mode(&options, &mut warnings);

    assert!(warnings.iter().any(|w| w.contains("Synology mode enabled")));
    assert!(warnings.iter().any(|w| w.contains("forced read-only")));
}

#[test]
fn detects_windows_dynamic_signatures() {
    let dir = tempfile::tempdir().expect("temp dir");
    let disk1 = dir.path().join("disk1.img");
    let disk2 = dir.path().join("disk2.img");
    std::fs::write(&disk1, b"....PRIVHEAD....").expect("disk1");
    std::fs::write(&disk2, b"....LDM_DATABASE....").expect("disk2");

    let report = detect_raid_configuration(&[disk1, disk2]).expect("raid detection");
    assert_eq!(report.controller, RaidController::WindowsDynamic);
    assert!(report.detected);
}

#[test]
fn detects_storage_spaces_signatures() {
    let dir = tempfile::tempdir().expect("temp dir");
    let disk1 = dir.path().join("space1.img");
    let disk2 = dir.path().join("space2.img");
    std::fs::write(&disk1, b"MSFT Storage Spaces metadata").expect("disk1");
    std::fs::write(&disk2, b"Storage Spaces").expect("disk2");

    let report = detect_raid_configuration(&[disk1, disk2]).expect("raid detection");
    assert_eq!(report.controller, RaidController::WindowsStorageSpaces);
    assert!(report.detected);
}
