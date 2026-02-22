use std::io::Write;
use std::path::PathBuf;

use loki_data_forge_core::models::{ContainerErrorPolicy, ScanMode, ScanOptions, VolumeLayer};
use loki_data_forge_core::scan::run_scan;

#[cfg(unix)]
#[tokio::test]
async fn accepts_raw_device_like_path_dev_null() {
    let opts = ScanOptions {
        source: PathBuf::from("/dev/null"),
        mode: ScanMode::Deep,
        include_container_scan: false,
        ..ScanOptions::default()
    };

    let report = run_scan(opts, None).await.expect("scan /dev/null");
    assert!(report.findings.is_empty());
}

#[tokio::test]
async fn malformed_container_is_warning_with_default_policy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("bad.zip");
    std::fs::write(&path, b"not-a-valid-zip").expect("write bad zip");

    let opts = ScanOptions {
        source: path,
        mode: ScanMode::Deep,
        include_container_scan: true,
        ..ScanOptions::default()
    };

    let report = run_scan(opts, None).await.expect("scan should continue");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("Container parse skipped")),
        "expected warning for malformed container"
    );
}

#[tokio::test]
async fn malformed_container_fails_in_strict_policy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("bad.zip");
    std::fs::write(&path, b"not-a-valid-zip").expect("write bad zip");

    let opts = ScanOptions {
        source: path,
        mode: ScanMode::Deep,
        include_container_scan: true,
        container_error_policy: ContainerErrorPolicy::StrictFail,
        ..ScanOptions::default()
    };

    let err = run_scan(opts, None)
        .await
        .expect_err("strict mode should fail");
    assert!(err.to_string().contains("ZIP open failed"));
}

#[tokio::test]
async fn finding_ids_are_unique_across_sources_with_same_offsets() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("tree");
    std::fs::create_dir_all(&root).expect("root");

    let file_a = root.join("a.img");
    let file_b = root.join("b.img");

    let mut payload = vec![0u8; 128];
    payload.extend_from_slice(&[0xff, 0xd8, 0xff, 0xe0]);
    payload.extend_from_slice(&[0u8; 128]);

    std::fs::write(&file_a, &payload).expect("file a");
    std::fs::write(&file_b, &payload).expect("file b");

    let opts = ScanOptions {
        source: root,
        mode: ScanMode::Deep,
        include_container_scan: false,
        ..ScanOptions::default()
    };

    let report = run_scan(opts, None).await.expect("scan");
    let unique_ids = report
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(
        unique_ids.len(),
        report.findings.len(),
        "finding IDs should be globally unique"
    );
}

#[tokio::test]
async fn strict_signature_profile_excludes_generated_signatures() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("noise.img");

    let mut f = std::fs::File::create(&path).expect("noise file");
    f.write_all(&[0u8; 4 * 1024]).expect("write noise");

    let opts = ScanOptions {
        source: path,
        mode: ScanMode::Deep,
        include_container_scan: false,
        ..ScanOptions::default()
    };

    let report = run_scan(opts, None).await.expect("scan");
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.signature_id.starts_with("sig-generated-")),
        "strict profile should not emit generated signatures"
    );
}

#[tokio::test]
async fn multi_source_scan_sets_raid_virtual_layer_when_detected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let disk0 = dir.path().join("member0.img");
    let disk1 = dir.path().join("member1.img");
    write_fake_mdadm_member(&disk0, 0, 2, 1);
    write_fake_mdadm_member(&disk1, 1, 2, 1);

    let opts = ScanOptions {
        source: disk0.clone(),
        sources: vec![disk0, disk1],
        mode: ScanMode::Quick,
        include_container_scan: false,
        ..ScanOptions::default()
    };

    let report = run_scan(opts, None).await.expect("scan");
    assert!(
        report
            .metadata
            .volume_layers
            .contains(&VolumeLayer::RaidVirtual)
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("RAID topology detected")),
        "expected raid topology warning"
    );
}

fn write_fake_mdadm_member(path: &std::path::Path, member_index: u32, expected: u32, level: i32) {
    let mut buf = vec![0u8; 8192];
    let base = 4096usize;
    buf[base..base + 4].copy_from_slice(&[0xfc, 0x4e, 0x2b, 0xa9]);
    buf[base + 0x48..base + 0x4c].copy_from_slice(&level.to_le_bytes());
    buf[base + 0x58..base + 0x5c].copy_from_slice(&64u32.to_le_bytes());
    buf[base + 0x5c..base + 0x60].copy_from_slice(&expected.to_le_bytes());
    buf[base + 0x90..base + 0x94].copy_from_slice(&member_index.to_le_bytes());
    std::fs::write(path, buf).expect("write mdadm member");
}
