use std::io::Write;

use loki_data_forge_core::models::{ContainerType, ScanMode, ScanOptions};
use loki_data_forge_core::raid::{RaidController, RaidMode, detect_raid_configuration};
use loki_data_forge_core::scan::run_scan;
use loki_data_forge_core::virtual_mount::{detect_container, mount_container};

#[tokio::test]
async fn deep_scan_finds_jpeg_signature() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("sample.img");

    let mut f = std::fs::File::create(&path).expect("create sample file");
    f.write_all(&[0u8; 4096]).expect("write zeros");
    f.write_all(&[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46])
        .expect("write jpeg header");
    f.write_all(&[0u8; 4096]).expect("write tail");

    let opts = ScanOptions {
        source: path.clone(),
        mode: ScanMode::Deep,
        include_container_scan: false,
        ..ScanOptions::default()
    };

    let report = run_scan(opts, None).await.expect("scan should succeed");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.signature_id == "sig-common-0001" || f.signature_id == "sig-common-0002"),
        "expected JPEG signature in findings"
    );
}

#[test]
fn detects_vhd_footer() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("disk.vhd");

    let mut buf = vec![0u8; 4096];
    let footer_start = buf.len() - 512;
    buf[footer_start..footer_start + 8].copy_from_slice(b"conectix");
    std::fs::write(&path, buf).expect("write vhd sample");

    let detected = detect_container(&path).expect("detect container");
    assert_eq!(detected, ContainerType::Vhd);
}

#[test]
fn mounts_vmdk_descriptor_extents() {
    let dir = tempfile::tempdir().expect("temp dir");
    let descriptor = dir.path().join("disk.vmdk");
    let extent = dir.path().join("disk-flat.vmdk");

    std::fs::write(&extent, vec![0u8; 1024 * 1024]).expect("write extent");

    let text = r#"# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"monolithicFlat\"

RW 2048 FLAT \"disk-flat.vmdk\" 0
"#;

    std::fs::write(&descriptor, text).expect("write descriptor");

    let mounted = mount_container(&descriptor).expect("mount vmdk");
    assert_eq!(mounted.container_type, ContainerType::Vmdk);
    assert!(!mounted.entries.is_empty());
    assert!(
        mounted
            .entries
            .iter()
            .any(|e| e.name.contains("disk-flat.vmdk")),
        "expected extent entry"
    );
}

#[test]
fn mounts_qcow2_header() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("disk.qcow2");

    let mut hdr = vec![0u8; 72];
    hdr[0..4].copy_from_slice(b"QFI\xfb");
    hdr[4..8].copy_from_slice(&3u32.to_be_bytes());
    hdr[24..32].copy_from_slice(&(32_u64 * 1024 * 1024).to_be_bytes());
    std::fs::write(&path, hdr).expect("write qcow2");

    let mounted = mount_container(&path).expect("mount qcow2");
    assert_eq!(mounted.container_type, ContainerType::Qcow2);
    assert!(mounted.descriptor.unwrap_or_default().contains("version=3"));
}

#[test]
fn mounts_zip_archive_entries() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("sample.zip");

    let f = std::fs::File::create(&path).expect("create zip");
    let mut zip = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default();
    zip.start_file("inside.txt", opts).expect("start zip file");
    zip.write_all(b"hello").expect("write zip payload");
    zip.finish().expect("finish zip");

    let mounted = mount_container(&path).expect("mount zip");
    assert_eq!(mounted.container_type, ContainerType::Archive);
    assert!(mounted.entries.iter().any(|e| e.name == "inside.txt"));
}

#[test]
fn detects_incomplete_mdadm_raid_and_missing_slot() {
    let dir = tempfile::tempdir().expect("temp dir");
    let disk0 = dir.path().join("member0.img");
    let disk2 = dir.path().join("member2.img");

    write_fake_mdadm_member(&disk0, 0, 3, 5);
    write_fake_mdadm_member(&disk2, 2, 3, 5);

    let report = detect_raid_configuration(&[disk0, disk2]).expect("raid detection should work");
    assert_eq!(report.controller, RaidController::Mdadm);
    assert_eq!(report.mode, Some(RaidMode::Raid5));
    assert_eq!(report.expected_members, 3);
    assert_eq!(report.detected_members, 2);
    assert!(report.degraded);
    assert!(
        report.missing_members.iter().any(|m| m.contains("slot #1")),
        "missing slot should be identified"
    );
}

#[tokio::test]
async fn directory_scan_reports_findings_from_multiple_files() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("tree");
    std::fs::create_dir_all(&root).expect("scan root");

    let file_a = root.join("a.img");
    let file_b = root.join("b.img");

    std::fs::write(
        &file_a,
        [vec![0u8; 128], vec![0xff, 0xd8, 0xff, 0xe0], vec![0u8; 128]].concat(),
    )
    .expect("file a");
    std::fs::write(
        &file_b,
        [vec![0u8; 256], vec![0xff, 0xd8, 0xff, 0xe0], vec![0u8; 64]].concat(),
    )
    .expect("file b");

    let opts = ScanOptions {
        source: root.clone(),
        mode: ScanMode::Deep,
        include_container_scan: false,
        ..ScanOptions::default()
    };
    let report = run_scan(opts, None).await.expect("scan should succeed");
    let unique_sources = report
        .findings
        .iter()
        .map(|f| f.source_path.clone())
        .collect::<std::collections::HashSet<_>>();
    assert!(
        unique_sources.contains(&file_a) && unique_sources.contains(&file_b),
        "expected findings from both files in the directory source"
    );
}

#[test]
fn mounts_vhdx_header() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("disk.vhdx");

    let mut hdr = vec![0u8; 4096];
    hdr[0..8].copy_from_slice(b"vhdxfile");
    std::fs::write(&path, hdr).expect("write vhdx");

    let mounted = mount_container(&path).expect("mount vhdx");
    assert_eq!(mounted.container_type, ContainerType::Vhdx);
}

#[test]
fn parses_vpk_v2_embedded_offsets() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("pak01_dir.vpk");

    let mut tree = Vec::new();
    tree.extend_from_slice(b"txt\0");
    tree.extend_from_slice(b" \0");
    tree.extend_from_slice(b"file\0");
    tree.extend_from_slice(&0u32.to_le_bytes()); // crc
    tree.extend_from_slice(&0u16.to_le_bytes()); // preload bytes
    tree.extend_from_slice(&0x7fffu16.to_le_bytes()); // embedded in dir file
    tree.extend_from_slice(&0u32.to_le_bytes()); // entry offset
    tree.extend_from_slice(&5u32.to_le_bytes()); // entry length
    tree.extend_from_slice(&0xffffu16.to_le_bytes()); // terminator
    tree.extend_from_slice(b"\0"); // end filenames
    tree.extend_from_slice(b"\0"); // end paths
    tree.extend_from_slice(b"\0"); // end extensions

    let mut header = Vec::new();
    header.extend_from_slice(&0x55AA1234u32.to_le_bytes());
    header.extend_from_slice(&2u32.to_le_bytes()); // version
    header.extend_from_slice(&(tree.len() as u32).to_le_bytes());
    header.extend_from_slice(&5u32.to_le_bytes()); // file_data_section_size
    header.extend_from_slice(&0u32.to_le_bytes()); // archive_md5_section_size
    header.extend_from_slice(&0u32.to_le_bytes()); // other_md5_section_size
    header.extend_from_slice(&0u32.to_le_bytes()); // signature_section_size

    let mut blob = Vec::new();
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&tree);
    blob.extend_from_slice(b"hello");
    std::fs::write(&path, blob).expect("write vpk");

    let mounted = mount_container(&path).expect("mount vpk v2");
    assert_eq!(mounted.container_type, ContainerType::Vpk);
    assert_eq!(mounted.entries.len(), 1);
    assert_eq!(mounted.entries[0].name, "file.txt");
    assert_eq!(mounted.entries[0].offset, 28 + tree.len() as u64);
    assert_eq!(mounted.entries[0].size, 5);
}

fn write_fake_mdadm_member(path: &std::path::Path, member_index: u32, expected: u32, level: i32) {
    let mut buf = vec![0u8; 8192];
    let base = 4096usize;
    buf[base..base + 4].copy_from_slice(&[0xfc, 0x4e, 0x2b, 0xa9]); // mdadm magic
    buf[base + 0x48..base + 0x4c].copy_from_slice(&level.to_le_bytes());
    buf[base + 0x58..base + 0x5c].copy_from_slice(&64u32.to_le_bytes()); // 64 KiB stripe
    buf[base + 0x5c..base + 0x60].copy_from_slice(&expected.to_le_bytes());
    buf[base + 0x90..base + 0x94].copy_from_slice(&member_index.to_le_bytes());
    buf[base + 0x20..base + 0x2a].copy_from_slice(b"md-test-0\0");
    std::fs::write(path, buf).expect("write test mdadm member");
}
