use std::path::Path;

use loki_data_forge_core::raid::{RaidMode, RaidParityLayout};
use loki_data_forge_core::raid_reconstruct::{RaidReconstructOptions, reconstruct_array};

fn write_member(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write member");
}

#[test]
fn reconstructs_raid1_from_single_member() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("member0.img");
    let output = dir.path().join("raid1_out.img");

    let payload = b"forensic-evidence-block-0001";
    write_member(&source, payload);

    let report = reconstruct_array(&RaidReconstructOptions {
        mode: RaidMode::Raid1,
        stripe_size: 64 * 1024,
        members: vec![Some(source)],
        output: output.clone(),
        parity_layout: RaidParityLayout::LeftSymmetric,
    })
    .expect("raid1 reconstruct");

    assert_eq!(report.bytes_written, payload.len() as u64);
    assert_eq!(std::fs::read(output).expect("output"), payload);
}

#[test]
fn reconstructs_raid0_stripes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let member0 = dir.path().join("member0.img");
    let member1 = dir.path().join("member1.img");
    let output = dir.path().join("raid0_out.img");

    let stripe_size = 4usize;
    let logical = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH";

    let mut disk0 = Vec::new();
    let mut disk1 = Vec::new();
    for (stripe_idx, chunk) in logical.chunks(stripe_size).enumerate() {
        if stripe_idx % 2 == 0 {
            disk0.extend_from_slice(chunk);
        } else {
            disk1.extend_from_slice(chunk);
        }
    }

    write_member(&member0, &disk0);
    write_member(&member1, &disk1);

    let report = reconstruct_array(&RaidReconstructOptions {
        mode: RaidMode::Raid0,
        stripe_size: stripe_size as u64,
        members: vec![Some(member0), Some(member1)],
        output: output.clone(),
        parity_layout: RaidParityLayout::LeftSymmetric,
    })
    .expect("raid0 reconstruct");

    assert_eq!(report.bytes_written, logical.len() as u64);
    assert_eq!(std::fs::read(output).expect("output"), logical);
}

#[test]
fn reconstructs_raid5_with_one_missing_member() {
    let dir = tempfile::tempdir().expect("temp dir");
    let member0 = dir.path().join("member0.img");
    let member2 = dir.path().join("member2.img");
    let output = dir.path().join("raid5_out.img");

    let stripe_size = 4usize;
    let disk_count = 3usize;
    let logical = b"ABCDWXYZ1234QRSTuvwxLMNO";

    let mut disks = vec![Vec::<u8>::new(), Vec::<u8>::new(), Vec::<u8>::new()];
    let mut data_cursor = 0usize;

    for stripe_idx in 0..(logical.len() / (stripe_size * (disk_count - 1))) {
        let parity_disk = parity_disk_index(
            stripe_idx as u64,
            disk_count,
            RaidParityLayout::LeftSymmetric,
        );
        let data_order = (1..disk_count)
            .map(|k| (parity_disk + k) % disk_count)
            .collect::<Vec<_>>();

        let mut stripe_chunks = vec![vec![0u8; stripe_size]; disk_count];
        for disk_idx in data_order {
            let next = &logical[data_cursor..data_cursor + stripe_size];
            stripe_chunks[disk_idx] = next.to_vec();
            data_cursor += stripe_size;
        }

        let parity = xor_chunks(
            &stripe_chunks
                .iter()
                .enumerate()
                .filter(|(idx, _)| *idx != parity_disk)
                .map(|(_, c)| c.clone())
                .collect::<Vec<_>>(),
        );
        stripe_chunks[parity_disk] = parity;

        for (disk_idx, chunk) in stripe_chunks.into_iter().enumerate() {
            disks[disk_idx].extend_from_slice(&chunk);
        }
    }

    std::fs::write(&member0, &disks[0]).expect("member0");
    std::fs::write(&member2, &disks[2]).expect("member2");

    let report = reconstruct_array(&RaidReconstructOptions {
        mode: RaidMode::Raid5,
        stripe_size: stripe_size as u64,
        members: vec![Some(member0), None, Some(member2)],
        output: output.clone(),
        parity_layout: RaidParityLayout::LeftSymmetric,
    })
    .expect("raid5 reconstruct");

    assert_eq!(report.reconstructed_missing_members, 1);
    assert_eq!(std::fs::read(output).expect("output"), logical);
}

fn parity_disk_index(stripe_idx: u64, disk_count: usize, layout: RaidParityLayout) -> usize {
    match layout {
        RaidParityLayout::RightSymmetric | RaidParityLayout::RightAsymmetric => {
            (stripe_idx as usize) % disk_count
        }
        RaidParityLayout::LeftSymmetric
        | RaidParityLayout::LeftAsymmetric
        | RaidParityLayout::Unknown => {
            (disk_count - 1usize).wrapping_sub((stripe_idx as usize) % disk_count)
        }
    }
}

fn xor_chunks(chunks: &[Vec<u8>]) -> Vec<u8> {
    let len = chunks.first().map(Vec::len).unwrap_or(0);
    let mut out = vec![0u8; len];
    for chunk in chunks {
        for (idx, byte) in chunk.iter().enumerate() {
            out[idx] ^= *byte;
        }
    }
    out
}
