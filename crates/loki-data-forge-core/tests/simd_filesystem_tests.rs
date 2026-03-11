use loki_data_forge_core::carver::calculate_rolling_shannon_entropy;

#[test]
fn test_simd_mft_hfs_catalog_corruption_boundaries() {
    // Generate a mock MFT record block (typically 1024 bytes per record)
    // "FILE" signature is 46 49 4C 45
    let mut mft_block = vec![0u8; 4096];
    
    // Valid MFT entry at start
    mft_block[0..4].copy_from_slice(b"FILE");
    // Some basic low entropy data (padding with zeros) is already there
    
    // At offset 1024, another valid record
    mft_block[1024..1028].copy_from_slice(b"FILE");
    
    // At offset 2048, deep corruption (simulating high entropy ransomware encryption)
    for i in 2048..3072 {
        mft_block[i] = (i * 17 ^ (i >> 2)) as u8; // Pseudo-random bit diffusion to raise entropy
    }
    
    // At offset 3072, another valid record
    mft_block[3072..3076].copy_from_slice(b"FILE");
    
    // Perform OS-native SIMD rolling entropy calculation over the chunk mapping
    let window_size = 1024;
    let step_size = 1024;
    let entropies = calculate_rolling_shannon_entropy(&mft_block, window_size, step_size);
    
    // We expect exactly 4 entropy bounds calculated corresponding to the 1024 byte chunks
    assert_eq!(entropies.len(), 4);
    
    // The first and second MFT blocks should have very low entropy (mostly zeros)
    assert!(entropies[0] < 1.0, "Normal block 0 should be low entropy: {}", entropies[0]);
    assert!(entropies[1] < 1.0, "Normal block 1 should be low entropy: {}", entropies[1]);
    
    // The third block should have significantly higher entropy due to deep mathematical corruption (encryption payload spoof)
    assert!(entropies[2] > 7.0, "Corrupt block 2 should have high entropy: {}", entropies[2]); 
    
    // The fourth block is normal again, marking the end of the corrupted zone
    assert!(entropies[3] < 1.0, "Recovered block 3 should be low entropy: {}", entropies[3]);
}
