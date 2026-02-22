use crate::models::FoundFile;

pub fn parse_mft_markers(
    chunk: &[u8],
    base_offset: u64,
    source_path: &std::path::Path,
) -> Vec<FoundFile> {
    let mut out = Vec::new();
    let needle = b"FILE0";
    let mut idx = 0usize;

    while idx + needle.len() <= chunk.len() {
        if &chunk[idx..idx + needle.len()] == needle {
            let absolute = base_offset + idx as u64;
            out.push(FoundFile {
                id: format!("mft-{absolute:016x}"),
                display_name: format!("ntfs_mft_record_{absolute:016x}"),
                extension: "mft".to_string(),
                signature_id: "ntfs-mft-file0".to_string(),
                source_path: source_path.to_path_buf(),
                container_path: None,
                offset: absolute,
                size: 1024,
                confidence: 0.72,
                category: "filesystem_metadata".to_string(),
                encrypted: false,
                notes: Some("Quick hit from NTFS FILE0 marker".to_string()),
            });
            idx += needle.len();
        } else {
            idx += 1;
        }
    }

    out
}
