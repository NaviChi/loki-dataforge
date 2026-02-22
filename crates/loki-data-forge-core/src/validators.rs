use crate::models::SignatureProfile;

pub fn structural_validation_score(
    signature_id: &str,
    chunk: &[u8],
    idx: usize,
    profile: SignatureProfile,
) -> f32 {
    let base = match signature_id {
        "sig-common-0001" | "sig-common-0002" => validate_jpeg(chunk, idx),
        "sig-common-0003" => validate_png(chunk, idx),
        "sig-common-0009" => validate_pdf(chunk, idx),
        s if s.contains("zip") || s.contains("docx") => validate_zip_like(chunk, idx),
        s if s.contains("vmdk") || s.contains("vhd") || s.contains("qcow") => {
            validate_virtual_disk_header(chunk, idx)
        }
        _ => 0.45,
    };

    match profile {
        SignatureProfile::Strict => base,
        SignatureProfile::Broad => (base * 0.85).max(0.2),
    }
}

fn validate_jpeg(chunk: &[u8], idx: usize) -> f32 {
    let end = (idx + 512).min(chunk.len());
    if end <= idx + 4 {
        return 0.5;
    }
    let window = &chunk[idx..end];
    if window.windows(2).any(|w| w == [0xff, 0xd9]) {
        0.92
    } else {
        0.68
    }
}

fn validate_png(chunk: &[u8], idx: usize) -> f32 {
    let end = (idx + 4096).min(chunk.len());
    if end <= idx + 8 {
        return 0.5;
    }
    let window = &chunk[idx..end];
    if window.windows(8).any(|w| w == b"IEND\xaeB`\x82") {
        0.95
    } else {
        0.74
    }
}

fn validate_pdf(chunk: &[u8], idx: usize) -> f32 {
    let end = (idx + 8192).min(chunk.len());
    if end <= idx + 4 {
        return 0.5;
    }
    let window = &chunk[idx..end];
    let has_obj = window.windows(5).any(|w| w.eq_ignore_ascii_case(b" obj\n"));
    let has_xref = window.windows(4).any(|w| w.eq_ignore_ascii_case(b"xref"));
    let has_eof = window.windows(5).any(|w| w.eq_ignore_ascii_case(b"%%EOF"));

    match (has_obj, has_xref || has_eof) {
        (true, true) => 0.96,
        (true, false) => 0.78,
        _ => 0.58,
    }
}

fn validate_zip_like(chunk: &[u8], idx: usize) -> f32 {
    let end = (idx + 16384).min(chunk.len());
    if end <= idx + 4 {
        return 0.5;
    }
    let window = &chunk[idx..end];
    let has_local = window.windows(4).any(|w| w == [0x50, 0x4b, 0x03, 0x04]);
    let has_central = window.windows(4).any(|w| w == [0x50, 0x4b, 0x01, 0x02]);
    let has_eocd = window.windows(4).any(|w| w == [0x50, 0x4b, 0x05, 0x06]);

    if has_local && (has_central || has_eocd) {
        0.93
    } else if has_local {
        0.72
    } else {
        0.55
    }
}

fn validate_virtual_disk_header(chunk: &[u8], idx: usize) -> f32 {
    let end = (idx + 128).min(chunk.len());
    if end <= idx + 8 {
        return 0.5;
    }
    let window = &chunk[idx..end];
    let zeros = window.iter().filter(|b| **b == 0).count() as f32 / window.len() as f32;
    if zeros > 0.15 { 0.88 } else { 0.69 }
}

#[cfg(test)]
mod tests {
    use super::structural_validation_score;
    use crate::models::SignatureProfile;

    #[test]
    fn validates_pdf_patterns() {
        let buf = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nxref\n0 1\n%%EOF";
        let score =
            structural_validation_score("sig-common-0009", buf, 0, SignatureProfile::Strict);
        assert!(score > 0.9);
    }

    #[test]
    fn validates_jpeg_with_eoi() {
        let buf = [
            vec![0xff, 0xd8, 0xff, 0xe0],
            vec![0u8; 16],
            vec![0xff, 0xd9],
        ]
        .concat();
        let score =
            structural_validation_score("sig-common-0001", &buf, 0, SignatureProfile::Strict);
        assert!(score > 0.85);
    }
}
