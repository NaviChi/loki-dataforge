use std::collections::HashMap;
use std::path::Path;

use crate::error::{LokiDataForgeError, Result};
use crate::models::SignatureDefinition;

static BUILTIN_SIGNATURES: &str = include_str!("../data/signatures.json");

#[derive(Debug, Clone)]
pub struct CompiledSignature {
    pub definition: SignatureDefinition,
    bytes: Vec<u8>,
    mask: Vec<bool>,
}

impl CompiledSignature {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn matches(&self, bytes: &[u8], idx: usize) -> bool {
        if idx + self.bytes.len() > bytes.len() {
            return false;
        }

        self.bytes
            .iter()
            .zip(self.mask.iter())
            .enumerate()
            .all(|(off, (needle, strict))| !strict || bytes[idx + off] == *needle)
    }
}

#[derive(Debug, Clone)]
pub struct SignatureSet {
    signatures: Vec<CompiledSignature>,
    first_byte_index: HashMap<u8, Vec<usize>>,
    pub max_len: usize,
}

impl SignatureSet {
    pub fn from_definitions(definitions: Vec<SignatureDefinition>) -> Result<Self> {
        let mut signatures = Vec::with_capacity(definitions.len());
        let mut first_byte_index: HashMap<u8, Vec<usize>> = HashMap::new();
        let mut max_len = 0usize;

        for definition in definitions {
            let (bytes, mask) = parse_hex_with_wildcards(&definition.magic)?;
            if bytes.is_empty() {
                return Err(LokiDataForgeError::InvalidSignatureDb(format!(
                    "signature {} has empty magic",
                    definition.id
                )));
            }

            max_len = max_len.max(bytes.len());
            let signature = CompiledSignature {
                definition,
                bytes,
                mask,
            };

            let idx = signatures.len();
            if signature.mask[0] {
                first_byte_index
                    .entry(signature.bytes[0])
                    .or_default()
                    .push(idx);
            }

            signatures.push(signature);
        }

        Ok(Self {
            signatures,
            first_byte_index,
            max_len,
        })
    }

    pub fn builtin() -> Result<Self> {
        let definitions: Vec<SignatureDefinition> = serde_json::from_str(BUILTIN_SIGNATURES)?;
        Self::from_definitions(definitions)
    }

    pub fn from_json_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let definitions: Vec<SignatureDefinition> = serde_json::from_str(&data)?;
        Self::from_definitions(definitions)
    }

    pub fn signatures(&self) -> &[CompiledSignature] {
        &self.signatures
    }

    pub fn candidates_for_byte(&self, b: u8) -> Option<&[usize]> {
        self.first_byte_index.get(&b).map(Vec::as_slice)
    }
}

fn parse_hex_with_wildcards(value: &str) -> Result<(Vec<u8>, Vec<bool>)> {
    let normalized = value
        .split_whitespace()
        .map(|p| p.to_ascii_lowercase())
        .collect::<Vec<_>>();

    let mut bytes = Vec::with_capacity(normalized.len());
    let mut mask = Vec::with_capacity(normalized.len());

    for part in normalized {
        if part == "??" {
            bytes.push(0);
            mask.push(false);
            continue;
        }

        if part.len() != 2 {
            return Err(LokiDataForgeError::InvalidSignatureDb(format!(
                "invalid hex byte '{part}'"
            )));
        }

        let parsed = u8::from_str_radix(&part, 16).map_err(|_| {
            LokiDataForgeError::InvalidSignatureDb(format!("invalid hex token '{part}'"))
        })?;

        bytes.push(parsed);
        mask.push(true);
    }

    Ok((bytes, mask))
}

#[cfg(test)]
mod tests {
    use super::parse_hex_with_wildcards;

    #[test]
    fn parses_wildcard_signature() {
        let (bytes, mask) = parse_hex_with_wildcards("ff d8 ?? e0").expect("must parse");
        assert_eq!(bytes, vec![0xff, 0xd8, 0x00, 0xe0]);
        assert_eq!(mask, vec![true, true, false, true]);
    }
}
