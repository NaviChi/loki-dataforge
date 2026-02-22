#[derive(Debug, Clone)]
pub struct FragmentSample<'a> {
    pub bytes: &'a [u8],
    pub signature_id: &'a str,
}

pub trait FragmentClassifier: Send + Sync {
    fn name(&self) -> &'static str;
    fn score(&self, sample: &FragmentSample<'_>) -> f32;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EntropyNgramClassifier;

impl FragmentClassifier for EntropyNgramClassifier {
    fn name(&self) -> &'static str {
        "entropy-ngram-v1"
    }

    fn score(&self, sample: &FragmentSample<'_>) -> f32 {
        if sample.bytes.is_empty() {
            return 0.0;
        }

        let entropy = shannon_entropy(sample.bytes);
        let ascii_ratio = sample
            .bytes
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\n' || **b == b'\r')
            .count() as f32
            / sample.bytes.len() as f32;

        let entropy_score = (entropy / 8.0).clamp(0.0, 1.0);
        let texture_score =
            (ascii_ratio * 0.6 + (1.0 - (ascii_ratio - 0.45).abs()) * 0.4).clamp(0.0, 1.0);

        // Lightweight domain priors keep this assistive, not authoritative.
        let prior = if sample.signature_id.contains("pdf") || sample.signature_id.contains("sql") {
            0.15
        } else if sample.signature_id.contains("jpg") || sample.signature_id.contains("png") {
            0.1
        } else {
            0.05
        };

        (entropy_score * 0.55 + texture_score * 0.35 + prior).clamp(0.0, 1.0)
    }
}

pub fn default_classifier() -> Box<dyn FragmentClassifier> {
    Box::new(EntropyNgramClassifier)
}

fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }

    let n = bytes.len() as f32;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|count| {
            let p = *count as f32 / n;
            -p * p.log2()
        })
        .sum::<f32>()
}

#[cfg(test)]
mod tests {
    use super::{FragmentSample, default_classifier};

    #[test]
    fn classifier_scores_non_empty_samples() {
        let classifier = default_classifier();
        let sample = FragmentSample {
            bytes: b"%PDF-1.7\n1 0 obj\n",
            signature_id: "sig-common-0009",
        };
        let score = classifier.score(&sample);
        assert!(score > 0.2);
        assert!(score <= 1.0);
    }
}
