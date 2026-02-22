use crate::models::ScanOptions;

pub fn apply_synology_mode(options: &ScanOptions, warnings: &mut Vec<String>) {
    warnings.push(
        "Synology mode enabled: assuming SHR + ext4/btrfs metadata hints and rkey workflow"
            .to_string(),
    );

    if !options.read_only {
        warnings.push("Synology mode forced read-only safety checks".to_string());
    }
}
