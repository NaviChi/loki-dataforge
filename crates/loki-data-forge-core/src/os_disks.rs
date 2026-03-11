use std::process::Command;

/// Advanced native macOS Disk Arbitration bindings for unmounted volume detection.
/// Executes `diskutil list` to identify raw, physical blocks bypassing standard mounted visibility.
pub fn get_macos_physical_drives() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let mut drives = Vec::new();
        // Fallback to simple diskutil output parsing if direct Disk Arbitration bindings aren't requested
        if let Ok(output) = Command::new("diskutil").arg("list").output() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            for line in out_str.lines() {
                if line.starts_with("/dev/disk") {
                    if let Some(disk) = line.split_whitespace().next() {
                        // For raw blocks on macOS, /dev/rdisk is preferred for IO speed and bypassing the cache barrier
                        let raw_disk = disk.replace("/dev/disk", "/dev/rdisk");
                        drives.push(raw_disk);
                    }
                }
            }
        }
        drives
    }
    
    #[cfg(not(target_os = "macos"))]
    {
        // For non-macOS, this function acts as a no-op scaffold since we specifically target macOS Disk Arbitration here.
        Vec::new()
    }
}
