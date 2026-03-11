# Virtual Machine Ransomware Healing Architecture

## The Problem: Partial Encryption
Ransomware variants targeting hypervisors (like ESXiArgs, DarkBit, or standard Windows variants impacting Hyper-V) increasingly employ "partial encryption" tactics. To maximize speed and disruption, they encrypt only the beginning (headers) and end of large container files (`.vmdk`, `.vhdx`), or encrypt in intermittent chunks. 

When the first 1MB-10MB of a VHDX or VMDK is encrypted, the container's structural metadata—the VMDK Descriptor, VHDX Header, and Block Allocation Table (BAT)—is mathematically destroyed. Standard hypervisors and forensic tools will reject the container as "Invalid Signature" because the magic bytes (`KDMV`, `vhdxfile`) are scrambled into ciphertext.

## Advanced Aerospace-Grade Healing & Extraction Protocol
Loki Data Forge completely bypasses the reliance on fragile container metadata using an approach inspired by signal-degradation resilience in military aerospace feeds. We assume the "map" (BAT/Header) is permanently compromised and mathematically project a new one directly from the remaining payload bytes.

### 1. The Redundant Header Strike
For VHDX specifically, the Microsoft specification requires redundant headers at `0x10000` (64KB) and `0x20000` (128KB). Certain ransomware actors lazily encrypt only the first 64KB, leaving the redundant header perfectly intact for complete architectural restoration. Our `VirtualHealer` attempts this first.

### 2. Deep Geometric Carving (The "Blind Map")
If both headers are destroyed, the container's translation tables are lost. The `VirtualHealer` scans the container byte-by-byte (using our Portable SIMD or cache-bypassed direct I/O) hunting for internal File System boundaries that would normally represent the Guest OS's drive layout:
- **NTFS Boot Sectors**: `EB 52 90 4E 54 46 53 20`
- **MFT Magic Sequences**: `FILE0`
- **Ext4 Superblocks**: `0xEF53` at specific alignments.

Once an unencrypted interior boot sector or MFT cluster is located, Loki mathematically aligns that sector as `LBA 0` of a new, ad-hoc "Raw Image" and creates a seamless translation layer. The user is then able to mount and extract the surviving files exactly as if the container were unencrypted.

### 3. Entropy-Shift Detection
By applying the `std::simd` Rolling Shannon Entropy calculator over the container, Loki dynamically maps the "Ransomware Boundary"—the exact mathematical point where high-entropy ciphertext abruptly shifts back into low-entropy plaintext. This boundary calculation prevents our carver from wasting CPU cycles on cryptographically dead zones.
