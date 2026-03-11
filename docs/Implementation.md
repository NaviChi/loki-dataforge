# Implementation Whitepaper: The Adaptive Qilin Matrix

This document acts as the definitive architecture reference for the Loki Data Forge engine.

## 1. Zero-Cache Ingest (`DirectBlockReader`)
The ingest layer must pull bare-metal drive sectors exclusively. OS-level buffer caches corrupt forensic data timestamps and introduce massive CPU overhead.
The `crates/loki-data-forge-core/src/io/direct_reader.rs` abstraction utilizes `cfg(target_os)` compilation blocks:
- **macOS (Darwin)**: Targets physical raw disks (`/dev/rdiskX`) and issues `fcntl(F_NOCACHE)` immediately after opening.
- **Windows**: Opens `\\.\PhysicalDriveN` with `FILE_FLAG_NO_BUFFERING` requiring 4KB sector-aligned `Seek`/`Read` instructions.
- **Linux**: Standard `O_DIRECT` block access.
This trait implements asynchronous multi-threading compatibility (`Send + Sync`) to allow polling from multiple thread pools simultaneously.

## 2. Portable SIMD & Shannon Entropy Calculus
(Completed) Our carver engine replaces signature matches with a statistical Shannon Entropy sliding window. Deep `std::simd` utilization allows 512-bit wide register sweeps, automatically compiling down to AVX-512 (Intel/AMD) or NEON (Apple M1/M2/M3). Falls back to auto-vectorized iterators if nightly `portable_simd` is unavailable.

## 3. Polyglot Computation (`wgpu`)
(Completed) Deep mathematical tasks involving Galois Field `GF(2^8)` intersection mapping (RAID6 / RAIDZ) bypass CPU floating-point registers entirely. By targeting `wgpu` compute shaders, we execute across NVIDIA, AMD, Intel, and Apple Silicon without requiring CUDA libraries or Linux-specific packages.

## 4. QUIC Mesh Swarm (`quinn`)
(Completed) The networking stack replaces standard TCP logic with an aerospace-grade user-space UDP layer powered by `quinn`. This permits high-latency, massive-volume forensic payload transfers using self-signed internal TLS 1.3 meshes without kernel buffer bloat.

## 5. GUI Integration (Tauri v2)
Testing follows the hybrid approach: Vitest unit testing for individual components (utilizing `data-testid` bounds) and full Playwright E2E for the `loki-data-forge` integration. Port 0 is dynamically assigned during `tauri dev` automated workflows.
