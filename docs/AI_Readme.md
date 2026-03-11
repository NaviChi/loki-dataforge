# AI Readme

## Overview
Loki Data Forge is a cross-platform Rust/Tauri forensic data recovery tool engineered for Military-Grade/Aerospace performance on any hardware topology via an Adaptive Pipeline.

## Architecture
- **Frontend**: Tauri v2, React, Vite (Zustand state management)
- **Backend**: Rust
- **Hardware Abstraction Layer (Adaptive Qilin Pipeline)**:
  - Cache-Bypass disk reading via `io::DirectBlockReader` (`O_DIRECT`, `F_NOCACHE`, `FILE_FLAG_NO_BUFFERING`).
  - Graphics acceleration via `wgpu` targeting Apple Metal, Windows DirectX 12, Linux Vulkan.
  - Network streaming via `quinn` (QUIC / UDP).
  - High-performance memory ops via Portable `std::simd` and CPU fallback via `rayon`.
