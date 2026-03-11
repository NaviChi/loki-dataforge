# Loki Data Forge: Headless Deployment & Integration Guide

Welcome to the Headless QuicSwarm Deployment manual. This documentation covers how to orchestrate the backend `loki-data-forge-cli` application on headless servers and clusters to build an active forensic mesh.

## Overview

Loki Data Forge ships with a full OS-Native headless CLI fallback compiled into the primary binary when the `cli` feature is enabled. This allows incident response teams to SSH into compromised Linux/Windows nodes, deploy the standalone binary, and actively stream forensic blocks back to the GUI analyst via the `quic_swarm` mesh.

## Running the Mesh Listener

On an infected target or a high-performance network ingestion terminal, you can bind the swarm listener:

```bash
# Starts the listener on port 4433 using PSK identity 'loki-mesh'
loki-data-forge-cli mesh --listen 0.0.0.0:4433 --server-name loki-mesh
```

**What this does:**
1. Instantiates a `QuicSwarm` endpoint using robust `rustls` configurations.
2. Injects a dynamically pinned EPSK (Ephemeral Pre-Shared Key) hash for peer authentication.
3. Automatically hooks into the OS-native disk APIs (`/dev/rdisk` on Mac, `CreateFile` with `FILE_FLAG_NO_BUFFERING` on Windows, or `O_DIRECT` on Linux) to serve exact block structures directly inside multiplexed QUIC streams.

## Connecting the Analyst Dashboard

On the investigator's machine (running the Tauri React GUI):
1. Click the **Mesh Setup** button in the top navigation bar.
2. Input the IP and Port of the headless listener (e.g., `192.168.1.100:4433`).
3. Set the identical PSK / Swarm ID (`loki-mesh`).
4. Click **Connect Peer**.

You will now see the headless node securely map into your `QuicSwarm Mesh Fleet` dashboard, instantly broadcasting its latency.

## Distributed RAID Reconstruction

If you are dealing with a massively degraded RAID-6 array striped across 48 physical disks over 4 unique server chassis, deploy the `loki-data-forge-cli` in listener mode across all 4 servers.

From your central GUI, connect to all 4 listeners. The math engine uses the Network Block Scraper to issue localized UDP block requests over `tokio`, injecting the physical disk targets directly into your local `wgpu` GF(2^8) math offload matrix without ever downloading the multi-terabyte containers locally.

## CI/CD Headless Automation & Scaling

For automated scanning on CI nodes, use standard CLI execution arguments. The CLI adheres to exactly the same Testability and CI workflow boundaries deployed throughout Phase 4.

```bash
# Example headless deep carve with strict signatures
loki-data-forge-cli scan --mode deep --signatures strict /dev/nvme0n1 /mnt/raid_array
```

## Security Posture

The mesh runs on a modified aerospace-grade QUIC transport:
- No data touches the TCP congestion windows, avoiding DPI throttling.
- `DummyVerifier` testing setups have been strictly replaced by `PinnedCertVerifier` SHA-256 bindings. If the PSK doesn't mathematically align with the client bounds, the connection instantly panics, avoiding Man-In-The-Middle attacks targeting forensic traffic.
