# Loki Data Forge

Loki Data Forge is a cross-platform, Rust-first data recovery toolchain for forensic and incident-response workflows.

- [![Release](https://img.shields.io/github/v/release/NaviChi/loki-dataforge?display_name=tag)](https://github.com/NaviChi/loki-dataforge/releases)
- [![Build](https://img.shields.io/github/actions/workflow/status/NaviChi/loki-dataforge/release.yml?branch=main)](https://github.com/NaviChi/loki-dataforge/actions/workflows/release.yml)
- [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

- Binary name: `loki-data-forge`
- Language: Rust (Edition 2024)
- UI: Tauri 2 + React + Tailwind (shadcn-inspired component system)
- Default safety profile: **read-only scanning**, explicit destination for recovery

## Highlights
- Quick metadata scan with NTFS MFT active/deleted entry extraction
- Deep carving engine with rayon-parallel chunk scanning + tokio streaming fallback
- Built-in signature database (`crates/loki-data-forge-core/data/signatures.json`) with **1225 entries**, including:
  - VMDK (`KDMV` + descriptor)
  - VHDX (`vhdxfile`)
  - VHD (`conectix`)
  - QCOW2 (`QFI\xfb`)
  - VDI marker detection
  - OVA (`ustar` + entry walk)
  - Valve VPK (`0x55AA1234`, v1/v2 tree parser)
  - WIM, TIB/TIBX, BAK, SQL dump signatures
- Virtual container mode (`mount`) for VM/backup/archive sources
- RAID reconstruction command (`reconstruct`) for RAID0/1/5 with missing-member support for RAID5
- Signature profiles (`strict` default, `broad` opt-in)
- Encryption marker auto-detection (BitLocker, LUKS, FileVault/CoreStorage, Synology rkey hints)
- Unified CLI + GUI binary (`loki-data-forge`) with feature flags
- Synology special mode scaffold (SHR/rkey metadata pathing)

## MVP Scope in This Build
Implemented and working now:
- NTFS MFT metadata scan with active/deleted entry state and filename extraction
- Deep signature carving (parallel memmap path + async streaming fallback)
- VMDK detection/descriptor extent parsing
- VPK v1/v2 entry parsing
- RAID0/1/5 reconstruction engine + CLI entrypoint
- Tauri GUI scan/preview/recover flow

Planned next (scaffolded with TODO markers):
- Full metadata-aware FS parsing (ReFS/ext4/Btrfs/APFS/HFS+/XFS/ZFS)
- RAID reconstruction (including full SHR parity behaviors)
- Encryption unlock adapters (BitLocker/LUKS/FileVault/rkey)
- SMART/NVMe deep health, partition reconstruction, bad-sector imaging map

## Workspace Layout
```text
Loki Data Forge/
  crates/
    loki-data-forge-core/      # recovery engine, parsers, carver, virtual mount
    loki-data-forge-cli/       # CLI command parsing + execution
    loki-data-forge-gui/       # Tauri command bridge/state
  apps/desktop/
    src-tauri/          # Tauri Rust app (binary: loki-data-forge)
    src/                # React/Tailwind frontend
  .github/workflows/
    release.yml
```

## CLI Usage
```bash
# Hybrid scan with container inspection
loki-data-forge scan \
  --source /dev/sda \
  --mode hybrid \
  --threads 32 \
  --chunk-size 8388608 \
  --max-carve-size 16777216 \
  --report scan.json

# Multi-source RAID/NAS style scan
loki-data-forge scan \
  --source ./member0.img \
  --source ./member1.img \
  --source ./member2.img \
  --mode deep \
  --report raid-scan.json

# Deep scan + direct recovery to different destination
loki-data-forge scan --source ./disk.img --mode deep --output /recovery --overwrite

# Strict container parsing and broad signature profile
loki-data-forge scan --source ./disk.img --mode deep --strict-containers --signature-profile broad

# Encryption detect/unlock policy controls
loki-data-forge scan --source ./disk.img --encryption-detect-only
loki-data-forge scan --source ./disk.img --unlock-with bitlocker

# Optional bypass mode (disabled by default, audit logged)
loki-data-forge scan --source ./disk.img --enable-bypass --case-id CASE-123 --legal-authority "Warrant-XYZ"

# Recover from existing report
loki-data-forge recover --report scan.json --source ./disk.img --output /recovery

# Reconstruct RAID5 (use 'missing' for unavailable member slots)
loki-data-forge reconstruct \
  --mode raid5 \
  --stripe-size 65536 \
  --member ./member0.img \
  --member missing \
  --member ./member2.img \
  --output ./reconstructed.img

# Virtual mount a container and list entries
loki-data-forge mount --container ./backup.vmdk --json
```

## RAID Usage (New)
- Select multiple input drives/images from the GUI `Browse` button.
- Loki Data Forge auto-detects RAID metadata across mdadm, Synology SHR, Windows Dynamic/Storage Spaces, DDF, and Apple RAID signatures.
- If the array is incomplete, a native warning dialog appears:
  - `Add Missing Drives`
  - `Skip & Continue (Degraded Mode)`
- Degraded mode continues scanning with available members and marks recovery as potentially incomplete.

### Safety Notes
- `scan` defaults to `--signature-profile strict` and `container_error_policy=warn_and_skip`.
- `--strict-containers` upgrades malformed container parsing to hard-fail behavior.
- Unlock and bypass requests are append-audited with signed hash-chain metadata in `.loki-data-forge-audit.log`.

## GUI
```bash
cd apps/desktop
npm install
npm run dev

cd src-tauri
cargo run -p loki-data-forge --features "cli gui"
```

### GUI (single command, recommended)
```bash
/Users/navi/Documents/Projects/Loki_DataRecovery/Loki_Data_Forge/scripts/launch_gui.sh
```

This command builds frontend assets and launches Tauri in one step, avoiding blank-window startup caused by missing dev server/frontend output.

### Screenshot Walkthrough (UI sections)
- Header: mode/status/security state (read-only default)
- Wizard/Advanced scan tabs: source path, recovery target, mode, thread/chunk tuning
- Findings table: sortable recoverable items with signature metadata
- Preview pane: byte-level hex preview for selected finding
- Container tree pane: virtual mount entries for VM/backup archives

## Build

### Local
```bash
cargo check --workspace
cd apps/desktop && npm install && npm run build
```

### Linux Cross-Compilation Targets
```bash
rustup target add \
  x86_64-unknown-linux-gnu \
  aarch64-unknown-linux-gnu \
  x86_64-pc-windows-gnu \
  x86_64-pc-windows-msvc \
  aarch64-pc-windows-msvc \
  x86_64-apple-darwin \
  aarch64-apple-darwin

cargo build -p loki-data-forge --no-default-features --features cli --target aarch64-unknown-linux-gnu
cargo build -p loki-data-forge --no-default-features --features cli --target x86_64-pc-windows-gnu
cargo build -p loki-data-forge --no-default-features --features cli --target aarch64-apple-darwin
```

## Build & Release
- Tag push (`v*`) triggers `.github/workflows/release.yml`
- Release workflow builds Tauri bundles and uploads:
  - Windows: `.msi` + `.exe` installer artifacts
  - macOS: `.dmg` + universal binary flow
  - Linux: `.AppImage` + `.deb` + `.rpm`
- Matrix includes both x64 and arm64 targets where native runners are available.
- Linux runner installs required WebKit/GTK packaging dependencies during CI.

## Releases & Installation
- Create a Git tag (for example `v1.0.0`) and push it to trigger automated packaging on GitHub Actions.
- Download artifacts from the matching GitHub Release:
  - Windows: install using `.exe` or `.msi`.
  - macOS: install via `.dmg` (universal binary; notarized when Apple signing secrets are configured).
  - Linux: choose `.AppImage`, `.deb`, or `.rpm`.
- CLI-only usage is also available from the same source tree:
```bash
cargo build -p loki-data-forge --no-default-features --features cli --release
./target/release/loki-data-forge --help
```

### Release checklist (GitHub)
```bash
git tag v1.0.0
git push origin main
git push origin v1.0.0
```

GitHub Actions will produce:
- Windows installers (`.exe`, `.msi`)
- macOS installer (`.dmg`, universal)
- Linux packages (`.AppImage`, `.deb`, `.rpm`)

## How Loki Data Forge Beats Commercial Recovery Suites
- Transparent and auditable Rust source (no black-box carve pipeline)
- Deterministic JSON signature DB and parser modules under version control
- Scriptable and automatable CLI for SOC/IR pipelines
- Cross-platform native binary with the same core engine for desktop and CLI
- Forensic-friendly defaults: read-only first, explicit safe destination checks

## How to Contribute
- Read `/Users/navi/Documents/Projects/Loki_DataRecovery/Loki_Data_Forge/CONTRIBUTING.md` for coding standards and PR workflow.
- Keep recovery writes disabled by default and preserve read-only behavior in all scan paths.
- Add tests for parser or recovery changes (new signature formats, RAID metadata edge cases, or resume behavior).

## Disclaimer
Loki Data Forge is intended for lawful recovery and forensic operations on systems/data you are authorized to access.
