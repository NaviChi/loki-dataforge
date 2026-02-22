# Contributing to Loki Data Forge

## Ground Rules
- Always keep scan paths read-only by default.
- Never write recovered output back to the source volume.
- Keep changes cross-platform (Windows, macOS x64/aarch64, Linux x64/aarch64).
- Add/maintain structured error handling (`thiserror` + `anyhow`) and avoid panics in user paths.

## Local Setup
```bash
git clone https://github.com/loki-data-forge/loki-data-forge.git
cd loki-data-forge
cargo check --workspace
cd apps/desktop && npm install && npm run build
```

## Run CLI
```bash
cargo run -p loki-data-forge --features cli -- scan --drive /dev/sda --mode deep --threads 32 --report scan.json
```

## Run GUI
```bash
./scripts/launch_gui.sh
```

## Cross-Compilation from Linux
```bash
rustup target add \
  x86_64-unknown-linux-gnu \
  aarch64-unknown-linux-gnu \
  x86_64-pc-windows-gnu \
  aarch64-pc-windows-msvc \
  x86_64-apple-darwin \
  aarch64-apple-darwin

cargo build -p loki-data-forge --no-default-features --features cli --target aarch64-unknown-linux-gnu
cargo build -p loki-data-forge --no-default-features --features cli --target x86_64-pc-windows-gnu
```

## Suggested PR Scope
- One major feature per PR (parser, carver algorithm, filesystem module, GUI flow).
- Include test samples/minimal fixtures where legal.
- Update README command examples and docs when behavior changes.
