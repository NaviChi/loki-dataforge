#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR/apps/desktop"
if [[ ! -d node_modules ]]; then
  npm install
fi
npm run build

cd "$ROOT_DIR"
exec cargo run -p loki-data-forge --features "cli gui"
