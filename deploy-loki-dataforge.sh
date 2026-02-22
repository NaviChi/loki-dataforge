#!/usr/bin/env bash
set -euo pipefail

# Set this to your new empty GitHub repo URL before running.
REMOTE_URL="https://github.com/REPLACE_WITH_YOUR_USERNAME/loki-dataforge.git"

if [[ "$REMOTE_URL" == *"REPLACE_WITH_YOUR_USERNAME"* ]]; then
  echo "Edit REMOTE_URL in deploy-loki-dataforge.sh before running."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

git init
git branch -M main

git add .
git commit --allow-empty -m "Release v1.0.0 — production ready"

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi

git push -u origin main
git tag -f v1.0.0
git push -f origin v1.0.0

echo "Pushed main + tag v1.0.0. GitHub Actions release workflow should start now."
