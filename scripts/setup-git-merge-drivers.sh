#!/usr/bin/env bash
# setup-git-merge-drivers.sh - Register the workspace's custom merge
# drivers in .git/config. Idempotent. Run once per clone.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

git config merge.cargo-lock-regen.name   "Cargo.lock regeneration"
git config merge.cargo-lock-regen.driver "scripts/cargo-lock-merge.sh %O %A %B %L %P"

printf 'registered merge.cargo-lock-regen\n'
git config --get-regexp '^merge\.' || true
