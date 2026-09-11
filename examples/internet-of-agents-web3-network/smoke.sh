#!/usr/bin/env bash
set -euo pipefail
example_root="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$example_root/orchestrate.py" "$@"
