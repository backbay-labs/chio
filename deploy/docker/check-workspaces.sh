#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${script_dir}/chio-workspace/regenerate.sh" --check
"${script_dir}/chio-workspace/check.sh"
"${script_dir}/proof-room-workspace/check.sh"
