#!/usr/bin/env bash
set -euo pipefail
# Uses the supplied application and issues its own short-lived grant.
exec python3 "$(dirname "$0")/local/run.py" --check
