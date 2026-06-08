#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-sdk-release.sh"

grep -F 'sdks/python/chio-sdk-python/pyproject.toml' "$SCRIPT" >/dev/null
grep -F 'chio-sdk-python metadata version' "$SCRIPT" >/dev/null
grep -F 'python -m build sdks/python/chio-sdk-python' "$SCRIPT" >/dev/null
grep -F 'chio_sdk/_generated/receipt/record_schema.py' "$SCRIPT" >/dev/null
grep -F 'wheel smoke verified chio-sdk-python' "$SCRIPT" >/dev/null
grep -F 'sdist smoke verified chio-sdk-python' "$SCRIPT" >/dev/null

echo "check-sdk-release-python-generated.test.sh: generated Python SDK release smoke is present"
