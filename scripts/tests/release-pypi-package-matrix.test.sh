#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/release-pypi.yml"
RELEASE_CHECK="$REPO_ROOT/scripts/check-sdk-release.sh"

expected="$(mktemp)"
actual="$(mktemp)"
trap 'rm -f "$expected" "$actual"' EXIT

python3 - "$RELEASE_CHECK" >"$expected" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
for match in re.finditer(r"python -m build (sdks/python/[^ ]+)", text):
    print(match.group(1))
PY

awk '
  /all_packages=\(/ { in_list = 1; next }
  in_list && /\)/ { in_list = 0; next }
  in_list {
    gsub(/[ "]/, "", $0)
    if ($0 != "") print $0
  }
' "$WORKFLOW" >"$actual"

while IFS= read -r package_dir; do
  grep -Fx "$package_dir" "$actual" >/dev/null || {
    echo "release-pypi.yml all_packages must include release-qualified package $package_dir" >&2
    exit 1
  }
  test -f "$REPO_ROOT/$package_dir/pyproject.toml" || {
    echo "release-pypi.yml package lacks pyproject.toml: $package_dir" >&2
    exit 1
  }
done <"$expected"

python3 - "$REPO_ROOT" <<'PY'
from pathlib import Path
import sys
import tomllib

root = Path(sys.argv[1])
pyproject = tomllib.loads((root / "sdks/python/chio-py/pyproject.toml").read_text())
if pyproject["project"]["name"] != "chio-sdk":
    raise SystemExit("sdks/python/chio-py must publish the chio-sdk distribution")
PY

echo "release-pypi-package-matrix.test.sh: PyPI matrix covers release-qualified Python packages"
