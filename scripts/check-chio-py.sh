#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "chio-sdk checks require python3 on PATH" >&2
  exit 1
fi

venv_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-sdk-check.XXXXXX")"
cleanup() {
  rm -rf "$venv_dir"
}
trap cleanup EXIT

python3 -m venv "$venv_dir"
. "$venv_dir/bin/activate"
python -m pip install --quiet -e sdks/python/chio-py
python -m unittest discover -s sdks/python/chio-py/tests
