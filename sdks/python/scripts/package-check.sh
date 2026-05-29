#!/usr/bin/env bash
# Local smoke-test for every Chio Python SDK package.
#
# For each package listed below:
#   1. Run `uv build --sdist --wheel` into an isolated out-dir.
#   2. Install the wheel into a throwaway venv with --no-deps.
#   3. Import the module and print its __file__.
#
# Exits non-zero on the first failure and prints a summary at the end.
# Mirrors the build+smoke legs of .github/workflows/release-pypi.yml so
# developers can reproduce CI failures locally.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Packages to check. Each entry is: <path-relative-to-repo-root>
PACKAGES=(
  "sdks/python/chio-sdk-python"
  "sdks/python/chio-adapter-base"
  "sdks/python/chio-asgi"
  "sdks/python/chio-django"
  "sdks/python/chio-fastapi"
  "sdks/python/chio-langchain"
  "sdks/python/chio-crewai"
  "sdks/python/chio-autogen"
  "sdks/python/chio-llamaindex"
  "sdks/python/chio-temporal"
  "sdks/python/chio-prefect"
  "sdks/python/chio-dagster"
  "sdks/python/chio-airflow"
  "sdks/python/chio-ray"
  "sdks/python/chio-streaming"
  "sdks/python/chio-iac"
  "sdks/python/chio-observability"
  "sdks/python/chio-langgraph"
  "sdks/python/chio-code-agent"
  "sdks/python/chio-hermes"
  "sdks/lambda/chio-lambda-python"
)

# Two special cases: the canonical import name does not match the
# hyphen-to-underscore convention.
import_name_for() {
  case "$1" in
    chio-sdk-python) echo "chio_sdk" ;;
    chio-lambda-python) echo "chio_lambda" ;;
    *) echo "${1//-/_}" ;;
  esac
}

if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv is not installed. See https://docs.astral.sh/uv/ for install instructions." >&2
  exit 127
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found on PATH." >&2
  exit 127
fi

WORKDIR="$(mktemp -d -t chio-pkgcheck-XXXXXX)"
trap 'rm -rf "${WORKDIR}"' EXIT

passed=()
failed=()

for rel_path in "${PACKAGES[@]}"; do
  pkg_dir="${REPO_ROOT}/${rel_path}"
  slug="$(basename "${rel_path}")"
  import_name="$(import_name_for "${slug}")"

  if [[ ! -f "${pkg_dir}/pyproject.toml" ]]; then
    echo "SKIP ${slug}: no pyproject.toml at ${pkg_dir}" >&2
    failed+=("${slug}: missing pyproject.toml")
    continue
  fi

  echo "=== ${slug} ==="
  out_dir="${WORKDIR}/${slug}-dist"
  mkdir -p "${out_dir}"

  if ! (cd "${pkg_dir}" && uv build --sdist --wheel --out-dir "${out_dir}"); then
    failed+=("${slug}: uv build failed")
    continue
  fi

  wheel="$(find "${out_dir}" -maxdepth 1 -name '*.whl' -print -quit 2>/dev/null)"
  if [[ -z "${wheel}" ]]; then
    failed+=("${slug}: no wheel produced")
    continue
  fi

  venv_dir="${WORKDIR}/${slug}-venv"
  if ! python3 -m venv "${venv_dir}"; then
    failed+=("${slug}: venv creation failed")
    continue
  fi

  # shellcheck disable=SC1091
  source "${venv_dir}/bin/activate"
  if ! pip install --quiet --upgrade pip; then
    deactivate
    failed+=("${slug}: pip upgrade failed")
    continue
  fi
  if ! pip install --quiet --no-deps "${wheel}"; then
    deactivate
    failed+=("${slug}: wheel install failed")
    continue
  fi

  if python3 -c "import importlib; m = importlib.import_module('${import_name}'); print('  imported', m.__name__, 'from', getattr(m, '__file__', '?'))"; then
    passed+=("${slug}")
  else
    failed+=("${slug}: import ${import_name} failed")
  fi
  deactivate
done

echo
echo "=== Summary ==="
echo "Passed: ${#passed[@]}"
for p in "${passed[@]}"; do
  echo "  OK  ${p}"
done
echo "Failed: ${#failed[@]}"
for f in "${failed[@]}"; do
  echo "  FAIL ${f}"
done

if [[ ${#failed[@]} -gt 0 ]]; then
  exit 1
fi
