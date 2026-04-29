#!/usr/bin/env bash
set -euo pipefail

# Unified Chio SDK release qualification driver.
#
# Usage: check-sdk-release.sh <language>
#   language := cpp | go | py | ts
#
# Each branch performs the language-specific smoke build and consumer
# verification. The three legacy per-language entrypoints
# (check-chio-go-release.sh, check-chio-py-release.sh,
# check-chio-ts-release.sh) are thin wrappers around this script so that CI
# invocations and release runbooks stay source-compatible.

if [[ $# -lt 1 ]]; then
  echo "usage: $(basename "$0") <cpp|cpp-kernel|guard-cpp|drogon|go|py|ts> [extra args]" >&2
  exit 2
fi

lang="$1"
shift || true

case "${lang}" in
  -h|--help)
    cat <<'HELP'
check-sdk-release.sh <cpp|cpp-kernel|guard-cpp|drogon|go|py|ts>

Runs the release qualification smoke for one Chio SDK. The driver handles
shared setup (temp dir, cleanup trap, PATH probes) and delegates to a
per-language branch for the build, pack, and consumer-smoke steps.
HELP
    exit 0
    ;;
esac

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-sdk-release.XXXXXX")"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

# Run the Conan + vcpkg manifest smoke for a C++ SDK.
#   $1: package directory (containing conanfile.py and vcpkg.json)
#   $2: expected vcpkg.json "name" field
#   $3: optional space-separated list of conan references to "conan create" first
chio_cpp_packager_smoke() {
  local sdk_dir="$1"
  local expected_name="$2"
  local prereq_recipes="${3:-}"
  local require_packagers="${CHIO_CPP_REQUIRE_PACKAGERS:-${CI:-}}"

  if command -v conan >/dev/null 2>&1; then
    if ! conan profile path default >/dev/null 2>&1; then
      conan profile detect --force
    fi
    if [[ -n "${prereq_recipes}" ]]; then
      for prereq_dir in ${prereq_recipes}; do
        (
          cd "${prereq_dir}"
          conan create . --build=missing
        )
      done
    fi
    (
      cd "${sdk_dir}"
      conan create . --build=missing
    )
  elif [[ -n "${require_packagers}" && "${require_packagers}" != "0" ]]; then
    echo "Conan package smoke is required but conan is not on PATH" >&2
    exit 1
  else
    echo "skipping Conan package smoke for ${expected_name} because conan is not on PATH"
  fi

  local vcpkg_cmd=""
  if command -v vcpkg >/dev/null 2>&1; then
    vcpkg_cmd="$(command -v vcpkg)"
  elif [[ -n "${VCPKG_ROOT:-}" && -x "${VCPKG_ROOT}/vcpkg" ]]; then
    vcpkg_cmd="${VCPKG_ROOT}/vcpkg"
  fi

  if [[ -n "${vcpkg_cmd}" ]]; then
    # Layer the in-tree staging overlay so SDKs whose dependencies live in
    # our private overlay registry (e.g. chio-drogon -> chio-cpp) can
    # resolve those deps from local port files. The same port files are
    # later mirrored to backbay-labs/chio-vcpkg-registry by the publish
    # workflow, so the dry-run shape matches what consumers see.
    local overlay_ports_dir="${repo_root}/tools/vcpkg-overlay/ports"
    local vcpkg_args=(install "--x-manifest-root=${sdk_dir}" --dry-run)
    if [[ -d "${overlay_ports_dir}" ]]; then
      vcpkg_args+=("--overlay-ports=${overlay_ports_dir}")
    fi
    "${vcpkg_cmd}" "${vcpkg_args[@]}"
  elif [[ -n "${require_packagers}" && "${require_packagers}" != "0" ]]; then
    echo "vcpkg manifest build is required but vcpkg is not on PATH" >&2
    exit 1
  else
    python3 - "${sdk_dir}/vcpkg.json" "${expected_name}" <<'PY'
import json
import sys

manifest_path, expected_name = sys.argv[1], sys.argv[2]
with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
if manifest.get("name") != expected_name:
    raise SystemExit(
        f"unexpected vcpkg package name: {manifest.get('name')!r} != {expected_name!r}"
    )
print(f"vcpkg manifest syntax verified for {expected_name}")
PY
  fi
}

case "${lang}" in
  cpp)
    sdk_dir="${repo_root}/packages/sdk/chio-cpp"

    "${repo_root}/scripts/check-chio-cpp.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-cpp"

    echo "chio-cpp release qualification passed"
    ;;

  cpp-kernel)
    sdk_dir="${repo_root}/packages/sdk/chio-cpp-kernel"

    "${sdk_dir}/scripts/check-with-ffi.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-cpp-kernel"

    echo "chio-cpp-kernel release qualification passed"
    ;;

  guard-cpp)
    sdk_dir="${repo_root}/packages/sdk/chio-guard-cpp"

    "${sdk_dir}/scripts/check-native.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-guard-cpp"

    echo "chio-guard-cpp release qualification passed"
    ;;

  drogon)
    sdk_dir="${repo_root}/packages/sdk/chio-drogon"
    chio_cpp_dir="${repo_root}/packages/sdk/chio-cpp"

    "${repo_root}/scripts/check-chio-drogon.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-drogon" "${chio_cpp_dir}"

    echo "chio-drogon release qualification passed"
    ;;

  go)
    sdk_dir="${repo_root}/packages/sdk/chio-go"
    consumer_dir="${work_dir}/consumer"
    bin_dir="${work_dir}/bin"

    if ! command -v go >/dev/null 2>&1; then
      echo "chio-go release checks require go on PATH" >&2
      exit 1
    fi

    module_version="$(awk -F'"' '/ModuleVersion/ { print $2; exit }' "${sdk_dir}/version/version.go")"
    if [[ -z "${module_version}" ]]; then
      echo "failed to determine chio-go module version" >&2
      exit 1
    fi
    release_version="${module_version}"
    if [[ "${release_version}" != v* ]]; then
      release_version="v${release_version}"
    fi

    (
      cd "${sdk_dir}"
      CGO_ENABLED=0 go test ./...
      CGO_ENABLED=0 go vet ./...
      CGO_ENABLED=0 go build ./...
      GOBIN="${bin_dir}" CGO_ENABLED=0 go install ./cmd/conformance-peer
    )

    if [[ ! -x "${bin_dir}/conformance-peer" ]]; then
      echo "expected conformance-peer binary at ${bin_dir}/conformance-peer" >&2
      exit 1
    fi

    mkdir -p "${consumer_dir}"
    cat > "${consumer_dir}/main.go" <<'EOF'
package main

import (
	"context"
	"fmt"

	"github.com/backbay/chio/packages/sdk/chio-go/auth"
	"github.com/backbay/chio/packages/sdk/chio-go/client"
	"github.com/backbay/chio/packages/sdk/chio-go/version"
)

func main() {
	consumer := client.WithStaticBearer("http://127.0.0.1:8080", "token", nil)
	if consumer == nil {
		panic("nil client")
	}
	fmt.Printf("%s %s\n", version.DefaultClientName, version.ModuleVersion)
	_ = auth.StaticBearerToken("token")
	_, _ = context.WithCancel(context.Background())
}
EOF

    (
      cd "${consumer_dir}"
      go mod init example.com/chio-go-release-smoke
      go mod edit -require=github.com/backbay/chio/packages/sdk/chio-go@"${release_version}"
      go mod edit -replace=github.com/backbay/chio/packages/sdk/chio-go="${sdk_dir}"
      CGO_ENABLED=0 go mod tidy
      CGO_ENABLED=0 go build ./...
    )

    echo "chio-go release qualification passed for ${release_version}"
    ;;

  py)
    if ! command -v python3 >/dev/null 2>&1; then
      echo "chio-sdk release checks require python3 on PATH" >&2
      exit 1
    fi

    builder_venv="${work_dir}/builder"
    wheel_venv="${work_dir}/wheel-smoke"
    sdist_venv="${work_dir}/sdist-smoke"
    dist_dir="${work_dir}/dist"

    cd "${repo_root}"

    rm -rf packages/sdk/chio-py/build packages/sdk/chio-py/dist
    find packages/sdk/chio-py/src -maxdepth 1 -type d -name '*.egg-info' -prune -exec rm -rf {} +
    find packages/sdk/chio-py -type d -name '__pycache__' -prune -exec rm -rf {} +

    python3 - <<'PY'
from pathlib import Path
import tomllib

pyproject = tomllib.loads(Path("packages/sdk/chio-py/pyproject.toml").read_text())
declared_version = pyproject["project"]["version"]
declared_name = pyproject["project"]["name"]

version_ns = {}
exec(Path("packages/sdk/chio-py/src/chio/version.py").read_text(), version_ns)
module_version = version_ns["__version__"]

if declared_name != "chio-sdk":
    raise SystemExit(f"expected distribution name chio-sdk, found {declared_name}")
if declared_version != module_version:
    raise SystemExit(
        f"pyproject version {declared_version} does not match chio.version {module_version}"
    )
print(f"chio-sdk metadata version {declared_version} verified")
PY

    python3 -m venv "${builder_venv}"
    . "${builder_venv}/bin/activate"
    python -m pip install --quiet --upgrade pip build twine
    python -m build packages/sdk/chio-py --sdist --wheel --outdir "${dist_dir}"
    python -m twine check "${dist_dir}"/*
    python - "${dist_dir}" <<'PY'
from pathlib import Path
import sys
import tarfile
import zipfile

dist_dir = Path(sys.argv[1])
wheel = next(dist_dir.glob("chio_sdk-*.whl"))
sdist = next(dist_dir.glob("chio_sdk-*.tar.gz"))

with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    if not any(name.endswith("chio/py.typed") for name in names):
        raise SystemExit("wheel is missing chio/py.typed")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("wheel contains forbidden Python cache artifacts")

with tarfile.open(sdist, "r:gz") as archive:
    names = archive.getnames()
    if not any(name.endswith("src/chio/py.typed") for name in names):
        raise SystemExit("sdist is missing src/chio/py.typed")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("sdist contains forbidden Python cache artifacts")
    if any("/src/chio.egg-info/" in name or name.endswith("/src/chio.egg-info") for name in names):
        raise SystemExit("sdist contains stale src/chio.egg-info metadata")
    if any("/src/chio_py.egg-info/" in name or name.endswith("/src/chio_py.egg-info") for name in names):
        raise SystemExit("sdist contains stale src/chio_py.egg-info metadata")

print(f"validated wheel {wheel.name} and sdist {sdist.name}")
PY
    deactivate

    python3 -m venv "${wheel_venv}"
    . "${wheel_venv}/bin/activate"
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet "${dist_dir}"/chio_sdk-*.whl
    python - <<'PY'
import importlib.metadata
import chio

assert importlib.metadata.version("chio-sdk") == chio.__version__
assert chio.ChioClient is not None
assert chio.ChioSession is not None
assert chio.ReceiptQueryClient is not None
print(f"wheel smoke verified chio-sdk {chio.__version__}")
PY
    deactivate

    python3 -m venv "${sdist_venv}"
    . "${sdist_venv}/bin/activate"
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet "${dist_dir}"/chio_sdk-*.tar.gz
    python - <<'PY'
import importlib.metadata
import chio

assert importlib.metadata.version("chio-sdk") == chio.__version__
assert chio.ChioClient is not None
assert chio.ChioSession is not None
assert chio.ReceiptQueryClient is not None
print(f"sdist smoke verified chio-sdk {chio.__version__}")
PY
    ;;

  ts)
    source_dir="${repo_root}/packages/sdk/chio-ts"
    repo_copy_dir="${work_dir}/repo"
    sdk_dir="${repo_copy_dir}/packages/sdk/chio-ts"
    consumer_dir="${work_dir}/consumer"

    if ! command -v npm >/dev/null 2>&1; then
      echo "Chio TypeScript release checks require npm on PATH" >&2
      exit 1
    fi

    mkdir -p "${repo_copy_dir}/packages/sdk" "${repo_copy_dir}/tests"
    cp -R "${source_dir}" "${sdk_dir}"
    rm -rf "${sdk_dir}/node_modules" "${sdk_dir}/dist"
    cp -R "${repo_root}/tests/bindings" "${repo_copy_dir}/tests/bindings"

    (
      cd "${sdk_dir}"
      if [[ -f package-lock.json ]]; then
        npm ci --no-fund --no-audit
      else
        npm install --no-fund --no-audit
      fi
      npm test
      npm run build
    )

    pack_file="$(
      cd "${sdk_dir}" &&
        npm pack --json | node --input-type=module -e '
          let data = "";
          process.stdin.on("data", (chunk) => (data += chunk));
          process.stdin.on("end", () => {
            const parsed = JSON.parse(data);
            if (!Array.isArray(parsed) || parsed.length === 0 || !parsed[0].filename) {
              throw new Error("npm pack did not return a package filename");
            }
            process.stdout.write(parsed[0].filename);
          });
        '
    )"

    mkdir -p "${consumer_dir}"
    cat > "${consumer_dir}/package.json" <<'EOF'
{
  "name": "chio-ts-release-smoke",
  "private": true,
  "type": "module"
}
EOF

    (
      cd "${consumer_dir}"
      npm install --no-fund --no-audit "${sdk_dir}/${pack_file}"
      node --input-type=module <<'EOF'
import { ChioClient, ReceiptQueryClient } from "@chio-protocol/sdk";

if (typeof ChioClient?.withStaticBearer !== "function") {
  throw new Error("expected ChioClient.withStaticBearer export");
}

if (typeof ReceiptQueryClient !== "function") {
  throw new Error("expected ReceiptQueryClient export");
}

const client = ChioClient.withStaticBearer("http://127.0.0.1:8080/mcp", "token");
if (!client || typeof client.initialize !== "function") {
  throw new Error("expected initialized ChioClient surface");
}

const receiptClient = new ReceiptQueryClient("http://127.0.0.1:8940", "token");
if (!receiptClient || typeof receiptClient.query !== "function") {
  throw new Error("expected receipt query surface");
}

console.log("Chio TypeScript package smoke verified");
EOF
    )

    echo "Chio TypeScript release qualification passed"
    ;;

  *)
    echo "unknown SDK language: ${lang} (expected cpp, cpp-kernel, guard-cpp, drogon, go, py, or ts)" >&2
    exit 2
    ;;
esac
