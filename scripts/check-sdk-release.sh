#!/usr/bin/env bash
set -euo pipefail

# Unified Chio SDK release qualification driver.
#
# Usage: check-sdk-release.sh <language>
#   language := cpp | go | py | ts
#
# Each branch performs the language-specific smoke build and consumer
# verification. The per-language entrypoints (check-chio-go-release.sh,
# check-chio-py-release.sh, check-chio-ts-release.sh, and the cpp variants)
# are thin wrappers that dispatch here.

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
    sdk_dir="${repo_root}/sdks/cpp/chio-cpp"

    "${repo_root}/scripts/check-chio-cpp.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-cpp"

    echo "chio-cpp release qualification passed"
    ;;

  cpp-kernel)
    sdk_dir="${repo_root}/sdks/cpp/chio-cpp-kernel"

    "${sdk_dir}/scripts/check-with-ffi.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-cpp-kernel"

    echo "chio-cpp-kernel release qualification passed"
    ;;

  guard-cpp)
    sdk_dir="${repo_root}/sdks/guard/chio-guard-cpp"

    "${sdk_dir}/scripts/check-native.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-guard-cpp"

    echo "chio-guard-cpp release qualification passed"
    ;;

  drogon)
    sdk_dir="${repo_root}/sdks/cpp/chio-drogon"
    chio_cpp_dir="${repo_root}/sdks/cpp/chio-cpp"

    "${repo_root}/scripts/check-chio-drogon.sh"
    chio_cpp_packager_smoke "${sdk_dir}" "chio-drogon" "${chio_cpp_dir}"

    echo "chio-drogon release qualification passed"
    ;;

  go)
    sdk_dir="${repo_root}/sdks/go/chio-go"
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

	"github.com/backbay-labs/chio/sdks/go/chio-go/auth"
	"github.com/backbay-labs/chio/sdks/go/chio-go/client"
	"github.com/backbay-labs/chio/sdks/go/chio-go/version"
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
      go mod edit -require=github.com/backbay-labs/chio/sdks/go/chio-go@"${release_version}"
      go mod edit -replace=github.com/backbay-labs/chio/sdks/go/chio-go="${sdk_dir}"
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
    generated_builder_venv="${work_dir}/generated-builder"
    generated_wheel_venv="${work_dir}/generated-wheel-smoke"
    generated_sdist_venv="${work_dir}/generated-sdist-smoke"
    generated_dist_dir="${work_dir}/generated-dist"

    cd "${repo_root}"

    rm -rf sdks/python/chio-py/build sdks/python/chio-py/dist
    find sdks/python/chio-py/src -maxdepth 1 -type d -name '*.egg-info' -prune -exec rm -rf {} +
    find sdks/python/chio-py -type d -name '__pycache__' -prune -exec rm -rf {} +

    python3 - <<'PY'
from pathlib import Path
import tomllib

pyproject = tomllib.loads(Path("sdks/python/chio-py/pyproject.toml").read_text())
declared_version = pyproject["project"]["version"]
declared_name = pyproject["project"]["name"]

version_ns = {}
exec(Path("sdks/python/chio-py/src/chio/version.py").read_text(), version_ns)
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
    python -m build sdks/python/chio-py --sdist --wheel --outdir "${dist_dir}"
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
    deactivate

    rm -rf sdks/python/chio-sdk-python/build sdks/python/chio-sdk-python/dist
    find sdks/python/chio-sdk-python/src -type d -name '__pycache__' -prune -exec rm -rf {} +

    python3 - <<'PY'
from pathlib import Path
import tomllib

pyproject = tomllib.loads(Path("sdks/python/chio-sdk-python/pyproject.toml").read_text())
declared_name = pyproject["project"]["name"]
declared_version = pyproject["project"]["version"]

if declared_name != "chio-sdk-python":
    raise SystemExit(f"expected distribution name chio-sdk-python, found {declared_name}")
if not declared_version:
    raise SystemExit("chio-sdk-python version must not be empty")
print(f"chio-sdk-python metadata version {declared_version} verified")
PY

    python3 -m venv "${generated_builder_venv}"
    . "${generated_builder_venv}/bin/activate"
    python -m pip install --quiet --upgrade pip build twine
    python -m build sdks/python/chio-sdk-python --sdist --wheel --outdir "${generated_dist_dir}"
    python -m twine check "${generated_dist_dir}"/*
    python - "${generated_dist_dir}" <<'PY'
from pathlib import Path
import sys
import tarfile
import zipfile

dist_dir = Path(sys.argv[1])
wheel = next(dist_dir.glob("chio_sdk_python-*.whl"))
sdist = next(dist_dir.glob("chio_sdk_python-*.tar.gz"))

with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    if not any(name.endswith("chio_sdk/py.typed") for name in names):
        raise SystemExit("wheel is missing chio_sdk/py.typed")
    if not any(name.endswith("chio_sdk/_generated/receipt/record_schema.py") for name in names):
        raise SystemExit("wheel is missing generated receipt schema")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("wheel contains forbidden Python cache artifacts")

with tarfile.open(sdist, "r:gz") as archive:
    names = archive.getnames()
    if not any(name.endswith("src/chio_sdk/py.typed") for name in names):
        raise SystemExit("sdist is missing src/chio_sdk/py.typed")
    if not any(name.endswith("src/chio_sdk/_generated/receipt/record_schema.py") for name in names):
        raise SystemExit("sdist is missing generated receipt schema")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("sdist contains forbidden Python cache artifacts")

print(f"validated generated SDK wheel {wheel.name} and sdist {sdist.name}")
PY
    deactivate

    python3 -m venv "${generated_wheel_venv}"
    . "${generated_wheel_venv}/bin/activate"
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet "${generated_dist_dir}"/chio_sdk_python-*.whl
    python - <<'PY'
import importlib.metadata
import chio_sdk
from chio_sdk import ChioReceipt, Decision, ToolCallAction

assert importlib.metadata.version("chio-sdk-python")
assert chio_sdk.ChioClient is not None
receipt = ChioReceipt(
    id="5" * 64,
    timestamp=1700000000,
    capability_id="cap-1",
    tool_server="srv",
    tool_name="read_file",
    action=ToolCallAction(parameters={}, parameter_hash="a" * 64),
    decision=Decision.allow(),
    receipt_kind="mediated_decision",
    boundary_class="prevent",
    tool_origin="caller_executed",
    redaction_mode="none",
    trust_level="mediated",
    content_hash="d" * 64,
    policy_hash="cafebabe",
    kernel_key="b" * 64,
    signature="c" * 128,
)
dumped = receipt.model_dump(by_alias=True, exclude_none=True)
assert "bbs_projection_version" not in dumped
print("wheel smoke verified chio-sdk-python")
PY
    deactivate

    python3 -m venv "${generated_sdist_venv}"
    . "${generated_sdist_venv}/bin/activate"
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet "${generated_dist_dir}"/chio_sdk_python-*.tar.gz
    python - <<'PY'
import importlib.metadata
import chio_sdk
from chio_sdk import ChioReceipt

assert importlib.metadata.version("chio-sdk-python")
assert chio_sdk.ChioClient is not None
assert ChioReceipt is not None
print("sdist smoke verified chio-sdk-python")
PY
    deactivate
    ;;

  ts)
    repo_copy_dir="${work_dir}/repo"
    sdk_dir="${repo_copy_dir}/sdks/typescript"
    pack_dir="${work_dir}/packs"

    if ! command -v npm >/dev/null 2>&1; then
      echo "Chio TypeScript release checks require npm on PATH" >&2
      exit 1
    fi
    if ! command -v node >/dev/null 2>&1; then
      echo "Chio TypeScript release checks require node on PATH" >&2
      exit 1
    fi

    mkdir -p "${repo_copy_dir}" "${pack_dir}"
    (
      cd "${repo_root}"
      tar \
        --exclude='*/node_modules' \
        --exclude='*/dist' \
        --exclude='*/build' \
        --exclude='*/target' \
        --exclude='*/.artifacts' \
        --exclude='*/.next' \
        --exclude='*.tgz' \
        -cf - .cargo .tooling Cargo.lock Cargo.toml rust-toolchain.toml bench crates docs/demo/passkey examples formal integrations sdks/typescript tests xtask
    ) | (
      cd "${repo_copy_dir}"
      tar -xf -
    )

    package_discovery_script="${work_dir}/ts-package-records.mjs"
    cat > "${package_discovery_script}" <<'NODE'
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const root = process.env.TS_ROOT;
if (root == null || root === "") {
  throw new Error("TS_ROOT is required");
}

const rootPackage = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const workspacePatterns = rootPackage.workspaces ?? [];
const packageDirs = [];

for (const pattern of workspacePatterns) {
  if (typeof pattern !== "string") {
    continue;
  }
  if (!pattern.includes("*")) {
    packageDirs.push(path.join(root, pattern));
    continue;
  }
  const [prefix, suffix = ""] = pattern.split("*", 2);
  const baseDir = path.join(root, prefix);
  if (!existsSync(baseDir)) {
    continue;
  }
  for (const entry of readdirSync(baseDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      continue;
    }
    const candidate = path.join(baseDir, entry.name, suffix);
    packageDirs.push(candidate);
  }
}

const packages = [];
for (const dir of packageDirs) {
  const manifestPath = path.join(dir, "package.json");
  if (!existsSync(manifestPath)) {
    continue;
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.private === true) {
    continue;
  }
  if (typeof manifest.name !== "string" || manifest.name === "") {
    throw new Error(`publishable package is missing name: ${manifestPath}`);
  }

  const rootExport =
    manifest.exports != null && typeof manifest.exports === "object"
      ? manifest.exports["."]
      : undefined;
  const hasImport =
    rootExport != null &&
    typeof rootExport === "object" &&
    typeof rootExport.import === "string";
  const hasRequire =
    rootExport != null &&
    typeof rootExport === "object" &&
    typeof rootExport.require === "string";
  const binNames = [];
  if (typeof manifest.bin === "string") {
    binNames.push(manifest.name);
  } else if (manifest.bin != null && typeof manifest.bin === "object") {
    for (const name of Object.keys(manifest.bin)) {
      binNames.push(name);
    }
  }

  packages.push({
    dir,
    manifest,
    name: manifest.name,
    hasBuild:
      manifest.scripts != null &&
      typeof manifest.scripts === "object" &&
      typeof manifest.scripts.build === "string",
    hasTest:
      manifest.scripts != null &&
      typeof manifest.scripts === "object" &&
      typeof manifest.scripts.test === "string",
    hasImport,
    hasRequire,
    binNames: binNames.sort(),
    localDeps: [],
  });
}

const byName = new Map(packages.map(pkg => [pkg.name, pkg]));
for (const pkg of packages) {
  const dependencyBlocks = [
    pkg.manifest.dependencies,
    pkg.manifest.optionalDependencies,
    pkg.manifest.peerDependencies,
  ];
  const localDeps = new Set();
  for (const block of dependencyBlocks) {
    if (block == null || typeof block !== "object") {
      continue;
    }
    for (const name of Object.keys(block)) {
      if (byName.has(name)) {
        localDeps.add(name);
      }
    }
  }
      const scripts = pkg.manifest.scripts ?? {};
      const packageScriptText = [scripts.build, scripts.test]
        .filter(value => typeof value === "string")
        .join("\n");
      pkg.requiresBun = /\bbun\b/.test(packageScriptText);
      pkg.requiresWasmToolchain = /\b(build:wasm|build-wasm\.sh|wasm-pack)\b/.test(packageScriptText);
      pkg.localDeps = [...localDeps].sort();
}

const ordered = [];
const seen = new Set();
const visiting = new Set();

function visit(pkg) {
  if (seen.has(pkg.name)) {
    return;
  }
  if (visiting.has(pkg.name)) {
    throw new Error(`cycle in TypeScript package dependencies at ${pkg.name}`);
  }
  visiting.add(pkg.name);
  for (const depName of pkg.localDeps) {
    visit(byName.get(depName));
  }
  visiting.delete(pkg.name);
  seen.add(pkg.name);
  ordered.push(pkg);
}

const packageSeeds = [...packages].sort((left, right) => {
  if (left.hasRequire !== right.hasRequire) {
    return left.hasRequire ? -1 : 1;
  }
  return left.name.localeCompare(right.name);
});

for (const pkg of packageSeeds) {
  visit(pkg);
}

for (const pkg of ordered) {
  process.stdout.write(
    [
      pkg.dir,
      pkg.name,
      pkg.hasBuild ? "1" : "0",
      pkg.hasTest ? "1" : "0",
      pkg.requiresBun ? "1" : "0",
      pkg.requiresWasmToolchain ? "1" : "0",
      pkg.hasImport ? "1" : "0",
      pkg.hasRequire ? "1" : "0",
      pkg.binNames.join(","),
      pkg.localDeps.join(","),
    ].join("|") + "\n",
  );
}
NODE
    package_records=()
    while IFS= read -r package_record; do
      package_records+=("${package_record}")
    done < <(TS_ROOT="${sdk_dir}" node "${package_discovery_script}")

    if [[ "${#package_records[@]}" -eq 0 ]]; then
      echo "no publishable TypeScript SDK packages found" >&2
      exit 1
    fi

    ts_requires_bun=0
    ts_requires_wasm_toolchain=0
    for package_record in "${package_records[@]}"; do
      IFS='|' read -r _package_dir package_name _has_build _has_test requires_bun requires_wasm_toolchain _has_import _has_require _bin_names _local_deps <<<"${package_record}"
      if [[ "${requires_bun}" == "1" ]]; then
        ts_requires_bun=1
      fi
      if [[ "${requires_wasm_toolchain}" == "1" ]]; then
        ts_requires_wasm_toolchain=1
      fi
    done
    if [[ "${ts_requires_bun}" == "1" ]] && ! command -v bun >/dev/null 2>&1; then
      echo "Chio TypeScript release checks require bun on PATH because ${package_name} declares a Bun-backed build or test script" >&2
      exit 1
    fi
    if [[ "${ts_requires_wasm_toolchain}" == "1" ]]; then
      if ! command -v cargo >/dev/null 2>&1; then
        echo "Chio TypeScript release checks require cargo on PATH because a package declares a wasm build script" >&2
        exit 1
      fi
      required_wasm_pack_version="$(cat "${repo_copy_dir}/.tooling/wasm-pack.version")"
      if ! command -v wasm-pack >/dev/null 2>&1; then
        echo "Chio TypeScript release checks require wasm-pack ${required_wasm_pack_version} on PATH because a package declares a wasm build script" >&2
        exit 1
      fi
      actual_wasm_pack_version="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
      if [[ "${actual_wasm_pack_version}" != "${required_wasm_pack_version}" ]]; then
        echo "Chio TypeScript release checks require wasm-pack ${required_wasm_pack_version}; got ${actual_wasm_pack_version}" >&2
        exit 1
      fi
      required_wasm_bindgen_version="$(cat "${repo_copy_dir}/.tooling/wasm-bindgen.version")"
      if ! command -v wasm-bindgen >/dev/null 2>&1; then
        echo "Chio TypeScript release checks require wasm-bindgen-cli ${required_wasm_bindgen_version} on PATH because a package declares a wasm build script" >&2
        exit 1
      fi
      actual_wasm_bindgen_version="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"
      if [[ "${actual_wasm_bindgen_version}" != "${required_wasm_bindgen_version}" ]]; then
        echo "Chio TypeScript release checks require wasm-bindgen-cli ${required_wasm_bindgen_version}; got ${actual_wasm_bindgen_version}" >&2
        exit 1
      fi
    fi

    (
      cd "${sdk_dir}"
      npm install --ignore-scripts --no-fund --no-audit
    )

    packed_package_names=()
    packed_package_paths=()
    packed_package_deps=()
    packed_package_index_for() {
      local requested_name="$1"
      local idx
      for ((idx = 0; idx < ${#packed_package_names[@]}; idx += 1)); do
        if [[ "${packed_package_names[${idx}]}" == "${requested_name}" ]]; then
          printf "%s\n" "${idx}"
          return 0
        fi
      done
      return 1
    }

    append_packed_dependency_closure() {
      local requested_name="$1"
      local requested_index
      local requested_deps
      local existing_name
      local dep_name
      local -a requested_dep_names=()

      for existing_name in "${install_arg_names[@]}"; do
        if [[ "${existing_name}" == "${requested_name}" ]]; then
          return 0
        fi
      done

      if ! requested_index="$(packed_package_index_for "${requested_name}")"; then
        echo "TypeScript release smoke is missing packed local dependency ${requested_name}" >&2
        return 1
      fi

      requested_deps="${packed_package_deps[${requested_index}]}"
      if [[ -n "${requested_deps}" ]]; then
        IFS=',' read -r -a requested_dep_names <<<"${requested_deps}"
        for dep_name in "${requested_dep_names[@]}"; do
          if [[ -n "${dep_name}" ]]; then
            append_packed_dependency_closure "${dep_name}"
          fi
        done
      fi

      install_arg_names+=("${requested_name}")
      install_args+=("${packed_package_paths[${requested_index}]}")
    }

    package_index=0
    for package_record in "${package_records[@]}"; do
      IFS='|' read -r package_dir package_name has_build has_test requires_bun requires_wasm_toolchain has_import has_require bin_names local_deps <<<"${package_record}"
      echo "checking TypeScript package ${package_name}"

      (
        cd "${package_dir}"
        if [[ "${has_test}" == "1" ]]; then
          npm test
        fi
        if [[ "${has_build}" == "1" ]]; then
          CHIO_REQUIRE_WASM_TOOLCHAIN="${requires_wasm_toolchain}" npm run build
        fi
      )
      rm -rf "${repo_copy_dir}/target"

      pack_file="$(
        cd "${package_dir}" &&
          npm pack --pack-destination "${pack_dir}" --json | node --input-type=module -e '
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
      packed_package_names+=("${package_name}")
      packed_package_paths+=("${pack_dir}/${pack_file}")
      packed_package_deps+=("${local_deps}")

      package_index=$((package_index + 1))
      consumer_dir="${work_dir}/consumer-${package_index}"
      mkdir -p "${consumer_dir}"
      cat > "${consumer_dir}/package.json" <<'EOF'
{
  "name": "chio-ts-release-smoke",
  "private": true,
  "type": "module"
}
EOF

      # Install the complete same-release dependency closure in one npm
      # transaction. A direct-only install can still reach the public registry
      # for a second-hop package, such as wasm-core under edge, before any Chio
      # TypeScript package from this release exists there.
      install_args=()
      install_arg_names=()
      append_packed_dependency_closure "${package_name}"

      (
        cd "${consumer_dir}"
        npm install --ignore-scripts --no-fund --no-audit "${install_args[@]}"
        if [[ "${has_import}" == "1" && "${package_name}" != "@chio-protocol/workers" ]]; then
          CHIO_PACKAGE_NAME="${package_name}" node --experimental-wasm-modules --input-type=module <<'NODE'
const packageName = process.env.CHIO_PACKAGE_NAME;
if (packageName == null || packageName === "") {
  throw new Error("CHIO_PACKAGE_NAME is required");
}
const moduleNamespace = await import(packageName);
const exportNames = Object.keys(moduleNamespace);
if (exportNames.length === 0 && !("default" in moduleNamespace)) {
  throw new Error(`expected at least one ESM export from ${packageName}`);
}
console.log(`ESM import smoke verified ${packageName}`);
NODE
        fi
        if [[ "${has_require}" == "1" ]]; then
          CHIO_PACKAGE_NAME="${package_name}" node <<'NODE'
const packageName = process.env.CHIO_PACKAGE_NAME;
if (packageName == null || packageName === "") {
  throw new Error("CHIO_PACKAGE_NAME is required");
}
const moduleNamespace = require(packageName);
const exportNames = Object.keys(moduleNamespace);
if (exportNames.length === 0 && !("default" in moduleNamespace)) {
  throw new Error(`expected at least one CommonJS export from ${packageName}`);
}
console.log(`CommonJS require smoke verified ${packageName}`);
NODE
        fi
        if [[ -n "${bin_names}" ]]; then
          IFS=',' read -r -a package_bin_names <<<"${bin_names}"
          for package_bin_name in "${package_bin_names[@]}"; do
            if [[ -n "${package_bin_name}" ]]; then
              cli_help_output="$("./node_modules/.bin/${package_bin_name}" --help)"
              if [[ -z "${cli_help_output}" ]]; then
                echo "CLI ${package_bin_name} produced empty --help output" >&2
                exit 1
              fi
              echo "CLI smoke verified ${package_bin_name}"
            fi
          done
        fi
        if [[ "${package_name}" == "@chio-protocol/workers" ]]; then
          node --input-type=module <<'NODE'
import { existsSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const packageJsonPath = require.resolve("@chio-protocol/workers/package.json");
const packageRoot = path.dirname(packageJsonPath);
const expectedFiles = [
  "dist/index.js",
  "dist/bundler/chio_kernel_browser_bg.js",
  "dist/bundler/chio_kernel_browser_bg.wasm",
];

for (const relativePath of expectedFiles) {
  const candidate = path.join(packageRoot, relativePath);
  if (!existsSync(candidate)) {
    throw new Error(`missing packed Workers artifact: ${relativePath}`);
  }
}

console.log("Workers package artifact smoke verified @chio-protocol/workers");
NODE
          (
            cd "${sdk_dir}"
            CHIO_WORKERS_PACKAGE_JSON="${consumer_dir}/node_modules/@chio-protocol/workers/package.json" node --input-type=module <<'NODE'
import { Miniflare } from "miniflare";
import path from "node:path";

const packageJsonPath = process.env.CHIO_WORKERS_PACKAGE_JSON;
if (packageJsonPath == null || packageJsonPath === "") {
  throw new Error("CHIO_WORKERS_PACKAGE_JSON is required");
}

const packageRoot = path.dirname(packageJsonPath);
process.chdir(packageRoot);
const mf = new Miniflare({
  modules: true,
  scriptPath: "dist/index.js",
  compatibilityDate: "2026-04-27",
  modulesRules: [
    { type: "ESModule", include: ["**/*.js"], fallthrough: true },
    { type: "CompiledWasm", include: ["**/*.wasm"], fallthrough: true },
  ],
});
try {
  const res = await mf.dispatchFetch("https://workers.test/__chio_workers_smoke");
  const body = await res.json();
  if (
    !res.ok ||
    body.package !== "@chio-protocol/workers" ||
    body.wasmTarget !== "bundler" ||
    body.verifyReceipt !== true
  ) {
    throw new Error(`Miniflare smoke failed: ${JSON.stringify(body)}`);
  }
  console.log("Workers Miniflare smoke verified @chio-protocol/workers");
} finally {
  await mf.dispose();
}
NODE
          )
        fi
      )
    done

    echo "Chio TypeScript release qualification passed"
    ;;

  *)
    echo "unknown SDK language: ${lang} (expected cpp, cpp-kernel, guard-cpp, drogon, go, py, or ts)" >&2
    exit 2
    ;;
esac
