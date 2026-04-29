#!/usr/bin/env bash
# Build chio-kernel-browser to wasm and bundle for the TS SDK.
#
# Pinned versions are read from .tooling/{wasm-pack,wasm-bindgen}.version
# so the build is reproducible across local dev and CI. The wasm-bindgen
# version is consumed transitively by wasm-pack; we record it here so
# `cargo install wasm-bindgen-cli --version $(cat .tooling/wasm-bindgen.version)`
# can be invoked in environments that need the standalone CLI (for
# example, custom bindgen post-processing).
#
# Usage:
#   build-wasm.sh                         # defaults to browser pkg, target web
#   build-wasm.sh web|nodejs|bundler|deno|no-modules
#   build-wasm.sh --target web
#   build-wasm.sh --target=web
#   build-wasm.sh --all-targets
#   build-wasm.sh --package browser --all-targets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TS_PACKAGES_DIR="${REPO_ROOT}/sdks/typescript/packages"

WASM_PACK_VERSION="$(cat "${REPO_ROOT}/.tooling/wasm-pack.version")"
WASM_BINDGEN_VERSION="$(cat "${REPO_ROOT}/.tooling/wasm-bindgen.version")"

WASM_PACK_TARGETS="web bundler nodejs"
WASM_PACK_VALID_TARGETS="${WASM_PACK_TARGETS} deno no-modules"
PACKAGE="browser"
TARGET="web"
ALL_TARGETS=false
PACKAGE_EXPLICIT=false
TARGET_EXPLICIT=false
WASM_PACK_FORCE_NO_OPT=false

usage() {
  cat >&2 <<'USAGE'
Usage:
  build-wasm.sh                         # defaults to browser pkg, target web
  build-wasm.sh web|nodejs|bundler|deno|no-modules
  build-wasm.sh --target web
  build-wasm.sh --target=web
  build-wasm.sh --all-targets
  build-wasm.sh --package browser --all-targets
USAGE
}

is_valid_target() {
  case "${1}" in
    web|bundler|nodejs|deno|no-modules)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

cargo_lock_wasm_bindgen_version() {
  awk '
    $0 == "[[package]]" { in_pkg = 0; next }
    $0 == "name = \"wasm-bindgen\"" { in_pkg = 1; next }
    in_pkg == 1 && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "${REPO_ROOT}/Cargo.lock"
}

wasm_bindgen_version() {
  wasm-bindgen --version 2>/dev/null | awk '{print $2}'
}

wasm_bindgen_matches_required() {
  local required_version="${1}"
  local actual_version
  actual_version="$(wasm_bindgen_version)"
  [ "${actual_version}" = "${required_version}" ]
}

prepend_cached_wasm_bindgen() {
  local required_version="${1}"
  local cache_root
  local candidate

  if command -v wasm-bindgen >/dev/null 2>&1; then
    return 0
  fi

  for cache_root in \
    "${XDG_CACHE_HOME:-${HOME}/.cache}/.wasm-pack/wasm-bindgen-cargo-install-${required_version}" \
    "${HOME}/Library/Caches/.wasm-pack/wasm-bindgen-cargo-install-${required_version}"
  do
    for candidate in "${cache_root}/wasm-bindgen" "${cache_root}/bin/wasm-bindgen"; do
      if [ -x "${candidate}" ]; then
        PATH="$(dirname "${candidate}"):${PATH}"
        export PATH
        WASM_PACK_FORCE_NO_OPT=true
        echo "INFO: using cached wasm-bindgen ${required_version}: ${candidate}"
        return 0
      fi
    done
  done
}

while [ "$#" -gt 0 ]; do
  case "${1}" in
    --all-targets)
      ALL_TARGETS=true
      ;;
    --package)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --package requires a package name." >&2
        usage
        exit 1
      fi
      shift
      PACKAGE="${1}"
      PACKAGE_EXPLICIT=true
      ;;
    --package=*)
      PACKAGE="${1#--package=}"
      PACKAGE_EXPLICIT=true
      ;;
    --target)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --target requires one of: ${WASM_PACK_VALID_TARGETS}" >&2
        usage
        exit 1
      fi
      shift
      TARGET="${1}"
      TARGET_EXPLICIT=true
      ;;
    --target=*)
      TARGET="${1#--target=}"
      TARGET_EXPLICIT=true
      ;;
    web|bundler|nodejs|deno|no-modules)
      TARGET="${1}"
      TARGET_EXPLICIT=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument '${1}'." >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if ! is_valid_target "${TARGET}"; then
  echo "ERROR: unknown target '${TARGET}'." >&2
  echo "  expected one of: ${WASM_PACK_VALID_TARGETS}" >&2
  exit 1
fi

if [ "${ALL_TARGETS}" = true ] && [ "${TARGET_EXPLICIT}" = true ]; then
  echo "ERROR: --all-targets cannot be combined with a single --target." >&2
  usage
  exit 1
fi

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "WARN: wasm-pack not installed. Install with:" >&2
  echo "  cargo install wasm-pack --version ${WASM_PACK_VERSION}" >&2
  echo "WARN: wasm-bindgen-cli (transitive) pinned at ${WASM_BINDGEN_VERSION}." >&2
  echo "  cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION}" >&2
  echo "Soft-skipping wasm build; CI installs the toolchain via .tooling/ pins." >&2
  exit 0
fi

ACTUAL_WP_VER="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
if [ "${ACTUAL_WP_VER}" != "${WASM_PACK_VERSION}" ]; then
  echo "WARN: wasm-pack version mismatch: expected ${WASM_PACK_VERSION}, got ${ACTUAL_WP_VER}" >&2
  echo "  reinstall with: cargo install wasm-pack --version ${WASM_PACK_VERSION} --force" >&2
fi

WASM_BINDGEN_LIB_VERSION="$(cargo_lock_wasm_bindgen_version)"
if [ -z "${WASM_BINDGEN_LIB_VERSION}" ]; then
  WASM_BINDGEN_LIB_VERSION="${WASM_BINDGEN_VERSION}"
fi
if [ "${WASM_BINDGEN_LIB_VERSION}" != "${WASM_BINDGEN_VERSION}" ]; then
  echo "WARN: wasm-bindgen pin drift: .tooling has ${WASM_BINDGEN_VERSION}, Cargo.lock has ${WASM_BINDGEN_LIB_VERSION}" >&2
fi

prepend_cached_wasm_bindgen "${WASM_BINDGEN_LIB_VERSION}"

if command -v wasm-bindgen >/dev/null 2>&1; then
  ACTUAL_WB_VER="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"
  if [ "${ACTUAL_WB_VER}" != "${WASM_BINDGEN_VERSION}" ]; then
    echo "WARN: wasm-bindgen version mismatch: expected ${WASM_BINDGEN_VERSION}, got ${ACTUAL_WB_VER}" >&2
    echo "  reinstall with: cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --force" >&2
  fi
fi

CRATE_DIR="${REPO_ROOT}/crates/chio-kernel-browser"

if [ ! -d "${CRATE_DIR}" ]; then
  echo "ERROR: crate directory not found: ${CRATE_DIR}" >&2
  exit 1
fi

build_target() {
  local package="${1}"
  local target="${2}"
  local out_dir="${3}"
  local mode_args=()

  if command -v wasm-bindgen >/dev/null 2>&1 && wasm_bindgen_matches_required "${WASM_BINDGEN_LIB_VERSION}"; then
    mode_args=(--mode no-install)
  fi

  mkdir -p "${out_dir}"

  echo "INFO: building chio-kernel-browser (package=${package}, target=${target}) -> ${out_dir}"
  (
    cd "${CRATE_DIR}"
    if [ "${WASM_PACK_FORCE_NO_OPT}" = true ]; then
      echo "INFO: cached wasm-bindgen mode uses --no-opt to avoid wasm-pack cache writes"
      wasm-pack build \
        "${mode_args[@]}" \
        --target "${target}" \
        --out-dir "${out_dir}" \
        --release \
        --no-opt
      exit 0
    fi

    if wasm-pack build \
      "${mode_args[@]}" \
      --target "${target}" \
      --out-dir "${out_dir}" \
      --release
    then
      exit 0
    fi

    echo "WARN: optimized wasm-pack build failed; retrying ${package}/${target} with --no-opt" >&2
    wasm-pack build \
      "${mode_args[@]}" \
      --target "${target}" \
      --out-dir "${out_dir}" \
      --release \
      --no-opt
  )
}

package_dir_for() {
  printf '%s/%s' "${TS_PACKAGES_DIR}" "${1}"
}

build_default_target() {
  local package_dir
  local out_dir
  package_dir="$(package_dir_for "${PACKAGE}")"
  if [ ! -d "${package_dir}" ]; then
    echo "ERROR: package directory not found: ${package_dir}" >&2
    exit 1
  fi

  if [ "${PACKAGE}" = "browser" ] && [ "${TARGET}" = "web" ]; then
    out_dir="${package_dir}/pkg"
  else
    out_dir="${package_dir}/dist/${TARGET}"
  fi

  build_target "${PACKAGE}" "${TARGET}" "${out_dir}"
}

build_all_targets_for_package() {
  local package="${1}"
  local package_dir
  local target
  package_dir="$(package_dir_for "${package}")"

  if [ ! -d "${package_dir}" ]; then
    if [ "${PACKAGE_EXPLICIT}" = true ]; then
      echo "ERROR: package directory not found: ${package_dir}" >&2
      exit 1
    fi
    echo "INFO: skipping missing package directory: ${package_dir}"
    return 0
  fi

  for target in ${WASM_PACK_TARGETS}; do
    build_target "${package}" "${target}" "${package_dir}/dist/${target}"
  done
}

if [ "${ALL_TARGETS}" = true ]; then
  if [ "${PACKAGE_EXPLICIT}" = true ]; then
    build_all_targets_for_package "${PACKAGE}"
  else
    build_all_targets_for_package "browser"
    build_all_targets_for_package "workers"
    build_all_targets_for_package "edge"
    build_all_targets_for_package "deno"
  fi
else
  build_default_target
fi

echo "INFO: wasm build complete."
