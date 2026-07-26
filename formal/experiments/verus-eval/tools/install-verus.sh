#!/usr/bin/env bash
# install-verus.sh - Pin and install the Verus SMT-backed Rust verifier
# used by the FV-B5 evaluation spike
# (docs/formal/plan/FV-B5-verus-concurrency-evaluation.md).
#
# Pinned release: release/0.2026.07.18.3a4d30b.
# x86_64 Linux installs the upstream binary release under a hard-pinned
# sha256 (upstream publishes no separate checksum file). aarch64 Linux has
# no upstream binary asset, so it builds from source at the pinned tag and
# refuses to proceed if the cloned commit differs from the pinned hash.
# This script is idempotent: an existing install whose marker records the
# pinned identity is relinked and nothing is rebuilt. Any other content at
# the install path is refused, never overwritten.

set -euo pipefail

VERUS_VERSION="0.2026.07.18.3a4d30b"
VERUS_TAG="release/${VERUS_VERSION}"
VERUS_COMMIT="3a4d30bcdc4571e7927af97be9c4664973083eda"
VERUS_RUSTC="1.96.0"
VERUS_Z3="4.12.5"
# The upstream z3 4.12.5 arm64-glibc release zip contains an x86-64 binary
# (verified 2026-07-23), so aarch64 builds z3 from source at this pinned
# commit instead of trusting the mislabeled asset.
Z3_COMMIT="a7b564cafe3b96c8a868388bc4b96b319facea44"
# sha256 of verus-0.2026.07.18.3a4d30b-x86-linux.zip from the upstream
# GitHub release. Refresh in lockstep with VERUS_VERSION.
VERUS_X86_LINUX_SHA256="7097a91ea4bf5896a418d90743626cbe5c085ce5ef8a64ed8d84c0aa5e49ac55"

PREFIX="${VERUS_PREFIX:-${HOME}/.local/share/verus}"
BIN_DIR="${VERUS_BIN_DIR:-${HOME}/.local/bin}"
INSTALL_DIR="${PREFIX}/${VERUS_VERSION}"
MARKER="${INSTALL_DIR}/.chio-pin"
EXPECTED_MARKER="${VERUS_TAG} ${VERUS_COMMIT}"

link_binary() {
    mkdir -p "${BIN_DIR}"
    ln -sf "${INSTALL_DIR}/verus" "${BIN_DIR}/verus"
    echo "verus ${VERUS_VERSION} linked at ${BIN_DIR}/verus"
}

if [ -e "${INSTALL_DIR}" ]; then
    if [ -f "${MARKER}" ] && [ "$(cat "${MARKER}")" = "${EXPECTED_MARKER}" ] \
        && [ -x "${INSTALL_DIR}/verus" ]; then
        link_binary
        exit 0
    fi
    echo "refusing: ${INSTALL_DIR} exists but does not record the pinned" >&2
    echo "identity '${EXPECTED_MARKER}'. Remove it manually to reinstall." >&2
    exit 2
fi

uname_s="$(uname -s)"
uname_m="$(uname -m)"

install_x86_linux() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp}"' EXIT
    local zip="${tmp}/verus.zip"
    curl -sSfL -o "${zip}" \
        "https://github.com/verus-lang/verus/releases/download/${VERUS_TAG}/verus-${VERUS_VERSION}-x86-linux.zip"
    echo "${VERUS_X86_LINUX_SHA256}  ${zip}" | sha256sum -c - >/dev/null || {
        echo "refusing: release asset digest mismatch" >&2
        exit 2
    }
    unzip -q "${zip}" -d "${tmp}/unpacked"
    local verus_bin
    verus_bin="$(find "${tmp}/unpacked" -maxdepth 2 -type f -name verus | head -1)"
    if [ -z "${verus_bin}" ]; then
        echo "refusing: no verus binary in the release asset" >&2
        exit 2
    fi
    mkdir -p "${PREFIX}"
    mv "$(dirname "${verus_bin}")" "${INSTALL_DIR}"
}

install_source_build() {
    local src="${PREFIX}/src-${VERUS_VERSION}"
    rm -rf "${src}"
    mkdir -p "${PREFIX}"
    git clone --quiet --depth 1 --branch "${VERUS_TAG}" \
        https://github.com/verus-lang/verus.git "${src}"
    local head
    head="$(git -C "${src}" rev-parse HEAD)"
    if [ "${head}" != "${VERUS_COMMIT}" ]; then
        echo "refusing: cloned commit ${head} does not match pinned" >&2
        echo "${VERUS_COMMIT} for ${VERUS_TAG}" >&2
        rm -rf "${src}"
        exit 2
    fi
    (cd "${src}" && rustup toolchain install)
    local z3_src="${PREFIX}/z3-src-${VERUS_Z3}"
    rm -rf "${z3_src}"
    git clone --quiet --depth 1 --branch "z3-${VERUS_Z3}" \
        https://github.com/Z3Prover/z3.git "${z3_src}"
    local z3_head
    z3_head="$(git -C "${z3_src}" rev-parse HEAD)"
    if [ "${z3_head}" != "${Z3_COMMIT}" ]; then
        echo "refusing: z3 commit ${z3_head} does not match pinned ${Z3_COMMIT}" >&2
        rm -rf "${z3_src}"
        exit 2
    fi
    # Z3_INCLUDE_GIT_HASH=OFF keeps the version string exactly "4.12.5";
    # rust_verify exact-matches it and rejects the from-git hashcode suffix.
    cmake -S "${z3_src}" -B "${z3_src}/build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DZ3_BUILD_LIBZ3_SHARED=OFF \
        -DZ3_INCLUDE_GIT_HASH=OFF -DZ3_INCLUDE_GIT_DESCRIBE=OFF >/dev/null
    ninja -C "${z3_src}/build" shell >/dev/null
    cp "${z3_src}/build/z3" "${src}/source/z3"
    local z3_version
    z3_version="$("${src}/source/z3" --version)"
    case "${z3_version}" in
        *"${VERUS_Z3}"*) ;;
        *)
            echo "refusing: z3 version '${z3_version}' is not pinned ${VERUS_Z3}" >&2
            rm -rf "${z3_src}"
            exit 2
            ;;
    esac
    (cd "${src}/source" && bash -c 'source ../tools/activate && vargo build --release')
    if [ ! -x "${src}/source/target-verus/release/verus" ]; then
        echo "refusing: build produced no verus binary" >&2
        exit 2
    fi
    cp -a "${src}/source/target-verus/release" "${INSTALL_DIR}"
    if [ ! -x "${INSTALL_DIR}/z3" ] && [ -x "${src}/source/z3" ]; then
        cp -a "${src}/source/z3" "${INSTALL_DIR}/z3"
    fi
}

case "${uname_s}-${uname_m}" in
    Linux-x86_64) install_x86_linux ;;
    Linux-aarch64) install_source_build ;;
    *)
        echo "unsupported platform: ${uname_s}-${uname_m}" >&2
        echo "(upstream binary assets exist for x86 linux, x86/arm64 macos," >&2
        echo "x86 windows; extend this script deliberately, not ad hoc)" >&2
        exit 2
        ;;
esac

echo "${EXPECTED_MARKER}" > "${MARKER}"
link_binary
"${BIN_DIR}/verus" --version
