#!/usr/bin/env bash
# install-apalache.sh - Pin and install the Apalache TLA+ symbolic
# model checker used to discharge the RevocationPropagation spec.
#
# Pinned release: apalache-mc 0.50.x (see decisions.yml id=apalache-vs-tlc).
# This script is idempotent. It downloads the release tarball, extracts
# it under ~/.local/share/apalache, and links the launcher into
# ~/.local/bin/apalache-mc. Re-running with the pinned version is a
# no-op.

set -euo pipefail

APALACHE_VERSION="0.50.1"
APALACHE_RELEASE="v${APALACHE_VERSION}"
# Pinned SHA256 of apalache-${APALACHE_VERSION}.tgz from the upstream GitHub
# release. Apalache does not publish a separate checksum file, so we hard-pin
# the digest here to defend against tampering of the release asset or
# in-transit substitution. Refresh in lockstep with APALACHE_VERSION.
APALACHE_SHA256="4601ae8d1ac3f5e226ce8dc1db2df3d1bbdb9d904f3763eb982a244ed9f6ea6b"

uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "${uname_s}-${uname_m}" in
    Linux-x86_64)   ;;
    Linux-aarch64)  ;;
    Darwin-x86_64)  ;;
    Darwin-arm64)   ;;
    *) echo "unsupported platform: ${uname_s}-${uname_m}" >&2; exit 2 ;;
esac

if ! command -v java >/dev/null 2>&1; then
    echo "error: apalache-mc requires a Java 17+ runtime on PATH" >&2
    exit 3
fi

bin_dir="${HOME}/.local/bin"
share_dir="${HOME}/.local/share/apalache"
install_dir="${share_dir}/apalache-${APALACHE_VERSION}"
launcher="${install_dir}/bin/apalache-mc"
symlink="${bin_dir}/apalache-mc"

mkdir -p "${bin_dir}" "${share_dir}"
case ":${PATH}:" in
    *":${bin_dir}:"*) ;;
    *) echo "warning: ${bin_dir} is not on PATH; add it before invoking apalache-mc" >&2 ;;
esac

current_version=""
if [[ -x "${symlink}" ]]; then
    # Probe the existing launcher non-fatally. Any failure here (wrong Java
    # version, corrupted install, transient runtime error) must NOT abort
    # the script under `set -euo pipefail`; the installer recovers by
    # reinstalling the pinned tarball below. Match the recovery posture in
    # `scripts/install-orchestrator-tools.sh`.
    version_output="$("${symlink}" version 2>/dev/null || true)"
    current_version="$(printf '%s\n' "${version_output}" \
        | awk '/^EXITCODE/ {next} /[0-9]+\.[0-9]+\.[0-9]+/ {print $NF; exit}' \
        || true)"
fi

if [[ "${current_version}" == "${APALACHE_VERSION}" ]]; then
    echo "apalache-mc ${APALACHE_VERSION} already installed at ${symlink}"
    exit 0
fi

if [[ ! -x "${launcher}" ]]; then
    echo "installing apalache-mc ${APALACHE_VERSION}"
    asset="apalache-${APALACHE_VERSION}.tgz"
    # APALACHE_DOWNLOAD_URL is a test seam; defaults to the upstream release.
    # The checksum verification below is the real defense, so an attacker
    # controlling this variable cannot bypass the gate.
    url="${APALACHE_DOWNLOAD_URL:-https://github.com/apalache-mc/apalache/releases/download/${APALACHE_RELEASE}/${asset}}"
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT
    # Retry the download explicitly so a single transient curl failure does
    # not abort the installer under `set -euo pipefail`. curl's own --retry
    # already handles in-band retries; the outer loop survives total
    # connection failures (DNS flakes, GitHub release mirror hiccups).
    curl_attempts=0
    curl_max_attempts=5
    until curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 30 \
            "${url}" -o "${tmp_dir}/${asset}"; do
        curl_attempts=$((curl_attempts + 1))
        if [[ "${curl_attempts}" -ge "${curl_max_attempts}" ]]; then
            echo "error: failed to download ${url} after ${curl_max_attempts} attempts" >&2
            exit 5
        fi
        echo "warning: curl failed (attempt ${curl_attempts}/${curl_max_attempts}); retrying" >&2
        sleep $((curl_attempts * 2))
    done
    # Verify the pinned SHA256 before extraction. Reject any mismatch to
    # defend against supply-chain tampering (release-asset substitution,
    # MITM, or upstream re-tag). shasum is part of macOS base; sha256sum is
    # standard on Linux. Try the GNU tool first to keep error output short.
    if command -v sha256sum >/dev/null 2>&1; then
        actual_sha="$(sha256sum "${tmp_dir}/${asset}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual_sha="$(shasum -a 256 "${tmp_dir}/${asset}" | awk '{print $1}')"
    else
        echo "error: neither sha256sum nor shasum is available to verify ${asset}" >&2
        exit 6
    fi
    if [[ "${actual_sha}" != "${APALACHE_SHA256}" ]]; then
        echo "error: ${asset} sha256 mismatch" >&2
        echo "  expected: ${APALACHE_SHA256}" >&2
        echo "  actual:   ${actual_sha}" >&2
        exit 7
    fi
    tar -xzf "${tmp_dir}/${asset}" -C "${share_dir}"
    if [[ ! -x "${launcher}" ]]; then
        echo "error: extracted tree missing launcher at ${launcher}" >&2
        exit 4
    fi
fi

ln -sfn "${launcher}" "${symlink}"
echo "apalache-mc ${APALACHE_VERSION} installed at ${symlink}"
