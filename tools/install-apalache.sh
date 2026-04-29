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
    url="https://github.com/apalache-mc/apalache/releases/download/${APALACHE_RELEASE}/${asset}"
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
    tar -xzf "${tmp_dir}/${asset}" -C "${share_dir}"
    if [[ ! -x "${launcher}" ]]; then
        echo "error: extracted tree missing launcher at ${launcher}" >&2
        exit 4
    fi
fi

ln -sfn "${launcher}" "${symlink}"
echo "apalache-mc ${APALACHE_VERSION} installed at ${symlink}"
