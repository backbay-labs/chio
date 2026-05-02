#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/rebuild-from-source.sh [TAG]

Rebuild the Linux x86_64 chio-cli release binary from a signed source tag
using the pinned rust-toolchain.toml and a SOURCE_DATE_EPOCH derived from
the tag commit time. TAG defaults to the latest v*.*.* tag.

Set CHIO_REBUILD_OUT_DIR to choose the output directory.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

if [[ ! -f rust-toolchain.toml ]]; then
  echo "rebuild-from-source: rust-toolchain.toml is required" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "rebuild-from-source: refusing to run from a dirty worktree" >&2
  exit 1
fi

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  tag="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)"
fi
if [[ -z "${tag}" ]]; then
  echo "rebuild-from-source: no v*.*.* tag found" >&2
  exit 1
fi

semver_re='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?'
if ! [[ "${tag}" =~ ^v${semver_re}$ ]]; then
  echo "rebuild-from-source: tag '${tag}' does not match v<semver>" >&2
  exit 1
fi

tag_sha="$(git rev-list -n 1 "refs/tags/${tag}")"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "${tag_sha}")"
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
if [[ -n "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS} -C link-arg=-Wl,--threads=1 -C debuginfo=0"
else
  export RUSTFLAGS="-C link-arg=-Wl,--threads=1 -C debuginfo=0"
fi

build_root="${repo_root}"
tmp_root=""
if [[ "$(git rev-parse HEAD)" != "${tag_sha}" ]]; then
  tmp_root="$(mktemp -d)"
  trap 'git worktree remove --force "${tmp_root}/src" >/dev/null 2>&1 || true; rm -rf "${tmp_root}"' EXIT
  git worktree add --detach "${tmp_root}/src" "${tag_sha}" >/dev/null
  build_root="${tmp_root}/src"
fi

cd "${build_root}"
if [[ ! -f rust-toolchain.toml ]]; then
  echo "rebuild-from-source: tag ${tag} does not contain rust-toolchain.toml" >&2
  exit 1
fi

target="x86_64-unknown-linux-gnu"
toolchain="$(awk -F '"' '/channel[[:space:]]*=/{print $2; exit}' rust-toolchain.toml)"
if [[ -z "${toolchain}" ]]; then
  echo "rebuild-from-source: rust-toolchain.toml has no channel" >&2
  exit 1
fi

rustup toolchain install "${toolchain}" --profile minimal
rustup target add "${target}" --toolchain "${toolchain}"
cargo build --release --locked \
  --package chio-cli \
  --bin chio \
  --target "${target}"

out_dir="${CHIO_REBUILD_OUT_DIR:-${repo_root}/target/rebuild-from-source/${tag}}"
mkdir -p "${out_dir}"
cp "target/${target}/release/chio" "${out_dir}/chio"
{
  printf 'tag=%s\n' "${tag}"
  printf 'source_sha=%s\n' "${tag_sha}"
  printf 'source_date_epoch=%s\n' "${SOURCE_DATE_EPOCH}"
  printf 'toolchain=%s\n' "${toolchain}"
  printf 'target=%s\n' "${target}"
} > "${out_dir}/build-metadata.env"

(
  cd "${out_dir}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum chio > SHA256SUMS
  else
    shasum -a 256 chio > SHA256SUMS
  fi
  cat SHA256SUMS
)
