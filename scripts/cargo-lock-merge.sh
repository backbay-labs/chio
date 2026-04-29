#!/usr/bin/env bash
# cargo-lock-merge.sh - Custom git merge driver for Cargo.lock.
#
# Invoked by git when a three-way merge encounters Cargo.lock conflicts.
# Driver contract (per gitattributes(5) merge=<driver>):
#   $1  ancestor version  (%O)
#   $2  current version   (%A)        - written back to in-place
#   $3  other version     (%B)
#   $4  marker size       (%L)        - unused
#   $5  conflicted path   (%P)        - "Cargo.lock"
#
# Strategy: discard the conflict entirely, regenerate Cargo.lock from the
# merged Cargo.toml tree using `cargo update --workspace`, and assert
# reproducibility via `cargo metadata --locked`. The driver assumes
# Cargo.toml conflicts (workspace + members) are already resolved by the
# merge queue or human reviewer; this driver does NOT attempt to merge
# dep-version conflicts in manifests.
#
# Registered in .gitattributes:
#   Cargo.lock merge=cargo-lock-regen
# and in .git/config (per repo, set by scripts/setup-git-merge-drivers.sh):
#   [merge "cargo-lock-regen"]
#       name = Cargo.lock regeneration
#       driver = scripts/cargo-lock-merge.sh %O %A %B %L %P
#
# Exit codes:
#   0  merged successfully (current version updated)
#   1  regeneration failed; leave conflict markers untouched for human review

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC2034   # documented for clarity even when unused below
ancestor="$1"
current="$2"
other="$3"
marker_size="${4:-7}"
conflict_path="${5:-Cargo.lock}"

err() { printf 'cargo-lock-merge: %s\n' "$*" >&2; }

if [[ "${conflict_path}" != "Cargo.lock" ]]; then
    err "refusing to handle non-Cargo.lock conflict at ${conflict_path}"
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    err "cargo not on PATH; cannot regenerate Cargo.lock"
    exit 1
fi

cd "${ROOT}"

# Touch Cargo.lock to a known empty-ish state so cargo regenerates from
# scratch using the current Cargo.toml tree. Preserve the conflicted file
# in case regeneration fails.
backup="$(mktemp -t cargo-lock-merge.XXXXXX)"
cp -f "${current}" "${backup}"
trap 'rm -f "${backup}"' EXIT

# `cargo update --workspace` regenerates the lockfile to satisfy the
# current Cargo.toml without changing any deliberately-locked versions
# beyond what the manifest requires. If the manifest tree still has
# unresolved conflict markers, this fails fast and we surface that.
if ! cargo update --workspace --quiet 2>"${backup}.err"; then
    err "cargo update --workspace failed; restoring conflicted Cargo.lock"
    err "  see $(realpath "${backup}.err") for cargo output"
    cp -f "${backup}" "${current}"
    exit 1
fi

# Confirm reproducibility: metadata must resolve against the regenerated lock.
if ! cargo metadata --locked --no-deps --format-version 1 >/dev/null 2>"${backup}.err"; then
    err "cargo metadata --locked rejected the regenerated Cargo.lock"
    err "  see $(realpath "${backup}.err") for cargo output"
    cp -f "${backup}" "${current}"
    exit 1
fi

# git expects the merged result in-place at "${current}". cargo update
# writes Cargo.lock at the workspace root, which is the same path.
cp -f "${ROOT}/Cargo.lock" "${current}"
printf 'cargo-lock-merge: regenerated Cargo.lock (other=%s)\n' "${other}"
exit 0
