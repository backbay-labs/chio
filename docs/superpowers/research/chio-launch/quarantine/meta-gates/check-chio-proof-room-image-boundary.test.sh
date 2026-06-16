#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

tree="$(cd "$repo_root" && cargo tree -p chio-proof-room --edges normal --prefix none)"
for forbidden in \
  "alloy " \
  "chio-cli " \
  "chio-conformance " \
  "chio-kernel " \
  "chio-web3 " \
  "sigstore " \
  "wasmtime " \
  "webauthn-rs "
do
  if grep -Fq "$forbidden" <<<"$tree"; then
    echo "proof-room.dependency.heavy-edge: ${forbidden% }" >&2
    exit 1
  fi
done

echo "check-chio-proof-room-image-boundary.test.sh: Proof Room image boundary passed"
