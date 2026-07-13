#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

apalache_bin="${APALACHE_BIN:-apalache-mc}"
if ! command -v "${apalache_bin}" >/dev/null 2>&1 && [[ ! -x "${apalache_bin}" ]]; then
  echo "distributed-revocation temporal check: Apalache executable not found: ${apalache_bin}" >&2
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "distributed-revocation temporal check: timeout command is required" >&2
  exit 2
fi

apalache_bin="$(command -v "${apalache_bin}")"
version="$(${apalache_bin} version 2>&1)"
if [[ "${version}" != "0.50.1" ]]; then
  echo "distributed-revocation temporal check: Apalache 0.50.1 is required" >&2
  exit 2
fi

timeout 1800 "${apalache_bin}" check \
  --no-deadlock \
  --length=5 \
  --temporal=TemporalProjectionRefines \
  --config=formal/tla/MCDistributedRevocationTemporalRefinement.cfg \
  formal/tla/DistributedRevocationTemporalRefinement.tla

timeout 300 "${apalache_bin}" check \
  --no-deadlock \
  --length=3 \
  --config=formal/tla/MCDistributedRevocationTemporalWitness.cfg \
  formal/tla/DistributedRevocationTemporalWitness.tla

timeout 1800 "${apalache_bin}" check \
  --no-deadlock \
  --length=24 \
  --temporal=RevocationEventuallyObservedDistributed \
  --config=formal/tla/MCDistributedRevocationTemporal.cfg \
  formal/tla/DistributedRevocationTemporal.tla

echo "distributed-revocation temporal check: refinement, fairness witness, and liveness passed"
