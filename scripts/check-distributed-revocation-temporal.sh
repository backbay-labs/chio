#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

./scripts/check-apalache-positive.sh \
  --temporal TemporalProjectionRefines \
  --no-deadlock \
  --length 5 \
  --timeout-seconds 1800 \
  --config formal/tla/MCDistributedRevocationTemporalRefinement.cfg \
  formal/tla/DistributedRevocationTemporalRefinement.tla

./scripts/check-apalache-positive.sh \
  --invariant FairObservationWitness \
  --no-deadlock \
  --length 3 \
  --timeout-seconds 300 \
  --config formal/tla/MCDistributedRevocationTemporalWitness.cfg \
  formal/tla/DistributedRevocationTemporalWitness.tla

./scripts/check-apalache-positive.sh \
  --temporal RevocationEventuallyObservedDistributed \
  --no-deadlock \
  --length 24 \
  --timeout-seconds 1800 \
  --config formal/tla/MCDistributedRevocationTemporal.cfg \
  formal/tla/DistributedRevocationTemporal.tla

echo "distributed-revocation temporal check: refinement, fairness witness, and liveness passed"
