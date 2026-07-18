#!/usr/bin/env bash
# Source this file from the repository root before running the Proof Room
# source-checkout quickstart. These keys are checked-in fixture trust anchors
# for local verification only.

_chio_proof_env_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/chio-proof-trusted-keys.sh
source "$_chio_proof_env_root/scripts/lib/chio-proof-trusted-keys.sh"
unset _chio_proof_env_root
