#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
  cargo test -p chio-agent-web-interop --test agent_web_interop \
  core_tests::published_agent_web_schemas_accept_supported_projection_fixtures -- --exact

CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
  cargo test -p chio-agent-web-interop --test agent_web_interop \
  core_tests::published_v1_proof_envelope_schema_accepts_legacy_shape -- --exact

CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
  cargo test -p chio-agent-web-interop --test agent_web_interop \
  core_tests::published_v2_proof_envelope_schema_requires_scope_and_unique_receipts -- --exact

CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
  cargo test -p chio-agent-web-interop --test agent_web_interop \
  core_tests::verifier_accepts_signed_legacy_v1_envelope -- --exact
