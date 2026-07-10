#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
  cargo test -p chio-agent-web-interop --test agent_web_interop \
  core_tests::published_agent_web_schemas_accept_supported_projection_fixtures -- --exact
