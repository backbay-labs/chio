#!/usr/bin/env bash
#
# OSS-Fuzz build entry point for Chio.
#
# Builds every chio-fuzz target listed below and copies the resulting
# binary into $OUT/<target>, plus a per-target seed corpus zip when one
# exists under fuzz/corpus/<target>/.
#
# See docs/fuzzing/continuous.md for OSS-Fuzz integration details.

set -euo pipefail

# Move into the standalone fuzz workspace. cargo-fuzz emits binaries under
# the workspace's target/ tree, namespaced by host triple; OSS-Fuzz builders
# run on x86_64-unknown-linux-gnu.
cd "$SRC/chio/fuzz"

TARGETS=(
    attest_verify
    jwt_vc_verify
    oid4vp_presentation
    did_resolve
    anchor_bundle_verify
    mcp_envelope_decode
    a2a_envelope_decode
    acp_envelope_decode
    wasm_preinstantiate_validate
    wasm_guard_escape
    wasm_guard_smith
    wit_host_call_boundary
    chio_yaml_parse
    openapi_ingest
    receipt_log_replay
    eval_receipt_bundle
    canonical_json
    capability_receipt
    manifest_roundtrip
    federation_trust_establishment
    underwriting_policy_input
    fuzz_policy_parse_compile
    policy_analyze
    fuzz_sql_parser
    fuzz_merkle_checkpoint
    revocation_oracle_merkle
    fuzz_tool_action
)

for target in "${TARGETS[@]}"; do
    cargo +nightly fuzz build "$target" --release --sanitizer "$SANITIZER"
    # Binaries land under the fuzz workspace's own `target/` tree:
    # `$SRC/chio/fuzz` is a standalone Cargo workspace with its own
    # `[workspace]` stanza, not the parent project's target dir.
    cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"

    # Pack the per-target seed corpus when one exists in-tree.
    if [ -d "corpus/$target" ] && [ -n "$(ls -A "corpus/$target" 2>/dev/null)" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "corpus/$target"/*
    fi
done
