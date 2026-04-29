#!/usr/bin/env bash
#
# ClusterFuzzLite build entry point for Chio (formerly ARC).
#
# Builds the chio-fuzz targets listed below and copies each resulting
# binary into $OUT/<target>, plus a per-target seed corpus zip when one
# exists under fuzz/corpus/<target>/. Set CHIO_CFLITE_TARGET to build a
# single target or CHIO_CFLITE_TARGETS to build a newline/comma-separated
# subset selected by the PR changed-target workflow.
#
# Companion docs in docs/fuzzing/continuous.md (ClusterFuzzLite bridge section).
#
# This script mirrors infra/oss-fuzz/build.sh. The two scripts MUST enumerate
# the same target set; the OSS-Fuzz copy is the source-of-truth, so any new
# fuzz target lands in BOTH files in the same change set.

set -euo pipefail

# Move into the standalone fuzz workspace. cargo-fuzz emits binaries under
# the workspace's target/ tree, namespaced by host triple; CFLite builders
# run on x86_64-unknown-linux-gnu.
cd "$SRC/arc/fuzz"

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
    wit_host_call_boundary
    chio_yaml_parse
    openapi_ingest
    receipt_log_replay
    canonical_json
    capability_receipt
    manifest_roundtrip
    fuzz_policy_parse_compile
    fuzz_sql_parser
    fuzz_merkle_checkpoint
    fuzz_tool_action
)

selected_targets=("${TARGETS[@]}")
if [ -n "${CHIO_CFLITE_TARGETS:-}" ] && [ -n "${CHIO_CFLITE_TARGET:-}" ]; then
    echo "set only one of CHIO_CFLITE_TARGETS or CHIO_CFLITE_TARGET" >&2
    exit 1
fi

if [ -n "${CHIO_CFLITE_TARGETS:-}" ]; then
    mapfile -t requested_targets < <(printf '%s\n' "${CHIO_CFLITE_TARGETS}" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | sort -u)
    if [ "${#requested_targets[@]}" -eq 0 ]; then
        echo "CHIO_CFLITE_TARGETS was set but no target names were provided" >&2
        exit 1
    fi
    selected_targets=()
    for requested in "${requested_targets[@]}"; do
        found=false
        for target in "${TARGETS[@]}"; do
            if [ "$target" = "$requested" ]; then
                found=true
                selected_targets+=("$target")
                break
            fi
        done
        if [ "$found" != "true" ]; then
            echo "unknown CHIO_CFLITE_TARGETS entry: $requested" >&2
            exit 1
        fi
    done
elif [ -n "${CHIO_CFLITE_TARGET:-}" ]; then
    found=false
    for target in "${TARGETS[@]}"; do
        if [ "$target" = "$CHIO_CFLITE_TARGET" ]; then
            found=true
            selected_targets=("$target")
            break
        fi
    done
    if [ "$found" != "true" ]; then
        echo "unknown CHIO_CFLITE_TARGET: $CHIO_CFLITE_TARGET" >&2
        exit 1
    fi
fi

for target in "${selected_targets[@]}"; do
    cargo +nightly fuzz build "$target" --release --sanitizer "$SANITIZER"
    cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"

    # Pack the per-target seed corpus when one exists in-tree.
    if [ -d "corpus/$target" ] && [ -n "$(ls -A "corpus/$target" 2>/dev/null)" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "corpus/$target"/*
    fi
done
