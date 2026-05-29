#!/usr/bin/env bats
# shellcheck shell=bats
#
# Tests for `scripts/promote_fuzz_seed.sh --mode adversarial`.
#
# The adversarial mode auto-promotes a libFuzzer crash whose bytes decode
# cleanly into a triage-pending case under
# `crates/chio-adversarial-suite/cases/<class>/<sha>.json`. The placeholder
# `expected_verdict` is `DENY` and `pending` is `true` until a human triager
# confirms the verdict and strips the flag.
#
# Each test runs in a sandboxed temporary repo so it can mutate
# fuzz/corpus, fuzz/owners.toml, and crates/chio-adversarial-suite/cases
# without touching the live tree.
#
# This file is dual-runnable: `bats <file>` runs it as a Bats test suite,
# and the CI gate `bash <file>` re-execs itself under `bats` so
# the gate stays a simple `bash` invocation.

# When invoked under `bash` rather than `bats`, re-exec under bats and
# exit. The Bats parser never sees this block because Bats consumes the
# file's syntax tree directly without going through bash.
if [ -n "${BASH_VERSION:-}" ] && [ -z "${BATS_TEST_FILENAME:-}" ]; then
    if ! command -v bats >/dev/null 2>&1; then
        echo "promote_fuzz_seed_adversarial.bats: 'bats' binary not on PATH; install bats-core to run this gate" >&2
        exit 127
    fi
    exec bats "$0" "$@"
fi

setup() {
    REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
    SCRIPT="${REPO_ROOT}/scripts/promote_fuzz_seed.sh"

    SANDBOX="$(mktemp -d "${BATS_TMPDIR}/promote-adv.XXXXXX")"
    mkdir -p "${SANDBOX}/scripts" "${SANDBOX}/fuzz" \
        "${SANDBOX}/crates/chio-wasm-guards/tests" \
        "${SANDBOX}/crates/chio-adversarial-suite/cases"

    # Stage the script under test inside the sandbox so its REPO_ROOT
    # resolution lands on the sandbox.
    cp "${SCRIPT}" "${SANDBOX}/scripts/promote_fuzz_seed.sh"
    chmod +x "${SANDBOX}/scripts/promote_fuzz_seed.sh"

    # Minimal owners.toml: one target maps to a writable dummy crate.
    cat >"${SANDBOX}/fuzz/owners.toml" <<'EOF'
[targets.wasm_guard_escape]
crate = "chio-wasm-guards"
path  = "crates/chio-wasm-guards"
EOF

    # Stub Cargo.toml so the libfuzzer fallback path can run if invoked.
    cat >"${SANDBOX}/crates/chio-wasm-guards/Cargo.toml" <<'EOF'
[package]
name = "chio-wasm-guards"
version = "0.0.0"
edition = "2021"
EOF

    INPUT="${SANDBOX}/crash.bin"
}

teardown() {
    rm -rf "${SANDBOX}"
}

@test "rejects unknown --mode value" {
    printf 'crash' >"${INPUT}"
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode bogus \
        --class clock_rewound \
        --threat-id capability_token_theft
    [ "$status" -ne 0 ]
    [[ "$output" == *"--mode must be"* ]]
}

@test "adversarial mode requires --class" {
    printf 'crash' >"${INPUT}"
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode adversarial \
        --threat-id capability_token_theft
    [ "$status" -ne 0 ]
    [[ "$output" == *"--class"* ]]
}

@test "adversarial mode requires --threat-id" {
    printf 'crash' >"${INPUT}"
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode adversarial \
        --class clock_rewound
    [ "$status" -ne 0 ]
    [[ "$output" == *"--threat-id"* ]]
}

@test "adversarial mode rejects unknown attack class" {
    printf 'crash' >"${INPUT}"
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode adversarial \
        --class not_a_class \
        --threat-id capability_token_theft
    [ "$status" -ne 0 ]
    [[ "$output" == *"--class"* ]]
}

@test "adversarial mode rejects malformed threat id" {
    printf 'crash' >"${INPUT}"
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode adversarial \
        --class clock_rewound \
        --threat-id 'Bad Threat'
    [ "$status" -ne 0 ]
    [[ "$output" == *"--threat-id"* ]]
}

@test "non-adversarial modes reject --class and --threat-id" {
    printf 'crash' >"${INPUT}"
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode libfuzzer \
        --class clock_rewound
    [ "$status" -ne 0 ]
    [[ "$output" == *"only accepted with --mode adversarial"* ]]
}

@test "adversarial mode promotes a binary crash with pending triage flag" {
    # Use bytes that do NOT decode as a JSON object so we exercise the
    # fallback artifact-encoding path.
    printf '\x00\x01\xff\xfeBINARY-CRASH' >"${INPUT}"

    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode adversarial \
        --class clock_rewound \
        --threat-id capability_token_theft
    [ "$status" -eq 0 ]
    [[ "$output" == *"adversarial"* ]]

    # Exactly one case file was emitted under the requested class.
    case_file="$(find "${SANDBOX}/crates/chio-adversarial-suite/cases/clock_rewound" -type f -name '*.json' | head -n1)"
    [ -n "${case_file}" ]
    [ -f "${case_file}" ]

    # Required fields present and pending flag is true.
    grep -q '"pending": true' "${case_file}"
    grep -q '"expected_verdict": "DENY"' "${case_file}"
    grep -q '"class": "clock_rewound"' "${case_file}"
    grep -q '"threat_id": "capability_token_theft"' "${case_file}"
    grep -q '"schema_version": 1' "${case_file}"
    grep -q '"expected_reason":' "${case_file}"

    # Seed was relocated into the canonical corpus path.
    corpus_dir="${SANDBOX}/fuzz/corpus/wasm_guard_escape"
    [ -d "${corpus_dir}" ]
    corpus_file="$(find "${corpus_dir}" -type f -name '*.bin' | head -n1)"
    [ -n "${corpus_file}" ]
    [ -f "${corpus_file}" ]

    # Adversarial mode must NOT emit a regression .rs file under the owner crate's tests.
    if [ -d "${SANDBOX}/crates/chio-wasm-guards/tests" ]; then
        ! find "${SANDBOX}/crates/chio-wasm-guards/tests" -name 'regression_*.rs' | grep -q .
    fi
}

@test "adversarial mode preserves a clean JSON object as artifact" {
    cat >"${INPUT}" <<'EOF'
{"receipt": {"nonce": "abc", "issued_at": "2026-04-30T14:00:00Z"}}
EOF
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode adversarial \
        --class replayed_nonce \
        --threat-id native_channel_replay
    [ "$status" -eq 0 ]

    case_file="$(find "${SANDBOX}/crates/chio-adversarial-suite/cases/replayed_nonce" -type f -name '*.json' | head -n1)"
    [ -n "${case_file}" ]
    grep -q '"class": "replayed_nonce"' "${case_file}"
    grep -q '"threat_id": "native_channel_replay"' "${case_file}"
    grep -q '"pending": true' "${case_file}"
    grep -q '"artifact":' "${case_file}"
}

@test "adversarial mode is idempotent on second invocation with same seed" {
    printf 'idempotent-bytes' >"${INPUT}"

    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT}" \
        --mode adversarial \
        --class scope_superset \
        --threat-id delegation_chain_abuse
    [ "$status" -eq 0 ]

    # Re-run with a fresh copy of the same bytes; the canonical corpus
    # seed already exists, so the script must not error on the conflict.
    INPUT2="${SANDBOX}/crash2.bin"
    printf 'idempotent-bytes' >"${INPUT2}"
    run "${SANDBOX}/scripts/promote_fuzz_seed.sh" \
        --target wasm_guard_escape \
        --input "${INPUT2}" \
        --mode adversarial \
        --class scope_superset \
        --threat-id delegation_chain_abuse
    [ "$status" -eq 0 ]

    # The case directory still has exactly one JSON file for that hash.
    count="$(find "${SANDBOX}/crates/chio-adversarial-suite/cases/scope_superset" -type f -name '*.json' | wc -l | tr -d ' ')"
    [ "${count}" = "1" ]
}
