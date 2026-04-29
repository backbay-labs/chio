#!/usr/bin/env bash
# shellcheck disable=SC2016
# (Backticks inside single-quoted printf strings are intentional Markdown
# code-span literals for the report.md / log output, not command
# substitution. Disabling SC2016 file-wide keeps the wall-of-warnings
# from masking real findings.)
#
# mutants-fuzz-cocoverage.sh - replay the libFuzzer corpus against
# surviving cargo-mutants mutants. Cross-oracle nightly; advisory.
#
# Cross-oracle insight (the why):
#
#   - cargo-mutants flags a "surviving mutant" when the unit suite
#     fails to detect the mutation. Surviving mutants represent test
#     gaps.
#   - The libFuzzer corpus under fuzz/corpus/<target>/ is a different
#     oracle: accumulated adversarial inputs that exercise paths the
#     unit suite often does not reach.
#   - Replaying the corpus against the MUTATED binary may catch mutants
#     that the unit suite missed. Cross-oracle reduction in missed-
#     mutant count: expected 5-15%.
#
# Architecture (the how):
#
#   The naive approach - replaying the corpus once against the current
#   tree - cannot work. cargo-mutants applies each mutation to a TEMP
#   work tree, runs the test suite there, and then discards it; the
#   source-tree binary the script can reach has none of those mutations
#   applied. Replaying against it measures "does the corpus crash the
#   clean binary" (which should always be no), not the cocoverage signal.
#
#   The fix: drive mutant injection per-survivor by re-shelling
#   `cargo mutants` with `--file <path> --line <start>:<end>` plus a
#   custom `--test-tool` that runs OUR fuzz-replay against the mutated
#   tree cargo-mutants prepared. cargo-mutants applies the patch,
#   builds, invokes our wrapper as the "test", and reverts.
#   `--test-tool` is documented in cargo-mutants 25.x as the
#   substitution point for non-`cargo test` workflows. The wrapper's
#   exit code feeds straight into cargo-mutants' verdict for that
#   mutant; libFuzzer signalling (crash / leak / assert) is reported
#   as "caught by fuzz oracle".
#
# Always advisory: never fails the calling workflow. Emits a per-
# package summary.json and a human-readable report.md.
#
# Usage:
#
#   scripts/mutants-fuzz-cocoverage.sh \
#     --package chio-kernel-core \
#     --mutants-out mutants-out/chio-kernel-core \
#     --corpus-root fuzz/corpus \
#     --report-out  cocoverage-out/chio-kernel-core \
#     [--fuzz-runs 200000] \
#     [--per-mutant-budget-seconds 120]
#
# Exit codes:
#   0  always (advisory). Non-zero only on argument-validation failure.

set -euo pipefail

print_usage() {
    cat <<'USAGE'
mutants-fuzz-cocoverage.sh - cross-oracle nightly cocoverage runner.

Required:
  --package <name>           Crate name (informational; surfaces in report).
  --mutants-out <dir>        Directory holding cargo-mutants outcomes.json.
  --corpus-root <dir>        Root of fuzz/corpus/ (per-target subdirs).
  --report-out  <dir>        Output directory for summary.json + report.md.

Optional:
  --fuzz-runs <int>          libFuzzer --runs= per replay (default 200000).
  --per-mutant-budget-seconds <int>
                             Wall-clock cap per mutant replay (default 120).
  -h | --help                Show this help and exit 0.
USAGE
}

PACKAGE=""
MUTANTS_OUT=""
CORPUS_ROOT=""
REPORT_OUT=""
FUZZ_RUNS="200000"
PER_MUTANT_BUDGET="120"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --package)
            PACKAGE="${2:-}"
            shift 2
            ;;
        --mutants-out)
            MUTANTS_OUT="${2:-}"
            shift 2
            ;;
        --corpus-root)
            CORPUS_ROOT="${2:-}"
            shift 2
            ;;
        --report-out)
            REPORT_OUT="${2:-}"
            shift 2
            ;;
        --fuzz-runs)
            FUZZ_RUNS="${2:-}"
            shift 2
            ;;
        --per-mutant-budget-seconds)
            PER_MUTANT_BUDGET="${2:-}"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            printf 'cocoverage: unknown argument: %s\n' "$1" >&2
            print_usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "${PACKAGE}" || -z "${MUTANTS_OUT}" || -z "${CORPUS_ROOT}" || -z "${REPORT_OUT}" ]]; then
    printf 'cocoverage: missing required arguments\n' >&2
    print_usage >&2
    exit 2
fi

mkdir -p "${REPORT_OUT}"

summary_json="${REPORT_OUT}/summary.json"
report_md="${REPORT_OUT}/report.md"
log_file="${REPORT_OUT}/replay.log"

: > "${log_file}"

# Best-effort: locate cargo-mutants outcomes.json. cargo-mutants 25.x
# writes outcomes.json directly under --output; older layouts nest it
# under mutants.out/. Probe both.
outcomes_json=""
for candidate in \
    "${MUTANTS_OUT}/outcomes.json" \
    "${MUTANTS_OUT}/mutants.out/outcomes.json"; do
    if [[ -f "${candidate}" ]]; then
        outcomes_json="${candidate}"
        break
    fi
done

if [[ -z "${outcomes_json}" ]]; then
    printf 'cocoverage: no outcomes.json under %s; emitting empty report (advisory)\n' \
        "${MUTANTS_OUT}" | tee -a "${log_file}"
    printf '{\n  "package": "%s",\n  "surviving_mutants": 0,\n  "fuzz_replays_attempted": 0,\n  "fuzz_replays_caught": 0,\n  "note": "no cargo-mutants outcomes.json found"\n}\n' \
        "${PACKAGE}" > "${summary_json}"
    {
        printf '# Cocoverage report: %s\n\n' "${PACKAGE}"
        printf 'No `outcomes.json` was produced by cargo-mutants under `%s`.\n' "${MUTANTS_OUT}"
        printf 'This is advisory; the workflow continues.\n'
    } > "${report_md}"
    exit 0
fi

# Map a cargo-mutants source-file path to the most-likely fuzz target
# directory under fuzz/corpus/. The mapping is intentionally explicit:
# silent fall-through could mis-replay an unrelated corpus and inflate
# the "caught" count. Add new mappings here when new fuzz targets land.
map_source_to_fuzz_target() {
    local src_path="$1"
    case "${src_path}" in
        *capability_verify*|*capability*receipts*|*receipts*)
            echo "capability_receipt"
            ;;
        *passport_verify*)
            echo "anchor_bundle_verify"
            ;;
        *jwt_vc*|*credentials*jwt*)
            echo "jwt_vc_verify"
            ;;
        *oid4vp*|*presentation*)
            echo "oid4vp_presentation"
            ;;
        *did_resolve*|*registry*)
            echo "did_resolve"
            ;;
        *attest*)
            echo "attest_verify"
            ;;
        *manifest*)
            echo "manifest_roundtrip"
            ;;
        *acp_envelope*|*acp/*)
            echo "acp_envelope_decode"
            ;;
        *a2a_envelope*|*a2a/*)
            echo "a2a_envelope_decode"
            ;;
        *mcp_envelope*|*mcp/*)
            echo "mcp_envelope_decode"
            ;;
        *yaml*|*hushspec*)
            echo "chio_yaml_parse"
            ;;
        *openapi*)
            echo "openapi_ingest"
            ;;
        *receipt_log*|*replay*)
            echo "receipt_log_replay"
            ;;
        *wasm*|*preinstantiate*)
            echo "wasm_preinstantiate_validate"
            ;;
        *wit*|*host_call*)
            echo "wit_host_call_boundary"
            ;;
        *canonical_json*|*normalized*)
            echo "canonical_json"
            ;;
        *)
            echo ""
            ;;
    esac
}

# replay_one_mutant <source_file> <line_start> <target_name>
#
# Re-shells cargo-mutants for a single specific mutant location, with
# our fuzz-replay wrapper as the substituted test command. cargo-mutants
# prepares a temp tree with the mutation applied, builds it, then
# invokes the test-tool from the temp tree's working directory; that is
# the point at which `cargo +nightly fuzz run` sees the MUTATED binary.
#
# Returns 0 if the fuzz oracle did NOT signal (mutant survived in fuzz
# too), 1 if libFuzzer crashed / asserted / leaked (mutant caught), and
# 124 on per-mutant timeout (treated as "no signal" for accounting).
replay_one_mutant() {
    local source_file="$1"
    local line_start="$2"
    local target_name="$3"

    local target_corpus="${CORPUS_ROOT}/${target_name}"
    if [[ ! -d "${target_corpus}" ]]; then
        printf 'cocoverage: corpus dir missing for target=%s; skipping\n' \
            "${target_name}" >> "${log_file}"
        return 0
    fi

    # Construct a one-shot shell wrapper that cargo-mutants will invoke
    # as `--test-tool`. Stored in a tempdir so concurrent crates do not
    # clobber each other's wrappers when this script is run from a
    # matrix job in parallel.
    local wrapper_dir
    wrapper_dir="$(mktemp -d -t cocoverage-XXXXXX)"
    local wrapper="${wrapper_dir}/test-tool.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'set -euo pipefail\n'
        printf '# Runs the fuzz target corpus replay against the MUTATED binary.\n'
        printf 'exec timeout %s cargo +nightly fuzz run %s -- -runs=%s %s\n' \
            "${PER_MUTANT_BUDGET}" \
            "${target_name}" \
            "${FUZZ_RUNS}" \
            "${target_corpus}"
    } > "${wrapper}"
    chmod +x "${wrapper}"

    local replay_status=0
    cargo mutants \
        --package "${PACKAGE}" \
        --file "${source_file}" \
        --line "${line_start}" \
        --no-shuffle \
        --jobs 1 \
        --test-tool "${wrapper}" \
        --output "${wrapper_dir}/mutants-out" \
        >> "${log_file}" 2>&1 \
        || replay_status=$?

    rm -rf -- "${wrapper_dir}"
    return "${replay_status}"
}

# Walk outcomes.json. cargo-mutants 25.x marks survivors with
# .summary == "MissedMutant" (confirmed in scripts/mutants-comment.sh)
# and exposes .scenario.mutant.source_file as an OBJECT with a `.path`
# sub-field; this script previously consumed it as a bare string,
# producing garbled paths like {"path":"crates/foo/src/lib.rs"}.
surviving_count=0
attempted_count=0
caught_count=0
mapped_count=0
unmapped_count=0

if command -v jq >/dev/null 2>&1; then
    while IFS=$'\t' read -r source_path line_start outcome_summary; do
        [[ -z "${source_path}" ]] && continue
        case "${outcome_summary}" in
            MissedMutant|missed)
                ;;
            *)
                continue
                ;;
        esac
        surviving_count=$((surviving_count + 1))

        target_name="$(map_source_to_fuzz_target "${source_path}")"
        if [[ -z "${target_name}" ]]; then
            unmapped_count=$((unmapped_count + 1))
            printf 'cocoverage: unmapped source=%s; skipping replay\n' \
                "${source_path}" >> "${log_file}"
            continue
        fi
        mapped_count=$((mapped_count + 1))

        # Per-mutant replay. We deliberately do NOT deduplicate by
        # target: two surviving mutants in the same file may exercise
        # disjoint code paths, and the corpus might catch one but not
        # the other. Skipping later survivors biases the cocoverage
        # ratio downward.
        attempted_count=$((attempted_count + 1))
        printf 'cocoverage: replay survivor source=%s line=%s -> target=%s runs=%s\n' \
            "${source_path}" "${line_start}" "${target_name}" "${FUZZ_RUNS}" \
            | tee -a "${log_file}"

        replay_status=0
        replay_one_mutant "${source_path}" "${line_start}" "${target_name}" \
            || replay_status=$?

        # cargo-mutants returns 0 if the test-tool succeeded against the
        # mutant (== mutant SURVIVED fuzz too), and non-zero (typically
        # 1 with "found N mutants missed") when the test-tool failed
        # against the mutant (== fuzz oracle signalled, mutant CAUGHT).
        # Per-mutant timeout (124) is treated as "no signal" for the
        # accounting; the wall-clock cap is recorded in the log.
        if [[ "${replay_status}" -ne 0 && "${replay_status}" -ne 124 ]]; then
            caught_count=$((caught_count + 1))
            printf 'cocoverage: target=%s caught (cargo-mutants verdict status=%s)\n' \
                "${target_name}" "${replay_status}" \
                | tee -a "${log_file}"
        fi
    done < <(jq -r '
        .outcomes[]?
        | [
            (.scenario.mutant.source_file.path // ""),
            ((.scenario.mutant.span.start.line // 0) | tostring),
            (.summary // "")
        ]
        | @tsv
    ' "${outcomes_json}" 2>/dev/null || true)
else
    # jq absent: parse outcomes.json line-wise as a best-effort survivor
    # COUNT only. The mutated-binary replay path requires a structured
    # walk of source_file.path + span.start.line, which is brittle
    # without jq, so the no-jq branch reports survivors and skips the
    # cross-oracle phase rather than emit fabricated "caught" numbers.
    #
    # The literal substring is `"MissedMutant"` (with the closing quote
    # AFTER 'Mutant', not after 'Missed') - cargo-mutants emits that
    # exact tag for surviving mutants. Earlier revisions of this script
    # searched for `"Missed"` which is never a substring of
    # `"MissedMutant"` (the next char is 'M', not '"').
    while IFS= read -r line; do
        if [[ "${line}" == *'"summary"'*'"MissedMutant"'* ]]; then
            surviving_count=$((surviving_count + 1))
        fi
    done < "${outcomes_json}"
    printf 'cocoverage: jq missing; emitted survivor count only (no replay) = %s\n' \
        "${surviving_count}" | tee -a "${log_file}"
fi

# Emit summary.json. Hand-rolled to avoid a jq dependency.
{
    printf '{\n'
    printf '  "package": "%s",\n' "${PACKAGE}"
    printf '  "surviving_mutants": %s,\n' "${surviving_count}"
    printf '  "mapped_to_fuzz_target": %s,\n' "${mapped_count}"
    printf '  "unmapped": %s,\n' "${unmapped_count}"
    printf '  "fuzz_replays_attempted": %s,\n' "${attempted_count}"
    printf '  "fuzz_replays_caught": %s,\n' "${caught_count}"
    printf '  "expected_reduction_band": "5-15%%",\n'
    printf '  "advisory": true\n'
    printf '}\n'
} > "${summary_json}"

# Emit a human-readable report.md.
{
    printf '# Cocoverage report: %s\n\n' "${PACKAGE}"
    printf '_Cross-oracle nightly. Advisory only._\n\n'
    printf '| Metric | Count |\n'
    printf '| --- | ---: |\n'
    printf '| Surviving mutants | %s |\n' "${surviving_count}"
    printf '| Mapped to a fuzz target | %s |\n' "${mapped_count}"
    printf '| Unmapped (no replay) | %s |\n' "${unmapped_count}"
    printf '| Fuzz replays attempted | %s |\n' "${attempted_count}"
    printf '| Fuzz replays caught (libFuzzer signalled against mutant) | %s |\n\n' "${caught_count}"
    printf 'Expected cross-oracle reduction band: **5-15%%**.\n\n'
    printf 'Each surviving mutant is replayed individually: cargo-mutants\n'
    printf 'is re-shelled per survivor with `--file` + `--line` and a\n'
    printf '`--test-tool` wrapper that runs `cargo fuzz run` against the\n'
    printf 'corpus, so the libFuzzer corpus exercises the mutated binary\n'
    printf '(not the clean source tree).\n\n'
    printf 'See `replay.log` for per-target detail. Mapping table is in\n'
    printf '`scripts/mutants-fuzz-cocoverage.sh::map_source_to_fuzz_target`.\n'
} > "${report_md}"

printf 'cocoverage: package=%s survivors=%s attempted=%s caught=%s (advisory)\n' \
    "${PACKAGE}" "${surviving_count}" "${attempted_count}" "${caught_count}"

exit 0
