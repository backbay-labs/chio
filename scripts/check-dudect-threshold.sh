#!/usr/bin/env bash
# check-dudect-threshold.sh - Parse dudect-bencher stdout and verdict
# the maximum |t|-statistic against the leakage threshold (default 4.5).
#
# The dudect CI lane invokes this script once per harness output file and
# uses its exit code (0 = under threshold, 1 = over threshold) as a
# per-run verdict. A leak alarm requires TWO consecutive nightly runs to
# BOTH return exit 1 for the same harness ("two-consecutive-run pass rule"),
# which the workflow enforces by comparing the current verdict against the
# prior run's artifact before opening a GitHub Issue.
#
# Why 4.5:
#   The dudect paper (Reparaz, Balasch, Verbauwhede - 2017) recommends a
#   Welch's t-statistic threshold of |t| > 4.5 as the "highly statistically
#   significant" cutoff for declaring a constant-time violation. Below that
#   value the observed timing variance is consistent with measurement
#   noise; above it the data-dependent path is distinguishable with high
#   confidence. The threshold is a literal in this script (gate-required:
#   `grep -qE '4\.5'`) so a future relaxation/tightening is a deliberate
#   edit rather than a config drift.
#
# dudect-bencher 0.7 stdout shape (relevant lines):
#
#     running 1 bench
#     bench jwt_verify_bench seeded with 0xdeadbeef_cafef00d
#     bench jwt_verify_bench ... : n == +0.040M, max t = +2.13, max tau = ...
#
# The parser extracts every "max t = <signed-float>" occurrence, takes
# the absolute value, tracks the maximum, and compares against THRESHOLD.
#
# Usage:
#   scripts/check-dudect-threshold.sh --dry-run
#       Self-test: parse a built-in synthetic input, exit 0 if the parser
#       and the arithmetic agree on the synthetic max. Used by the gate
#       check in `.github/workflows/dudect.yml` and by the source-doc
#       gate-check command. No file I/O.
#
#   scripts/check-dudect-threshold.sh --input <file> [--threshold <T>]
#       Real use: parse <file>, extract max |t|, compare against T
#       (default 4.5). Prints a one-line verdict to stdout in the form:
#           dudect verdict: max|t|=<value> threshold=<T> result=<PASS|FAIL>
#       Exits 0 on PASS (max |t| < threshold) or 1 on FAIL (>=).
#
# Exit codes:
#   0   parse OK and (dry-run agreed | input under threshold)
#   1   input over threshold (real use only)
#   2   precondition failure (bad args, file missing, no t-stat lines found,
#       arithmetic helper missing)

set -euo pipefail

THRESHOLD_DEFAULT="4.5"

usage() {
    cat <<'USAGE'
Usage:
  check-dudect-threshold.sh --dry-run
  check-dudect-threshold.sh --input <file> [--threshold <T>]

Exits:
  0 PASS or dry-run OK
  1 FAIL (max |t| >= threshold)
  2 precondition failure
USAGE
}

err() { printf '%s\n' "$*" >&2; }

# extract_max_abs_t <file>
# Reads <file>, prints the maximum |t|-statistic found across all
# "max t = <signed-float>" occurrences. Empty output if no t-stats found.
# Uses awk for the parse + abs + max in one pass; no bc/python dep.
#
# Output uses awk's "%.17g" format - the round-trip-safe IEEE-754 double
# representation. Truncating to "%.4f" here would round borderline values
# such as 4.49996 up to 4.5000 and produce false FAIL verdicts under the
# two-consecutive-run rule. The verdict comparison downstream re-parses
# this value with awk + 0.0, so full precision is preserved end-to-end.
extract_max_abs_t() {
    local input="$1"
    awk '
        # Match the dudect-bencher 0.7 stdout fragment. The t value is a
        # signed float that may carry a leading + or -; awk + 0.0 coerces
        # to numeric and handles both. Allow optional fractional digits so
        # we accept high-precision lines like "max t = +61.61472".
        match($0, /max t = [+-]?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/) {
            seg = substr($0, RSTART, RLENGTH)
            sub(/max t = /, "", seg)
            v = seg + 0.0
            if (v < 0) v = -v
            if (v > maxv) maxv = v
            seen = 1
        }
        END {
            if (seen) printf "%.17g\n", maxv
        }
    ' "$input"
}

# self_test
# Parses a synthetic input that contains both above-threshold and
# below-threshold t-stats with mixed signs, verifies the parser picks the
# correct maximum (5.7321), and exits 0 on agreement. Intended for the
# `--dry-run` gate-check path; never touches the filesystem outside of a
# private tmp file that is unlinked on exit.
self_test() {
    local tmp
    tmp="$(mktemp -t dudect-threshold-dry.XXXXXX)"
    trap 'rm -f -- "${tmp}"' EXIT

    cat >"${tmp}" <<'SAMPLE'
running 1 bench
bench fake_left_right seeded with 0x0000000000000000
bench fake_left_right ... : n == +0.001M, max t = +1.2345, max tau = +1.000e-3
bench fake_left_right ... : n == +0.002M, max t = -3.4500, max tau = +2.000e-3
bench fake_left_right ... : n == +0.004M, max t = +5.7321, max tau = +3.000e-3
bench fake_left_right ... : n == +0.008M, max t = -2.0000, max tau = +1.500e-3
SAMPLE

    # Compare numerically rather than as strings: extract_max_abs_t now
    # emits "%.17g" round-trip precision, which can render a synthetic
    # 5.7321 as "5.7320999999999998" depending on awk's libc. The parser
    # contract is "preserve the input value to f64 precision", verified by
    # an awk numeric equality check rather than a literal string compare.
    local got
    got="$(extract_max_abs_t "${tmp}")"
    local want="5.7321"

    if [[ -z "${got}" ]]; then
        err "dry-run self-test FAIL: parser produced no output"
        exit 2
    fi

    local agree
    agree="$(awk -v a="${got}" -v b="${want}" \
        'BEGIN { print ((a + 0.0) - (b + 0.0) < 1e-9 && (b + 0.0) - (a + 0.0) < 1e-9) ? "OK" : "MISMATCH" }')"

    if [[ "${agree}" != "OK" ]]; then
        err "dry-run self-test FAIL: parser got '${got}', expected '${want}' (numeric mismatch)"
        exit 2
    fi

    printf 'dudect threshold script dry-run OK (parser max|t|=%s vs synthetic=%s)\n' \
        "${got}" "${want}"
    exit 0
}

# is_positive_number <string>
# Returns 0 (true) when the argument parses as a strictly-positive float
# (1.5, 4.5, 0.001, 1e3 etc.) and 1 (false) otherwise. Used to reject
# garbage --threshold inputs before they get coerced to 0 by awk + 0.0,
# which would otherwise misclassify almost every harness output as FAIL
# and fire spurious sustained-leak issues under the two-run correlation
# rule.
is_positive_number() {
    local s="$1"
    [[ -n "${s}" ]] || return 1
    awk -v s="${s}" '
        BEGIN {
            # Reject strings that do not match a real-number shape.
            if (s !~ /^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$/) exit 1
            # awk + 0.0 coerces empty / non-numeric tail to 0; the regex
            # above rules that out, so v reflects the parsed magnitude.
            v = s + 0.0
            if (v <= 0) exit 1
            exit 0
        }
    '
}

# verdict <input-file> <threshold>
# Real use: extract max |t|, compare to threshold, print verdict, exit
# 0 (PASS) or 1 (FAIL). Exit 2 on missing file or no t-stats.
verdict() {
    local input="$1"
    local threshold="$2"

    if [[ ! -r "${input}" ]]; then
        err "input file not readable: ${input}"
        exit 2
    fi

    local max_t
    max_t="$(extract_max_abs_t "${input}")"

    if [[ -z "${max_t}" ]]; then
        err "no 'max t = <float>' lines found in ${input}; nothing to verdict"
        exit 2
    fi

    # Numeric compare via awk (avoids bc dep). Returns 1 (FAIL) when
    # max_t >= threshold per the dudect paper's "highly significant" rule.
    local result
    result="$(awk -v a="${max_t}" -v b="${threshold}" 'BEGIN { print (a + 0.0 >= b + 0.0) ? "FAIL" : "PASS" }')"

    printf 'dudect verdict: max|t|=%s threshold=%s result=%s\n' \
        "${max_t}" "${threshold}" "${result}"

    if [[ "${result}" == "FAIL" ]]; then
        exit 1
    fi
    exit 0
}

main() {
    if [[ $# -eq 0 ]]; then
        usage >&2
        exit 2
    fi

    local dry_run="false"
    local input=""
    local threshold="${THRESHOLD_DEFAULT}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                dry_run="true"
                shift
                ;;
            --input)
                if [[ $# -lt 2 ]]; then
                    err "--input requires a path argument"
                    exit 2
                fi
                input="$2"
                shift 2
                ;;
            --threshold)
                if [[ $# -lt 2 ]]; then
                    err "--threshold requires a numeric argument"
                    exit 2
                fi
                if ! is_positive_number "$2"; then
                    err "--threshold must be a strictly-positive number; got '$2'"
                    exit 2
                fi
                threshold="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "unknown argument: $1"
                usage >&2
                exit 2
                ;;
        esac
    done

    if [[ "${dry_run}" == "true" ]]; then
        self_test
    fi

    if [[ -z "${input}" ]]; then
        err "missing --input <file> (or pass --dry-run for the self-test)"
        usage >&2
        exit 2
    fi

    verdict "${input}" "${threshold}"
}

main "$@"
