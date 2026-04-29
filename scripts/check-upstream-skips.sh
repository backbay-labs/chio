#!/usr/bin/env bash
# check-upstream-skips.sh - Sunset gate for fuzz/upstream_skips.toml.
#
# Why this exists
# ---------------
# Fuzz targets occasionally trip on instability in upstream deps
# (wasmtime nightly, libfuzzer-sys releases, arbitrary, regex-syntax,
# etc.) instead of real Chio bugs. The skip table at
# fuzz/upstream_skips.toml lets us record those false positives with a
# bounded sunset date so they cannot rot. This script enforces the
# bounds:
#
#   1. Each [[skips]] entry must declare target, reason, upstream_issue,
#      and sunset.
#   2. sunset must parse as a real ISO-8601 date (YYYY-MM-DD).
#   3. sunset must be >= today (UTC). Expired skips fail the gate so
#      the team is forced to re-evaluate the upstream bug.
#   4. sunset must be within 90 days of today (no long-lived skips).
#   5. upstream_issue must be an http(s):// URL.
#
# Usage:
#   scripts/check-upstream-skips.sh
#   scripts/check-upstream-skips.sh --dry-run
#   scripts/check-upstream-skips.sh --file fuzz/upstream_skips.toml
#   scripts/check-upstream-skips.sh --today 2026-04-26
#
# Exit codes:
#   0 = all skips current and valid (or table is empty)
#   1 = at least one skip is expired or out of bounds
#   2 = bad invocation, missing file, or unparseable TOML
#
# Dependencies: bash 3.2+, awk, date. No TOML library required: the
# parser is intentionally narrow and only understands the schema above
# (one [[skips]] section per entry, simple key = "value" pairs, plus
# the documented `skips = []` sentinel for an empty table).

set -euo pipefail

PROG="$(basename "$0")"

DEFAULT_FILE="fuzz/upstream_skips.toml"
FILE=""
DRY_RUN=0
TODAY_OVERRIDE=""

err() { printf '%s: %s\n' "${PROG}" "$*" >&2; }
die() { err "$1"; exit "${2:-2}"; }

usage() {
    cat <<USAGE
Usage: ${PROG} [--dry-run] [--file PATH] [--today YYYY-MM-DD] [--help]

Validates fuzz/upstream_skips.toml entries against the sunset gate
(max 90 days, must not be expired). Run with no arguments to gate the
default file.

Options:
  --dry-run         Skip parsing; emit a self-test line and exit 0.
  --file PATH       Override input path (default: ${DEFAULT_FILE}).
  --today DATE      Override "today" for testing (default: date -u).
  --help            Show this help and exit 0.
USAGE
}

while (( $# > 0 )); do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --file)
            [[ $# -ge 2 ]] || die "--file requires an argument"
            FILE="$2"; shift 2 ;;
        --file=*) FILE="${1#--file=}"; shift ;;
        --today)
            [[ $# -ge 2 ]] || die "--today requires an argument"
            TODAY_OVERRIDE="$2"; shift 2 ;;
        --today=*) TODAY_OVERRIDE="${1#--today=}"; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

if (( DRY_RUN )); then
    printf '%s: dry-run OK\n' "${PROG}"
    exit 0
fi

if [[ -z "${FILE}" ]]; then
    FILE="${DEFAULT_FILE}"
fi

if [[ ! -f "${FILE}" ]]; then
    die "skip table not found: ${FILE}" 2
fi

# Resolve today (UTC) once, allow tests to inject a fixed value.
if [[ -n "${TODAY_OVERRIDE}" ]]; then
    TODAY="${TODAY_OVERRIDE}"
else
    TODAY="$(date -u +%Y-%m-%d)"
fi

# Validate TODAY shape.
if ! [[ "${TODAY}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    die "today value is not YYYY-MM-DD: ${TODAY}" 2
fi

# Convert YYYY-MM-DD to days-since-epoch in a portable way (works on
# both BSD date and GNU date). We only need a monotonic integer to
# compare two dates, so any consistent transform is fine.
date_to_days() {
    local d="$1"
    if ! [[ "${d}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        return 1
    fi
    local epoch
    case "$(uname -s)" in
        Darwin)
            epoch="$(date -u -j -f '%Y-%m-%d' "${d}" +%s 2>/dev/null)" || return 1
            ;;
        *)
            epoch="$(date -u -d "${d}" +%s 2>/dev/null)" || return 1
            ;;
    esac
    printf '%s' $(( epoch / 86400 ))
}

today_days="$(date_to_days "${TODAY}")" \
    || die "failed to normalize today: ${TODAY}" 2
max_days=$(( today_days + 90 ))

# Parse the TOML using awk. We support exactly the schema documented in
# fuzz/upstream_skips.toml. The parser emits one line per entry of the
# form: "target|reason|upstream_issue|sunset". Empty/comment lines and
# the documented `skips = []` sentinel are ignored. Anything else is
# rejected as a parse error so typos like `[[skip]]` (singular) cannot
# silently pass the gate (regression: r3144336375).
parsed="$(awk '
BEGIN {
    in_entry = 0
    target = ""; reason = ""; issue = ""; sunset = ""
}
function emit(   _) {
    if (in_entry) {
        if (target == "" || reason == "" || issue == "" || sunset == "") {
            printf "PARSE_ERROR|missing field in [[skips]] entry near line %d|%s|%s\n", NR, target, sunset
        } else {
            printf "%s|%s|%s|%s\n", target, reason, issue, sunset
        }
    }
    in_entry = 0
    target = ""; reason = ""; issue = ""; sunset = ""
}
# Strip a single inline `#` comment from the right side of a value while
# respecting double-quoted strings. Without this guard a fragment-bearing
# URL like "https://example/issues/1#issuecomment-2" loses everything
# from `#` onward and the closing quote, breaking validation
# (regression: r3144340128).
function strip_inline_comment(s,    i, n, c, in_quotes, out, len) {
    n = length(s)
    in_quotes = 0
    out = ""
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "\"") {
            in_quotes = !in_quotes
            out = out c
            continue
        }
        if (c == "#" && !in_quotes) {
            break
        }
        out = out c
    }
    # Trim trailing whitespace introduced by the comment removal.
    sub(/[[:space:]]+$/, "", out)
    return out
}
function strip_quotes(s,    n) {
    n = length(s)
    if (n >= 2 && substr(s,1,1) == "\"" && substr(s,n,1) == "\"") {
        return substr(s, 2, n-2)
    }
    return s
}
{
    line = $0
    sub(/^[[:space:]]+/, "", line)
    sub(/[[:space:]]+$/, "", line)
    if (line == "" || substr(line,1,1) == "#") next
    if (line == "[[skips]]") { emit(); in_entry = 1; next }
    # Skip the documented empty-table sentinel.
    if (line ~ /^skips[[:space:]]*=[[:space:]]*\[\][[:space:]]*$/) next
    if (in_entry) {
        # Match `key = value` lines without relying on gawk-only
        # match(...,array) capture syntax. Split on the first "=".
        eq = index(line, "=")
        if (eq > 1) {
            key = substr(line, 1, eq - 1)
            val = substr(line, eq + 1)
            sub(/[[:space:]]+$/, "", key)
            sub(/^[[:space:]]+/, "", val)
            val = strip_inline_comment(val)
            val = strip_quotes(val)
            if (key == "target") target = val
            else if (key == "reason") reason = val
            else if (key == "upstream_issue") issue = val
            else if (key == "sunset") sunset = val
            else {
                printf "PARSE_ERROR|unknown key %q in [[skips]] entry near line %d|%s|%s\n", key, NR, target, sunset
            }
        } else {
            printf "PARSE_ERROR|unparseable line in [[skips]] entry near line %d (%s)|%s|%s\n", NR, line, target, sunset
        }
    } else {
        # Any other top-level content is unrecognised. Fail closed so a
        # typo like `[[skip]]` (singular) cannot pass the sunset gate.
        printf "PARSE_ERROR|unknown top-level content at line %d (%s)|%s|%s\n", NR, line, target, sunset
    }
}
END { emit() }
' "${FILE}" 2>/dev/null)" || die "awk failed to parse ${FILE}" 2

# An empty parse result with no errors means an empty skip table; that
# is the steady state and a valid PASS.
if [[ -z "${parsed}" ]]; then
    printf '%s: %s has no active skips (today=%s)\n' \
        "${PROG}" "${FILE}" "${TODAY}"
    exit 0
fi

# Walk parsed entries. We distinguish parse errors (structural failures
# in the TOML) from policy errors (expired / out-of-bounds skips) so the
# caller can map them to the documented exit-code contract:
#   exit 1 = at least one policy violation
#   exit 2 = at least one structural parse failure
# (regression: r3144336377 / r3144340129).
parse_errors=0
policy_errors=0
total=0
while IFS='|' read -r target reason issue sunset; do
    [[ -z "${target}${reason}${issue}${sunset}" ]] && continue
    if [[ "${target}" == "PARSE_ERROR" ]]; then
        err "parse error: ${reason}"
        parse_errors=$(( parse_errors + 1 ))
        continue
    fi
    total=$(( total + 1 ))

    # Validate upstream_issue URL.
    if ! [[ "${issue}" =~ ^https?://[^[:space:]]+$ ]]; then
        err "skip ${target}: upstream_issue is not an http(s) URL: ${issue}"
        policy_errors=$(( policy_errors + 1 ))
    fi

    # Validate sunset shape and bounds.
    sunset_days="$(date_to_days "${sunset}" 2>/dev/null || true)"
    if [[ -z "${sunset_days}" ]]; then
        err "skip ${target}: sunset is not a valid YYYY-MM-DD: ${sunset}"
        policy_errors=$(( policy_errors + 1 ))
        continue
    fi
    if (( sunset_days < today_days )); then
        err "skip ${target}: sunset ${sunset} has expired (today=${TODAY}); remove or re-evaluate"
        policy_errors=$(( policy_errors + 1 ))
    fi
    if (( sunset_days > max_days )); then
        err "skip ${target}: sunset ${sunset} is more than 90 days out (today=${TODAY}); reduce per house rule (max 90d)"
        policy_errors=$(( policy_errors + 1 ))
    fi
done <<< "${parsed}"

# Parse errors take precedence over policy errors so callers that
# distinguish "the file is malformed" from "the file is valid but the
# skip is expired" get the right signal.
if (( parse_errors > 0 )); then
    err "FAIL (parse): ${parse_errors} structural problem(s) in ${FILE}"
    exit 2
fi
if (( policy_errors > 0 )); then
    err "FAIL: ${policy_errors} problem(s) across ${total} skip entr(y/ies) in ${FILE}"
    exit 1
fi

printf '%s: OK (%d valid skip entr(y/ies) in %s, today=%s)\n' \
    "${PROG}" "${total}" "${FILE}" "${TODAY}"
exit 0
