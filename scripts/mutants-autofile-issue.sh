#!/usr/bin/env bash
# mutants-autofile-issue.sh - File issues for cargo-mutants survivors beyond
# the inline PR comment cap.
#
# Usage:
#   scripts/mutants-autofile-issue.sh <pr-number> <mutants-output-dir>
#
# Environment:
#   GH_TOKEN                 : required by gh issue commands.
#   MUTANTS_PACKAGE          : package name for titles and fingerprints.
#   MUTANTS_PR_SURVIVOR_CAP  : number of survivors kept inline, default 5.
#   GITHUB_REPOSITORY        : owner/repo for gh --repo, optional locally.
#   GITHUB_SERVER_URL        : used to build workflow URLs.
#   GITHUB_RUN_ID            : used to build workflow URLs.

set -euo pipefail

PR_NUMBER="${1:-}"
OUTPUT_DIR="${2:-}"
PACKAGE="${MUTANTS_PACKAGE:-unknown}"
SURVIVOR_CAP="${MUTANTS_PR_SURVIVOR_CAP:-5}"
REPO_FULL="${GITHUB_REPOSITORY:-}"
RUN_URL=""

err() { printf '%s\n' "$*" >&2; }

if [[ -z "${PR_NUMBER}" || -z "${OUTPUT_DIR}" ]]; then
    err "usage: $0 <pr-number> <mutants-output-dir>"
    exit 1
fi

if [[ ! "${SURVIVOR_CAP}" =~ ^[0-9]+$ ]]; then
    err "invalid MUTANTS_PR_SURVIVOR_CAP=${SURVIVOR_CAP}; expected integer"
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    err "missing required tool: gh"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    err "missing required tool: jq"
    exit 1
fi

OUTCOMES_JSON="${OUTPUT_DIR}/outcomes.json"
if [[ ! -f "${OUTCOMES_JSON}" ]]; then
    printf 'mutants-autofile-issue: no outcomes.json at %s; nothing to file\n' "${OUTCOMES_JSON}"
    exit 0
fi

if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${REPO_FULL}" && -n "${GITHUB_RUN_ID:-}" ]]; then
    RUN_URL="${GITHUB_SERVER_URL}/${REPO_FULL}/actions/runs/${GITHUB_RUN_ID}"
fi

repo_args=()
if [[ -n "${REPO_FULL}" ]]; then
    repo_args=(--repo "${REPO_FULL}")
fi

issue_label_args=()
available_labels="$(gh label list "${repo_args[@]}" --limit 200 --json name --jq '.[].name' 2>/dev/null || true)"
for desired_label in mutants-survivor triage; do
    if grep -Fxq "${desired_label}" <<<"${available_labels}"; then
        issue_label_args+=(--label "${desired_label}")
    else
        printf 'mutants-autofile-issue: label %s is unavailable; continuing without it\n' \
            "${desired_label}" >&2
    fi
done

hash_input() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    else
        err "neither sha256sum nor shasum is available"
        return 1
    fi
}

survivors_json=$(jq -c --argjson cap "${SURVIVOR_CAP}" '
    def outcomes:
        if (.outcomes | type) == "array" then .outcomes
        elif (.outcomes | type) == "object" then [.outcomes[]]
        elif type == "array" then .
        else []
        end;
    def verdict: (.summary // .status // "unknown");
    def survivor: verdict == "MissedMutant" or verdict == "Timeout";
    def pathish($value):
        if ($value | type) == "object" then
            pathish($value.path // $value.file // $value.name // empty)
        elif ($value | type) == "string" then
            if $value == "" or $value == "null" then empty else $value end
        elif $value == null then
            empty
        else
            ($value | tostring)
        end;
    def source_file:
        (pathish(.scenario.mutant.source_file)
         // pathish(.source_file)
         // pathish(.file)
         // pathish(.filename)
         // "unknown");
    def source_line:
        (.scenario.mutant.span.start.line
         // .scenario.mutant.line
         // .line
         // 0);
    def replacement:
        (.scenario.mutant.replacement
         // .scenario.mutant.description
         // .scenario.name
         // .description
         // "unknown mutation");
    [outcomes[] | select(survivor)]
    | .[$cap:]
    | .[]
    | {
        verdict: verdict,
        source_file: source_file,
        source_line: source_line,
        replacement: replacement
      }
' "${OUTCOMES_JSON}")

if [[ -z "${survivors_json}" ]]; then
    printf 'mutants-autofile-issue: no survivors beyond inline cap %s for %s\n' \
        "${SURVIVOR_CAP}" "${PACKAGE}"
    exit 0
fi

filed=0
while IFS= read -r survivor; do
    [[ -n "${survivor}" ]] || continue

    verdict=$(jq -r '.verdict' <<<"${survivor}")
    source_file=$(jq -r '.source_file' <<<"${survivor}")
    source_line=$(jq -r '.source_line' <<<"${survivor}")
    replacement=$(jq -r '.replacement' <<<"${survivor}")
    location="${source_file}:${source_line}"

    fingerprint=$(printf '%s|%s|%s|%s|%s' \
        "${PACKAGE}" "${source_file}" "${source_line}" "${verdict}" "${replacement}" \
        | hash_input)
    fingerprint_prefix=$(printf '%s' "${fingerprint}" | cut -c1-16)
    issue_title="[mutants-survivor] ${PACKAGE}: ${fingerprint_prefix}"

    existing=$(gh issue list "${repo_args[@]}" \
        --state open \
        --search "\"${fingerprint_prefix}\" in:title,body" \
        --limit 100 \
        --json number,title \
        --jq '.[0].number')

    if [[ -n "${existing}" && "${existing}" != "null" ]]; then
        # Literal Markdown code spans are intentional in the issue body.
        # shellcheck disable=SC2016
        body=$(printf 'Recurrence detected by `mutants.yml`.\n\n- PR: #%s\n- Package: `%s`\n- Location: `%s`\n- Verdict: `%s`\n- Fingerprint: `%s`\n' \
            "${PR_NUMBER}" "${PACKAGE}" "${location}" "${verdict}" "${fingerprint_prefix}")
        if [[ -n "${RUN_URL}" ]]; then
            body="${body}
- Workflow run: ${RUN_URL}"
        fi
        gh issue comment "${existing}" "${repo_args[@]}" --body "${body}"
        continue
    fi

    body_file=$(mktemp)
    {
        # Literal Markdown code spans are intentional in the issue body.
        # shellcheck disable=SC2016
        printf 'Auto-filed by `mutants.yml` for PR #%s.\n\n' "${PR_NUMBER}"
        printf '### Package\n%s\n\n' "${PACKAGE}"
        printf '### Survivor fingerprint\n%s\n\n' "${fingerprint_prefix}"
        printf '### Source location\n%s\n\n' "${location}"
        printf '### Cargo-mutants verdict\n%s\n\n' "${verdict}"
        # shellcheck disable=SC2016
        printf '### Mutation\n```\n%s\n```\n\n' "${replacement}"
        printf '### Triage notes\n'
        printf -- '- Inline survivor cap: %s\n' "${SURVIVOR_CAP}"
        if [[ -n "${RUN_URL}" ]]; then
            printf -- '- Workflow run: %s\n' "${RUN_URL}"
        fi
        printf -- '- Preferred fix: add or strengthen tests.\n'
        # shellcheck disable=SC2016
        printf -- '- Skip path: update `mutants.toml` with a rationale and link this issue.\n\n'
        # shellcheck disable=SC2016
        printf 'See `docs/fuzzing/mutants.md` for survivor triage policy.\n'
    } >"${body_file}"

    gh issue create "${repo_args[@]}" \
        --title "${issue_title}" \
        "${issue_label_args[@]}" \
        --body-file "${body_file}"
    rm -f "${body_file}"
    filed=$((filed + 1))
done <<<"${survivors_json}"

printf 'mutants-autofile-issue: filed %s new issue(s) for %s\n' "${filed}" "${PACKAGE}"
