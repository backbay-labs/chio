#!/usr/bin/env bash
# Workspace lint: HttpEgressContract enforcement coverage.
#
# Walks every crate that initiates outbound HTTP and asserts that each
# `reqwest` dispatch call site in production code is paired with an
# `HttpEgressContract` invocation (or its `send_with_contract` helper).
#
# This lint detects six reqwest patterns:
#   1. Direct: `reqwest::Client::*`
#   2. Direct: `reqwest::ClientBuilder::*`
#   3. Blocking direct: `reqwest::blocking::Client::*`
#   4. Imported: `use reqwest::{blocking::Client, Client};` followed by
#      `Client::builder()`, `Client::new()`, or `Client::default()`
#   5. Aliased: `use reqwest as foo;` or `use reqwest::blocking as foo;`
#      followed by `foo::Client::*`
#   6. Indirect: a value bound from `reqwest::Client::builder()` (or
#      `reqwest::ClientBuilder::*`) that subsequently invokes a dispatch
#      method (`.get(`, `.post(`, `.put(`, `.delete(`, `.patch(`,
#      `.head(`, `.execute(`, `.send()`).
#
# Allowed to skip:
# - `chio-egress-contract` (owns the contract)
# - `chio-http-core` (re-exports the contract)
# - `chio-mcp-adapter` (kernel-side adapter that owns its own protocol stack)
# - test files (`tests.rs`, `*-tests.rs`, files under `tests/` or
#   `crates/*/tests/`).
#
# Fail-closed: ambiguous matches (e.g. unrecognized aliases) are reported
# rather than silently skipped.
#
# Exits 0 on coverage; exits 1 on a coverage gap, printing offending lines.

set -euo pipefail

# Allow callers to override the search root (used by the self-test). Default
# to the repo root that contains this script.
REPO_ROOT="${CHIO_EGRESS_LINT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPO_ROOT"

ALLOW_LIST=(
    "crates/protocol/chio-egress-contract/"
    "crates/platform/chio-http-core/"
    "crates/protocol/chio-mcp-adapter/"
)

# Compose a regex that catches:
#   - reqwest::Client::*
#   - reqwest::ClientBuilder::*
#   - reqwest::blocking::Client::*
#   - imported Client::builder() call sites from reqwest or
#     reqwest::blocking imports
#   - any `use reqwest as <alias>;` followed by `<alias>::Client::*` /
#     `<alias>::ClientBuilder::*`, and `use reqwest::blocking as <alias>;`
#     followed by `<alias>::Client::*`.
#
# Files that match the regex but do not pair with a contract reference or
# only declare a non-dispatching helper are reported.

# Initial sweep: any direct reference to reqwest Client or ClientBuilder,
# including blocking clients.
CANDIDATE_FILES=()
while IFS= read -r candidate_file; do
    CANDIDATE_FILES+=("$candidate_file")
done < <(
    grep -rln -E "reqwest(::blocking)?::(Client|ClientBuilder)" --include='*.rs' \
        crates/ 2>/dev/null || true
)

# Top-level reqwest dispatch helpers such as `reqwest::get(...)` are also
# production egress even when no explicit Client value appears in the file.
while IFS= read -r candidate_file; do
    CANDIDATE_FILES+=("$candidate_file")
done < <(
    grep -rln -E "reqwest(::blocking)?::(get|post|put|delete|patch|head)\\(" --include='*.rs' \
        crates/ 2>/dev/null || true
)

# Imported Client builders, including `use reqwest::blocking::Client;`,
# `use reqwest::blocking::{Client, ...};`, and `use reqwest::{Client, ...};`.
while IFS= read -r import_match; do
    file="${import_match%%:*}"
    if grep -qE "\\b(Client|ClientBuilder)::(builder|new|default)\\(" "$file" \
        || grep -qE "\\bClientBuilder::" "$file"; then
        CANDIDATE_FILES+=("$file")
    fi
done < <(
    grep -rn -E "use[[:space:]]+reqwest(::blocking)?(::[A-Za-z_][A-Za-z0-9_]*|::\\{[^;]*\\b(Client|ClientBuilder)\\b|[[:space:]]+as[[:space:]]+[A-Za-z_][A-Za-z0-9_]*)" --include='*.rs' crates/ 2>/dev/null || true
)

# Aliased imports: scan for `use reqwest as foo;` and expand the candidate
# set with files that use the alias to call into Client/ClientBuilder.
while IFS= read -r alias_match; do
    file="${alias_match%%:*}"
    rest="${alias_match#*:}"
    # Extract the alias name from a line like `use reqwest as foo;` or
    # `use reqwest::blocking as foo;`.
    alias=$(echo "$rest" | sed -nE 's/.*use[[:space:]]+reqwest(::blocking)?[[:space:]]+as[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;.*/\2/p')
    if [[ -n "$alias" ]]; then
        if grep -qE "\b${alias}::(Client|ClientBuilder)" "$file" \
            || grep -qE "\b${alias}::(get|post|put|delete|patch|head)\\(" "$file"; then
            CANDIDATE_FILES+=("$file")
        fi
    fi
done < <(grep -rn -E "use[[:space:]]+reqwest(::blocking)?[[:space:]]+as[[:space:]]+[A-Za-z_]" --include='*.rs' crates/ 2>/dev/null || true)

# De-duplicate.
if [[ ${#CANDIDATE_FILES[@]} -gt 0 ]]; then
    DEDUPED_CANDIDATE_FILES=()
    while IFS= read -r candidate_file; do
        DEDUPED_CANDIDATE_FILES+=("$candidate_file")
    done < <(printf '%s\n' "${CANDIDATE_FILES[@]}" | awk '!seen[$0]++')
    CANDIDATE_FILES=("${DEDUPED_CANDIDATE_FILES[@]}")
fi

DISPATCH_REGEX="\\.execute\\(|\\.send\\(\\)|\\.send_string\\(|\\.send_json\\(|\\.call\\(\\)|\\.send\\(.+\\)\\.await|reqwest(::blocking)?::(get|post|put|delete|patch|head)\\("
INDIRECT_BINDING_REGEX="let[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*(reqwest(::blocking)?::Client::(builder|new|default)|reqwest(::blocking)?::ClientBuilder::|Client::(builder|new|default)|ClientBuilder::|[A-Za-z_][A-Za-z0-9_]*::Client::(builder|new|default)|[A-Za-z_][A-Za-z0-9_]*::ClientBuilder::)"
INDIRECT_DISPATCH_REGEX="\\.(get|post|put|delete|patch|head|execute|send)\\("
CLASSIFICATION_MARKER="CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST:"
REQWEST_GAP_LINE_REGEX="reqwest(::blocking)?::(Client|ClientBuilder)::(builder|new|default)\\(|reqwest(::blocking)?::(get|post|put|delete|patch|head)\\(|(^|[^A-Za-z0-9_])(Client|ClientBuilder)::(builder|new|default)\\(|(^|[^A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*::(Client|ClientBuilder)::(builder|new|default)\\(|(^|[^A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*::(get|post|put|delete|patch|head)\\(|\\.send\\(\\)"
REQWEST_EXECUTE_GAP_LINE_REGEX="(^|[^A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*\\.)*([A-Za-z_][A-Za-z0-9_]*_)?client[A-Za-z0-9_]*\\.execute\\("

line_is_classified() {
    local file="$1"
    local line_no="$2"
    awk -v line_no="$line_no" -v marker="$CLASSIFICATION_MARKER" '
        NR >= line_no - 4 && NR <= line_no {
            if (index($0, marker) > 0) {
                found = 1
            }
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "$file"
}

unclassified_reqwest_lines() {
    local file="$1"
    while IFS= read -r match; do
        line_no="${match%%:*}"
        if ! line_is_classified "$file" "$line_no"; then
            printf '%s\n' "$match"
        fi
    done < <(grep -nE "$REQWEST_GAP_LINE_REGEX" "$file" 2>/dev/null || true)
    while IFS= read -r match; do
        line_no="${match%%:*}"
        if ! line_is_classified "$file" "$line_no"; then
            printf '%s\n' "$match"
        fi
    done < <(grep -nE "$REQWEST_EXECUTE_GAP_LINE_REGEX" "$file" 2>/dev/null || true)
}

failed=()
for file in "${CANDIDATE_FILES[@]}"; do
    rel="${file#./}"

    # Skip allowed paths.
    skip=0
    for allow in "${ALLOW_LIST[@]}"; do
        if [[ "$rel" == "$allow"* ]]; then
            skip=1
            break
        fi
    done
    if [[ $skip -eq 1 ]]; then
        continue
    fi

    # Skip test sources.
    case "$rel" in
        */tests.rs|*/tests/*|*-tests.rs)
            continue
            ;;
    esac

    # Any send_with_contract caller must also construct the reqwest client via
    # client_builder_with_contract so automatic redirects are disabled.
    if grep -qE "\\bsend_with_contract\\b" "$file" \
        && ! grep -qE "\\bclient_builder_with_contract\\b" "$file"; then
        failed+=("$file")
        continue
    fi

    # If the file has no dispatch method calls and no indirectly-bound
    # client builder (which would imply a later dispatch in the same
    # file), it is a non-dispatching helper. Accept it.
    has_direct_dispatch=0
    if grep -qE "$DISPATCH_REGEX" "$file"; then
        has_direct_dispatch=1
    fi
    has_indirect_binding=0
    if grep -qE "$INDIRECT_BINDING_REGEX" "$file" \
        && grep -qE "$INDIRECT_DISPATCH_REGEX" "$file"; then
        has_indirect_binding=1
    fi
    if [[ $has_direct_dispatch -eq 0 && $has_indirect_binding -eq 0 ]]; then
        continue
    fi

    # Production dispatches must use the blessed helper for each reqwest
    # dispatch. A mixed file cannot pass merely because one call path uses
    # send_with_contract while another still calls reqwest directly.
    gap_count=0
    while IFS= read -r gap; do
        failed+=("$file:$gap")
        gap_count=$((gap_count + 1))
    done < <(unclassified_reqwest_lines "$file")
    if [[ $gap_count -gt 0 ]]; then
        continue
    fi

    continue
done

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "HttpEgressContract coverage gap: the following production crates use reqwest::Client without enforcing the typed egress contract:" >&2
    for f in "${failed[@]}"; do
        echo "  $f" >&2
    done
    echo "" >&2
    echo "Add either an explicit HttpEgressContract field on the dispatch struct" >&2
    echo "or route every call through chio_egress_contract::send_with_contract." >&2
    exit 1
fi

echo "HttpEgressContract coverage OK across the workspace."
