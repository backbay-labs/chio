#!/usr/bin/env bash
# Self-test for scripts/check-http-egress-contract.sh.
#
# Synthesizes positive and negative cases for each pattern the lint
# claims to recognise (direct, ClientBuilder, aliased, indirect binding).
# The negative cases construct tiny fake crates under a temp dir and
# point the lint at each via the CHIO_EGRESS_LINT_ROOT override.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LINT="$REPO_ROOT/scripts/check-http-egress-contract.sh"

work="$(mktemp -d -t chio-egress-lint-XXXXXX)"
trap 'rm -rf "$work"' EXIT

# Synthetic positive: crate that builds the reqwest client through the egress
# helper and dispatches through send_with_contract.
mkdir -p "$work/positive/crates/chio-fake-positive/src"
cat > "$work/positive/crates/chio-fake-positive/src/lib.rs" <<'EOF'
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

pub async fn dispatch(contract: &HttpEgressContract) {
    let client: reqwest::Client = client_builder_with_contract(contract).build().unwrap();
    let req = client.get("https://example.com").build().unwrap();
    let _ = send_with_contract(contract, &client, req).await;
}
EOF

# Synthetic negative: crate that uses reqwest::Client without the contract.
mkdir -p "$work/negative/crates/chio-fake-negative/src"
cat > "$work/negative/crates/chio-fake-negative/src/lib.rs" <<'EOF'
pub async fn dispatch(client: &reqwest::Client) {
    let _ = client.get("https://example.com").send().await;
}
EOF

# Synthetic negative: crate that uses reqwest::ClientBuilder + .send() with
# no contract. The lint must flag the builder form, not just literal
# `reqwest::Client`.
mkdir -p "$work/negative_builder/crates/chio-fake-builder/src"
cat > "$work/negative_builder/crates/chio-fake-builder/src/lib.rs" <<'EOF'
pub async fn dispatch() {
    let client = reqwest::Client::builder().build().unwrap();
    let _ = client.get("https://example.com").send().await;
}
EOF

# Synthetic negative: blocking clients are still production reqwest egress.
mkdir -p "$work/negative_blocking/crates/chio-fake-blocking/src"
cat > "$work/negative_blocking/crates/chio-fake-blocking/src/lib.rs" <<'EOF'
pub fn dispatch() {
    let client = reqwest::blocking::Client::builder().build().unwrap();
    let _ = client.get("https://example.com").send();
}
EOF

# Synthetic negative: imported Client::builder() must be detected.
mkdir -p "$work/negative_imported/crates/chio-fake-imported/src"
cat > "$work/negative_imported/crates/chio-fake-imported/src/lib.rs" <<'EOF'
use reqwest::blocking::Client;

pub fn dispatch() {
    let client = Client::builder().build().unwrap();
    let _ = client.get("https://example.com").send();
}
EOF

# Synthetic negative: braced imports must not hide Client::new().
mkdir -p "$work/negative_imported_braced_new/crates/chio-fake-imported-braced-new/src"
cat > "$work/negative_imported_braced_new/crates/chio-fake-imported-braced-new/src/lib.rs" <<'EOF'
use reqwest::{Client, StatusCode};

pub async fn dispatch() {
    let client = Client::new();
    let response = client.get("https://example.com").send().await;
    let _ = (response, StatusCode::OK);
}
EOF

# Synthetic negative: braced blocking imports must not hide Client::default().
mkdir -p "$work/negative_blocking_braced_default/crates/chio-fake-blocking-braced-default/src"
cat > "$work/negative_blocking_braced_default/crates/chio-fake-blocking-braced-default/src/lib.rs" <<'EOF'
use reqwest::blocking::{Client, Response};

pub fn dispatch() {
    let client = Client::default();
    let response: Result<Response, reqwest::Error> = client.get("https://example.com").send();
    let _ = response;
}
EOF

# Synthetic negative: aliased reqwest import (`use reqwest as rq;`) used
# to construct a Client. The lint must match through the alias.
mkdir -p "$work/negative_aliased/crates/chio-fake-aliased/src"
cat > "$work/negative_aliased/crates/chio-fake-aliased/src/lib.rs" <<'EOF'
use reqwest as rq;

pub async fn dispatch() {
    let client = rq::Client::builder().build().unwrap();
    let _ = client.post("https://example.com").send().await;
}
EOF

# Synthetic negative: mentions HttpEgressContract but still dispatches through
# bare reqwest. This guards against comment/import-only false positives.
mkdir -p "$work/negative_mention/crates/chio-fake-mention/src"
cat > "$work/negative_mention/crates/chio-fake-mention/src/lib.rs" <<'EOF'
use chio_egress_contract::HttpEgressContract;

pub async fn dispatch(client: &reqwest::Client, _contract: &HttpEgressContract) {
    let _ = client.get("https://example.com").send().await;
}
EOF

# Synthetic negative: caller-supplied Client::execute() is still raw reqwest
# egress and must not hide behind the absence of `.send()`.
mkdir -p "$work/negative_execute/crates/chio-fake-execute/src"
cat > "$work/negative_execute/crates/chio-fake-execute/src/lib.rs" <<'EOF'
pub async fn dispatch(client: &reqwest::Client, request: reqwest::Request) {
    let _ = client.execute(request).await;
}
EOF

# Synthetic negative: top-level reqwest::get() has no explicit Client
# constructor, but still opens outbound HTTP.
mkdir -p "$work/negative_top_level_get/crates/chio-fake-top-level-get/src"
cat > "$work/negative_top_level_get/crates/chio-fake-top-level-get/src/lib.rs" <<'EOF'
pub async fn dispatch() {
    let _ = reqwest::get("https://example.com").await;
}
EOF

# Synthetic negative: production directories whose names end in "tests" (for
# example "contests") must not be skipped as if they were test sources.
mkdir -p "$work/negative_contests/crates/chio-fake-contests/src/contests"
cat > "$work/negative_contests/crates/chio-fake-contests/src/contests/helper.rs" <<'EOF'
pub async fn dispatch() {
    let _ = reqwest::get("https://example.com").await;
}
EOF

# Synthetic negative: blocking top-level reqwest::blocking::get() is also
# direct egress.
mkdir -p "$work/negative_blocking_top_level_get/crates/chio-fake-blocking-top-level-get/src"
cat > "$work/negative_blocking_top_level_get/crates/chio-fake-blocking-top-level-get/src/lib.rs" <<'EOF'
pub fn dispatch() {
    let _ = reqwest::blocking::get("https://example.com");
}
EOF

# Synthetic negative: dispatches through send_with_contract but accepts a
# caller-supplied client, so the lint cannot prove automatic redirects were
# disabled through client_builder_with_contract.
mkdir -p "$work/negative_send_without_builder/crates/chio-fake-send/src"
cat > "$work/negative_send_without_builder/crates/chio-fake-send/src/lib.rs" <<'EOF'
use chio_egress_contract::{send_with_contract, HttpEgressContract};

pub async fn dispatch(client: &reqwest::Client, contract: &HttpEgressContract) {
    let req = client.get("https://example.com").build().unwrap();
    let _ = send_with_contract(contract, client, req).await;
}
EOF

# Synthetic negative: a mixed file has one contract-backed dispatch and one
# raw reqwest dispatch. The file-level send_with_contract reference must not
# hide the unsafe call path.
mkdir -p "$work/negative_mixed/crates/chio-fake-mixed/src"
cat > "$work/negative_mixed/crates/chio-fake-mixed/src/lib.rs" <<'EOF'
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

pub async fn safe_dispatch(contract: &HttpEgressContract) {
    let client = client_builder_with_contract(contract).build().unwrap();
    let req = client.get("https://example.com").build().unwrap();
    let _ = send_with_contract(contract, &client, req).await;
}

pub async fn unsafe_dispatch(client: &reqwest::Client) {
    let _ = client.post("https://example.com").send().await;
}
EOF

# Synthetic positive: ClientBuilder with the contract helper.
mkdir -p "$work/positive_builder/crates/chio-fake-pos-builder/src"
cat > "$work/positive_builder/crates/chio-fake-pos-builder/src/lib.rs" <<'EOF'
use chio_egress_contract::{client_builder_with_contract, HttpEgressContract};

pub fn make_client(contract: &HttpEgressContract) -> reqwest::Client {
    client_builder_with_contract(contract).build().unwrap()
}
EOF

# Synthetic positive: explicitly classified non-substrate diagnostic caller.
mkdir -p "$work/positive_classified/crates/chio-fake-classified/src"
cat > "$work/positive_classified/crates/chio-fake-classified/src/lib.rs" <<'EOF'
use reqwest::blocking::Client;

pub fn dispatch() {
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: diagnostic self-test caller,
    // outside substrate tool egress.
    let client = Client::builder().build().unwrap();
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: diagnostic self-test caller,
    // outside substrate tool egress.
    let _ = client.get("https://example.com").send();
}
EOF

# Run the lint with a per-case repo-root override via env var.
positive_output=$(CHIO_EGRESS_LINT_ROOT="$work/positive" bash "$LINT" 2>&1) && positive_status=0 || positive_status=$?
negative_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative" bash "$LINT" 2>&1) && negative_status=0 || negative_status=$?
negative_builder_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_builder" bash "$LINT" 2>&1) && negative_builder_status=0 || negative_builder_status=$?
negative_blocking_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_blocking" bash "$LINT" 2>&1) && negative_blocking_status=0 || negative_blocking_status=$?
negative_imported_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_imported" bash "$LINT" 2>&1) && negative_imported_status=0 || negative_imported_status=$?
negative_imported_braced_new_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_imported_braced_new" bash "$LINT" 2>&1) && negative_imported_braced_new_status=0 || negative_imported_braced_new_status=$?
negative_blocking_braced_default_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_blocking_braced_default" bash "$LINT" 2>&1) && negative_blocking_braced_default_status=0 || negative_blocking_braced_default_status=$?
negative_aliased_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_aliased" bash "$LINT" 2>&1) && negative_aliased_status=0 || negative_aliased_status=$?
negative_mention_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_mention" bash "$LINT" 2>&1) && negative_mention_status=0 || negative_mention_status=$?
negative_execute_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_execute" bash "$LINT" 2>&1) && negative_execute_status=0 || negative_execute_status=$?
negative_top_level_get_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_top_level_get" bash "$LINT" 2>&1) && negative_top_level_get_status=0 || negative_top_level_get_status=$?
negative_contests_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_contests" bash "$LINT" 2>&1) && negative_contests_status=0 || negative_contests_status=$?
negative_blocking_top_level_get_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_blocking_top_level_get" bash "$LINT" 2>&1) && negative_blocking_top_level_get_status=0 || negative_blocking_top_level_get_status=$?
negative_send_without_builder_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_send_without_builder" bash "$LINT" 2>&1) && negative_send_without_builder_status=0 || negative_send_without_builder_status=$?
negative_mixed_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_mixed" bash "$LINT" 2>&1) && negative_mixed_status=0 || negative_mixed_status=$?
positive_builder_output=$(CHIO_EGRESS_LINT_ROOT="$work/positive_builder" bash "$LINT" 2>&1) && positive_builder_status=0 || positive_builder_status=$?
positive_classified_output=$(CHIO_EGRESS_LINT_ROOT="$work/positive_classified" bash "$LINT" 2>&1) && positive_classified_status=0 || positive_classified_status=$?

echo "positive case: status=$positive_status output=$positive_output"
echo "negative case: status=$negative_status output=$negative_output"
echo "negative builder case: status=$negative_builder_status output=$negative_builder_output"
echo "negative blocking case: status=$negative_blocking_status output=$negative_blocking_output"
echo "negative imported case: status=$negative_imported_status output=$negative_imported_output"
echo "negative imported braced Client::new case: status=$negative_imported_braced_new_status output=$negative_imported_braced_new_output"
echo "negative blocking braced Client::default case: status=$negative_blocking_braced_default_status output=$negative_blocking_braced_default_output"
echo "negative aliased case: status=$negative_aliased_status output=$negative_aliased_output"
echo "negative mention case: status=$negative_mention_status output=$negative_mention_output"
echo "negative execute case: status=$negative_execute_status output=$negative_execute_output"
echo "negative top-level reqwest::get case: status=$negative_top_level_get_status output=$negative_top_level_get_output"
echo "negative contests path case: status=$negative_contests_status output=$negative_contests_output"
echo "negative blocking top-level reqwest::blocking::get case: status=$negative_blocking_top_level_get_status output=$negative_blocking_top_level_get_output"
echo "negative send-without-builder case: status=$negative_send_without_builder_status output=$negative_send_without_builder_output"
echo "negative mixed case: status=$negative_mixed_status output=$negative_mixed_output"
echo "positive builder case: status=$positive_builder_status output=$positive_builder_output"
echo "positive classified case: status=$positive_classified_status output=$positive_classified_output"

if [[ $positive_status -ne 0 ]]; then
    echo "FAIL: lint should accept the positive synthetic crate" >&2
    exit 1
fi

if [[ $negative_status -eq 0 ]]; then
    echo "FAIL: lint should reject the negative synthetic crate (bare reqwest::Client without contract)" >&2
    exit 1
fi

if [[ $negative_builder_status -eq 0 ]]; then
    echo "FAIL: lint should reject the ClientBuilder synthetic crate without contract" >&2
    exit 1
fi

if [[ $negative_blocking_status -eq 0 ]]; then
    echo "FAIL: lint should reject blocking reqwest::Client without contract" >&2
    exit 1
fi

if [[ $negative_imported_status -eq 0 ]]; then
    echo "FAIL: lint should reject imported Client::builder without contract" >&2
    exit 1
fi

if [[ $negative_imported_braced_new_status -eq 0 ]]; then
    echo "FAIL: lint should reject braced imported Client::new without contract" >&2
    exit 1
fi

if [[ $negative_blocking_braced_default_status -eq 0 ]]; then
    echo "FAIL: lint should reject braced blocking imported Client::default without contract" >&2
    exit 1
fi

if [[ $negative_aliased_status -eq 0 ]]; then
    echo "FAIL: lint should reject the aliased reqwest crate without contract" >&2
    exit 1
fi

if [[ $negative_mention_status -eq 0 ]]; then
    echo "FAIL: lint should reject mention-only HttpEgressContract coverage" >&2
    exit 1
fi

if [[ $negative_execute_status -eq 0 ]]; then
    echo "FAIL: lint should reject Client::execute without contract" >&2
    exit 1
fi

if [[ $negative_top_level_get_status -eq 0 ]]; then
    echo "FAIL: lint should reject top-level reqwest::get without contract" >&2
    exit 1
fi

if [[ $negative_contests_status -eq 0 ]]; then
    echo "FAIL: lint should reject production contests/ reqwest egress" >&2
    exit 1
fi

if [[ $negative_blocking_top_level_get_status -eq 0 ]]; then
    echo "FAIL: lint should reject top-level reqwest::blocking::get without contract" >&2
    exit 1
fi

if [[ $negative_send_without_builder_status -eq 0 ]]; then
    echo "FAIL: lint should reject send_with_contract without client_builder_with_contract" >&2
    exit 1
fi

if [[ $negative_mixed_status -eq 0 ]]; then
    echo "FAIL: lint should reject mixed contract-backed and bare reqwest dispatch" >&2
    exit 1
fi

if [[ $positive_builder_status -ne 0 ]]; then
    echo "FAIL: lint should accept the positive ClientBuilder + contract crate" >&2
    exit 1
fi

if [[ $positive_classified_status -ne 0 ]]; then
    echo "FAIL: lint should accept explicitly classified direct reqwest caller" >&2
    exit 1
fi

echo "OK: HttpEgressContract lint correctly accepts wired or classified callers and rejects bare reqwest dispatch (including ClientBuilder, Client::new/default, blocking, imported, alias, execute, top-level get, mention-only, send-without-builder, and mixed-file forms)."
