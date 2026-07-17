# Direction C: Governed x402 Outbound Rail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Productize the governed outbound payment rail that already exists at the kernel into a deterministic, custody-neutral v1 (no-broadcast Sim adapter, a fail-closed MustPrepay gate placed where it actually fires, a CLI/config surface, and a no-key smoke), and in parallel land the ADR-0015 follow-up B anti-self-dealing roster + decision-rule constraints anchored so they are not per-adjudication fabricable.

**Architecture:** Rail A (the kernel HTTP x402/ACP `PaymentAdapter` at `crates/kernel/chio-kernel/src/payment.rs`, already wired into the guard pipeline via `authorize_payment_if_needed`) is the authoritative governed-outbound-initiation rail. A deterministic `SimPaymentAdapter` gives a no-key acceptance surface. The fail-closed "MustPrepay requires an adapter" gate is moved into the governed-intent validation stage (`governed_validation.rs::validate_metered_billing_context`) so it fires for every MustPrepay intent regardless of budget charge, closing the fail-open that the naive placement leaves. Anti-self-dealing binds a signed roster anchor id/hash into the adjudication artifact and enforces the roster at every value-path constructor. All EVM/EIP-3009 digest logic (Rail B, deferrable) stays at the CLI/control-plane layer and prepare-only (digest, never broadcast); the kernel payment adapter stays rail-agnostic.

**Tech Stack:** Rust (workspace crates `chio-market`, `chio-control-plane`, `chio-kernel`, `chio-core-types`/`chio-core`, `chio-settle`, `chio-cli`), `serde`/`serde_json`, `chio-test-support` extension traits for tests, `ureq` (existing HTTP adapters), bash acceptance smoke under `examples/`.

## Global Constraints

Every task's requirements implicitly include this section.

- No em-dashes (U+2014) anywhere in code, comments, docs, or commit messages. Use hyphens (`-`) or parentheses.
- Clippy `unwrap_used = "deny"` and `expect_used = "deny"` are enforced workspace-wide, including tests. In `chio-kernel` tests, plain `.unwrap()`/`.expect()` are permitted only because `crates/kernel/chio-kernel/src/lib.rs:22` carries `#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]`. In `chio-market` tests, use the in-crate helpers `require_ok(result, "ctx")`, `require_err(result, "ctx")`, `require_some(option, "ctx")` (defined in `crates/economy/chio-market/src/tests.rs:4-24`). In new crates/files without a test allow, use `use chio_test_support::prelude::*;` and `.test_unwrap()` / `.test_expect("ctx")` / `.test_unwrap_err()` / `.test_expect_err("ctx")` (defined in `crates/tooling/chio-test-support/src/lib.rs`). Never introduce a bare `.unwrap()`/`.expect()` in non-test code.
- Fail-closed: errors deny access; invalid policies reject at load time; absence of a required control is a denial, not a skip.
- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`). Every commit message ends with a trailing blank line then exactly:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Do NOT run `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace`, or `cargo fmt --all`. Verify scoped to the crate(s) you touched only (`-p <crate>`).
- Before every `cargo` invocation, run `rm -rf target/debug/incremental` and export `CARGO_INCREMENTAL=0`. Canonical verify pattern for a crate:
  ```bash
  rm -rf target/debug/incremental
  CARGO_INCREMENTAL=0 cargo test -p <crate> <filter> -- --exact
  CARGO_INCREMENTAL=0 cargo clippy -p <crate> --all-targets -- -D warnings
  cargo fmt -p <crate> -- --check
  ```
- Every new acceptance/smoke gate MUST assert a NONZERO executed-test count (no false green): parse the test summary and fail if `0 passed`/`0 filtered`/`no tests to run`.
- Custody-neutral: sim/testnet-first, digest-only, no broadcast; no operator-managed-custody or fund-holding mode may be exposed by any new CLI surface. Keep EVM/digest logic at the CLI/control-plane layer, never in the kernel payment adapter.

**Dependency note (do not re-serialize):** C-M1..M4 (Tasks 1-10) target the CLI/control-plane host, which already routes through the kernel guard pipeline (`authorize_payment_if_needed` runs there), so they are NOT blocked by Direction A. Only the api-protect-sidecar-hosted rail is gated by A and is out of scope here. Direction A supplies the `execution_nonce`; Task 11 reserves an `Option::None` slot for it and does not depend on A landing. Framing correction to keep in mind while wiring the roster: `chio-control-plane` reaches `chio-market` types via the `chio-core` re-export (it does not directly depend on `chio-market`); pass roster values in as concrete `&[String]` to avoid any crate cycle.

---

## File Structure

**Modify (M1 anti-self-dealing):**
- `crates/economy/chio-market/src/claim.rs` - add optional `decision_rule_ref` + `roster_anchor_ref` fields to `LiabilityClaimAdjudicationArtifact`; shape-only checks in `validate()`; new `validate_against_roster(...)` policy gate.
- `crates/economy/chio-market/src/tests.rs` - unit tests for the fields, serialization stability, and `validate_against_roster`; update the existing `LiabilityClaimAdjudicationArtifact` fixture literal at L795.
- `crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs` - thread a `RosterPolicy` into the three value-path constructors (L1213 adjudication, L1266 payout, L1335 settlement instruction), fold the two new fields into `adjudication_id`, enforce `validate_against_roster` at each site.
- `crates/platform/chio-control-plane/src/trust_control/capital_and_liability/service_types/requests.rs` - add optional `decision_rule_ref` to the adjudication request type.
- `docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md` - Status flip + follow-up-B acceptance subsection (M0).
- `scripts/check-liability-roster-enforcement.sh` (Create) - CI grep proving all liability value-path artifacts are constructed only alongside `validate_against_roster`; asserts nonzero matches.

**Modify (M2 governed MustPrepay gate + sim adapter):**
- `crates/kernel/chio-kernel/src/kernel/governed_validation.rs` - add `payment_adapter_configured: bool` param to `validate_metered_billing_context` (L276) and the fail-closed MustPrepay gate; update the call site at L1034; add an in-file `#[cfg(test)] mod`.
- `crates/kernel/chio-kernel/src/payment.rs` - declare `mod sim;` and `pub use sim::SimPaymentAdapter;`.
- `crates/kernel/chio-kernel/src/payment/sim.rs` (Create) - deterministic no-broadcast `SimPaymentAdapter` implementing `PaymentAdapter`.
- `crates/kernel/chio-kernel/src/kernel/tests.rs` - end-to-end sim kernel tests (execute + receipt fold, zero-cost release, abort unwind).

**Modify (M3 CLI/config):**
- `crates/products/chio-cli/src/cli/mcp/wrap.rs` - resolve a `PaymentAdapterConfig` and call `set_payment_adapter` on the constructed `ChioKernel` (L303 area).
- `crates/products/chio-cli/src/cli/mcp/payment_config.rs` (Create) - `PaymentAdapterConfig` enum + parse + load-time config-consistency reject + `build_adapter()`.
- `crates/products/chio-cli/Cargo.toml` - ensure `chio-kernel` adapter types are in scope (already depends on `chio-kernel` at L50).

**Create (M4 smoke):**
- `examples/governed-x402-sim/smoke.sh` - no-key deterministic governed-x402 smoke.
- `examples/governed-x402-sim/assert_receipt.py` - receipt-bundle assertions (positive fold + negative deny) with nonzero-test guard.

**Modify (M5 deferrable Rail B):**
- `crates/economy/chio-settle/src/payments.rs` - `RailBinding` + `approval_binding_from_governed(...)` seam + `OffchainSettlementReceiptArtifact` + `validate_offchain_settlement_receipt(...)` (reserved `execution_nonce: Option<String>` slot).
- `crates/platform/chio-control-plane` or `crates/products/chio-cli` - seller->RailBinding resolver from operator config (CLI/control-plane layer only).
- `scripts/check-no-eip3009-broadcast.sh` (Create) - CI grep proving no in-tree `transferWithAuthorization`/`eth_sendTransaction` broadcast in the off-chain lanes; asserts nonzero scanned files.

---

## Milestone M0: Prerequisites (ADR-0015 governance + scoped baseline)

### Task 1: Move ADR-0015 to Accepted-for-follow-up-B and record a scoped baseline

**Files:**
- Modify: `docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md:3` (Status line) and the "## Required follow-up" section.

**Interfaces:**
- Consumes: nothing.
- Produces: a normative anchor that M1's roster + decision-rule constraints reference. No code interface.

- [ ] **Step 1: Record the scoped green baseline for the crates in scope**

Run each and confirm it succeeds (this is the recorded baseline; do NOT use `--workspace`):
```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-market -- --list >/dev/null && echo "chio-market baseline OK"
CARGO_INCREMENTAL=0 cargo test -p chio-kernel -- --list >/dev/null && echo "chio-kernel baseline OK"
CARGO_INCREMENTAL=0 cargo test -p chio-settle -- --list >/dev/null && echo "chio-settle baseline OK"
```
Expected: three `... baseline OK` lines. If any crate is red, stop and fix/note before proceeding (these crates are widely re-exported).

- [ ] **Step 2: Flip the ADR status**

In `docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md`, change line 3 from:
```
- Status: Proposed
```
to:
```
- Status: Accepted for follow-up B (Rust roster + decision-rule constraints); follow-up A (Solidity impairBondDetailed allowlist) and follow-up C remain deferred
```

- [ ] **Step 3: Add the normative subsection under "## Required follow-up"**

Immediately after the follow-up B bullet (the paragraph ending "No new discretionary override lane is introduced."), add:
```markdown
### Follow-up B enforcement (accepted)

Follow-up B is accepted for the Rust value path. `LiabilityClaimAdjudicationArtifact`
gains two optional, signature-safe fields: `decision_rule_ref` (the predeclared
decision rule or circuit-breaker condition id applied) and `roster_anchor_ref`
(the id/hash of the signed roster artifact the adjudicator was checked against).
A new `validate_against_roster` policy gate enforces roster membership, an allowed
decision-rule set, and that the recorded `roster_anchor_ref` equals the anchor of
the roster actually applied. Every value-path constructor (adjudication, payout
instruction, settlement instruction) is a fail-closed choke point that MUST call
this gate; a CI check enforces that no liability value-path artifact is constructed
without it. Follow-up A stays deferred: `ChioBondVault` is immutable with no admin
or upgrade lane (D1), so the on-chain allowlist requires a new deployment.
```

- [ ] **Step 4: Verify the ADR still reads cleanly and carries no em-dash**

Run:
```bash
grep -nP "\x{2014}" docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md && echo "EM-DASH FOUND" || echo "no em-dash OK"
grep -n "Accepted for follow-up B" docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md
```
Expected: `no em-dash OK` and one match for the accepted status line.

- [ ] **Step 5: Commit**

```bash
git add docs/adr/ADR-0015-predeclared-escrow-circuit-breakers.md
git commit -m "$(cat <<'EOF'
docs(adr-0015): accept follow-up B and record roster enforcement posture

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Milestone M1: Anti-self-dealing (predeclared, anchored adjudicator roster + recorded decision rule)

### Task 2: Add signature-safe `decision_rule_ref` + `roster_anchor_ref` fields with shape-only validation

**Files:**
- Modify: `crates/economy/chio-market/src/claim.rs:300-372` (`LiabilityClaimAdjudicationArtifact` struct + `validate()`).
- Modify: `crates/economy/chio-market/src/tests.rs:795-805` (existing fixture literal) and add new tests.

**Interfaces:**
- Consumes: existing `LiabilityClaimAdjudicationArtifact` (claim.rs:300).
- Produces: two new fields
  ```rust
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub decision_rule_ref: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub roster_anchor_ref: Option<String>,
  ```
  Both omitted from canonical JSON when `None` (serialization stable for pre-change fixtures). `validate()` gains shape-only checks (trim non-empty when `Some`).

- [ ] **Step 1: Write the failing serialization-stability test**

Append to `crates/economy/chio-market/src/tests.rs`:
```rust
#[test]
fn adjudication_new_optional_fields_are_omitted_when_none() {
    let fixtures = sample_market_fixtures();
    let adjudication = fixtures.claim_adjudication.body.clone();
    let json = require_ok(
        serde_json::to_string(&adjudication),
        "serialize adjudication",
    );
    assert!(
        !json.contains("decisionRuleRef") && !json.contains("decision_rule_ref"),
        "decision_rule_ref must be omitted when None: {json}"
    );
    assert!(
        !json.contains("rosterAnchorRef") && !json.contains("roster_anchor_ref"),
        "roster_anchor_ref must be omitted when None: {json}"
    );
}

#[test]
fn adjudication_shape_validate_rejects_blank_decision_rule() {
    let fixtures = sample_market_fixtures();
    let mut adjudication = fixtures.claim_adjudication.body.clone();
    adjudication.decision_rule_ref = Some("   ".to_string());
    let error = require_err(
        adjudication.validate(),
        "blank decision_rule_ref must fail shape validation",
    );
    assert!(error.contains("decision_rule_ref"));
}
```

- [ ] **Step 2: Run it to confirm it fails to compile (fields do not exist yet)**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-market adjudication_new_optional_fields_are_omitted_when_none -- --exact
```
Expected: compile error `no field decision_rule_ref on type LiabilityClaimAdjudicationArtifact`.

- [ ] **Step 3: Add the two fields to the struct**

In `crates/economy/chio-market/src/claim.rs`, inside `LiabilityClaimAdjudicationArtifact` (after the `note` field at L310, before `evidence_refs`):
```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Predeclared decision rule or circuit-breaker condition id the
    /// adjudication applied (ADR-0015 follow-up B). Optional and omitted when
    /// absent so existing signed fixtures keep byte-stable canonical JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_rule_ref: Option<String>,
    /// Id or hash of the signed roster artifact the adjudicator was checked
    /// against (ADR-0015 follow-up B anchoring). Records which ex-ante roster
    /// was applied so the check is auditable and not per-adjudication fabricable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_anchor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<LiabilityClaimEvidenceReference>,
```

- [ ] **Step 4: Add shape-only checks in `validate()`**

In `LiabilityClaimAdjudicationArtifact::validate()` (claim.rs), immediately after the non-empty adjudicator check (the block ending at L321), insert:
```rust
        if self
            .decision_rule_ref
            .as_ref()
            .is_some_and(|rule| rule.trim().is_empty())
        {
            return Err(
                "claim adjudication decision_rule_ref must not be blank when present".to_string(),
            );
        }
        if self
            .roster_anchor_ref
            .as_ref()
            .is_some_and(|anchor| anchor.trim().is_empty())
        {
            return Err(
                "claim adjudication roster_anchor_ref must not be blank when present".to_string(),
            );
        }
```

- [ ] **Step 5: Update the existing fixture literal so it compiles**

In `crates/economy/chio-market/src/tests.rs:795-805`, add the two fields to the `LiabilityClaimAdjudicationArtifact { ... }` literal (after `note:`):
```rust
        note: Some("partial settlement ordered".to_string()),
        decision_rule_ref: None,
        roster_anchor_ref: None,
        evidence_refs: Vec::new(),
```

- [ ] **Step 6: Run the tests to confirm they pass**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-market adjudication_new_optional_fields_are_omitted_when_none adjudication_shape_validate_rejects_blank_decision_rule -- --exact
```
Expected: `test result: ok. 2 passed`. If it reports `0 passed`, the filter is wrong; fix before continuing.

- [ ] **Step 7: Verify clippy + fmt scoped**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-market --all-targets -- -D warnings
cargo fmt -p chio-market -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 8: Commit**

```bash
git add crates/economy/chio-market/src/claim.rs crates/economy/chio-market/src/tests.rs
git commit -m "$(cat <<'EOF'
feat(chio-market): add optional decision_rule_ref and roster_anchor_ref to adjudication

Signature-safe optional fields (skip_serializing_if) keep canonical JSON byte-stable
when absent so existing signed adjudication fixtures still verify. Shape-only checks
reject blank values when present.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 3: Add `validate_against_roster` policy gate (roster + decision-rule + anchor)

**Files:**
- Modify: `crates/economy/chio-market/src/claim.rs` (new method on `LiabilityClaimAdjudicationArtifact`).
- Modify: `crates/economy/chio-market/src/tests.rs` (unit tests).

**Interfaces:**
- Consumes: the fields from Task 2.
- Produces:
  ```rust
  impl LiabilityClaimAdjudicationArtifact {
      pub fn validate_against_roster(
          &self,
          roster: &[String],
          allowed_decision_rules: &[String],
          roster_anchor: &str,
      ) -> Result<(), String>;
  }
  ```
  `validate()`'s signature is NOT changed (settlement.rs value-movement callers at L103/L211/L303/L488 keep compiling against the shape-only `validate()`).

- [ ] **Step 1: Write the failing tests**

Append to `crates/economy/chio-market/src/tests.rs`:
```rust
#[test]
fn validate_against_roster_accepts_on_roster_with_rule_and_anchor() {
    let fixtures = sample_market_fixtures();
    let mut adjudication = fixtures.claim_adjudication.body.clone();
    adjudication.decision_rule_ref = Some("rule.partial-settlement.v1".to_string());
    adjudication.roster_anchor_ref = Some("roster-anchor-abc".to_string());
    require_ok(
        adjudication.validate_against_roster(
            &["arbiter.chio".to_string()],
            &["rule.partial-settlement.v1".to_string()],
            "roster-anchor-abc",
        ),
        "on-roster adjudicator with valid rule and matching anchor should pass",
    );
}

#[test]
fn validate_against_roster_rejects_off_roster_adjudicator() {
    let fixtures = sample_market_fixtures();
    let mut adjudication = fixtures.claim_adjudication.body.clone();
    adjudication.decision_rule_ref = Some("rule.partial-settlement.v1".to_string());
    adjudication.roster_anchor_ref = Some("roster-anchor-abc".to_string());
    let error = require_err(
        adjudication.validate_against_roster(
            &["someone.else".to_string()],
            &["rule.partial-settlement.v1".to_string()],
            "roster-anchor-abc",
        ),
        "off-roster adjudicator must be denied",
    );
    assert!(error.contains("not on the predeclared roster"));
}

#[test]
fn validate_against_roster_rejects_missing_or_unknown_rule() {
    let fixtures = sample_market_fixtures();
    let mut adjudication = fixtures.claim_adjudication.body.clone();
    adjudication.roster_anchor_ref = Some("roster-anchor-abc".to_string());
    // missing rule
    let missing = require_err(
        adjudication.validate_against_roster(
            &["arbiter.chio".to_string()],
            &["rule.partial-settlement.v1".to_string()],
            "roster-anchor-abc",
        ),
        "missing decision_rule_ref must be denied",
    );
    assert!(missing.contains("decision_rule_ref"));
    // present but unknown rule
    adjudication.decision_rule_ref = Some("rule.unknown".to_string());
    let unknown = require_err(
        adjudication.validate_against_roster(
            &["arbiter.chio".to_string()],
            &["rule.partial-settlement.v1".to_string()],
            "roster-anchor-abc",
        ),
        "unknown decision_rule_ref must be denied",
    );
    assert!(unknown.contains("not an allowed decision rule"));
}

#[test]
fn validate_against_roster_rejects_anchor_mismatch() {
    let fixtures = sample_market_fixtures();
    let mut adjudication = fixtures.claim_adjudication.body.clone();
    adjudication.decision_rule_ref = Some("rule.partial-settlement.v1".to_string());
    adjudication.roster_anchor_ref = Some("roster-anchor-STALE".to_string());
    let error = require_err(
        adjudication.validate_against_roster(
            &["arbiter.chio".to_string()],
            &["rule.partial-settlement.v1".to_string()],
            "roster-anchor-abc",
        ),
        "recorded anchor not matching the applied roster must be denied",
    );
    assert!(error.contains("roster_anchor_ref"));
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-market validate_against_roster_accepts_on_roster_with_rule_and_anchor -- --exact
```
Expected: compile error `no method named validate_against_roster`.

- [ ] **Step 3: Implement `validate_against_roster`**

In `crates/economy/chio-market/src/claim.rs`, add to `impl LiabilityClaimAdjudicationArtifact` (after `validate()`):
```rust
    /// Fail-closed policy gate for ADR-0015 follow-up B.
    ///
    /// Requires the adjudicator to be an exact (trimmed) member of the
    /// operator-supplied predeclared `roster`, requires `decision_rule_ref` to
    /// be present and a member of `allowed_decision_rules`, and requires the
    /// recorded `roster_anchor_ref` to equal `roster_anchor` (the id/hash of the
    /// signed roster artifact the `roster` was drawn from). Callers pass concrete
    /// values so `chio-market` needs no dependency on the roster's source crate.
    pub fn validate_against_roster(
        &self,
        roster: &[String],
        allowed_decision_rules: &[String],
        roster_anchor: &str,
    ) -> Result<(), String> {
        let adjudicator = self.adjudicator.trim();
        if !roster.iter().any(|entry| entry.trim() == adjudicator) {
            return Err(format!(
                "adjudicator \"{adjudicator}\" is not on the predeclared roster"
            ));
        }
        let rule = self
            .decision_rule_ref
            .as_ref()
            .map(|rule| rule.trim())
            .filter(|rule| !rule.is_empty())
            .ok_or_else(|| {
                "adjudication is missing a decision_rule_ref (ADR-0015 follow-up B)".to_string()
            })?;
        if !allowed_decision_rules
            .iter()
            .any(|allowed| allowed.trim() == rule)
        {
            return Err(format!(
                "decision_rule_ref \"{rule}\" is not an allowed decision rule"
            ));
        }
        let recorded_anchor = self
            .roster_anchor_ref
            .as_ref()
            .map(|anchor| anchor.trim())
            .filter(|anchor| !anchor.is_empty())
            .ok_or_else(|| {
                "adjudication is missing a roster_anchor_ref (ADR-0015 follow-up B)".to_string()
            })?;
        if recorded_anchor != roster_anchor.trim() {
            return Err(format!(
                "roster_anchor_ref \"{recorded_anchor}\" does not match the applied roster anchor \"{}\"",
                roster_anchor.trim()
            ));
        }
        Ok(())
    }
```

- [ ] **Step 4: Run the tests to confirm they pass**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-market validate_against_roster -- --exact 2>&1 | tail -20
```
Expected: `test result: ok. 4 passed`. Confirm the count is nonzero.

- [ ] **Step 5: Verify clippy + fmt scoped**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-market --all-targets -- -D warnings
cargo fmt -p chio-market -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 6: Commit**

```bash
git add crates/economy/chio-market/src/claim.rs crates/economy/chio-market/src/tests.rs
git commit -m "$(cat <<'EOF'
feat(chio-market): add validate_against_roster anti-self-dealing policy gate

Enforces predeclared roster membership, an allowed decision-rule set, and that the
recorded roster_anchor_ref matches the applied roster anchor. validate() is left
shape-only so existing value-movement callers keep compiling.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 4: Enforce the roster at every value-path constructor and fold anchors into `adjudication_id`

**Files:**
- Modify: `crates/platform/chio-control-plane/src/trust_control/capital_and_liability/service_types/requests.rs:~751` (add optional `decision_rule_ref` to the adjudication request).
- Modify: `crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs:1213` (adjudication constructor), `:1266` (payout constructor), `:1335` (settlement-instruction constructor).

**Interfaces:**
- Consumes: `LiabilityClaimAdjudicationArtifact::validate_against_roster` (Task 3).
- Produces: a `RosterPolicy { roster: Vec<String>, allowed_decision_rules: Vec<String>, roster_anchor: String }` threaded from operator config into the three constructors; `adjudication_id` derivation extended to fold `decision_rule_ref` and `roster_anchor_ref`.

- [ ] **Step 1: Add a `RosterPolicy` type and the request field**

In `crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs`, near the top of the module add:
```rust
/// Operator-supplied predeclared roster policy for liability adjudication.
///
/// `roster_anchor` is the id or hash of the signed roster artifact that
/// `roster` was drawn from (for example a `chio-trust-market-context`
/// `AdjudicationJurisdictionReceipt`). It is recorded on the adjudication so
/// the audit trail shows which ex-ante roster was applied and the check is not
/// per-adjudication fabricable.
#[derive(Debug, Clone)]
pub struct RosterPolicy {
    pub roster: Vec<String>,
    pub allowed_decision_rules: Vec<String>,
    pub roster_anchor: String,
}
```
In `service_types/requests.rs` add to the adjudication request struct (near L751 where `adjudicator`/`service_types` live):
```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_rule_ref: Option<String>,
```

- [ ] **Step 2: Write the failing choke-point test**

Add a control-plane handler test (in the existing test module for `liability.rs`, or a new `#[cfg(test)] mod roster_enforcement` at the end of `liability.rs`). Use `chio_test_support::prelude::*` (add `chio-test-support` to `chio-control-plane` `[dev-dependencies]` if absent):
```rust
#[test]
fn payout_and_settlement_constructors_reject_off_roster_adjudication() {
    // Build a pre-signed adjudication whose adjudicator is NOT on the roster.
    let policy = RosterPolicy {
        roster: vec!["arbiter.on-roster".to_string()],
        allowed_decision_rules: vec!["rule.partial-settlement.v1".to_string()],
        roster_anchor: "roster-anchor-abc".to_string(),
    };
    let off_roster = sample_signed_off_roster_adjudication(); // helper below
    // Feeding it to the payout-instruction constructor must deny.
    let payout_err = build_payout_instruction_with_policy(&off_roster, &policy).test_unwrap_err(
        "off-roster adjudication must be denied at payout construction",
    );
    assert!(payout_err.to_string().contains("not on the predeclared roster"));
    // Feeding it to the settlement-instruction constructor must also deny.
    let settle_err = build_settlement_instruction_with_policy(&off_roster, &policy)
        .test_unwrap_err("off-roster adjudication must be denied at settlement construction");
    assert!(settle_err.to_string().contains("not on the predeclared roster"));
}
```
(Provide `sample_signed_off_roster_adjudication`, `build_payout_instruction_with_policy`, and `build_settlement_instruction_with_policy` as thin test helpers wrapping the existing constructors with the new `RosterPolicy` parameter; model the fixture on `crates/economy/chio-market/src/tests.rs:795`.)

- [ ] **Step 3: Run to confirm failure**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-control-plane payout_and_settlement_constructors_reject_off_roster_adjudication -- --exact
```
Expected: compile error (constructors do not yet accept `RosterPolicy`) or assertion failure. Either is the expected red.

- [ ] **Step 4: Thread `RosterPolicy` and enforce at all three constructors**

At the adjudication constructor (`liability.rs:1213`): after `artifact.validate().map_err(CliError::cli_other_error)?;`, add:
```rust
    artifact
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
```
Set the new fields when constructing the artifact literal (before `evidence_refs`):
```rust
        note: request.note.clone(),
        decision_rule_ref: request.decision_rule_ref.clone(),
        roster_anchor_ref: Some(policy.roster_anchor.clone()),
        evidence_refs,
```
Extend the `adjudication_id` folded tuple (currently schema, issued_at, dispute_id, adjudicator, outcome, awarded_amount, note) to also include the two new fields:
```rust
            &canonical_json_bytes(&(
                LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
                issued_at,
                &request.dispute.body.dispute_id,
                &request.adjudicator,
                request.outcome,
                &request.awarded_amount,
                &request.note,
                &request.decision_rule_ref,
                &policy.roster_anchor,
            ))
```
At the payout-instruction constructor (`liability.rs:1266`), after its `artifact.validate()...?;`, add:
```rust
    request
        .adjudication
        .body
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
```
At the settlement-instruction constructor (`liability.rs:1335`), after its `artifact.validate()...?;`, re-check the nested adjudication (reach it via the payout receipt -> payout instruction -> adjudication path already present on the request), for example:
```rust
    request
        .payout_receipt
        .body
        .payout_instruction
        .body
        .adjudication
        .body
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
```
Add `policy: &RosterPolicy` as a parameter to each of the three constructor functions and update their call sites in the handler to pass the operator-config roster policy.

- [ ] **Step 5: Run the choke-point test to confirm it passes**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-control-plane payout_and_settlement_constructors_reject_off_roster_adjudication -- --exact 2>&1 | tail -20
```
Expected: `test result: ok. 1 passed`.

- [ ] **Step 6: Add and run a construction-time `adjudication_id` golden**

Because the folded tuple now includes the two new fields, the derived id changes for newly constructed artifacts even when `decision_rule_ref` is `None`. Add a test asserting the new derivation is stable (pin the produced id string for a fixed input), and note in the commit body that construction-time id goldens change while signature/serialization goldens (Task 2) stay stable. Run:
```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-control-plane adjudication_id -- --nocapture 2>&1 | tail -20
```
Expected: nonzero passing tests; record the pinned id.

- [ ] **Step 7: Verify clippy + fmt scoped**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-control-plane --all-targets -- -D warnings
cargo fmt -p chio-control-plane -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 8: Commit**

```bash
git add crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs crates/platform/chio-control-plane/src/trust_control/capital_and_liability/service_types/requests.rs crates/platform/chio-control-plane/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(chio-control-plane): enforce anchored adjudicator roster at every value-path constructor

Threads an operator RosterPolicy (roster, allowed decision rules, signed roster
anchor) into the adjudication, payout-instruction, and settlement-instruction
constructors and calls validate_against_roster at each fail-closed choke point.
Folds decision_rule_ref and roster_anchor into adjudication_id; the pre-signed
off-roster adjudication is denied at both payout and settlement construction.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 5: CI enforcement that liability value-path artifacts are only constructed alongside `validate_against_roster`

**Files:**
- Create: `scripts/check-liability-roster-enforcement.sh`.

**Interfaces:**
- Consumes: the enforced constructors (Task 4).
- Produces: a CI guard failing if any of the three liability value-path artifacts is constructed at a site that does not also call `validate_against_roster`, and failing on zero matches (no false green).

- [ ] **Step 1: Write the failing check script**

Create `scripts/check-liability-roster-enforcement.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="${ROOT}/crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs"

# The three liability value-path artifacts whose construction moves money.
ARTIFACTS=(
  "LiabilityClaimAdjudicationArtifact {"
  "LiabilityClaimPayoutInstructionArtifact {"
  "LiabilityClaimSettlementInstructionArtifact {"
)

# 1) Every construction of these artifacts anywhere under crates/ must live in
#    liability.rs (the known choke-point file). Any other site is a violation.
violations=0
found_total=0
while IFS= read -r hit; do
  found_total=$((found_total + 1))
  file="${hit%%:*}"
  if [[ "${file}" != "${LIB}" ]]; then
    echo "VIOLATION: liability value-path artifact constructed outside liability.rs: ${hit}"
    violations=$((violations + 1))
  fi
done < <(grep -rn --include='*.rs' -F \
  -e "LiabilityClaimAdjudicationArtifact {" \
  -e "LiabilityClaimPayoutInstructionArtifact {" \
  -e "LiabilityClaimSettlementInstructionArtifact {" \
  "${ROOT}/crates" | grep -v "/tests.rs:" | grep -v "src/tests" || true)

# 2) No false green: we must have actually found the known constructions.
if [[ "${found_total}" -eq 0 ]]; then
  echo "FALSE-GREEN GUARD: found 0 liability value-path constructions; grep is broken"
  exit 1
fi

# 3) liability.rs must call validate_against_roster at least three times
#    (one per value-path choke point).
roster_calls="$(grep -c "validate_against_roster" "${LIB}" || true)"
if [[ "${roster_calls}" -lt 3 ]]; then
  echo "VIOLATION: expected >=3 validate_against_roster calls in liability.rs, found ${roster_calls}"
  violations=$((violations + 1))
fi

if [[ "${violations}" -ne 0 ]]; then
  echo "check-liability-roster-enforcement: FAILED (${violations} violations)"
  exit 1
fi
echo "check-liability-roster-enforcement: OK (${found_total} constructions checked, ${roster_calls} roster calls)"
```

- [ ] **Step 2: Make it executable and run it**

```bash
chmod +x scripts/check-liability-roster-enforcement.sh
scripts/check-liability-roster-enforcement.sh
```
Expected: `check-liability-roster-enforcement: OK (N constructions checked, M roster calls)` with `N >= 3` and `M >= 3`. If it fails, a construction escaped the choke point or a roster call is missing; fix Task 4 rather than loosening the script.

- [ ] **Step 3: Sanity-check the false-green guard**

Temporarily point the grep at an empty subtree to confirm the guard trips:
```bash
bash -c 'set -e; found=0; if [[ "$found" -eq 0 ]]; then echo "guard trips on zero"; fi'
```
Expected: `guard trips on zero` (confirms the zero-match branch is reachable). Do not commit this scratch command.

- [ ] **Step 4: Commit**

```bash
git add scripts/check-liability-roster-enforcement.sh
git commit -m "$(cat <<'EOF'
test(chio-control-plane): CI guard that liability artifacts only build with roster enforcement

Fails if any liability value-path artifact is constructed outside the choke-point
file or without validate_against_roster, and fails on zero matches (no false green).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Milestone M2: Governed MustPrepay gate (BLOCKING fix) + Sim adapter

### Task 6: BLOCKING - move the fail-closed MustPrepay gate into the governed-intent validation stage

This is the primary adversarial-review fix. As originally drafted the gate sat inside `authorize_payment_if_needed` AFTER `let Some(charge) = charge_result else { return Ok(None) }` (validation.rs:1232-1237), so a governed MustPrepay intent with no budget charge bypassed it and executed UNPAID. The gate must fire in `governed_validation.rs::validate_metered_billing_context`, before any early-return, for EVERY MustPrepay intent, threading whether an adapter is configured.

**Files:**
- Modify: `crates/kernel/chio-kernel/src/kernel/governed_validation.rs:276-283` (add param + gate) and `:1034` (call site).

**Interfaces:**
- Consumes: `ChioKernel.payment_adapter` (`kernel_struct.rs:148`, `Option<Box<dyn PaymentAdapter>>`), `MeteredSettlementMode::MustPrepay` (`governance.rs:57`).
- Produces:
  ```rust
  fn validate_metered_billing_context(
      intent: &chio_core::capability::governance::GovernedTransactionIntent,
      charge_result: Option<&BudgetChargeResult>,
      payment_adapter_configured: bool,
      now: u64,
  ) -> Result<(), KernelError>;
  ```
  Fail-closed rule: `settlement_mode == MustPrepay && !payment_adapter_configured => Err(GovernedTransactionDenied)`, independent of `charge_result`.

- [ ] **Step 1: Write the failing tests (the currently-uncovered no-charge path is the point)**

Append a new module to the end of `crates/kernel/chio-kernel/src/kernel/governed_validation.rs`:
```rust
#[cfg(test)]
mod mustprepay_gate_tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote, MeteredSettlementMode,
    };
    use chio_core::capability::scope::MonetaryAmount;

    fn must_prepay_intent() -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: "intent-1".to_string(),
            server_id: "srv-1".to_string(),
            tool_name: "tool-1".to_string(),
            purpose: "test".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: Some(MeteredBillingContext {
                settlement_mode: MeteredSettlementMode::MustPrepay,
                quote: MeteredBillingQuote {
                    quote_id: "q-1".to_string(),
                    provider: "meter".to_string(),
                    billing_unit: "1k_tokens".to_string(),
                    quoted_units: 10,
                    quoted_cost: MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    },
                    issued_at: 1_000,
                    expires_at: None,
                },
                max_billed_units: None,
            }),
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
        }
    }

    #[test]
    fn mustprepay_without_adapter_and_no_charge_is_denied() {
        // The uncovered path: MustPrepay + charge_result None + no adapter.
        let intent = must_prepay_intent();
        let result =
            ChioKernel::validate_metered_billing_context(&intent, None, false, 1_500);
        let error = result.expect_err("MustPrepay with no adapter and no charge must be denied");
        assert!(matches!(error, KernelError::GovernedTransactionDenied(_)));
        assert!(error.to_string().contains("MustPrepay"));
    }

    #[test]
    fn mustprepay_with_adapter_passes_metered_validation() {
        let intent = must_prepay_intent();
        ChioKernel::validate_metered_billing_context(&intent, None, true, 1_500)
            .expect("MustPrepay with an adapter configured should pass metered validation");
    }

    #[test]
    fn non_mustprepay_without_adapter_is_allowed() {
        let mut intent = must_prepay_intent();
        if let Some(metered) = intent.metered_billing.as_mut() {
            metered.settlement_mode = MeteredSettlementMode::AllowThenSettle;
        }
        ChioKernel::validate_metered_billing_context(&intent, None, false, 1_500)
            .expect("non-prepay mode without an adapter must not be gated");
    }
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-kernel mustprepay_gate_tests -- --exact
```
Expected: compile error - `validate_metered_billing_context` takes 3 args, test passes 4. This confirms the signature must change.

- [ ] **Step 3: Add the parameter and the fail-closed gate**

In `crates/kernel/chio-kernel/src/kernel/governed_validation.rs`, change the `validate_metered_billing_context` signature (L276-280) to add `payment_adapter_configured: bool` before `now`:
```rust
    fn validate_metered_billing_context(
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
        charge_result: Option<&BudgetChargeResult>,
        payment_adapter_configured: bool,
        now: u64,
    ) -> Result<(), KernelError> {
        let Some(metered) = intent.metered_billing.as_ref() else {
            return Ok(());
        };

        // Fail-closed rail-mandate gate (ADR/house rule; Direction C adversarial fix).
        // A governed intent that mandates prepayment must not execute unless a
        // payment adapter is configured to prepay it. This fires for EVERY
        // MustPrepay intent regardless of charge_result, so it cannot be bypassed
        // by the charge_result == None early-return in authorize_payment_if_needed.
        // v1 decision: the gate is charge-independent; the authorized amount stays
        // charge.cost_charged and the charge currency is already checked below
        // against quote.quoted_cost.currency. Binding the authorized amount itself
        // to quote.quoted_cost is a documented deferred refinement.
        if metered.settlement_mode
            == chio_core::capability::governance::MeteredSettlementMode::MustPrepay
            && !payment_adapter_configured
        {
            return Err(KernelError::GovernedTransactionDenied(
                "governed intent mandates prepayment (settlement_mode=MustPrepay) but no payment \
                 adapter is configured; denying fail-closed"
                    .to_string(),
            ));
        }
```
(Leave the rest of the function body unchanged.)

- [ ] **Step 4: Update the call site to thread adapter presence**

At `governed_validation.rs:1034`, change:
```rust
        Self::validate_metered_billing_context(intent, charge_result, now)?;
```
to:
```rust
        Self::validate_metered_billing_context(
            intent,
            charge_result,
            self.payment_adapter.is_some(),
            now,
        )?;
```

- [ ] **Step 5: Run the gate tests to confirm they pass**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-kernel mustprepay_gate_tests -- --exact 2>&1 | tail -20
```
Expected: `test result: ok. 3 passed`. The `mustprepay_without_adapter_and_no_charge_is_denied` case is the previously-uncovered fail-open path; it must be among the passing tests.

- [ ] **Step 6: Verify clippy + fmt scoped**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel --all-targets -- -D warnings
cargo fmt -p chio-kernel -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 7: Commit**

```bash
git add crates/kernel/chio-kernel/src/kernel/governed_validation.rs
git commit -m "$(cat <<'EOF'
fix(chio-kernel): fail-closed MustPrepay gate fires before the payment early-return

Moves the rail-mandate gate into validate_metered_billing_context so a governed
MustPrepay intent with no budget charge can no longer bypass it via the
charge_result == None early-return in authorize_payment_if_needed. Denies every
MustPrepay intent when no payment adapter is configured, regardless of charge_result.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 7: Add the deterministic no-broadcast `SimPaymentAdapter`

**Files:**
- Modify: `crates/kernel/chio-kernel/src/payment.rs` (declare submodule + re-export).
- Create: `crates/kernel/chio-kernel/src/payment/sim.rs`.

**Interfaces:**
- Consumes: `PaymentAdapter` trait (payment.rs:150), `PaymentAuthorizeRequest` (payment.rs:86), `PaymentAuthorization` (payment.rs:8), `PaymentResult` (payment.rs:19), `RailSettlementStatus` (payment.rs:31), `chio_core::sha256_hex` (re-exported at `crates/core/chio-core/src/lib.rs:168`).
- Produces:
  ```rust
  pub struct SimPaymentAdapter;
  impl SimPaymentAdapter { pub fn new() -> Self; }
  impl PaymentAdapter for SimPaymentAdapter { /* authorize/capture/release/refund */ }
  ```
  `authorize` returns `authorization_id = format!("sim-{}", &sha256_hex(seed)[..32])` where `seed = "{reference}|{amount_units}|{currency}"`, `settled=false` (so the kernel exercises capture/release). No HTTP, no key, no funds held.

- [ ] **Step 1: Write the failing tests (in the new module)**

Create `crates/kernel/chio-kernel/src/payment/sim.rs`:
```rust
//! Deterministic, no-broadcast payment adapter for sim-first acceptance lanes.
//!
//! Custody-neutral by construction: it performs no HTTP, holds no key, and moves
//! no funds. Authorization ids are a pure function of the request so smokes are
//! reproducible. It echoes the governed binding into `metadata` so the settled
//! tool-call receipt carries the governed intent hash and approval token id.

use crate::payment::{
    PaymentAdapter, PaymentAuthorizeRequest, PaymentAuthorization, PaymentError, PaymentResult,
    RailSettlementStatus,
};

/// Deterministic no-broadcast payment adapter.
#[derive(Debug, Clone, Default)]
pub struct SimPaymentAdapter;

impl SimPaymentAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn deterministic_id(prefix: &str, reference: &str, amount_units: u64, currency: &str) -> String {
        let seed = format!("{reference}|{amount_units}|{currency}");
        let digest = chio_core::sha256_hex(seed.as_bytes());
        format!("{prefix}-{}", &digest[..32])
    }
}

impl PaymentAdapter for SimPaymentAdapter {
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let authorization_id = Self::deterministic_id(
            "sim",
            &request.reference,
            request.amount_units,
            &request.currency,
        );
        Ok(PaymentAuthorization {
            authorization_id,
            settled: false,
            metadata: serde_json::json!({
                "adapter": "sim",
                "mode": "prepaid_no_broadcast",
                "governed": request.governed,
                "commerce": request.commerce,
            }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "sim", "action": "capture" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "sim", "action": "release" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "sim", "action": "refund" }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reference: &str, amount: u64) -> PaymentAuthorizeRequest {
        PaymentAuthorizeRequest {
            amount_units: amount,
            currency: "USD".to_string(),
            payer: "agent-1".to_string(),
            payee: "srv-1".to_string(),
            reference: reference.to_string(),
            governed: None,
            commerce: None,
        }
    }

    #[test]
    fn authorize_is_deterministic_and_unsettled() {
        let adapter = SimPaymentAdapter::new();
        let a = adapter.authorize(&request("req-1", 100)).unwrap();
        let b = adapter.authorize(&request("req-1", 100)).unwrap();
        assert_eq!(a.authorization_id, b.authorization_id);
        assert!(a.authorization_id.starts_with("sim-"));
        assert!(!a.settled, "sim must leave capture/release to the kernel");
    }

    #[test]
    fn distinct_requests_get_distinct_ids() {
        let adapter = SimPaymentAdapter::new();
        let a = adapter.authorize(&request("req-1", 100)).unwrap();
        let c = adapter.authorize(&request("req-2", 100)).unwrap();
        assert_ne!(a.authorization_id, c.authorization_id);
    }

    #[test]
    fn capture_and_release_map_to_settled_and_released() {
        let adapter = SimPaymentAdapter::new();
        let captured = adapter.capture("sim-abc", 100, "USD", "req-1").unwrap();
        assert_eq!(captured.settlement_status, RailSettlementStatus::Settled);
        let released = adapter.release("sim-abc", "req-1").unwrap();
        assert_eq!(released.settlement_status, RailSettlementStatus::Released);
    }
}
```

- [ ] **Step 2: Wire the submodule into `payment.rs` and the crate root**

At the top of `crates/kernel/chio-kernel/src/payment.rs` (after the existing `use` block), add:
```rust
mod sim;
pub use sim::SimPaymentAdapter;
```
Then add `SimPaymentAdapter` to the existing crate-root re-export at `crates/kernel/chio-kernel/src/lib.rs:393-397` so `chio_kernel::SimPaymentAdapter` resolves in Task 9 (the other adapters are already there):
```rust
pub use payment::{
    AcpPaymentAdapter, CommercePaymentContext, GovernedPaymentContext, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizeRequest, PaymentError, PaymentResult,
    RailSettlementStatus, ReceiptSettlement, SimPaymentAdapter, X402PaymentAdapter,
};
```

- [ ] **Step 3: Run the sim tests**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-kernel sim:: -- --nocapture 2>&1 | tail -20
```
Expected: `test result: ok. 3 passed`. Confirm nonzero.

- [ ] **Step 4: Verify clippy + fmt scoped**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel --all-targets -- -D warnings
cargo fmt -p chio-kernel -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/kernel/chio-kernel/src/payment.rs crates/kernel/chio-kernel/src/payment/sim.rs crates/kernel/chio-kernel/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(chio-kernel): add deterministic no-broadcast SimPaymentAdapter

Custody-neutral sim adapter: no HTTP, no key, no funds held. Deterministic
authorization ids (sim-<sha256 prefix> of reference|amount|currency), settled=false
so the kernel exercises capture/release, and echoes the governed binding into
authorization metadata for the receipt fold.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 8: End-to-end kernel coverage: Sim authorize -> capture -> receipt fold, zero-cost release, abort unwind

**Files:**
- Modify: `crates/kernel/chio-kernel/src/kernel/tests.rs` (add sim-adapter end-to-end tests using the existing kernel test harness/builders).

**Interfaces:**
- Consumes: `SimPaymentAdapter` (Task 7), `ChioKernel::set_payment_adapter` (`construction.rs:429`), the post-execution settlement fold (`validation.rs:1003-1108`, stamps `FinancialReceiptMetadata.payment_reference` at L1097 and `settlement_status` at L1098), and `unwind_aborted_monetary_invocation` (`dispatch.rs:125`).
- Produces: no new interface; asserts existing machinery handles the sim authorization.

- [ ] **Step 1: Write the failing end-to-end tests**

In `crates/kernel/chio-kernel/src/kernel/tests.rs`, add tests that reuse the existing kernel-construction and governed-tool-call test builders in that file (follow the nearest existing governed/payment test as a template for building a `ChioKernel`, a `ToolGrant`, a governed `ToolCallRequest` with `metered_billing.settlement_mode = MustPrepay`, and an approval token):
```rust
#[test]
fn sim_adapter_settles_governed_mustprepay_onto_receipt() {
    let mut kernel = build_test_kernel_with_grant(); // existing helper in tests.rs
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    let request = governed_mustprepay_request(/* nonzero quoted cost */);
    let response = kernel.evaluate_tool_call(&request); // existing entry used by other tests
    let receipt = expect_admit_with_financial_meta(&response); // existing helper/assert
    assert!(
        receipt.payment_reference.as_deref().unwrap_or("").starts_with("sim-"),
        "settled receipt must carry the deterministic sim payment reference"
    );
    assert!(matches!(
        receipt.settlement_status,
        SettlementStatus::Settled | SettlementStatus::Pending
    ));
}

#[test]
fn governed_mustprepay_without_adapter_is_denied_end_to_end() {
    let kernel = build_test_kernel_with_grant(); // no adapter set
    let request = governed_mustprepay_request(0); // even with zero/no charge
    let response = kernel.evaluate_tool_call(&request);
    assert_denied_no_execution(&response); // existing deny assertion helper
}
```
(Where a helper does not already exist, add a thin local `fn` in `tests.rs` mirroring the existing governed-payment test setup in that file. Add the zero-cost release and abort-unwind cases the same way, asserting the sim `release`/`refund` path via `unwind_aborted_monetary_invocation`.)

- [ ] **Step 2: Run to confirm the deny case is red before wiring the adapter path**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-kernel sim_adapter_settles_governed_mustprepay_onto_receipt governed_mustprepay_without_adapter_is_denied_end_to_end -- --exact
```
Expected: initially red where the harness helpers are missing; add helpers until it compiles, then the deny case passes because of Task 6 and the settle case passes because of Task 7.

- [ ] **Step 3: Implement any missing test helpers and iterate to green**

Add the local test helpers referenced above; re-run until:
```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-kernel sim_adapter -- --nocapture 2>&1 | tail -20
```
Expected: `test result: ok.` with a nonzero passing count covering settle, deny, zero-cost release, and abort unwind.

- [ ] **Step 4: Verify clippy + fmt scoped**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel --all-targets -- -D warnings
cargo fmt -p chio-kernel -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/kernel/chio-kernel/src/kernel/tests.rs
git commit -m "$(cat <<'EOF'
test(chio-kernel): end-to-end sim-adapter governed MustPrepay settlement and unwind

Proves the sim authorization flows through the existing post-exec capture/release
path and stamps FinancialReceiptMetadata.payment_reference (sim-*) plus a
settlement_status in {Settled, Pending}; zero-cost releases; abort unwinds via
refund/release; and MustPrepay with no adapter denies before execution.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Milestone M3: Productize - CLI/config surface to select and wire the facilitator adapter

### Task 9: CLI payment-adapter config (sim | http-x402 | http-acp), wire via `set_payment_adapter`, config-consistency reject

**Files:**
- Create: `crates/products/chio-cli/src/cli/mcp/payment_config.rs`.
- Modify: `crates/products/chio-cli/src/cli/mcp/wrap.rs:303` (kernel construction).

**Interfaces:**
- Consumes: `ChioKernel::set_payment_adapter(Box<dyn PaymentAdapter>)` (`construction.rs:429`), `SimPaymentAdapter` (Task 7), `X402PaymentAdapter`/`AcpPaymentAdapter` (payment.rs:205/219, both `new(base_url)` + `with_bearer_token`).
- Produces:
  ```rust
  pub enum PaymentAdapterConfig {
      Sim,
      HttpX402 { base_url: String, bearer_token: Option<String> },
      HttpAcp { base_url: String, bearer_token: Option<String> },
  }
  impl PaymentAdapterConfig {
      pub fn validate(&self) -> Result<(), String>;              // load-time config-consistency
      pub fn build_adapter(&self) -> Box<dyn chio_kernel::PaymentAdapter>;
      pub fn default_safe() -> Self;                             // Sim
  }
  ```
  Custody guard: no operator-managed-custody or broadcast variant exists; only sim/http facilitator delegation.

- [ ] **Step 1: Write the failing config tests**

Create `crates/products/chio-cli/src/cli/mcp/payment_config.rs` with the enum, then add its tests (this file has no crate-level test allow, so use `chio_test_support::prelude::*`; ensure `chio-test-support` is in `chio-cli` `[dev-dependencies]`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn default_is_sim_and_safe() {
        assert!(matches!(PaymentAdapterConfig::default_safe(), PaymentAdapterConfig::Sim));
    }

    #[test]
    fn http_x402_requires_non_empty_base_url() {
        let cfg = PaymentAdapterConfig::HttpX402 {
            base_url: "   ".to_string(),
            bearer_token: None,
        };
        let error = cfg.validate().test_unwrap_err("blank base_url must reject at load time");
        assert!(error.contains("base_url"));
    }

    #[test]
    fn valid_variants_pass_validation_and_build() {
        let sim = PaymentAdapterConfig::Sim;
        sim.validate().test_unwrap();
        let _ = sim.build_adapter();
        let http = PaymentAdapterConfig::HttpAcp {
            base_url: "https://facilitator.example".to_string(),
            bearer_token: Some("tok".to_string()),
        };
        http.validate().test_unwrap();
        let _ = http.build_adapter();
    }
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-cli payment_config -- --exact
```
Expected: unresolved-item / missing-module error.

- [ ] **Step 3: Implement the config enum**

Fill in `payment_config.rs`:
```rust
//! CLI selection of the kernel payment adapter. Sim is the safe default; the
//! http variants delegate to an external facilitator. No custody or broadcast
//! variant is exposed (custody-neutral).

use chio_kernel::{AcpPaymentAdapter, PaymentAdapter, SimPaymentAdapter, X402PaymentAdapter};

#[derive(Debug, Clone)]
pub enum PaymentAdapterConfig {
    Sim,
    HttpX402 { base_url: String, bearer_token: Option<String> },
    HttpAcp { base_url: String, bearer_token: Option<String> },
}

impl PaymentAdapterConfig {
    #[must_use]
    pub fn default_safe() -> Self {
        Self::Sim
    }

    /// Load-time config-consistency check (house rule: invalid policies reject
    /// at load time). This is a config-shape check only; the authoritative
    /// fail-closed enforcement is the kernel runtime MustPrepay gate.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Sim => Ok(()),
            Self::HttpX402 { base_url, .. } | Self::HttpAcp { base_url, .. } => {
                if base_url.trim().is_empty() {
                    return Err("http payment adapter requires a non-empty base_url".to_string());
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn build_adapter(&self) -> Box<dyn PaymentAdapter> {
        match self {
            Self::Sim => Box::new(SimPaymentAdapter::new()),
            Self::HttpX402 { base_url, bearer_token } => {
                let mut adapter = X402PaymentAdapter::new(base_url.clone());
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token.clone());
                }
                Box::new(adapter)
            }
            Self::HttpAcp { base_url, bearer_token } => {
                let mut adapter = AcpPaymentAdapter::new(base_url.clone());
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token.clone());
                }
                Box::new(adapter)
            }
        }
    }
}
```
(`AcpPaymentAdapter`, `X402PaymentAdapter`, and `PaymentAdapter` are already re-exported at the `chio_kernel` crate root (`lib.rs:393-397`); `SimPaymentAdapter` was added to that same re-export list in Task 7, so all four resolve here.)

- [ ] **Step 4: Register the module and wire it into kernel construction**

In the parent `mcp` module file, add `pub mod payment_config;`. In `crates/products/chio-cli/src/cli/mcp/wrap.rs` at L303, after `let mut kernel = chio_kernel::ChioKernel::new(...)`, resolve the config (default `Sim`), validate it fail-closed, and wire it:
```rust
    let payment_adapter_config = resolve_payment_adapter_config(/* from CLI flags/config */)
        .unwrap_or_else(PaymentAdapterConfig::default_safe);
    payment_adapter_config
        .validate()
        .map_err(|error| /* map to the command's error type */ )?;
    kernel.set_payment_adapter(payment_adapter_config.build_adapter());
```

- [ ] **Step 5: Run the config tests to green**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-cli payment_config -- --nocapture 2>&1 | tail -20
```
Expected: `test result: ok. 3 passed`.

- [ ] **Step 6: Add and run the CLI-hosted integration test**

Add an integration test that builds the kernel via the CLI config path selecting `Sim` and runs one governed MustPrepay tool call, asserting the receipt carries a `sim-` payment reference. Run:
```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-cli governed_mustprepay_via_cli_sim -- --nocapture 2>&1 | tail -20
```
Expected: nonzero passing.

- [ ] **Step 7: Verify clippy + fmt scoped (both crates touched)**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-cli --all-targets -- -D warnings
cargo fmt -p chio-cli -- --check
CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel --all-targets -- -D warnings
cargo fmt -p chio-kernel -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 8: Commit**

```bash
git add crates/products/chio-cli/src/cli/mcp/payment_config.rs crates/products/chio-cli/src/cli/mcp/wrap.rs crates/products/chio-cli/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(chio-cli): select and wire the kernel payment adapter (sim default, http facilitators)

Adds PaymentAdapterConfig (sim | http-x402 | http-acp), a load-time config-consistency
reject for http variants missing a base_url, and wires the resolved Box<dyn PaymentAdapter>
into ChioKernel via set_payment_adapter. Sim is the safe default; no custody/broadcast
variant is exposed.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Milestone M4: Sim-first acceptance lane - deterministic no-key governed-x402 smoke

### Task 10: No-key governed-x402 smoke with positive settlement fold and negative deny, nonzero-test guard

**Files:**
- Create: `examples/governed-x402-sim/smoke.sh`.
- Create: `examples/governed-x402-sim/assert_receipt.py`.

**Interfaces:**
- Consumes: the CLI sim adapter path (Task 9), the shared smoke helpers at `examples/_shared/hello-http-common.sh` (`ensure_chio_bin`, `pick_free_port`, `wait_for_http`).
- Produces: a deterministic CI lane emitting a governed-x402 receipt bundle and asserting the fold fields plus the fail-closed deny path; the assertion step fails on zero assertions executed.

- [ ] **Step 1: Write the smoke harness**

Create `examples/governed-x402-sim/smoke.sh` (model on `examples/agent-commerce-network/smoke.sh`):
```bash
#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
ARTIFACT_ROOT="$(mktemp -d)"
trap 'rm -rf "${ARTIFACT_ROOT}"' EXIT

# shellcheck source=/dev/null
source "${ROOT}/examples/_shared/hello-http-common.sh"

CHIO_BIN="$(ensure_chio_bin)"

# 1) Positive: CLI-hosted kernel with the sim adapter runs a governed MustPrepay
#    tool call and writes the signed tool-call receipt to the bundle.
"${CHIO_BIN}" <governed-x402 sim run subcommand> \
  --payment-adapter sim \
  --governed-mustprepay \
  --out "${ARTIFACT_ROOT}/receipt.json"

# 2) Negative: same intent with the adapter disabled must be denied with no
#    execution receipt.
set +e
"${CHIO_BIN}" <governed-x402 sim run subcommand> \
  --payment-adapter none \
  --governed-mustprepay \
  --out "${ARTIFACT_ROOT}/deny.json"
deny_rc=$?
set -e

python3 "${HERE}/assert_receipt.py" \
  --receipt "${ARTIFACT_ROOT}/receipt.json" \
  --deny-rc "${deny_rc}" \
  --deny-out "${ARTIFACT_ROOT}/deny.json"

echo "governed-x402-sim smoke: OK"
```
(Replace `<governed-x402 sim run subcommand>` with the CLI subcommand wired in Task 9. If a bespoke subcommand is not warranted, drive the same path through the existing MCP serve command plus a one-shot governed request fixture.)

- [ ] **Step 2: Write the assertion script with a nonzero-assertion guard**

Create `examples/governed-x402-sim/assert_receipt.py`:
```python
#!/usr/bin/env python3
import argparse, json, sys

def find_financial_metadata(node):
    """Locate the FinancialReceiptMetadata object anywhere in the receipt tree.

    It is the object carrying a settlement_status field. Confirm the concrete
    wrapper key against a real dump in Step 4; this walk avoids hard-coding it.
    """
    if isinstance(node, dict):
        if "settlement_status" in node and ("payment_reference" in node or "currency" in node):
            return node
        for value in node.values():
            found = find_financial_metadata(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = find_financial_metadata(value)
            if found is not None:
                return found
    return None

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--deny-rc", type=int, required=True)
    ap.add_argument("--deny-out", required=True)
    args = ap.parse_args()

    checks = 0

    with open(args.receipt) as fh:
        receipt = json.load(fh)
    # FinancialReceiptMetadata has no serde rename_all, so its JSON keys are
    # snake_case (payment_reference, settlement_status, cost_breakdown) and
    # SettlementStatus serializes snake_case (settled/pending). Confirm the
    # parent receipt key that holds the financial metadata against a real dump
    # in Step 4 and adjust the lookup below if the wrapper key differs.
    fin = find_financial_metadata(receipt)
    assert fin is not None, "no FinancialReceiptMetadata found in receipt bundle"

    pay_ref = fin.get("payment_reference") or ""
    assert pay_ref.startswith("sim-"), f"expected sim payment reference, got {pay_ref!r}"
    checks += 1

    status = fin.get("settlement_status")
    assert status in ("settled", "pending"), f"bad status {status!r}"
    checks += 1

    # Governed binding round-trips into the payment breakdown (exact nesting
    # confirmed against a real dump in Step 4).
    breakdown = json.dumps(fin.get("cost_breakdown") or {})
    assert "intent_hash" in breakdown or "intentHash" in breakdown, "governed intent hash missing"
    checks += 1

    # Negative: adapter-absent MustPrepay must be denied (nonzero rc, no exec receipt).
    assert args.deny_rc != 0, "adapter-absent MustPrepay must be denied"
    checks += 1

    # No false green: we must have run assertions.
    assert checks > 0, "no assertions executed"
    print(f"assert_receipt: OK ({checks} assertions)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```
(Confirm the exact JSON field names by dumping one real receipt during Step 4 and adjust the keys to match the serialized `FinancialReceiptMetadata`.)

- [ ] **Step 3: Make the smoke executable**

```bash
chmod +x examples/governed-x402-sim/smoke.sh
```

- [ ] **Step 4: Run the smoke with no keys and no network**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo build -p chio-cli
examples/governed-x402-sim/smoke.sh
```
Expected: `assert_receipt: OK (4 assertions)` then `governed-x402-sim smoke: OK`. If the receipt JSON keys differ, adjust `assert_receipt.py` to the real serialized names and re-run. Confirm it is deterministic by running twice and diffing `receipt.json` payment reference.

- [ ] **Step 5: Wire the smoke into the no-key CI lane**

Add the smoke to the same CI lane that runs `examples/agent-commerce-network/smoke.sh` (a shell step invoking `examples/governed-x402-sim/smoke.sh`). Ensure the lane fails if the smoke exits nonzero or prints `0 assertions`.

- [ ] **Step 6: Commit**

```bash
git add examples/governed-x402-sim/smoke.sh examples/governed-x402-sim/assert_receipt.py
git commit -m "$(cat <<'EOF'
test(examples): deterministic no-key governed-x402 sim smoke with deny path

Runs a CLI-hosted kernel with the sim adapter through a governed MustPrepay tool
call, asserts the receipt settlement fold (sim payment reference, settled/pending,
governed intent hash), and asserts the adapter-absent negative denies. Assertion
step fails on zero assertions (no false green).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Milestone M5 (DEFERRABLE): EIP-3009 ApprovalBinding bridge + off-chain settlement receipt (Rail B, custody-neutral digest-only)

This milestone is deferrable/optional for v1 and stays prepare-only (digest, never broadcast). All EVM/digest logic lives at the CLI/control-plane layer; the kernel payment adapter stays rail-agnostic. It depends on Task 6/7 (so the sim path can accept the digest as a pseudo-broadcast reference) and on a decided seller->rail EVM-binding-field source. It reserves an `Option::None` slot for Direction A's `execution_nonce` so the Phase-2 LIVE variant composes without a schema v2.

### Task 11: `RailBinding` + `approval_binding_from_governed` seam and the off-chain settlement receipt

**Files:**
- Modify: `crates/economy/chio-settle/src/payments.rs` (add `RailBinding`, `approval_binding_from_governed`, `OffchainSettlementReceiptArtifact`, `validate_offchain_settlement_receipt`).
- Create: `scripts/check-no-eip3009-broadcast.sh`.
- Modify (CLI/control-plane layer): add the seller->`RailBinding` resolver from operator config (NOT in the kernel adapter).

**Interfaces:**
- Consumes: `ApprovalBinding` (payments.rs:192, `{ chain_id: u64, payee_address: String, amount_minor_units: u128, token_symbol: String, token_contract: Option<String>, approval_expires_at: u64 }`), `prepare_transfer_with_authorization` (payments.rs:473), `GovernedApprovalToken` (`chio_core_types::capability::governance`), `PreparedTransferWithAuthorization` (payments.rs:59), `MonetaryAmount`.
- Produces:
  ```rust
  pub struct RailBinding {
      pub chain_id: u64,
      pub token_contract: String,
      pub payee_address: String,
      pub token_decimals: u8,
      pub token_symbol: String,
  }
  pub fn approval_binding_from_governed(
      token: &GovernedApprovalToken,
      rail: &RailBinding,
      amount_minor_units: u128,
      approval_expires_at: u64,
  ) -> Result<ApprovalBinding, SettlementError>;

  pub struct OffchainSettlementReceiptArtifact {
      pub schema: String,                 // "chio.settle.offchain_receipt.v1"
      pub settlement_receipt_id: String,
      pub issued_at: u64,
      pub authorization_digest: String,   // from PreparedTransferWithAuthorization
      pub governed_receipt_id: String,    // A-contract slot 1: binds back to the tool-call receipt
      pub settled_amount: MonetaryAmount,
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub execution_nonce: Option<String>, // A-contract slot 2: None until Direction A lands
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub note: Option<String>,
  }
  pub fn validate_offchain_settlement_receipt(
      receipt: &OffchainSettlementReceiptArtifact,
  ) -> Result<(), SettlementError>;
  ```

- [ ] **Step 1: Write the failing bridge + receipt tests**

Add tests to `chio-settle` (use `chio_test_support::prelude::*` if the file lacks a test allow):
```rust
#[test]
fn bridge_builds_binding_prepare_accepts_happy_path() {
    let token = sample_verified_approval_token();     // fixture helper
    let rail = RailBinding {
        chain_id: 8453,
        token_contract: "0xToken".to_string(),
        payee_address: "0xPayee".to_string(),
        token_decimals: 6,
        token_symbol: "USDC".to_string(),
    };
    let binding = approval_binding_from_governed(&token, &rail, 1_000_000, token.expires_at)
        .test_unwrap();
    let prepared = prepare_transfer_with_authorization(
        sample_domain(),
        sample_authorization_input(&binding),
        &binding,
        token.issued_at + 1,
        &sample_nonce_store(),
    )
    .test_unwrap();
    assert!(!prepared.authorization_digest.is_empty());
}

#[test]
fn bridge_prepare_rejects_payee_mismatch() {
    // A binding whose payee differs from the authorization must fail closed.
    let error = prepare_transfer_with_authorization(
        sample_domain(),
        sample_authorization_input_with_wrong_payee(),
        &sample_binding(),
        1_000,
        &sample_nonce_store(),
    )
    .test_unwrap_err("payee mismatch must fail closed");
    assert!(matches!(error, SettlementError::InvalidBinding(_)));
}

#[test]
fn offchain_receipt_validate_binds_digest_to_governed_receipt() {
    let receipt = OffchainSettlementReceiptArtifact {
        schema: "chio.settle.offchain_receipt.v1".to_string(),
        settlement_receipt_id: "osr-1".to_string(),
        issued_at: 1_700_000_000,
        authorization_digest: "0xdigest".to_string(),
        governed_receipt_id: "rc-1".to_string(),
        settled_amount: MonetaryAmount { units: 1_000_000, currency: "USDC".to_string() },
        execution_nonce: None, // reserved A slot, None until Direction A lands
        note: None,
    };
    validate_offchain_settlement_receipt(&receipt).test_unwrap();
    // Empty governed_receipt_id must fail closed.
    let mut bad = receipt.clone();
    bad.governed_receipt_id = String::new();
    let error = validate_offchain_settlement_receipt(&bad)
        .test_unwrap_err("empty governed_receipt_id must fail");
    assert!(matches!(error, SettlementError::InvalidInput(_)));
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-settle bridge_builds_binding_prepare_accepts_happy_path -- --exact
```
Expected: unresolved items (`RailBinding`, `approval_binding_from_governed`, `OffchainSettlementReceiptArtifact`).

- [ ] **Step 3: Implement the seam, receipt, and validator**

In `crates/economy/chio-settle/src/payments.rs` add the `RailBinding` struct, `approval_binding_from_governed` (constructs an `ApprovalBinding` from the resolved rail values plus the amount and the token's approval expiry; the caller is the trust boundary that resolved the rail from a verified token, exactly as the L169-189 doc describes), the `OffchainSettlementReceiptArtifact` struct (with the two reserved A-contract fields), and `validate_offchain_settlement_receipt` (reject empty `schema`/`settlement_receipt_id`/`authorization_digest`/`governed_receipt_id`; require positive `settled_amount`; leave `execution_nonce` optional). Keep everything prepare-only: never call any broadcast path.

- [ ] **Step 4: Run the bridge + receipt tests to green**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo test -p chio-settle offchain_receipt_validate_binds_digest_to_governed_receipt bridge_builds_binding_prepare_accepts_happy_path bridge_prepare_rejects_payee_mismatch -- --exact 2>&1 | tail -20
```
Expected: `test result: ok. 3 passed`.

- [ ] **Step 5: Add the seller->RailBinding resolver at the CLI/control-plane layer**

Add a resolver mapping `GovernedCommerceContext.seller` (+ token symbol) to a `RailBinding` sourced from operator config, in `chio-cli` or `chio-control-plane` (NOT the kernel adapter). The sim adapter path, when a resolved rail is EVM, calls `approval_binding_from_governed` at this layer to produce the digest and derives a deterministic pseudo-broadcast reference from it; the kernel `SimPaymentAdapter` stays rail-agnostic. Add a unit test asserting the pseudo reference derives from `authorization_digest`.

- [ ] **Step 6: Add the no-broadcast CI guard**

Create `scripts/check-no-eip3009-broadcast.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

scanned=0
violations=0
while IFS= read -r file; do
  scanned=$((scanned + 1))
  # Allow the doc-comment mention; forbid an actual submit/broadcast in the off-chain lane.
  if grep -nE "eth_sendTransaction|\.send_transaction\(|broadcast_transfer_with_authorization" "${file}" \
       | grep -v "^[0-9]*:[[:space:]]*//" >/dev/null; then
    echo "VIOLATION: broadcast path in off-chain settle lane: ${file}"
    violations=$((violations + 1))
  fi
done < <(find "${ROOT}/crates/economy/chio-settle/src" -name 'payments.rs')

if [[ "${scanned}" -eq 0 ]]; then
  echo "FALSE-GREEN GUARD: scanned 0 files"; exit 1
fi
if [[ "${violations}" -ne 0 ]]; then
  echo "check-no-eip3009-broadcast: FAILED"; exit 1
fi
echo "check-no-eip3009-broadcast: OK (${scanned} files scanned)"
```
Run:
```bash
chmod +x scripts/check-no-eip3009-broadcast.sh
scripts/check-no-eip3009-broadcast.sh
```
Expected: `check-no-eip3009-broadcast: OK (1 files scanned)`.

- [ ] **Step 7: Verify clippy + fmt scoped**

```bash
rm -rf target/debug/incremental
CARGO_INCREMENTAL=0 cargo clippy -p chio-settle --all-targets -- -D warnings
cargo fmt -p chio-settle -- --check
```
Expected: no warnings, fmt clean.

- [ ] **Step 8: Commit**

```bash
git add crates/economy/chio-settle/src/payments.rs scripts/check-no-eip3009-broadcast.sh
git commit -m "$(cat <<'EOF'
feat(chio-settle): governed ApprovalBinding seam and prepare-only off-chain settlement receipt

Gives the orphaned EIP-3009 lane its first non-test caller via
approval_binding_from_governed (all existing fail-closed binding/nonce/window
assertions still reject mismatches) and a new OffchainSettlementReceiptArtifact
binding authorization_digest -> governed_receipt_id with a reserved Option::None
execution_nonce slot for Direction A. Prepare-only, digest-only; CI guard proves
no in-tree broadcast.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Spec Coverage Map

Verifies every spec milestone, risk, prerequisite, and adversarial correction maps to a task.

| Spec item | Task(s) |
| --- | --- |
| M0 prerequisites: baseline + ADR-0015 governance to Accepted-for-follow-up-B; deferred follow-up A recorded | Task 1 |
| M1 anti-self-dealing: optional `decision_rule_ref`, signature-safe serialization golden | Task 2 |
| M1 `validate_against_roster` (roster + decision rule), `validate()` stays shape-only | Task 3 |
| M1 enforce at every value-path constructor + fold into `adjudication_id` + choke-point test | Task 4 |
| M2 (spec) sim adapter | Task 7 |
| M2 fail-closed MustPrepay gate | Task 6 (blocking placement fix) + Task 8 (end-to-end) |
| M3 CLI/config adapter select + wire `set_payment_adapter` + load-time reject | Task 9 |
| M4 no-key sim smoke + negative deny | Task 10 |
| M5 EIP-3009 ApprovalBinding bridge + off-chain settlement receipt (deferrable) | Task 11 |
| Adversarial BLOCKING: gate before `charge_result==None` early-return, thread `payment_adapter_configured`, fire for every MustPrepay, add uncovered no-charge+no-adapter DENY test | Task 6 (Steps 1-5) |
| Adversarial M1: restore "anchored in a registry" (bind signed roster id/hash into adjudication, folded into `adjudication_id`) | Tasks 2-4 (`roster_anchor_ref` + fold + anchor-mismatch test) |
| Adversarial M1: CI/grep that all liability artifacts construct only at `validate_against_roster` sites | Task 5 |
| Adversarial M1: id-golden changes while serialization/signature goldens stay stable, assert both | Task 2 Step 1 (serialization) + Task 4 Step 6 (id golden) |
| Adversarial M3: reframe load-time reject as config-consistency only; M2 runtime gate is authoritative; sim default | Task 9 Step 3 doc + Step 4 |
| Adversarial framing: control-plane reaches chio-market via chio-core re-export; keep EIP-3009 bridge at CLI/control-plane | Dependency note + Task 11 Step 5 |
| Custody-neutral: sim/testnet-first, digest-only, no broadcast; reserve A-contract slot (`authorization_digest -> governed_receipt_id + execution_nonce`, None until A) | Task 7 (no HTTP/key), Task 11 (reserved slots + no-broadcast guard) |
| Nonzero executed-test guard on every acceptance/smoke gate | Tasks 5, 10, 11 (explicit zero-match/zero-assertion failures) |
| Dependency: C-M1..M4 not blocked by A; only sidecar rail gated by A | Dependency note (header) |
| Risk 1 (signed-artifact break) | Task 2 (optional `skip_serializing_if` fields) |
| Risk 2 (`validate()` churn) | Task 3 (separate `validate_against_roster`) |
| Risk 3 (fail-open payment) | Task 6 |
| Risk 4 (custody creep) | Tasks 7, 9, 11 (no custody/broadcast surface) |
| Risk 5 (crate cycle) | Task 4 (pass `&[String]`, no new dep) |
| Risk 6 (two-x402-surface confusion) | Task 1 rail decision + Task 11 Step 5 composition |
| Risk 7 (Solidity immutability) | Task 1 (follow-up A deferred) |

**Open questions resolved by this plan:** v1 rail = Rail A (kernel HTTP x402/ACP) authoritative, Rail B (EIP-3009 prepare-only) deferrable under it (Task 1, Task 11). EVM binding fields come from a caller-side seller->RailBinding resolver, not an intent schema change (Task 11). A new off-chain settlement receipt is minted (Task 11). Sim-first surface = deterministic no-key SimPaymentAdapter + smoke (Tasks 7, 10). Roster sourced as concrete `&[String]` from control-plane operator config with a bound signed anchor (Tasks 3-4). Both roster and decision-rule halves are in scope as optional/anchored fields (Tasks 2-4). MustPrepay-without-adapter denies (Task 6). ADR-0015 moved to Accepted-for-follow-up-B (Task 1).

## Execution Handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** - dispatch a fresh subagent per task, review between tasks, fast iteration (superpowers:subagent-driven-development).
2. **Inline Execution** - execute tasks in-session with checkpoints (superpowers:executing-plans).

Suggested order given the dependency note: Task 1, then Tasks 2-5 (M1, independent of the rail and of Directions A/B/D, can land first/in parallel), then Task 6 (blocking gate) before any other M2 work, then Tasks 7-8, 9, 10, and finally Task 11 (deferrable).
