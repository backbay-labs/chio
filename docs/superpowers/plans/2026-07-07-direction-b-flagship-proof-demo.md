# Direction B: Flagship Proof Demo + Unified Spend/Exposure Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship two fail-closed, non-overclaiming deliverables: (1) a single narrated one-command operator story over the existing signed Proof Room commerce-transaction-passport bundle (mandate/allowance -> kernel-signed DENY receipt -> kernel-signed ALLOW receipt -> green settlement), wired into the release-qualification lane as a regression asset; and (2) one versioned, schema-governed spend/exposure contract `chio.comptroller.surface-report.v1` that is a pure projection over the existing `OperatorReport` (kernel) + `ExposureLedgerReport` (credit) types, published as JSON Schema, enforced by the signed-artifact registry gate, and consumed by both the in-repo dashboard (generated TypeScript, no hand-maintained drift) and the out-of-repo dashboard (schema + optional signed export).

**Architecture:** Reuse, never rebuild. The demo is a narration wrapper over an already-signed, already-CI-green bundle plus the deterministic trusted-key block extracted from `scripts/check-chio-transaction-passport.sh`. The contract is a new Rust projection type in the `chio-kernel` `operator_report` module (kernel already depends on `chio-credit`, so it can embed `chio_credit::ExposureLedgerCurrencyPosition`; putting it in `chio-credit` would create a dependency cycle), composed by a new control-plane builder from `build_operator_report` + `build_exposure_ledger_report`, exposed on a new `GET /v1/reports/comptroller-surface` endpoint, published as a signed-artifact JSON Schema under a new `spec/schemas/chio-comptroller/v1` namespace, and cross-language-enforced by a Rust round-trip conformance test plus a TypeScript no-drift codegen gate.

**Tech Stack:** Rust (workspace crates `chio-kernel`, `chio-credit`, `chio-core-types`, `chio-control-plane`, `chio-cli`), `serde`/`serde_json` with `rename_all = "camelCase"`, `jsonschema` 0.46.0 (already a `chio-core-types` dependency), Bash gate scripts + Python3 (schema-registry manifest), JSON Schema draft 2020-12, React/Vite dashboard with pinned `json-schema-to-typescript@15.0.4` (the exact version the repo's `cargo xtask codegen --lang ts` already pins).

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the spec, `CLAUDE.md`, and the coordinating ROADMAP.

- **No em dashes (U+2014)** anywhere in code, comments, prose, scripts, or JSON. Use hyphens (`-`) or parentheses.
- **Fail-closed:** errors deny/reject. Invalid inputs and validation failures return errors, never silent success or coercion. Any new HTTP path maps validation failure to a 5xx, never a 200.
- **clippy `unwrap_used` and `expect_used` are DENIED** in non-test crate `src/`. Use `Result` + `?`, `map_err`, or the repo's helpers (`CliError::cli_other_error`, `TrustHttpError`). Test modules follow the existing repo convention: `crates/products/chio-cli/tests/receipt_query_export.rs` uses `.expect("...")` freely in `#[test]` code, so mirror that pattern inside test functions only.
- **Conventional commits** (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`), each ending with a trailing blank line then exactly:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- **Do NOT run `cargo build --workspace` / `cargo test --workspace` / `cargo clippy --workspace`** during task execution (multi-minute cold builds). Use scoped `-p <crate>` verification only, named per task. The full one-liner is a maintainer-run final gate, not a per-task step.
- **Before any cargo invocation in a task**, run `rm -rf target/debug/incremental` and export `CARGO_INCREMENTAL=0` (keeps scoped builds deterministic and avoids incremental-cache corruption across split crates).
- **Canonical JSON (RFC 8785)** is mandatory for any signed payload; the existing `Keypair::sign_canonical` / `PublicKey::verify_canonical` and `SignedExportEnvelope` provide it. Do not hand-roll canonicalization.
- **serde convention:** the `operator_report` module and `chio-credit` export types all use `#[serde(rename_all = "camelCase")]`. Every new type in the contract MUST use the same, and every published JSON Schema property name MUST match the camelCase serde output exactly (this is the anti-drift anchor).
- **Non-claims discipline:** the demo proves the wall at the artifact/verifier level over an offline projection (`payment-lifecycle` psp `stripe-shaped-offline`, settlement `settled` via verified cache). No prose or banner may imply a live money-stop, fund custody, or public availability. Mirror the language of `xtask/src/launch_acceptance.rs` `write_non_claims`.
- **Cross-direction dependency:** the LIVE `examples/agent-commerce-network` flagship variant is gated by Direction A (authoritative kernel mediation / `execution_nonce` in `chio-api-protect`) and is OUT OF SCOPE here. The static bundle (M1) and the entire unified contract (M2-M5, Tasks 3-11) have NO dependency on A. Per ROADMAP integration point 1, the v1 schema and Rust type MUST reserve `executionNonceRef`/`holdRef` linkage slots now (`Option::None` until A lands) so the Phase-2 LIVE variant composes without a governance-gated schema v2.

---

## File Structure

Each file's single responsibility.

**M1 - flagship demo (Tasks 1-2):**
- `scripts/lib/chio-proof-trusted-keys.sh` (new): single source of truth for the deterministic `CHIO_*_TRUSTED_*` env block, sourced by both the passport gate and the demo runner.
- `scripts/check-chio-transaction-passport.sh` (modify): replace its inline export block with a `source` of the shared lib; no behavior change.
- `scripts/demo/flagship-wall-stops-money.sh` (new): one-command narrated runner over the signed bundle; honest, independent narration; fail-closed.
- `scripts/tests/flagship-wall-stops-money.test.sh` (new): asserts the runner is green + narrates on a pristine bundle and non-zero on a tampered bundle.
- `docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md` (new): operator-facing walkthrough, inside the non-claims discipline.
- `scripts/qualify-release.sh` (modify): add the passport gate + launch-acceptance + demo test as release-lane regressions.

**M2 - projection type + endpoint (Tasks 3-5):**
- `crates/kernel/chio-kernel/src/operator_report/comptroller_surface.rs` (new): `ComptrollerSurfaceReport` projection type, `ComptrollerDecisionSummary`, `ComptrollerSurfaceSourceRefs`, `from_parts`, `validate_consistency`.
- `crates/kernel/chio-kernel/src/operator_report/mod.rs` (modify): register `pub mod comptroller_surface` + re-exports.
- `crates/kernel/chio-kernel/src/operator_report/queries.rs` (modify): add `to_exposure_ledger_query` converter on `OperatorReportQuery`.
- `crates/platform/chio-control-plane/src/trust_control/reports.rs` (modify): add `build_comptroller_surface_report` (fail-closed compose + validate).
- `crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs` (modify): add `COMPTROLLER_SURFACE_REPORT_PATH`.
- `crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs` (modify): add `handle_comptroller_surface_report`.
- `crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs` (modify): register the route next to `OPERATOR_REPORT_PATH` (line 303).
- `crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs` (modify): add `comptroller_surface` client op.
- `crates/products/chio-cli/tests/receipt_query_export.rs` (modify): add `test_comptroller_surface_report_endpoint` (correct test binary).

**M3 - schema governance (Task 6):**
- `spec/schemas/chio-comptroller/v1/surface-report.schema.json` (new): the published draft-2020-12 schema.
- `crates/core/chio-core-types/src/signed_artifact.rs` (modify): add const + `SIGNED_ARTIFACT_SCHEMA_SPECS` entry so the id lands in BOTH `KNOWN_SIGNED_ARTIFACT_SCHEMAS` and `built_in_signed_artifact_registry()`.
- `spec/schemas/registry.json` (modify): add the artifact entry.
- `spec/schemas/MANIFEST.sha256` (modify): deterministic regeneration.
- `scripts/check-chio-schema-registry.sh` (modify): enroll `spec/schemas/chio-comptroller/` in `checked_chio_schema_roots`.
- `spec/schemas/COVERAGE.md` (modify): documentation row (not gated, but kept accurate).

**M4 - cross-language enforcement (Tasks 7-9):**
- `crates/kernel/chio-kernel/tests/comptroller_surface_schema.rs` (new): Rust round-trip conformance (positive + negatives) against the published schema.
- `crates/products/chio-cli/dashboard/package.json` (modify): `gen:contracts` script + pinned `json-schema-to-typescript@15.0.4`.
- `crates/products/chio-cli/dashboard/scripts/gen-contracts.mjs` (new): codegen driver.
- `crates/products/chio-cli/dashboard/src/generated/comptroller-surface.ts` (generated): the single TS source of truth for these shapes.
- `crates/products/chio-cli/dashboard/src/types.ts` (modify): consume the generated types for comptroller-surface shapes.
- `scripts/check-comptroller-contract-no-drift.sh` (new): regenerate + `git diff --exit-code` no-drift gate.
- `crates/platform/chio-control-plane/src/trust_control/reports.rs` (modify): optional `build_signed_comptroller_surface_report`.

**M5 - lane gate + docs (Tasks 10-11):**
- `scripts/qualify-comptroller-operator-surfaces.sh` (modify): fix wrong-binary invocations, add the 6th surface + nonzero-test-count guard.
- `docs/standards/CHIO_OPERATOR_CONTROL_SURFACE_PROFILE.json` (modify): add the witnessed 6th surface.
- `scripts/qualify-release.sh` (modify): add schema-registry + TS no-drift + operator-surfaces gates.
- `docs/reference/RECEIPT_DASHBOARD_GUIDE.md`, `docs/reference/RECEIPT_QUERY_API.md`, `docs/reference/AGENT_ECONOMY.md` (modify): document the contract as the single cross-language source of truth.

---

## Task 1: Extract shared trusted-key block + honest flagship demo runner

**Files:**
- Create: `scripts/lib/chio-proof-trusted-keys.sh`
- Modify: `scripts/check-chio-transaction-passport.sh:123-150`
- Create: `scripts/demo/flagship-wall-stops-money.sh`
- Create: `scripts/tests/flagship-wall-stops-money.test.sh`

**Interfaces:**
- Consumes: the existing signed bundle at `fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle`; the `chio` binary via `CHIO_BIN` (self-builds `target/debug/chio` if unset, mirroring `check-chio-transaction-passport.sh:111-121`).
- Produces: `scripts/lib/chio-proof-trusted-keys.sh` (sourced env block, single source of truth); `scripts/demo/flagship-wall-stops-money.sh <bundle-path>` (fail-closed narrated runner); `scripts/tests/flagship-wall-stops-money.test.sh`.

**Adversarial fix folded in (M1 honest narration):** the two terminal receipts carry ONLY `{kernel_key, policy_digest, receipt_id, schema, signature, terminal_status}` (verified: `commerce-terminal-allow-receipt.json` / `commerce-terminal-denial-receipt.json`). They share `kernel_key e8da63...` / `policy_digest 824f6c...` (a shared kernel + policy, NOT a mandate link) and carry NO amount and NO reference to `mandate-commerce-001`. The runner MUST narrate the allow and deny independently and MUST NOT assert they are two occurrences of the same mandate.

- [ ] **Step 1: Write the failing test**

Create `scripts/tests/flagship-wall-stops-money.test.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$ROOT/scripts/demo/flagship-wall-stops-money.sh"
BUNDLE="$ROOT/fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle"

# 1. Pristine bundle: runner exits 0 and narrates all four arcs plus the non-claims banner.
out="$(bash "$RUNNER" "$BUNDLE")"
for needle in "MANDATE / ALLOWANCE" "DENIED" "denied_guard_request" "ALLOWED" "allowed_executed" "SETTLED" "NON-CLAIMS"; do
  grep -q "$needle" <<<"$out" || { echo "FAIL: runner output missing '$needle'"; exit 1; }
done
# Honesty guard: the runner must NOT assert a same-mandate deny/allow linkage.
if grep -Eqi "same (mandate|order)|two occurrences|second occurrence of mandate-commerce-001" <<<"$out"; then
  echo "FAIL: runner overclaims a same-mandate allow/deny linkage the receipts do not carry"; exit 1
fi

# 2. Tampered bundle: runner is fail-closed (non-zero).
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp -R "$BUNDLE" "$tmp/bundle"
python3 - "$tmp/bundle/commerce-terminal-allow-receipt.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["terminal_status"] = "tampered_status"
json.dump(d, open(p, "w"))
PY
if bash "$RUNNER" "$tmp/bundle" >/dev/null 2>&1; then
  echo "FAIL: runner accepted a tampered bundle (not fail-closed)"; exit 1
fi
echo "OK flagship-wall-stops-money.test.sh"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash scripts/tests/flagship-wall-stops-money.test.sh`
Expected: FAIL with `flagship-wall-stops-money.sh: No such file or directory` (runner not created yet).

- [ ] **Step 3: Extract the shared trusted-key block**

Create `scripts/lib/chio-proof-trusted-keys.sh` containing exactly the `export CHIO_*` block currently at `scripts/check-chio-transaction-passport.sh:123-150` (the `CHIO_AGENT_WEB_*`, `CHIO_PROOF_ROOM_TRUSTED_*`, `CHIO_TRANSACTION_TRUSTED_ROOT_KEYS`, `CHIO_RUNTIME_*`, `CHIO_ENTERPRISE_TRUSTED_*`, `CHIO_SWARM_*`, `CHIO_DISCLOSURE_*`, `CHIO_TRUST_MARKET_*`, `CHIO_COMMERCE_TRUSTED_*`, `CHIO_PUBLIC_SETTLEMENT_*` exports, verbatim, each keeping its `${VAR:-default}` form). Prefix with:

```bash
# Deterministic trusted-key block for the Chio Proof Room commerce-transaction-passport bundle.
# Single source of truth: sourced by scripts/check-chio-transaction-passport.sh and
# scripts/demo/flagship-wall-stops-money.sh. Do not fork these values.
```

- [ ] **Step 4: Replace the inline block in the passport gate with a source**

In `scripts/check-chio-transaction-passport.sh`, delete lines 123-150 (the inline `export` block) and replace with:

```bash
# shellcheck source=scripts/lib/chio-proof-trusted-keys.sh
source "$ROOT/scripts/lib/chio-proof-trusted-keys.sh"
```

- [ ] **Step 5: Verify the passport gate is unchanged (regression)**

Run: `CHIO_BIN="${CHIO_BIN:-target/debug/chio}" bash scripts/check-chio-transaction-passport.sh`
Expected: `OK transaction-passport verifier gate: <N> positive, <M> negative, <K> proof-room` (same as before the extraction; if `target/debug/chio` is absent it will build it first).

- [ ] **Step 6: Write the honest demo runner**

Create `scripts/demo/flagship-wall-stops-money.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
# NON-CLAIMS: this is a verifier-level proof over an OFFLINE projection. It is not a live
# money-stop, holds no funds, and asserts no public availability. Settlement is a verify-only
# x402/AP2/ACP-Commerce projection over an offline PSP (stripe-shaped-offline).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="${1:-$ROOT/fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle}"

# shellcheck source=scripts/lib/chio-proof-trusted-keys.sh
source "$ROOT/scripts/lib/chio-proof-trusted-keys.sh"

if [[ -n "${CHIO_BIN:-}" ]]; then
  [[ -x "$CHIO_BIN" ]] || { echo "CHIO_BIN is not executable: $CHIO_BIN" >&2; exit 2; }
elif [[ -x "$ROOT/target/debug/chio" ]]; then
  CHIO_BIN="$ROOT/target/debug/chio"
else
  ( cd "$ROOT" && cargo build -p chio-cli --bin chio )
  CHIO_BIN="$ROOT/target/debug/chio"
fi

echo "== Chio flagship: the wall stops money (offline verifier proof) =="
"$CHIO_BIN" proof verify "$BUNDLE" \
  --require denials --require commerce --require settlement --require risk --require trust-market

echo
echo "-- MANDATE / ALLOWANCE --"
python3 - "$BUNDLE/mandate-allowance-ledger.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
m = d if isinstance(d, dict) and d.get("id") == "mandate-commerce-001" else None
if m is None:
    for cand in (d.get("mandates") or d.get("entries") or []):
        if isinstance(cand, dict) and cand.get("id") == "mandate-commerce-001":
            m = cand; break
if m is None:
    print("mandate-commerce-001 not found"); raise SystemExit(3)
print(f"mandate {m['id']}: max_amount_minor={m['max_amount_minor']} "
      f"max_occurrences={m['max_occurrences']} currency={m.get('currency')}")
PY

echo
echo "-- DENIED (kernel-signed terminal receipt) --"
python3 - "$BUNDLE/commerce-terminal-denial-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"terminal_status={d['terminal_status']} kernel_key={d['kernel_key'][:12]}...")
PY
echo "over-budget/over-limit corpus the verifier REJECTS (separate negative fixtures):"
echo "  commerce-payment-before-budget, commerce-mandate-occurrence-limit,"
echo "  commerce-expired-mandate, commerce-payment-amount-mismatch"

echo
echo "-- ALLOWED (kernel-signed terminal receipt) --"
python3 - "$BUNDLE/commerce-terminal-allow-receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"terminal_status={d['terminal_status']} kernel_key={d['kernel_key'][:12]}...")
PY
echo "in-budget attempt authorized via x402/AP2/ACP-Commerce verify-only protocol_projections"

echo
echo "-- SETTLED (offline projection) --"
python3 - "$BUNDLE/settlement-packet.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"schema={d.get('schema')} status={d.get('status')}")
PY

echo
echo "== NON-CLAIMS: offline verifier proof; no live money-stop, no fund custody, no availability claim. =="
```

Narration is independent: the DENIED and ALLOWED receipts are described as two independent kernel-signed terminal receipts plus a separate rejected negative corpus. The script never claims they are two occurrences of one mandate.

- [ ] **Step 7: Make scripts executable and run the test**

Run: `chmod +x scripts/demo/flagship-wall-stops-money.sh scripts/tests/flagship-wall-stops-money.test.sh scripts/lib/chio-proof-trusted-keys.sh && bash scripts/tests/flagship-wall-stops-money.test.sh`
Expected: `OK flagship-wall-stops-money.test.sh`

- [ ] **Step 8: Commit**

```bash
git add scripts/lib/chio-proof-trusted-keys.sh scripts/check-chio-transaction-passport.sh scripts/demo/flagship-wall-stops-money.sh scripts/tests/flagship-wall-stops-money.test.sh
git commit -m "feat(demo): honest flagship wall-stops-money runner over signed bundle

Extract the deterministic trusted-key block into a shared lib sourced by both
the passport gate and the new one-command narrated runner. Narration is
independent per the artifacts (receipts carry no mandate/amount link).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Flagship walkthrough doc + wire demo gates into the release lane

**Files:**
- Create: `docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md`
- Modify: `scripts/qualify-release.sh:31` (insert new gates after the last existing gate, before the `output_root=` assignment)

**Interfaces:**
- Consumes: `scripts/demo/flagship-wall-stops-money.sh`, `scripts/check-chio-transaction-passport.sh`, `cargo xtask verify launch-acceptance`, `scripts/tests/check-chio-proof-room-launch-acceptance.test.sh`, `scripts/tests/flagship-wall-stops-money.test.sh` (all from Task 1 + existing).
- Produces: `scripts/qualify-release.sh` now references `check-chio-transaction-passport` and `launch-acceptance` (closes the lane-wiring gap: today `qualify-release.sh` references neither).

- [ ] **Step 1: Write the failing lane-wiring assertion**

Run this grep before editing (it must currently fail):
Run: `grep -Eq "check-chio-transaction-passport|launch-acceptance" scripts/qualify-release.sh && echo PRESENT || echo ABSENT`
Expected: `ABSENT` (proves the gap is real; this is the failing pre-condition).

- [ ] **Step 2: Write the flagship walkthrough doc**

Create `docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md`:

```markdown
# Flagship: the wall stops money (offline verifier proof)

One command walks the whole arc over the signed, deterministic Proof Room bundle:

    bash scripts/demo/flagship-wall-stops-money.sh

It runs `chio proof verify <bundle> --require denials --require commerce --require
settlement --require risk --require trust-market` and then narrates:

1. MANDATE / ALLOWANCE - mandate-commerce-001 (max_amount_minor, max_occurrences).
2. DENIED - a kernel-signed terminal receipt (terminal_status `denied_guard_request`),
   alongside the negative catalog (commerce-payment-before-budget,
   commerce-mandate-occurrence-limit, commerce-expired-mandate,
   commerce-payment-amount-mismatch) that the verifier REJECTS.
3. ALLOWED - a kernel-signed terminal receipt (terminal_status `allowed_executed`),
   authorized via the x402/AP2/ACP-Commerce verify-only protocol projections.
4. SETTLED - the offline settlement-packet (status `settled`).

## Honesty boundary (non-claims)

This is a verifier-level proof over an OFFLINE projection. The DENIED and ALLOWED
receipts are two independent kernel-signed terminal receipts; they carry no amount
and no mandate reference, so this walkthrough does NOT claim they are two occurrences
of one mandate. Settlement is a verify-only x402/AP2/ACP-Commerce projection over an offline
PSP (stripe-shaped-offline). No funds are held, no live money-stop is claimed, and no
public availability is asserted. See docs/start-here/PROOF_ROOM_QUICKSTART.md.
```

- [ ] **Step 3: Wire the demo gates into `qualify-release.sh`**

In `scripts/qualify-release.sh`, immediately after line 31 (`./scripts/check-chio-go-release.sh`) and before the `output_root=` assignment (line 33), insert:

```bash
# Flagship demo + launch-acceptance regression assets (lane wiring).
cargo build -p chio-cli --bin chio
CHIO_BIN="$(pwd)/target/debug/chio" bash ./scripts/check-chio-transaction-passport.sh
CHIO_BIN="$(pwd)/target/debug/chio" cargo xtask verify launch-acceptance --out target/proof-room/public-bundle
bash ./scripts/tests/check-chio-proof-room-launch-acceptance.test.sh
CHIO_BIN="$(pwd)/target/debug/chio" bash ./scripts/tests/flagship-wall-stops-money.test.sh
```

- [ ] **Step 4: Verify the lane wiring assertion now passes**

Run: `grep -Eq "check-chio-transaction-passport" scripts/qualify-release.sh && grep -Eq "launch-acceptance" scripts/qualify-release.sh && echo PRESENT`
Expected: `PRESENT`

- [ ] **Step 5: Syntax-check the edited script**

Run: `bash -n scripts/qualify-release.sh && echo "syntax ok"`
Expected: `syntax ok`

- [ ] **Step 6: Commit**

```bash
git add docs/start-here/FLAGSHIP_WALL_STOPS_MONEY.md scripts/qualify-release.sh
git commit -m "docs(demo): flagship walkthrough + wire demo gates into release lane

Add FLAGSHIP_WALL_STOPS_MONEY.md inside the non-claims discipline and make the
passport gate, launch-acceptance, and the demo test release-lane regressions.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `ComptrollerSurfaceReport` projection type + re-anchored `validate_consistency`

**Files:**
- Create: `crates/kernel/chio-kernel/src/operator_report/comptroller_surface.rs`
- Modify: `crates/kernel/chio-kernel/src/operator_report/mod.rs`
- Modify: `crates/kernel/chio-kernel/src/operator_report/queries.rs` (add `Default` to `OperatorReportQuery` derive)
- Modify: `crates/kernel/chio-kernel/src/operator_report/settlement_report.rs:12` and `crates/kernel/chio-kernel/src/operator_report/budget_report.rs` (add `Default` to the two `*Summary` derives)
- Modify: `crates/core/chio-core-types/src/signed_artifact.rs` (add the schema const only; the `SIGNED_ARTIFACT_SCHEMA_SPECS` registration entry is added in Task 6)
- Test: `crates/kernel/chio-kernel/src/operator_report/comptroller_surface.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `chio_credit::{ExposureLedgerCurrencyPosition, ExposureLedgerReport}`; `super::{OperatorReport, OperatorReportQuery, SettlementReconciliationSummary, BudgetUtilizationSummary}`; `chio_core_types::CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA`.
- Produces (exact signatures):
  - `pub const COMPTROLLER_SURFACE_REPORT_SCHEMA: &str` (re-export of the core-types const, single source of truth)
  - `pub struct ComptrollerSurfaceReport { schema, generated_at, filters, exposure_positions, decision_summary, settlement_reconciliation, budget_utilization, source_refs, execution_nonce_ref, hold_ref }`
  - `pub struct ComptrollerDecisionSummary { allow_count, deny_count, cancelled_count, incomplete_count }`
  - `pub struct ComptrollerSurfaceSourceRefs { operator_report_ref, exposure_ledger_ref, risk_comptroller_report_ref }`
  - `impl ComptrollerSurfaceReport { pub fn from_parts(operator: &OperatorReport, exposure: &ExposureLedgerReport) -> Self; pub fn validate_consistency(&self) -> Result<(), String>; }`

**Adversarial fix folded in (M2 re-anchored invariant):** `governed_max_exposure_units` does NOT exist on `BudgetUtilizationReport`; it DOES exist as a `u64` on `chio_credit::ExposureLedgerCurrencyPosition` (verified: lib.rs:248). The invariant is therefore SINGLE-DOMAIN (credit exposure only): within each position, outstanding holds (`reserved_units + pending_units`) must not exceed `governed_max_exposure_units`, with a ceiling of `0` treated as "no governed ceiling" (fail-safe, skipped - not fail-closed). No cross-domain compare against kernel budget cost units (undefined unit mapping).

**A-linkage fix folded in:** `execution_nonce_ref` and `hold_ref` are `Option<String>`, `None` in v1 (reserved for the Phase-2 Direction A hold/nonce), each with `#[serde(default, skip_serializing_if = "Option::is_none")]` so they are omitted from serialized output until A lands.

- [ ] **Step 1: Add the schema-id const to core-types (single source of truth)**

In `crates/core/chio-core-types/src/signed_artifact.rs`, next to the existing `CHIO_ENTERPRISE_*` / `CHIO_RISK_*` consts (around line 88-99), add:

```rust
/// Schema id for the unified spend/exposure comptroller surface projection.
pub const CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA: &str = "chio.comptroller.surface-report.v1";
```

- [ ] **Step 2: Write the failing unit test**

Create `crates/kernel/chio-kernel/src/operator_report/comptroller_surface.rs` with only the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chio_credit::ExposureLedgerCurrencyPosition;

    fn position(currency: &str, governed: u64, reserved: u64, pending: u64) -> ExposureLedgerCurrencyPosition {
        ExposureLedgerCurrencyPosition {
            currency: currency.to_string(),
            governed_max_exposure_units: governed,
            reserved_units: reserved,
            settled_units: 0,
            pending_units: pending,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        }
    }

    fn sample() -> ComptrollerSurfaceReport {
        ComptrollerSurfaceReport {
            schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_000,
            filters: OperatorReportQuery::default(),
            exposure_positions: vec![position("USD", 4200, 1000, 200)],
            decision_summary: ComptrollerDecisionSummary { allow_count: 1, deny_count: 1, cancelled_count: 0, incomplete_count: 0 },
            settlement_reconciliation: SettlementReconciliationSummary::default(),
            budget_utilization: BudgetUtilizationSummary::default(),
            source_refs: ComptrollerSurfaceSourceRefs::default(),
            execution_nonce_ref: None,
            hold_ref: None,
        }
    }

    #[test]
    fn serde_round_trip_is_camel_case() {
        let report = sample();
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"schema\":\"chio.comptroller.surface-report.v1\""));
        assert!(json.contains("\"generatedAt\""));
        assert!(json.contains("\"exposurePositions\""));
        assert!(json.contains("\"governedMaxExposureUnits\""));
        assert!(json.contains("\"allowCount\""));
        // Reserved A-linkage slots are omitted until Phase 2.
        assert!(!json.contains("executionNonceRef"));
        assert!(!json.contains("holdRef"));
        let back: ComptrollerSurfaceReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back);
    }

    #[test]
    fn validate_consistency_accepts_coherent_positions() {
        assert!(sample().validate_consistency().is_ok());
    }

    #[test]
    fn validate_consistency_rejects_outstanding_over_governed_ceiling() {
        let mut report = sample();
        report.exposure_positions = vec![position("USD", 4200, 5000, 0)];
        let err = report.validate_consistency().expect_err("must reject over-ceiling");
        assert!(err.contains("exceed governed ceiling"));
    }

    #[test]
    fn validate_consistency_treats_zero_ceiling_as_no_ceiling() {
        let mut report = sample();
        report.exposure_positions = vec![position("USD", 0, u64::MAX / 2, u64::MAX / 2)];
        assert!(report.validate_consistency().is_ok());
    }
}
```

- [ ] **Step 2b: Run the test to verify it fails**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel --lib comptroller_surface 2>&1 | tail -5`
Expected: FAIL - compile error `cannot find type ComptrollerSurfaceReport in this scope` (type not defined yet).

- [ ] **Step 3: Implement the projection type + `validate_consistency`**

Prepend to `crates/kernel/chio-kernel/src/operator_report/comptroller_surface.rs` (above the test module):

```rust
//! Unified spend/exposure comptroller surface projection.
//!
//! Pure projection over the existing `OperatorReport` (kernel) and
//! `ExposureLedgerReport` (credit) types. This is the single Rust source of
//! truth for the `chio.comptroller.surface-report.v1` schema.

use chio_credit::{ExposureLedgerCurrencyPosition, ExposureLedgerReport};
use chio_core_types::CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA;
use serde::{Deserialize, Serialize};

use super::{BudgetUtilizationSummary, OperatorReport, OperatorReportQuery, SettlementReconciliationSummary};

/// Schema id for the comptroller surface projection (re-exported single source of truth).
pub const COMPTROLLER_SURFACE_REPORT_SCHEMA: &str = CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA;

/// Allow/deny/cancelled/incomplete decision counts projected from the operator activity summary.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComptrollerDecisionSummary {
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
}

/// Optional sha256 hash-refs to the composed source artifacts (enterprise telemetry-projection pattern).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComptrollerSurfaceSourceRefs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_report_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure_ledger_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_comptroller_report_ref: Option<String>,
}

/// Unified spend/exposure contract: a projection over OperatorReport + ExposureLedgerReport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComptrollerSurfaceReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: OperatorReportQuery,
    pub exposure_positions: Vec<ExposureLedgerCurrencyPosition>,
    pub decision_summary: ComptrollerDecisionSummary,
    pub settlement_reconciliation: SettlementReconciliationSummary,
    pub budget_utilization: BudgetUtilizationSummary,
    pub source_refs: ComptrollerSurfaceSourceRefs,
    /// Reserved Direction A linkage; None until Phase 2 (avoids a governance-gated schema v2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce_ref: Option<String>,
    /// Reserved Direction A/C linkage; None until Phase 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_ref: Option<String>,
}

impl ComptrollerSurfaceReport {
    /// Compose the projection from the already-built operator + exposure read models.
    pub fn from_parts(operator: &OperatorReport, exposure: &ExposureLedgerReport) -> Self {
        Self {
            schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
            generated_at: operator.generated_at,
            filters: operator.filters.clone(),
            exposure_positions: exposure.positions.clone(),
            decision_summary: ComptrollerDecisionSummary {
                allow_count: operator.activity.summary.allow_count,
                deny_count: operator.activity.summary.deny_count,
                cancelled_count: operator.activity.summary.cancelled_count,
                incomplete_count: operator.activity.summary.incomplete_count,
            },
            settlement_reconciliation: operator.settlement_reconciliation.summary.clone(),
            budget_utilization: operator.budget_utilization.summary.clone(),
            source_refs: ComptrollerSurfaceSourceRefs::default(),
            execution_nonce_ref: None,
            hold_ref: None,
        }
    }

    /// Fail-closed single-domain invariant over the credit exposure positions.
    ///
    /// Within each currency position, outstanding holds (reserved + pending) must not exceed the
    /// governed exposure ceiling. A ceiling of 0 means "no governed ceiling" and is skipped
    /// (fail-safe). This is a credit-domain-only check; it does NOT cross into kernel budget cost
    /// units, whose unit mapping to exposure units is undefined.
    pub fn validate_consistency(&self) -> Result<(), String> {
        for position in &self.exposure_positions {
            if position.governed_max_exposure_units == 0 {
                continue;
            }
            let outstanding = position.reserved_units.saturating_add(position.pending_units);
            if outstanding > position.governed_max_exposure_units {
                return Err(format!(
                    "exposure position {} outstanding holds {} exceed governed ceiling {}",
                    position.currency, outstanding, position.governed_max_exposure_units
                ));
            }
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Register the module + re-exports**

In `crates/kernel/chio-kernel/src/operator_report/mod.rs`, add `pub mod comptroller_surface;` next to the other `pub mod` declarations, and add a re-export block mirroring the existing ones:

```rust
pub use comptroller_surface::{
    ComptrollerDecisionSummary, ComptrollerSurfaceReport, ComptrollerSurfaceSourceRefs,
    COMPTROLLER_SURFACE_REPORT_SCHEMA,
};
```

Confirm `SettlementReconciliationSummary` and `BudgetUtilizationSummary` are already re-exported from `mod.rs` (they are, via the `settlement_report` and `budget_report` `pub use` blocks).

The sample in Step 2 calls `::default()` on three structs that do NOT currently derive `Default` (verified: `OperatorReportQuery` derives only `Debug, Clone, Serialize, Deserialize, PartialEq, Eq`; `SettlementReconciliationSummary` the same). Add `Default` to each derive so the samples compile:
- `crates/kernel/chio-kernel/src/operator_report/queries.rs`: change `OperatorReportQuery`'s derive to `#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]` (all fields are `Option`, so `Default` is safe).
- `crates/kernel/chio-kernel/src/operator_report/settlement_report.rs:12`: add `Default` to `SettlementReconciliationSummary`'s derive.
- `crates/kernel/chio-kernel/src/operator_report/budget_report.rs`: add `Default` to `BudgetUtilizationSummary`'s derive.

If any of those three structs has a field that is not `Default`-able (compile error), do NOT force `Default`; instead construct that summary explicitly in the test's `sample()` from its public fields (inspect with `sed -n '/pub struct <Name>/,/^}/p'`).

- [ ] **Step 5: Run the test to verify it passes**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel --lib comptroller_surface 2>&1 | tail -8`
Expected: `test result: ok. 4 passed; 0 failed` (the four `comptroller_surface::tests::*`).

- [ ] **Step 6: Scoped clippy on the new module**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel -p chio-core-types -- -D warnings 2>&1 | tail -5`
Expected: no warnings (no `unwrap`/`expect` in `src/`; test-only `.expect` is allowed).

- [ ] **Step 7: Commit**

```bash
git add crates/core/chio-core-types/src/signed_artifact.rs crates/kernel/chio-kernel/src/operator_report/comptroller_surface.rs crates/kernel/chio-kernel/src/operator_report/mod.rs
git commit -m "feat(chio-kernel): add ComptrollerSurfaceReport projection type

Single-domain fail-closed validate_consistency over credit exposure positions
(governed_max_exposure_units, ceiling 0 = no-ceiling). Reserve executionNonceRef
and holdRef linkage slots (None until Direction A Phase 2).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `to_exposure_ledger_query` converter + `build_comptroller_surface_report` builder

**Files:**
- Modify: `crates/kernel/chio-kernel/src/operator_report/queries.rs:64` (add converter next to `to_receipt_analytics_query`)
- Modify: `crates/platform/chio-control-plane/src/trust_control/reports.rs` (add builder next to `build_operator_report` at line 14)
- Test: inline `#[cfg(test)]` in `queries.rs` for the converter

**Interfaces:**
- Consumes: `build_operator_report(receipt_store: &SqliteReceiptStore, budget_store: &SqliteBudgetStore, query: &OperatorReportQuery) -> Result<OperatorReport, Response>`; `build_exposure_ledger_report(receipt_store: &SqliteReceiptStore, query: &ExposureLedgerQuery) -> Result<ExposureLedgerReport, TrustHttpError>`; `ComptrollerSurfaceReport::{from_parts, validate_consistency}`.
- Produces:
  - `impl OperatorReportQuery { pub fn to_exposure_ledger_query(&self) -> chio_credit::ExposureLedgerQuery }`
  - `pub(crate) fn build_comptroller_surface_report(receipt_store: &SqliteReceiptStore, budget_store: &SqliteBudgetStore, query: &OperatorReportQuery) -> Result<ComptrollerSurfaceReport, Response>`

- [ ] **Step 1: Inspect `ExposureLedgerQuery` fields**

Run: `sed -n '/pub struct ExposureLedgerQuery/,/^}/p' crates/economy/chio-credit/src/lib.rs`
Expected: prints the field set (capability/subject/tool filter fields + time bounds). Use the printed field names verbatim in Step 3.

- [ ] **Step 2: Write the failing converter test**

Add to the bottom of `crates/kernel/chio-kernel/src/operator_report/queries.rs`:

```rust
#[cfg(test)]
mod exposure_query_tests {
    use super::*;

    #[test]
    fn to_exposure_ledger_query_threads_shared_filters() {
        let query = OperatorReportQuery {
            agent_subject: Some("subject-hex".to_string()),
            tool_server: Some("shell".to_string()),
            tool_name: Some("bash".to_string()),
            since: Some(10),
            until: Some(99),
            ..OperatorReportQuery::default()
        };
        let exposure = query.to_exposure_ledger_query();
        assert_eq!(exposure.agent_subject.as_deref(), Some("subject-hex"));
        assert_eq!(exposure.tool_server.as_deref(), Some("shell"));
    }
}
```

(Adjust the asserted field names to the real `ExposureLedgerQuery` field names printed in Step 1 - keep the shared filter fields that exist on both.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel --lib to_exposure_ledger_query 2>&1 | tail -5`
Expected: FAIL - `no method named to_exposure_ledger_query`.

- [ ] **Step 4: Implement the converter**

In `crates/kernel/chio-kernel/src/operator_report/queries.rs`, inside `impl OperatorReportQuery`, next to `to_cost_attribution_query` (line 79), add (mapping only the fields that exist on `ExposureLedgerQuery`, per Step 1):

```rust
/// Project the shared operator filters into an exposure-ledger query.
///
/// ExposureLedgerQuery has exactly eight fields (verified: chio-credit lib.rs:116);
/// construct all of them explicitly so this does not depend on a Default impl.
pub fn to_exposure_ledger_query(&self) -> chio_credit::ExposureLedgerQuery {
    chio_credit::ExposureLedgerQuery {
        capability_id: self.capability_id.clone(),
        agent_subject: self.agent_subject.clone(),
        tool_server: self.tool_server.clone(),
        tool_name: self.tool_name.clone(),
        since: self.since,
        until: self.until,
        receipt_limit: None,
        decision_limit: None,
    }
}
```

- [ ] **Step 5: Run the converter test to verify it passes**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel --lib to_exposure_ledger_query 2>&1 | tail -5`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 6: Implement the fail-closed builder**

In `crates/platform/chio-control-plane/src/trust_control/reports.rs`, immediately after `build_operator_report` (ends before line 233), add:

```rust
/// Compose the unified comptroller surface projection from the operator + exposure read models.
/// Fail-closed: exposure-builder errors and consistency-validation failures map to 5xx, never 200.
pub(crate) fn build_comptroller_surface_report(
    receipt_store: &SqliteReceiptStore,
    budget_store: &SqliteBudgetStore,
    query: &OperatorReportQuery,
) -> Result<ComptrollerSurfaceReport, Response> {
    let operator = build_operator_report(receipt_store, budget_store, query)?;
    let exposure = build_exposure_ledger_report(receipt_store, &query.to_exposure_ledger_query())
        .map_err(|error| error.into_response())?;
    let report = ComptrollerSurfaceReport::from_parts(&operator, &exposure);
    report.validate_consistency().map_err(|message| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("comptroller surface consistency check failed: {message}"),
        )
            .into_response()
    })?;
    Ok(report)
}
```

Add `use chio_kernel::operator_report::ComptrollerSurfaceReport;` (or the crate's existing `chio_kernel::...` import path for operator-report types) to the file's imports. Confirm `TrustHttpError` implements `into_response()` (it is used by neighboring builders); if the return type differs, mirror the exact error mapping `build_signed_exposure_ledger_report` uses.

- [ ] **Step 7: Scoped compile check**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo build -p chio-control-plane 2>&1 | tail -5`
Expected: builds clean (`Finished`).

- [ ] **Step 8: Commit**

```bash
git add crates/kernel/chio-kernel/src/operator_report/queries.rs crates/platform/chio-control-plane/src/trust_control/reports.rs
git commit -m "feat(chio-control-plane): build_comptroller_surface_report (fail-closed compose)

Compose OperatorReport + ExposureLedgerReport into the surface projection; map
exposure-build and consistency failures to 5xx. Add to_exposure_ledger_query.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `GET /v1/reports/comptroller-surface` endpoint + client op + endpoint test

**Files:**
- Modify: `crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs:123` (add const near `OPERATOR_REPORT_PATH`)
- Modify: `crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs:410` (add handler near `handle_operator_report`)
- Modify: `crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs:303` (register route)
- Modify: `crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs:544` (add client op near `operator_report`)
- Test: `crates/products/chio-cli/tests/receipt_query_export.rs` (add `test_comptroller_surface_report_endpoint`)

**Interfaces:**
- Consumes: `build_comptroller_surface_report` (Task 4); `handle_operator_report(...)` (receipt_handlers.rs:410) as the mirror; `self.get_json_with_query(...)` (operations.rs pattern).
- Produces:
  - `pub(crate) const COMPTROLLER_SURFACE_REPORT_PATH: &str = "/v1/reports/comptroller-surface";`
  - `pub(crate) async fn handle_comptroller_surface_report(...)` (same extractors/signature as `handle_operator_report`)
  - route `.route(COMPTROLLER_SURFACE_REPORT_PATH, get(handle_comptroller_surface_report))`
  - `pub fn comptroller_surface(&self, query: &OperatorReportQuery) -> Result<ComptrollerSurfaceReport, CliError>`

**Adversarial fix folded in (M5 correct test binary):** the endpoint test goes in `receipt_query_export.rs` (the binary that actually contains `test_operator_report_endpoint`), NOT the `receipt_query.rs` 3-test stub. Invocation targets `--test receipt_query_export`.

- [ ] **Step 1: Write the failing endpoint test**

Read `crates/products/chio-cli/tests/receipt_query_export.rs` lines 62-328 (`test_operator_report_endpoint`) as the exact template. Append a new test that reuses the same setup (same imports, `spawn_trust_service`, `SqliteBudgetStore`, seeded root/child capability + allow + deny receipts) and hits the new path:

```rust
#[test]
fn test_comptroller_surface_report_endpoint() {
    skip_when_loopback_denied!(test_comptroller_surface_report_endpoint);
    // ... identical seed block to test_operator_report_endpoint (dirs, keypairs, scope,
    // root/child capability, rc-op-1 Allow + rc-op-2 Deny receipts, checkpoint, budget usage) ...

    let listen = reserve_listen_addr();
    let service_token = "comptroller-surface-token";
    let _service = spawn_trust_service(
        listen, service_token, &receipt_db_path, &revocation_db_path, &authority_db_path, &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/comptroller-surface"))
        .query(&[("agentSubject", leaf_hex.as_str()), ("toolServer", "shell"), ("toolName", "bash")])
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {service_token}"))
        .send()
        .expect("send comptroller surface request");

    assert_eq!(response.status(), reqwest::StatusCode::OK, "expected 200 for comptroller surface");
    let body: serde_json::Value = response.json().expect("parse comptroller surface json");

    assert_eq!(body["schema"].as_str(), Some("chio.comptroller.surface-report.v1"));
    assert_eq!(body["decisionSummary"]["allowCount"].as_u64(), Some(1));
    assert_eq!(body["decisionSummary"]["denyCount"].as_u64(), Some(1));
    assert!(body["exposurePositions"].is_array(), "exposurePositions present");
    // Reserved A-linkage slots are omitted until Phase 2.
    assert!(body.get("executionNonceRef").is_none());
    assert!(body.get("holdRef").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-cli --test receipt_query_export test_comptroller_surface_report_endpoint -- --exact 2>&1 | tail -8`
Expected: FAIL - either a 404 (`expected 200 for comptroller surface`) if it compiles against the running server, or a compile error if the test references `ComptrollerSurfaceReport` before wiring. Confirm the failure is a real assertion/compile failure and NOT `0 filtered out; 0 passed` (which would be a false green from targeting the wrong binary).

- [ ] **Step 3: Add the path const**

In `crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs`, after line 123 (`OPERATOR_REPORT_PATH`), add:

```rust
pub(crate) const COMPTROLLER_SURFACE_REPORT_PATH: &str = "/v1/reports/comptroller-surface";
```

- [ ] **Step 4: Add the handler**

Read `crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs:410` (`handle_operator_report`) in full. Immediately after it, add `handle_comptroller_surface_report` with the identical extractor signature (same `State`, `Query<OperatorReportQuery>`, auth guard), differing only in the body build call:

```rust
pub(crate) async fn handle_comptroller_surface_report(
    // ... exact same extractor arguments as handle_operator_report ...
) -> Response {
    // ... exact same auth-guard + store-lock prelude as handle_operator_report ...
    match build_comptroller_surface_report(&receipt_store, &budget_store, &query) {
        Ok(report) => Json(report).into_response(),
        Err(response) => response,
    }
}
```

Import `build_comptroller_surface_report` from the `reports` module alongside the existing `build_operator_report` import.

- [ ] **Step 5: Register the route**

In `crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs`, next to line 303 (`.route(OPERATOR_REPORT_PATH, get(handle_operator_report))`), add:

```rust
        .route(COMPTROLLER_SURFACE_REPORT_PATH, get(handle_comptroller_surface_report))
```

Add `COMPTROLLER_SURFACE_REPORT_PATH` and `handle_comptroller_surface_report` to the existing `use` imports at the top of `router.rs`.

- [ ] **Step 6: Add the client op**

In `crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs`, next to `operator_report` (line 544), add:

```rust
    pub fn comptroller_surface(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<ComptrollerSurfaceReport, CliError> {
        self.get_json_with_query(COMPTROLLER_SURFACE_REPORT_PATH, query)
    }
```

Add `ComptrollerSurfaceReport` and `COMPTROLLER_SURFACE_REPORT_PATH` to the file's imports.

- [ ] **Step 7: Run the endpoint test to verify it passes (with nonzero-count guard)**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-cli --test receipt_query_export test_comptroller_surface_report_endpoint -- --exact 2>&1 | tee /tmp/cs.out | tail -6; grep -Eq "1 passed" /tmp/cs.out && ! grep -Eq "0 passed" /tmp/cs.out && echo "GUARD OK: nonzero tests ran"`
Expected: `test result: ok. 1 passed; 0 failed` followed by `GUARD OK: nonzero tests ran` (proves the test actually executed, not a 0-match false green).

- [ ] **Step 8: Commit**

```bash
git add crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs crates/products/chio-cli/tests/receipt_query_export.rs
git commit -m "feat(chio-control-plane): GET /v1/reports/comptroller-surface endpoint

Add the surface-report handler, route, and client op; endpoint test lives in the
receipt_query_export binary (not the receipt_query stub) and guards nonzero runs.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Published JSON Schema + full signed-artifact registration + fail-closed gate

**Files:**
- Create: `spec/schemas/chio-comptroller/v1/surface-report.schema.json`
- Modify: `crates/core/chio-core-types/src/signed_artifact.rs` (add the `SIGNED_ARTIFACT_SCHEMA_SPECS` entry)
- Modify: `spec/schemas/registry.json`
- Modify: `spec/schemas/MANIFEST.sha256` (deterministic regeneration)
- Modify: `scripts/check-chio-schema-registry.sh:111-131` (add checked root)
- Modify: `spec/schemas/COVERAGE.md`
- Test: `scripts/check-chio-schema-registry.sh` + `crates/core/chio-core-types/tests/signed_artifact_schema.rs` (existing mirror test)

**Interfaces:**
- Consumes: the camelCase serde output of `ComptrollerSurfaceReport` (Task 3) as the schema's exact property set.
- Produces: `spec/schemas/chio-comptroller/v1/surface-report.schema.json` (draft-2020-12, `additionalProperties:false`, `schema` const `chio.comptroller.surface-report.v1`); a registry.json artifact entry; the schema id in BOTH `KNOWN_SIGNED_ARTIFACT_SCHEMAS` and `built_in_signed_artifact_registry()`.

**Adversarial fix folded in (M3 full registration):** the exposure-ledger "intentional exemption" precedent is FALSE (exposure-ledger has no schema file and is unregistered, so it never enters the checked-roots -> registry -> KNOWN chain). For a signed, externally-pinned contract, register into ALL of: `KNOWN_SIGNED_ARTIFACT_SCHEMAS` + `built_in_signed_artifact_registry()` (both via one `SIGNED_ARTIFACT_SCHEMA_SPECS` entry) + `registry.json` + `MANIFEST.sha256` + `checked_chio_schema_roots`. Omitting any one makes the fail-closed verifier REJECT a `SignedComptrollerSurfaceReport` while tests stay green (the mirror test only enforces KNOWN subset-of registry-union-exemption, one direction).

- [ ] **Step 1: Author the schema (property names = camelCase serde output)**

Create `spec/schemas/chio-comptroller/v1/surface-report.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://chio.world/schemas/chio-comptroller/v1/surface-report.schema.json",
  "title": "Chio Comptroller Surface Report",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema",
    "generatedAt",
    "filters",
    "exposurePositions",
    "decisionSummary",
    "settlementReconciliation",
    "budgetUtilization",
    "sourceRefs"
  ],
  "properties": {
    "schema": { "const": "chio.comptroller.surface-report.v1" },
    "generatedAt": { "type": "integer", "minimum": 0 },
    "filters": { "type": "object" },
    "exposurePositions": {
      "type": "array",
      "items": { "$ref": "#/$defs/exposurePosition" }
    },
    "decisionSummary": { "$ref": "#/$defs/decisionSummary" },
    "settlementReconciliation": { "type": "object" },
    "budgetUtilization": { "type": "object" },
    "sourceRefs": { "$ref": "#/$defs/sourceRefs" },
    "executionNonceRef": { "type": ["string", "null"], "minLength": 1 },
    "holdRef": { "type": ["string", "null"], "minLength": 1 }
  },
  "$defs": {
    "exposurePosition": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "currency",
        "governedMaxExposureUnits",
        "reservedUnits",
        "settledUnits",
        "pendingUnits",
        "failedUnits",
        "provisionalLossUnits",
        "recoveredUnits",
        "quotedPremiumUnits",
        "activeQuotedPremiumUnits"
      ],
      "properties": {
        "currency": { "type": "string", "minLength": 1 },
        "governedMaxExposureUnits": { "type": "integer", "minimum": 0 },
        "reservedUnits": { "type": "integer", "minimum": 0 },
        "settledUnits": { "type": "integer", "minimum": 0 },
        "pendingUnits": { "type": "integer", "minimum": 0 },
        "failedUnits": { "type": "integer", "minimum": 0 },
        "provisionalLossUnits": { "type": "integer", "minimum": 0 },
        "recoveredUnits": { "type": "integer", "minimum": 0 },
        "quotedPremiumUnits": { "type": "integer", "minimum": 0 },
        "activeQuotedPremiumUnits": { "type": "integer", "minimum": 0 }
      }
    },
    "decisionSummary": {
      "type": "object",
      "additionalProperties": false,
      "required": ["allowCount", "denyCount", "cancelledCount", "incompleteCount"],
      "properties": {
        "allowCount": { "type": "integer", "minimum": 0 },
        "denyCount": { "type": "integer", "minimum": 0 },
        "cancelledCount": { "type": "integer", "minimum": 0 },
        "incompleteCount": { "type": "integer", "minimum": 0 }
      }
    },
    "sourceRefs": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "operatorReportRef": { "type": "string", "minLength": 1 },
        "exposureLedgerRef": { "type": "string", "minLength": 1 },
        "riskComptrollerReportRef": { "type": "string", "minLength": 1 }
      }
    }
  }
}
```

Note: `settlementReconciliation`/`budgetUtilization`/`filters` are modeled as permissive `{"type":"object"}` in v1 (they carry the existing kernel summary subtypes; strict field-level modeling of those summaries is deferred). Strictness (`additionalProperties:false`) is enforced where it is the load-bearing proof: exposure positions and decision summary.

- [ ] **Step 2: Add the checked schema root**

In `scripts/check-chio-schema-registry.sh`, inside the `checked_chio_schema_roots` tuple (lines 111-131), add the entry in sorted position (between `chio-commerce/` and `chio-crypto/`):

```
    "spec/schemas/chio-comptroller/",
```

- [ ] **Step 3: Add the registry.json artifact entry**

In `spec/schemas/registry.json`, add to the `artifacts` array (keep the array's existing formatting; a trailing entry is fine, the check does not require sorting of registry entries):

```json
    {
      "schema": "chio.comptroller.surface-report.v1",
      "artifactKind": "chio_comptroller_surface_report",
      "introducedBy": "chio-comptroller-surface/v1",
      "schemaFile": "spec/schemas/chio-comptroller/v1/surface-report.schema.json"
    }
```

- [ ] **Step 4: Register in `SIGNED_ARTIFACT_SCHEMA_SPECS`**

In `crates/core/chio-core-types/src/signed_artifact.rs`, add an entry to the `SIGNED_ARTIFACT_SCHEMA_SPECS` array (using the const added in Task 3 Step 1), mirroring the `CHIO_ENTERPRISE_TELEMETRY_PROJECTION_V1_SCHEMA` entry:

```rust
    (
        CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA,
        Some(("chio_comptroller_surface_report", "chio-comptroller-surface/v1")),
    ),
```

This single entry places the id in BOTH `KNOWN_SIGNED_ARTIFACT_SCHEMAS` (via `KNOWN_SIGNED_ARTIFACT_SCHEMA_LIST`) and `built_in_signed_artifact_registry()` (the `.filter_map` keeps `Some(...)` entries).

- [ ] **Step 5: Stage the new/edited schema files, then regenerate the manifest deterministically**

Stage first (the manifest inventory is `git ls-files`-based, so the new schema must be tracked):

```bash
git add spec/schemas/chio-comptroller/v1/surface-report.schema.json spec/schemas/registry.json
```

Regenerate `spec/schemas/MANIFEST.sha256` with the exact algorithm the verifier uses (git-tracked schema inventory, sorted, per-file sha256, self-hash excludes the manifest line):

```bash
python3 - <<'PY'
import hashlib, pathlib, subprocess
root = pathlib.Path(".").resolve()
manifest_rel = "spec/schemas/MANIFEST.sha256"
registry_rel = "spec/schemas/registry.json"
tracked = subprocess.run(["git", "ls-files", "-z", "--", "spec/schemas"],
                         check=True, stdout=subprocess.PIPE).stdout.decode("utf-8").split("\0")
paths = sorted(p for p in tracked
               if p.endswith(".schema.json") or p in {manifest_rel, registry_rel, "spec/schemas/VERSION"})
lines_wo_self = [f"{hashlib.sha256((root / p).read_bytes()).hexdigest()}  {p}\n"
                 for p in paths if p != manifest_rel]
self_hash = hashlib.sha256("".join(lines_wo_self).encode("utf-8")).hexdigest()
content = "".join(
    (f"{self_hash}  {manifest_rel}\n" if p == manifest_rel
     else f"{hashlib.sha256((root / p).read_bytes()).hexdigest()}  {p}\n")
    for p in paths)
(root / manifest_rel).write_text(content, encoding="utf-8")
print("regenerated", manifest_rel)
PY
```

- [ ] **Step 6: Run the schema-registry gate (the "test" for this task)**

Run: `bash scripts/check-chio-schema-registry.sh && bash scripts/tests/check-chio-schema-registry.test.sh`
Expected: `OK Chio schema registry metadata` (and the `.test.sh` passes). If it reports `... is not registered in registry.json` or `... absent from MANIFEST.sha256`, fix the missing entry and re-run Step 5.

- [ ] **Step 7: Run the signed-artifact mirror test**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-core-types --test signed_artifact_schema 2>&1 | tail -6`
Expected: `test result: ok` (the `known_signed_artifact_schemas_match_public_registry_or_internal_exemption` test still passes, because the new id is now in `registry.json`).

- [ ] **Step 8: Update COVERAGE.md (documentation accuracy, not gated)**

In `spec/schemas/COVERAGE.md`, add a row noting the new `chio-comptroller/v1` family (1 file: `surface-report.schema.json`, the unified spend/exposure contract). Match the existing table format.

- [ ] **Step 9: Commit**

```bash
git add spec/schemas/chio-comptroller/v1/surface-report.schema.json spec/schemas/registry.json spec/schemas/MANIFEST.sha256 spec/schemas/COVERAGE.md scripts/check-chio-schema-registry.sh crates/core/chio-core-types/src/signed_artifact.rs
git commit -m "feat(spec): publish + fully register chio.comptroller.surface-report.v1

Register the signed contract in KNOWN_SIGNED_ARTIFACT_SCHEMAS, built_in registry,
registry.json, MANIFEST.sha256, and checked_chio_schema_roots so the fail-closed
verifier accepts it. No false exposure-ledger exemption.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Rust round-trip schema conformance test (positive + negatives)

**Files:**
- Create: `crates/kernel/chio-kernel/tests/comptroller_surface_schema.rs`
- Modify: `crates/kernel/chio-kernel/Cargo.toml` (add `jsonschema` + `serde_json` as `[dev-dependencies]` if absent)

**Interfaces:**
- Consumes: `chio_kernel::operator_report::ComptrollerSurfaceReport` (Task 3); `spec/schemas/chio-comptroller/v1/surface-report.schema.json` (Task 6, loaded via `include_str!`).
- Produces: a conformance test asserting a serialized sample validates, and that extra-field / missing-required / wrong-const negatives are all rejected (anti-drift guarantee between the Rust type and the published schema).

- [ ] **Step 1: Confirm the jsonschema harness API used in-repo**

Run: `sed -n '1,40p' crates/core/chio-core-types/tests/wire_protocol_schema.rs | grep -n "jsonschema\|validator_for\|is_valid\|Validator"`
Expected: prints the exact `jsonschema` calls (e.g. `jsonschema::validator_for(&schema)` returning a validator with `.is_valid(&instance)`). Use whatever API that file uses verbatim in Step 3.

- [ ] **Step 2: Write the failing conformance test**

Create `crates/kernel/chio-kernel/tests/comptroller_surface_schema.rs`:

```rust
use chio_credit::ExposureLedgerCurrencyPosition;
use chio_kernel::operator_report::{
    ComptrollerDecisionSummary, ComptrollerSurfaceReport, ComptrollerSurfaceSourceRefs,
    COMPTROLLER_SURFACE_REPORT_SCHEMA,
};

const SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-comptroller/v1/surface-report.schema.json"
));

fn sample() -> ComptrollerSurfaceReport {
    ComptrollerSurfaceReport {
        schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
        generated_at: 1_700_000_000,
        filters: chio_kernel::operator_report::OperatorReportQuery::default(),
        exposure_positions: vec![ExposureLedgerCurrencyPosition {
            currency: "USD".to_string(),
            governed_max_exposure_units: 4200,
            reserved_units: 1000,
            settled_units: 200,
            pending_units: 100,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        }],
        decision_summary: ComptrollerDecisionSummary {
            allow_count: 1,
            deny_count: 1,
            cancelled_count: 0,
            incomplete_count: 0,
        },
        settlement_reconciliation: Default::default(),
        budget_utilization: Default::default(),
        source_refs: ComptrollerSurfaceSourceRefs::default(),
        execution_nonce_ref: None,
        hold_ref: None,
    }
}

fn schema_value() -> serde_json::Value {
    serde_json::from_str(SCHEMA_JSON).expect("schema parses")
}

#[test]
fn positive_sample_validates_against_published_schema() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let instance = serde_json::to_value(sample()).expect("serialize sample");
    assert!(validator.is_valid(&instance), "serialized sample must satisfy the published schema");
}

#[test]
fn extra_top_level_field_is_rejected() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let mut instance = serde_json::to_value(sample()).expect("serialize sample");
    instance["unexpectedField"] = serde_json::json!("nope");
    assert!(!validator.is_valid(&instance), "additionalProperties:false must reject extra fields");
}

#[test]
fn missing_required_field_is_rejected() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let mut instance = serde_json::to_value(sample()).expect("serialize sample");
    instance.as_object_mut().expect("object").remove("exposurePositions");
    assert!(!validator.is_valid(&instance), "missing required field must be rejected");
}

#[test]
fn wrong_schema_const_is_rejected() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let mut instance = serde_json::to_value(sample()).expect("serialize sample");
    instance["schema"] = serde_json::json!("chio.comptroller.surface-report.v2");
    assert!(!validator.is_valid(&instance), "wrong schema const must be rejected");
}
```

(Adjust `jsonschema::validator_for` / `is_valid` to the exact API confirmed in Step 1. Adjust the `include_str!` relative depth so it resolves from `crates/kernel/chio-kernel/` to repo-root `spec/schemas/...` - verify with the path printed by `ls` in Step 4.)

- [ ] **Step 3: Add dev-dependencies if missing**

Run: `grep -q '^jsonschema' crates/kernel/chio-kernel/Cargo.toml || echo MISSING`
If `MISSING`, add under `[dev-dependencies]` in `crates/kernel/chio-kernel/Cargo.toml`:

```toml
jsonschema = { version = "0.46.0", default-features = false }
serde_json = { workspace = true }
```

(Match the workspace's existing `serde_json` dependency form.)

- [ ] **Step 4: Verify the include path resolves**

Run: `ls crates/kernel/chio-kernel/../../../spec/schemas/chio-comptroller/v1/surface-report.schema.json`
Expected: the path lists (confirms the `include_str!` relative depth is correct).

- [ ] **Step 5: Run the conformance test**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel --test comptroller_surface_schema 2>&1 | tail -8`
Expected: `test result: ok. 4 passed; 0 failed`.

- [ ] **Step 6: Commit**

```bash
git add crates/kernel/chio-kernel/tests/comptroller_surface_schema.rs crates/kernel/chio-kernel/Cargo.toml
git commit -m "test(chio-kernel): round-trip conformance vs published surface schema

Positive sample validates; extra-field, missing-required, and wrong-const
negatives are all rejected (anti-drift between Rust type and JSON Schema).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: TypeScript codegen + dashboard consumption + no-drift gate

**Files:**
- Modify: `crates/products/chio-cli/dashboard/package.json`
- Create: `crates/products/chio-cli/dashboard/scripts/gen-contracts.mjs`
- Create (generated): `crates/products/chio-cli/dashboard/src/generated/comptroller-surface.ts`
- Modify: `crates/products/chio-cli/dashboard/src/types.ts`
- Create: `scripts/check-comptroller-contract-no-drift.sh`

**Interfaces:**
- Consumes: `spec/schemas/chio-comptroller/v1/surface-report.schema.json` (Task 6).
- Produces: `npm run gen:contracts` (emits the generated TS); `scripts/check-comptroller-contract-no-drift.sh` (regenerate + `git diff --exit-code`, mirroring the repo's `cargo xtask codegen --lang ts --check` no-drift pattern); `dashboard/src/types.ts` re-exports the generated comptroller-surface shapes.

- [ ] **Step 1: Pin the codegen tool + add the script**

In `crates/products/chio-cli/dashboard/package.json`, add to `devDependencies`:

```json
    "json-schema-to-typescript": "15.0.4"
```

and to `scripts`:

```json
    "gen:contracts": "node scripts/gen-contracts.mjs"
```

(15.0.4 is the exact version the repo already pins for `cargo xtask codegen --lang ts`; keep them aligned.)

- [ ] **Step 2: Write the codegen driver**

Create `crates/products/chio-cli/dashboard/scripts/gen-contracts.mjs`:

```javascript
import { compileFromFile } from "json-schema-to-typescript";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../../../..");
const schema = resolve(repoRoot, "spec/schemas/chio-comptroller/v1/surface-report.schema.json");
const out = resolve(here, "../src/generated/comptroller-surface.ts");

const banner = "// GENERATED by dashboard/scripts/gen-contracts.mjs from\n" +
  "// spec/schemas/chio-comptroller/v1/surface-report.schema.json. Do not edit by hand.\n" +
  "// Regenerate with: npm run gen:contracts\n\n";

const ts = await compileFromFile(schema, {
  additionalProperties: false,
  bannerComment: "",
  style: { singleQuote: true, semi: false },
});
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, banner + ts, "utf-8");
console.log("wrote", out);
```

- [ ] **Step 3: Generate the types**

Run: `cd crates/products/chio-cli/dashboard && npm install && npm run gen:contracts && cd - >/dev/null`
Expected: `wrote .../src/generated/comptroller-surface.ts`; the file contains `export interface ChioComptrollerSurfaceReport` with camelCase properties (`generatedAt`, `exposurePositions`, `governedMaxExposureUnits`, `decisionSummary`, `allowCount`).

- [ ] **Step 4: Consume the generated types in `types.ts`**

In `crates/products/chio-cli/dashboard/src/types.ts`, add near the top (after line 1's mirror comment):

```typescript
// Comptroller surface shapes are generated from the published JSON Schema; do not hand-mirror them.
export type {
  ChioComptrollerSurfaceReport,
  ChioComptrollerSurfaceReport as ComptrollerSurfaceReport,
} from './generated/comptroller-surface'
```

(If any hand-written comptroller-surface interface already exists in `types.ts`, delete it and rely on the generated re-export. The existing snake_case receipt/lineage mirror types stay as-is - they belong to different endpoints.)

- [ ] **Step 5: Write the no-drift gate**

Create `scripts/check-comptroller-contract-no-drift.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/crates/products/chio-cli/dashboard"
npm install --silent
npm run gen:contracts >/dev/null
cd "$ROOT"
if ! git diff --exit-code -- crates/products/chio-cli/dashboard/src/generated/comptroller-surface.ts; then
  echo "FAIL: generated comptroller-surface TypeScript is out of date; run npm run gen:contracts" >&2
  exit 1
fi
echo "OK comptroller contract TypeScript is in sync with the published schema"
```

- [ ] **Step 6: Run the no-drift gate + dashboard build/test**

Run: `chmod +x scripts/check-comptroller-contract-no-drift.sh && bash scripts/check-comptroller-contract-no-drift.sh`
Expected: `OK comptroller contract TypeScript is in sync with the published schema` (clean `git diff`, since we just generated + committed the same bytes).

Run: `cd crates/products/chio-cli/dashboard && npm test && npm run build && cd - >/dev/null`
Expected: vitest passes and `tsc -b && vite build` succeeds (the generated types compile and `types.ts` consumes them without error).

- [ ] **Step 7: Commit**

```bash
git add crates/products/chio-cli/dashboard/package.json crates/products/chio-cli/dashboard/package-lock.json crates/products/chio-cli/dashboard/scripts/gen-contracts.mjs crates/products/chio-cli/dashboard/src/generated/comptroller-surface.ts crates/products/chio-cli/dashboard/src/types.ts scripts/check-comptroller-contract-no-drift.sh
git commit -m "feat(dashboard): generate comptroller-surface TS from published schema

Pin json-schema-to-typescript@15.0.4, generate src/generated/comptroller-surface.ts,
consume it from types.ts, and add a regenerate + git diff no-drift gate.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Signed export builder (`SignedComptrollerSurfaceReport`)

**Files:**
- Modify: `crates/platform/chio-control-plane/src/trust_control/reports.rs` (add `build_signed_comptroller_surface_report`)
- Test: inline `#[cfg(test)]` in `reports.rs`, or extend the existing signed-exposure builder test

**Interfaces:**
- Consumes: `ComptrollerSurfaceReport` (Task 3) + its `validate_consistency`; `SignedExportEnvelope::sign(body, keypair)` (chio-core-types/receipt/lineage.rs:407); `load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path) -> Result<Keypair, CliError>` (policy_support.rs:644) - the same signing authority `build_signed_exposure_ledger_report` uses.
- Produces (mirrors the CLI-style, `CliError`-returning shape of `build_signed_exposure_ledger_report`, reports.rs:233, whose tail is `Signed...::sign(report, &keypair).map_err(Into::into)`):
  - `pub type SignedComptrollerSurfaceReport = SignedExportEnvelope<ComptrollerSurfaceReport>;`
  - `pub fn build_signed_comptroller_surface_report(report: ComptrollerSurfaceReport, authority_seed_path: Option<&Path>, authority_db_path: Option<&Path>) -> Result<SignedComptrollerSurfaceReport, CliError>`

Note: this signs an already-built `ComptrollerSurfaceReport` (returning `CliError`), avoiding the `Response`/`CliError` impedance mismatch with the HTTP-path `build_comptroller_surface_report` (Task 4, which returns `Response`). The HTTP handler or a CLI export command builds the report first, then signs it.

- [ ] **Step 1: Write the failing signature test**

Add to the test module in `crates/platform/chio-control-plane/src/trust_control/reports.rs`. Build a minimal sample `ComptrollerSurfaceReport` (reuse the kernel `sample()` shape from Task 3 Step 2) and a temp authority-seed path (with `Some(seed_path), None`, `load_behavioral_feed_signing_keypair` creates the keypair from the seed file):

```rust
#[test]
fn signed_comptroller_surface_report_verifies_and_is_canonical() {
    use chio_credit::ExposureLedgerCurrencyPosition;
    use chio_kernel::operator_report::{
        ComptrollerDecisionSummary, ComptrollerSurfaceReport, ComptrollerSurfaceSourceRefs,
        OperatorReportQuery, COMPTROLLER_SURFACE_REPORT_SCHEMA,
    };

    let dir = std::env::temp_dir().join(format!("chio-signed-cs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let authority_seed_path = dir.join("authority.seed");

    let report = ComptrollerSurfaceReport {
        schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
        generated_at: 1_700_000_000,
        filters: OperatorReportQuery::default(),
        exposure_positions: vec![ExposureLedgerCurrencyPosition {
            currency: "USD".to_string(),
            governed_max_exposure_units: 4200,
            reserved_units: 1000,
            settled_units: 0,
            pending_units: 0,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        }],
        decision_summary: ComptrollerDecisionSummary { allow_count: 1, deny_count: 1, cancelled_count: 0, incomplete_count: 0 },
        settlement_reconciliation: Default::default(),
        budget_utilization: Default::default(),
        source_refs: ComptrollerSurfaceSourceRefs::default(),
        execution_nonce_ref: None,
        hold_ref: None,
    };

    let signed = build_signed_comptroller_surface_report(report, Some(&authority_seed_path), None)
        .expect("build signed comptroller surface");
    assert!(signed.verify_signature().expect("verify"), "signature must verify");
    assert_eq!(signed.body.schema, "chio.comptroller.surface-report.v1");
    // Canonical round-trip: serialize + reparse + re-verify.
    let reserialized = serde_json::to_vec(&signed).expect("serialize envelope");
    let parsed: SignedComptrollerSurfaceReport = serde_json::from_slice(&reserialized).expect("parse");
    assert!(parsed.verify_signature().expect("verify parsed"));
    let _ = std::fs::remove_dir_all(&dir);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-control-plane signed_comptroller_surface_report_verifies 2>&1 | tail -5`
Expected: FAIL - `cannot find function build_signed_comptroller_surface_report`.

- [ ] **Step 3: Implement the signed builder**

In `crates/platform/chio-control-plane/src/trust_control/reports.rs`, next to `build_signed_exposure_ledger_report` (line 233), add (its two tail lines mirror the existing signed exposure builder exactly):

```rust
pub type SignedComptrollerSurfaceReport = SignedExportEnvelope<ComptrollerSurfaceReport>;

/// Sign an already-built comptroller surface projection with the behavioral-feed signing authority.
pub fn build_signed_comptroller_surface_report(
    report: ComptrollerSurfaceReport,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
) -> Result<SignedComptrollerSurfaceReport, CliError> {
    report
        .validate_consistency()
        .map_err(CliError::cli_other_error)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    SignedComptrollerSurfaceReport::sign(report, &keypair).map_err(Into::into)
}
```

Add `SignedExportEnvelope` and `ComptrollerSurfaceReport` to the imports (the crate already imports `SignedExportEnvelope` for `SignedExposureLedgerReport`, and `ComptrollerSurfaceReport` was added in Task 4). `CliError::cli_other_error(String)` is the same constructor used across the crate (e.g. policy_support.rs).

- [ ] **Step 4: Run the test to verify it passes**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-control-plane signed_comptroller_surface_report_verifies 2>&1 | tail -5`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/platform/chio-control-plane/src/trust_control/reports.rs
git commit -m "feat(chio-control-plane): signed comptroller surface export

SignedComptrollerSurfaceReport via SignedExportEnvelope + the shared
load_behavioral_feed_signing_keypair authority (no forked signing path).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Fix + extend the operator-surface qualification (6th surface + nonzero guard)

**Files:**
- Modify: `scripts/qualify-comptroller-operator-surfaces.sh`
- Modify: `docs/standards/CHIO_OPERATOR_CONTROL_SURFACE_PROFILE.json`

**Interfaces:**
- Consumes: `test_comptroller_surface_report_endpoint` (Task 5, in `receipt_query_export.rs`).
- Produces: corrected test-binary invocations, a nonzero-executed-test guard, and a 6th witnessed surface (`comptroller-surface`) in the profile snapshot.

**Adversarial fix folded in (M5 wrong-binary + false-green):** the script currently runs all 7 surface tests via `--test receipt_query` (the 3-test stub), so every one matches 0 tests and false-greens. Correct each invocation to its real binary and add a nonzero-count guard.

- [ ] **Step 1: Map each existing test to its real binary**

Run: `for t in test_operator_report_endpoint test_settlement_reconciliation_report_and_action_endpoint test_metered_billing_reconciliation_report_and_action_endpoint test_authorization_context_report_and_cli test_underwriting_decision_issue_and_list_surfaces test_credit_facility_report_issue_and_list_surfaces test_capital_book_report_export_surfaces; do echo -n "$t -> "; grep -rl "fn $t" crates/products/chio-cli/tests/ | sed 's|.*/tests/||'; done`
Expected: prints the owning `receipt_query_*.rs` binary for each (e.g. `test_operator_report_endpoint -> receipt_query_export.rs`). Use this exact mapping in Step 2.

- [ ] **Step 2: Add a shared runner with a nonzero guard + fix the invocations**

In `scripts/qualify-comptroller-operator-surfaces.sh`, replace the 7 `cargo test -p chio-cli --test receipt_query <name> -- --exact` lines (currently ~44-57) with a guarded helper and correct `<binary> <name>` pairs (from Step 1), plus the new comptroller-surface test:

```bash
run_surface_test() {
  local binary="$1" name="$2"
  local out
  out="$(cargo test -p chio-cli --test "$binary" "$name" -- --exact 2>&1)"
  echo "$out"
  if ! grep -Eq "test result: ok\. [1-9][0-9]* passed" <<<"$out"; then
    echo "FAIL: $binary::$name did not run a nonzero passing test count (false-green guard)" >&2
    exit 1
  fi
}

run_surface_test receipt_query_export        test_operator_report_endpoint
run_surface_test receipt_query_export        test_settlement_reconciliation_report_and_action_endpoint
run_surface_test receipt_query_export        test_metered_billing_reconciliation_report_and_action_endpoint
run_surface_test receipt_query_authorization test_authorization_context_report_and_cli
run_surface_test receipt_query_underwriting  test_underwriting_decision_issue_and_list_surfaces
run_surface_test receipt_query_credit_exposure test_credit_facility_report_issue_and_list_surfaces
run_surface_test receipt_query_capital       test_capital_book_report_export_surfaces
run_surface_test receipt_query_export        test_comptroller_surface_report_endpoint
```

(Use the exact binary names printed in Step 1; the mapping above is the expected result but confirm it.)

- [ ] **Step 3: Add the 6th surface to the profile snapshot**

In `docs/standards/CHIO_OPERATOR_CONTROL_SURFACE_PROFILE.json`, add a 6th entry to the surfaces array mirroring the `operator-report` entry's shape, with a witness pointing at the new test:

```json
    {
      "id": "comptroller-surface",
      "kind": "report",
      "path": "/v1/reports/comptroller-surface",
      "schema": "chio.comptroller.surface-report.v1",
      "witness": {
        "test_binary": "receipt_query_export",
        "test": "test_comptroller_surface_report_endpoint"
      }
    }
```

(Match the exact key names the existing 5 entries use - inspect the file first and follow its shape verbatim.)

- [ ] **Step 4: Run the qualification script**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 bash scripts/qualify-comptroller-operator-surfaces.sh 2>&1 | tail -12`
Expected: all 8 `run_surface_test` calls print `test result: ok. 1 passed` (or more), no `FAIL` guard trip, and the script exits 0 with the profile snapshot including the 6th surface.

- [ ] **Step 5: Commit**

```bash
git add scripts/qualify-comptroller-operator-surfaces.sh docs/standards/CHIO_OPERATOR_CONTROL_SURFACE_PROFILE.json
git commit -m "fix(qualify): correct operator-surface test binaries + add comptroller surface

Route each surface test to its real receipt_query_* binary (the old --test
receipt_query matched 0 tests = false green), guard nonzero runs, add the 6th
witnessed comptroller-surface.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Wire the contract gates into the release lane + docs

**Files:**
- Modify: `scripts/qualify-release.sh`
- Modify: `docs/reference/RECEIPT_DASHBOARD_GUIDE.md`
- Modify: `docs/reference/RECEIPT_QUERY_API.md`
- Modify: `docs/reference/AGENT_ECONOMY.md`

**Interfaces:**
- Consumes: `scripts/check-chio-schema-registry.sh`, `scripts/check-comptroller-contract-no-drift.sh` (Task 8), `scripts/qualify-comptroller-operator-surfaces.sh` (Task 10).
- Produces: the full contract (governance + codegen no-drift + endpoint conformance) as a release-lane regression, complementing the M1 demo gates.

- [ ] **Step 1: Add the contract gates to `qualify-release.sh`**

In `scripts/qualify-release.sh`, after the demo-gate block inserted in Task 2 (still before the `output_root=` assignment), add:

```bash
# Unified spend/exposure contract regression (governance + codegen + endpoint).
bash ./scripts/check-chio-schema-registry.sh
bash ./scripts/check-comptroller-contract-no-drift.sh
bash ./scripts/qualify-comptroller-operator-surfaces.sh
```

- [ ] **Step 2: Verify the wiring assertion**

Run: `for g in check-chio-schema-registry check-comptroller-contract-no-drift qualify-comptroller-operator-surfaces; do grep -q "$g" scripts/qualify-release.sh && echo "$g PRESENT" || { echo "$g ABSENT"; exit 1; }; done`
Expected: all three print `PRESENT`.

- [ ] **Step 3: Syntax-check**

Run: `bash -n scripts/qualify-release.sh && echo "syntax ok"`
Expected: `syntax ok`.

- [ ] **Step 4: Document the contract as the single cross-language source of truth**

In `docs/reference/RECEIPT_QUERY_API.md`, add a section for `GET /v1/reports/comptroller-surface` returning `chio.comptroller.surface-report.v1` (list the response shape: `schema`, `generatedAt`, `exposurePositions[]`, `decisionSummary`, `settlementReconciliation`, `budgetUtilization`, `sourceRefs`, reserved `executionNonceRef`/`holdRef`). In `docs/reference/RECEIPT_DASHBOARD_GUIDE.md`, note the in-repo dashboard now consumes `src/generated/comptroller-surface.ts` (generated from the schema, no hand-maintained mirror for these shapes). In `docs/reference/AGENT_ECONOMY.md`, document the out-of-repo consumption model: schema-governed HTTP polling of `/v1/reports/comptroller-surface` plus the optional signed offline export (`SignedComptrollerSurfaceReport`), both pinned to the published `spec/schemas/chio-comptroller/v1/surface-report.schema.json`. Keep all prose inside the non-claims / custody-neutral discipline (the projection implies no fund movement).

- [ ] **Step 5: Commit**

```bash
git add scripts/qualify-release.sh docs/reference/RECEIPT_DASHBOARD_GUIDE.md docs/reference/RECEIPT_QUERY_API.md docs/reference/AGENT_ECONOMY.md
git commit -m "docs+lane: wire contract gates into release lane + document surface contract

Add schema-registry, TS no-drift, and operator-surfaces gates to qualify-release;
document chio.comptroller.surface-report.v1 as the single cross-language source of
truth (HTTP poll + optional signed offline export), inside the non-claims discipline.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (maintainer gate, not a per-task step)

After all tasks, the maintainer runs the full one-liner from `CLAUDE.md` once:

```bash
cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```

Plus the acceptance checks from the spec:
- `bash scripts/check-chio-transaction-passport.sh` exits 0.
- `cargo xtask verify launch-acceptance --out target/proof-room/public-bundle` exits 0 (no FAILED verdict).
- `grep -E "check-chio-transaction-passport|launch-acceptance" scripts/qualify-release.sh` finds both.
- `bash scripts/demo/flagship-wall-stops-money.sh` exits 0 and narrates DENIED + ALLOWED + SETTLED + NON-CLAIMS; `scripts/tests/flagship-wall-stops-money.test.sh` is green (including the tamper -> non-zero fail-closed check).
- `bash scripts/check-chio-schema-registry.sh` exits 0 with `chio-comptroller/v1` registered + hashed + git-tracked + enrolled in checked roots.
- `cargo test -p chio-cli --test receipt_query_export test_comptroller_surface_report_endpoint -- --exact` runs a nonzero passing count.
- `cargo test -p chio-kernel --test comptroller_surface_schema` passes (positive + 3 negatives).
- `bash scripts/check-comptroller-contract-no-drift.sh` is clean; dashboard `npm test` + `npm run build` pass.
- `bash scripts/qualify-comptroller-operator-surfaces.sh` green with the 6th witnessed surface.
- No em dashes; no `unwrap`/`expect` introduced in `src/`.
