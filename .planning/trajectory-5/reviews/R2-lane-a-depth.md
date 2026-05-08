# R2 - Lane A Technical Depth Review

**Reviewer role**: Wave 2 Lane A depth reviewer (Quality, Mutation, and
Formal-Verification Skeptic stance).
**Review date**: 2026-05-07.
**Scope**: Lane A floor plan, all seven `.planning/trajectory-5/lane-a-floor/*.md`
files, plus codebase ground-truth spot checks.
**Verdict**: APPROVED-WITH-FIXES (see Section 11).

---

## Executive summary

Lane A is the right shape: it correctly identifies the trj4 erratum failure
modes (caught:0 placeholders, rfl tautology, missing Kani harnesses on three
deferred crates, advisory apalache-temporal lane, unmeasured per-crate kill
rates), it adopts the release work Evidence Gate as its close bar, and it lays out 46
tickets with weekly cadence and per-crate budgets.

The plan is honest about what it does not yet know (assumptions called out in
README.md sections "Assumptions" and "Status check on the property names"),
and the ticket text quotes verbatim Quality Skeptic line numbers when proposing
each remediation. It does not paper over the placeholder pattern.

What it does NOT yet do is verify, against the actual production code, that
the production entry-point names cited as Kani harness targets exist. They do
not, in three of the most visible cases. The plan also under-specifies the
CI integration for the new Kani harnesses (the existing `nightly.yml` and
`ci.yml` both hardcode `cargo kani -p chio-kernel-core`; there is no matrix
to extend, only a hardcoded shell loop). The `lean4-fix.md` proposal mis-states
the Rust signature and proposes a Lean model whose refinement claim is too
weak to be load-bearing.

These are correctable. This review proposes specific patches, marks each
finding by severity (BLOCKER / MAJOR / MINOR / OBSERVATION), and recommends
APPROVED-WITH-FIXES.

**Tally**: 4 BLOCKER, 9 MAJOR, 11 MINOR, 6 OBSERVATION.

---

## 1. Mutation uplift realism (BLOCKER + MAJOR + MINOR)

### 1.1 Per-crate budgets achievable in 8 weeks? (MAJOR)

The plan budgets `chio-attest-verify` >= 80% as the longest-running crate
(weeks 1-3, with sharding). The current per-crate baseline is the string
`pending trajectory-3.1 phase 4.2 full-sweep measurement` for ALL six crates
(`releases.toml:77-82`). The aggregate banner reads 31% (`README.md:17`) on
n=375 viable mutants from 2026-04-29.

Reality check: the plan does not back the >=80% target with a sample run. The
mutation-budget.md table uses `unmeasured` for every current value. There is
no historical evidence that `chio-attest-verify` mutants are tractable enough
to push from `unmeasured` to >=80% in ~3 weeks of one-engineer effort. The
plan's only mitigation is "budget two engineer-weeks" (PLAN.md:357) and "up
to 20% of residuals annotated" (mutation-budget.md:73).

**Risk**: at the eight-week horizon, the lane could plateau at 50-65% on
`chio-attest-verify`. Risk Register R2 captures this but its escalation path
("plateaus below 70%") is permissive: a 78% kill rate would still be a miss
against synthesis ship-bar 1.

**Patch**: mutation evidence item should be split into two tickets: mutation evidence item (run the
baseline) and mutation evidence item (publish the per-crate numbers). After mutation evidence item,
the plan should re-baseline the >=80% target against the ACTUAL initial
attest-verify kill rate before week 3 starts. If the baseline is below 50%,
escalate to Wave 2 IMMEDIATELY rather than after two waves of test-surface
expansion. R2's "two waves" criterion is too late.

### 1.2 Cargo-mutants config does mutate trust-boundary lines (OBSERVATION)

I checked `.cargo/mutants.toml` lines 164-203. The `exclude_globs` correctly
exclude tests, benches, build scripts, fuzz harnesses, and Kani harness
files. They do exclude some non-trivial production files (e.g.
`chio-kernel-core/src/clock.rs`, `chio-policy/src/models.rs`,
`chio-guards/src/external/**`), and each carries a single-line rationale.

This is defensible for the listed exclusions, but there is no signal in
Lane A that a re-audit of the exclusion list is on the agenda. If the
"31% aggregate" was computed against an exclusion list that hides
mutation-killable lines, the kill-rate bump from 31% to 65% may be
artificially compressed.

**Patch**: add a mutation exclusion audit ticket: "Audit `.cargo/mutants.toml`
`exclude_globs` and confirm each exclusion is either (a) test/build/fuzz
scaffolding, (b) covered by a Kani harness, or (c) accompanied by a
production-call-path conformance test. Output: a per-line audit report
under `audits/evidence/mutation exclusion audit/exclude-audit.md` with each exclusion
marked OK or FOR-REMOVAL." Without this, the >=65% target is held against
a pre-existing exclusion list whose justification has not been re-checked
in the release work frame.

### 1.3 Banner format spec is clean (OBSERVATION)

`mutation-budget.md` lines 88-93 specifies the post-Lane-A banner shape:
`Mutation kill: 65% (lowest of six trust-boundary crates;
chio-attest-verify 82%) - measured <YYYY-MM-DD>`. This format reflects the
synthesis requirement (lowest observed, not target) and is the strongest
defense against the trj4 banner-vs-reality drift pattern. The
mutation evidence item reproducibility check ("re-running the workflow on the same
data produces an identical line") is good belt-and-suspenders.

### 1.4 `mutants.yml` workflow rebuild status (MINOR)

PLAN.md:34 references "`mutants.yml` workflow has two consecutive
`status_at_capture: success` nightly runs". I verified `mutants.yml` exists.
The plan does not call out whether the workflow is currently green; if the
workflow has been red or sharded-with-skip-budget for the last several
weeks, the two-night requirement starts from the first green run, which
adds calendar latency.

**Patch**: mutation evidence item should verify the current `status_at_capture` of the
last 7 nightly runs and document any flake. If the workflow has been red,
mutation evidence item owns un-flaking it before the per-crate measurement starts.

---

## 2. Threat-evidence backfill quality (BLOCKER + MAJOR + MINOR)

### 2.1 21 vs 20 file count (OBSERVATION)

The plan resolves the synthesis-vs-reality discrepancy correctly:
README.md:131 calls out the assumption ("synthesis says 21; actual count is
20"); threat-evidence-backfill.md confirms 20 rows mapping 1:1 to threat IDs
in `spec/security/chio-threat-model.v1.json`. I confirmed via
`ls audits/evidence/threats/ | wc -l` returning 20 and
`grep -c '"id":' spec/security/chio-threat-model.v1.json` returning 20.

The "threat evidence item absorbs a 21st" hedge is fine.

### 2.2 Test files exist under correct path (OBSERVATION)

The plan asserts test files at `crates/chio-conformance/tests/threats/<id>.rs`.
I confirmed all 20 exist. The path under `crates/chio-conformance/tests/`
matches Evidence Gate Artifact C (templates/EVIDENCE-GATE.md section 1.3,
"Lane A (floor / threat coverage)"). Good.

### 2.3 Production call path identification - 12 of 20 are TBD (BLOCKER)

The threat-evidence-backfill.md per-row table claims a production call path
for each threat. I checked the precise function names cited:

- Row 8 `kernel_impersonation` cites `sign_receipt` kernel-key binding.
  Verified by `grep` - `sign_receipt` exists in `chio-kernel-core::receipts`.
  OK.
- Row 4 `capability_token_theft` cites "Replay-store key check on
  `body_hash` (Lane B receipt v2 work) and capability verifier signature
  check". This is **TBD** by Lane B; if Lane B does not land, this row
  has no production call path. The plan must say so explicitly.
- Row 14 `pq_signature_downgrade` cites "Hybrid-PQ signature dispatch;
  algorithm-tag check in capability verifier". The exact function name is
  not given. This is hand-wavy; in the actual production code there are
  multiple algorithm-tag checks, and the test would need to pick one.
- Row 17 `tee_quote_forgery` cites
  "`chio-tee-frame::validate_signed` and `verify_tenant_sig`". The plan
  references TRJ4-021 evidence but does not confirm those functions are
  real, fully-wired production paths today. Risk Register R3 explicitly
  flags `tee_quote_forgery` as a candidate "depends on
  `chio-tee-frame::validate` real cryptographic verification, TRJ4-021
  carry-forward".

Of the 20 rows, **at least 12 cite production call paths in
not-yet-fully-existent terms** (where "fully-existent" means a `pub fn`
named exactly as cited that the test can import directly without a wrapper).

This is the trj4 anti-pattern in disguise: cite a production call path that
does not exist as a public function name today, then close on a test that
calls something else and pretend it is the cited path. The plan must NOT
admit this.

**Patch (BLOCKER)**: each release work-A2.<n> ticket must, before close,
include in its acceptance section the literal `pub fn` import path under
which the test invokes the production decision. If the production decision
is a trait method on `dyn Verifier`, the test must instantiate the
concrete impl (not a mock), and the concrete impl must be named in the
ticket. Add a row to threat-evidence-backfill.md per threat ID labeled
"Public symbol invoked in test" with the form
`crate::module::function_name` and verify by grep that the symbol exists.
Tickets that cannot satisfy this enter R3-defer at Wave 1, not at Wave 2.

### 2.4 Backfillable in release work vs blocked on architecture (MAJOR)

Per Risk Register R3: "More than 4 of 21 rows tag as
`provable-only-in-trj6`. At that point the release work banner claim is too soft
to count as a closeout."

My audit suggests the candidate-deferral count could exceed 4 absent
explicit Wave 1 triage. Beyond the three R3 candidates
(`wasm_guard_resource_exhaustion`, `ssrf_via_http_substrate`,
`tee_quote_forgery`), the following look architecturally fragile:

- `kernel_impersonation` (#8): rewriting requires feeding an
  impersonation key into `sign_receipt`. Plausible but the test fixture
  must construct a wrong-kernel-key path that the verifier rejects, not
  just one the kernel never accepts because it sees a missing field.
- `passkey_credential_theft` (#11): the plan says "or whichever crate
  today owns the passkey path", which is not specific. If passkey
  enforcement is not yet a production primitive, this is R3.
- `device_key_extraction` (#7), `mobile_attestation_replay` (#9),
  `play_integrity_token_replay` (#13) - all three depend on TRJ4-033
  hooks. The plan asserts those hooks are real but does not verify.

**Patch (MAJOR)**: Wave 1 deliverable - run a per-row triage against the
actual codebase. For each row, mark `IMPL-EXISTS-AND-PUBLIC`,
`IMPL-EXISTS-PRIVATE` (test must be in the same crate or use a
public wrapper), `IMPL-PARTIAL` (production has a stub), or
`IMPL-MISSING` (R3 defer). Update the Risk Register R3 escalation
criterion to fire when the IMPL-MISSING + IMPL-PARTIAL count exceeds 2
rather than 4.

### 2.5 Nine weak-row rewrites - acceptance criteria are correct (OBSERVATION)

PLAN.md:101-110 specifies the nine weak rows must be rewritten as deny-
asserting fixtures with three concrete sub-criteria: build a verifier or
guard fixture, feed an attack input, assert `Verdict::Deny`. This matches
the Quality Skeptic's prescription
(`04-quality-verification-skeptic.md` line 86) and is the correct anti-
pattern guard against `assert_threat_covered_by_corpus` and
`assert_file_contains` bodies.

I confirmed `crates/chio-conformance/tests/threats/native_channel_replay.rs`
is 41 lines of meta-only assertions today (`assert_threat_covered_by_corpus`,
`corpus_cases_for(...).len() >= 2`). Replacing this with a verifier
fixture is real work, not a doc rewrite.

### 2.6 The bootstrap-bypass clause is not retired by Lane A (MAJOR)

`scripts/check-threat-coverage-mutants.sh` lines 32-39 say: "A row with
`needs_real_run: true` is treated as `weak_coverage` regardless of
`caught`, and a downgrade hint is emitted with reason
`bootstrap_placeholder`. The script does NOT exit 1 on bootstrap
placeholders." The script supports this only until `BOOTSTRAP_EXPIRES_DATE`
(default 2026-08-01).

Today is 2026-05-07. The bootstrap accommodation expires August 1. Lane
A's 8-week timeline lands week 8 around 2026-07-02; the bootstrap-expiry
clock would still be running.

The Lane A plan does not retire the `needs_real_run: true` bypass clause
from the script when Lane A closes. Instead it relies on the script
emitting downgrade hints and Lane A clearing them (PLAN.md:101 "exits 0
without emitting `bootstrap_placeholder`..."). After Lane A closes, the
clause is still in the script as live code, available to be re-used in
the next bootstrap cycle.

**Patch (MAJOR)**: threat evidence item should DELETE the `needs_real_run` clause
from `scripts/check-threat-coverage-mutants.sh` (not just remove the
footnote from `docs/security/threat-coverage.md`). After Lane A closes,
no row should be allowed to claim placeholder status; the bypass code
should not exist.

### 2.7 Mobile rows scheduling (MINOR)

A2 lists `device_key_extraction`, `mobile_attestation_replay`,
`play_integrity_token_replay` with `Depends-on: mutation evidence item, TRJ4-033`.
TRJ4-033 is described as "carry-forward". The plan does not say whether
TRJ4-033 has merged or is still open. If TRJ4-033 has not merged, A2
mobile rows are blocked on a Lane A-external dependency.

**Patch**: release work-A2 should fail closed if `TRJ4-033` is not in its
`closed` bucket. Wave 1 must check this status and either confirm
TRJ4-033 closed or escalate.

---

## 3. Kani harness feasibility (BLOCKER + MAJOR)

### 3.1 Production entry names DO NOT match the codebase (BLOCKER)

This is the most serious finding. The harness invariant tables in
`kani-harness-design.md` cite production entry names that do not exist as
public functions in the trees they reference.

#### 3.1a `chio-attest-verify` cited entries

`kani-harness-design.md` lines 38-42:

| # | Cited entry |
|---|---|
| 1 | `chio_attest_verify::verify_quote_signed` (paths under `quote.rs` and `tee_signature.rs`). |
| 2 | `chio_attest_verify::tee_signature::verify` |
| 3 | `chio_attest_verify::nitro::verify` (or sev_snp.rs/tdx.rs/sigstore.rs). |
| 4 | `chio_attest_verify::policy::verify_nonce` |

Reality: I ran
`grep -nE '^pub fn ' crates/chio-attest-verify/src/*.rs`. The only
result is `crates/chio-attest-verify/src/quote.rs:163: pub fn
expect_report_data(...)`. Every other `verify_*` exposed externally is a
trait method on `AttestVerifier` or `QuoteVerifier`
(`crates/chio-attest-verify/src/lib.rs:265-330`). `verify_quote_signed`,
`tee_signature::verify`, `nitro::verify`, and `policy::verify_nonce`
are NOT `pub fn` anywhere.

A Kani harness must call a concrete production entry. For trait methods
the harness must instantiate a concrete impl. The plan does not name the
concrete impl crate (e.g. is the harness against the `chio-tee-frame`
default impl, or a specific TEE-backend impl?).

#### 3.1b `chio-anchor` cited entries

`kani-harness-design.md` lines 70-75:

| # | Cited entry |
|---|---|
| 3 | `chio_anchor::batch::verify_inclusion_proof` |
| 4 | `chio_anchor::witness::verify_witness` |

Reality: `verify_inclusion_proof` does NOT exist in the `chio-anchor`
crate (`grep -n 'verify_inclusion_proof' crates/chio-anchor/src/*.rs`
returns no hits). `verify_witness` also does NOT exist.

What does exist: `verify_anchor_batch` (line 208), `evaluate_witness_policy`
(line 312), `batch_body_hash` (line 193). The invariants in 3 and 4 must
be re-targeted at functions that exist.

#### 3.1c `chio-weights` cited entries

`kani-harness-design.md` lines 107-110:

| # | Cited entry |
|---|---|
| 1 | `chio_weights::card::verify` |
| 2 | `chio_weights::lineage::verify` |
| 3 | `chio_weights::bundle::verify` |
| 4 | `chio_weights::card::verify_signature` |

Reality: NONE of those four function names exist as `pub fn` in the
crate. The actual public verify-shaped exports are:
- `chio_weights::bundle::verify_model_card_bundle`
- `chio_weights::lineage::verify_model_card_anchor`
- `chio_weights::lineage::anchor_projection_bytes`
- `chio_weights::lineage::anchor_model_card`

The harness invariants (card-hash binding, lineage commitment, bundle
mismatch) are real properties, but the entry names cited are wrong.

**Patch (BLOCKER)**: rewrite kani-harness-design.md tables (1), (2), (3)
to cite the actual production entries. Specifically:

For `chio-attest-verify`, target either (a) the default `AttestVerifier`
impl provided by the crate's bundle/Sigstore default, OR (b) a specific
TEE-backend impl in `nitro.rs`/`sev_snp.rs`/`tdx.rs`. Pick one impl,
name it, and confirm it is a publicly constructible type.

For `chio-anchor`, replace `verify_inclusion_proof` with
`verify_anchor_batch` (which internally checks inclusion proofs) and
re-state invariant 3 as "feed `verify_anchor_batch` a batch with a
mis-ordered sibling and observe error". Replace `verify_witness` with
`evaluate_witness_policy`.

For `chio-weights`, replace each invariant entry with the actual public
function name. The plan can keep the invariant content; it must match
the production function the test calls.

This is BLOCKER because Lane A's Evidence Gate Artifact A requires "a
non-test, non-example, non-`#[cfg(test)]` module" (EVIDENCE-GATE.md
section 1.1), and a Kani harness referencing a non-existent function is
not an enforced call site.

### 3.2 Bound parameters realistic for Kani CI? (MAJOR)

Kani-harness-design.md proposes bounds (chain.len() <= 3, leaves.len() <=
8, body.len() <= 64, proof.len() <= 4, etc.). For an SHA-256 hash chain
of length 4, Kani symbolic execution can be expensive even with these
bounds because hash functions explode. The chio-kernel-core harnesses
today use `--default-unwind 8` (`nightly.yml:126`).

The plan acknowledges this for `chio-anchor` ("may exceed default Kani
budget", "harness uses `#[kani::unwind(4)]`") but not for the other two
crates. SHA-256 verification under symbolic input is the canonical Kani-
times-out scenario.

**Patch (MAJOR)**: each harness file in Kani harness evidence/A3.2/A3.3 must
include a section in the file header stating: (a) bound parameters
chosen, (b) per-harness `#[kani::unwind(N)]` value, (c) Kani CI run
timeout used, (d) measured wall-clock from a local run. Without these,
the "two consecutive green nightly runs" criterion is held against a
job that may take hours or time out.

Add a Kani harness evidence ticket: "Run each proposed Kani invariant locally with
the proposed bounds. Capture wall-clock, memory, and exit status to
`audits/evidence/Kani harness evidence/local-bound-validation.md`. If any invariant
exceeds 30 minutes locally, escalate (R-new) before Kani harness evidence starts."

### 3.3 CI integration is hand-wavy (BLOCKER)

`kani-harness-design.md` line 130-146 sketches a YAML matrix change:

```yaml
jobs:
  kani:
    strategy:
      matrix:
        crate:
          - chio-kernel-core
          - chio-attest-verify
          - chio-anchor
          - chio-weights
```

This is not how the workflow is structured today. `nightly.yml:62-129`
runs a single shell loop:

```bash
mapfile -t HARNESSES < <(python3 - ...)
for harness in "${HARNESSES[@]}"; do
  cargo kani -p chio-kernel-core --lib --harness "${harness}" \
    --default-unwind 8 --no-unwinding-checks
done
```

The Python helper reads
`formal/rust-verification/kani-public-harnesses.toml` whose top-level
declares `crate = "chio-kernel-core"` (single crate). The same single-
crate hardcoding applies to `ci.yml:478,590`.

To extend Kani to three new crates, the plan needs: (a) either a per-
crate harness manifest under `formal/rust-verification/<crate>/kani-
public-harnesses.toml`, or (b) a multi-crate manifest schema change at
`formal/rust-verification/kani-public-harnesses.toml`, plus (c) workflow
changes to either nest a per-crate loop or fan out a matrix. Neither is
in the plan.

**Patch (BLOCKER)**: Kani multi-crate manifest must own the workflow rewrite, with a
specific named approach. Add a sub-ticket Kani multi-crate manifesta "Extend
`formal/rust-verification/kani-public-harnesses.toml` schema (or split
to per-crate files) to support a multi-crate harness registry. Cite the
exact diff to `nightly.yml` and `ci.yml`. Run two consecutive green
multi-crate Kani runs."

The current Kani multi-crate manifest description ("Wire all three harnesses into
`nightly.yml` ... Capture two consecutive green run URLs") is too
shallow for this scope. It needs to enumerate the three workflow files
that touch Kani (`nightly.yml`, `ci.yml`, `kani-public-pr` job) and
specify the diff for each.

### 3.4 Theorem-inventory cross-reference (OBSERVATION)

Kani harness evidence updates `formal/proof-manifest.toml`. I confirmed
`formal/rust-verification/kani-public-harnesses.toml` exists with a
`harness_groups` array. The exact registry to update is named
`kani-public-harnesses.toml`, not `proof-manifest.toml`; the plan should
clarify (or both files exist and the plan should name both).

**Patch (MINOR)**: Kani harness evidence should reference the actual file
`formal/rust-verification/kani-public-harnesses.toml`. If
`formal/proof-manifest.toml` does not exist (I did not verify), this is
a name mismatch that will block close.

---

## 4. TLA+ rewrites (MAJOR + MINOR)

### 4.1 The "rewrite vs introduce" framing is honest (OBSERVATION)

`tla-rewrites.md:22-34` correctly notes that `RevocationCutCompleteness`,
`ReceiptBeforeAllow`, and the `Allow` action do NOT exist in
`RevocationPropagation.tla` today. The plan reframes TRJ4-015 and
TRJ4-016 as "introducing" the properties via the rewrite. I verified by
`grep` on the file: `Allow`, `LogReceipt`, `PublishAllow`, and
`ReceiptBeforeAllow` are absent. `RevocationCutCompleteness` is absent.
Only `RevocationEventuallySeen` (line 379) and the existing
`NoAllowAfterRevoke` (line 271) safety property exist. The plan's
honesty here is good.

### 4.2 Bounded transitive-closure unrolling expressible in Apalache 0.50.x? (MAJOR)

`tla-rewrites.md:46-58` describes the target as `reachable_set(a, c, k)`
with `k = 3`. Apalache 0.50.x supports recursive `LET` definitions but
has well-known limitations on recursive operators in temporal contexts.
The doc says "if the proof times out at depth 3, the unrolling is
reduced to depth 2" (lines 75-77).

The plan does not cite a specific Apalache feature flag or model fragment
proving the unrolling is expressible. The existing module
`formal/tla/RevocationPropagation.tla:17-25` documents a forced
workaround for an Apalache encoding limit on `WF_vars(\E ...)` -
evidence that this codebase has hit Apalache encoding limits before.

**Patch (MAJOR)**: release work-A4.2 must include a "feasibility spike" sub-task:
write a 20-line TLA fragment expressing the bounded transitive-closure
operator and run Apalache against it standalone. Capture exit status and
a link in `audits/evidence/release work-A4.2/feasibility-spike.md`. If Apalache
0.50.x does not handle the encoding, release work-A4.2 escalates - the only
realistic fallback is to inline-unroll the closure into a hand-written
`Reachable_step1`, `Reachable_step2`, `Reachable_step3` chain, which is
ugly but expressible.

### 4.3 EpochMax 4 -> 6 fits run budget? (MINOR)

The cfg actually uses `DEPTH_MAX`, not `EpochMax`. The plan calls this
out (`tla-rewrites.md:139`). The bump from 4 to 6 doubles the trace
length budget, which roughly cubes the apalache state space for a model
with multi-process interleaving. The current PR-tier config is `PROCS=4
CAPS=8 DEPTH_MAX=4` (verified from `MCRevocationPropagation.cfg`).

A length-6 trace at PROCS=4 CAPS=8 may still fit a 30-minute apalache
budget on `apalache-temporal.yml` (timeout-minutes: 30), but the plan
provides no measured baseline.

**Patch (MINOR)**: release work-A4.3 must record the apalache run wall-clock
before AND after the bump, captured in
`audits/evidence/release work-A4.3/length-budget.md`. If the post-bump run
exceeds 25 minutes (within 5 minutes of timeout), a follow-up either
sets `DEPTH_MAX=5` or extends the workflow timeout.

### 4.4 Promotion to required: branch protection is github-level (OBSERVATION)

`tla-rewrites.md:191-193`: branch-protection configuration is "captured
as a PR description note since branch protection is not in the repo".
This is correct but operationally fragile. The plan should additionally
require `audits/evidence/release work-A4.4/branch-protection-screenshot.png` or
equivalent so future reviewers can verify the workflow is actually
required without relying on PR archaeology.

**Patch**: add "screenshot of GitHub branch-protection settings showing
`apalache-temporal` in the required list, captured to
`audits/evidence/release work-A4.4/branch-protection.png`" to release work-A4.4
acceptance.

### 4.5 ReceiptBeforeAllow tautology guard (OBSERVATION)

`tla-rewrites.md:99-109` states the new property:

> `ReceiptBeforeAllow == \A a \in ProcSet, c \in CapSet, t \in Nat:
> PublishAllow(a, c, t) was enabled implies LogReceipt(a, c, t)
> already happened.`

This is correctly non-tautological IF `PublishAllow` and `LogReceipt`
are independent actions. The anti-pattern guard at `tla-rewrites.md:255`
("a `ReceiptBeforeAllow` proof body that reduces to one-line unfolding
is the tautological pattern the Quality Skeptic flagged") is good.

The risk: if the TLA author writes
`PublishAllow(a,c,t) == LogReceipt(a,c,t) /\ ...`, the property
unfolds tautologically again. The plan does not require a code review
checking for this. The cascade-update ticket (release work-A4.5) is the right
slot: review `theorem-inventory.json` AND the `PublishAllow` definition
for evidence of unfolding shortcuts.

---

## 5. Lean4 fix quality (BLOCKER + MAJOR + MINOR)

### 5.1 Rust signature is mis-stated (BLOCKER)

`lean4-fix.md:75-85` claims the Rust signature:

```rust
pub fn verify_capability_with_negotiated_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CryptoFloor,
    peer_max_schema: Schema,
) -> Result<(), CapabilityError>
```

I verified the actual signature at
`crates/chio-kernel-core/src/capability_verify.rs:226-232`:

```rust
pub fn verify_capability_with_negotiated_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
) -> Result<VerifiedCapability, CapabilityError>
```

Differences: the type is `CapabilityCryptoFloor` (not `CryptoFloor`); the
fifth argument is `&CapabilityNegotiation` (not `Schema`); the return is
`Result<VerifiedCapability, _>` (not `Result<(), _>`). The `peer.max_capability_schema`
is reached via the `CapabilityNegotiation` struct.

This matters because `lean4-fix.md` then proposes a Lean model term that
matches the WRONG signature (`peerMax: Schema` directly). The fix is
shallow if the Rust signature shape is mis-stated.

**Patch (BLOCKER)**: rewrite `lean4-fix.md` lines 75-85 against the actual
signature. The Lean model term should reflect the
`CapabilityNegotiation` shape with at least the `max_capability_schema`
field, not a flat Schema. Acknowledge that `crypto_floor` is a separate
parameter (the proposed model term lumps it into `floorOk: Bool`, which is
correct as a refinement-level abstraction but should be called out).

### 5.2 Refinement claim is too weak (MAJOR)

The proposed re-stated theorem
(`lean4-fix.md:117-141`) says:

> `(verify_capability_with_negotiated_floor_model ... = CeilingVerdict.admit)
> -> Schema.le tokenSchema peerMax = true`

This is a one-direction implication. The "iff" formulation in the doc
(line 121: "admits iff the schema-ceiling property holds") is stated in
prose but the actual theorem only proves admit-implies-le. The reverse
direction (le-implies-admit, modulo signature/time/floor) is also needed
for refinement and is not in the proposed proof.

Also, the docstring claim (`lean4-fix.md:53`) is "schema-ceiling
rejection precedes signature, time, and floor check runs". The proposed
model term puts all three boolean checks AFTER the schema check, which
captures ordering. But the proposed theorem only quantifies over
admission outcome - it does not assert the ordering directly. A real
ordering theorem would state: for all
`(token, peer, signatureOk, timeOk, floorOk)` where `Schema.le ... = false`,
the model term returns `rejectExceedsCeiling` REGARDLESS of the three
`*Ok` booleans.

The proposed proof discharges the existing rfl tautology but does not
discharge the docstring claim. It substitutes one weak proof for a
slightly less weak proof.

**Patch (MAJOR)**: release work-A5.3 should state at least three theorems, not
one:

- `negotiation_safety_admit_implies_le`: admit -> Schema.le.
- `negotiation_safety_reject_implies_not_le_or_other_failure`:
  reject implies (Schema.le=false) OR (signatureOk=false) OR
  (timeOk=false) OR (floorOk=false). This is the negation of the
  no-silent-admit clause.
- `negotiation_safety_schema_first`: forall `(t, p, sOk, tOk, fOk)`
  if `Schema.le t p = false` then the model returns
  `rejectExceedsCeiling`. This proves ordering.

Without the third theorem, the docstring claim is not proven. Without
the second, the no-silent-admit clause from the synthesis ("Fail-closed
default") is not proven.

### 5.3 Lean toolchain in CI is its own ticket (MINOR)

release work-A5.1 adds a `lean.yml` workflow. The existing situation: Lean is
mentioned in the file header lines 10-12 ("currently unavailable in
CI"). I checked `.github/workflows/`: there is no `lean.yml` today. The
plan's release work-A5.1 absorbs this work but it is sized M, not S, because
Lean 4 toolchain installation in CI is non-trivial (lake build, package
manager setup, deterministic version pin).

**Patch (MINOR)**: release work-A5.1 should be re-scoped from M to L given the
toolchain bringup work. Add a sub-task: "Pin a specific Lean 4 toolchain
version in `lean-toolchain` file (or equivalent) and document the
elaboration time + CI cache strategy. Without this, every PR rebuilds
the whole proof set from scratch."

### 5.4 The four sibling rfl theorems retain status (OBSERVATION)

`lean4-fix.md:188-203` correctly observes that the four sibling
`negotiation_safety_*` proofs (e.g.
`negotiation_safety_v2_rejected_under_v1_ceiling`) are concrete-input
sanity checks, not tautological universals. `rfl` is correct for those.
Good distinction; the plan does not over-claim.

---

## 6. Evidence Gate compliance - sample audit (MAJOR)

I sampled eight tickets across sub-lanes and checked each against the
Evidence Gate Four-Artifact Rule (EVIDENCE-GATE.md section 1.1-1.4).

### 6.1 mutation evidence item (banner update) - PASS

Artifact A: `mutants-banner.yml` workflow.
Artifact B (Lane A audit citation): `audits/evidence/mutants/<crate>/<date>.json`.
Artifact C: implicitly the workflow's own reproducibility check.
Artifact D: "re-running the workflow on the same data produces an
identical line" - this is a production-call-path exercise.
**Pass.**

### 6.2 threat evidence item (`native_channel_replay` rewrite) - INCOMPLETE

Artifact A: NOT named. The ticket says "instantiate a verifier" but does
not say which one. The actual production path is the kernel-core
replay-store check. The ticket should say
`crates/chio-kernel-core/src/replay_store.rs:<line>` (or wherever).
Artifact B: `audits/evidence/threats/native_channel_replay.json` with
caught >= 1.
Artifact C: `crates/chio-conformance/tests/threats/native_channel_replay.rs`
rewritten.
Artifact D: not specified.
**Fails Artifact A and D specificity.** Patch: each release work-A2.<n> ticket
needs an Artifact A line and an Artifact D revert-and-rerun procedure.

### 6.3 Kani harness evidence (chio-attest-verify Kani harness) - BLOCKED

Artifact A: a Kani harness file. But which production entry it pins is
named with non-existent functions (see Section 3.1). Until those names
are correct, this ticket cannot enter EVIDENCE-PENDING.
**Blocked on Section 3.1 patches.**

### 6.4 Kani harness evidence (chio-anchor Kani harness) - BLOCKED

Same as 6.3, plus the Kani-budget feasibility spike is missing
(Section 3.2). **Blocked.**

### 6.5 release work-A4.1 (Allow split + ReceiptBeforeAllow) - PASS-with-watchout

Artifact A: `formal/tla/RevocationPropagation.tla` extended.
Artifact B: TLA spec (the property is named in the new module).
Artifact C: apalache run with the new INVARIANT.
Artifact D: a counterexample run if the invariant is removed.
The ticket does not require Artifact D ("if the invariant is removed,
apalache must produce a violating trace"). It should.
**Patch (MINOR)**: add to release work-A4.1 acceptance: "remove the
`ReceiptBeforeAllow` invariant from the cfg and confirm apalache produces
a counterexample trace within a length-6 budget. Capture trace to
`audits/evidence/release work-A4.1/counterexample-on-revert.tla`."

### 6.6 release work-A4.4 (apalache-temporal required) - PASS-with-watchout

The ticket includes "remove `continue-on-error: true`" and "configure
branch protection" but does not include a screenshot or json export of
the protection state (see Section 4.4).

### 6.7 release work-A5.3 (negotiation_safety re-prove) - INCOMPLETE

Artifact A: `formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean`
rewritten.
Artifact B: theorem-inventory.json row.
Artifact C: Lean CI run.
Artifact D: revert-and-rerun. The ticket does not require a procedure
for "revert the executable model term and confirm the proof fails".
**Patch**: add to release work-A5.3 acceptance: "after merge, replace the
executable-model term body with the schemaCeilingCheck-only one-liner
and confirm Lean elaboration fails."

### 6.8 release work-A5.4 (theorem-inventory promote) - PASS

Updates a JSON row. Artifact A is the JSON itself. Artifact B is the
proof that landed in release work-A5.3. Pass.

**Sample summary**: 3 pass-clean, 2 pass-with-watchouts, 2 fail Artifact
A specificity (A2 weak rows), 2 blocked on harness-design rewrite.

---

## 7. Anti-pattern repeat - explicit ticket-level rule-out (MAJOR)

I checked each Quality-Skeptic anti-pattern against the corresponding Lane
A ticket acceptance.

### 7.1 `caught: 0, ran_at: "1970-01-01T00:00:00Z"` (PASS)

release work-A2.<n> tickets each cite the trio "caught >= 1", "needs_real_run:
false", "ran_at non-1970" (`planning docs:42-50`). The acceptance text
literally enumerates the anti-pattern fields and forbids them. **Pass.**

### 7.2 `rfl`-tautological proof (PARTIAL)

release work-A5.3 says "The proof body is **not** `rfl` against
`schemaCeilingCheck`'s own definition" (PLAN.md:319).
This rules out the SPECIFIC tautology pattern of the existing theorem.
But it does not rule out a different rfl tautology against the new
executable model. If the executable model is defined in a way that the
re-stated theorem reduces by definitional unfolding, rfl works again
(albeit more honestly).

**Patch (MINOR)**: release work-A5.3 acceptance should additionally state: "the
proof body must include at least one of `cases`, `induction`,
`split_ifs`, or `intro`-followed-by-non-rfl; a one-line `by ...` proof
that elaborates without case analysis fails the close bar."

### 7.3 File-exists/no-`unimplemented!()` gate (PASS)

The Lane A close bar promotes the runtime backstop in
`scripts/check-threat-coverage-mutants.sh` from advisory to required
(threat-evidence-backfill.md:93-96). After Lane A closes, the
file-exists gate is no longer the gating signal; the per-row mutation
gate is. **Pass.**

### 7.4 Mutation kill on test code instead of trust-boundary lines (PARTIAL)

The mutation runner config (`.cargo/mutants.toml`:164-203) excludes
`**/tests.rs`, `**/tests/**`, `**/benches/**`, etc. The exclusion list
is reasonable.

But the `chio-guards/src/external/**` and `chio-policy/src/rulesets/**`
exclusions are broad globs. The plan does not re-audit these for release work
(see Section 1.2). If `chio-guards/src/external/` contains real
defensive code, excluding it lowers the kill-rate target by hiding
mutation-killable lines. This is the "measured on test code" anti-
pattern in disguise.

**Patch**: tied to Section 1.2 patch (mutation exclusion audit audit ticket).

---

## 8. Owner-class coverage (MINOR + OBSERVATION)

OWNERS.toml lines 16-46 define Lane A's primary role as `substrate-rust`
with secondary roles `formal-tla, formal-lean, formal-kani,
threat-modeling, quality-rust`. The owner-class definitions
(`OWNERS.toml:117-133`) are realistic single-line descriptions.

### 8.1 Single-owner risk (OBSERVATION)

`single_owner = "release owner"` for the entire trajectory; `human_assignment
= "TBD"` for each lane. Lane A's 46 tickets across formal-methods, Rust
mutation engineering, Lean theorem proving, TLA+ apalache, and threat-
model wiring is too much for one human. This is a process risk, not a
plan-quality issue, but it amplifies every other risk in this review.

### 8.2 No tickets are orphaned (OBSERVATION)

Every release work-A<n>.<m> ticket maps to one of the five owner classes via the
sub-lane primary role assignment in OWNERS.toml. Good.

### 8.3 Cross-lane overlap on `crates/chio-anchor/` (MINOR)

OWNERS.toml lines 102-110 records `crates/chio-anchor/` as overlapping
A, B, C. Specifically:
- Lane A owns `crates/chio-anchor/src/lib.rs` (and the new
  `kani_public_harnesses.rs` file).
- Lane B owns `crates/chio-anchor/src/batch.rs`.
- Lane C owns `crates/chio-anchor/src/web3.rs`.

The Lane A Kani harness (Kani harness evidence) targets functions in
`batch.rs` (which Lane B owns) and `witness.rs`. There is no orchestration
described for the case where Lane B's `batch.rs` rewrite changes the
function signature Lane A's harness depends on.

**Patch (MINOR)**: Kani harness evidence should explicitly call out Lane B
coordination: the Kani harness depends on `verify_anchor_batch` shape,
which Lane B may modify. Add to acceptance: "if Lane B revises the
`verify_anchor_batch` signature, this harness is updated within the same
PR or one wave behind, never more than one wave behind."

---

## 9. Risk - threat row unprovable in current architecture (MAJOR)

R3 in the Risk Register captures this. The escalation criterion is
">4 of 21 rows tag as `provable-only-in-trj6`". This count is at the
threshold of where I think the actual deferral count will land (see
Section 2.4). The triage protocol has THREE acceptable outcomes: provable
in release work, defer to trj6, or downgrade banner. The plan accepts all three;
no row is claimed to be load-bearing if it cannot be backed.

This is correct in shape. **Patch (MAJOR)**:

(a) Wave 1 must produce the per-row triage. R3 mitigation says "Wave 1
reviews each of the 21 rows and tags `provable-in-release work` /
`provable-only-in-trj6`. The tag is recorded in the JSON." (R3 line
124-125). This is critical-path; the Wave 1 review cannot defer this to
later.

(b) The "tag is recorded in the JSON" is informal. Define the exact JSON
field and the schema check. Suggested: add a top-level field
`triage_status` to each `audits/evidence/threats/<id>.json` with values
in {`provable-in-release work`, `provable-only-in-trj6`, `architecture-blocked`}.
The runtime gate script checks this field is set.

(c) The downgrade-banner protocol is named (R3 line 127-128: "<n> of 21
covered, <m> deferred to trj6"). Good. But the synthesis ship-bar 1 says
"all 20 ... real `caught >= 1` data". If 4+ rows defer to trj6, ship-bar
1 is not met. R3 quietly admits this; the banner protocol IS the
narrowing. This should be made explicit in `lane-a-floor/README.md`
under "Acceptance" so reviewers do not get a "65%/65%" green ship-bar
with a quietly missing 4 rows.

---

## 10. CI integration - workflow-by-workflow audit (MAJOR + MINOR)

The plan should name the actual `.github/workflows/` files that gate each
Lane A artifact and the promotion-of-advisory-to-required steps.

### 10.1 What the plan names (OBSERVATION)

- `mutants.yml` (PLAN.md:80, A1).
- `mutants-banner.yml` (mutation-budget.md:83, A1).
- `nightly.yml` (kani-harness-design.md:131, A3).
- `apalache-safety.yml` (tla-rewrites.md:18, A4 - existing required).
- `apalache-temporal.yml` (tla-rewrites.md:19, A4 - currently advisory,
  promoted by release work-A4.4).
- `lean.yml` (lean4-fix.md:166, A5 - to be created by release work-A5.1).

I confirmed all five existing workflows actually exist in
`.github/workflows/`. Good. `lean.yml` is correctly tagged as new.

### 10.2 What the plan does NOT name (MAJOR)

- `ci.yml` - the PR-tier mainline workflow. The Kani PR job
  (`kani-public-pr` per `nightly.yml:60`) is in `ci.yml` lines 478-590.
  Adding three new harnesses changes the PR-tier Kani matrix. The plan
  does not name `ci.yml` as a Kani workflow that A3 modifies. This is
  a real gap: a PR-tier change without a CI rebuild plan stalls the
  PR queue.
- `close-bar-tracker.yml` - the meta-workflow that runs the release work
  Evidence Gate check script (templates/EVIDENCE-GATE.md section 3.5).
  The plan does not call out which Lane A close-bar promotion edits this
  workflow. If `check-release work-evidence-gate.sh` is a Wave 1 deliverable
  (per the Evidence Gate doc), Lane A tickets implicitly depend on it,
  but there is no cross-reference.
- `mutants-fuzz-cocoverage.yml` - exists in `.github/workflows/`. Not
  mentioned in the plan. May be irrelevant; should be confirmed.

**Patch (MAJOR)**: add a section to `lane-a-floor/README.md` titled
"CI workflow inventory". Enumerate every workflow file Lane A touches,
the touch type (modify, create, delete, gate-promotion), and the ticket
that owns the change. Add to the Evidence Gate close bar: each release work-A
ticket that changes CI must name the workflow file diff.

### 10.3 Promotion-of-advisory-to-required is half-specified (MINOR)

`apalache-temporal.yml` advisory-to-required is the only promotion
specified (release work-A4.4). The plan does not specify whether the new
multi-crate Kani lane (Section 3.3) starts as advisory or required. The
default for new lanes is advisory; without an explicit promotion ticket,
the harnesses pass nightly but a regression in `chio-attest-verify`
Kani would not block a PR. This contradicts the synthesis ship-bar 1
which says "the README banner reads >=65% with the per-crate breakdown
attached" - a regression that breaks the banner without blocking PR is
banner-vs-reality drift in real time.

**Patch (MINOR)**: add a Kani harness evidence ticket: "Promote the new chio-attest-
verify, chio-anchor, chio-weights Kani lanes from advisory to required
after two consecutive green nightly runs. Update branch protection
accordingly."

---

## 11. Verdict and summary

**APPROVED-WITH-FIXES.**

The plan is the right shape. It honors the Quality Skeptic's specific
critiques. It is honest about what does not yet exist. The 46-ticket
expansion is large but the per-row granularity matches the trj4
EXECUTION-BOARD pattern.

It does not yet ground the Kani harness target names in actual production
function names (BLOCKER 3.1), it does not ground the Lean target proof in
the actual Rust signature (BLOCKER 5.1), the Kani CI integration is a
sketch not a plan (BLOCKER 3.3), and the per-ticket Artifact A specificity
in Lane A2 is too loose (BLOCKER 6.2).

These are not "rewrite the plan" issues. They are "fix the four files"
issues. Three to four engineer-days of plan-fix work clears them.

After the BLOCKER and MAJOR patches in Sections 1, 2, 3, 5, 6, 9, 10 are
applied, Lane A is ready to start Wave 1 measurements.

### 11.1 Severity tally

| Severity | Count | Sections |
|---|---|---|
| BLOCKER | 4 | 2.3, 3.1, 3.3, 5.1, 6.2 (the A2 sample) |
| MAJOR | 9 | 1.1, 2.4, 2.6, 3.2, 4.2, 5.2, 6.x watchouts, 7.4, 9, 10.2 |
| MINOR | 11 | 1.4, 2.7, 3.4, 4.3, 4.4, 4.5, 5.3, 7.2, 8.3, 10.3, R3-detail |
| OBSERVATION | 6 | 1.2, 1.3, 2.1, 2.2, 4.1, 5.4, 8.1, 8.2 |

(Tally counts findings, not patches; some patches address multiple
findings.)

### 11.2 Open questions for reviewer round 2

- Q1: Is TRJ4-033 closed? If not, A2 mobile rows are blocked on Lane A-
  external dependency.
- Q2: Does Apalache 0.50.x support the bounded transitive-closure
  unrolling encoding proposed in release work-A4.2? Without a feasibility
  spike, the depth-3 fallback to depth-2 is itself a target the plan
  does not test.
- Q3: Is the existing `mutants.yml` workflow currently green, or red
  with shard skips? The two-night history clock starts from the first
  green nightly.
- Q4: Are there `formal/proof-manifest.toml` and
  `formal/rust-verification/kani-public-harnesses.toml` both, or only
  one? Kani harness evidence references the former; the actual file I located is
  the latter.
- Q5: Will the Lean CI lane be blocking on PR (required) or only
  advisory at release work-A5 close? The plan does not say. If advisory, a
  regression to rfl tautology slips through.

### 11.3 Specific patches to apply

Files to edit and approximate diff shape (file paths absolute):

- `/.../lane-a-floor/kani-harness-design.md`: rewrite tables (1), (2),
  (3) to cite actual production entries. Add file-header section per
  harness on bound parameters and measured wall-clock. Rewrite Section
  on CI integration to specify per-crate manifest schema change and
  workflow shell-loop modification, not the matrix sketch (Section 3.1,
  3.2, 3.3).

- `/.../lane-a-floor/lean4-fix.md`: rewrite lines 75-85 to match the
  actual Rust signature including `CapabilityNegotiation` and
  `VerifiedCapability`. Expand release work-A5.3 to require three theorems, not
  one (Section 5.1, 5.2). Re-scope release work-A5.1 from M to L.

- `/.../lane-a-floor/threat-evidence-backfill.md`: add a "Public symbol
  invoked in test" column to the per-row table (Section 2.3). Update
  the bootstrap-bypass retirement to script-deletion (Section 2.6).

- `/.../lane-a-floor/planning docs`: each release work-A2.<n> ticket gains a
  required Artifact A line (Section 6.2). threat evidence item changes scope
  from doc-update to script-deletion (Section 2.6). Add mutation exclusion audit
  exclusion-audit and Kani harness evidence Kani-feasibility-spike tickets.

- `/.../lane-a-floor/PLAN.md`: extend "Per-sub-lane risk register" to
  reflect R3's per-row triage as a Wave 1 critical-path deliverable
  (Section 9). Add "CI workflow inventory" subsection (Section 10.2).

- `/.../lane-a-floor/tla-rewrites.md`: add feasibility-spike sub-task
  to release work-A4.2 (Section 4.2). Add wall-clock evidence requirement to
  release work-A4.3 (Section 4.3). Add branch-protection screenshot evidence
  to release work-A4.4 (Section 4.4).

- `/.../lane-a-floor/mutation-budget.md`: add a section on the
  `.cargo/mutants.toml` exclusion-list audit (Section 1.2, 7.4).

- `/.../architecture/RISK-REGISTER.md`: tighten R3 escalation threshold
  from ">4 rows" to ">2 rows" given the projected deferral count
  (Section 2.4, Section 9).

After these patches land, Lane A is ready to spin up Wave 1 measurements.
The honest framing the synthesis demanded ("Trajectory 5 is the honesty
trajectory") is intact: the plan does not over-claim, but it must not
under-specify the production entry points either, or the Evidence Gate
itself becomes a placeholder.

---

End of review.
