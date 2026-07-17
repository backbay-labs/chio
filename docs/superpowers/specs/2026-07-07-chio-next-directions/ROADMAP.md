# Combined roadmap: Chio next directions (A/B/C/D)

_Synthesized by the roadmap agent from the four researched+planned+reviewed directions. The keystone (A) plan is in A-*.md (produced separately after the workflow's A lane failed its structured-output cap)._

## Execution order

SEQUENCING (dependency graph: A=keystone unblocks the LIVE variants of B and C; A-prep, C-M1, and all of D run parallel; C stays sim/testnet-first).

Crucial correction the individual plans hide: as SCOPED, B (M1-M5) and C (M1-M4) do NOT need A implemented. B's static flagship + unified contract build on already-signed fixtures and existing types; C's sim rail targets the CLI/control-plane host, which already routes through the kernel guard. A gates only the OUT-OF-SCOPE variants (B's live agent-commerce-network flagship, C's api-protect-sidecar rail). So the real serialization is narrow, and B+C can run in parallel with A - PROVIDED A's execution_nonce + atomic-hold contract SHAPE is frozen first (see integration points; B publishes a governance-gated v1 schema that is expensive to re-version).

PHASE 0 - tomorrow, fully parallel, low-risk foundation + honesty:
- A (critical path start): fix the atomic-ledger gating bug (the fork's one real gating bug) and FREEZE the execution_nonce + atomic-hold contract as an interface/ADR, even before full sidecar mediation lands.
- C-M1 anti-self-dealing (2-3d, independent of everything) with the anchoring fix applied.
- D-M1 (ADR-0014/ADAPTER-SPEC reconciliation) + D-M2 (upstream iroh-gossip FR) - hours, pure honesty wins.
- B: apply the four paper corrections (M1 narration, M2 invariant, M3 signed-artifact registration, M5 test binary) before any code.

PHASE 1 - up to four concurrent tracks if staffed; a single engineer serializes A -> B -> C:
- Track A (long pole, serialized internally): kernel-guard mediation of the api-protect tool-call path with execution_nonce + atomic hold. MUST get its own adversarial review before B/C pin to it.
- Track B (parallel to A): M2 projection type+builder+endpoint (reserving the execution_nonce linkage field) -> M3 signed schema (corrected registration) -> M4 cross-language no-drift + optional signed export -> M5 lane gate (correct binary + nonzero-test guard). Serial internally.
- Track C (parallel, CLI host): M2 corrected fail-closed MustPrepay gate (moved into governed_validation stage) -> M3 CLI/config select adapter -> M4 no-key sim smoke. C-M5 (EIP-3009 ApprovalBinding) deferrable, after C-M2.
- Track D (parallel, second engineer): M3 RISK_REGISTER row, M4 feature-gate iroh out of default binary (only real break-the-build risk), M5 Swift CI.

PHASE 2 - convergence, AFTER A lands and passes review:
- B LIVE flagship variant wires the reserved execution_nonce field to real kernel mediation (no schema v2 because the slot was reserved in v1).
- C sidecar-hosted rail wires the governed x402 rail into chio-api-protect (blocked on A); the sim adapter now composes with A's execution_nonce.
- End-to-end LIVE narrated flagship: A hold -> B contract projection -> C rail + settlement fold, still non-claims/sim-testnet.

MUST serialize: A before Phase-2 LIVE B/C; B M2->M3->M4->M5; C M2->M3->M4; C-M5 after C-M2. CAN parallelize: all of D; C-M1; B's entire contract chain vs A vs C's sim rail. Single-engineer serial order: A ledger-fix+freeze -> C-M1 -> A keystone+review -> B M2-M5 -> C M2-M4 -> Phase-2 convergence -> C-M5; D interleaved or on a second person.

## Integration points

Seven seams where the four directions meet (this is the view no individual plan gives):

1. execution_nonce + atomic-hold contract (A) is consumed by BOTH B and C. ACTION: freeze its shape FIRST and reserve a linkage field in B's chio.comptroller.surface-report.v1 schema and in C's settlement receipt now, so the Phase-2 LIVE variants compose WITHOUT forcing a governance-gated schema v2. This is the single highest-leverage cross-cutting decision.

2. Shared atomic budget_store ledger (ADR-0006, confirmed at chio-kernel/src/budget_store*). A hardens it; B reuses it read-only as the projection source (M2); C charges against it via authorize_payment_if_needed. Because all three touch it, A's fix must precede B's projection freeze AND C's prepay-amount decision. Tie-in: C's open question "prepay quote.quoted_cost vs charge.cost_charged" is not just a C concern - whichever number is authoritative is the number B's exposure/spend projection must report, so decide it once, in A, and thread it to both.

3. B's unified data contract feeds C. C's settlement linkage and anti-self-dealing adjudication artifacts (C-M1) become referenced inputs in B's surface-report projection; C-M4's sim settlement receipt should surface into the same comptroller projection. Build B's projection with a slot for C's settlement + adjudication references.

4. Single signing authority: load_behavioral_feed_signing_keypair signs B's export, C/A receipts, and adjudication artifacts. Keep one authority; do not fork a second signing path.

5. Signed-artifact allowlist (registry.json + KNOWN_SIGNED_ARTIFACT_SCHEMAS + built_in_signed_artifact_registry + MANIFEST + checked_chio_schema_roots, confirmed live in scripts/check-chio-schema-registry.sh:111). B-M3 adds the surface-report entry; C-M1 adjudication and any C settlement artifact flow through the SAME allowlist. Coordinate these edits (merge-collision + ordering) and enforce the signed-artifact-only semantics from B-M3's correction across both.

6. Release-qualification lane (xtask launch_acceptance, check-chio-transaction-passport.sh, qualify-release.sh). B-M1/M5 add gates, C-M4 adds the no-key governed-x402 smoke, D adds CI legs. All converge on one lane. Sequence lane edits to avoid clobbering, and make every new gate assert a nonzero executed-test count (see risks - false-green appears in both B-M5 and D-M5).

7. Non-claims discipline banner is shared by B's flagship narration and C's sim-first custody-neutral framing. One honesty posture, one banner, applied to every demo/receipt surface.

## Per-direction readiness

A (keystone) - NOT in this review packet; treat as UNVERIFIED. It carries the fork's one real gating bug (atomic ledger) and the execution_nonce/hold contract that B and C pin to. READINESS GATE: A needs its own adversarial review BEFORE B-M3 publishes its v1 schema and before C settlement receipts reference the nonce - otherwise a schema-governed contract pins to an unreviewed interface and you pay a v2 churn. Freeze the interface first, implement second, review before pinning.

B (needs-revision) - target is REAL (the unified spend/exposure contract genuinely does not exist; registry has 248 artifacts, zero exposure schema; dashboard/src/types.ts is hand-maintained). Four fixes MUST land before/within the affected milestones: (M1) narrate honestly - do not assert the allow and deny are two occurrences of mandate-commerce-001 (the receipts carry no amount/mandate link); use independent narration or build the deferred sealed fixture. (M2) re-anchor validate_consistency to a real single-domain invariant on fields that exist (governed_max_exposure_units does not exist); treat Option::None ceiling as no-ceiling/fail-safe. (M3) flip the default - register the signed contract into KNOWN_SIGNED_ARTIFACT_SCHEMAS + built_in_signed_artifact_registry + registry.json + MANIFEST + checked roots, OR go unsigned and do not register at all; drop the false exposure-ledger precedent. (M5) target receipt_query_export (not the receipt_query stub) and assert nonzero tests run. KEEP: ComptrollerSurfaceReport in chio-kernel/operator_report/ (dep direction correct, module confirmed split), the --require verify command, passport/launch_acceptance/signing reuse. Verdict: sound and targeted, not a rewrite - but do not start M3/M5 until the corrections are folded.

C (needs-revision) - premise is RIGHT (productize, do not rebuild). One blocking fix: (M2) the fail-closed MustPrepay gate is placed AFTER the charge_result==None early-return, so a governed MustPrepay intent with no budget charge executes UNPAID - the fail-open persists exactly where it matters. Move the gate into the governed-intent validation stage (governed_validation.rs), thread payment_adapter_configured, fire for every MustPrepay regardless of charge_result, and add the currently-uncovered test (no charge + no adapter => DENY). Without that test the property is unproven. (M1) restore the "anchored in a registry" property - a bare Vec<String> roster is per-adjudication-fabricable by the key holder; bind a signed roster id/hash into the adjudication (folded into adjudication_id) and add a CI/grep test that all three liability artifacts construct only at sites calling validate_against_roster. (M3) reframe the load-time reject as config-consistency only; M2 runtime gate is the real enforcement. Correct the framing: control-plane reaches chio-market via chio-core re-export. C-M5 stays deferrable/digest-only. Verdict: do not start M2 without the gate-placement fix.

D (solid) - ready to start as-is; fold refinements during execution. (M1) reconcile ADAPTER-SPEC section 7's signer_id->EndpointId bullet (resolved by the same commit 7f8e156d3); do not claim "section 7 needs no change." (M5) do not hardcode -scheme Chio (use the Chio-Package test-inclusive scheme), assert nonzero test count, pin the simulator destination, and confirm the ChioFFI systemLibrary modulemap resolves against the simulator slice. (M4) the cfg(not(feature=iroh)) arm must consume ALL iroh_* fields (not just iroh_enable) to survive -D warnings, and place the fail-closed error at the inner serve/tick. (M2) also anchor the FR URL in the section 7 topic-membership bullet. Verdict: green light tomorrow, second engineer.

## Risks + guardrails

FAIL-CLOSED / FALSE CLOSURE (top risk, recurs across A/B/C): enforcement must sit at the true choke point, before any early-return, and tests must cover the edge/no-charge path, not just the happy path. Concrete instances: C-M2's MustPrepay gate currently sits after the charge_result==None early-return (fail-open) and B-M1 narrates a mandate linkage the artifacts do not carry (overclaim). Guardrail: for every fail-closed claim, name the exact path that would bypass it and write the test that exercises that path.

NO FALSE GREEN / zero-tests-run (recurs in B-M5 wrong-binary and D-M5 wrong-scheme): a filter that matches 0 tests exits 0 and masquerades as passing. ROADMAP-WIDE RULE: every new acceptance gate must assert a nonzero executed-test count (grep for "N passed" with N>0 / fail on "0 filtered out ... 0 passed" / parse the xcresult). Apply to B-M5, C-M4, D-M5, and any launch_acceptance addition.

CUSTODY-NEUTRAL: C stays sim/testnet-first, digest-only, no broadcast; C-M5 (EIP-3009 ApprovalBinding) is deferrable and prepare-only. Keep the EVM/digest logic at the CLI/control-plane layer, not in the kernel payment adapter (kernel already depends on chio-settle, so no cycle, but keep the rail adapter rail-agnostic). Custody is a Year-2 goal; nothing here should assume it.

SCHEMA-VERSIONING TRAP: B-M3 publishes a governance-gated signed v1 that is expensive to re-version. Reserve the A execution_nonce/hold-link and C settlement/adjudication reference slots in v1 now, or Phase-2 forces a v2. Also: register the signed artifact correctly (KNOWN + built_in + registry.json + MANIFEST + checked root) or the standard fail-closed verifier will REJECT it while tests still pass (semantically broken but green).

IROH CONTAINMENT: D feature-gates iroh out of the DEFAULT shipped chio binary (fail-closed handler when absent) while stating plainly the workspace still compiles iroh. Add the CI leg so the ~20 gated CLI tests do not rot, and consume every iroh_* field in the not(iroh) arm for -D warnings. iroh federation remains a deferred Year-2 transport - do not let A/B/C take a hard dependency on it.

AUDIT ANCHORING: C-M1 roster and B/C signed artifacts must be anchored (signed roster id/hash bound into the adjudication), not per-call fabricable by the key holder - otherwise the guard proves nothing in an audit.

REVIEW-BEFORE-PIN: A must pass its own adversarial review before B's schema and C's receipts pin to its interface.

## First concrete milestone

Start A's foundation: fix the atomic-ledger gating bug and FREEZE the execution_nonce + atomic-hold contract as a written interface/ADR (the actual ledger fix in chio-kernel/src/budget_store*, plus the contract shape that B and C will pin against). Rationale: it is the fork's one real gating bug, it is the keystone every LIVE variant composes on, and freezing the nonce/hold SHAPE now is the single decision that lets B's governance-gated v1 schema and C's settlement receipts reserve their linkage slots and avoid a costly Phase-2 schema v2. Decide the prepay-amount authority (quote.quoted_cost vs charge.cost_charged) here too, since both B's projection and C's gate depend on it.

Launch same-day in parallel (independent, cheap, honest): C-M1 anti-self-dealing with the roster-anchoring fix (2-3d self-contained win), and D-M1 (ADR-0014/ADAPTER-SPEC section-7 reconciliation) + D-M2 (upstream iroh-gossip FR) as hours-long honesty wins. While those run, apply B's four paper corrections so B-M2 can begin against the frozen A interface without rework. Do NOT begin C-M2 or B-M3 until their respective review corrections are folded.
