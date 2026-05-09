# R3: Lane B Spec-Compliance Review

**Reviewer**: Wave 2 Reviewer (Protocol Realization Engineer perspective)
**Date**: 2026-05-07
**Scope**: Lane B sub-lanes B0/B1/B2/B3 against Evidence Gate Artifacts A-D, with focus on whether the proposed conformance fixtures actually exercise the production hot path or merely "test the schema". The lens is the trj4 erratum's "structural framing without runtime wiring" pattern.

---

## Executive summary

Lane B's design documents are unusually disciplined for this codebase. The conformance-fixture-spec, evidence-gate, and per-sub-lane deep dives correctly identify the trj4 anti-patterns and write rules to defend against them. Spot-checks of the cited code locations confirm the diagnostics are accurate: `verify_capability_signature` at `mod.rs:4005` and `verify_capability_full_without_budget_admit` at `mod.rs:4035` are real, the warn-and-downgrade at `mod.rs:1574-1591` exists exactly as cited (the W1 correction from `:1148-1165` is correct), the dispatch sync-helper hop at `mod.rs:6402-6442` is real, the sync wrapper at `batch.rs:227-235` is real, and `chio-kernel-mobile/Cargo.toml` does indeed depend on `chio-kernel-core` and not `chio-kernel`.

That said, the review identified **three BLOCKERS, six MAJOR findings, four MINOR findings, and three OBSERVATIONS** that must be resolved before Lane B opens its first close PR. The most concerning is finding #4 (B2 fail-closed scope drift): the design proposes failing closed when a peer is named but not pinned fresh, but PROTOCOL.md never claims pin-freshness implies v2-required. The plan synthesizes a normative MUST that does not exist in the spec and that the cited line range (737-741) does not in fact authorize. Before B2 ships, the spec edit must come first or the review must accept that B2 is not strictly tightening an existing rule, it is inventing one. Either is defensible; the doc must pick.

The B3 gate-script algorithm is also weaker than represented: it is a 50-line-window grep heuristic that will miss real bugs (multi-file producer setups, function calls that hand a `WitnessPolicy` through three layers) and false-positive on advisory-mode policies that happen to live near sync-wrapper calls. The plan acknowledges false-positives are "tolerated" and false-negatives are "not", but the implementation cannot guarantee that contract; promote it to a Cargo `xtask` that AST-parses the call sites or accept the soundness gap as documented.

The B1 fixture is the strongest of the three: it counts `BudgetRegistry::try_admit_share` calls against the real registry, which is a direct observation of the production path and would catch the noop-substitution. B0 is sound and well-scoped. The Evidence Gate state machine is rigorous and the close protocol is parser-checkable. The forcing-function (R4) is wired in via Lane C dependence on Lane B fixtures.

**Verdict**: APPROVE-WITH-CHANGES. Lane B may begin B0 and B1 immediately. B2 must resolve the spec scope question before its spec edit. B3 must either harden its gate script or accept the soundness gap with a tracking ticket.

---

## Findings

### 1. Production-call-path rule (Evidence Gate Artifact D)

**Verdict**: B0 OBSERVATION (no fixture). B1 PASS. B2 PASS. B3 PASS-WITH-RESERVATION.

#### B0 (no Lane B fixture; the existing `v2_receipt_kernel_round_trip.rs:58-77` echoes the trait change)

B0 has no Artifact-C deliverable of its own; it is the architectural prerequisite. The `async-trait-migration.md` correctly notes that the existing `EchoToolServer` impl in `v2_receipt_kernel_round_trip.rs:58-77` is updated to the async trait without behavior change. This is sufficient because B0 ships no normative MUST.

OBSERVATION: a B0 sanity test that asserts `dispatch_tool_call_with_cost` does NOT contain a sync-helper delegation is named in `async-trait-migration.md` section 3 step 4 ("Add a regression test that asserts ... grep-based, brittle but cheap"). This is a static lint, not a fixture. That is fine for B0; do not mistake it for an Artifact C.

#### B1 (PASS)

`single-entry-verifier.md` section "Negative conformance fixture" is the strongest design in Lane B. It:

- Imports the production `ChioKernel` from `chio_kernel`, not a copy (Artifact D rule satisfied per `CONFORMANCE-FIXTURE-PATTERN.md` section 2.2).
- Builds a real `ChioKernel` via the same `make_kernel` shape as `v2_receipt_kernel_round_trip.rs:92-115`.
- Drives `evaluate_tool_call_blocking` (the same entry every production caller hits).
- Observes `BudgetRegistry::try_admit_share` mutations on the actual registry. This is a direct observation of the production-path side effect: the deleted `verify_capability_full_without_budget_admit` substitutes `chio_kernel_core::NoopBudgetRegistry` (verified at `mod.rs:4045`), so a noop count of zero would distinguish the partial path from the full path.

The fixture would in fact fail when B1.2 is reverted; the design is sound.

#### B2 (PASS, but see finding #4 for the spec MUST question)

`receipt-v2-failclosed.md` section "The conformance fixture" cites the same `make_kernel` shape and exercises `evaluate_tool_call_blocking`. The three sub-tests (`v2_capable_peer_pinned_fresh_mints_v2`, `v2_negotiation_with_stale_pin_rejects`, `no_peer_named_kernel_default_v1_mints_v1_only`) drive the production mint path through `record_chio_receipt_with_federation` (`responses.rs:1405-1427`) which calls `kernel_receipt_version_for_remote` (`mod.rs:1569-1592`). Spot-check at `responses.rs:1405-1427` confirmed this is the real propagation point; the design correctly targets it.

The fixture would fail when B2.2 is reverted to the warn-and-downgrade form at `mod.rs:1574-1591` because sub-test 2 expects `KernelError::ReceiptNegotiationDowngrade` and the reverted kernel returns `Ok(Verdict::Allow)` with a v1 receipt.

**Reservation**: the fixture's helper functions (`register_v2_capable_peer`, `advance_kernel_clock`, `count_v1_receipts`, `count_v2_receipts`) are not yet implemented and the design does not specify whether they live in `chio-conformance/tests/common/` or as `pub(crate) #[cfg(test)]` accessors on `ChioKernel`. If `count_v2_receipts` requires a new `ChioKernel::test_only_count_v2_receipts` accessor, that approaches the `EVIDENCE-GATE.md` section 8.3 anti-pattern of "side-effecting setup that bypasses the gate". Recommend: read counts from the real `chio_receipts_v2` SQLite table directly (the test already opens a real `SqliteReceiptStore` at `make_kernel`), not via a kernel-side accessor.

#### B3 (PASS-WITH-RESERVATION)

`anchor-batch-async-only.md` section "The conformance fixture" imports `chio_anchor::{build_anchor_batch, verify_anchor_batch_with_witness_policy, ...}` from the real production crate. The fixture exercises the gated function directly. PASS.

Reservation: the fixture builds the batch via `build_anchor_batch` (production), then mutates `batch.body.witness_state` to `WitnessState::Witnessed` after construction. This pattern is borrowed from `anchor_batch_forged_root_rejected.rs` and is acceptable because the mutation is on a value that the caller owns; nothing in the production path is mocked. The gate at `batch.rs:227-235` is exercised verbatim.

### 2. Fails-when-reverted proof

**Verdict**: B1 PASS. B2 PASS (with one wording fix). B3 PASS.

The Evidence Gate (section 1.4 Artifact D) requires either (a) a CI run URL, or (b) a `git stash`-style local-reproduction procedure. The Lane B docs operationalize this as the "Reverse-test" section in PR descriptions, per `conformance-fixture-spec.md` section 5.

`single-entry-verifier.md` line 101 names the reverse-test path: "intentionally revert B1.2 on a draft branch and run this fixture; record that it FAILS with the structured reason". This is the (b) form; acceptable.

`receipt-v2-failclosed.md` line 173 names the reverse-test: "revert B2.2 on a draft branch (restore the `tracing::warn!` + `return V1Legacy` block at `mod.rs:1574-1591`)". The wording at the bottom of the file says "sub-test 2 FAILS because the dispatch now returns Allow with a v1 receipt". Spot-check at `mod.rs:1574-1591` confirmed the warn-and-downgrade block is exactly what the revert restores. PASS.

MINOR: `receipt-v2-failclosed.md` line 36 mentions the synthesis-cited line range was `mod.rs:1148-1165` and corrects it to `1574-1591`. The doc explains `1148-1165` is actually the `KernelReceiptVersion::from_capabilities` resolver helper (peer-profile -> version mapping). Spot-check at `mod.rs:1148-1158` confirmed: `from_capabilities` is at line 1151. The correction is right. The original synthesis at `00-SYNTHESIS.md:31` should be updated by the audit-doc maintainer; this is a process note, not a Lane B blocker.

`anchor-batch-async-only.md` line 188 names the reverse-test: "revert B3.2 on a draft branch (remove the early-return). Run `cargo test -p chio-conformance --test anchor_batch_sync_path_rejected_under_public_witness`; the first sub-test FAILS because the sync function now reaches the structural verify and returns either Ok or a different error". PASS.

### 3. Single-entry verifier (B1) caller migration completeness

**Verdict**: PASS, with one ENRICHMENT note.

The plan identifies four hosted call sites:

- `mod.rs:2452` (calls `verify_capability_signature`).
- `mod.rs:2706` (calls `verify_capability_signature`).
- `mod.rs:2898` (calls `verify_capability_full_without_budget_admit`).
- `mod.rs:3403` (calls `verify_capability_full_without_budget_admit`).

I independently verified via `grep -n "verify_capability_signature\|verify_capability_full_without_budget_admit" mod.rs`:

```
2452:        self.verify_capability_signature(capability)
2706:        if let Err(reason) = self.verify_capability_signature(cap) {
2898:        if let Err(reason) = self.verify_capability_full_without_budget_admit(
3403:        if let Err(reason) = self.verify_capability_full_without_budget_admit(
4005:    fn verify_capability_signature(&self, cap: &CapabilityToken) -> Result<(), String> {
4035:    fn verify_capability_full_without_budget_admit(
```

The four call-site lines and the two helper definitions match exactly. Test-only callers do not appear in this grep because `verify_capability_signature` is a `fn` (private) on `ChioKernel`; tests cannot call it. PASS for completeness.

ENRICHMENT: the plan at `single-entry-verifier.md` line 65 says the migration replaces

```
self.verify_capability_signature(capability)
    .map_err(|_| KernelError::InvalidSignature)?;
```

with

```
self.verify_capability_full_hosted(capability, None, agent_id, current_unix_timestamp())?;
```

The error-mapping change is non-trivial: `verify_capability_signature` returns `Result<(), String>` and the caller maps to `KernelError::InvalidSignature`, which is a generic. The full verifier returns richer errors (`SchemaExceedsNegotiatedCeiling`, `AttenuationViolation`, `InvalidCapability`), which the call site at `mod.rs:2452` (the resource/prompt path) currently has no error-routing infrastructure for. Recommend B1.2 expand the acceptance criterion to include "the call site emits a typed deny reason that distinguishes signature failure from chain-binding failure from schema-ceiling failure". Otherwise the production benefit of the unified verifier is silently flattened back to "signature did not verify" at this site.

The negative-conformance fixture's "only one entry exists" assertion is approached two ways in `single-entry-verifier.md` section "Negative conformance fixture" item 6: (a) a `compiletest_rs` or `trybuild` test that asserts `use chio_kernel::verify_capability_signature` fails to compile, OR (b) a runtime assertion. Both are acceptable. The doc says "B1.6 picks the simpler approach (likely a `trybuild` test)". This is fine, but `trybuild` is not currently a workspace dev-dependency; B1.6 must add it.

OBSERVATION: the kernel-local helpers are private (`fn`, not `pub fn`), so the `trybuild` test is verifying that no future PR adds a `pub` modifier or re-exports the symbols. That is a legitimate static guarantee but it is not the same as proving "no production call site uses a partial entry". The lint script `scripts/check-verify-capability-full.sh` is what proves the latter. Both are needed.

### 4. Receipt v2 fail-closed (B2): the spec scope question

**Verdict**: BLOCKER (#1).

This is the most substantive finding in the review.

PROTOCOL.md lines 737-741 read (verbatim, spot-checked):

> "Negotiation downgrade. When the peer profile is v1-only or when no federation peer is pinned fresh for the request, the kernel falls back to minting only the v1 UUIDv7 receipt. The downgrade emits a structured warning so operators can see receipt-version regressions in observability."

The current spec language explicitly authorizes the runtime behavior the kernel implements at `mod.rs:1574-1591`. The "falls back" wording is descriptive of the runtime, not a SHOULD that is being weaker than a MUST. **It is correct prose for what the code does.** There is no MUST to promote here; B1's `SHOULD -> MUST` move is straightforward, but B2's move is `current-behavior -> opposite-behavior`.

The Lane B plan is clear-eyed about this: `PLAN.md` Sub-lane B2 spec citation explicitly says the spec edit changes "falls back" to "fails closed". The receipt-v2-failclosed doc names the new typed error and provides the new function signature. Both are coherent. But the synthesis at `00-SYNTHESIS.md:104-106` framed B2 as "replace the warn-and-downgrade ... with a hard reject. PROTOCOL.md §714-741 changes 'falls back' -> 'fails closed'." That framing implies the spec was always normatively v2-required-under-v2-negotiation and the runtime drifted; the truth is the runtime is conformant to the current spec, and B2 is a normative tightening.

**Why this is a blocker**: per `EVIDENCE-GATE.md` section 1.2, "If the line range contains only `SHOULD`, the ticket has not yet promoted the spec language and MUST do so before close. Promoting `SHOULD` to `MUST` is part of the ticket scope; it cannot be deferred." But there is no SHOULD in lines 737-741 to promote. The spec edit is rewriting prose, not promoting a modal verb. The ticket can still close with a spec edit, but the PR description must accurately frame the change as "tightening" rather than "promotion".

Specific fixes:

1. `02-protocol-realization-engineer.md:19` says: "the spec language permits receipt v1 indefinitely; the conformance suite ... does not have a negative test that fails when a kernel built without `ACCEPTS_RECEIPT_V2` advertisement signs a governed receipt." This is the right framing.
2. `PLAN.md` Sub-lane B2 acceptance criterion 4 should be reworded to: "PROTOCOL.md lines 737-741 are rewritten to introduce a NEW normative MUST: 'When the peer profile is v2-capable but no federation peer is pinned fresh for the request, the kernel MUST reject the dispatch with KernelError::ReceiptNegotiationDowngrade'. This is a tightening, not a promotion." The current criterion 4 reads as if it were a promotion.
3. The reverse-test description in `receipt-v2-failclosed.md` line 173 is fine; the negative test still works because the new MUST is well-defined runtime behavior.

Additionally: the new fail-closed rule is asymmetric. **Case D** in `receipt-v2-failclosed.md` (federation v1-only fresh peer) still mints v1 normally, which is correct. **Case E** (federation, stale) becomes fail-closed. But what about a request that names a remote peer that has NEVER been pinned (i.e., not just stale, but never seen)? The current downgrade path treats this identically to stale. The B2 design says "always fail closed in Case E", which absorbs both. Recommend the spec edit explicitly names both "stale" and "never-pinned" as fail-closed, otherwise a future implementation could plausibly read "not pinned fresh" as "stale" only and re-introduce a bypass for the never-pinned path.

### 5. Anchor-batch async-only (B3): the gate-script soundness question

**Verdict**: MAJOR.

The proposed `scripts/check-anchor-batch-async-witness.sh` is a 50-line-window bash + grep heuristic. Per `anchor-batch-async-only.md` section "The gate-script algorithm" lines 50-92:

```bash
# Heuristic: if there's a WitnessPolicy { ... require_public_witness: true ... }
# nearby, flag it. False-positives are tolerable; false-negatives are not.
if grep -q 'require_public_witness:\s*true' <<< "$window"; then
    if [[ ! "$content" =~ verify_anchor_batch_with_witness_policy_async ]]; then
        failures+=("$file:$linenum: ...")
    fi
fi
```

The doc claims "false-negatives are not [tolerated]". But the script's contract cannot deliver this guarantee. Counter-examples that produce false negatives:

1. **The `WitnessPolicy` is constructed in a separate function** from where the sync wrapper is called. The 50-line window does not span function boundaries reliably; if the policy is built in module A and passed to module B's sync caller, the script fails to flag it.

2. **The `WitnessPolicy` is built from a deserialized JSON or YAML config**, e.g. `serde_json::from_str::<WitnessPolicy>(s)` or `let policy: WitnessPolicy = config.witness_policy.clone()`. The literal `require_public_witness: true` is in a config file, not in Rust source.

3. **The `WitnessPolicy` is built via a builder or setter** that does not use the literal struct-init syntax. `WitnessPolicy::default().require_public_witness(true)` does not match the regex `require_public_witness:\s*true`.

4. **Cross-crate calls**: a producer in `chio-anchor-foo` builds the policy and a consumer in `chio-anchor-bar` calls the sync wrapper with it. The 50-line window is intra-file.

The doc says "Implementation polish (regex tightening, multi-line policy struct support) is a B3.3 PR detail." This is insufficient. The script's stated contract ("false-negatives are not tolerated") is unachievable by a grep-window; either:

- (A) The runtime gate at `batch.rs:227-235` is the only real defense (the lint is defense-in-depth that catches obvious mistakes), and the doc says so explicitly.
- (B) The lint is upgraded to a real call-graph analysis (Cargo `xtask` walking syn-parsed AST, or a clippy-style pass).

**Recommendation**: pick (A). The runtime gate is the actual MUST enforcement; the lint is documentation. Update `anchor-batch-async-only.md` line 90 to read "False-negatives in the lint are tolerated because the runtime gate at `batch.rs:227-235` is the load-bearing defense; the lint exists to give developers fast feedback on the obvious cases." Otherwise B3 is shipping a contract it cannot keep.

This finding is upgraded to MAJOR rather than BLOCKER because the runtime gate does in fact close the spec MUST. The lint is only for early-warning; the soundness of the spec is preserved by the runtime gate alone.

### 6. Async-trait migration (B0): impl count audit

**Verdict**: MAJOR.

The plan claims "31 production-and-test impls" (`async-trait-migration.md` section "Production-path implementor inventory" + "Test-path implementor inventory" + a doc-test). My grep:

```
$ grep -rln "impl ToolServerConnection for" crates/ | wc -l
31

$ grep -rn "impl ToolServerConnection for\|impl .* ToolServerConnection for" crates/ | wc -l
47
```

The 31 number counts FILES with at least one impl. The 47 number counts impl SITES. Several files contain multiple impls (e.g. `chio-kernel/src/kernel/tests/all.rs` has six impls visible in the grep output). The plan's release work-B0.3 says "Update 11 production `ToolServerConnection` impls" and release work-B0.4 says "Update ~20 test-path impls". These 11+20 = 31 numbers match the file count, not the impl count.

The impact for diff sizing is small (each impl is mechanical: add `#[async_trait]`, change `fn` to `async fn`, add `.await` if any inner call became async). But the doc's blast-radius estimate is undercounted by ~16 impls. The PR description should accurately count impl sites, not files; otherwise the "diff size estimate" in `ASYNC-KERNEL-MIGRATION.md` section 5 is off by a similar percentage.

Specific list of files with multiple impls:

- `crates/chio-kernel/src/kernel/tests/all.rs` (lines 1298, 1318, 1409, 1430, 5266, 5299, 5328, 9664) - 8 impls.
- `crates/chio-mcp-edge/src/runtime/runtime_tests.rs` (lines 41, 73, 128, 155, 183) - 5 impls.
- `crates/chio-acp-edge/src/lib.rs` (1541, 1562) - 2 impls.
- `crates/chio-a2a-edge/src/lib.rs` (1634, 1655, 1676) - 3 impls.
- `crates/chio-openai/src/lib.rs` (561, 582) - 2 impls.
- `crates/chio-openapi-mcp-bridge/src/lib.rs` (329, 423) - 2 impls.
- `crates/chio-mcp-remote/src/remote_mcp/session_core.rs` (1838) - 1 impl (the doc said 2682 + 2860; my grep shows only 1838; investigate the discrepancy).

**Action**: release work-B0.1 is "Audit `ToolServerConnection` callers". Update the audit to count impl sites, not files, and resolve the `session_core.rs` line-number discrepancy. Update the diff-size estimate accordingly.

Re the `&mut self` setter count: synthesis line 38 cites "36 `&mut self` setters" and `async-trait-migration.md` section 5 repeats it. My count:

```
$ grep -c "&mut self" crates/chio-kernel/src/kernel/mod.rs
36
$ grep -nP "fn \w+.*\(\s*&mut self" crates/chio-kernel/src/kernel/mod.rs | wc -l
24
```

There are 36 occurrences of `&mut self` in the file but only 24 of them are method definitions. The remaining 12 are call sites or method bodies. The synthesis number is "occurrences", which is a sloppy proxy for "setters". The async-trait-migration plan correctly says these are out of scope and defers them to trj6, so the count error has no functional impact, but it should be corrected to "24 `&mut self` methods" (further refined to "X public setters" if anyone wants the exact count).

Re the `chio-kernel-mobile` claim: the README assumption 1 says the crate "depends only on `chio-kernel-core`". I verified:

```
$ grep -E "^chio-kernel" crates/chio-kernel-mobile/Cargo.toml
chio-kernel-core = { path = "../chio-kernel-core" }
chio-kernel-core = { path = "../chio-kernel-core" }

$ grep -rn "ToolServerConnection" crates/chio-kernel-mobile/
(no output)
```

PASS. The mobile crate does not import `ToolServerConnection`. The B0 migration is mobile-safe.

Re the rollback plan: `ASYNC-KERNEL-MIGRATION.md` section 6 enumerates trigger criteria and procedure. The trigger criteria are realistic (>1500 LOC across 8+ crates; >5% bench regression; wasm bundle-size regression). The procedure is "revert the trait change ... restore `dispatch_tool_call_with_cost_sync` as the production path. Lane B receipts the rollback in its plan: B1, B2, B3 wiring proceeds through the sync path with explicit ticket notes". This is realistic; PASS.

### 7. Spec MUST citations

**Verdict**: MAJOR (mixed). B1 PASS. B2 BLOCKER (see #4). B3 OBSERVATION.

Spec MUST inventory in PROTOCOL.md (verified by `grep -n "MUST\b" spec/PROTOCOL.md`):

```
281: "MUST dispatch from the signature prefix"
283: "MUST NOT contain concrete algorithm-set strings"
387: "attenuation_proof.parent_scope_hash field MUST be bound to the token's"
395: "A direct-issue v2 token (empty `delegation_chain`) MUST have"
398: "A delegated v2 token MUST have"
903: "Chio MUST NOT" (preview-tier)
```

There are six MUSTs in the entire normative spec. The Lane B plan presumes that B1 promotes a SHOULD (line 408) to a MUST and that B2/B3 introduce new MUSTs. The B1 promotion is verifiable: line 408 says "Production kernels SHOULD prefer the Wave 1.5 composite entrypoint" (verbatim, spot-checked). PASS.

B2's lines 737-741 contain neither MUST nor SHOULD; the prose is descriptive ("the kernel falls back to minting only the v1 UUIDv7 receipt"). The B2 spec edit is introducing a brand-new MUST. See finding #4.

B3's lines 980-993 use arrow notation ("`require_public_witness: true`, `Witnessed` on the sync path -> reject"). The arrows are prescriptive but not RFC 2119. The B3 spec edit at `PLAN.md` Sub-lane B3 spec citation reads: "Producers and consumers MUST route through `verify_anchor_batch_with_witness_policy_async` whenever `require_public_witness=true`. The sync entry point ... MUST reject any policy carrying `require_public_witness=true` at runtime."

This is a clean MUST addition. The arrow notation already constrains the runtime; B3 is making the routing rule load-bearing rather than the per-state rule load-bearing, which is a real (and small) tightening. PASS, but the Wave-1 audit-doc owner should note that the arrow notation is being upgraded to RFC 2119 MUST language.

The spec drift workflow (`spec-drift.yml`, mentioned in `CONFORMANCE-FIXTURE-PATTERN.md` section 6) is supposed to catch citations that resolve to lines without MUST. Per `EVIDENCE-GATE.md` section 3.5 step 2: "fails CI if ... Any cited line range in `spec/PROTOCOL.md` does not contain `MUST`." If B2's audit-doc cites lines 737-741 before the spec edit lands, the close-bar gate WILL fail. The plan correctly orders the spec edit (B2.4) before the conformance fixture (B2.5), so the CI gate will pass at the close PR.

### 8. Spec-to-runtime map completeness

**Verdict**: PASS, with one DEFERRED-trj6 question.

`SPEC-TO-RUNTIME-MAP.md` has rows for capability negotiation (section 1), receipt v2 (section 2), attenuation witnesses (section 3), anchor-batch (section 4), sibling-sum (section 5), hybrid PQ (section 6), metered billing (section 7), plus Lane C rows (sections 8-11). The first three Lane B in scope, the last three deferred per synthesis. Verified the deferral logic against `00-SYNTHESIS.md:134-144` "Out of scope (explicit)". Rows match.

The DEFERRED-trj6 question: section 6 (hybrid PQ wire format) cites `PROTOCOL.md` 4.1 lines 173-177, 4.4 lines 233-238, and 5 lines 277-285. Spot-check at line 281: "MUST dispatch from the signature prefix". This is one of the six existing MUSTs and the runtime is partially wired (`KernelTrustExchange` was lifted to a `SigningBackend`, per `02-protocol-realization-engineer.md:27`). The DEFERRED-trj6 designation is correct because the spec is already MUST and the runtime is partially compliant; the question is whether the partial compliance is bad enough to warrant release work scope.

`SPEC-TO-RUNTIME-MAP.md` line 77 says "kernel hot path still single-keypair", which would be a bypass of the existing MUST. Recommend the trj6 carry-over ticket explicitly note that this is an unwired existing MUST (not a new MUST waiting on a spec edit), so trj6 is closing an erratum-class gap, not introducing new functionality.

Section 5 (sibling-sum budget) is partially covered by B1.E because B1's fixture observes `try_admit_share` mutations; this is correctly captured in the map row.

OBSERVATION: section 5 row 2 references "TRJ4-118 sub-agent budget propagation" as deferred-trj6. If TRJ4-118 has shipped or is in flight in trj4 wave plan, the row should cite that explicitly so release work reviewers don't double-count work. This is a maintenance issue for the audit-doc owner; not a Lane B blocker.

### 9. Evidence Gate state machine

**Verdict**: PASS.

`EVIDENCE-GATE.md` section 3 defines OPEN -> EVIDENCE-PENDING -> EVIDENCE-COMPLETE. The transitions are machine-checkable per section 3.5 (CI gate via `scripts/check-release work-evidence-gate.sh`).

The "pretend close" defense at section 3.5 is strong: the script reads each `### release work-X.y` audit-doc block, parses paths, validates spec MUST citations, validates conformance test paths, validates audit-evidence JSON. If any cited path does not exist OR the spec line range lacks MUST OR the JSON has `caught: 0` / `ran_at: 1970-*`, the script exits non-zero. There is no `--force` flag.

The audit-doc evidence section format (section 3.4) requires:

- Enforced call site: file:line.
- Spec MUST: section + lines.
- Negative conformance test: file path.
- Production call path exercise: imports + failure proof.
- State.

This satisfies the four-artifact rule. PASS.

OBSERVATION: section 3.2 says "A ticket can sit in `EVIDENCE-PENDING` for at most one wave." Lane B has six weeks and four sub-lanes; if B1 lands its fixture in week 4 and the audit-doc update slips to week 5, the ticket is in EVIDENCE-PENDING for one week, which is fine per the rule. If the slip extends to two weeks, the rule says escalate or downgrade to trj6. The Lane B PLAN.md correctly schedules audit-doc updates inline with each fixture landing, so this risk is low. Not a blocker.

The planning docs per-sub-lane Evidence Gate close ticket (release work-B.CLOSE) is the right closing instrument: it requires each fixture to be deliberately reverted on a draft branch and confirmed to fail. PASS.

MINOR: the planning docs release work-B.CLOSE acceptance line says "the threat-row JSON references the fixture path; this ticket closes only when all three are confirmed by the reviewer." Per `EVIDENCE-GATE.md` section 3.3: "All four artifacts recorded in the audit doc. The audit doc has been signed off by both the lane owner AND a reviewer who is not the ticket author." The release work-B.CLOSE ticket should explicitly call out the second-reviewer requirement; otherwise, the lane owner could be the sign-off reviewer.

### 10. Forcing-function integrity (R4)

**Verdict**: PASS.

`RISK-REGISTER.md` R4 (lines 142-184) names the risk: "Lane C demo reveals a Lane B primitive isn't actually enforced". The mitigation:

- Lane C tickets START before Lane B closes (`PLAN.md` Sub-lane C scheduling with hard-deps on Lane B fixtures, per `lane-c-demo/PLAN.md:60-227`).
- Lane C release work-C*.E Evidence Gate tickets explicitly assert that the demo run exercises each Lane B primitive.
- Demo output receipts are committed as fixtures under `examples/<demo>/fixtures/`.

The Lane C plan at `lane-c-demo/PLAN.md` has 14 references to "Lane B" as a hard or soft dependency. C3 explicitly will not start if Lane B's receipt-v2 hot-path enforcement is not landed (line 360). C6 will not tag if Lane B's three negative conformance fixtures are not green (line 361). This is the continuous-validation hook.

The CI hook is implicit: if the Lane C `crates/chio-conformance/tests/cross_org_*` fixtures are running on every PR (per `.github/workflows/ci.yml` cargo-test invocation), then a regression in Lane B that would let the demo bypass a primitive would be caught. This satisfies R4.

OBSERVATION: the Lane C plan at `lane-c-demo/PLAN.md:332` says "Hard dep on Lane B's three negative conformance fixtures being [merged]". The plan does not say "and being green continuously". If a Lane B fixture is merged but later flakes, Lane C will not catch the regression unless the CI is configured to fail the build on chio-conformance test failures. Spot-check `.github/workflows/ci.yml` is out of scope for this review; recommend reviewer confirms the workflow does not allow `chio-conformance` failures.

---

## Specific patches

The findings above motivate concrete edits. File:line references below.

### Patch 1: receipt-v2-failclosed.md (BLOCKER from finding #4)

`receipt-v2-failclosed.md` line 102 (B2 spec citation paragraph) reads:

> "This 'falls back' language becomes 'fails closed'."

Recommend rewrite to:

> "PROTOCOL.md lines 737-741 currently authorize warn-and-downgrade with descriptive prose ('the kernel falls back to minting only the v1 UUIDv7 receipt'). B2's spec edit introduces a NEW normative MUST that did not previously exist: when the peer is named and v2-capable but pin freshness has expired (or the peer was never pinned fresh), the kernel MUST reject the dispatch with `KernelError::ReceiptNegotiationDowngrade`. This is a tightening of the v2 negotiation contract, not a SHOULD->MUST promotion. The reverse-test fixture is unaffected."

Also: clarify "stale" vs "never-pinned" (finding #4 last paragraph). The B2 design's case E covers both, but the spec edit should explicitly enumerate both attack scenarios.

### Patch 2: anchor-batch-async-only.md (MAJOR from finding #5)

`anchor-batch-async-only.md` line 90:

> "False-negatives in the lint are tolerated because the runtime gate at `batch.rs:227-235` is the load-bearing defense; the lint exists to give developers fast feedback on the obvious cases (literal `WitnessPolicy { require_public_witness: true, ... }` near a sync wrapper call). Cross-file or builder-pattern policy construction is acknowledged out of scope for the lint; the runtime gate fires regardless."

This rewords the contract honestly. The runtime gate at `batch.rs:227-235` IS the spec MUST enforcement; the lint is documentation.

### Patch 3: async-trait-migration.md (MAJOR from finding #6)

`async-trait-migration.md` section "Production-path implementor inventory" lines 30-46 (the 12-impl list) and "Test-path implementor inventory" lines 51-71 (the 18-impl list) need to be reconciled with the actual impl-site count of 47. The fix is small: add a note at the top of section "Blast-radius numbers" that "the 31 number is files; the impl-site count is 47 because several files contain multiple impls (notably `chio-kernel/src/kernel/tests/all.rs` with 8 impls and `chio-mcp-edge/src/runtime/runtime_tests.rs` with 5)."

`crates/chio-mcp-remote/src/remote_mcp/session_core.rs` was cited as containing impls at lines 2682 and 2860; my grep found only one impl (at line 1838). Investigate whether the session_core.rs impl was refactored since the doc was authored, or whether the line numbers refer to call-sites of `Box<dyn ToolServerConnection>` rather than impl declarations. If the latter, the doc should disambiguate.

### Patch 4: planning docs (MINOR from finding #9)

planning docs release work-B.CLOSE acceptance:

Add to acceptance: "Sign-off requires the lane owner AND a reviewer who is not the ticket author, per `EVIDENCE-GATE.md` section 3.3."

### Patch 5: single-entry-verifier.md (ENRICHMENT from finding #3)

`single-entry-verifier.md` section "Migration sequence" item 2 sub-bullet `mod.rs:2452`:

The error-mapping change is non-trivial. Add to acceptance: "B1.2 emits typed deny reasons distinguishing signature failure, chain-binding failure, and schema-ceiling failure at the four hosted call sites, rather than collapsing all into `KernelError::InvalidSignature`."

### Patch 6: PLAN.md (MINOR from finding #4 follow-up)

`PLAN.md` Sub-lane B2 acceptance criterion 4:

Change from "PROTOCOL.md lines 737-741 are rewritten as quoted in 'Spec citation' above" to "PROTOCOL.md lines 737-741 are rewritten to introduce a new normative MUST (this is a tightening, not a SHOULD->MUST promotion) per Patch 1 of R3 review."

---

## Open questions

### Q1 (BLOCKER): is the B2 fail-closed rule in scope for release work?

Finding #4 raised the question: B2 introduces a new MUST that did not exist in the spec. The synthesis at `00-SYNTHESIS.md:104-106` framed it as a tightening; the receipt-v2-failclosed.md doc treats it the same way. Provided the spec edit accurately frames the change, this is fine. But: is the "always fail-closed when the named peer is not pinned fresh" rule the right MUST? The alternative is a softer MUST: "fail-closed only if the kernel-level `receipt_v2_default()` is true". The latter is less invasive, less likely to break existing federation deployments, and still closes the original audit gap. The Lane B plan picks the harder rule. Recommend the synthesis owner ratify this choice explicitly.

### Q2 (MAJOR): does the `evaluate_tool_call_blocking` entry actually mutate the persistent budget registry, or only the in-memory one?

The B1 fixture observes `BudgetRegistry::try_admit_share` mutations. The kernel's `budget_registry` field at `mod.rs:4099-4101` is held under a `Mutex` that mutates in-process state. Whether `try_admit_share` also writes to the persistent store (SQLite) is unclear from the design. If it does NOT, the B1 fixture is observing an in-process side effect, which is fine for the fail-when-reverted test but does not fully prove the production budget-admit semantics under failure recovery. Recommend B1.6 PR description clarify whether the registry is in-memory-only or persistent, and what the failure model is.

### Q3 (MINOR): are the chiodos_pheromone, chiodos_ladder primitives definitely out of release work?

`SPEC-TO-RUNTIME-MAP.md` section 13 says yes (research drafts). The Productization Champion (debate position 5) and Vision Strategist (debate position 6) had pushed back on this in the synthesis discussion. Recommend the audit-doc owner confirm with synthesis authors that no chiodos primitive has migrated from "research draft" to "ready to wire" since 2026-05-07, otherwise a row may be missing.

### Q4 (OBSERVATION): does the `chio_kernel_core::NoopBudgetRegistry` survive Lane B?

`mod.rs:4045` substitutes `chio_kernel_core::NoopBudgetRegistry` for the partial path. After B1.3 deletes the partial-entry helpers, is `NoopBudgetRegistry` itself still needed in `chio-kernel-core`? It is exported as a public type for portable callers who genuinely want the noop semantics (e.g. the `chio_kernel_core::evaluate_with_full_floor` portable test infrastructure). Recommend B1.3 PR description confirm whether the type stays public or becomes test-only; if it stays public, the lint script needs to confirm `chio-kernel`'s production code does not import it.

### Q5 (OBSERVATION): does `trybuild` work for the B1 negative-conformance "compile-fail" assertion?

`single-entry-verifier.md` section "Negative conformance fixture" item 6 says "B1.6 picks the simpler approach (likely a `trybuild` test)". `trybuild` is a procedural-macro testing crate that ships test cases as standalone Rust files and compares compiler output. It is not currently in `[dev-dependencies]`. Adding it is a small addition; the Lane B PR should not assume it.

---

## Verdict

**APPROVE-WITH-CHANGES**. Lane B's design is consistent with the release work synthesis, internally coherent, and correctly diagnoses the trj4 erratum's failure modes. The conformance fixtures are designed to exercise the production hot path, observe production-path side effects (B1 budget registry, B2 receipt store rows, B3 typed error variant), and fail when the wiring is reverted. This is the Artifact-D contract.

The three findings that block close-PR readiness:

1. **B2's spec edit must be reframed** (Patch 1) before B2.4 lands. The current framing implies a SHOULD->MUST promotion when the spec actually has neither modal verb in lines 737-741. This is the BLOCKER.

2. **B3's lint-script contract must be honestly described** (Patch 2). The current claim that "false-negatives are not tolerated" is unachievable by a 50-line-window grep. Pick one: rewrite the contract or upgrade to AST-based analysis.

3. **B0's impl count must be corrected** (Patch 3). 31 is the file count, not the impl count; the impl count is 47.

The major findings 1, 5, and 6 are addressed by the patches above. Minor findings 4, 9, and observations 1, 2, 3 are tracking issues for the Wave-1 audit-doc owner.

**B0 and B1 may begin immediately**. **B2 must land its spec-edit ticket (B2.4) with the reframed wording before its conformance fixture (B2.5)**. **B3 must update the lint-script contract documentation before B3.3 lands**.

The forcing-function integrity (R4) is satisfied by Lane C's hard-dep wiring. The Evidence Gate state machine is parser-checkable and prevents pretend-close. The Spec-to-Runtime Map correctly defers hybrid PQ, attenuation witness resolver, and metered billing to trj6 per synthesis.

**Reviewer signature**: Wave 2 R3 (Protocol Realization Engineer perspective).

**Sign-off requirement**: per `EVIDENCE-GATE.md` section 3.3, Lane B audit-doc close requires lane-owner + non-author reviewer. This document is one such reviewer's report; a second reviewer (substrate-eng or refactor-eng class) should also sign.

---

## Appendix A: Anti-Pattern Walkthrough for Each Lane B Sub-Lane

This appendix concretizes how each Lane B sub-lane defends against (or fails to defend against) the eight anti-patterns enumerated in `EVIDENCE-GATE.md` section 2.

### A.1 B0 (async-trait migration)

| Anti-pattern | Defense | Notes |
|---|---|---|
| 2.1 `caught: 0` placeholder | N/A | B0 has no audit-evidence JSON. |
| 2.2 File-exists-without-no-unimplemented | partial | After B0.5 collapses the dispatch hop, the new `dispatch_tool_call_with_cost` body is the actual logic. Reviewer must `grep -n 'unimplemented!\|todo!' crates/chio-kernel/src/kernel/mod.rs` and confirm zero hits on dispatch path. |
| 2.3 Mock-not-runtime | N/A | B0 is a refactor, not a test addition. |
| 2.4 Structural-framing-without-wiring | DEFENDED | B0 explicitly removes the structural lie ("`async fn dispatch_tool_call_with_cost` that calls `_sync` helper"). |
| 2.5 Tautological proof | N/A | No formal proof in B0. |
| 2.6 Banner-vs-reality drift | partial | B0 should not change any banner; if a banner reads "all dispatch is async-native", B0 makes it true. |
| 2.7 Coverage-state pending | N/A | B0 has no threat row. |
| 2.8 Schema-only test | N/A | B0 has no test. |

OBSERVATION: B0 is mostly defended by virtue of being a refactor. The new `scripts/check-tool-server-async.sh` (`planning docs:14`) is a static guarantee against regression. The fact that it greps for `fn invoke(` (sync form) inside files containing `impl ToolServerConnection` is a tight enough check; reviewer should verify the regex captures `pub fn` and `pub(crate) fn` variants.

### A.2 B1 (single-entry verifier)

| Anti-pattern | Defense | Notes |
|---|---|---|
| 2.1 caught:0 placeholder | DEFENDED | release work-B.CLOSE updates the threat-row JSON with `caught: 1` from a real run. |
| 2.2 File-exists-without-no-unimplemented | DEFENDED | B1.3 deletes the partial-entry helpers; nothing left to be unimplemented. |
| 2.3 Mock-not-runtime | DEFENDED | The fixture imports `chio_kernel::ChioKernel` and uses the real `BudgetRegistry`. The `CountingBudgetRegistry` wrapper (single-entry-verifier.md:94) delegates to the real registry; it does not replace it. |
| 2.4 Structural-framing-without-wiring | DEFENDED | The fixture's "critical assertion" (single-entry-verifier.md:98) counts `try_admit_share` calls. If the wiring is structural-only and the noop is substituted, count is zero, fixture fails. |
| 2.5 Tautological proof | N/A | B1 has no formal proof. |
| 2.6 Banner-vs-reality drift | partial | If the README mutation banner is updated to claim "verify_capability_full is the only production verifier", the lint script (`scripts/check-verify-capability-full.sh`) is the artifact-cite. |
| 2.7 Coverage-state pending | DEFENDED | release work-B.CLOSE updates threat-row JSON. |
| 2.8 Schema-only test | DEFENDED | The fixture exercises `evaluate_tool_call_blocking` (the production verb), not a JSON-schema validator. |

The B1 fixture is the strongest in Lane B precisely because it observes a side effect that distinguishes the partial path from the full path. Its design is the model for future protocol-realization work.

### A.3 B2 (receipt v2 fail-closed)

| Anti-pattern | Defense | Notes |
|---|---|---|
| 2.1 caught:0 placeholder | DEFENDED | release work-B.CLOSE updates threat-row JSON. |
| 2.2 File-exists-without-no-unimplemented | DEFENDED | B2.2 replaces a real `tracing::warn!` block with a real fail-closed return; nothing is `unimplemented!()` on the new path. |
| 2.3 Mock-not-runtime | DEFENDED | Fixture imports `chio_kernel::ChioKernel` and uses real `SqliteReceiptStore`. |
| 2.4 Structural-framing-without-wiring | DEFENDED | The fixture's sub-test 2 explicitly asserts `count_v1_receipts == 0 AND count_v2_receipts == 0` after the dispatch fails. A reverted kernel would have `count_v1_receipts == 1`. The side-effect observation directly distinguishes the two states. |
| 2.5 Tautological proof | N/A | |
| 2.6 Banner-vs-reality drift | partial | If a release note claims "v2 negotiation is enforced fail-closed", the artifact citation is the test path. |
| 2.7 Coverage-state pending | DEFENDED | |
| 2.8 Schema-only test | DEFENDED | The fixture exercises `evaluate_tool_call_blocking`, not a `KernelError` deserialization. |

CAVEAT: per finding #4, the spec MUST citation must be reframed before close. The runtime guarantees are sound; the documentation framing is what needs the patch.

### A.4 B3 (anchor-batch async-only)

| Anti-pattern | Defense | Notes |
|---|---|---|
| 2.1 caught:0 placeholder | DEFENDED | |
| 2.2 File-exists-without-no-unimplemented | DEFENDED | B3.2's early-return is real code returning `Err(AnchorError::SyncRouteRequiresAdvisoryPolicy)`. |
| 2.3 Mock-not-runtime | DEFENDED | Fixture imports `chio_anchor::{build_anchor_batch, verify_anchor_batch_with_witness_policy, ...}`. |
| 2.4 Structural-framing-without-wiring | DEFENDED at runtime, partially defended in static analysis | The runtime gate at `batch.rs:227-235` IS the spec MUST. The lint script is best-effort defense-in-depth (see finding #5). |
| 2.5 Tautological proof | N/A | |
| 2.6 Banner-vs-reality drift | partial | |
| 2.7 Coverage-state pending | DEFENDED | |
| 2.8 Schema-only test | DEFENDED | The fixture calls the gated function and asserts the typed error variant, not a serde round-trip. |

CAVEAT: the lint contract (finding #5) should be honestly described. Otherwise, the documentation drifts toward Anti-Pattern 2.6 (banner-vs-reality).

---

## Appendix B: Allowed-Imports Audit for Each Lane B Fixture

Per `CONFORMANCE-FIXTURE-PATTERN.md` section 2.2, allowed imports are limited to:

```
use chio_anchor::{...};
use chio_core::{...};
use chio_core_types::{...};
use chio_federation::{...};
use chio_kernel::{...};
use chio_kernel_core::{...};
```

Plus standard test helpers (`assert_matches`, `serde_json`, `tokio`, `tempfile`).

### B.1 verify_full_is_only_production_entry.rs (B1)

Expected imports (per `single-entry-verifier.md`):

- `chio_kernel::{ChioKernel, KernelConfig, KernelError, Verdict, ...}`.
- `chio_kernel_core::{BudgetRegistry, ...}` (for the counting wrapper).
- `chio_core::{Keypair, ...}`.
- `chio_core_types::capability::{sign_capability_v2, ...}`.
- `chio_store_sqlite::SqliteReceiptStore`.

The `chio_store_sqlite` import is not in the allowed list above. Spot-check `v2_receipt_kernel_round_trip.rs:36` shows it IS imported there as part of the existing pattern. Recommend `CONFORMANCE-FIXTURE-PATTERN.md` section 2.2 add `chio_store_sqlite` to the allowed list, or recommend B1.6 use the in-memory fallback if available. The current pattern uses the SQLite store; making this work is a small fix.

The `CountingBudgetRegistry` wrapper, if added to `tests/common/`, must NOT redeclare any `chio_kernel_core` type. It must `impl BudgetRegistry for CountingBudgetRegistry { ... }` and delegate to a wrapped real registry. The plan at `single-entry-verifier.md:94` is consistent with this.

### B.2 receipt_v2_required_under_v2_negotiation.rs (B2)

Expected imports:

- `chio_kernel::{ChioKernel, KernelConfig, KernelError, KernelReceiptVersion, NegotiationDowngradeReason, Verdict, ...}`.
- `chio_core::{Keypair, capability::*}`.
- `chio_core_types::receipt::*`.
- `chio_store_sqlite::SqliteReceiptStore`.
- `rusqlite::Connection` (for direct `chio_receipts_v2` table reads, per finding #1 reservation).

The new `KernelError::ReceiptNegotiationDowngrade` variant and `NegotiationDowngradeReason` enum must be exported from `chio_kernel`. The plan implies they will be (planning docs release work-B2.1: "variant compiles; printed message under `Display` includes the structured fields").

### B.3 anchor_batch_sync_path_rejected_under_public_witness.rs (B3)

Expected imports (per `anchor-batch-async-only.md:120-125`):

- `chio_anchor::{build_anchor_batch, verify_anchor_batch_with_witness_policy, AnchorBatchWitness, AnchorBatchWitnessKind, AnchorError, WitnessPolicy}`.
- `chio_core::hashing::Hash`.
- `chio_core::Keypair`.

The new `AnchorError::SyncRouteRequiresAdvisoryPolicy` variant must be exported. The plan implies it (planning docs release work-B3.1: "variant compiles; `Display` impl matches ...").

All three fixtures' import lists conform to `CONFORMANCE-FIXTURE-PATTERN.md` section 2.2 allowed imports (modulo the `chio_store_sqlite` extension). PASS.

---

## Appendix C: Why the B1 Fixture is the Strongest in Lane B

The B1 fixture is the model the other fixtures should follow. Its strength comes from observing a side effect that DIRECTLY distinguishes the two paths:

- Production path with `verify_capability_full` -> `BudgetRegistry::try_admit_share` is called against the real registry -> count increments.
- Pre-B1 path with `verify_capability_full_without_budget_admit` -> `chio_kernel_core::NoopBudgetRegistry` substituted at `mod.rs:4045` -> count stays at zero.

There is no way for a stub or schema validation to fake this side effect. The real registry is the only thing that maintains the count; substituting a fake would have to be done inside the kernel, which the test cannot do without bypassing the production path (Anti-Pattern 8.3 in `CONFORMANCE-FIXTURE-PATTERN.md`).

This is exactly the discipline the trj4 erratum was missing. The B1 design proves it can be done. The other Lane B fixtures should be evaluated against this bar.

The B2 fixture comes close (counting receipt rows is also a side-effect observation) but the count is more easily faked because a future kernel could mint a v1 receipt to a separate table or skip the table entirely. The B3 fixture relies on a typed error variant, which is a weaker observation because a future kernel could choose a different error variant for the same fail-closed behavior.

The strongest Lane B fixtures, in order:

1. B1 (registry mutation count).
2. B2 (receipt-table row count).
3. B3 (typed error variant).

All three are sound; B1 is the model. Future trj-N protocol-realization work should aim for B1-style side-effect observations.

---

## Appendix D: Cross-Reference Index

For reviewers cross-checking this review against the source:

| Claim | Source file | Lines |
|---|---|---|
| W1 correction: receipt-v2 downgrade is at mod.rs:1574-1591, not :1148-1165 | `crates/chio-kernel/src/kernel/mod.rs` | 1574-1591 (verified) |
| `KernelReceiptVersion::from_capabilities` resolver helper | `crates/chio-kernel/src/kernel/mod.rs` | 1147-1158 (verified) |
| `verify_capability_signature` legacy entry | `crates/chio-kernel/src/kernel/mod.rs` | 4005-4033 (verified) |
| `verify_capability_full_without_budget_admit` partial entry | `crates/chio-kernel/src/kernel/mod.rs` | 4035-4058 (verified) |
| Hosted call sites (4 total) | `crates/chio-kernel/src/kernel/mod.rs` | 2452, 2706, 2898, 3403 (verified) |
| Dispatch sync-helper hop | `crates/chio-kernel/src/kernel/mod.rs` | 6402-6442 (verified) |
| `ToolServerConnection` trait | `crates/chio-kernel/src/runtime.rs` | 254-306 (verified) |
| `verify_capability_full` composite | `crates/chio-kernel-core/src/capability_verify.rs` | 400-476 (verified) |
| Anchor-batch sync wrapper | `crates/chio-anchor/src/batch.rs` | 227-235 (verified) |
| Anchor-batch async wrapper | `crates/chio-anchor/src/batch.rs` | 251-269 (verified) |
| `record_chio_receipt_with_federation` mint hook | `crates/chio-kernel/src/kernel/responses.rs` | 1405-1427 (verified) |
| PROTOCOL.md SHOULD on capability-full | `spec/PROTOCOL.md` | 405-418 (verified, line 408 SHOULD) |
| PROTOCOL.md receipt-v2 negotiation downgrade | `spec/PROTOCOL.md` | 714-741 (verified, lines 737-741 descriptive prose, no MUST/SHOULD) |
| PROTOCOL.md anchor-batch verifier rule | `spec/PROTOCOL.md` | 980-993 (verified, arrow notation, no MUST) |
| PROTOCOL.md MUST inventory (6 total) | `spec/PROTOCOL.md` | 281, 283, 387, 395, 398, 903 (verified) |
| `chio-kernel-mobile` depends on `chio-kernel-core` only | `crates/chio-kernel-mobile/Cargo.toml` | 30 (verified) |
| Existing fixture pattern (Anchor) | `crates/chio-conformance/tests/anchor_batch_forged_root_rejected.rs` | 1-72 (verified) |
| Existing fixture pattern (Receipt) | `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs` | 1-115 (verified) |
| Impl-site count vs file count | grep output | 47 sites in 31 files (verified) |
| `&mut self` count | grep output | 36 occurrences, 24 method definitions (verified) |

Each claim above was independently verified by Read or Bash grep against the cited source. The W1 correction (downgrade location) is the most consequential of the verifications: the synthesis line 31 cited `:1148-1165` but the actual warn-and-downgrade block is at `:1574-1591`. The Lane B plan correctly applies the W1 correction.

---

## Appendix E: Compositional Risk With Lane A

`PLAN.md` "Inter-lane composition (Lane A x Lane B)" line 165 reads:

> "the threat rows for 'capability bypass via partial verifier', 'receipt downgrade', and 'anchor-batch sync routing under public witness' are populated by Lane B's fixture `caught: 1` runs (Lane A owns that the JSON is non-placeholder; Lane B owns that the fixture is real)."

The composition is correct in shape: Lane A's `audits/evidence/threats/<id>.json` rows are updated by Lane B fixture runs. The release work-B.CLOSE ticket explicitly does this update.

Risk: the threat-row JSON schema requires a real `ran_at` timestamp and a real `caught` count. The Lane A floor expects `caught >= 1` per `EVIDENCE-GATE.md` section 1.2. The Lane B fixture, when run on a green kernel, asserts the typed error and PASSES. The `caught` count for the threat (e.g., "capability bypass via partial verifier") in this case would be 1 (the test caught the threat by asserting the rejection). This is consistent with Lane A's contract.

But: Lane A's mutation-kill regime requires that the test ALSO catch synthetic mutants of the production code. Lane B's fixtures are negative tests; they assert rejection on an attacker input. Mutation testing flips production code; the fixture's resilience to those mutations is a separate axis. Recommend reviewer confirm that Lane B fixtures are included in the cargo-mutants run for `chio-kernel` and `chio-anchor`, otherwise Lane A's "65% mutation kill" claim does not benefit from Lane B's wiring.

---

## Appendix F: What This Review Did NOT Cover

For completeness, the following were out of scope for R3:

- Lane A floor work (mutation kill, threat coverage, Kani harnesses). Reviewed elsewhere.
- Lane C demo design. Reviewed elsewhere.
- The `chio-conformance` crate's `Cargo.toml` `[dev-dependencies]` for the new fixtures (TBD-from-W1 per `CONFORMANCE-FIXTURE-PATTERN.md` section 5).
- The `.github/workflows/` CI workflow file diffs that wire up the new lint scripts. The workflow references in `CONFORMANCE-FIXTURE-PATTERN.md` section 6 are correct in shape; the actual YAML edits are out of this review's scope.
- Performance impact of the async-trait migration on the dispatch hot path. The `RISK-REGISTER.md` R1 captures this; this review takes the rollback plan at face value.
- Wasm bundle-size impact on `chio-kernel-browser`. Captured in `ASYNC-KERNEL-MIGRATION.md` section 4.2; out of this review's scope.

These are explicit hand-offs to other reviewers (R1, R2, R4, ...).

---

## Final tally

- Findings: 10 (3 BLOCKER, 6 MAJOR, 4 MINOR, 3 OBSERVATION).
- Patches: 6 specific edits with file:line references.
- Open questions: 5 (Q1 BLOCKER, Q2 MAJOR, Q3 MINOR, Q4-Q5 OBSERVATION).
- Verdict: APPROVE-WITH-CHANGES.
- Sign-off path: B0 + B1 may begin; B2 + B3 require pre-flight patches; release work-B.CLOSE requires non-author sign-off per `EVIDENCE-GATE.md` 3.3.

This document is itself a Wave 2 deliverable per `KICKOFF-CHECKLIST.md` (TBD-from-W1) and is parsable by `scripts/check-release work-evidence-gate.sh` once that script lands. The headings and finding-numbered sections are stable identifiers for downstream tickets.
