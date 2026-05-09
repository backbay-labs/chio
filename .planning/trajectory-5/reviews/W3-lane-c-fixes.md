# W3 Lane C Fixes - Fix Log

**Wave 3 fix agent for Lane C (release work).**
**Date:** 2026-05-07
**Scope:** Address every R4 (Lane C feasibility) and R1
(cross-lane) finding affecting Lane C. Rework the demo to depend on
the new Lane B sub-lane B4 (DSSE-conformant signing) instead of the
W1 Option-A bolt-on. Fix Lane C tickets to reference Evidence Gate
and use real Lane B ticket IDs.

## Files modified

- `.planning/trajectory-5/lane-c-demo/bilateral-cosign-flow.md`
- `.planning/trajectory-5/lane-c-demo/architecture.md`
- `.planning/trajectory-5/lane-c-demo/release-bar.md`
- `.planning/trajectory-5/lane-c-demo/kb-mcp-integration.md`
- `.planning/trajectory-5/lane-c-demo/planning docs` (full rewrite)
- `.planning/trajectory-5/lane-c-demo/selective-disclosure.md`
- `.planning/trajectory-5/lane-c-demo/PLAN.md`
- `.planning/trajectory-5/lane-c-demo/README.md`

Out of scope (parallel agents own these):
- Lane A docs
- Lane B docs (including the new B4 sub-lane)
- Master docs (`debate/`, `architecture/`, `templates/`,
  `EXECUTION-BOARD.md`, `SHIP-BAR-TRACKER.md`, `SCOPE-LOCK.md`,
  `OWNERS.toml`, etc.)

## R4 findings addressed

### R4 BLOCKER 1 (DSSE signing scheme - Option A insufficient) - REWORKED

**Resolution:** Lane C dropped the "Option A two-signature bolt-on"
entirely. The DSSE-conformant signing primitive is now Lane B
sub-lane B4 (`lane-b-wiring/dsse-bilateral-signing.md`, tickets
`bilateral DSSE signing item-B4.x`, owned by parallel Lane B fix agent).

Patches:
- `bilateral-cosign-flow.md`: replaced "Two co-existing signing
  surfaces / Option A / Option B / Recommendation: Option A" with
  "Single signing surface: DSSE PAE produced by Lane B B4". The
  document now explains the structural cut (B4 owns the envelope
  and signing surface; Lane C owns the predicate helper and §7
  verifier inside the same module). Adapter code blocks rewritten
  to show the Lane-C-side helper, not the original
  `build_envelope_from_dual_signed`. Added "Two-keypair signing
  protocol" section per R4 Step gap 7c (each kernel signs its own
  PAE; existing `CoSigningRequest`/`Response` cadence
  generalised by B4).
- `architecture.md`: updated the diagram to show "rewired by
  Lane B B4" on the `DualSignedReceipt` box and the
  bilateral_dsse module box; updated "Crates touched" table.
- `release-bar.md`: dropped the weasel "AND a DSSE envelope"
  language; release notes now claim spec §6 conformance directly
  via Lane B B4.
- planning docs: release work-C2.1..C2.6 now consume B4 (`Depends on:
  bilateral DSSE signing item`) and the C2 sub-lane simplifies from "ship Option-A
  adapter" to "consume B4, ship §7 verifier".

### R4 BLOCKER 2 (KB MCP HTTP/stdio bridge) - RESOLVED

**Resolution:** demo uses `mcp-remote` (the Node.js stdio<->HTTP
bridge already documented at `ops/knowledge-base/README.md:136-151`)
as the wrapped command for `chio mcp serve`.

Patches:
- `kb-mcp-integration.md`: rewrote the topology diagram to show the
  `chio mcp serve -> npx mcp-remote -> HTTP KB MCP` chain. Added
  pre-requisites section (Node.js 18+ on PATH; air-gapped CI runners
  pre-warm npm cache). Replaced the fictional policy YAML schema
  with a HushSpec-shaped one matching
  `examples/policies/canonical-hushspec.yaml` (review finding 5b option
  a: amount cap is ladder-driven, not policy-YAML-driven).
- planning docs: release work-C3.2 wraps the new command:
  `chio mcp serve --policy ... -- npx -y mcp-remote
  http://localhost:8111/mcp/`. Pre-requisite bullet "Node.js / npx
  available in the smoke container" added.
- `PLAN.md`: C3 scope text updated to acknowledge the bridge.

### R4 MAJORs

- **Finding 3 (cross-lane dep aliases not anchored to Lane B IDs):**
  resolved by replacing every alias use in `Depends on` rows with
  literal Lane B ticket IDs (`release work-B0.5`, `release work-B1.6`, `release work-B2.5`,
  `release work-B3.5`, `bilateral DSSE signing item`). The alias->ID map is preserved in
  planning docs as a documentation table for traceability but no
  ticket dep cites the alias.

- **Finding 4 (release-bar.md AND overclaims §6 conformance):**
  resolved. The new release-bar.md item 2 cites Lane B B4 directly
  for the spec §6 signing surface; "What this release DOES NOT
  CLAIM" gained items 13 (auditor view single-party local) and 14
  (selective disclosure deferral path).

- **Finding 5a (chiodos-ladder primitive missing in code):**
  resolved. release work-C1.3 effort bumped from M to L; explicit
  acknowledgment that this is NEW Rust code; primitive lives in
  `examples/chiodome-bilateral/src/ladder.rs`. Bounded-claim text
  in `release-bar.md` and `architecture.md` notes "the
  chiodos-ladder primitive used in the demo is an example-local
  minimal implementation; production primitive deferred to trj6".

- **Finding 5b (policy YAML format mismatch):** resolved. Policy
  YAML rewritten in HushSpec shape; amount cap moved to ladder
  intersection per option (a). release work-C3.1 acceptance now exercises
  `chio check --policy <yaml>` against the real chio-policy crate.

- **Finding 6 (BBS+ deps absent; R6 mitigation soft):** resolved by
  adding explicit deferral path. Lane C C5 ships only if the W2
  dep-tree validation succeeds; otherwise C5 is dropped and the
  release ships as a five-artifact bundle. `selective-disclosure.md`
  has a new "Fallback if BBS+ deps cannot resolve (R6 escalation)"
  section. `release-bar.md` item 14 of "What this release DOES NOT
  CLAIM" enumerates the deferral. release work-C5.1 acceptance includes
  explicit MSRV-resolution check.

- **Finding 7 (end-to-end composition gaps):** resolved. New
  release work-C2.5 ticket "Anchor inclusion proof emission" (R4 Step gap
  7a). The §7 verifier ticket release work-C2.4 explicitly depends on
  release work-B1.6/B2.5/B3.5/B4.x. Two-keypair signing protocol section
  added to `bilateral-cosign-flow.md` (Step gap 7c).

- **Finding 8 (17-step verifier cross-crate calls):** resolved.
  `bilateral-cosign-flow.md` now has an "Architecture cut for
  cross-crate calls" section choosing option B (trait objects for
  `ReceiptStore` and `CapabilityVerifier`). release work-C2.1 introduces
  the `CapabilityVerifier` trait in `chio-federation`. release work-C4.1
  effort bumped from M to L per Finding 9.

- **Finding 10 (forcing-function CI hook missing):** resolved by
  adding release work-C6.3 "Continuous chiodome demo workflow" with the
  spec from review finding 10 verbatim (nightly + Lane B path push,
  failures open issues, 7 consecutive nights green pre-tag).

### R4 MINORs

- **Finding 9 (`chio receipt explain` underestimated):** resolved.
  release work-C4.1 bumped from M to L; acceptance now requires the
  explain output's "policy verdict disagreement" to be surfaced as
  a top-level diagnostic and the bilateral chain to render with
  parent->child arrows. release work-C4.4 doc page merged with release work-C4.3
  snapshot test acceptance into a single release work-C4.2.

- **Finding 11 (demo fixture reproducibility):** resolved. New
  release work-C6.4 "Diff-stable fixture tarball" includes the
  `tools/diff-stable.py` (or Rust binary) per review finding 11; smoke
  step 5 calls it; the rule is "diff-stable across runs", not
  "byte-identical".

- **Finding 12 (mock-receipt detection):** resolved. release work-C6.2
  acceptance requires the workflow to verify every fixture under
  `examples/chiodome-bilateral/fixtures/` was produced by the
  smoke run in the same workflow run (mtime check).

- **Finding 13 (predicate URI):** no patch needed; already correct.

### R4 OBSERVATIONs

- **Finding 14 (ticket count over target):** addressed. Original 30
  tickets reduced to 24 by merging adjacent tickets that shared
  scope (C2.4+C2.5; C3.4+C3.5; C4.3+C4.1; C4.4+T1.6; C5.2+C5.3;
  C5.4+C5.5; C6.1+C6.4) and adding two new tickets for previously
  hidden scope (C2.5 anchor inclusion; C6.3 continuous workflow;
  C6.4 diff-stable). Final count is 24, within the R1 §11.7
  recommended 22-26 range.

## R1 cross-cutting findings addressed

### R1 BLOCKER (Lane C zero Evidence Gate references) - RESOLVED

Patches to planning docs:
- New introductory paragraph: "Every ticket closes under the release work
  Evidence Gate trio".
- Every release work-C* ticket Acceptance is now a five-row block matching
  TICKET-TEMPLATE §2.1 (production wiring + spec MUST citation +
  negative conformance test path + audit-doc evidence reference +
  banner update).
- `Owner-class` field added to every ticket.

### R1 BLOCKER (Lane C cross-lane aliases) - RESOLVED

See review finding 3 above. Aliases preserved only in the cross-reference
documentation table, never in `Depends on` rows.

### R1 MAJOR (continuous Lane C run) - RESOLVED

See review finding 10 above. release work-C6.3 added; W3 scaffolding start
(R1 §6.2) reflected in the README.md timeline and PLAN.md week
range fields.

### R1 MAJOR (line-range and trait-name drift)

Lane-C-internal occurrences fixed:
- `architecture.md`: `mod.rs:1148-1165` -> `mod.rs:1574-1591`
  (`kernel_receipt_version_for_remote`); `LB-CAP/LB-RV2/LB-AB/LB-AT`
  arrows replaced with `release work-B1.x/B2.x/B3.x/B0.x`.
- `release-bar.md`: same line-range fix; reference rewritten with
  function name.
- `README.md`: same line-range fix; trait name corrections;
  "ToolServer" -> "ToolServerConnection".
- `bilateral-cosign-flow.md`: bare `ToolServer` -> `ToolServerConnection`.
- planning docs: rewritten from scratch using post-correction line
  ranges and trait names.
- `PLAN.md`: `ToolServer` -> `ToolServerConnection`.

Master docs are out of scope (parallel agents own these); the
worktree-internal references are now consistent.

### R1 MINOR (ticket count over budget) - RESOLVED

See review finding 14 above. 30 -> 24 tickets.

## DSSE rework summary (most material change)

Lane C's W1 plan claimed §6 conformance via a Lane-C-side adapter
that bolted a DSSE PAE signature alongside the existing
`CoSigningBody` signature. review finding 1 rejected this as
structural-framing-without-wiring (`templates/EVIDENCE-GATE.md`
§2.4) - the spec verifier would be honored by the DSSE envelope
alone, but the `DualSignedReceipt`'s built-in `verify` would still
accept the legacy preimage, so a third party would see a
"§6-conformant" tag whose primary federation artifact is not
§6-conformant.

**The W3 rework promotes the DSSE-conformant signing primitive to
Lane B sub-lane B4** (`lane-b-wiring/dsse-bilateral-signing.md`,
tickets `bilateral DSSE signing item-B4.x`). After B4 lands:

- The kernel cross-org dispatch hot path emits the §6 DSSE envelope
  by default.
- `DualSignedReceipt::verify` is rewired to validate against PAE
  bytes of the canonical Statement.
- The legacy `CoSigningBody`-scoped Ed25519 signing surface is
  retained only as a fixture-only signer used by B4's negative
  conformance test (proves the production verifier rejects legacy
  preimages).

Lane C consumes B4-produced envelopes and ships:

- A `predicate_from_kernel_state` helper for demo orchestration
  (in the same `bilateral_dsse.rs` module).
- The full §7 17-step verifier (`verify_envelope`).
- A `CapabilityVerifier` trait so the verifier in `chio-federation`
  does not pull in `chio-kernel` directly (architecture cut option B).
- 16 negative conformance fixtures (one per §7.1 error code).

The release work ship date may slip ~1 week (synthesis 8-week max -> ~9
weeks) due to B4. Acceptable per R4.

## KB MCP HTTP/stdio bridge resolution

Original W1 plan: `chio mcp serve --policy ... -- chio-kb-mcp`
(would not work; KB MCP is HTTP, not stdio).

Wave 3 plan: `chio mcp serve --policy ... -- npx -y mcp-remote
http://localhost:8111/mcp/`. The `mcp-remote` shim is already
documented at `ops/knowledge-base/README.md:136-151` for Claude
Desktop integration. Bounded-claim language acknowledges the demo
validates `chio mcp serve` plus the bridge, NOT direct HTTP MCP
wrapping.

## Final ticket count

24 tickets total (down from W1's 30, within R1 §11.7's recommended
22-26 range):

- C1: 4 (release work-C1.1 .. C1.4)
- C2: 6 (release work-C2.1 .. C2.6) - consumes B4; 16-case negative
  fixture set merged into C2.4; new C2.5 anchor inclusion
- C3: 4 (release work-C3.1 .. C3.4) - merged W1's C3.4+C3.5
- C4: 2 (release work-C4.1, C4.2) - bumped C4.1 to L per review finding 9;
  merged C4.3 snapshot into C4.1 acceptance; merged C4.4 doc with
  T1.6 close
- C5: 3 (release work-C5.1 .. C5.3) - deferable per R6
- C6: 5 (release work-C6.1 .. C6.5) - new C6.3 continuous workflow;
  new C6.4 diff-stable; merged W1's C6.1+C6.4

## Bounded-claim audit results

`release-bar.md` re-audited against v3.18 RELEASE_AUDIT.md style
discipline:

- **No claim of consensus-grade HA, distributed-linearizable spend,
  transparency-log semantics:** preserved (items 1-12 of "What this
  release DOES NOT CLAIM").
- **Auditor view = local proof, single-party verification, NOT a
  public log:** new item 13 added explicitly. Honest about the
  malicious-issuer scenario where one party controls both kernels.
- **Selective disclosure: bounded claim about reveal vs. no-reveal:**
  preserved. `selective-disclosure.md` "Auditor view - what we DO
  NOT claim" already listed seven non-claims; W3 adds items 8 (BBS+
  implementation may not be cryptographically conformant with
  eventual W3C Recommendation) and 9 (auditor view may be DEFERRED
  to v0.2 per R6).
- **W3C CR caveat promoted to headline** of the release-bar
  selective-disclosure block, per review finding 6 recommendation.
- **No overclaim of §6 conformance via the AND structure:**
  resolved. The release notes now cite Lane B B4 directly for the
  §6 signing surface, with no parallel "DualSignedReceipt AND DSSE"
  language.

## Anything for Wave 4 final-pass

Wave 4 final-pass should reconcile the following items where
parallel agents may have made coordinating changes:

1. **Lane B B4 ticket numbers.** This fix log uses placeholder
   `bilateral DSSE signing item` throughout; the parallel Lane B fix agent will fix
   specific IDs (B4.1, B4.2, ...). Wave 4 sweeps Lane C docs and
   replaces `bilateral DSSE signing item` with the specific Lane B ticket IDs that
   are appropriate for each dependency.

2. **Spec line-range citations.** Several Lane C tickets cite
   `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6/§7 line ranges
   as "lines to be filled in by audit-doc owner". Wave 4 fills in
   the specific line ranges from the spec files (currently
   referenced as e.g. "lines 338-353 (PAE)", "step 11-12
   (signature verification)").

3. **Master-doc DSSE Option-A propagation.** R1 Finding 1.4 / 9
   noted that the master docs (`SCOPE-LOCK.md`,
   `SHIP-BAR-TRACKER.md`, `SPEC-TO-RUNTIME-MAP.md`,
   `RISK-REGISTER.md`) need the DSSE Option-A row deleted (now
   that we promoted to B4) and replaced with a B4 row. That is a
   different fix agent's responsibility; this fix log does not
   touch master docs.

4. **OWNERS.toml + EXECUTION-BOARD.md.** Lane C now starts in W3
   (not W1). The cross-lane dependency table in
   `EXECUTION-BOARD.md` should be updated; OWNERS.toml may need
   `coordination_owner` rows on overlap paths. Out of scope for
   this fix agent.

5. **R7 risk register addition.** R1 Finding 1.4 proposed an R7
   risk in `architecture/RISK-REGISTER.md` for "spec WG rejects
   Option-A two-signature design". Since Option A is gone, the R7
   text should be reframed as "spec WG rejects B4's signing
   surface decision" or omitted. That decision is the Lane B fix
   agent's coordination point.

6. **Lane B negative conformance fixture B4.x naming.** The
   `release-bar.md` "Forcing-function dependency on Lane B" lists
   a fourth fixture
   `crates/chio-conformance/tests/b4_legacy_cosigning_body_signature_rejected.rs`.
   The exact filename should match Lane B's ticketing decision;
   Wave 4 reconciles.

7. **Continuous CI workflow filename.** release work-C6.3 names the file
   `.github/workflows/chiodome-demo-continuous.yml`. If Lane B's
   fix agent reused the same name in a different ticket, Wave 4
   reconciles.

End of W3 Lane C fix log.
