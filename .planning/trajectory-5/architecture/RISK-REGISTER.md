# Trj5 Risk Register

**Status**: living catalog of the six release work risks identified at synthesis time.
Each row is owned by a lane; each row has an escalation criterion that
flips it into a review item. Wave 1 Creator emits this document;
reviewers update it; the release work closeout doc retires it.

**Origin**: `.planning/trajectory-5/debate/00-SYNTHESIS.md` "Where the agents
disagreed" plus the residual concessions in
`.planning/trajectory-5/debate/03-architecture-decomposition.md` and
`.planning/trajectory-5/debate/04-quality-verification-skeptic.md`.

---

## R1: Async-trait migration blast radius larger than estimated

| Field | Value |
|---|---|
| Probability | medium (35%) |
| Impact | high - Lane B blocks if migration stalls |
| Owner-class | substrate-eng |
| Lane | B0 (architectural prerequisite) |

**Description**: the synthesis-sanctioned migration is the SMALLEST
decomposition cut. The estimate in
`.planning/trajectory-5/architecture/ASYNC-KERNEL-MIGRATION.md` section 5
is ~1,500-2,000 LOC across 30-55 files. If implementer catch-up reveals
hidden coupling (e.g. an in-tree implementer that holds a `RefCell` across
an `.await` point, or an FFI shim that requires Option B in section 4.3),
the migration could balloon past 3,000 LOC and force a rollback.

**Mitigation**:
- Wave 1 lands the implementer enumeration (TBD-from-W1 in the migration
  doc) BEFORE any code change. The enumeration is the first ticket in B0.
- Hold a hard 3,000 LOC ceiling in CI via `scripts/check-async-trait-uniform.sh`
  measured against a baseline.
- Sequence the implementer catch-up so each implementer is its own
  small ticket; bail-and-rollback after any single catch-up exceeds 500
  LOC.
- The rollback plan in `ASYNC-KERNEL-MIGRATION.md` section 6 is documented
  and rehearsable.

**Escalation criteria**:
- Wave 1 enumeration shows >8 implementers OR any single implementer
  >800 LOC.
- C++ FFI per-call overhead measured at >5% of dispatch_allow bench.
- Wasm bundle-size regression >5% on `chio-kernel-browser`.

If any criterion fires, escalate to a Wave 2 design review and consider
rolling back to the sync helper while Lane B proceeds through it.

---

## R2: Mutation kill plateau below 65% on a specific crate

| Field | Value |
|---|---|
| Probability | high (55%) |
| Impact | medium - blocks Lane A close; does not block Lane B/C |
| Owner-class | substrate-eng |
| Lane | A1 (mutation kill) |

**Description**: the synthesis floor is `>=65%` on trust-boundary crates
and `>=80%` on `chio-attest-verify`. The current banner is 31%. Some
crates in the trust-boundary set may have inherently low mutation
killability without aggressive test-surface expansion (e.g. crates with
heavy const-evaluation, or crates whose semantics are dominated by
serialization round-trips that mutators can break in benign ways).

Concrete trj4 evidence: the workspace banner sat at 31% across the trj4
window. Several trust-boundary crates may need new property tests, not
just more example tests, to reach 65%.

**Mitigation**:
- Wave 1 produces a per-crate kill-rate baseline from a real
  `cargo-mutants` run on the trust-boundary set.
- For each crate below 65% at baseline, the audit-doc owner identifies
  the surface (proptest, kani, conformance, integration) most likely to
  raise the rate.
- Allow per-crate carve-outs ONLY with `# unreachable: <justification>`
  annotations on specific mutation lines, NOT blanket exemptions.
- The `chio-attest-verify` 80% target gets explicit Kani harness coverage
  (TRJ4-012 carry-forward) so the proof is upstream of the test rate.

**Escalation criteria**:
- Any trust-boundary crate plateaus below 50% after two waves of
  test-surface expansion. (50% means we are not just slow; we are
  measuring the wrong thing.)
- `chio-attest-verify` plateaus below 70% (the 80% target then becomes
  unreachable in release work timeline).

If a crate cannot be raised, document the residual risk in the per-crate
audit-doc evidence section AND in `RELEASE_AUDIT.md` so the bounded claim
matches reality. Do not silently lower the banner target.

---

## R3: A threat row is unprovable without architecture change

| Field | Value |
|---|---|
| Probability | medium (30%) |
| Impact | high - forces a row out of release work into trj6 |
| Owner-class | substrate-eng |
| Lane | A2 (threat coverage) |

**Description**: the 20 threat rows in `audits/evidence/threats/*.json`
(synthesis says "21"; the on-disk count is 20 per `ls
audits/evidence/threats/ | wc -l`; Lane A targets 20 as authoritative
per Wave 3 reconciliation) all read `caught: 0`, `needs_real_run:
true`. Some rows may correspond to attacks whose enforcement primitive
does not yet exist as wired runtime (e.g.
`wasm_guard_resource_exhaustion` requires a wasm-guard SDK v4 in
production; the synthesis kept WASM Guard v4 out of scope). Such a row
cannot satisfy the Lane A Evidence Gate (caught >= 1 against the
production call path) without an architectural change that the synthesis
declined to sanction.

Concrete candidates (Wave 1 confirms via per-row triage):
- `wasm_guard_resource_exhaustion` (depends on guard SDK v4)
  -- pre-Wave-1 estimate: `BLOCKED-BY-ARCHITECTURE`.
- `tool_server_escape` (sandbox enforcement may be partial post
  release work-B0 `ToolServerConnection` migration) -- pre-Wave-1 estimate: `IMPL-PARTIAL`.
- `passkey_credential_theft`, `resource_exhaustion_dos` (Wave 1
  identifies the production `pub fn`; if absent, downgrade)
  -- pre-Wave-1 estimate: `IMPL-EXISTS-PRIVATE` pending confirmation.
- `tee_quote_forgery` (depends on `chio-tee-frame::validate_signed`
  real cryptographic verification; the function exists today at
  `crates/chio-tee-frame/src/schema.rs:93` per Wave 3 verification, so
  this row is `IMPL-EXISTS-AND-PUBLIC`).

**Mitigation**:
- Wave 1 reviews each of the 20 rows and tags one of
  {`IMPL-EXISTS-AND-PUBLIC`, `IMPL-EXISTS-PRIVATE`, `IMPL-PARTIAL`,
  `BLOCKED-BY-ARCHITECTURE`}. The tag is recorded as a top-level
  `triage_status` field in `audits/evidence/threats/<id>.json`. The
  runtime gate script checks this field is set.
- Rows tagged `BLOCKED-BY-ARCHITECTURE` are removed from the release work
  ship-bar and the README banner reads "<n> of 20 covered, <m>
  deferred to trj6", not "20 of 20". Banner-vs-reality drift is the
  trj4 failure mode.
- The deferred rows ship as trj6 tickets at the start of trj6, not as
  release work carry-forward erratum rows.

**Escalation criteria** (tightened per R2 MAJOR Section 2.4):
- More than **2** of 20 rows tag as `IMPL-PARTIAL` +
  `BLOCKED-BY-ARCHITECTURE` combined. (Tightened from the prior ">4"
  threshold; the projected pre-Wave-1 deferral count is 1
  (`wasm_guard_resource_exhaustion`); a count of 3 would mean
  multiple primitives are still partial-enforcement, which makes the
  release work banner claim too soft to count as a closeout.)

If >2 rows defer, review reconsiders the release work ship bar. The
synthesis stipulated "all 20 contain real `caught >= 1`" (read with
the on-disk count); meaningful deferral changes the bar.

---

## R4: Lane C demo reveals a Lane B primitive isn't actually enforced

| Field | Value |
|---|---|
| Probability | medium (40%) |
| Impact | high - the demo is the forcing function; this is its purpose |
| Owner-class | demo-eng + protocol-eng |
| Lane | C (forcing demo) |

**Description**: Lane C's purpose is to compose Lane B primitives end-to-end
in a two-kernel cross-org bilateral cosign demo. If the demo runs and
produces a receipt, but the receipt's body_hash is missing, or the
attenuation chain has an unwitnessed parent, or the anchor batch sync path
was used despite `require_public_witness=true`, then Lane B's claim of
enforcement is contradicted by the demo run.

This is GOOD: it is exactly why the demo exists. But it is also a risk:
during Wave 4-5 Lane B may close on its own conformance fixtures, then
Wave 6-7 Lane C run reveals enforcement is partial. At that point the
release work ship bar is in jeopardy.

**Mitigation**:
- Lane C tickets are scheduled to START before Lane B closes, so demo
  smoke-tests run continuously against in-progress Lane B work.
- Lane C release work-C*.E Evidence Gate tickets explicitly assert that the
  demo run exercises each Lane B primitive (`receipt v2 body_hash
  present`, `anchor batch witness verified`, `dual-signed receipt has
  both signatures`). The assertions are wired into
  `crates/chio-conformance/tests/cross_org_*` fixtures.
- The demo's output receipts are committed as fixtures under
  `examples/<demo>/fixtures/` so reviewers can inspect them with
  `chio receipt explain`.

**Escalation criteria**:
- Demo run shows a Lane B primitive bypassed in any reproducible
  configuration, AND the bypass is fixable only by a >L-effort change
  not currently scoped.

If a Lane B primitive turns out to need more than its scoped effort,
escalate to Wave 2 to either (a) extend the lane budget or (b) carve a
sub-row out as `DEFERRED-trj6` with the demo's bounded claim narrowed
accordingly.

---

## R5: Lean4 `negotiation_safety` re-proof needs an executable model

| Field | Value |
|---|---|
| Probability | high (60%) |
| Impact | medium - blocks Lane A close on the formal sub-lane |
| Owner-class | substrate-eng (formal) |
| Lane | A3 (formal proofs) |

**Description**: the trj4 erratum identified that `negotiation_safety` was
"proven by `rfl`" - tautology, not refinement. The release work synthesis
requires the theorem to be re-proved against an executable model. The
problem: an executable model that the theorem refines may not exist as
machine-readable code today. Building one is a real piece of work; if
underestimated, the formal sub-lane closes late or not at all.

The `formal/theorem-inventory.json` file records `0 of 75 IDs proven`
with substantive proofs. The depth of the gap is not just one theorem;
multiple rows may have similar `rfl`-shaped proofs.

**Mitigation**:
- Wave 1 audits `formal/theorem-inventory.json` and identifies which IDs
  have substantive proofs vs `rfl`-shaped placeholders.
- For each `rfl`-shaped ID, decide whether: (a) build executable model
  (M-L effort each), (b) accept that the theorem is informational only
  and downgrade its status to `informational`, or (c) defer to trj6.
- The release work floor commits to ONLY the `negotiation_safety` re-proof as
  load-bearing. Other `rfl` proofs are downgraded informationally; their
  re-proof is trj6.

**Escalation criteria**:
- Wave 1 audit shows building an executable model for
  `negotiation_safety` is >L effort. (At that point, the proof is a
  multi-week formal-methods project, not a sub-lane.)

If escalated, Lane A's formal sub-lane scope narrows to "downgrade
mis-stated proof statuses to `informational` and produce an honest
inventory"; the executable-model re-proof moves to trj6.

---

## R6: Selective disclosure (`bbs-stub` feature) cargo-dep weight

| Field | Value |
|---|---|
| Probability | medium (35%) |
| Impact | low-medium - complicates CI matrix; may force feature gating |
| Owner-class | demo-eng |
| Lane | C4 (selective disclosure demo) |

**Description**: Lane C4 ships an auditor-view selective-disclosure
fixture behind a `bbs-stub` Cargo feature flag. Proof-friendly libraries
(`arkworks-rs`, `bellman`, `halo2`, etc.) carry significant compile-time
weight and may pull in MSRV-sensitive transitive crates. Adding the
feature to `chio-conformance` or `chio-federation` could meaningfully
slow CI.

**Mitigation**:
- The `bbs-stub` feature is OFF by default. Only the C4 conformance test and
  the demo binary opt in.
- CI runs the `bbs-stub`-feature build in a dedicated workflow job
  (TBD-from-W1: `.github/workflows/conformance-selective-disclosure.yml`), not as part of
  the main `ci.yml` matrix.
- If the dep weight forces a MSRV bump, accept it as a documented
  constraint of release work OR drop C4 from the demo and ship the bilateral
  cosign demo without the auditor-view slice.
- Bounded claim: "selective disclosure available behind `bbs-stub` feature; not
  on by default."

**Escalation criteria**:
- `bbs-stub`-feature build adds >5 minutes to CI critical path.
- `bbs-stub`-feature requires a workspace-wide MSRV bump that breaks any
  current consumer.

If escalated, drop C4 from the demo. The Lane C ship bar narrows to
C1-C3 (bilateral cosign + lease/bond + anchored receipts) without the
selective-disclosure auditor-view slice.

---

## R7: DSSE-conformant bilateral signing complexity (Ed25519 over DSSE PAE encoding)

| Field | Value |
|---|---|
| Probability | medium (40%) |
| Impact | medium-high - blocks Lane B4 close and Lane C2 DSSE adapter |
| Owner-class | protocol-eng + federation-eng |
| Lane | B4 (newly added per R4 BLOCKER 1) |

**Description**: Lane B4 (DSSE-conformant bilateral signing, promoted from
Lane C "Option A two-signature" per R4 BLOCKER 1) wires Ed25519 over DSSE
PAE bytes of a canonical-JSON in-toto Statement that carries the §5
predicate body. This requires:

- Correct DSSE PAE encoding: `"DSSEv1" SP LEN(payload-type) SP payload-type SP LEN(payload) SP payload`. Mistaken encoding yields valid-looking signatures that fail spec §6 verification.
- A canonical JSON encoding that is byte-stable for the in-toto Statement (currently `chio-federation` uses `canonical_json_bytes`; ensure the new module uses the same).
- Coordination with the existing `crates/chio-federation/src/bilateral.rs::DualSignedReceipt::verify` (line 108): the design choice is "single-version transition" or "cohabitation"; both must be specified before B4.1 lands.

The R4 finding observed that the legacy `CoSigningBody` preimage (lines
41-77 of `bilateral.rs`) shares ZERO bytes with the §6 DSSE PAE preimage.
A naive "two signatures, one keypair" approach (the previously proposed
Lane C "Option A") does NOT satisfy §6 strictly.

**Mitigation**:
- Lane B4.1 ticket lands the wire-format design BEFORE any production code: documents the canonical JSON encoding, the DSSE PAE bytes, the in-toto Statement structure, and the relationship to legacy `DualSignedReceipt`.
- Lane B4.2 lands the new module `crates/chio-federation/src/bilateral_dsse.rs` with thin functions: `encode_dsse_envelope`, `verify_dsse_envelope`, `pae_bytes`, each independently testable.
- Lane B4.5 negative conformance fixture rejects (a) attempts to claim §6 conformance via the legacy preimage; (b) tampered PAE bytes; (c) DSSE envelope with mismatched payload-type.
- The legacy `DualSignedReceipt::verify` at `bilateral.rs:108` is NOT changed during release work; it remains usable for backward compatibility with non-§6 callers, with explicit non-conformance disclaimer in Lane C release notes.

**Escalation criteria**:
- DSSE PAE encoding implementation reveals a hidden ambiguity in the spec text (§6 lines 338-353) requiring a spec-WG resolution.
- Coexistence design (legacy + DSSE) creates ambiguity for verifiers about which artifact is canonical.
- B4 effort exceeds L (estimated 3-6 days; if Wave 1 audit shows >L effort, consider Option 2 from R4 review: narrow the bounded claim instead of promoting to B4).

If escalated, fall back to R4's Option 2: keep `DualSignedReceipt`
unchanged in release work, narrow Lane C release notes to disclaim §6 conformance
for the legacy preimage, and defer the `bilateral_dsse.rs` module to
trj6.

---

## Summary table

| ID | Risk | Prob | Impact | Lane |
|---|---|---|---|---|
| R1 | Async-trait migration blast radius | medium | high | B0 |
| R2 | Mutation kill plateau | high | medium | A1 |
| R3 | Unprovable threat row | medium | high | A2 |
| R4 | Demo reveals Lane B partial enforcement | medium | high | C |
| R5 | Lean re-proof needs executable model | high | medium | A3 |
| R6 | `bbs-stub` feature cargo-dep weight | medium | low-medium | C4 |
| R7 | DSSE-conformant bilateral signing complexity | medium | medium-high | B4 |

**Top-of-list for review**: R4. The demo is the forcing function;
its job is to falsify the Lane B claim if it is false. R4 has a 40%
probability of firing and a high impact, and it is the risk most likely
to surface trj4-pattern partial enforcement that the conformance fixtures
alone would not catch. Wave 2 should focus its review on whether Lane C
fixtures are wired to assert the Lane B primitives at every dispatch step
of the demo, and whether the demo runs continuously (not just at the end
of release work) so Lane B partial-enforcement findings have time to be fixed.

R1 is the second priority because it gates everything downstream; if Wave
2 detects any signal that the migration is creeping past 3,000 LOC, the
rollback plan in `ASYNC-KERNEL-MIGRATION.md` section 6 should activate
early rather than late.
