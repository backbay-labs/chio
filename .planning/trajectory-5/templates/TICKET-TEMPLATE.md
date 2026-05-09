# Trajectory 5 Ticket Template

**Status**: normative shape for every release work-X.y ticket. Lane A, B, and C
ticket files MUST emit tickets in this exact form so the close-bar tracker
and `scripts/check-release work-evidence-gate.sh` can parse them.

**Origin**: shaped after `.planning/trajectory-4/EXECUTION-BOARD.md` lines
56-87 with the trj4 erratum's failure modes addressed by the Evidence Gate
fields below.

---

## 1. Required fields

Every ticket emits the following block. No field is optional.

```
| Ticket | release work-X.y |
|---|---|
| Title | <short imperative title> |
| Lane | A | B | C |
| Sub-lane | A1 | A2 | A3 | B1 | B2 | B3 | B4 | C1 | C2 | C3 | C4 |
| Files | <comma-separated list of paths the ticket touches> |
| Effort | XS | S | M | L | XL |
| Depends on | release work-..., release work-..., or - |
| Owner-class | substrate-eng | protocol-eng | federation-eng | sre-eng | refactor-eng | demo-eng |
| Status | OPEN | EVIDENCE-PENDING | EVIDENCE-COMPLETE |
| Acceptance | see Evidence Gate (`.planning/trajectory-5/templates/EVIDENCE-GATE.md`) |
```

### 1.1 ID convention

`release work-<X>.<y>` where:

- `X` is the sub-lane id (`A1`, `A2`, ..., `B1`, ..., `C1`, ...).
- `y` is a zero-padded sequence within the sub-lane (`01`, `02`, ...).

Evidence Gate tickets use the `.E` suffix: `release work-B1.E`, `release work-B2.E`, etc.
There is one `.E` ticket per sub-lane.

### 1.2 Effort scale

| Code | Person-days | Examples |
|---|---|---|
| XS | <= 0.5 | one-line schema entry; one CI check addition |
| S | 0.5-2 | one new function + one new test |
| M | 2-5 | one new module; multi-file refactor at one seam |
| L | 5-12 | a sub-lane primitive end-to-end |
| XL | >12 | multi-week effort; SHOULD be split |

If a draft ticket carries `XL`, it MUST be split before close. XL exists to
flag mis-sized work, not to permit it.

---

## 2. Acceptance Criteria Block

The acceptance section follows a fixed shape so the gate script can parse
it. Lane A, B, C variants below.

### 2.1 Lane B / Lane C (Evidence Gate enforced)

```
## Acceptance

1. **Production wiring**: <one-sentence description of the call site>.
   - Enforced call site: crates/<crate>/src/<file>:<line>
2. **Spec MUST**: <quoted MUST text, <= 15 words, in quotation marks>.
   - Citation: spec/PROTOCOL.md section <N.M.K> lines <a>-<b>
3. **Negative conformance test**: crates/chio-conformance/tests/<file>.rs
   - Imports the production module directly (no mock, no test-local copy).
   - Fails when the call site is reverted (proof: <CI URL or revert procedure>).
4. **Audit-doc evidence**: `.planning/trajectory-5/audits/<audit>.md`
   `### release work-X.y` block records all four artifacts.
5. **Banner update** (if applicable): the README/CLAIMS banner reflects the
   new state. Banner-vs-reality drift is a close-blocker.

This ticket closes only when all five rows are checked AND
`scripts/check-release work-evidence-gate.sh` returns 0 in CI.

See: `.planning/trajectory-5/templates/EVIDENCE-GATE.md` section 1.
```

### 2.2 Lane A (floor / threat coverage)

```
## Acceptance

1. **Real-evidence artifact**: <description of the JSON/proof produced>.
   - Path: audits/evidence/threats/<id>.json (or audits/evidence/mutants/<crate>.json,
     or formal/<spec>.tla, or crates/<crate>/proofs/<harness>.rs).
2. **caught >= 1, ran_at non-1970**: the JSON's `caught` field is >= 1, the
   `ran_at` field is a valid RFC-3339 timestamp from a real run, and
   `needs_real_run` is false.
3. **Production call path**: the test or harness exercises code under
   crates/<crate>/src/<file>:<line>, not a fixture or copy.
4. **CI run URL**: the workflow run that produced the artifact is recorded in
   the audit doc.
5. **Banner update**: README mutation banner / threat-coverage banner is
   recomputed from the artifact, not hand-edited.

This ticket closes only when all five rows are checked AND
`scripts/check-threat-coverage.sh` (or the equivalent gate for the
sub-lane) returns 0 in CI.

See: `.planning/trajectory-5/templates/EVIDENCE-GATE.md` section 1.3 (Lane A row).
```

### 2.3 Evidence Gate ticket (.E suffix)

The `.E` ticket for a sub-lane closes only when EVERY ticket in that
sub-lane is in `EVIDENCE-COMPLETE`. It also lands the spec amendment, the
schema update, and the audit-doc signoff.

```
## Acceptance (Evidence Gate ticket)

1. All release work-X.y tickets in sub-lane X are EVIDENCE-COMPLETE.
2. spec/PROTOCOL.md amended (SHOULD -> MUST where required by sub-lane).
3. Relevant JSON schemas under spec/schemas/ updated.
4. Claim registry (`spec/registries/claim-registry.v1.json`) carries the
   sub-lane's claim.
5. Proof manifest (`spec/registries/proof-manifest.v1.json`) ties claim to
   evidence paths.
6. Theorem inventory (`spec/registries/theorem-inventory.v1.json`) updated
   if any Lean/TLA+ theorem refines.
7. Generated proof report regenerated.
8. Audit doc `.planning/trajectory-5/audits/<audit>.md` signed off by lane
   owner AND a non-author reviewer.
9. Close-bar snapshot at `audits/evidence/close-bar-snapshot.json` records
   the sub-lane as PROVEN_WIRED.
```

---

## 3. Worked Example (Lane B1)

```
| Ticket | release work-B1.03 |
|---|---|
| Title | Make `verify_capability_full` the only production capability verifier |
| Lane | B |
| Sub-lane | B1 |
| Files | crates/chio-kernel/src/kernel/mod.rs, crates/chio-kernel-core/src/capability_verify.rs, scripts/check-verify-capability-full.sh |
| Effort | M |
| Depends on | release work-A0.01 (async-trait migration prerequisite) |
| Owner-class | protocol-eng |
| Status | OPEN |

## Acceptance

1. **Production wiring**: every governed capability decision in the kernel
   hot path routes through `verify_capability_full`; partial entries are
   `#[doc(hidden)]` and crate-private.
   - Enforced call site: crates/chio-kernel/src/kernel/mod.rs:<line-after-patch>
2. **Spec MUST**: "production kernels MUST use the W1.5 composite entrypoint".
   - Citation: spec/PROTOCOL.md section 5.4 lines 408-418 (post-amend).
3. **Negative conformance test**:
   crates/chio-conformance/tests/b1_capability_partial_entry_disallowed.rs
   - Imports `chio_kernel_core::capability_verify` directly.
   - Asserts a build-time or runtime guard fires when a partial entry is
     called from production code.
   - Fails when `scripts/check-verify-capability-full.sh` is removed.
4. **Audit-doc evidence**: `.planning/trajectory-5/audits/lane-b-protocol.md`
   `### release work-B1.03` block records all four artifacts.
5. **Banner update**: not applicable (no public banner for this primitive).

This ticket closes only when all five rows are checked AND
`scripts/check-release work-evidence-gate.sh` returns 0 in CI.

See: `.planning/trajectory-5/templates/EVIDENCE-GATE.md` section 1.
```

---

## 4. State Machine

```
OPEN
  -> (PR opened, code merged) ->
EVIDENCE-PENDING
  -> (audit-doc records all four artifacts AND gate script passes) ->
EVIDENCE-COMPLETE
  -> (audit-doc signoff by sub-lane Evidence Gate ticket) ->
(sub-lane bucket: PROVEN_WIRED in close-bar snapshot)
```

The state field in the ticket header is updated by the audit-doc owner. The
close-bar tracker workflow reads the audit doc and recomputes
`audits/evidence/close-bar-snapshot.json` on every PR to `main`.

---

## 5. Anti-Patterns

### 5.1 Acceptance criteria as prose, not list

A ticket whose acceptance section is "this should make the verifier
correct" is not parseable by the gate script and is a close-blocker.

### 5.2 Spec citation to a SHOULD

If the cited spec line range contains only `SHOULD`, the ticket is incomplete.
Promoting `SHOULD` to `MUST` is part of the ticket's scope.

### 5.3 "Tests pass" as the only criterion

`cargo test` passing on the new file is necessary but not sufficient. The
test MUST exercise the production call path AND the test MUST fail when the
call site is reverted. Both rules are checked by the Evidence Gate, not by
`cargo test`.

### 5.4 Files list missing the production crate

Every Lane B / Lane C ticket touches at least one file in
`crates/chio-{kernel,kernel-core,anchor,federation,core-types}/src/`. If
the Files row contains only test files and schema JSONs, the ticket is
structural-framing-only. See
`.planning/trajectory-5/templates/EVIDENCE-GATE.md` section 2.4.

### 5.5 Owner-class mis-assigned

A "substrate-eng" owner cannot close a Lane C demo ticket; a "demo-eng"
owner cannot close a Lane A Kani harness ticket. Mis-assigned ownership
short-circuits review.
