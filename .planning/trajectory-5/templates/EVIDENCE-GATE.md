# Trajectory 5 Evidence Gate

**Status**: normative. This document is the contract every closing release work-X.y
ticket cites. It is not guidance. It is rules.

**Origin**: `.planning/trajectory-4/TRAJECTORY-4-CLOSEOUT-ERRATUM.md` (2026-05-05).
The erratum recorded that approximately 30 P0/P1 issues were filed against
artifacts the prior closeout had marked Closed or Validation. Trj4 used a
weaker close bar; release work uses this one.

**Audience**: Lane A (floor: mutation kill, threat-coverage real runs, Kani,
TLA+, Lean), Lane B (hot-path wiring of negotiation/receipt-v2/anchor-batch),
Lane C (one bilateral cosigned demo). Every ticket in every lane closes against
this document.

---

## 1. The Four-Artifact Rule

A release work-X.y ticket flips from `EVIDENCE-PENDING` to `EVIDENCE-COMPLETE` only when
ALL FOUR of the following are committed in the same merged PR (or in a chain of
PRs whose final PR carries the audit-doc signoff). Any one missing keeps the
ticket open. There is no "three of four". There is no provisional close.

### 1.1 Artifact A: Enforced call site

A path-and-line reference to production code that performs the check. The
call site MUST be inside a non-test, non-example, non-`#[cfg(test)]` module of
a workspace crate that is on the kernel/verifier/anchor/federation/edge hot
path.

Format in the ticket:

```
Enforced call site: crates/<crate>/src/<file>:<line>
```

A reference to a fixture, a `mod tests`, an `examples/` binary, a doc-test, or
a `dev-dependencies`-only crate is not an enforced call site. The call site
MUST be reachable from a public production entry point used by at least one
shipping artifact (`chio` binary, `chio-cli`, `chio-mcp-edge`, `chio-tower`,
`chio-federation`, `chio-anchor`, `chio-kernel-mobile`, or `chio-kernel-browser`).

### 1.2 Artifact B: Spec MUST citation

For Lane B (protocol realization) and Lane C (forcing demo): a citation to
`spec/PROTOCOL.md` (or `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` /
`spec/CHIODOS_SELECTIVE_DISCLOSURE.md` for Lane C) of the form:

```
Spec MUST: spec/PROTOCOL.md section <N.M.K> lines <a>-<b>
```

The cited lines MUST contain the literal token `MUST` (RFC 2119 sense) AT THE
TIME OF AUDIT-DOC SIGNOFF. If the line range contains only `SHOULD` (or only
descriptive prose, e.g. PROTOCOL.md lines 737-741 today which read "falls
back" with neither MUST nor SHOULD), the ticket has not yet brought the spec
language into MUST shape and MUST do so before close. Two equivalent paths to
satisfy this:

- **Promotion** (e.g. B1: line 408 `SHOULD prefer` -> `MUST route through`).
  The previous language was a SHOULD; the ticket promotes it to MUST.
- **Tightening** (e.g. B2: lines 737-741 currently descriptive prose with
  neither MUST nor SHOULD; the ticket REWRITES the prose to introduce a NEW
  normative MUST). This is NOT a SHOULD-to-MUST promotion; it is a fresh
  introduction of a normative rule. The audit-doc evidence block MUST mark
  the change explicitly as "tightening" so the reviewer does not misread it
  as promotion.

Either path satisfies Artifact B as long as the post-edit cited lines contain
`MUST`. The ticket scope MUST include the spec edit; promotion or tightening
cannot be deferred.

The `scripts/check-release work-evidence-gate.sh` script (Wave 1 deliverable) reads
the audit-doc-cited spec lines from the merged-branch HEAD of `spec/PROTOCOL.md`
(NOT from the synthesis-time snapshot), so a tightening that lands the spec
edit in the same PR will pass the gate.

For Lane A (floor): the citation is to the audit-evidence JSON whose
`coverage_state` flips from `pending` to `covered`, of the form:

```
Audit JSON: audits/evidence/threats/<id>.json
```

That file MUST then satisfy: `caught >= 1`, `needs_real_run: false`, and
`ran_at` is a non-1970 RFC-3339 timestamp.

### 1.3 Artifact C: Signed negative conformance test

The test path is fixed by lane:

| Lane | Test home |
|---|---|
| A (floor / threat coverage) | `audits/evidence/threats/<threat_id>.json` plus the test invoked by `scripts/check-threat-coverage.sh` |
| A (mutation / Kani / TLA+) | `crates/<crate>/proofs/` for Kani, `formal/<spec>.tla` for TLA+, `audits/evidence/mutants/<crate>.json` for cargo-mutants |
| B (protocol primitives) | `crates/chio-conformance/tests/<lane>_<primitive>_<negative_case>.rs` |
| C (forcing demo) | `examples/<demo>/fixtures/<negative_case>.rs` plus `crates/chio-conformance/tests/cross_org_<demo>_<negative_case>.rs` |

The test MUST be negative: it MUST assert that the runtime rejects, denies, or
fails closed when an attacker-controlled input violates the MUST. A test that
asserts only happy-path behavior does not satisfy Artifact C.

### 1.4 Artifact D: Production call path exercise

The test in Artifact C MUST execute the call site in Artifact A. Concretely:

- The test imports the production module by its workspace path (`use
  chio_kernel::...`, `use chio_anchor::...`), not a copy.
- The test does not mock or stub the function under test. It may mock external
  systems (HTTP, OS time, randomness) but it MUST drive the real verifier or
  the real kernel dispatch path.
- If the production call site is reverted (the enforcement removed), the test
  MUST fail. The ticket records a one-line proof of this in the form of either:
  (a) a CI run URL where the test failed when the change was reverted, or
  (b) a `git stash`-and-rerun procedure documented in the test header comment
  with the expected failure message.

A test that passes against a stub, a copy of production code, or only a schema
validation does NOT satisfy Artifact D, regardless of how thorough it looks.
This is the single most-violated rule in the trj4 erratum's findings.

---

## 2. Anti-Pattern Catalog

Each entry is a concrete failure mode the trj4 erratum or the Quality Skeptic
identified. If a release work reviewer detects any of these in a closing PR, the
ticket goes back to `EVIDENCE-PENDING`.

### 2.1 `caught: 0` placeholder

Pattern: `audits/evidence/threats/<id>.json` reads:

```json
{
  "caught": 0,
  "needs_real_run": true,
  "note": "Bootstrap placeholder. ...",
  "ran_at": "1970-01-01T00:00:00Z",
  "survivors": []
}
```

All 20 files in `audits/evidence/threats/` had this shape on 2026-05-07
(synthesis says "21"; on-disk count is 20, one per row in
`spec/security/chio-threat-model.v1.json` -- Lane A targets 20 as
authoritative). The 20/0/0 PASS banner in
`scripts/check-threat-coverage.sh` was a placeholder PASS. Real close
requires `caught >= 1` and a non-1970 timestamp from a real mutation
run on a real production call path.

### 2.2 File-exists-without-no-unimplemented

Pattern: a `.rs` file is checked in, the file compiles, but the production
function it claims to implement still contains `unimplemented!()`,
`todo!()`, or returns `Err(KernelError::Unsupported(_))` on the path that
actually matters. CI does not catch this because nothing exercises the path.

Detection rule: every release work close MUST run
`grep -rn 'unimplemented!\|todo!\|"not yet implemented"' <touched_files>` and
verify the production hot-path function does not contain any of these on the
governed path.

### 2.3 Mock-not-runtime

Pattern: the conformance test imports a struct named like the production type,
but it is in fact a near-copy declared in the test file or in a `tests/common/`
helper. The test passes; production is unaffected.

Detection rule: every release work conformance test MUST satisfy `cargo expand` in
the test crate showing only `chio_kernel`, `chio_anchor`, `chio_federation`,
`chio_kernel_core`, `chio_core_types`, `chio_core` (and equivalents) as the
imports of the function under test. If a test-local helper redefines a
production type, the test does not exercise the production path.

### 2.4 Structural-framing-without-wiring

Pattern: types are defined, schemas are emitted, registry entries are added,
doc generators run. But the kernel hot path branches around the new type, or
calls a partial entry point, or defaults to the old behavior on the negotiated
profile. PROTOCOL.md says "fails closed"; the runtime says "warns and
continues".

Concrete trj4 examples (cited in `.planning/trajectory-5/debate/02-protocol-realization-engineer.md`):

- `verify_capability_full_without_budget_admit` is the production hot-path
  entry; the spec MUST cites `verify_capability_full`. The composite verifier
  exists, it is not the only entry point.
  (`crates/chio-kernel/src/kernel/mod.rs:4035-4047`).
- Receipt v2 dual-mint emits "a structured warning so operators can see
  receipt-version regressions" when negotiation said v2. The spec language
  at PROTOCOL.md lines 737-741 is currently descriptive prose ("the kernel
  falls back to minting only the v1 UUIDv7 receipt") with neither MUST nor
  SHOULD; B2 introduces a NEW normative MUST (this is a tightening, not a
  promotion). (`crates/chio-kernel/src/kernel/mod.rs:1574-1591`,
  `kernel_receipt_version_for_remote`). Note: synthesis line 31 cited
  `:1148-1165` which is the resolver helper `KernelReceiptVersion::from_capabilities`,
  not the runtime downgrade.
- `verify_anchor_batch` (sync) is still callable when
  `require_public_witness=true` even though PROTOCOL.md §982-991 mandates the
  async verifier. (`crates/chio-anchor/src/batch.rs:208`).

### 2.5 Tautological proof (`rfl` against own definition)

Pattern: a Lean4 / Coq theorem is recorded as `proven` but the proof is
`rfl` (or `Eq.refl`, or `simp` against the same definition the theorem
quantifies). The proof refines nothing; it asserts a definitional equality.

Concrete trj4 example: `negotiation_safety` in `formal/theorem-inventory.json`
proven by `rfl`. `formal/theorem-inventory.json` had 0 of 75 IDs in the
`proven` state with substantive proofs.

Detection rule: every Lane A Lean4 close MUST cite an executable model
(written separately from the theorem, executable via `lake exe`) that the
theorem refines. A theorem proved against itself is rejected.

### 2.6 Banner-vs-reality drift

Pattern: a README or release note advertises a metric (mutation kill 65%,
20/0/0 threat coverage, "all Kani harnesses green") that the underlying CI
job either does not run, runs in warn-only mode, or runs against a
placeholder fixture.

Detection rule: every release work banner MUST reference the workflow run URL of the
job that produced the banner number, plus the artifact path that contains
the raw output. `chio-attest-verify` mutation kill 80%? Cite the run, cite the
artifact, cite the survivors.

### 2.7 Coverage-state stuck on `pending`

Pattern: a threat row in `docs/security/threat-coverage.md` claims
`coverage_state: covered` in prose but `audits/evidence/threats/<id>.json`
still contains `coverage_state: pending` or the JSON file is missing the
field entirely.

Detection rule: every Lane A close MUST run `scripts/check-threat-coverage.sh`
locally AND in CI. The script's per-row JSON output is the source of truth;
prose narrative is descriptive only.

### 2.8 Schema-only test

Pattern: a conformance test deserializes a wire artifact, runs JSON-schema
validation, and asserts schema rejection. It never calls the verifier, never
invokes the kernel, never runs the production decision path.

The schema is part of the contract, but schema validation is not enforcement.
Many primitives in trj4 had schema-only negative tests; the runtime would
have allowed the same input.

Detection rule: every Artifact C in Lanes B and C MUST call at least one
function whose name starts with `verify_`, `dispatch_`, `mint_`, `sign_`,
`build_`, or equivalent (the production verb), against the production type.

---

## 3. Close-Bar Tracker Integration

Every release work-X.y ticket carries one of three states. Transitions are
machine-checkable.

### 3.1 OPEN

Initial state. No work has produced merged code yet, or the work is in
progress and the audit-doc evidence section is empty.

### 3.2 EVIDENCE-PENDING

Work has merged. The four artifacts MAY be in place, but the audit-doc has
not yet recorded all four with paths and lines, OR the
`scripts/close-bar-snapshot.sh` (Wave 0 deliverable) has not yet recomputed.

A ticket can sit in `EVIDENCE-PENDING` for at most one wave. If two
consecutive waves end with the ticket still in `EVIDENCE-PENDING`, the audit
doc owner MUST escalate or downgrade the ticket to a deferred-to-trj6 row.

### 3.3 EVIDENCE-COMPLETE

All four artifacts recorded in the audit doc. The audit doc has been signed
off by both the lane owner AND a reviewer who is not the ticket author. The
close-bar snapshot at `audits/evidence/close-bar-snapshot.json` records the
ticket as `bucket: PROVEN_WIRED`, `wired_runtime_path: y`,
`negative_conformance_test: <path>`, and (for Lane A theorem rows)
`theorem_status: proven`.

### 3.4 Audit-doc evidence section format

Every release work audit doc MUST contain a section named `## Evidence` with a
sub-section per ticket of the form:

```
### release work-X.y: <title>

- Enforced call site: crates/<crate>/src/<file>:<line>
- Spec MUST: spec/PROTOCOL.md section <N.M.K> lines <a>-<b>
  (or Audit JSON: audits/evidence/threats/<id>.json)
- Negative conformance test: crates/chio-conformance/tests/<test>.rs
  (or audits/evidence/threats/<id>.json with caught >= 1)
- Production call path exercise:
  - Test imports: <list of crate paths>
  - Failure proof: <CI run URL or revert-and-rerun procedure>
- State: EVIDENCE-COMPLETE
```

Any field marked `TBD-from-W{1,2}` is acceptable in the audit-doc skeleton
that lands at the start of the wave. It is NOT acceptable on the close PR.

### 3.5 Workflow gating

The `.github/workflows/close-bar-tracker.yml` workflow (existing, see
`.github/workflows/`) is extended by Wave 1 to run
`scripts/check-release work-evidence-gate.sh` (a Wave 1 deliverable, TBD-from-W1).
The script reads the audit doc, parses each `### release work-X.y` block, and
fails CI if:

- Any cited path does not exist.
- Any cited line range in `spec/PROTOCOL.md` does not contain `MUST`.
- Any cited test crate does not include the cited test name.
- Any audit-evidence JSON has `caught: 0` or `ran_at: 1970-*`.

CI failure on this script blocks the ticket-closing PR. There is no `--force`
flag.

---

## 4. Cross-References

- Lane B fixture pattern: `.planning/trajectory-5/templates/CONFORMANCE-FIXTURE-PATTERN.md`.
- Ticket shape: `.planning/trajectory-5/templates/TICKET-TEMPLATE.md`.
- Async migration prerequisite: `.planning/trajectory-5/architecture/ASYNC-KERNEL-MIGRATION.md`.
- Spec-to-runtime gap inventory: `.planning/trajectory-5/architecture/SPEC-TO-RUNTIME-MAP.md`.
- Risk register: `.planning/trajectory-5/architecture/RISK-REGISTER.md`.

---

## 5. The One-Line Summary

A release work ticket closes when an external auditor can read the audit doc and,
without running CI, point to a path:line where production enforces the rule
and a test path that fails when that line is reverted. Anything less is the
trj4 pattern.
