# M04: Mutation Gate + Verdict Matrix Promotion

**Wave:** W1  |  **Trust-boundary:** yes  |  **Tickets:** 17  |  **Effort weeks:** 9-12

## In one paragraph

M04 promotes the trajectory-2 mutation lane and verdict matrix from
advisory to gating at honest thresholds. Target kill-score floor is
80% per crate; D08 accepts 65% as the honest floor, and the gate
flips at the achieved value rather than slipping M08. The
trajectory-2 M02 closeout 30.7% aggregate is misleading on
inspection: per-crate spread runs from 0% on `chio-attest-verify`
(the gate-flip blocker) to 100% on bounded shards too small to be
load-bearing. M04 captures full-sweep per-crate baselines, runs
targeted survivor sweeps (proptests on `chio-kernel-core`, fixture
suites on `chio-attest-verify`, predicate negative tests on
`chio-credentials`, boundary tests on `chio-policy`, full sweeps
on `chio-guards` / `chio-anchor`), verifies M02-owned Python and Go
verdict-matrix drivers reach `status = "active"` with zero
unsupported / zero divergence, then flips both gates with a
two-consecutive-green observation. Release gate: QUALIFICATION;
M08 reviewer cites the gate value.

## Phases at a glance

| Phase | One-liner |
|-------|-----------|
| P0 | Audit doc + per-crate full-sweep kill-score baseline |
| P1 | Mutant survivor sweep on lagging crates (chio-attest-verify priority) |
| P2 | Verify M02 Python + Go verdict-matrix drivers active and zero divergence |
| P3 | Mutation lane flip to required (releases.toml gate-flip PR) |
| P4 | Verdict-matrix Python + Go drivers flip to required (verdict-matrix.yml) |
| P5 | M04 audit doc closure + M08 handoff artefact set |

## Locked decisions

- **D06 (trajectory-2):** six trust-boundary crates bind the gate;
  do NOT widen to `chio-weights`, `chio-custody-hw`, or
  `chio-cross-protocol`.
- **D08:** week-12 contingency: ship gate at honest threshold;
  target 80%, accept 65% floor; do NOT slip M08. M04.P3.T1 carries
  the floor-vs-target rule explicitly.

## Active freezes

- `m04-mutation-gate-pivot` (P3-P5): covers `.cargo/mutants.toml`,
  `mutants-baseline.toml`, `.github/workflows/mutation-coverage.yml`
  (file-of-record name; live path is `.github/workflows/mutants.yml`),
  `.github/workflows/verdict-matrix.yml`,
  `crates/chio-conformance/verdict_matrix/**`. Start: M04.P3.T1.
  End: M04.P5.T5.
- `m04-m05-attest-verify-coupling` (P3-P5): covers
  `crates/chio-attest-verify/src/**`. M04.P3.T1 close is a
  precondition for M05 starting `dispatch_allow.rs` work in
  `m05-threat-coverage-pivot`.
- `m02-m04-verdict-matrix-coupling` (M02 P2-P3): covers
  `crates/chio-conformance/verdict_matrix/**`. M02 P2 (Python
  driver) and P3 (Go driver) MUST close before M04.P3 opens, so
  the non-Rust drivers reach `passing` before they are gated.

## Cross-milestone dependencies

- Hard-dep on M03 hosted-CI restoration: nightly mutation +
  verdict-matrix runs require billing-restored hosted runners to
  produce the two-consecutive-green observation P3 and P4 flip on.
- Hard-dep on M02 P2 (Python driver) and M02 P3 (Go driver) per the
  freeze sequence above.
- Downstream: M05 P2.T1 (`dispatch_allow` placeholder eviction) opens
  AFTER M04.P5 closes; the `m04-m05-attest-verify-coupling` freeze
  enforces this. M08 reviewer cites the M04 gate value
  (`08-independent-crypto-protocol-review.md` line 118).

## When this milestone is done

- Mutation lane required-CI green on the six trust-boundary crates
  at the activation threshold (>= 65% per crate; aim 80%).
- Verdict-matrix `python-sdk` and `go-http-sdk` required-CI green
  with zero divergence vs `rust-kernel`.
- `releases.toml [mutants]` carries the activation_evidence YAML
  block, `cycle_end_tag` non-empty, and
  `activation_threshold_percent_per_crate` populated.
- `.planning/trajectory-3/audits/M04-mutation-gate.md` records
  achieved kill-rate per crate, gap analysis per D08, and the M08
  handoff artefact set; two nightly-run JSONs committed under
  `M04-mutation-gate-evidence/`.
