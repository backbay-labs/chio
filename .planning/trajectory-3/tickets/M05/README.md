# M05: Threat-Coverage Closure

**Wave:** W1  |  **Trust-boundary:** yes  |  **Tickets:** 12  |  **Effort weeks:** 3/5/7

## In one paragraph

M05 closes the three named carry-forward gaps from trajectory-2:
weights_hash_spoof flips partial->covered via a recomputable
loaded-weights digest under `chio-provider-conformance`; the M06
dispatch_allow Criterion bench placeholder is replaced with a real
wall-clock check on the production dispatch path; the third M06
placeholder (the dispatch_allow dhat allocation-count probe) is
evicted with a real measured budget. The eight remaining advisory
pending threats are reclassified (two flip to `covered`, six receive
`deferred_to` references). The coverage gate
`scripts/check-threat-coverage.sh` flips to fail-closed on `partial`
and on `pending` lacking `deferred_to`. Release gate is RELEASE_AUDIT:
the threat-coverage table has zero `partial` rows and zero `pending`
rows lacking a `deferred_to` reference.

## Phases at a glance

| Phase | Tickets | Effort (days) | One-liner |
|-------|---------|---------------|-----------|
| P0 | 1 | 1.0 | Audit baseline + coverage.yaml/JSON reconciliation + freeze path-of-record decision |
| P1 | 3 | 4.0 | weights_hash_spoof partial -> covered (LoadedWeights trait + adapter impls + test body) |
| P2 | 2 | 3.5 | dispatch_allow Criterion placeholder replaced with real wall-clock measurement |
| P3 | 1 | 2.0 | dispatch_allow_dhat placeholder evicted with real allocation-count budget |
| P4 | 3 | 4.0 | Coverage gate flip + advisory threats reclassified |
| P5 | 2 | 1.5 | Closeout audit + M08 reviewer-handoff cross-ref hook |

Total: 12 tickets, 16.0 effort-days.

## Locked decisions

- D14 closure scope: three named gaps + classification only; M07/M10
  introductions out of scope.
- LoadedWeights trait lands under `chio-provider-conformance` (not a
  new `chio-providers` crate) per research §1 option 1.
- dispatch_allow path-of-record: amend freeze path_globs to point at
  `crates/chio-kernel/benches/dispatch_allow*.rs` (matches live
  tree). P0.T1 ships the freeze amendment.

## Active freezes

- `m05-threat-coverage-pivot` covers
  `spec/security/chio-threat-model.v1.json`,
  `crates/chio-conformance/tests/threats/**`,
  `crates/chio-attest-verify/src/policy.rs`,
  `crates/chio-kernel/benches/dispatch_allow*.rs` (post-P0.T1
  amendment), and `docs/security/threat-coverage.md` during P1-P4.
- `m04-m05-attest-verify-coupling` (M04-owned) covers
  `crates/chio-attest-verify/src/**` from M04.P3.T1 to M04.P5.T5.
  M05.P0 and M05.P1 may run during the M04 freeze; M05.P2/P3/P4
  wait for M04.P5.T5 close.

## When this milestone is done

- `spec/security/chio-threat-model.v1.json` has zero `partial` rows
  and zero `pending` rows lacking `deferred_to`.
- `scripts/check-threat-coverage.sh` fails closed on `partial` and
  on `pending` without `deferred_to`.
- `crates/chio-kernel/benches/dispatch_allow.rs` and
  `dispatch_allow_dhat.rs` measure real dispatch-path numbers.
- `.planning/trajectory-3/audits/M05-threat-coverage.md` Section 3
  closure log filled row-by-row; Section 4 cites the post-flip CI
  run URL.
- The M08 reviewer cross-checks closure in their report.
