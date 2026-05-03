# M08 Handoff Addendum: M05 Threat-Coverage Closure

**Trajectory:** trajectory-3
**Source milestone:** M05 threat coverage closure
**Consumer:** M08 independent crypto and protocol review
**Date:** 2026-05-02

## Summary

M05 closed the threat-coverage reconciliation that M08 reviewers use as
the row-level oracle for security claims. The milestone removed all
`coverage_state: partial` rows, documented all pending rows with
`deferred_to`, and flipped the threat-coverage check to fail closed on
partial coverage or unknown states.

## Closure points

- `weights_hash_spoof` moved from partial coverage to covered through
  the `chio-provider-conformance` loaded-weight digest path.
- `dispatch_allow` no longer uses a placeholder Criterion body. The
  path of record is the kernel benchmark family, not a new
  `chio-attest-verify/src/dispatch_allow.rs` module.
- `dispatch_allow_dhat` replaced the third M06 placeholder with a
  measured allocation budget and explicit follow-up replay target.
- `scripts/check-threat-coverage.sh` fails on `partial`, fails on
  pending rows without `deferred_to`, and fails on unknown states.
- `spec/security/chio-threat-model.v1.json` records 17 threat rows for
  M08 cross-check.
- `spec/security/coverage.yaml` keeps the explicit coverage map for
  downstream consumers.

## Reviewer guidance

M08 reviewers should use
`.planning/trajectory-3/audits/M05-threat-coverage.md`,
`spec/security/chio-threat-model.v1.json`, and
`spec/security/coverage.yaml` together. If the JSON threat row and YAML
coverage map disagree, the reviewer should treat the row as
unverifiable until Chio resolves the mismatch. If `weights_hash_spoof`
or `dispatch_allow` evidence fails to reproduce, the expected finding
class is a fail-closed verification gap, not an advisory documentation
issue.

## Gate status

The M05 closeout records (post-M05.P5 snapshot of the 17-row M05-scope
threat list):

- zero partial rows
- zero placeholder JSON states
- 6 pending rows, each with `deferred_to`
- 11 covered rows
- `weights_hash_spoof` covered
- `dispatch_allow` real wall-clock check recorded
- `dispatch_allow_dhat` allocation budget recorded

The M05.P0 baseline of the same 17-row scope was 6 covered + 11 pending;
M05 flipped 5 pending rows to covered and stamped `deferred_to` on the
remaining 6 pending rows.

After M05 closed, M07 (mobile patient-app extension audit baseline)
added three mobile-surface rows to
`spec/security/chio-threat-model.v1.json`
(`mobile_attestation_replay`, `device_key_extraction`,
`play_integrity_token_replay`). Those three rows are M07-scope, not
M05-scope, and are tracked in
`.planning/trajectory-3/audits/M05-threat-coverage.md` section 3.1.bis
as post-M05 JSON drift. The total threat row count today is 20 rather
than the 17 referenced under "Closure points" above, and the current
JSON breakdown is 11 covered + 9 pending. Trajectory-3.1 Phase 5.1
(PR #510) stamped `deferred_to: trajectory-4.M07.real-attestation` on
each mobile row so the threat-coverage gate passes; the
trajectory-4-handover roster therefore includes 9 deferred rows total
(the 6 M05 deferrals plus the 3 M07 mobile rows).

This addendum is append-only and does not reopen M05.
