# M05 Audit: Threat-Coverage Closure

**Trajectory:** trajectory-3
**Milestone:** M05
**Wave:** W1
**Status:** Closed 2026-05-02; zero partial rows and all pending rows carry `deferred_to`.
**Audit start:** 2026-05-02 (P0 baseline merge target)
**Audit close:** 2026-05-02T10:38:43Z

## 1. Audit scope

M05 closes the three named carry-forward gaps from trajectory-2 and
classifies remaining advisory threats. Release gate: RELEASE_AUDIT;
zero `coverage_state: partial` rows and zero `coverage_state: pending`
rows lacking a `deferred_to` reference at milestone close.

Bounded scope per D14:

- weights_hash_spoof (`partial` -> `covered`)
- dispatch_allow Criterion bench (placeholder -> real check)
- dispatch_allow dhat bench (third M06 placeholder, evicted)
- Eight advisory threats classified (`covered` or `deferred_to`)
- Coverage gate flip (`scripts/check-threat-coverage.sh` fails on
  `partial` and on `pending` lacking `deferred_to`)

Out of scope per D14: new threat IDs from M07 (mobile) or M10
(distribution); enum widening; `chio-providers` crate creation.

## 2. Hard counts at P0

Reproduce by running the named command in the worktree at
`.worktrees/trajectory-3/`. Date stamp: 2026-04-30.

- `coverage_state: partial` row count: 0
  (`python3 -c "import json; d=json.load(open('spec/security/chio-threat-model.v1.json')); print(sum(1 for t in d['threats'] if t.get('coverage_state')=='partial'))"`)
- `coverage_state: placeholder` row count: 0 (the JSON enum admits
  `{covered, partial, pending}` only; `placeholder` is shorthand for
  the dispatch_allow benches and is not a JSON state)
- `coverage_state: pending` row count: 11
  (`python3 -c "import json; d=json.load(open('spec/security/chio-threat-model.v1.json')); print(sum(1 for t in d['threats'] if t.get('coverage_state')=='pending'))"`)
- coverage_state: pending. row count: 11 (literal P0 gate marker)
- `coverage_state: covered` row count: 6
- Per-threat stub files calling `unimplemented!()`: 11 of 17
  (`grep -l 'unimplemented!' crates/chio-conformance/tests/threats/*.rs | wc -l`)
- Advisory threats with no coverage row: 0 (all 17 carry a
  coverage_state; pending rows lacking `deferred_to` are the closure
  target, not orphans)
- `spec/security/coverage.yaml` rows: 3 (`passkey_credential_theft`,
  `audience_confusion`, `weights_hash_spoof`)
- `spec/security/coverage.yaml` partial rows: 1 (`weights_hash_spoof`)
- coverage.yaml-vs-JSON divergence: 3 rows (all three YAML rows
  disagree with the JSON state)
- `crates/chio-kernel/benches/dispatch_allow*.rs`: 2 placeholder
  benches (Criterion + dhat); both are M05 closure targets
- `chio-providers` crate existence: NO
  (`grep -l '^name = "chio-providers"' crates/*/Cargo.toml` returns
  nothing); LoadedWeights trait lands under `chio-provider-conformance`
  per research §1 option 1

### 2.1 coverage.yaml vs JSON divergence (P0 reconciliation)

| Threat ID | JSON state | YAML state | P0 reconciliation |
|-----------|------------|------------|-------------------|
| passkey_credential_theft | pending | covered | Flip JSON to `covered` (M10.P2.T6 closed); update at P4.T2 |
| audience_confusion | pending | covered | Flip JSON to `covered` (M10.P2.T4 closed); update at P4.T2 |
| weights_hash_spoof | pending | partial | M05.P1 closes; flip both surfaces to `covered` at P1.T3 |

### 2.2 dispatch_allow path-of-record (P0.T1 decision)

- Freeze `m05-threat-coverage-pivot.path_globs` names
  `crates/chio-attest-verify/src/dispatch_allow.rs`.
- Live placeholders at `crates/chio-kernel/benches/dispatch_allow.rs`
  and `crates/chio-kernel/benches/dispatch_allow_dhat.rs`.
- Recommended: amend freeze path_globs to point at the chio-kernel
  benches.
- Decision: amend the freeze to the live chio-kernel benches. The
  path-of-record for M05 P2/P3 is
  `crates/chio-kernel/benches/dispatch_allow.rs` and
  `crates/chio-kernel/benches/dispatch_allow_dhat.rs`; no
  `crates/chio-attest-verify/src/dispatch_allow.rs` file is created.
  This keeps the implementation aligned with the existing M06
  placeholder family and avoids inventing a new module boundary.

### 2.3 coverage.yaml downstream consumers (P0.T1 grep)

P0 grep command:

`rg -n "spec/security/coverage.yaml|coverage.yaml" .planning/trajectory-2/audits .planning/trajectory-3/audits docs/security`

Consumers found:

- `.planning/trajectory-2/audits/M03-AUDIT.md`: line 146 references
  the `spec/security/coverage.yaml` file shape and requires the M10
  threat IDs to be marked in that companion surface.
- `.planning/trajectory-3/audits/M05-threat-coverage.md`: this audit
  doc is the M05 source of record for the YAML-vs-JSON reconciliation.
- No `docs/security/` consumer currently references
  `spec/security/coverage.yaml`; `docs/security/threat-coverage.md`
  is regenerated from the JSON source.

## 3. Closure log

M05 baseline (P0) of the JSON threat list: 17 threat rows total
(6 covered, 11 pending). M05 closes 5 pending rows to covered
(`weights_hash_spoof`, `pq_signature_downgrade`, `tee_quote_forgery`,
`passkey_credential_theft`, `audience_confusion`) and stamps
`deferred_to` on the remaining 6 pending rows. Net post-M05 state on
the M05.P5 close commit: 11 covered + 6 pending, every pending row
carrying `deferred_to`. M05 deferred zero rows that were previously
covered (no covered -> deferred regressions).

| Threat ID | Before | After | Phase | Cross-ref |
|-----------|--------|-------|-------|-----------|
| weights_hash_spoof | pending (JSON) / partial (YAML) | covered | P1 | M05.P1.T1, T2, T3; chio-provider-conformance LoadedWeights trait |
| dispatch_allow (Criterion) | placeholder (0_u64) | real wall-clock check | P2 | M05.P2.T1, T2; benches/dispatch_allow.rs |
| dispatch_allow_dhat | placeholder (0/0 budgets) | measured allocation budget | P3 | M05.P3.T1; benches/dispatch_allow_dhat.rs |
| pq_signature_downgrade | pending | covered | P4 | M05.P4.T1; chio-conformance/tests/threats/pq_signature_downgrade.rs |
| tee_quote_forgery | pending | covered | P4 | M05.P4.T1; chio-conformance/tests/threats/tee_quote_forgery.rs |
| passkey_credential_theft | pending (JSON) / covered (YAML) | covered | P4 | M05.P4.T2; M10.P2.T6 evidence |
| audience_confusion | pending (JSON) / covered (YAML) | covered | P4 | M05.P4.T2; M10.P2.T4 evidence |
| ssrf_via_http_substrate | pending | pending + deferred_to | P4 | M05.P4.T2; deferred_to `trajectory-4.hosted-http-egress-hardening` |
| pii_phi_exposure | pending | pending + deferred_to | P4 | M05.P4.T2; deferred_to `trajectory-4.healthcare-phi-data-guard-validation` |
| agent_velocity_abuse | pending | pending + deferred_to | P4 | M05.P4.T2; deferred_to `trajectory-4.distributed-rate-limit-store` |
| cumulative_data_exfiltration | pending | pending + deferred_to | P4 | M05.P4.T2; deferred_to `trajectory-4.cross-session-data-flow-accounting` |
| behavioral_sequence_attack | pending | pending + deferred_to | P4 | M05.P4.T2; deferred_to `trajectory-4.behavioral-policy-compiler` |
| wasm_guard_resource_exhaustion | pending | pending + deferred_to | P4 | M05.P4.T2; deferred_to `trajectory-4.wasm-runtime-quota-hardening` |

### 3.1.bis Post-M05 JSON drift (M07 mobile baseline addition)

After M05 closed, M07 (mobile patient-app extension, audit-baseline
commit `f9d87742`) added three mobile-surface threat rows to
`spec/security/chio-threat-model.v1.json`:

- `mobile_attestation_replay`
- `device_key_extraction`
- `play_integrity_token_replay`

These three rows are M07-scope (mobile_ios / mobile_android surfaces);
they are not part of M05's 11-row pending baseline and they are not
M05-scope flips. Today's JSON therefore reads `11 covered + 9 pending`
rather than the `11 covered + 6 pending` that M05 left at close. The
3-row delta is M07 drift, not an M05 accounting error.

Trajectory-3.1 Phase 5.1 (PR #510, commit `664f94be`) stamped
`deferred_to: trajectory-4.M07.real-attestation` on each of the three
M07 mobile rows so the threat-coverage gate passes; that reconciliation
is owned by the M07 audit doc, not by this M05 audit. Trajectory-4
will pick up the 3 mobile rows alongside the 6 M05-deferred rows.

### 3.1 Freeze amendment record

P0.T1 amends `m05-threat-coverage-pivot.path_globs` in
`.planning/trajectory-3/freezes.yml` by replacing the nonexistent
`crates/chio-attest-verify/src/dispatch_allow.rs` path with:

- `crates/chio-kernel/benches/dispatch_allow.rs`
- `crates/chio-kernel/benches/dispatch_allow_dhat.rs`

Commit SHA and PR URL are recorded in the M05.P0 ticket stamp.

### 3.2 dispatch_allow real-check measurements

| Bench | Median (ns) | 95% CI | total_blocks | total_bytes | Reference runner |
|-------|-------------|--------|--------------|-------------|-------------------|
| dispatch_allow (Criterion) | 67,495 ns | 67,414 ns to 67,820 ns | n/a | n/a | local quick bench, warm cache; hosted replay tracked in CI-DEBT |
| dispatch_allow_dhat | n/a | n/a | 410 measured, 512 budget | 34,075 measured, 40,960 budget | local dhat smoke; final 4-core Linux replay pending |

### 3.3 Coverage gate post-flip behavior matrix

| coverage_state | deferred_to | Gate result |
|----------------|-------------|-------------|
| covered | irrelevant | PASS if test body populated |
| covered | irrelevant | FAIL if test body still calls unimplemented!() |
| partial | irrelevant | FAIL (no escape hatch in trajectory-3) |
| pending | populated | PASS (advisory deferral) |
| pending | empty / missing | FAIL |
| any other | irrelevant | FAIL ("unknown coverage_state") |

(Unit test at `scripts/tests/check-threat-coverage.test.sh` exercises
the six cells.)

## 4. Closure attestations

- Threat-coverage table validated zero-partial: https://github.com/bb-connor/arc/actions/runs/25249973328
  (`threat-model-coverage` queued on M05.P4 merge commit
  `8da02be92bb8c2f7265feb8aa43233c7d2fbfe8a`; local P5.T1 gate
  rechecked zero `coverage_state: partial` rows before close).
- M08 reviewer cross-checks closure: M08.P1.T6 evidence-pack addendum
  cites this audit doc, `docs/security/threat-coverage.md`, the
  post-flip run URL above, and PR #473 as the reviewer handoff hook.
- Audit doc hash at M08 handoff: recompute with
  `git rev-parse HEAD:.planning/trajectory-3/audits/M05-threat-coverage.md`
  on the M05.P5 merge commit; M08.P1.T6 pins that blob ID in the
  evidence-pack addendum.
