# M10 Hardware Custody And Model Cards Audit

Measured: 2026-04-30 (P0 baseline) and 2026-04-30 (P5 closing pass).

Scope: hardware custody (passkey issuer + capability cascade) and
policy-bound model cards (signed cards, kernel binding refusal,
`arc bind --card`). This document records the starting counts before
custody crates, fixtures, model-card enforcement, and threat coverage
landed, and the closing counts after the P5 cross-cutting pass.

## Starting counts

| Surface | Baseline | Reproduce |
| ------- | -------- | --------- |
| `chio-custody-hw` crate | 0 crates named `chio-custody-hw` | `ls crates \| grep -c '^chio-custody-hw$'` |
| `chio-weights` crate | 0 crates named `chio-weights` | `ls crates \| grep -c '^chio-weights$'` |
| Passkey and WebAuthn fixtures | 0 matching fixture or source paths under `crates/` | `find crates \( -name '*passkey*' -o -name '*webauthn*' \) -print \| wc -l` |
| New threat IDs | 0 rows for `passkey_credential_theft`, `audience_confusion`, or `weights_hash_spoof` in parent commit `3fa0dd127cf700f4d9b5b7463959907a489c90d0`; 3 rows after this P0 update | `git show 3fa0dd127cf700f4d9b5b7463959907a489c90d0:spec/security/chio-threat-model.v1.json \| rg '"id": "(passkey_credential_theft\|audience_confusion\|weights_hash_spoof)"' \| wc -l` |

## Closing counts

Reproduce on the M10 P5 close worktree (`wave/W4/m10/p5.phase`).

| Surface | Closing | Reproduce |
| ------- | ------- | --------- |
| `chio-custody-hw` source lines | 1,720 lines across `src/*.rs` | `find crates/chio-custody-hw/src -name '*.rs' -exec wc -l {} + \| tail -1` |
| `chio-custody-hw` test lines | 1,329 lines across `tests/*.rs` | `find crates/chio-custody-hw/tests -name '*.rs' -exec wc -l {} + \| tail -1` |
| `chio-weights` source lines | 1,272 lines across `src/*.rs` | `find crates/chio-weights/src -name '*.rs' -exec wc -l {} + \| tail -1` |
| `chio-weights` test lines | 986 lines across `tests/*.rs` | `find crates/chio-weights/tests -name '*.rs' -exec wc -l {} + \| tail -1` |
| Passkey fixture corpus | 8 pinned fixtures (4 positive, 4 negative) at `crates/chio-custody-hw/fixtures/passkey/{positive,negative}/` | `ls crates/chio-custody-hw/fixtures/passkey/positive crates/chio-custody-hw/fixtures/passkey/negative \| grep -c '\.json$'` |
| Threat IDs in `chio-threat-model.v1.json` | 17 total (14 prior register + 3 M10) | `rg '^\s*"id":' spec/security/chio-threat-model.v1.json \| wc -l` |
| `@chio/passkey` TS SDK | 4 source files + 4 spec files at `sdks/typescript/packages/passkey/` | `find sdks/typescript/packages/passkey -name '*.ts' \| wc -l` |
| Demo page assets | 4 files at `docs/demo/passkey/` (index.html, main.ts, passkey.css, test-double.ts) | `ls docs/demo/passkey/` |
| M07 verdict-equivalence smoke green | 5 cases passing under `--features smoke` | `cargo test -p chio-weights --features smoke --test equivalence` |
| Model-card lineage anchor green | 4 cases passing | `cargo test -p chio-weights --test lineage_anchor` |
| Threat coverage gate green | 3 grep hits in `spec/security/coverage.yaml` | `grep -q 'passkey_credential_theft' spec/security/coverage.yaml && grep -q 'audience_confusion' spec/security/coverage.yaml && grep -q 'weights_hash_spoof' spec/security/coverage.yaml` |

## Notes

- `spec/errors/registry.yaml` already reserves the `custody` and `weights`
  domains and includes grep-visible `urn:chio:error:custody:*` and
  `urn:chio:error:weights:*` entries.
- Cargo.lock already contains `base64ct 1.8.3` through existing dependency
  resolution. WebAuthn crates use exact workspace-level requirements for later
  consuming crates; no lockfile entries should be fabricated before a
  consuming crate exists.
- The `chio-weights` lineage anchor (P5.T1) reuses the
  `chio-lineage::anchor` `FrontierDigest`, `CanonicalSource`, and
  `SigningState` shapes verbatim so the public registry serves a single
  artifact format across both lineage-graph and model-card anchors.
- The cross-provider equivalence test (P5.T2) is gated by
  `--features smoke`. The full 8-provider * 12-fixture nightly sweep
  rides the trajectory-1 M07 nightly conformance lane and is not
  duplicated in `chio-weights`.

## Threat-model coverage gate (P5.T3)

The three new threat IDs introduced by M10 land in `spec/security/coverage.yaml`
under the M05 P5.T1 schema (coverage_state enum = {covered, partial, pending}).
`covered` and `partial` both PASS the M05 P5.T4 CI gate; `pending` fails closed
unless it carries an explicit `deferred_to` field.

| Threat ID | coverage_state | Closed by | Residual gap |
| --- | --- | --- | --- |
| `passkey_credential_theft` | covered | M10.P2.T6 | None |
| `audience_confusion` | covered | M10.P2.T4 | None |
| `weights_hash_spoof` | partial | M10.P4.T5 | loaded-weight recomputation pending `chio-providers` hash-recompute landing |

The `weights_hash_spoof` partial state is documented inline in
`spec/security/coverage.yaml` under `partial_reason` and surfaces under the
Partial heading of `docs/security/threat-coverage.md` once the M05 P5.T5 doc
generator lands. The gap flips to `covered` automatically when
`chio-providers` exposes a recomputable loaded-weight digest; no schema bump
is required.

## Closing posture

- All P0-P4 deliverables landed on `main` before the P5 cross-cutting
  pass opened. P5 added the lineage anchor surface (T1), the smoke
  cross-provider equivalence test (T2), the threat-model coverage map
  (T3), this audit doc final pass (T4), and the custody / model-card
  documentation pages (T5).
- The cross-milestone interactions named in
  `.planning/trajectory-2/10-hardware-custody-and-model-cards.md`
  (M03 hybrid signing, M04 revocation oracle, M05 threat-model
  schema, M07 verdict-equivalence oracle, M09 lineage anchors) are
  consumed verbatim; M10 does not fork any of them.
- The descope plan named in the milestone narrative (custody is the
  half that ships under schedule pressure) was not exercised; both
  halves landed.
