# M10 Hardware Custody And Model Cards Audit

Measured: 2026-04-30

Scope: P0 baseline only for hardware custody and policy-bound model-card
work. This document records the starting counts before custody crates,
fixtures, model-card enforcement, and threat coverage land.

## Starting Counts

| Surface | Baseline | Reproduce |
| ------- | -------- | --------- |
| `chio-custody-hw` crate | 0 crates named `chio-custody-hw` | `ls crates \| grep -c '^chio-custody-hw$'` |
| `chio-weights` crate | 0 crates named `chio-weights` | `ls crates \| grep -c '^chio-weights$'` |
| Passkey and WebAuthn fixtures | 0 matching fixture or source paths under `crates/` | `find crates \( -name '*passkey*' -o -name '*webauthn*' \) -print \| wc -l` |
| New threat IDs | 0 rows for `passkey_credential_theft`, `audience_confusion`, or `weights_hash_spoof` in parent commit `3fa0dd127cf700f4d9b5b7463959907a489c90d0`; 3 rows after this P0 update | `git show 3fa0dd127cf700f4d9b5b7463959907a489c90d0:spec/security/chio-threat-model.v1.json \| rg '"id": "(passkey_credential_theft\|audience_confusion\|weights_hash_spoof)"' \| wc -l` |

## Notes

- `spec/errors/registry.yaml` already reserves the `custody` and `weights`
  domains and includes grep-visible `urn:chio:error:custody:*` and
  `urn:chio:error:weights:*` entries.
- Cargo.lock already contains `base64ct 1.8.3` through existing dependency
  resolution. WebAuthn crates use exact workspace-level requirements for later
  consuming crates; no lockfile entries should be fabricated before a
  consuming crate exists.

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
