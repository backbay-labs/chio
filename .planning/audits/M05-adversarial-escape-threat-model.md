# M05 Adversarial Escape Threat Model Audit

This audit records trajectory-2 M05 evidence for the adversarial corpus,
guard escape, tenant policy, and threat-model-as-code milestone.

Source-of-truth: `.planning/trajectory-2/05-adversarial-escape-threat-model.md`.
Ticket phase covered here: M05.P1.
Snapshot date: 2026-04-30.

## P1 Scope

P1 adds the curated `chio-adversarial-suite` answer key and wires it into the
two first consumers required by the phase:

- `crates/chio-adversarial-suite`
- `crates/chio-kernel-core/tests/adversarial_suite.rs`
- `crates/chio-attest-verify/tests/adversarial_suite.rs`

The phase intentionally does not add auto-promotion, WASM guard escape
fixtures, tenant policy migration, threat-model codegen, or generated
threat-coverage docs. Those remain P2 through P5 work.

## Corpus Counts

Snapshot command:

```bash
find crates/chio-adversarial-suite/cases -mindepth 2 -name '*.json' -print | sed 's|.*/cases/||; s|/.*||' | sort | uniq -c
```

| Attack class | Vector count |
|--------------|-------------:|
| `anchor_grafted` | 5 |
| `clock_rewound` | 5 |
| `future_dated` | 5 |
| `partial_signature` | 5 |
| `replayed_nonce` | 5 |
| `revocation_rollback` | 5 |
| `scope_superset` | 5 |
| `sigstore_bundle_payload_mismatch` | 5 |
| **Total** | **40** |

Every vector uses schema version 1, `expected_verdict: "DENY"`,
`pending: false`, a non-empty `expected_reason`, a non-empty `threat_id`,
and a non-empty object artifact. The shared loader rejects unsupported schema
versions, empty IDs, malformed IDs, empty reasons, malformed threat IDs, empty
notes, empty artifacts, scalar artifacts, unknown fields, and pending cases in
coverage mode.

## Consumer Wiring

`chio-kernel-core` consumes these classes:

- `clock_rewound`
- `future_dated`
- `replayed_nonce`
- `partial_signature`
- `scope_superset`
- `revocation_rollback`
- `anchor_grafted`

`chio-attest-verify` consumes these classes:

- `anchor_grafted`
- `sigstore_bundle_payload_mismatch`

The attestation class overlap is intentional. `anchor_grafted` is both a
kernel trust-boundary case and an attest-verify provenance case.

## Local Gate Evidence

Executed from `.worktrees/wave-W2/m05/p1.phase-adversarial-corpus` on
2026-04-30 after rebasing onto `origin/main` commit `aec9ceb8`.

```bash
cargo build -p chio-adversarial-suite --quiet
cargo test -p chio-adversarial-suite --quiet
cargo test -p chio-kernel-core --test adversarial_suite
cargo test -p chio-attest-verify --test adversarial_suite
rg -n "unwrap\\(|expect\\(|todo!|unimplemented!|panic!|allow\\(|ignore" \
  crates/chio-adversarial-suite \
  crates/chio-kernel-core/tests/adversarial_suite.rs \
  crates/chio-attest-verify/tests/adversarial_suite.rs
rg -n "$(printf '\\342\\200\\224')" \
  crates/chio-adversarial-suite \
  crates/chio-kernel-core/tests/adversarial_suite.rs \
  crates/chio-attest-verify/tests/adversarial_suite.rs \
  .planning/trajectory-2/tickets/M05 .planning/audits spec/security
git diff --check main...HEAD
```

Results:

- `chio-adversarial-suite`: 12 tests passed.
- `chio-kernel-core --test adversarial_suite`: 1 test passed.
- `chio-attest-verify --test adversarial_suite`: 1 test passed.
- No `unwrap`, `expect`, `todo!`, `unimplemented!`, `panic!`, `allow`, or
  ignored-test markers found in the P1 Rust surfaces.
- No em dash found in the scanned P1 and audit surfaces.
- `git diff --check main...HEAD` passed.

## Phase Risks And Handoffs

- P1 is an answer-key and loader phase. It asserts that each curated vector is
  deny-expected, but it does not yet execute the production kernel evaluator
  against full replay receipts.
- P2 must keep auto-promoted vectors `pending: true` until manual triage.
- P5 must connect these `threat_id` values to the load-bearing
  threat-model-coverage gate and generated threat coverage docs.
- Future corpus additions should keep five-vector minimums per class or update
  this audit and the consumer tests in the same phase PR.

## Audit-Local Phase Tracking

- [x] P1.T1: Crate schema and cases layout merged in PR #356.
- [x] P1.T2: Clock, future, and nonce classes have 15 deny vectors.
- [x] P1.T3: Signature, scope, and revocation classes have 15 deny vectors.
- [x] P1.T4: Anchor and Sigstore mismatch classes have 10 deny vectors.
- [x] P1.T5: `chio-kernel-core` adversarial suite gate is wired and green.
- [x] P1.T6: `chio-attest-verify` adversarial suite gate is wired and green.
