# M04: Recursive Delegation + Revocation Oracle

**Wave:** W2  |  **Trust-boundary:** yes  |  **Tickets:** 32  |  **Effort:** 44.25 days

## In one paragraph

M04 ships a sparse-Merkle CRL-Lite revocation oracle (`chio-revocation-oracle`) with sub-second federation gossip plus a recursive `Capability::Delegate` primitive proven correct in Lean 4 and bounded in Apalache. It re-attacks the v3.18 bounded-claim retreat: revoking a planner capability kills its delegated children mid-call within 500 ms median. M09 marketplace and M10 custody both depend on this surface.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 4 | Pin rs_merkle 1.5; scaffold `chio-revocation-oracle`; open audit doc and freeze |
| P1 | 6 | Sparse-Merkle CRL-Lite primitives + per-epoch signed root + property tests + bench |
| P2 | 6 | Federation gossip (push/pull), `RevocationView` cache, end-to-end 500 ms gate |
| P3 | 5 | `Capability::Delegate` + receipt schema + 3 proptests + kernel integration behind flag |
| P4 | 6 | Lean 4 theorems (4), Apalache module, +4 Kani harnesses, mapping refresh |
| P5 | 5 | 3-tier swarm acceptance test, receipt-chain proof, `delegation_v2` default-on, audit close |

## Load-bearing artifacts

- `crates/chio-revocation-oracle/` (M04.P0.T2 scaffolds; P1 fills)
- `Capability::Delegate` mint helper (M04.P3.T1)
- `DelegationReceipt` canonical-JSON schema (M04.P3.T2)
- `formal/lean4/Chio/Chio/Capability/Delegation.lean` 4 theorems (P4.T1-T3)
- `formal/tla/DelegationDepthBound.tla` + `MCDelegationDepthBound.cfg` (M04.P4.T4)
- `crates/chio-kernel-core/src/kani_public_harnesses.rs` (P4.T5; cap = 14 per D11)
- `crates/chio-revocation-oracle/tests/swarm_revocation_e2e.rs` 3-tier acceptance (M04.P5.T1)

## Cross-trajectory deps

- trajectory-2 M03 PQ-hybrid - per-epoch signed root signed via M03 surface (soft_dep on M04.P1.T3); freeze ordering ensures M03 closes first
- trajectory-2 M06 `CanonicalBytes` - delegation receipt encoding (soft_dep on M04.P3.T2)
- trajectory-1 M03 `NoAllowAfterRevoke` invariant - admits causal allow-before-revoke histories cited in M04.P5.T2

## Locked decisions

- D11 Kani cap at 14 harnesses (4 new in P4) - shuttle/miri/mutants pay better at the margin
- D12 `delegation_v2` ships behind cargo feature flag; flipped default-on at P5.T3 after acceptance

## Active freezes

- `m04-revocation-oracle-pivot` (`crates/chio-revocation-oracle/**`, `crates/chio-credentials/src/revocation*.rs`, `crates/chio-federation/src/revocation*.rs`): opens at M04.P1.T1, closes at M04.P3.T5
- `m04-delegation-pivot` (`crates/chio-core-types/src/capability*.rs`, `crates/chio-kernel/src/delegation*.rs`, Lean + TLA paths): opens at M04.P3.T1, closes at M04.P5.T5

## When this milestone is done

- `crates/chio-revocation-oracle/` ships with signed epoch-root path and 4+ named proptests green at `PROPTEST_CASES=256`.
- Federation gossip delivers oracle inserts to a remote verifier within 500 ms median across 100 trials.
- 4 Lean theorems build under `lake build` in CI (theorem 3 may ship as documented `axiom`; the other three are closed proofs).
- Apalache `apalache-mc check --inv=DepthBoundedByRoot --inv=AttenuatedAtEachStep --inv=RevokedSubtreeNotObservable --length=10` green.
- `formal/rust-verification/kani-public-harnesses.toml` lists exactly 14 entries (10 baseline + 4 new).
- 3-tier swarm acceptance test (P5.T1) median revoke-to-deny latency < 500 ms across 100 trials on the reference runner.
- `delegation_v2` default-on after P5.T3.
