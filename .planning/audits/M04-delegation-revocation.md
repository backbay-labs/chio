# M04 Delegation Revocation Audit

Scope: trajectory-2 M04 P0 baseline for recursive delegation and the
revocation oracle. This file records the opening state only. It does not
claim that oracle logic, federation gossip, recursive delegation, or formal
proof work is implemented.

## P0 Opening State

- Milestone: M04 recursive-delegation-revocation-oracle.
- Wave: W2.
- Trust boundary: yes.
- Required review: @bb-connor plus security x2 on every PR.
- Freeze ids in scope: `m04-revocation-oracle-pivot`,
  `m04-delegation-pivot`.
- Overlap watch: M04 P3 unions both freeze rows from M04.P3.T1 through
  M04.P3.T5.

## Starting Counts

- Kani public harnesses: 10 Kani harnesses in
  `formal/rust-verification/kani-public-harnesses.toml`.
- TLA modules: 1 TLA module, `RevocationPropagation.tla`, with companion
  `MCRevocationPropagation.cfg`.
- Lean delegation theorems: 0. `Capability/Delegation.lean` is absent at
  P0 open.
- Revocation implementation surface: live measurement on 2026-04-30 is
  256 LoC across the three implementation files named by the milestone.
  The milestone baseline text records 254 LoC from its 2026-04-29 count.
  The two-line drift is recorded here as opening evidence, not treated as
  an implementation claim.

## Reproduction Commands

```bash
awk '/covered_symbols = \[/{flag=1; next} flag && /\]/{flag=0} flag && /"/{count++} END{print count}' formal/rust-verification/kani-public-harnesses.toml
find formal/tla -maxdepth 1 -type f \( -name '*RevocationPropagation*' -o -name '*DelegationDepthBound*' \) | sort
find formal/lean4/Chio -path '*Delegation.lean' -o -path '*Revocation.lean' | sort
wc -l crates/chio-kernel/src/revocation_store.rs crates/chio-kernel/src/revocation_runtime.rs crates/chio-store-sqlite/src/revocation_store.rs
```

## P0 Ticket Evidence

- M04.P0.T1 pins `rs_merkle = "1.5"` at workspace scope and refreshes
  dependency resolution.
- M04.P0.T2 scaffolds `crates/chio-revocation-oracle/` as an empty
  package with a placeholder integration test.
- M04.P0.T3 opens this audit doc with baseline counts.
- M04.P0.T4 wires freeze coverage for the exact
  `crates/chio-core-types/src/capability.rs` and
  `crates/chio-federation/src/lib.rs` paths required by the P0 gate.

## Freeze Notes

`m04-revocation-oracle-pivot` covers the oracle and revocation-gossip
surface. `m04-delegation-pivot` covers the delegation mint helper,
delegation kernel integration, and formal delegation artifacts. During
M04 P3, the `m04-freeze-guard` must union both rows and fail closed for
non-M04 work touching either set of paths.

Security x2 review is required for P0 and every later M04 PR because M04 is
a trust-boundary milestone.
