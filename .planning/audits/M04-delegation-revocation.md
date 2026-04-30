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

## P3 SDK Breakage Audit (M04.P3.T5)

P3 introduces three new public symbols in `chio-core-types`:

- `chio_core_types::delegate(...)` (mint helper)
- `chio_core_types::DelegationReceipt` (signed-receipt envelope)
- `chio_core_types::ScopeAttenuation` (mint input request)

All three are gated behind a new cargo feature `delegation_v2` (default
OFF). Without the feature, the `delegation_receipt` module is not
compiled and the `delegate` re-export is absent, so existing SDK
consumers see byte-identical type and function tables to pre-M04.P3.

`Operation::Delegate` (the existing `Operation` enum variant) is NOT
new in P3 - it predates this milestone and remains unchanged. The doc
text "Capability::Delegate variant" in
`.planning/trajectory-2/04-recursive-delegation-revocation-oracle.md`
refers to the new `delegate` mint helper surface introduced in this
phase, not a new enum variant on `Operation` or `CapabilityToken`.

### Migration path for downstream consumers

To opt into recursive delegation:

1. Add the feature to your Cargo.toml dependency on `chio-core-types`:

   ```toml
   chio-core-types = { workspace = true, features = ["delegation_v2"] }
   ```

2. (Optional) enable the kernel-side oracle consultation by also
   flipping the `chio-kernel` feature:

   ```toml
   chio-kernel = { workspace = true, features = ["delegation_v2"] }
   ```

3. Install a `chio_kernel_core::RevocationView` snapshot via
   `ChioKernel::set_revocation_view(view)` so dispatch consults the
   federation-gossiped revocation set on every delegated request.

4. Mint child capabilities by calling `chio_core_types::delegate(...)`
   instead of building `DelegationLink::sign` calls by hand. The
   helper enforces scope subset, expiry monotonicity, and budget
   monotonicity at mint time.

### Gate verification

Both feature axes build:

- `cargo build -p chio-core-types --no-default-features` keeps the
  legacy SDK shape (no `delegate`, no `DelegationReceipt`).
- `cargo build -p chio-core-types --features delegation_v2` links the
  new mint helper and receipt envelope.

Trajectory-2 M07 framework adapters opt in explicitly per the M04
plan; this audit row records the gating decision and the migration
contract that downstream SDKs follow.

### Trajectory-2 M06 CanonicalBytes integration

The `DelegationReceipt::canonical_bytes()` method returns
`chio_core_types::CanonicalBytes`. M06's CanonicalBytes newtype is
preferred and already in place, so the soft-dep listed on M04.P3.T2
is satisfied at this audit's writing.
