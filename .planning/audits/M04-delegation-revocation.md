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

## P5 Final Audit Pass (M04.P5.T4)

This section records the milestone-closing counts after P5 lands the
3-tier swarm acceptance test (T1), the receipt-chain proof (T2), the
`delegation_v2` default-on flip (T3), and this final audit pass.

### Final counts

- Kani public harnesses: 14 Kani entries in
  `formal/rust-verification/kani-public-harnesses.toml`
  `covered_symbols`. Reproducible:
  `awk '/covered_symbols = \[/{flag=1; next} flag && /\]/{flag=0} flag && /"/{count++} END{print count}' formal/rust-verification/kani-public-harnesses.toml`
  prints `14`. Cap recorded in the milestone risk note (no future
  delegation properties land as public harnesses without a risk-
  ledger entry).
- TLA modules: 2 modules covering the milestone surface.
  `formal/tla/RevocationPropagation.tla` carries the trajectory-1 M03
  baseline plus the new `RevocationFreshness` invariant landed in
  M04.P4.T6. `formal/tla/DelegationDepthBound.tla` (with companion
  `MCDelegationDepthBound.cfg`) carries the M04.P4.T4 depth-bound
  module. Both invariants are cited in `formal/MAPPING.md` and are
  enforced by `scripts/check-mapping.sh`.
- Lean delegation theorems: 4 theorems in
  `formal/lean4/Chio/Chio/Capability/Delegation.lean`. All four are
  shipped as `theorem` (no `axiom` fallback was needed):
  - `delegate_no_widen` (~L208) - shipped as theorem, closed by
    `ChioScope.isSubsetOf_trans`.
  - `attenuation_monotone` (~L221) - shipped as theorem, also closed
    by `ChioScope.isSubsetOf_trans`.
  - `revocation_is_cut` (~L238) - shipped as theorem, closed by
    `List.any_eq_true.mpr` over the chain witnesses. The milestone
    risk note budgeted 2 days for an `axiom` fallback if the
    auxiliary graph theory exceeded budget; the proof closed inside
    the budget so no axiom landed in `formal/assumptions.toml`.
  - `compose_preserves_algebra` (~L267) - shipped as theorem,
    closed by `ChioScope.isSubsetOf_trans`.
- Revocation oracle implementation surface: 1031 LoC across the
  seven `crates/chio-revocation-oracle/src/*.rs` files
  (`api.rs`=124, `epoch.rs`=212, `freshness.rs`=53, `lib.rs`=23,
  `passport_bridge.rs`=307, `signer.rs`=65, `sparse_merkle.rs`=247).
  Reproducible: `wc -l crates/chio-revocation-oracle/src/*.rs`.
- revoke-to-deny median latency: 0 ms (sub-millisecond) median
  observed across 100 trials of the M04.P5.T1 swarm acceptance test
  on the reference Linux/macOS runner. The acceptance budget is 500
  ms median; observed revoke-to-deny is well inside the budget. The
  test asserts `median < 500ms` and prints
  `revoke->deny min=<n> ms, median=<n> ms, max=<n> ms across 100 trials`
  on every run. Fixture is
  `crates/chio-revocation-oracle/tests/swarm_revocation_e2e.rs`.
- Receipt-chain proof: green. Every allow receipt observed across
  the swarm fixture has `seen_epoch < min_revoke_epoch`; every deny
  receipt has `seen_epoch >= 1` (non-empty-sentinel). Fixture is
  `crates/chio-revocation-oracle/tests/receipt_chain_proof.rs`. The
  trajectory-1 M03 `NoAllowAfterRevoke` TLA invariant is the model
  this runtime witness mirrors on real receipts.

### Theorem-vs-axiom status (per theorem)

| Theorem | Status | Source line | Notes |
| ------- | ------ | ----------- | ----- |
| `delegate_no_widen` | shipped as theorem | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L208) | No `axiom` needed. |
| `attenuation_monotone` | shipped as theorem | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L221) | No `axiom` needed. |
| `revocation_is_cut` | shipped as theorem | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L238) | Risk note budgeted 2 days for an `axiom` fallback if graph theory exceeded budget; the proof closed inside budget so no `axiom` landed. |
| `compose_preserves_algebra` | shipped as theorem | `formal/lean4/Chio/Chio/Capability/Delegation.lean` (~L267) | No `axiom` needed. |

The four entries close the row that the milestone-success criterion
requires ("4 Lean theorems ... must be `theorem` with closed proofs",
with `revocation_is_cut` allowed as `axiom`). All four shipped as
`theorem`.

### `delegation_v2` default-on flip

`crates/chio-kernel/Cargo.toml`'s `default` feature set is now
`["legacy-sync", "delegation_v2"]`. Verifiable:
`grep -q 'default = \[.*"delegation_v2"' crates/chio-kernel/Cargo.toml`
exits 0. Migration note at `docs/migrations/M04-delegation-v2.md`
documents the upgrade path, the legacy-sync opt-out, and the
verification checklist. `chio-core-types` keeps `delegation_v2`
default-OFF (kernel pulls it transitively).

### `formal/assumptions.toml` ledger

P5.T5 decision: `ASSUME-NETWORK-TRANSPORT` is left UNCHANGED in
`formal/assumptions.toml` `required_assumption_ids`.

Rationale: the M04.P4.T6 `RevocationFreshness` invariant in
`formal/tla/RevocationPropagation.tla` (~L321) constrains every
recorded local revocation epoch to be strictly less than the global
clock value. The predicate is

```tla
\A a \in ProcSet, c \in CapSet :
    rev_epoch[a][c] # 0 => rev_epoch[a][c] < clock
```

`clock` is a single shared variable rather than a per-peer logical
timestamp, so the invariant discharges only the local freshness gate
(single-authority observed-epoch monotonicity). It does NOT model
multiple gossip peers, vector-clock-ordered delivery, or any other
cross-peer ordering primitive. The cross-peer ordering claim covered
by `ASSUME-NETWORK-TRANSPORT` ("authenticated messages received by
Chio are not silently rewritten below TLS or signature checks")
therefore remains audited rather than discharged. The operational
mitigation is the wire-level signature pinning in
`crates/chio-federation/src/revocation_gossip.rs` (signer_id pin,
signature verification before
`RevocationView::install_if_newer`); the formal discharge is left
for a future milestone that ships a distributed-time TLA model.

The decision row is mirrored in `formal/proof-manifest.toml` under
the `# M04 P5.T5 assumptions-toml ledger row` block so the
milestone-success criterion ("the `assumptions.toml` ledger updated
(or explicitly documented as unchanged)") is traceable from both
the audit doc and the proof manifest. Sign-off requires the
`formal-verification` owner per trajectory-1 M03's discipline; this
ticket records that the decision is "leave untouched" rather than
"narrow", consistent with the soft-dep rationale on M04.P5.T5.

### Reproduction commands

```bash
awk '/covered_symbols = \[/{flag=1; next} flag && /\]/{flag=0} flag && /"/{count++} END{print count}' formal/rust-verification/kani-public-harnesses.toml
find formal/tla -maxdepth 1 -type f \( -name '*RevocationPropagation*' -o -name '*DelegationDepthBound*' \) | sort
find formal/lean4/Chio -path '*Delegation.lean' -o -path '*Revocation.lean' | sort
wc -l crates/chio-revocation-oracle/src/*.rs
cargo test -p chio-revocation-oracle --test swarm_revocation_e2e --features delegation_v2 --release -- --nocapture
cargo test -p chio-revocation-oracle --test receipt_chain_proof --features delegation_v2
```
