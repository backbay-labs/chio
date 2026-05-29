# Delegation Migration

This migration flips `delegation` to default-on in
`crates/chio-kernel/Cargo.toml`. The kernel now consults the installed
`RevocationView` snapshot on every delegated dispatch and denies the
capability if any link in its delegation chain (or the leaf capability
itself) appears in the revoked set. This is the trust-boundary's
fail-closed step that has shipped behind the `delegation` feature
gate in an earlier phase.

## What changed

- `crates/chio-kernel/Cargo.toml`'s `default` feature set now contains
  both `legacy-sync` and `delegation`. A standard
  `chio-kernel = { version = "..." }` dependency picks both up
  transparently, with no Cargo.toml edits required by consumers.
- `chio-kernel`'s `delegation` feature still cascades to
  `chio-core-types/delegation`, which in turn enables
  `chio_core_types::delegate(...)`,
  `chio_core_types::DelegationReceipt`, and
  `chio_core_types::ScopeAttenuation`. With the kernel default flipped,
  these symbols are reachable from any default kernel build.
- The legacy single-step `RevocationStore` lookup still runs on every
  dispatch. The new oracle consultation is additive and runs *only*
  when a `RevocationView` has been installed via
  `ChioKernel::set_revocation_view`. Kernels that never install a view
  see no behavioural change beyond a single conditional branch on each
  delegated dispatch.

## What this changes for consumers

### Default kernel users

No action required. The kernel boots with `delegation` on, but the
kernel-side oracle consultation is dormant until a `RevocationView` is
installed. Default deployments (no view installed) keep the legacy
`RevocationStore`-only revocation surface and behave identically.

### Recursive-delegation deployments

Deployments that wire up federation gossip should:

1. Construct a `chio_kernel_core::RevocationView` and install it on the
   kernel:

   ```rust
   let view = std::sync::Arc::new(RevocationView::new());
   kernel.set_revocation_view(view.clone());
   ```

2. Wire the federation gossip path so newly received signed epoch roots
   are converted into `RevocationSnapshot` values and installed via
   `view.install_if_newer(snapshot)`. The cache is monotone: snapshots
   whose epoch does not strictly advance the current snapshot are
   rejected fail-closed.

3. Mint child capabilities through `chio_core_types::delegate(...)`
   instead of building `DelegationLink::sign` calls by hand. The helper
   enforces scope subset, expiry monotonicity, and budget monotonicity
   at mint time.

### Consumers that need to opt out (legacy-sync only)

Downstream crates that need the pre-migration single-step path can disable
the new default:

```toml
chio-kernel = { version = "...", default-features = false, features = ["legacy-sync"] }
```

This is consistent with the precedent set by the async-kernel
migration's `legacy-sync` flag (see `docs/migrations/async-kernel-migration.md`):
default-on the new surface, leave one explicit opt-out path for
consumers still on the legacy contract. Mixed `default-features = false`
without `legacy-sync` is unsupported - the kernel needs at least one
of the two to compile its dispatch path.

### chio-core-types stays opt-in

`chio-core-types` keeps its own `delegation` feature default-OFF.
Direct consumers of `chio-core-types` (without `chio-kernel`) that
want the new mint helper must still opt in explicitly:

```toml
chio-core-types = { workspace = true, features = ["delegation"] }
```

This avoids a transitive surface flip for SDK consumers that depend on
`chio-core-types` for type definitions only and never instantiate a
kernel. Framework adapters continue to opt in explicitly.

## Compatibility and rollback

- **Wire format:** No new wire surface is introduced by this flip. The
  `RevocationView` cache is in-process; gossip frames remain
  schema-versioned by `chio-federation::REVOCATION_ROOT_GOSSIP_SCHEMA`.
- **Receipt format:** No new receipt fields. Allow / deny verdicts that
  pass through the new consultation step are byte-identical to those
  produced by the pre-flip legacy path, with one exception: a
  capability whose chain is revoked in the installed view now denies
  with `KernelError::DelegationChainRevoked(<id>)` (or
  `KernelError::CapabilityRevoked(<id>)` for the leaf). Both variants
  predate this flip; the change is *which* path produces them.
- **Roll-back:** Pin the previous version or set
  `default-features = false, features = ["legacy-sync"]` on every
  `chio-kernel` dependency. No data migration is required.

## Verification checklist

After upgrading:

1. `cargo build` of any crate that depends on `chio-kernel` should
   pick up `delegation` automatically with no Cargo.toml change.
2. The kernel's revocation behaviour is unchanged when no
   `RevocationView` is installed (tested by
   `crates/chio-kernel/src/kernel/delegation.rs::tests::no_view_installed_returns_ok`).
3. Federation-gossip-enabled deployments observe the delegation
   acceptance gate: revoking a planner capability propagates to its
   children and produces a deny receipt within 500 ms median across
   100 trials. The acceptance harness is
   `crates/chio-revocation-oracle/tests/swarm_revocation_e2e.rs`.
4. The receipt-chain proof gate
   (`crates/chio-revocation-oracle/tests/receipt_chain_proof.rs`)
   asserts no allow receipt has `seen_epoch >= revoke_epoch`.

## References

- Kernel-side consultation surface:
  `crates/chio-kernel/src/kernel/delegation.rs`
- View cache:
  `crates/chio-kernel-core/src/revocation_view.rs`
- Recursive-delegation Lean theorems:
  `formal/lean4/Chio/Chio/Capability/Delegation.lean`
- TLA+ depth bound and freshness invariants:
  `formal/tla/DelegationDepthBound.tla`,
  `formal/tla/RevocationPropagation.tla` (`RevocationFreshness`)
