# M04 P0/P1/P2 Sweep Fix List

| Source | Severity | File path | Intended fix | Gate command |
|--------|----------|-----------|--------------|--------------|
| PR #392 comment 3171207218 | P1 | `crates/chio-kernel-core/src/revocation_view.rs` | Make `RevocationView::install_if_newer` use an atomic compare-and-swap retry loop. | `cargo test -p chio-kernel-core --features revocation-view revocation_view --quiet`; `cargo clippy -p chio-kernel-core --features revocation-view --lib -- -D warnings` |
| PR #392 comment 3171209488 | P2 | `crates/chio-kernel-core/src/revocation_view.rs` | Same atomic install fix covers the Cursor TOCTOU report. | `cargo test -p chio-kernel-core --features revocation-view revocation_view --quiet` |
| PR #392 comment 3171207220 | P1 | `crates/chio-federation/src/revocation_gossip.rs` | Drop stale signed roots instead of appending them behind newer per-peer epochs. | `cargo test -p chio-federation push_queue --quiet`; `cargo clippy -p chio-federation --lib -- -D warnings` |
| PR #398 comment 3171306933 | P1 | `crates/chio-core-types/src/capability.rs` | Reject delegation mints when the parent scope lacks `Operation::Delegate`. | `cargo test -p chio-core-types --features delegation_v2 delegate_ --quiet`; `cargo clippy -p chio-core-types --features delegation_v2 --lib -- -D warnings` |
| PR #398 comment 3171306935 | P2 | `crates/chio-core-types/tests/property_capability_algebra.rs` | Build each generated delegation hop from the previous child scope. | `cargo test -p chio-core-types --test property_capability_algebra --quiet`; `cargo clippy -p chio-core-types --test property_capability_algebra -- -D warnings` |
| PR #398 comment 3171308624 | P2 | `crates/chio-core-types/tests/property_capability_algebra.rs` | Same chained strategy fix covers the Cursor monotonicity report. | `cargo test -p chio-core-types --test property_capability_algebra --quiet` |
| PR #398 comment 3171308631 | P2 | `crates/chio-core-types/tests/property_capability_algebra.rs` | Replace the revocation tautology with a set-based ancestor revocation check and unrelated-capability negative checks. | `cargo test -p chio-core-types --test property_capability_algebra --quiet` |
| PR #403 comment 3171622440 | P1 | `crates/chio-kernel-core/src/kani_public_harnesses.rs` | Remove self-referential M04 Kani helper models and bind harnesses to runtime predicates/canonical encoding helpers. | `bash scripts/kani-changed-harnesses.sh --dry-run`; `bash scripts/check-mapping.sh` |
| PR #403 comment 3171639712 | P2 | `.planning/trajectory-2/tickets/M04/P4.yml` | Add the missing `--config=formal/tla/MCDelegationDepthBound.cfg` flag to the Apalache gate. | Python assertion for `--config=` in the gate command |
| PR #414 comment 3171928721 | P2 | `crates/chio-revocation-oracle/tests/receipt_chain_proof.rs` | Read receipt epoch and revocation decision from one snapshot load in the consult loop. | `cargo test -p chio-revocation-oracle --test receipt_chain_proof --features delegation_v2 --quiet`; `cargo clippy -p chio-revocation-oracle --test receipt_chain_proof --features delegation_v2 -- -D warnings` |
| `.planning/trajectory-2/deferred/m04-p2-deferred.md` | P2 | `crates/chio-core-types`, `crates/chio-federation` | Current main already passes the no-default feature build, and this sweep fixes `chio-federation --tests` clippy. Delete stale deferred file. | `cargo build -p chio-kernel-core --no-default-features`; `cargo clippy -p chio-federation --tests -- -D warnings` |

## Audit residuals

`M04-delegation-revocation.md` has no open P0/P1/P2 residual-risk section. The `ASSUME-NETWORK-TRANSPORT` note remains a documented formal-model boundary with its owning row already mirrored in `formal/proof-manifest.toml`.
