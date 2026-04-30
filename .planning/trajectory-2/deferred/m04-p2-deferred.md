# M04 P2 deferred items

Pre-existing issues observed during M04 P2 execution that are out-of-scope
for this phase (per the GSD deviation rules: only fix issues directly
caused by the current task's changes).

## chio-core-types `--no-default-features` build is broken

`cargo build -p chio-kernel-core --no-default-features` fails because
`crates/chio-core-types/src/crypto.rs` uses `Box::new(...)` and `Box<...>`
types without an `extern crate alloc; use alloc::boxed::Box;` import. The
failure reproduces on the baseline branch (stashed M04 P2 changes,
re-ran the same command, same errors), so it pre-dates this phase.

The portability proof (`scripts/check-portable-kernel.sh`) that the
trajectory-2 ASSUME-PORTABLE-KERNEL boundary depends on apparently runs
through a different toolchain path or worker script that papers over the
issue, but the bare workspace build is broken on `--no-default-features`.

Out-of-scope for M04 P2: file a separate ticket against
`chio-core-types`. The `revocation-view` module added by M04.P2.T4 is
gated behind an opt-in feature that pulls in `arc-swap` (which itself
requires std), so the portable wasm proof can stay green by leaving
`revocation-view` off; the underlying `chio-core-types` regression is
upstream of that decision.
