# Chio attest buyer legacy replay boundary

## Objective

Move buyer review legacy proof replay out of the CLI and behind the
`chio-attest-buyer` API. The CLI should read files, assemble review sources,
and write reports, but it should not call `chio_attest_buyer_core::` or
`chio_runtime_core::` directly for buyer verification.

## Plan

1. Add a failing source-boundary regression proving `buyer.rs` still names the
   historical verifier crates directly.
2. Add a `chio-attest-buyer` API that runs review verification with verifier
   trust JSON and replays the historical proof verifier only inside the buyer
   boundary.
3. Retarget `cmd_chio_attest_buyer_verify` to the new API.
4. Reexport the runtime evidence manifest type through `chio-attest-buyer` so
   buyer package assembly also avoids direct runtime-crate naming.
5. Run focused buyer crate tests, CLI source tests, clippy, formatting,
   whitespace, and dash scans.

## Verification

- [x] `cargo test -p chio-cli --bin chio_attest_buyer_dispatch_owns_legacy_replay_boundary` fails before implementation.
- [x] `cargo test -p chio-cli --bin chio_attest_buyer_dispatch_owns_legacy_replay_boundary`
- [x] `cargo test -p chio-attest-buyer --test buyer_review`
- [x] `cargo test -p chio-attest-buyer`
- [x] `cargo test -p chio-cli --bin chio_attest_buyer`
- [x] `cargo clippy -p chio-attest-buyer --all-targets -- -D warnings`
- [x] `cargo clippy -p chio-cli --bin chio -- -D warnings`
