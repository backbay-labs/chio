# chio-guard-sdk

`chio-guard-sdk` is the guest-side SDK for writing Chio WASM guards, targeting
the `chio:guard@0.2.0` WIT world. It is the primary dependency for guard
authors and provides the `GuardRequest` / `GuardVerdict` / `GuestDenyResponse`
types with serde annotations matching the host ABI exactly, plus safe wrappers
for the `chio.log`, `chio.get_config`, `chio.get_time_unix_secs`, and
`chio:guard/host.fetch-blob` host imports.

Use this crate to author a guard that compiles to a `.wasm` module loaded by
`chio-wasm-guards`. The `#[chio_guard]` attribute macro that generates the ABI
exports lives in `chio-guard-sdk-macros`.
