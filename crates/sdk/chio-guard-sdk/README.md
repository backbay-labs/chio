# chio-guard-sdk

Guest-side SDK for authoring Chio WASM guards. It defines the JSON ABI shared
with the host runtime, safe wrappers for the host imports, the guest allocator,
and the glue that decodes a request and encodes a verdict. A guard built with
this crate compiles to a `.wasm` module that `chio-wasm-guards` loads into the
kernel at runtime.

## Responsibilities

- Define `GuardRequest`, `GuardVerdict`, and `GuestDenyResponse` with serde
  field shapes byte-compatible with the host-side ABI in `chio-wasm-guards`.
- Provide safe wrappers for the `chio.log`, `chio.get_config`,
  `chio.get_time_unix_secs`, and `chio:guard/host.fetch-blob` host imports, with
  no-op or documented-default fallbacks on non-`wasm32` targets so guard logic
  runs under `cargo test` without a WASM runtime.
- Deserialize the request from guest linear memory (`read_request`), encode a
  verdict into the ABI return code (`encode_verdict`), and export
  `chio_deny_reason` for structured deny reasons.
- Export `chio_alloc` / `chio_free`, a `Vec`-backed guest allocator the host
  writes the request into.
- Wrap the `policy-context.bundle-handle` resource (`PolicyContext`) for reading
  host-owned content-bundle blobs via `fetch_blob`.

## Public API

- `types::{GuardRequest, GuardVerdict, GuestDenyResponse, VERDICT_ALLOW, VERDICT_DENY}`
- `host::{log, log_level, get_config, get_time, fetch_blob, PolicyContext}`
- `glue::{read_request, encode_verdict, chio_deny_reason}`
- `alloc::{chio_alloc, chio_free}`
- `prelude` - re-exports the full guard-author API for `use chio_guard_sdk::prelude::*;`

## Usage

```rust,ignore
use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    if req.tool_name == "dangerous_tool" {
        GuardVerdict::deny("tool is blocked by policy")
    } else {
        GuardVerdict::allow()
    }
}
```

`#[chio_guard]` (from `chio-guard-sdk-macros`) generates the `evaluate`
`extern "C"` entry point and the `chio_alloc` / `chio_free` / `chio_deny_reason`
exports around this function. Without the macro, a guard author calls
`read_request`, `encode_verdict`, and the allocator exports directly.

## Testing

`cargo test -p chio-guard-sdk`

## See also

- `chio-guard-sdk-macros` - the `#[chio_guard]` attribute macro that generates
  the ABI exports around a plain `evaluate` function.
- `chio-wasm-guards` - host-side runtime that loads the compiled `.wasm` guard,
  writes requests through the allocator exports, and interprets the return code.
- `chio-guard-sdk-compat` - re-exports this crate's API as a standalone Cargo
  package outside the root workspace.
- `chio-cli` - `guard new` scaffolds a new guard project against this crate.
