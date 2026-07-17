# chio-kernel-browser

`chio-kernel-browser` is the `wasm-bindgen` facade over the portable
`chio-kernel-core` surface: capability verification, verdict evaluation, and
receipt signing exposed to browser JavaScript and TypeScript as JSON-in /
JSON-out functions. Where `chio-kernel-core` is host-agnostic `no_std + alloc`
logic that takes its clock and RNG as trait objects, this crate supplies the
browser half of that contract: `BrowserClock` and `WebCryptoRng` platform
adapters, the `#[wasm_bindgen]` entry points, and the JSON wire types that
cross the wasm boundary.

Use this crate when embedding Chio capability checks or receipt signing in a
browser page or another `wasm32` host. The native sidecar lives in
`chio-kernel`; the mobile FFI lives in `chio-kernel-mobile`.

## Responsibilities

- Adapt browser platform primitives to the portable kernel traits:
  `BrowserClock` implements `chio_kernel_core::Clock` via `js_sys::Date::now()`;
  `WebCryptoRng` implements `chio_kernel_core::Rng` via
  `window.crypto.getRandomValues`.
- Expose `evaluate`, `sign_receipt`, `sign_receipt_relaying_trusted_body`,
  `verify_capability`, `verify_capability_with_context`, `verify_receipt`, and
  `mint_signing_seed_hex` as `#[wasm_bindgen]` functions.
- Own the JSON wire contract (`wire.rs`) that crosses the wasm boundary,
  independent of internal `chio-kernel-core` / `chio-core-types` shapes.
- Enforce the WYSIWYS content-hash recompute gate on the default signing path,
  keeping the trusted-body relay as a separate, explicitly named export.
- Downgrade a capability-only kernel `allow` to `pending_approval`, since
  browser evaluation runs an empty guard pipeline and cannot itself authorize
  execution.
- Keep `wasm-bindgen`, `js-sys`, and `web-sys` behind
  `cfg(target_arch = "wasm32")` so the crate builds and tests on a native host
  without a wasm toolchain.

## Public API

`wasm` module (`target_arch = "wasm32"` only; JSON string or byte array in,
`JsValue` out):

| Function | Backing |
|---|---|
| `evaluate(request_json)` | `evaluate_pure` -> `chio_kernel_core::evaluate_with_full_floor` |
| `sign_receipt(body_json, seed_hex)` | `sign_receipt_pure`, WYSIWYS recompute-and-refuse |
| `sign_receipt_relaying_trusted_body(body_json, seed_hex)` | `sign_receipt_relaying_trusted_body_pure`, trusts caller `content_hash` |
| `verify_capability(token_json, authority_hex)` | `verify_capability_pure` -> `verify_capability_full` (single hex key or JSON array) |
| `verify_capability_with_context(request_json)` | `verify_capability_pure` with full trust-root / budget context |
| `verify_receipt(envelope, trusted_issuers)` | `verify_receipt_pure` |
| `mint_signing_seed_hex()` | `WebCryptoRng` -> 32 CSPRNG bytes as lowercase hex |

Portable Rust API (all targets, re-exported from the crate root):

- `BrowserClock`, `WebCryptoRng`, `WebCryptoRngError` - platform adapters.
- `evaluate_pure`, `sign_receipt_pure`, `sign_receipt_relaying_trusted_body_pure`,
  `verify_capability_pure`, `verify_receipt_pure`, `decode_seed_hex`,
  `hex_encode_lower`, `parse_authority_input` - the logic the `wasm` entry
  points call.
- `wire::{EvaluateRequestJson, EvaluationVerdictJson, SignReceiptRequestJson,
  VerifyCapabilityRequestJson, VerifiedCapabilityJson, VerifyReceiptResultJson,
  ToolCallRequestJson, ParentBudgetSnapshotJson, AdmittedChildBudgetJson,
  BindingError}` - the JSON wire DTOs.

## Usage

```js
import init, { evaluate, mint_signing_seed_hex, sign_receipt } from "./pkg/chio_kernel_browser.js";

await init();
const verdict = evaluate(JSON.stringify(evaluateRequest));              // EvaluationVerdictJson
const seedHex = mint_signing_seed_hex();
const receipt = sign_receipt(JSON.stringify(signReceiptBody), seedHex); // ChioReceipt
```

`pkg/` is produced by `wasm-pack build --target web --release
crates/kernel/chio-kernel-browser`. See `examples/demo.html` and
`examples/demo.js` for a complete page.

## Testing

| Target | Command |
|---|---|
| Host (pure helpers + `src/tests.rs`) | `cargo test -p chio-kernel-browser` |
| `wasm32-unknown-unknown` build | `cargo build -p chio-kernel-browser --target wasm32-unknown-unknown --release` |
| Browser entry points (headless Chrome) | `wasm-pack test --headless --chrome crates/kernel/chio-kernel-browser` |
| `verify_receipt` corpus (Node) | `wasm-pack test --node crates/kernel/chio-kernel-browser` |

`./scripts/qualify-portable-browser.sh` runs the full qualification: release
`wasm-pack` build, artifact size, headless-Chrome suite, and `evaluate`
latency. Release `wasm-pack` builds skip `wasm-opt`
(`[package.metadata.wasm-pack.profile.release]`): the pinned Binaryen
validator rejects the bulk-memory operations the pinned Rust toolchain emits.

## See also

- `chio-kernel-core` - the portable evaluation, signing, and verification logic this crate binds.
- `chio-kernel-mobile` - the analogous UniFFI binding over the same core, for iOS and Android.
- `chio-kernel` - the native desktop/sidecar runtime built on the same core.
