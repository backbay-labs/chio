# chio-kernel-browser

Browser (`wasm-bindgen`) bindings over the portable [`chio-kernel-core`]
surface.

## What this is

The `chio-kernel-core` crate is a pure
`no_std + alloc` library: verdict evaluation, capability verification,
and receipt signing run with no async runtime, no filesystem, and no
network. `chio-kernel-browser` wraps that surface with `wasm-bindgen`
so browser JavaScript / TypeScript hosts can drive the same kernel
code paths the native sidecar uses.

Three entry points are exposed to JS:

| JS function | Rust backing |
|-------------|--------------|
| `evaluate(request_json)` | `chio_kernel_core::evaluate` |
| `sign_receipt(body_json, seed_hex)` | `chio_kernel_core::sign_receipt` |
| `verify_capability(token_json, authority_hex)` | `chio_kernel_core::verify_capability` |

A fourth helper, `mint_signing_seed_hex()`, pulls 32 bytes from
`window.crypto.getRandomValues` and returns them as lowercase hex so
callers that want the browser to mint fresh Ed25519 seeds per receipt
can fuse it with `sign_receipt`.

Platform adapters:

- **`BrowserClock`** implements `chio_kernel_core::Clock` via
  `js_sys::Date::now()`. Fail-closed: negative or non-finite timestamps
  map to `0`, which treats every non-trivial capability as not-yet-valid.
- **`WebCryptoRng`** implements `chio_kernel_core::Rng` via
  `web_sys::Crypto::get_random_values_with_u8_array`. Fail-closed: if
  `getRandomValues` throws, the adapter zeros the destination buffer and
  the signing path rejects the zero-seed with `code:
  "weak_entropy"`.

## Building

The crate is set up for two flows:

### Host (`cargo test`)

The pure helpers (`evaluate_pure`, `sign_receipt_pure`,
`verify_capability_pure`) compile on any host target. The wasm-bindgen
dependencies are gated on `cfg(target_arch = "wasm32")` so host builds
do not need any wasm toolchain.

```bash
CARGO_TARGET_DIR=target/browser cargo test -p chio-kernel-browser
```

### `wasm32-unknown-unknown` (raw)

```bash
CARGO_TARGET_DIR=target/browser cargo build \
  --target wasm32-unknown-unknown \
  -p chio-kernel-browser \
  --release
```

This produces `target/browser/wasm32-unknown-unknown/release/chio_kernel_browser.wasm`.

### `wasm-pack` (browser-ready bundle)

```bash
# from the repo root
wasm-pack build --target web --release crates/chio-kernel-browser
```

`wasm-pack` emits a `pkg/` directory inside the crate containing:

- `chio_kernel_browser_bg.wasm` -- the compiled kernel.
- `chio_kernel_browser.js` -- ES-module JS glue that imports the wasm.
- `chio_kernel_browser.d.ts` -- TypeScript declarations for the exported
  entry points.
- `package.json` -- ready for `npm publish` or drop-in use from any
  bundler that understands ES modules.

### Artifact size targets

The core library targets < 1 MB stripped. This crate carries the
wasm-bindgen glue plus
`serde-wasm-bindgen`, so the browser bundle is expected to be modestly
larger. Actual values on Apple Silicon running stable Rust 1.93:

| Artifact | Profile | Expected range |
|----------|---------|----------------|
| `chio_kernel_browser.wasm` | `--release` | ~0.7 MB |
| `chio_kernel_browser_bg.wasm` (via wasm-pack) | `--release` with `wasm-opt -Oz` | ~0.45 MB |

Use `wasm-opt -Oz` or `--release` with `lto = true` in a release
profile to drive the stripped size down further. The `wasm-pack`
pipeline runs `wasm-opt` automatically when the `binaryen` toolchain is
installed.

## Browser support matrix

| Browser | `Date.now()` | `crypto.getRandomValues` | WebAssembly | Verdict |
|---------|--------------|---------------------------|-------------|---------|
| Chrome ≥ 91 | yes | yes | yes | supported |
| Firefox ≥ 89 | yes | yes | yes | supported |
| Safari ≥ 14 | yes | yes | yes | supported |
| Edge (Chromium) | yes | yes | yes | supported |
| Node.js ≥ 18 (with `web` polyfills) | yes | yes | yes | supported via `wasm-pack --target nodejs` |
| Non-browser wasm32 hosts (no `window`) | -- | -- | yes | `WebCryptoRng::try_new` fails; receipts cannot be minted |

## Entry-point wire shapes

All entry points exchange plain JSON strings for maximum portability.
The Rust wire types are declared alongside the bindings and match the
portable kernel-core shapes byte-for-byte.

### `evaluate`

```ts
interface EvaluateRequest {
  request: {
    request_id: string;
    tool_name: string;
    server_id: string;
    agent_id: string;       // hex-encoded agent public key
    arguments: any;
  };
  capability: CapabilityToken;   // full signed envelope
  trusted_issuers_hex: string[]; // hex-encoded trusted authority keys
  clock_override_unix_secs?: number;
  session_filesystem_roots?: string[];
}

interface EvaluationVerdict {
  verdict: "allow" | "deny" | "pending_approval";
  reason?: string;
  matched_grant_index?: number;
  subject_hex?: string;
  issuer_hex?: string;
  capability_id?: string;
  evaluated_at?: number;
}
```

### `sign_receipt`

```ts
interface SignReceiptRequest {
  body: ChioReceiptBody;
}
// sign_receipt(JSON.stringify(request), seedHex) => ChioReceipt
```

The `seedHex` argument is the 32-byte Ed25519 seed in lowercase hex
(with or without a leading `0x`). The signing path rewrites the body's
`kernel_key` to match the seed's public key so callers cannot submit a
mismatched body.

### `verify_capability`

```ts
// verify_capability(JSON.stringify(token), authorityHexOrArray)
//     => VerifiedCapability
```

`authorityHexOrArray` is either a single hex-encoded authority public
key or a JSON-encoded array of hex strings.

## Error shape

Every entry point returns `Err(JsValue)` on failure with a structured
object:

```ts
interface BindingError {
  code: string;    // machine-readable
  message: string; // human-readable
}
```

Error codes used by this crate: `invalid_json_input`,
`invalid_issuer_hex`, `invalid_seed_hex`, `invalid_authority_input`,
`capability_verification_failed`, `receipt_signing_failed`,
`weak_entropy`, `webcrypto_unavailable`, `encode_result_failed`.

## Acceptance checks

Acceptance criteria for the browser bindings:

> A browser page loads the WASM module via `wasm-bindgen`.
> `evaluate()` returns a verdict in <5ms. Receipt signing works using
> Web Crypto for entropy.

The repo-local verification suite for this crate is:

```bash
./scripts/qualify-portable-browser.sh
```

It builds the browser package, records the emitted wasm artifact size,
and runs the headless browser bindings test suite with latency output.

Drive the acceptance flow from the `examples/` directory:

1. `wasm-pack build --target web --release crates/chio-kernel-browser`.
2. Serve the crate root through any static file server
   (`python -m http.server`, `npx http-server`, etc.).
3. Open `examples/demo.html` in a supported browser.
4. Click **Load WASM**, then **Run evaluate()**, then
   **Run sign_receipt()**. The demo measures elapsed time via
   `performance.now()` and logs both the verdict envelope and the
   signed receipt envelope.

`tests/wasm_bindings.rs` replays the same flow programmatically via
`wasm-bindgen-test`; it is skipped on native targets and runs under
`wasm-bindgen-test-runner` when a headless browser is available.
