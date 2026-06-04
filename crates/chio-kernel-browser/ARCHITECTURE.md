# chio-kernel-browser Architecture

`chio-kernel-browser` is the wasm-bindgen facade over the portable
`chio-kernel-core` surface. It adapts browser clock and entropy sources to the
core kernel, exposes JSON-over-wire entry points to JavaScript and TypeScript,
and keeps native tests on pure helper functions so the crate can be verified
without a browser toolchain.

## Boundaries

- `chio-kernel-core` owns capability verification, verdict evaluation, receipt
  signing, budget-split enforcement, and portable receipt verification.
- `chio-core-types` owns capability, receipt, key, and canonical JSON shapes.
- Browser-only dependencies (`wasm-bindgen`, `js-sys`, `web-sys`, and
  `serde-wasm-bindgen`) stay behind `cfg(target_arch = "wasm32")`.
- This crate owns browser wire envelopes, `BrowserClock`, `WebCryptoRng`, JS
  error shaping, authority-input parsing, receipt seed decoding, and conversion
  between browser JSON values and portable kernel inputs.

## Trust Invariants

- Browser capability-only evaluation never returns authoritative `allow`; a
  core allow is downgraded to `pending_approval` until mediated execution can
  issue a prevent-boundary receipt.
- Trusted authority inputs must be non-empty hex strings. JSON authority arrays
  reject empty arrays and blank members before public-key decoding.
- Web Crypto entropy failure never signs a receipt with a zero seed.
- Receipt verification distinguishes signature math from trust pinning; `ok`
  requires a valid signature, valid parameter hash, valid receipt id, and an
  explicitly trusted signer.
- Native stubs for browser clock and RNG fail closed and exist only so host
  tests can exercise pure helpers.

## Testing Focus

Native unit tests cover pure evaluation, capability verification, budget
snapshots, seed decoding, authority parsing, receipt signing, and receipt
verification. Wasm-bindgen tests cover the browser entry points when the wasm
test runner is available. Verdict-matrix tests document which classes the
browser capability-only driver supports and which stateful classes remain
unsupported.
