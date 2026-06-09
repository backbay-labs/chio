# Escape harness static fixtures

Static byte fixtures consumed by `crates/chio-wasm-guards/tests/escape/`.
The malformed-component-encoding class lives here (raw `.wasm` blobs);
the signed-but-malicious class is generated programmatically at test
time via `ed25519_dalek` so the harness does not depend on a checked-in
private key.

Files:

- `malformed_component_truncated.wasm` -- valid component preamble
  (4-byte magic plus `\x0d\0\x01\0` layer/version), followed by an
  invalid section id (`0xff`) and four bytes of garbage payload. Drives
  `ComponentBackend::load_module` into the parse-error path.
- `malformed_component_zero_layer.wasm` -- core-module magic (`\x01\0\x00\0`
  layer/version) preamble that nonetheless carries the component-magic
  prefix; surfaces as a typed Compilation error rather than hitting the
  core path.
- `malformed_component_wrong_version.wasm` -- component preamble with a
  bumped version field (`\x99\0`) the runtime does not recognise.

These fixtures are NOT in `fuzz/corpus/wasm_guard_escape/` -- the fuzz
corpus carries one seed per class for libFuzzer mutation; this
directory carries multiple per-class fixtures for deterministic
companion-test coverage.
