# Guard-world fuzz fixture

`guard_world.wasm` is the compact component used by `wasm_guard_smith` to
exercise successful `chio:guard@0.2.0` evaluation. It returns allow only when
`tool_name` is `smith-allow`; every other request returns a typed deny. The
fuzzer embeds a wasm-smith-generated nested component into this component, then
checks the host result against the independently selected request.

The committed source is `src/lib.rs`; `guard_world.wit` is the target world.
The adjacent manifest, lockfile, and toolchain pin make the component
byte-reproducible with `cargo-component 0.21.1`. From this directory, run:

```bash
cargo component build --locked --release --target wasm32-unknown-unknown
sha256sum target/wasm32-unknown-unknown/release/chio_wasm_guard_world_fixture.wasm
cmp target/wasm32-unknown-unknown/release/chio_wasm_guard_world_fixture.wasm \
  guard_world.wasm
```

The component name and Rust 1.96.0 toolchain affect the emitted bytes and are
therefore pinned rather than treated as incidental build metadata.

The expected SHA-256 is
`975da1624d19023092c26e90a6dc21f013ef911c9b641abbf89a2e23e93363f9`.
