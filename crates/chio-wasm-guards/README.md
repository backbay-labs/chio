# chio-wasm-guards

`chio-wasm-guards` is the WASM guard runtime for Chio. It lets operators author
guards in any language that compiles to WebAssembly (Rust, AssemblyScript, Go,
C) and load them into the kernel at runtime via `chio.yaml`. The host runs
`.wasm` guard modules with fuel metering and transparently supports both core
modules and WASM components.

Use this crate when running operator-authored guards as sandboxed WASM. Guard
authors should start with `chio-guard-sdk`; signed distribution of modules is
handled by `chio-guard-registry`.
