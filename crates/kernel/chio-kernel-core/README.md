# chio-kernel-core

`chio-kernel-core` is the portable, pure-compute subset of Chio evaluation,
packaged as a `no_std + alloc` library. The same verdict-producing code can run
inside a browser (`wasm32-unknown-unknown`), a Cloudflare Worker
(`wasm32-wasip1`), a mobile app (UniFFI static lib), or the desktop sidecar
(`chio-kernel`). It performs verdict evaluation, capability verification, and
receipt signing without pulling in I/O, transport, or persistence.

Use this crate when you need Chio enforcement logic on a constrained or
non-native target. The full sidecar runtime lives in `chio-kernel`; the
architecture contract is documented in
`docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md`.
