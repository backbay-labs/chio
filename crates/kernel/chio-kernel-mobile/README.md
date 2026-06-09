# chio-kernel-mobile

`chio-kernel-mobile` is the mobile FFI for the portable Chio kernel core. It
wraps the `chio-kernel-core` surface in an ergonomic, JSON-in / JSON-out Rust
API and projects it across the C ABI using UniFFI. The UDL file in
`src/chio_kernel_mobile.udl` drives binding generation for Swift (iOS) and
Kotlin (Android).

Use this crate when embedding Chio verdict evaluation in an iOS or Android app.
See `bindings/README.md` for the bindgen workflow.
