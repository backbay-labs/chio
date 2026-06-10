# chio-bindings-ffi

`chio-bindings-ffi` is the C ABI for Chio's deterministic SDK invariant
helpers. The ABI stays intentionally narrow: UTF-8 strings and byte buffers in,
UTF-8 buffers out, explicit Rust-side deallocation, and no async or session
state crossing the boundary. It wraps `chio-binding-helpers`.

Use this crate to call Chio's invariant helpers from a non-Rust language over a
plain C ABI.
