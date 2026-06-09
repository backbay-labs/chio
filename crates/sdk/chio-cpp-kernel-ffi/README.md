# chio-cpp-kernel-ffi

`chio-cpp-kernel-ffi` is the C ABI for the Chio C++ offline kernel package. It
mirrors the mobile adapter's JSON-in / JSON-out shape but exposes a plain C ABI
that the C++ SDK can link without surfacing UniFFI or Rust concepts in public
C++ headers.

Use this crate to embed the offline Chio kernel in a C++ application. The
portable evaluation core it wraps is `chio-kernel-core`.
