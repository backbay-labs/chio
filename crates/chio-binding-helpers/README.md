# chio-binding-helpers

`chio-binding-helpers` exposes a small set of bindings-friendly invariant
helpers over `chio-core` for multi-language Chio SDKs: canonical JSON from raw
JSON strings, capability parsing and verification, hashing and signing, signed
manifest parsing and verification, and receipt parsing and verification. The
surface stays deliberately narrow; session runtime, transport, auth, and
callback orchestration remain in the language-native SDKs.

Use this crate as the Rust core that language bindings call for the
verification invariants that must be implemented identically across SDKs.
