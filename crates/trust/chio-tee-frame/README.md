# chio-tee-frame

`chio-tee-frame` defines the wire format for Chio TEE replay frames (kernel
decision capture). The Rust types in `frame` mirror the v1 JSON schema
field-for-field, and `schema` holds the structural and pattern invariants.
Encoding reuses `chio_core::canonical::canonical_json_bytes` (RFC 8785) so a
frame signed in Rust round-trips byte-for-byte.

Use this crate for the canonical frame types shared by the capture runner
(`chio-tee`) and replay tooling. The normative wire specification is
`spec/PROTOCOL.md`.
