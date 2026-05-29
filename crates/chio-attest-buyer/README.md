# chio-attest-buyer

`chio-attest-buyer` owns the public Chio buyer attestation verification
boundary. The public proof-verification API and data types are defined here so
callers depend on Chio shapes rather than on the proof-verifier internals. Full
proof replay is delegated to the hardened verifier core in
`chio-attest-buyer-core`, which keeps strict treaty-bound DSSE semantics and
leaves hash-only DSSE unresolved.

Use this crate as the entry point for verifying a Chio buyer proof package.
