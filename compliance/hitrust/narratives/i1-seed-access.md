# Access Control Narrative

Chio access control is implemented through capability issuance,
validation, attenuation, revocation, sender constraints, and kernel
admission checks. The evidence is the protocol and security specs
(`spec/PROTOCOL.md`, `spec/SECURITY.md`), the kernel implementation
(`crates/chio-kernel-core/src/evaluate.rs`,
`crates/chio-core-types/src/capability.rs`), and the formal proofs that
constrain these call sites (`formal/MAPPING.md`).

This family is self-assessed as implemented for the in-scope deployment.
The only outstanding work is row-level control mapping and, for a real
engagement, sampling of production receipts and revocation cases (which
have not occurred).

Fail-closed note: invalid, expired, revoked, or sender-mismatched
capabilities deny access.
