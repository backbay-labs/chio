# Access Control Narrative

Chio access control is implemented through capability issuance,
validation, attenuation, revocation, sender constraints, and kernel
admission checks. The strongest inherited evidence is `spec/PROTOCOL.md`,
`spec/SECURITY.md`, and the kernel implementation. The P1 posture is
ready with inherited evidence, pending assessor sampling of receipts
and revocation cases.

Fail-closed note: invalid, expired, revoked, or sender-mismatched
capabilities deny access.
