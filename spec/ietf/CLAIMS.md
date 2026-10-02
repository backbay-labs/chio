# Chio Protocol document review

Reviewed October 2, 2026 against the completed production kernel profile.

The review covers authority and exact-argument approval, durable execution ownership, dispatch commitment and uncertain effects, accounting and replay, authenticated runtime context, output release, evidence and retention, transport interoperability, signing roles, key lifecycle, and deployment security.

The document distinguishes artifact verification from execution-kernel conformance. A conforming kernel enforces the complete requirements of every selected feature. An adapter or artifact library alone does not establish execution conformance. Signatures authenticate statements under trusted keys; execution, provider effects, and public log visibility require their own evidence.

## Corrections

- Bind capabilities, approved arguments, reservations, executor authority, and finalized evidence to the same logical operation.
- Specify operation-owned nonce signing, pending approvals, and inline MCP receipt evidence.
- Preserve replay and committed exposure across restart, timeout, and ambiguous outcomes.
- Require configured receipt signers, explicit approver roles, authenticated trust-state updates, and actual attestation verification.
- Align MCP negotiation, notification responses, Origin validation, media types, and sender confirmation with the selected transport profile.
- Define confinement, credential custody, information flow, active response, tenant reads, trusted time, and retention at their enforcement boundaries.
- Preserve the exact signing projections and cryptographic vectors; separate protocol requirements from implementation-specific backing and assurance.

## Verification

`make -C spec/ietf check` regenerates the document and verifies committed renderings, example bytes, folding, XML structure, text width, and idnits submission checks. The review passed 79 vector-renderer tests, 8 build-gate tests, and 51 additional schema and signing-input assertions. idnits reported zero errors, warnings, or comments. The normative inventory covers 227 source blocks containing 591 BCP 14 keywords.

The normative text is the release conformance contract. Documentation checks do not certify deployment behavior or independent interoperability. Runtime acceptance must establish the lifecycle, confinement, recovery, and security requirements of the chosen production profile.
