# Chio Adversarial Cases

This directory holds malicious-but-well-formed cases consumed by
trust-boundary tests. Every case is a canonical JSON object that validates
against `../schema/case.schema.json` and is deny-asserted by downstream
harnesses.

Case files are grouped by attack class:

- `clock_rewound/`
- `future_dated/`
- `replayed_nonce/`
- `partial_signature/`
- `scope_superset/`
- `revocation_rollback/`
- `anchor_grafted/`
- `sigstore_bundle_payload_mismatch/`

Vector files are stored in these directories. Auto-promoted cases must set
`pending: true` until triaged; pending cases do not count as threat-model
coverage.
