# HITRUST Key Rotation Policy

**Scope:** Chio healthcare design-partner deployment (this assessed release)
**Owner:** Chio security owner

> **Status: internal readiness.** This policy is documented; rotation
> execution evidence has not yet been produced and is an open gap.

## Rotation schedule

| Key class | Rotation cadence | Emergency trigger | Evidence |
|-----------|------------------|-------------------|----------|
| capability signing keys | at least every 90 days | suspected key compromise, scoped revocation bypass, signer mismatch | rotation receipt and key-id cutover log |
| TLS service certificates | before expiration and at least annually | private key exposure, CA revocation, endpoint mis-issuance | certificate inventory and deployment record |
| audit-log export keys | at least every 180 days | export-key exposure, integrity failure, recipient rotation | export-key rotation receipt |
| MyCSF portal credentials | quarterly access review | assessor roster change, vendor offboarding | access-review evidence packet |

## Capability signing cutover

Capability signing key rotation uses a fail-closed cutover:

1. Create the new key under custody controls.
2. Publish the new key identifier to the verifier set.
3. Issue new capabilities only from the new key.
4. Keep the old key in verify-only mode for the maximum capability
   lifetime.
5. Revoke the old key and record the cutover receipt.

If verifiers cannot load the new key set, issuance pauses and access is
denied rather than falling back to an untracked signer.

## Evidence requirements

Each rotation record must contain the key class, old key id, new key id,
operator, timestamp, reason, verification result, and receipt hash. P3
evidence bundles include only hashes or redacted records, not private
key material.
