# chio-custody-hw Architecture

## Boundary

`chio-custody-hw` owns Chio's hardware-backed custody minting surface. It verifies passkey assertions, carries mobile attestation helpers, builds the audience-pinned `PasskeyCapability` envelope, signs capabilities through the configured backend, and rejects replays, revoked credentials, and issuance floods before a signature is produced.

## Internal Surfaces

The crate is split into assertion verification, capability canonicalization, signing, issuer orchestration, nonce stores, rate limiting, revocation cascade adapters, and mobile attestation verifiers. The issuer is the main trust boundary: it receives a verified assertion plus a mint request and must reject malformed transport material before rate-limit, revocation, replay, or signing state changes happen.

## Trust Invariants

The security constraint is hardware assertion freshness. Credential ids, challenge nonces, audience pins, scope sets, expiry timestamps, revocation subjects, and detached signatures must remain canonical and unambiguous across verifier, issuer, nonce-store, and kernel checks.

## Verification Focus

Tests should cover malformed WebAuthn transport material, replay nonce absence and presence, revoked credentials, rate-limit ordering, audience-pin mismatches, and signing backend failures that must not leak partially minted capabilities.

## Improvement Target

Planned improvement: reject non-base64url credential ids and challenge nonces at the issuer boundary even when no replay nonce store is attached, so malformed WebAuthn transport material cannot be signed into a capability.
