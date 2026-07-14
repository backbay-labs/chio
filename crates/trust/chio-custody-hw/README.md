# chio-custody-hw

Chio's hardware-backed custody surface. It verifies WebAuthn passkey
assertions and mobile device attestations (Apple App Attest, Android Play
Integrity), and its `IssuerService` mints short-lived (5-minute), audience-pinned
`PasskeyCapability` envelopes signed through a configured `SigningBackend`.
Issuance runs through a fixed, fail-closed gate pipeline and never returns an
unsigned capability.

## Responsibilities

- Verify WebAuthn passkey assertions with their own per-credential replay
  resistance, independent of the issuer's replay store (`verifier`, feature
  `passkey`).
- Verify Apple App Attest and Android Play Integrity mobile attestations
  against pinned trust roots, never a caller-supplied key in production
  (`attestation`).
- Define the audience-pinned `PasskeyCapability` envelope and its RFC 8785
  canonical-JSON encoding (`capability`).
- Sign capabilities and reconstruct the signed message over any
  `chio_core_types::crypto::SigningBackend` (`mint`).
- Orchestrate issuance through a fixed, ordered gate pipeline that never
  emits an unsigned capability (`issuer`).
- Gate issuance with a pluggable per-subject rate limiter, replay nonce
  store, and transactional revocation cascade, each with an in-memory and a
  SQLite-backed implementation (`rate_limit`, `nonce_store`, `revocation`).
- Own the `urn:chio:error:custody:*` error taxonomy mirrored in
  `spec/errors/registry.yaml` (`error`).

Every item below is also re-exported at the crate root
(`chio_custody_hw::IssuerService`, and so on).

## Public API

- `capability::{PasskeyCapability, ScopeSet}` - the audience-pinned
  capability envelope and its scope set.
- `mint::{sign_capability, signing_message}` - detached-signature mint and
  the inverse message reconstruction verifiers use.
- `issuer::{IssuerService, MintRequest, MintResponse}` - the fail-closed
  issuance pipeline.
- `verifier::{PasskeyVerifier, VerifiedAssertion}` - WebAuthn assertion
  verification (`PasskeyVerifier` requires feature `passkey`).
- `attestation::{verify_app_attest, verify_play_integrity,
  verify_mobile_receipt_chain, AppAttestVerificationInput,
  PlayIntegrityVerificationInput, VerifiedAppAttest, VerifiedPlayIntegrity,
  VerifiedMobileReceiptChain, AttestationError, APP_ATTEST_FORMAT,
  MEETS_DEVICE_INTEGRITY, PLAY_RECOGNIZED}` - mobile device-attestation
  verifiers.
- `nonce_store::{PasskeyNonceStore, InMemoryPasskeyNonceStore,
  SqlitePasskeyNonceStore, RecordOutcome, DEFAULT_CLOCK_SKEW_SECONDS}` -
  replay detection (`SqlitePasskeyNonceStore` requires feature
  `sqlite-store`).
- `rate_limit::{IssuanceRateLimiter, RateLimiter, RateLimitOutcome,
  DEFAULT_MAX_PER_WINDOW, DEFAULT_WINDOW_SECONDS}` - per-subject issuance
  throttling.
- `revocation::{CredentialRevocationOracle, InMemoryCredentialRevocationOracle,
  SqliteCredentialRevocationOracle, credential_revocation_nonce,
  CREDENTIAL_REVOCATION_NONCE_VALUE}` - the revocation cascade
  (`SqliteCredentialRevocationOracle` requires feature `sqlite-store`).
- `error::CustodyError` - the crate's fail-closed error taxonomy.

## Usage

```rust
use std::sync::Arc;

use chio_core_types::crypto::{Ed25519Backend, Keypair, SigningBackend};
use chio_custody_hw::{IssuerService, MintRequest, ScopeSet, VerifiedAssertion};

let signer: Arc<dyn SigningBackend> =
    Arc::new(Ed25519Backend::new(Keypair::from_seed(&[7u8; 32])));
// Production deployments also wire durable stores (`with_durable_stores`, or
// `enforce_revocation_replay()` to make the requirement a construction-time
// error): a bare `with_signer` issuer skips revocation and replay checks.
let issuer = IssuerService::with_signer("urn:chio:audience:kernel", signer);

let verified = VerifiedAssertion {
    credential_id_b64: "AAAA".into(),
    user_verified: true,
};
let request = MintRequest {
    audience: "urn:chio:audience:kernel".into(),
    scope_set: ScopeSet::new(["tool:read"]),
    challenge_nonce: "n-1".into(),
};

let response = issuer.mint_capability(&verified, &request, chrono::Utc::now())?;
assert!(!response.capability.signature.is_empty());
```

## Feature flags

| Flag | Effect |
|------|--------|
| `passkey` (default) | Enables `PasskeyVerifier`, pulling in `webauthn-rs` / `webauthn-rs-proto`. |
| `sqlite-store` (default) | Enables `SqlitePasskeyNonceStore` and `SqliteCredentialRevocationOracle`, durable stores sharing the workspace's pinned `rusqlite` version with `chio-store-sqlite`. |
| `pq` | Enables post-quantum `HybridBackend` signing via `chio-core-types/pq` (ML-DSA-65). |
| `dev-fixtures` | Compiles in synthetic mobile-attestation fixtures (the App Attest compact-map shape, a caller-supplied Play Integrity JWKS). Test/dev only; never enable in a shipped binary. |

## Testing

`cargo test -p chio-custody-hw`

Integration tests under `tests/` cover attestation verification, replay
resistance, the revocation cascade, audience confusion, canonical-JSON
stability, and an end-to-end issuer-to-kernel-verifier flow.
`fixtures/passkey/` pins a JSON descriptor corpus mapping WebAuthn failure
modes to their expected `urn:chio:error:custody:*` code.

## See also

- `chio-core-types` - supplies the `SigningBackend` family and canonical-JSON
  encoding the issuer signs over.
- `chio-revocation-oracle` - the sparse-Merkle oracle `CredentialRevocationOracle` wraps.
- `chio-kernel` - its `custody::PasskeyCapabilityVerifier` verifies capabilities minted here.
- `chio-kernel-mobile` - consumes the App Attest / Play Integrity verifiers with `default-features = false` to avoid the OpenSSL-backed `webauthn-rs` graph in iOS staticlib builds.
