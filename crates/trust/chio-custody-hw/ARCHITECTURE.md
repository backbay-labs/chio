# chio-custody-hw architecture

## Overview

`chio-custody-hw` turns a verified WebAuthn passkey assertion or a mobile
device attestation into evidence the rest of the workspace can act on.
`IssuerService` is the crate's central trust boundary: it holds the mandatory
signing backend and runs every mint through an ordered, fail-closed gate
pipeline before a signature is produced. The crate is a library, not a
service: `MintRequest` / `MintResponse` are HTTP-shaped so an operator (see
`chio-kernel`) can wire an HTTP surface without changing the call site. Mobile
attestation (Apple App Attest, Android Play Integrity) is a separate,
stateless verification surface with its own pinned trust roots; it is not
wired into the capability-mint pipeline.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate re-exports. `#![forbid(unsafe_code)]`, `clippy::unwrap_used`, `clippy::expect_used`. |
| `src/capability.rs` | `PasskeyCapability` envelope, `ScopeSet`, canonical-JSON encode/decode, audience and expiry checks. |
| `src/mint.rs` | `sign_capability` / `signing_message`: the detached signature over the canonical envelope, via `SigningBackend`. |
| `src/issuer.rs` | `IssuerService`: the ordered, fail-closed mint pipeline (`MintRequest` -> `MintResponse`). |
| `src/verifier.rs` | `PasskeyVerifier` (feature `passkey`): wraps `webauthn-rs`, adds a per-credential replay nonce store. |
| `src/nonce_store.rs` | `PasskeyNonceStore` trait; `InMemoryPasskeyNonceStore` and `SqlitePasskeyNonceStore` (feature `sqlite-store`). |
| `src/rate_limit.rs` | `IssuanceRateLimiter` trait; `RateLimiter`, a per-subject sliding-window limiter. |
| `src/revocation.rs` | `CredentialRevocationOracle` trait wrapping `chio-revocation-oracle`'s sparse-Merkle oracle, plus the dependency cascade; `InMemoryCredentialRevocationOracle` and `SqliteCredentialRevocationOracle` (feature `sqlite-store`). |
| `src/error.rs` | `CustodyError` taxonomy; `urn:chio:error:custody:*` codes mirrored in `spec/errors/registry.yaml`. |
| `src/attestation/mod.rs` | Mobile device-attestation verifier re-exports. |
| `src/attestation/app_attest.rs` | Apple App Attest verifier: CBOR/COSE parsing, cert-chain validation to the pinned root, nonce/app-id/counter/key binding. |
| `src/attestation/apple_root.rs` | Pinned Apple App Attestation Root CA (PEM + SHA-256 fingerprint) and its self-check. |
| `src/attestation/google_root.rs` | Pinned Play Integrity verification key, plus `assert_play_integrity_root_is_production_ready`. |
| `src/attestation/play_integrity.rs` | Android Play Integrity JWS verifier against the pinned JWKS. |
| `src/attestation/receipt_chain.rs` | Shape-only receipt/evidence envelope shell; not on any capability-mint path. |
| `src/attestation/errors.rs` | `AttestationError` taxonomy and its `urn:chio:error:custody:app-attest-*` / `play-integrity-*` codes. |

## Issuance pipeline

`IssuerService::mint_capability` runs a fixed sequence so the cheapest and
most abuse-resistant checks deny before any state mutates or the signer is
touched:

1. Audience pin match (`MintRequest.audience` against the issuer's
   configured audience).
2. User-verification bit (`VerifiedAssertion.user_verified`); an assertion
   that verified cryptographically but reports no UV gesture is still
   rejected.
3. Transport validation of the credential id and challenge nonce (non-empty,
   unpadded, base64url-no-pad, bounded length).
4. Per-subject rate limit (`IssuanceRateLimiter`), if wired.
5. Revocation cascade (`CredentialRevocationOracle::is_revoked`), if wired.
6. Replay nonce store (`PasskeyNonceStore::record_if_fresh`), if wired.
7. Signature over the canonical-JSON envelope (`mint::sign_capability`),
   which itself refuses to return `Ok(_)` with an empty signature.

## Mobile attestation verification

`verify_app_attest` and `verify_play_integrity` are independent, stateless
functions, not steps in the issuance pipeline above; `chio-kernel-mobile`
calls them directly. Each validates against a pinned trust root rather than
a caller-supplied one:

- App Attest parses the CBOR attestation object, validates the `x5c` chain
  to the pinned Apple App Attestation Root CA, binds the server challenge
  through Apple's nonce X.509 extension, checks the app-id hash, enforces
  counter monotonicity, and binds the attestation leaf key to the
  credential's COSE public key (WebAuthn registration step 6).
- Play Integrity validates the ES256 JWS against the pinned Google JWKS
  (`google_root`), then checks `aud`, `exp`, nonce, package name, and the
  app/device integrity verdicts.
- `verify_mobile_receipt_chain` is a shape-only shell (schema and
  platform-string checks only); it is reachable from the crate root but not
  consulted by any capability-mint path.

## Invariants and failure modes

- The issuer never emits an unsigned capability: the signing backend is a
  mandatory constructor argument, and `sign_capability` refuses to return
  `Ok(_)` with an empty signature.
- **Fail-open default:** `IssuerService::with_signer` alone wires neither the
  revocation cascade nor the replay nonce store; a fresh issuer will mint for
  a revoked credential and accept a replayed nonce. Production wiring is
  `with_durable_stores`, or `enforce_revocation_replay()` to turn a missing
  gate into a construction-time error instead of a silent runtime gap.
- The revocation cascade is transactional: `revoke_credential` and
  `register_dependency` stage the full transitive closure against a scratch
  oracle clone (or one SQLite transaction) and commit only if every leaf
  inserts cleanly; the walk is cycle-safe.
- The WebAuthn-ceremony replay store (`PasskeyVerifier`) and the mint-time
  replay store (`IssuerService`'s `PasskeyNonceStore`) are separate instances
  guarding different boundaries; wiring one does not substitute for the
  other.
- Play Integrity's pinned root is currently a committed synthetic fixture key
  (`chio-play-integrity-fixture-root`); the production verification path
  fails closed via `assert_play_integrity_root_is_production_ready` until it
  is rotated for a real Google key.
- App Attest rejects the sandbox/development AAGUIDs when
  `AppAttestVerificationInput::production` is `true`; the compact-map
  development-fixture path only compiles under `cfg(test)` or feature
  `dev-fixtures` and is otherwise unreachable.
- The nonce store and rate limiter both fail closed on lock poisoning,
  capacity limits, and non-positive windows/budgets; a fault narrows the
  admitted rate, never widens it.
- `PasskeyCapability::exp` is fixed at `iat + 5 minutes`. Every trust check
  that depends on time (`mint_capability`, `verify_assertion`,
  `check_and_record`, `record_if_fresh`, `is_live`) takes `now` as an
  explicit argument rather than reading the system clock, so a deployment
  pins one authoritative clock source and tests stay deterministic.

## Dependencies

Internal: `chio-core-types` supplies `SigningBackend` (`Ed25519Backend`, the
FIPS P-256/P-384 backends, `HybridBackend` under `pq`), canonical-JSON
encoding (RFC 8785), and the `Keypair` / `PublicKey` / `Signature` types.
`chio-revocation-oracle` supplies the sparse-Merkle `RevocationOracle`
(`InMemoryRevocationOracle`, `RevocationKey`, `SubjectId`, `EpochNonce`,
`EpochRoot`) that `revocation.rs` wraps as `CredentialRevocationOracle`.

External: `webauthn-rs` / `webauthn-rs-proto` (feature `passkey`) is the
relying-party WebAuthn implementation `PasskeyVerifier` wraps; `url` supplies
the `Url` type for relying-party origins. `rusqlite` (feature `sqlite-store`)
backs the durable nonce store and revocation oracle, version-pinned to match
`chio-store-sqlite`. `coset`, `x509-parser`, and `der` parse CBOR/COSE and
validate X.509 chains for App Attest. `jsonwebtoken` decodes and verifies the
Play Integrity ES256 JWS. `sha2`, `hex`, and `base64ct` provide hashing and
the base64url/hex transport encodings. `chrono` carries the caller-supplied
clock (`iat`/`exp`, rate-limit and nonce-store retention bounds); the crate
never reads the system clock internally.

## Extension points

- `PasskeyNonceStore`, `IssuanceRateLimiter`, `CredentialRevocationOracle` -
  swap in durable or distributed backends without changing the
  `IssuerService` call site; each ships an in-memory default plus a
  SQLite-backed implementation under `sqlite-store`.
- `chio_core_types::crypto::SigningBackend` - any backend the issuer is
  constructed with (classical, FIPS, or hybrid post-quantum).
