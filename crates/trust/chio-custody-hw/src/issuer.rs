//! Issuer service.
//!
//! The in-process [`IssuerService`] turns a verified WebAuthn assertion
//! into a SIGNED audience-pinned [`PasskeyCapability`]. There is
//! intentionally no Axum binary in this crate: the service is a library
//! surface that `chio-control-plane` operators mount. The shape is
//! HTTP-shaped ([`MintRequest`] / [`MintResponse`]) so a follower can wire
//! an Axum `Router` without changing the call site.
//!
//! # Trust contract
//!
//! - The issuer accepts a `MintRequest` containing the audience pin, the
//!   verified credential id, the requested scope set, and the WebAuthn
//!   challenge nonce.
//! - The issuer never derives the audience from caller input outside of
//!   the signed request body; deployments pin the audience via constructor
//!   configuration that the caller cannot rewrite.
//! - The issuer requires user verification on the underlying assertion.
//!   A verified assertion that reports `user_verified = false` is rejected
//!   fail-closed with [`CustodyError::UserVerificationRequired`]; custody
//!   issuance is never downgraded to possession-only authentication, even
//!   in deployments where the relying party has not pinned UV at the
//!   WebAuthn layer.
//! - The issuer NEVER emits an unsigned capability. A signing backend is
//!   a mandatory constructor argument ([`IssuerService::with_signer`]), so
//!   an issuer without a signer cannot be constructed and the unsigned
//!   path is unrepresentable rather than merely guarded at runtime.
//!
//! # Issuance pipeline (fail-closed, ordered)
//!
//! `mint_capability` applies its gates in this order so the cheapest /
//! most abuse-resistant checks run first and an early deny never advances
//! later state:
//!
//! 1. Audience pin match.
//! 2. User-verification bit.
//! 3. Verified credential id and request challenge nonce canonicality.
//! 4. Per-subject rate limit ([`IssuanceRateLimiter`]). A flood is denied
//!    before the oracle, nonce store, or signer are touched.
//! 5. Revocation cascade ([`CredentialRevocationOracle`]). A revoked
//!    credential (or one revoked transitively through its parent) is
//!    denied before recording the nonce or signing.
//! 6. Replay nonce store ([`PasskeyNonceStore`]). A replayed
//!    `(credential_id, challenge_nonce)` is denied before signing.
//! 7. Signature over the canonical-JSON envelope.

use std::sync::Arc;

use chio_core_types::crypto::SigningBackend;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::capability::{PasskeyCapability, ScopeSet};
use crate::error::CustodyError;
use crate::mint::sign_capability;
use crate::nonce_store::{PasskeyNonceStore, RecordOutcome, MAX_NONCE_KEY_BYTES};
use crate::rate_limit::{IssuanceRateLimiter, RateLimitOutcome};
use crate::revocation::CredentialRevocationOracle;
use crate::verifier::VerifiedAssertion;

/// HTTP-shaped mint request. Canonical-JSON encodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRequest {
    /// Audience the caller wants the capability bound to. The issuer
    /// rejects the request fail-closed if this does not match its
    /// configured audience pin.
    pub audience: String,
    /// Requested scope set.
    pub scope_set: ScopeSet,
    /// Base64url-no-pad WebAuthn challenge nonce.
    pub challenge_nonce: String,
}

/// HTTP-shaped mint response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintResponse {
    /// The minted, signed capability. Its `signature` is never empty on a
    /// successful mint.
    pub capability: PasskeyCapability,
}

/// In-process issuer service.
///
/// Configured with a fixed audience pin that requests must match. The
/// audience pin is the kernel identity URI; it is not caller-rewritable.
///
/// The signing backend is MANDATORY: it turns the canonical envelope into
/// a signed capability and is the reason the issuer never emits an
/// unsigned artifact. The constructor accepts any
/// [`chio_core_types::crypto::SigningBackend`] (Ed25519, P-256/P-384 via
/// the `fips` feature, or `HybridBackend` via the `pq` feature) so a
/// deployment running with `crypto_floor=allow_classical` and one running
/// hybrid produce byte-identical envelopes apart from the `signature`
/// slot itself.
///
/// The rate limiter, nonce store, and revocation oracle are injectable so
/// a single-process deployment can use the in-crate in-memory
/// implementations while a clustered deployment swaps in durable /
/// distributed backends without changing the call site. When a gate is
/// not wired the corresponding check is skipped; the rate limiter is
/// wired by default (see [`Self::with_signer`]) so a freshly-constructed
/// issuer is rate-limited out of the box.
///
/// # FAIL-OPEN DEFAULT (read before constructing a production issuer)
///
/// The revocation cascade and the replay nonce store are **NOT wired by
/// default**: a bare [`Self::with_signer`] issuer skips BOTH checks and
/// will therefore mint for a *revoked* credential and accept a *replayed*
/// `(credential_id, challenge_nonce)`. The "wired-by-default" guarantee is
/// feature-level only; it exists once you call [`Self::with_durable_stores`]
/// (production) or [`Self::with_revocation_oracle`] /
/// [`Self::with_nonce_store`] (tests / single-process). Construct a
/// production issuer with [`Self::with_durable_stores`] (or wire both
/// stores explicitly); a `with_signer`-only issuer is for tests and any
/// deployment that has *deliberately* moved revocation/replay enforcement
/// upstream. A deployment that wants the fail-open posture to be an
/// explicit, fail-closed decision can chain
/// [`Self::enforce_revocation_replay`] as the final builder step: it
/// returns [`CustodyError`] (no issuer) unless BOTH gates are wired, so an
/// accidental fail-open issuer fails loudly at construction instead of
/// silently minting without revocation/replay enforcement.
pub struct IssuerService {
    audience: String,
    signer: Arc<dyn SigningBackend>,
    rate_limiter: Option<Arc<dyn IssuanceRateLimiter>>,
    nonce_store: Option<Arc<dyn PasskeyNonceStore>>,
    revocation: Option<Arc<dyn CredentialRevocationOracle>>,
}

fn validate_base64url_transport_field(label: &str, value: &str) -> Result<(), CustodyError> {
    if value.is_empty() {
        return Err(CustodyError::AssertionRejected(format!(
            "{label} must be a non-empty base64url-no-pad string"
        )));
    }
    if value.trim() != value {
        return Err(CustodyError::AssertionRejected(format!(
            "{label} must not have surrounding whitespace"
        )));
    }
    if value.len() > MAX_NONCE_KEY_BYTES {
        return Err(CustodyError::AssertionRejected(format!(
            "{label} length {} exceeds {MAX_NONCE_KEY_BYTES} bytes",
            value.len()
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(CustodyError::AssertionRejected(format!(
            "{label} must contain only base64url-no-pad characters"
        )));
    }
    Ok(())
}

impl IssuerService {
    /// Build an issuer pinned to an audience URI and a signing backend.
    /// The signing backend is typically the hybrid `HybridBackend` (or any
    /// [`SigningBackend`] when `crypto_floor=allow_classical`).
    ///
    /// A default [`RateLimiter`](crate::rate_limit::RateLimiter) (the
    /// conservative module defaults) is wired automatically so a
    /// freshly-constructed issuer is rate-limited without extra
    /// configuration; replace it with [`Self::with_rate_limiter`] or
    /// remove it with [`Self::without_rate_limiter`]. The nonce store and
    /// revocation oracle are opt-in via the builder methods.
    #[must_use]
    pub fn with_signer(audience: impl Into<String>, signer: Arc<dyn SigningBackend>) -> Self {
        Self {
            audience: audience.into(),
            signer,
            rate_limiter: Some(Arc::new(crate::rate_limit::RateLimiter::new())),
            nonce_store: None,
            revocation: None,
        }
    }

    /// Attach a custom [`IssuanceRateLimiter`], replacing the default.
    ///
    /// Builder-style: returns the issuer with the limiter wired. The
    /// limiter is consulted FIRST in the mint pipeline so a flood is
    /// denied before the oracle, nonce store, or signer are touched.
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: Arc<dyn IssuanceRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Remove the issuance rate limiter.
    ///
    /// Builder-style: returns the issuer with rate limiting disabled. Use
    /// only when an upstream component (e.g. an API gateway) already
    /// enforces a per-subject issuance budget; the default posture keeps
    /// the in-crate limiter wired.
    #[must_use]
    pub fn without_rate_limiter(mut self) -> Self {
        self.rate_limiter = None;
        self
    }

    /// Attach a [`PasskeyNonceStore`] for replay-attack resistance.
    ///
    /// Builder-style: returns the issuer with the nonce store wired.
    /// When set, every successful mint records
    /// `(credential_id, challenge_nonce)` keyed for replay detection;
    /// a duplicate fails the mint with [`CustodyError::ReplayDetected`].
    #[must_use]
    pub fn with_nonce_store(mut self, store: Arc<dyn PasskeyNonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    /// Attach a [`CredentialRevocationOracle`] for the revocation cascade.
    ///
    /// Builder-style: returns the issuer with the revocation cascade
    /// wired through the sparse-Merkle oracle. When set, every mint
    /// consults the oracle BEFORE recording the nonce or signing; a
    /// revoked credential fails-closed with
    /// [`CustodyError::CredentialRevoked`].
    #[must_use]
    pub fn with_revocation_oracle(mut self, oracle: Arc<dyn CredentialRevocationOracle>) -> Self {
        self.revocation = Some(oracle);
        self
    }

    /// Wire the DURABLE, default-posture stores: a SQLite-backed
    /// revocation oracle and replay nonce store, both persisted under
    /// `dir`. This is the wired-by-default path for a production issuer:
    /// the revocation cascade and the replay-detection state survive an
    /// issuer restart instead of resetting to empty (which would silently
    /// re-admit a previously-revoked credential or a previously-seen
    /// replay nonce after a crash).
    ///
    /// Builder-style: returns the issuer with both durable stores wired.
    /// The two stores live in sibling files under `dir`
    /// (`revocation.sqlite3` and `nonces.sqlite3`). Tests and
    /// single-process deployments can instead wire the in-memory stores via
    /// [`Self::with_revocation_oracle`] / [`Self::with_nonce_store`].
    ///
    /// Fail-closed: if either durable store cannot be opened (I/O fault,
    /// permission error, corrupt schema), this returns
    /// [`CustodyError`] and NO issuer is produced, so a deployment never
    /// silently falls back to a non-durable posture.
    ///
    /// This is the backward-compatible shape that hides the durable handles
    /// inside the issuer. When a deployment also needs to call
    /// `revoke_credential` / `is_revoked` (or share the same revoked-set
    /// cache across services) on the SAME `Arc` the issuer reads, use
    /// [`Self::with_durable_stores_handle`] instead: opening
    /// `revocation.sqlite3` through a SECOND oracle would NOT update this
    /// issuer's in-RAM cache, so post-startup revocations would not be
    /// observed by `mint_capability` until the issuer is rebuilt.
    #[cfg(feature = "sqlite-store")]
    pub fn with_durable_stores(self, dir: &std::path::Path) -> Result<Self, CustodyError> {
        // Construct and discard the handle: callers that only want the
        // wired issuer keep the original signature.
        let (issuer, _revocation) = self.with_durable_stores_handle(dir)?;
        Ok(issuer)
    }

    /// Like [`Self::with_durable_stores`], but ALSO returns the shared
    /// durable revocation oracle handle so a deployment can query
    /// `is_revoked` / drive `revoke_credential` on the very same `Arc` the
    /// issuer consults, or share that single revoked-set cache across
    /// services.
    ///
    /// The returned `Arc<SqliteCredentialRevocationOracle>` is the EXACT
    /// instance wired into the issuer (cloned, not reopened), so an operator
    /// revocation made through the handle is observed by `mint_capability`
    /// immediately, with no reopen and no second in-RAM cache to drift out of
    /// sync. The nonce store stays encapsulated; only the revocation oracle
    /// is shareable because it is the handle the operator/control-plane path
    /// needs.
    ///
    /// Same fail-closed contract as [`Self::with_durable_stores`]: if either
    /// store cannot be opened, this returns [`CustodyError`] and produces
    /// neither an issuer nor a handle.
    #[cfg(feature = "sqlite-store")]
    pub fn with_durable_stores_handle(
        self,
        dir: &std::path::Path,
    ) -> Result<
        (
            Self,
            Arc<crate::revocation::SqliteCredentialRevocationOracle>,
        ),
        CustodyError,
    > {
        let revocation_path = dir.join("revocation.sqlite3");
        let nonce_path = dir.join("nonces.sqlite3");
        let revocation_path = revocation_path.to_str().ok_or_else(|| {
            CustodyError::Encoding("durable revocation store path is not valid UTF-8".into())
        })?;
        let nonce_path = nonce_path.to_str().ok_or_else(|| {
            CustodyError::Encoding("durable nonce store path is not valid UTF-8".into())
        })?;
        let revocation = Arc::new(crate::revocation::SqliteCredentialRevocationOracle::open(
            revocation_path,
        )?);
        let nonces = crate::nonce_store::SqlitePasskeyNonceStore::open(nonce_path)?;
        let issuer = self
            .with_revocation_oracle(revocation.clone())
            .with_nonce_store(Arc::new(nonces));
        Ok((issuer, revocation))
    }

    /// Make the FAIL-OPEN DEFAULT an explicit, fail-closed decision at
    /// construction: assert that BOTH the revocation cascade and the replay
    /// nonce store are wired, returning [`CustodyError`] (no issuer) if
    /// either is missing.
    ///
    /// A bare [`Self::with_signer`] issuer skips both checks (see the
    /// type-level "FAIL-OPEN DEFAULT" note); minting against it admits a
    /// revoked credential and a replayed nonce. Production wiring should be
    /// [`Self::with_durable_stores`], but a deployment that builds the issuer
    /// by hand can chain `.enforce_revocation_replay()?` as the final builder
    /// step to turn an accidental fail-open posture into a loud, fail-closed
    /// construction error rather than a silent runtime gap. This is purely
    /// additive (existing call sites that deliberately run a minimal issuer,
    /// such as tests or deployments that enforce revocation/replay upstream,
    /// are unaffected unless they opt in to this guard).
    pub fn enforce_revocation_replay(self) -> Result<Self, CustodyError> {
        if self.revocation.is_none() {
            return Err(CustodyError::Encoding(
                "IssuerService::enforce_revocation_replay: no revocation oracle wired - \
                 minting would fail open on revocation; wire with_durable_stores or \
                 with_revocation_oracle"
                    .into(),
            ));
        }
        if self.nonce_store.is_none() {
            return Err(CustodyError::Encoding(
                "IssuerService::enforce_revocation_replay: no replay nonce store wired - \
                 minting would fail open on replay; wire with_durable_stores or \
                 with_nonce_store"
                    .into(),
            ));
        }
        Ok(self)
    }

    /// Configured audience pin for inspection.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Share the wired revocation oracle handle, if any.
    ///
    /// Returns the EXACT `Arc<dyn CredentialRevocationOracle>` the issuer
    /// consults (cloned, not reopened), so an operator path can drive
    /// `revoke_credential` / read `is_revoked` / enumerate `revoked_closure`
    /// on the same instance the issuer reads, with no second cache to drift
    /// out of sync. Returns `None` for a `with_signer`-only issuer that has
    /// not wired an oracle. For the durable concrete handle (e.g. to share a
    /// single SQLite-backed revoked-set cache across services), construct
    /// with [`Self::with_durable_stores_handle`].
    #[must_use]
    pub fn revocation_oracle(&self) -> Option<Arc<dyn CredentialRevocationOracle>> {
        self.revocation.clone()
    }

    /// Mint a capability from a verified assertion plus a request.
    ///
    /// `now` is the verifier clock; the capability's `iat` and `exp` are
    /// computed off this value (not the system clock) so tests can pin
    /// the timeline deterministically.
    ///
    /// Fail-closed paths (in pipeline order):
    /// - audience mismatch -> [`CustodyError::AudienceMismatch`]
    /// - assertion did not report user verification ->
    ///   [`CustodyError::UserVerificationRequired`]. Custody issuance
    ///   requires UV; an authenticator that verified cryptographically but
    ///   did not perform a user-verifying gesture (PIN, biometric) is
    ///   possession-only authentication, which the custody trust contract
    ///   forbids.
    /// - subject over its issuance budget -> [`CustodyError::RateLimited`]
    /// - credential revoked (directly or via a revoked parent) ->
    ///   [`CustodyError::CredentialRevoked`]
    /// - replayed `(credential_id, challenge_nonce)` ->
    ///   [`CustodyError::ReplayDetected`]
    ///
    /// On success the returned capability is always signed; the issuer
    /// has no code path that returns an unsigned capability.
    pub fn mint_capability(
        &self,
        verified: &VerifiedAssertion,
        request: &MintRequest,
        now: DateTime<Utc>,
    ) -> Result<MintResponse, CustodyError> {
        if request.audience != self.audience {
            return Err(CustodyError::AudienceMismatch {
                expected: self.audience.clone(),
                found: request.audience.clone(),
            });
        }

        if !verified.user_verified {
            return Err(CustodyError::UserVerificationRequired);
        }

        validate_base64url_transport_field("credential_id", &verified.credential_id_b64)?;
        validate_base64url_transport_field("challenge_nonce", &request.challenge_nonce)?;

        // Rate limiting. The cheapest abuse gate runs first so a flood is
        // shed before the oracle, nonce store, or signer are touched. A
        // limited subject (or a lock/clock fault inside the limiter)
        // fails closed.
        if let Some(limiter) = &self.rate_limiter {
            match limiter.check_and_record(&verified.credential_id_b64, now)? {
                RateLimitOutcome::Allowed => {}
                RateLimitOutcome::Limited => {
                    return Err(CustodyError::rate_limited(
                        verified.credential_id_b64.clone(),
                    ));
                }
            }
        }

        // Revocation cascade. The check happens AFTER the rate gate but
        // BEFORE recording the nonce or signing so a revoked credential
        // never advances the nonce store nor consumes a signing budget.
        // The cascade is synchronous from the issuer's point of view:
        // revoking the credential (or a parent that cascades to it) at the
        // oracle denies the next mint within the current epoch.
        if let Some(oracle) = &self.revocation {
            if oracle.is_revoked(&verified.credential_id_b64)? {
                return Err(CustodyError::CredentialRevoked);
            }
        }

        let mut cap = PasskeyCapability::new_stub_unsigned(
            self.audience.clone(),
            verified.credential_id_b64.clone(),
            request.scope_set.clone(),
            request.challenge_nonce.clone(),
            now,
        );

        // Replay-attack resistance. The nonce store is keyed on
        // (credential_id, challenge_nonce). The check happens BEFORE
        // signing so a replayed assertion never produces a signed
        // capability, even if the signer is fast enough to keep up.
        // Retention is `cap.exp + clock_skew` (clock_skew = 30s default
        // per `DEFAULT_CLOCK_SKEW_SECONDS`).
        if let Some(store) = &self.nonce_store {
            match store.record_if_fresh(
                &verified.credential_id_b64,
                &request.challenge_nonce,
                cap.exp.timestamp(),
            )? {
                RecordOutcome::Fresh => {}
                RecordOutcome::Replayed => {
                    return Err(CustodyError::ReplayDetected {
                        credential_id: verified.credential_id_b64.clone(),
                    });
                }
            }
        }

        // Signing is mandatory. `new_stub_unsigned` produced the envelope
        // with an empty `signature` slot; `sign_capability` overwrites it
        // with a detached signature over the canonical-JSON bytes and
        // refuses to return `Ok(_)` with an empty signature. There is no
        // branch that leaves the capability unsigned, so the issuer never
        // emits an unsigned artifact.
        sign_capability(&mut cap, self.signer.as_ref())?;
        debug_assert!(
            !cap.signature.is_empty(),
            "mint_capability invariant: returned capability must be signed"
        );

        Ok(MintResponse { capability: cap })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::RateLimiter;
    use chio_core_types::crypto::{Ed25519Backend, Keypair, Signature};
    use chrono::TimeZone;

    fn fixed_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 29, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_now fixture must construct"),
        }
    }

    fn signer(seed: u8) -> Arc<dyn SigningBackend> {
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[seed; 32])))
    }

    fn issuer(audience: &str, seed: u8) -> IssuerService {
        IssuerService::with_signer(audience, signer(seed))
    }

    fn verified() -> VerifiedAssertion {
        VerifiedAssertion {
            credential_id_b64: "AAAA".into(),
            user_verified: true,
        }
    }

    #[test]
    fn mints_signed_capability_with_correct_audience() {
        let svc = issuer("urn:chio:audience:kernel", 1);
        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let res = svc.mint_capability(&verified(), &req, fixed_now());
        let resp = match res {
            Ok(r) => r,
            Err(e) => panic!("mint must succeed for matching audience: {e}"),
        };
        assert_eq!(resp.capability.audience, "urn:chio:audience:kernel");
        assert!(
            !resp.capability.signature.is_empty(),
            "issued capability MUST be signed; the issuer never emits an unsigned artifact"
        );
        assert_eq!(resp.capability.credential_id, "AAAA");
    }

    #[test]
    fn mint_rejects_blank_verified_credential_id() {
        let svc = issuer("urn:chio:audience:kernel", 1);
        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let mut assertion = verified();
        assertion.credential_id_b64 = " ".into();

        let res = svc.mint_capability(&assertion, &req, fixed_now());

        assert!(matches!(
            res,
            Err(CustodyError::AssertionRejected(message)) if message.contains("credential")
        ));
    }

    #[test]
    fn mint_rejects_malformed_challenge_nonce_without_nonce_store() {
        let svc = issuer("urn:chio:audience:kernel", 1);
        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "bad nonce".into(),
        };

        let res = svc.mint_capability(&verified(), &req, fixed_now());

        assert!(matches!(
            res,
            Err(CustodyError::AssertionRejected(message)) if message.contains("challenge_nonce")
        ));
    }

    #[test]
    fn issued_signature_verifies_under_signer_public_key() {
        // Proves the issued capability verifies under the signer's public
        // key, and (with the empty-signature refusal in `sign_capability`)
        // that an unsigned issued capability is impossible.
        let backend = Ed25519Backend::new(Keypair::from_seed(&[5u8; 32]));
        let public = backend.public_key();
        let svc = IssuerService::with_signer("urn:chio:audience:kernel", Arc::new(backend));
        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "verify-me".into(),
        };
        let resp = match svc.mint_capability(&verified(), &req, fixed_now()) {
            Ok(r) => r,
            Err(e) => panic!("signed mint must succeed: {e}"),
        };
        let message = match crate::mint::signing_message(&resp.capability) {
            Ok(m) => m,
            Err(e) => panic!("signing_message must encode: {e}"),
        };
        let signature = match Signature::from_hex(&resp.capability.signature) {
            Ok(s) => s,
            Err(e) => panic!("issued signature must decode: {e}"),
        };
        assert!(
            public.verify(&message, &signature),
            "issued capability must verify under the signer public key"
        );
    }

    #[test]
    fn rejects_audience_mismatch_fail_closed() {
        let svc = issuer("urn:chio:audience:kernel", 2);
        let req = MintRequest {
            audience: "urn:chio:audience:other".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let res = svc.mint_capability(&verified(), &req, fixed_now());
        assert!(matches!(res, Err(CustodyError::AudienceMismatch { .. })));
    }

    #[test]
    fn rejects_assertion_without_user_verification_fail_closed() {
        // An authenticator that verified cryptographically but did not
        // report a user-verifying gesture must NOT receive a capability:
        // custody issuance requires UV to avoid silent downgrade to
        // possession-only authentication.
        let svc = issuer("urn:chio:audience:kernel", 3);
        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "n".into(),
        };
        let assertion = VerifiedAssertion {
            credential_id_b64: "AAAA".into(),
            user_verified: false,
        };
        let res = svc.mint_capability(&assertion, &req, fixed_now());
        let err = match res {
            Ok(_) => panic!("missing UV must fail-closed"),
            Err(e) => e,
        };
        assert!(matches!(err, CustodyError::UserVerificationRequired));
        assert_eq!(
            err.urn(),
            "urn:chio:error:custody:user-verification-required"
        );
    }

    #[test]
    fn rate_limit_triggers_fail_closed() {
        // A 1-per-window limiter admits the first mint and denies the
        // second within the window. The deny is a typed RateLimited
        // error, not an unsigned capability.
        let svc = IssuerService::with_signer("urn:chio:audience:kernel", signer(4))
            .with_rate_limiter(Arc::new(RateLimiter::with_limits(1, 600)));
        let first = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "rl-1".into(),
        };
        let second = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "rl-2".into(),
        };
        match svc.mint_capability(&verified(), &first, fixed_now()) {
            Ok(_) => {}
            Err(e) => panic!("first mint within budget must succeed: {e}"),
        }
        let err = match svc.mint_capability(&verified(), &second, fixed_now()) {
            Ok(_) => panic!("second mint over budget MUST fail-closed"),
            Err(e) => e,
        };
        match &err {
            CustodyError::RateLimited { subject } => assert_eq!(subject, "AAAA"),
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert_eq!(err.urn(), "urn:chio:error:custody:rate-limited");
    }

    #[cfg(feature = "sqlite-store")]
    #[test]
    fn durable_stores_handle_shares_the_revocation_oracle_with_the_issuer() {
        // The returned handle must be the SAME instance the issuer reads, so
        // a revocation driven through the handle is observed by mint_capability
        // immediately (no reopen, no second in-RAM cache to drift).
        let dir = std::env::temp_dir().join(format!(
            "chio-issuer-durable-handle-{}",
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_nanos(),
                Err(e) => panic!("clock before epoch: {e}"),
            }
        ));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            panic!("create temp dir: {e}");
        }

        let (svc, handle) = match IssuerService::with_signer("urn:chio:audience:kernel", signer(9))
            .with_durable_stores_handle(&dir)
        {
            Ok(pair) => pair,
            Err(e) => panic!("with_durable_stores_handle: {e}"),
        };

        let req = MintRequest {
            audience: "urn:chio:audience:kernel".into(),
            scope_set: ScopeSet::new(["tool:read"]),
            challenge_nonce: "dh-1".into(),
        };

        // Mint succeeds before any revocation.
        match svc.mint_capability(&verified(), &req, fixed_now()) {
            Ok(_) => {}
            Err(e) => panic!("first mint must succeed: {e}"),
        }

        // Revoke through the SHARED handle; the issuer must observe it.
        if let Err(e) = handle.revoke_credential("AAAA", 1_000) {
            panic!("revoke via shared handle: {e}");
        }
        let replay = MintRequest {
            challenge_nonce: "dh-2".into(),
            ..req.clone()
        };
        let err = match svc.mint_capability(&verified(), &replay, fixed_now()) {
            Ok(_) => panic!("mint after revocation via shared handle MUST fail-closed"),
            Err(e) => e,
        };
        assert!(
            matches!(err, CustodyError::CredentialRevoked),
            "a revocation on the shared handle must deny the next mint"
        );

        // The issuer also exposes the same oracle through the generic accessor.
        assert!(
            svc.revocation_oracle().is_some(),
            "a durable issuer must expose its wired revocation oracle"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enforce_revocation_replay_rejects_a_fail_open_issuer() {
        // The fail-open default is explicit: a bare with_signer issuer that
        // opts in to the guard must be rejected fail-closed at construction
        // rather than silently minting without revocation/replay checks.
        let bare = IssuerService::with_signer("urn:chio:audience:kernel", signer(7));
        assert!(
            matches!(
                bare.enforce_revocation_replay(),
                Err(CustodyError::Encoding(_))
            ),
            "an issuer with neither gate wired must be rejected by the guard"
        );

        // Wiring both gates lets the guard pass.
        let wired = IssuerService::with_signer("urn:chio:audience:kernel", signer(7))
            .with_revocation_oracle(Arc::new(
                crate::revocation::InMemoryCredentialRevocationOracle::new(),
            ))
            .with_nonce_store(Arc::new(
                crate::nonce_store::InMemoryPasskeyNonceStore::new(),
            ));
        assert!(
            wired.enforce_revocation_replay().is_ok(),
            "an issuer with both gates wired must pass the guard"
        );
    }
}
