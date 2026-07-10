use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    is_default_optional_algorithm, sign_canonical_with_backend, Keypair, PublicKey, Signature,
    SigningAlgorithm, SigningBackend,
};
use crate::error::{Error, Result};
use crate::schema_binding::ensure_schema_matches;
use crate::signer_binding::{
    ensure_backend_matches_embedded_key, ensure_keypair_matches_embedded_key,
};

use super::attenuation::{
    scope_hash, validate_attenuation_proof, verify_attenuation_witness, Attenuation,
    AttenuationProof, DelegationLink, ScopeHash,
};
use super::caveat::Caveat;
use super::crypto_floor::{CapabilityCryptoFloor, CapabilityFloorVerifyError};
use super::features::{self, CapabilityNegotiation};
use super::scope::ChioScope;
use super::validation::validate_budget_share_bps;

/// Current capability-token schema. Chio is unreleased, so pre-release
/// attenuation and delegation-binding fields are folded into this v1 shape.
pub const CHIO_CAPABILITY_SCHEMA: &str = "chio.capability.v1";

fn default_capability_schema() -> String {
    CHIO_CAPABILITY_SCHEMA.to_string()
}

fn is_none_or_empty<T>(value: &Option<Vec<T>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

fn is_none_or_empty_attenuation_proof(value: &Option<AttenuationProof>) -> bool {
    value.is_none()
}

/// A Chio capability token. Scoped, time-bounded, cryptographically signed.
///
/// The `signature` field covers the canonical JSON of all other fields.
/// Verification re-serializes the token (excluding the signature), computes
/// the canonical form, and checks the signature against `issuer` using the
/// algorithm declared by the `algorithm` field (defaulting to Ed25519 when
/// absent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Versioned signed-artifact schema. Wire schema identifier; tokens that
    /// omit this field default to `chio.capability.v1`.
    #[serde(default = "default_capability_schema")]
    pub schema: String,
    /// Unique token ID (UUIDv7 recommended, used for revocation).
    pub id: String,
    /// Capability Authority (or delegating agent) that issued this token.
    pub issuer: PublicKey,
    /// Agent this capability is bound to (DPoP sender constraint).
    pub subject: PublicKey,
    /// What this token authorizes.
    pub scope: ChioScope,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// Ordered list of delegation links from the root CA to this token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationLink>,
    /// Signing algorithm. Absent means Ed25519 (the default).
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    /// Typed caveats. Empty tokens omit this on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
    /// High-level attenuation request exposed on attenuated tokens.
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub scope_attenuations: Option<Vec<Attenuation>>,
    /// Wire witness proving child-scope attenuation.
    #[serde(default, skip_serializing_if = "is_none_or_empty_attenuation_proof")]
    pub attenuation_proof: Option<AttenuationProof>,
    /// Fixed-point sub-agent budget share in basis points. Values above
    /// 10000 are rejected by validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_share_bps: Option<u16>,
    /// Signature over canonical JSON of all fields above.
    pub signature: Signature,
}

/// The body of a capability token, containing every field except the signature.
/// Used as the signing input.
///
/// The declared signing algorithm is not included in the body: the `signature`
/// type itself is self-describing (Ed25519 / P-256 / P-384) via its hex
/// encoding, and the `issuer` key encodes its own algorithm. This keeps the
/// pre-`SigningBackend` Ed25519 body serialization byte-identical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenBody {
    pub id: String,
    pub issuer: PublicKey,
    pub subject: PublicKey,
    pub scope: ChioScope,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationLink>,
}

/// Schema-aware capability-token signing input used by newly-issued tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenSigningBody {
    pub schema: String,
    #[serde(flatten)]
    pub body: CapabilityTokenBody,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub scope_attenuations: Option<Vec<Attenuation>>,
    #[serde(default, skip_serializing_if = "is_none_or_empty_attenuation_proof")]
    pub attenuation_proof: Option<AttenuationProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_share_bps: Option<u16>,
}

/// Attenuated capability signing input with attenuation and caveat fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenAttenuationBody {
    #[serde(flatten)]
    pub body: CapabilityTokenBody,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_attenuations: Vec<Attenuation>,
    pub attenuation_proof: AttenuationProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_share_bps: Option<u16>,
}

impl CapabilityToken {
    /// Extract the body (everything except the signature) for re-verification.
    #[must_use]
    pub fn body(&self) -> CapabilityTokenBody {
        CapabilityTokenBody {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            scope: self.scope.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            delegation_chain: self.delegation_chain.clone(),
        }
    }

    /// Extract the schema-aware body used for newly-issued signatures.
    #[must_use]
    pub fn signing_body(&self) -> CapabilityTokenSigningBody {
        CapabilityTokenSigningBody {
            schema: self.schema.clone(),
            body: self.body(),
            caveats: self.caveats.clone(),
            scope_attenuations: self.scope_attenuations.clone(),
            attenuation_proof: self.attenuation_proof.clone(),
            budget_share_bps: self.budget_share_bps,
        }
    }

    fn permits_plain_body_signature(&self) -> bool {
        // Plain v1 tokens sign over the body directly; caveat-bearing tokens sign the schema-aware envelope.
        self.schema == CHIO_CAPABILITY_SCHEMA
            && self.caveats.is_empty()
            && self.scope_attenuations.as_ref().is_none_or(Vec::is_empty)
            && self.attenuation_proof.is_none()
            && self.budget_share_bps.is_none()
    }

    /// Reject unknown schema IDs and budget amplification.
    pub fn validate_schema(&self) -> Result<()> {
        ensure_schema_matches(&self.schema, CHIO_CAPABILITY_SCHEMA, "capability token")?;
        if !self.caveats.is_empty() {
            return Err(Error::AttenuationViolation {
                reason:
                    "capability caveats are not enforced by admission and are rejected fail-closed"
                        .to_string(),
            });
        }
        let needs_attenuation_proof = self.requires_chain_binding();
        if needs_attenuation_proof && self.attenuation_proof.is_none() {
            return Err(Error::AttenuationViolation {
                reason: "attenuated capability token must carry attenuation_proof".to_string(),
            });
        }
        if let Some(share) = self.budget_share_bps {
            validate_budget_share_bps(share)?;
        }
        if let Some(proof) = self.attenuation_proof.as_ref() {
            let child_hash = scope_hash(&self.scope)?;
            if proof.child_scope_hash != child_hash {
                return Err(Error::AttenuationViolation {
                    reason: "attenuation_proof child_scope_hash does not match token scope"
                        .to_string(),
                });
            }
            verify_attenuation_witness(
                &proof.parent_scope_hash,
                &proof.child_scope_hash,
                &proof.normalized_subset_proof,
            )?;
        }
        Ok(())
    }

    /// Delegation chain-binding check.
    ///
    /// Closes the P0 soundness bug where `attenuation_proof.parent_scope_hash`
    /// was unbound from the issuer's actual upstream parent capability. An
    /// issuer with true authority `scope_X` can no longer mint a token
    /// claiming `parent_scope = scope_BIGGER` and have the verifier accept
    /// it: this check requires `parent_scope_hash` to equal either
    ///
    /// - `trust_root_scope_hash` (when the chain is empty: a direct issue
    ///   from the trust-root authority binds the witness to the
    ///   verifier-known authority hash); or
    /// - `delegation_chain.last().scope_hash` (when delegation has
    ///   occurred: the witness must bind to the immediate predecessor's
    ///   authorized scope, which is itself signed by the predecessor's
    ///   key as part of the chain).
    ///
    /// Combined with [`validate_delegation_chain_with_trust_root`], this
    /// closes the chain-binding gap: there is no longer a way to inflate
    /// `parent_scope` and supply a "looks plausible but is unsound"
    /// witness that the verifier accepts.
    ///
    /// Direct non-attenuated tokens omit `attenuation_proof`, so this check
    /// is a no-op for those tokens.
    pub fn validate_chain_binding(&self, trust_root_scope_hash: &ScopeHash) -> Result<()> {
        let Some(proof) = self.attenuation_proof.as_ref() else {
            if self.requires_chain_binding() {
                return Err(Error::AttenuationViolation {
                    reason: "chain-binding violation: attenuated capability token must carry attenuation_proof".to_string(),
                });
            }
            return Ok(());
        };

        if self.delegation_chain.is_empty() {
            if &proof.parent_scope_hash != trust_root_scope_hash {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "chain-binding violation: attenuation_proof.parent_scope_hash {} does not match trust-root scope hash {} for direct-issue token",
                        proof.parent_scope_hash, trust_root_scope_hash
                    ),
                });
            }
        } else {
            // Delegated token: bind parent_scope_hash to the predecessor's
            // signed scope_hash.
            let last = self
                .delegation_chain
                .last()
                .ok_or_else(|| Error::AttenuationViolation {
                    reason: "delegation chain unexpectedly empty after non-empty check".to_string(),
                })?;
            let Some(last_hash) = last.scope_hash.as_ref() else {
                return Err(Error::AttenuationViolation {
                    reason:
                        "chain-binding violation: last delegation link omits scope_hash; every hop must bind its authorized scope"
                            .to_string(),
                });
            };
            if &proof.parent_scope_hash != last_hash {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "chain-binding violation: attenuation_proof.parent_scope_hash {} does not match last delegation link scope_hash {}",
                        proof.parent_scope_hash, last_hash
                    ),
                });
            }
        }
        Ok(())
    }

    /// Whether the token's shape requires the chain-binding rule to fire.
    ///
    /// Chain binding closes the P0 soundness gap where an issuer could mint
    /// an attenuated token claiming `parent_scope = scope_BIGGER` and
    /// supply an internally consistent witness. The rule binds
    /// `attenuation_proof.parent_scope_hash` to either the trust-root scope
    /// hash (direct issue) or `delegation_chain.last().scope_hash` (delegated
    /// chain). The rule is therefore meaningful only when the token actually
    /// introduces narrowing relative to its parent: an explicit
    /// `attenuation_proof`, non-empty `scope_attenuations`, or a
    /// `budget_share_bps` value that narrows the parent budget.
    ///
    /// A non-empty `delegation_chain` by itself is NOT a trigger: each
    /// `DelegationLink` carries its own signature (`DelegationLink.signature`),
    /// the leaf token is signed by its issuer, and signature/connectivity
    /// invariants over the chain are enforced by
    /// [`validate_delegation_chain`]. A plain pass-through delegation that
    /// introduces no new attenuation has nothing to bind against the parent
    /// scope, so requiring `attenuation_proof` would render every plain
    /// delegated token unverifiable while adding no soundness.
    #[must_use]
    pub fn requires_chain_binding(&self) -> bool {
        self.attenuation_proof.is_some()
            || self
                .scope_attenuations
                .as_ref()
                .is_some_and(|items| !items.is_empty())
            || self.budget_share_bps.is_some()
    }

    pub fn validate_chain_binding_with_features(
        &self,
        trust_root_scope_hash: &ScopeHash,
        negotiated: &CapabilityNegotiation,
    ) -> Result<()> {
        let enabled = negotiated
            .features
            .get(features::DELEGATION_CHAIN_BINDING)
            .copied()
            .unwrap_or(true);
        if !enabled && self.requires_chain_binding() {
            return Err(Error::AttenuationViolation {
                reason: "delegation_chain_binding is disabled; attenuated tokens are rejected"
                    .to_string(),
            });
        }
        self.validate_chain_binding(trust_root_scope_hash)
    }

    /// Sign a capability token body with the given Ed25519 keypair.
    ///
    /// This is the bare Ed25519 signing entry point: the `algorithm` envelope
    /// field is omitted from the serialized output, so the artifact is
    /// byte-identical to one signed through the `SigningBackend` path with the
    /// default Ed25519 algorithm.
    pub fn sign(body: CapabilityTokenBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(&body.issuer, keypair, "capability token", "issuer")?;
        let signing_body = CapabilityTokenSigningBody {
            schema: CHIO_CAPABILITY_SCHEMA.to_string(),
            body: body.clone(),
            caveats: Vec::new(),
            scope_attenuations: None,
            attenuation_proof: None,
            budget_share_bps: None,
        };
        let (signature, _bytes) = keypair.sign_canonical(&signing_body)?;
        Ok(Self {
            schema: CHIO_CAPABILITY_SCHEMA.to_string(),
            id: body.id,
            issuer: body.issuer,
            subject: body.subject,
            scope: body.scope,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            delegation_chain: body.delegation_chain,
            algorithm: None,
            caveats: Vec::new(),
            scope_attenuations: None,
            attenuation_proof: None,
            budget_share_bps: None,
            signature,
        })
    }

    /// Sign an attenuated capability token with caveats and an attenuation proof.
    pub fn sign_attenuated(
        body: CapabilityTokenAttenuationBody,
        keypair: &Keypair,
    ) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.body.issuer,
            keypair,
            "capability token",
            "issuer",
        )?;
        if !body.caveats.is_empty() {
            return Err(Error::AttenuationViolation {
                reason:
                    "capability caveats are not enforced by admission and are rejected fail-closed"
                        .to_string(),
            });
        }
        let child_hash = scope_hash(&body.body.scope)?;
        if body.attenuation_proof.child_scope_hash != child_hash {
            return Err(Error::AttenuationViolation {
                reason: "attenuation_proof child_scope_hash does not match token scope".to_string(),
            });
        }
        validate_attenuation_proof(
            &body.attenuation_proof.parent_scope_hash,
            &body.attenuation_proof.child_scope_hash,
            &body.attenuation_proof.normalized_subset_proof,
        )?;
        if let Some(share) = body.budget_share_bps {
            validate_budget_share_bps(share)?;
        }
        let signing_body = CapabilityTokenSigningBody {
            schema: CHIO_CAPABILITY_SCHEMA.to_string(),
            body: body.body.clone(),
            caveats: body.caveats.clone(),
            scope_attenuations: Some(body.scope_attenuations.clone()),
            attenuation_proof: Some(body.attenuation_proof.clone()),
            budget_share_bps: body.budget_share_bps,
        };
        let (signature, _bytes) = keypair.sign_canonical(&signing_body)?;
        Ok(Self {
            schema: CHIO_CAPABILITY_SCHEMA.to_string(),
            id: body.body.id,
            issuer: body.body.issuer,
            subject: body.body.subject,
            scope: body.body.scope,
            issued_at: body.body.issued_at,
            expires_at: body.body.expires_at,
            delegation_chain: body.body.delegation_chain,
            algorithm: None,
            caveats: body.caveats,
            scope_attenuations: Some(body.scope_attenuations),
            attenuation_proof: Some(body.attenuation_proof),
            budget_share_bps: body.budget_share_bps,
            signature,
        })
    }

    /// Sign a capability token body with an arbitrary [`SigningBackend`].
    ///
    /// Use this entry point to produce FIPS-algorithm (P-256 / P-384) tokens
    /// when operating under the `fips` feature. The `body.issuer` field must
    /// equal `backend.public_key()`; otherwise verification will fail.
    ///
    /// The resulting token's `algorithm` envelope field is populated with the
    /// backend's algorithm. It is informational only -- verification
    /// dispatches off the `signature` hex prefix, not this field.
    pub fn sign_with_backend(
        body: CapabilityTokenBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        ensure_backend_matches_embedded_key(&body.issuer, backend, "capability token", "issuer")?;
        let signing_body = CapabilityTokenSigningBody {
            schema: CHIO_CAPABILITY_SCHEMA.to_string(),
            body: body.clone(),
            caveats: Vec::new(),
            scope_attenuations: None,
            attenuation_proof: None,
            budget_share_bps: None,
        };
        let (signature, _bytes) = sign_canonical_with_backend(backend, &signing_body)?;
        Ok(Self {
            schema: CHIO_CAPABILITY_SCHEMA.to_string(),
            id: body.id,
            issuer: body.issuer,
            subject: body.subject,
            scope: body.scope,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            delegation_chain: body.delegation_chain,
            algorithm: Some(backend.algorithm()),
            caveats: Vec::new(),
            scope_attenuations: None,
            attenuation_proof: None,
            budget_share_bps: None,
            signature,
        })
    }

    /// Verify the token's signature against its issuer key.
    ///
    /// Dispatches off the algorithm carried by `signature` and `issuer`.
    /// For FIPS algorithms, the `fips` feature must be enabled at the crate
    /// level or verification returns `Ok(false)`.
    pub fn verify_signature(&self) -> Result<bool> {
        self.validate_schema()?;
        let signing_body = self.signing_body();
        if self
            .issuer
            .verify_canonical(&signing_body, &self.signature)?
        {
            return Ok(true);
        }
        if self.permits_plain_body_signature() {
            let legacy_body = self.body();
            return self.issuer.verify_canonical(&legacy_body, &self.signature);
        }
        Ok(false)
    }

    /// Verify the token's signature and enforce the kernel-side
    /// `crypto_floor` posture in one pass.
    ///
    /// Verification dispatches off `Signature::algorithm()`:
    ///
    /// - [`SigningAlgorithm::Hybrid`] tokens are accepted under
    ///   [`CapabilityCryptoFloor::AllowHybrid`] and
    ///   [`CapabilityCryptoFloor::PqRequired`] and rejected under
    ///   [`CapabilityCryptoFloor::AllowClassical`].
    /// - Classical tokens (Ed25519 / P-256 / P-384) are accepted under
    ///   [`CapabilityCryptoFloor::AllowClassical`] and
    ///   [`CapabilityCryptoFloor::AllowHybrid`] and rejected under
    ///   [`CapabilityCryptoFloor::PqRequired`].
    ///
    /// The floor check fires BEFORE the cryptographic verification step
    /// so a forged classical signature on a hybrid-only deployment cannot
    /// burn CPU cycles on a doomed verify call (and so the rejection
    /// path is explicit in the audit trail).
    ///
    /// `algorithm` envelope-field consistency is also checked here: when
    /// the optional `CapabilityToken::algorithm` field is present, it MUST
    /// agree with `Signature::algorithm()`. A mismatch is a downgrade
    /// signal and is rejected fail-closed.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`CapabilityFloorVerifyError::RejectedByCryptoFloor`] when the
    /// signature algorithm violates the floor.
    /// [`CapabilityFloorVerifyError::AlgorithmMismatch`] when the envelope
    /// field disagrees with the signature material.
    /// [`CapabilityFloorVerifyError::Crypto`] when canonical
    /// re-serialization fails.
    pub fn verify_signature_with_floor(
        &self,
        floor: CapabilityCryptoFloor,
    ) -> core::result::Result<bool, CapabilityFloorVerifyError> {
        let signature_algorithm = self.signature.algorithm();

        // Step 1: envelope vs. signature consistency. If the envelope
        // declares an algorithm, it MUST match the signature's
        // self-describing prefix. Treat a mismatch as a downgrade
        // signal: an attacker who flips the envelope bit but cannot
        // reforge the signature should not be able to coerce a
        // different verification path.
        if let Some(declared) = self.algorithm {
            if declared != signature_algorithm {
                return Err(CapabilityFloorVerifyError::AlgorithmMismatch {
                    declared,
                    actual: signature_algorithm,
                });
            }
        }

        // Step 2: floor enforcement. Reject any combination that the
        // configured floor disallows BEFORE doing the cryptographic
        // check. Threat model row `pq_signature_downgrade` is the
        // surface this guards.
        let is_hybrid = matches!(signature_algorithm, SigningAlgorithm::Hybrid);
        let allowed = if is_hybrid {
            floor.allows_hybrid()
        } else {
            floor.allows_classical_only()
        };
        if !allowed {
            return Err(CapabilityFloorVerifyError::RejectedByCryptoFloor {
                floor,
                signature_algorithm,
            });
        }

        // Step 3: schema and cryptographic verification.
        self.validate_schema()
            .map_err(CapabilityFloorVerifyError::Crypto)?;
        let signing_body = self.signing_body();
        if self
            .issuer
            .verify_canonical(&signing_body, &self.signature)
            .map_err(CapabilityFloorVerifyError::Crypto)?
        {
            return Ok(true);
        }
        if self.permits_plain_body_signature() {
            let legacy_body = self.body();
            return self
                .issuer
                .verify_canonical(&legacy_body, &self.signature)
                .map_err(CapabilityFloorVerifyError::Crypto);
        }
        Ok(false)
    }

    /// Verify the signature AND enforce the validity window in one pass.
    ///
    /// This is the sanctioned entry point when a verifier also needs
    /// freshness: it fails closed on expiry / not-yet-valid tokens, which
    /// the bare [`CapabilityToken::verify_signature`] does not check. A clock
    /// is threaded explicitly via `now` (unix seconds) so there is no hidden
    /// wall-clock read in this pure check.
    ///
    /// Ordering is deliberate and fail-closed: the cryptographic signature is
    /// checked FIRST. A token with an invalid (or forged) signature is
    /// rejected before the time window is consulted, so an attacker cannot use
    /// the error variant to distinguish "expired" from "never validly signed".
    ///
    /// Returns `Ok(true)` only when the signature verifies and `now` is within
    /// `[issued_at, expires_at)`. Returns `Ok(false)` when the signature does
    /// not verify. Returns [`Error::CapabilityNotYetValid`] /
    /// [`Error::CapabilityExpired`] when the signature is valid but the token
    /// is outside its validity window.
    pub fn verify_signature_at(&self, now: u64) -> Result<bool> {
        if !self.verify_signature()? {
            return Ok(false);
        }
        self.validate_time(now)?;
        Ok(true)
    }

    /// Verify the signature, enforce the `crypto_floor` posture, AND enforce
    /// the validity window in one pass.
    ///
    /// Equivalent to [`CapabilityToken::verify_signature_with_floor`] followed
    /// by [`CapabilityToken::validate_time`], with the same fail-closed
    /// ordering: floor + signature are checked before the time window, so a
    /// floor violation or invalid signature is reported ahead of expiry. A
    /// clock is threaded explicitly via `now` (unix seconds).
    ///
    /// # Errors
    ///
    /// Propagates every error of
    /// [`CapabilityToken::verify_signature_with_floor`]. When the signature
    /// and floor pass but the token is outside its validity window, the time
    /// error is surfaced as [`CapabilityFloorVerifyError::Crypto`] wrapping
    /// [`Error::CapabilityNotYetValid`] / [`Error::CapabilityExpired`].
    pub fn verify_signature_with_floor_at(
        &self,
        floor: CapabilityCryptoFloor,
        now: u64,
    ) -> core::result::Result<bool, CapabilityFloorVerifyError> {
        if !self.verify_signature_with_floor(floor)? {
            return Ok(false);
        }
        self.validate_time(now)
            .map_err(CapabilityFloorVerifyError::Crypto)?;
        Ok(true)
    }

    /// Check whether this token is expired at the given unix timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Check whether this token is valid at the given unix timestamp
    /// (issued_at <= now < expires_at).
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Validate time bounds, returning an error on failure.
    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}
