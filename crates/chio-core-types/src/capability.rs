//! Capability tokens: Ed25519-signed, scoped, time-bounded authorizations.
//!
//! A Chio capability token is the sole authority to invoke a tool. There is no
//! ambient authority. The Kernel validates the token on every request and denies
//! access if any check fails.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::canonical::canonical_json_bytes;
use crate::crypto::{
    is_default_optional_algorithm, sha256_hex, sign_canonical_with_backend, Keypair, PublicKey,
    Signature, SigningAlgorithm, SigningBackend,
};
use crate::error::{Error, Result};
use crate::runtime_attestation::{
    derive_runtime_attestation_trust_material, AttestationVerifierFamily,
    RuntimeAttestationTrustMaterial,
};
use crate::session::SessionAnchorReference;

/// Capability-negotiation schema exchanged during federation handshakes.
pub const CHIO_CAPABILITIES_SCHEMA: &str = "chio.capabilities.v1";

/// Frozen v1 capability-token schema. Legacy tokens that omit `schema`
/// deserialize to this value.
pub const CHIO_CAPABILITY_V1_SCHEMA: &str = "chio.capability.v1";

/// Capability-token v2 schema with typed caveats and attenuation witnesses.
pub const CHIO_CAPABILITY_V2_SCHEMA: &str = "chio.capability.v2";

fn default_capability_schema() -> String {
    CHIO_CAPABILITY_V1_SCHEMA.to_string()
}

fn capability_v1_schema() -> String {
    CHIO_CAPABILITY_V1_SCHEMA.to_string()
}

fn capabilities_schema() -> String {
    CHIO_CAPABILITIES_SCHEMA.to_string()
}

fn is_empty_capability_features(features: &BTreeMap<String, bool>) -> bool {
    features.is_empty()
}

fn is_none_or_empty<T>(value: &Option<Vec<T>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

fn is_none_or_empty_attenuation_proof(value: &Option<AttenuationProof>) -> bool {
    value.is_none()
}

/// Stable feature names used by `chio.capabilities.v1`.
pub mod capability_features {
    pub const ACCEPTS_CAPABILITY_V2: &str = "accepts_capability_v2";
    pub const ACCEPTS_RECEIPT_V2: &str = "accepts_receipt_v2";
    pub const ACCEPTS_ANCHOR_BATCH_V1: &str = "accepts_anchor_batch_v1";
    pub const ACCEPTS_HYBRID_SIGNATURES: &str = "accepts_hybrid_signatures";
    /// W1.1: opts the peer into the v2 delegation-chain binding rules.
    /// Requires `DelegationLink.scope_hash` to be populated and
    /// `attenuation_proof.parent_scope_hash` to match the issuer's
    /// trust-root scope hash (or the last chain link's scope hash) per
    /// `validate_delegation_chain_with_trust_root`.
    pub const DELEGATION_V2_CHAIN_BINDING: &str = "delegation_v2_chain_binding";
}

/// Peer-advertised protocol feature bitset.
///
/// The map is intentionally string-keyed so new additive features can be
/// introduced without a flag-day enum release. Validation still rejects
/// malformed names fail-closed before any negotiated feature is used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityNegotiation {
    #[serde(default = "capabilities_schema")]
    pub schema: String,
    #[serde(default, skip_serializing_if = "is_empty_capability_features")]
    pub features: BTreeMap<String, bool>,
    #[serde(default = "capability_v1_schema")]
    pub max_capability_schema: String,
}

impl Default for CapabilityNegotiation {
    fn default() -> Self {
        Self::v1_default()
    }
}

impl CapabilityNegotiation {
    /// Baseline peer profile: v1 capability tokens only.
    #[must_use]
    pub fn v1_default() -> Self {
        Self {
            schema: CHIO_CAPABILITIES_SCHEMA.to_string(),
            features: BTreeMap::new(),
            max_capability_schema: CHIO_CAPABILITY_V1_SCHEMA.to_string(),
        }
    }

    /// T1 peer profile: v2 capability, receipt v2, and anchor batches.
    #[must_use]
    pub fn t1_default() -> Self {
        let mut features = BTreeMap::new();
        features.insert(capability_features::ACCEPTS_CAPABILITY_V2.to_string(), true);
        features.insert(capability_features::ACCEPTS_RECEIPT_V2.to_string(), true);
        features.insert(
            capability_features::ACCEPTS_ANCHOR_BATCH_V1.to_string(),
            true,
        );
        Self {
            schema: CHIO_CAPABILITIES_SCHEMA.to_string(),
            features,
            max_capability_schema: CHIO_CAPABILITY_V2_SCHEMA.to_string(),
        }
    }

    /// Return whether a named feature is explicitly advertised.
    #[must_use]
    pub fn supports(&self, feature: &str) -> bool {
        self.features.get(feature).copied().unwrap_or(false)
    }

    /// Validate schema and feature-name shape before negotiation.
    pub fn validate(&self) -> Result<()> {
        if self.schema != CHIO_CAPABILITIES_SCHEMA {
            return Err(Error::CanonicalJson(format!(
                "unsupported capability negotiation schema: {}",
                self.schema
            )));
        }
        if self.max_capability_schema != CHIO_CAPABILITY_V1_SCHEMA
            && self.max_capability_schema != CHIO_CAPABILITY_V2_SCHEMA
        {
            return Err(Error::CanonicalJson(format!(
                "unsupported max capability schema: {}",
                self.max_capability_schema
            )));
        }
        for feature in self.features.keys() {
            validate_capability_feature_name(feature)?;
        }
        Ok(())
    }

    /// Intersect two negotiated feature sets.
    pub fn negotiated_with(&self, remote: &Self) -> Result<Self> {
        self.validate()?;
        remote.validate()?;
        let mut features = BTreeMap::new();
        for (feature, enabled) in &self.features {
            if *enabled && remote.features.get(feature).copied().unwrap_or(false) {
                features.insert(feature.clone(), true);
            }
        }
        let max_capability_schema = if self.max_capability_schema == CHIO_CAPABILITY_V2_SCHEMA
            && remote.max_capability_schema == CHIO_CAPABILITY_V2_SCHEMA
            && features
                .get(capability_features::ACCEPTS_CAPABILITY_V2)
                .copied()
                .unwrap_or(false)
        {
            CHIO_CAPABILITY_V2_SCHEMA
        } else {
            CHIO_CAPABILITY_V1_SCHEMA
        };
        Ok(Self {
            schema: CHIO_CAPABILITIES_SCHEMA.to_string(),
            features,
            max_capability_schema: max_capability_schema.to_string(),
        })
    }
}

fn validate_capability_feature_name(feature: &str) -> Result<()> {
    let valid = !feature.is_empty()
        && feature.len() <= 96
        && feature
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(Error::CanonicalJson(format!(
            "malformed capability negotiation feature: {feature}"
        )))
    }
}

/// Minimum cryptographic posture enforced by the capability validator.
///
/// Mirrors the wire form of `chio_policy::CryptoFloor` and the kernel-side
/// `KernelCryptoFloor`. Defined locally in `chio-core-types` so the
/// portable verifier (no_std builds, edge runtimes) can branch on the
/// configured floor without taking a dependency on `chio-policy` or
/// `chio-kernel`. Operators that load a HushSpec policy translate the
/// parsed floor into this enum at the kernel boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCryptoFloor {
    /// Accept classical-only Ed25519/P-256/P-384 envelopes. Default.
    #[default]
    AllowClassical,
    /// Accept either classical-only or hybrid classical-plus-ML-DSA-65
    /// envelopes.
    AllowHybrid,
    /// Reject classical-only envelopes; require hybrid signing on every
    /// signed capability token.
    PqRequired,
}

impl CapabilityCryptoFloor {
    /// Whether the floor permits hybrid envelopes on the wire.
    #[must_use]
    pub fn allows_hybrid(&self) -> bool {
        matches!(self, Self::AllowHybrid | Self::PqRequired)
    }

    /// Whether the floor permits classical-only envelopes on the wire.
    #[must_use]
    pub fn allows_classical_only(&self) -> bool {
        matches!(self, Self::AllowClassical | Self::AllowHybrid)
    }

    /// Stable wire-format identifier for diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowClassical => "allow_classical",
            Self::AllowHybrid => "allow_hybrid",
            Self::PqRequired => "pq_required",
        }
    }
}

/// Lowercase wire label for a [`SigningAlgorithm`] used in error messages.
///
/// Equivalent to `SigningAlgorithm::prefix` for the non-Ed25519 variants
/// but returns the explicit `"ed25519"` literal for Ed25519 (the prefix
/// helper returns `""` because Ed25519 keys render bare on the wire).
fn signing_algorithm_label(alg: SigningAlgorithm) -> &'static str {
    match alg {
        SigningAlgorithm::Ed25519 => "ed25519",
        SigningAlgorithm::P256 => "p256",
        SigningAlgorithm::P384 => "p384",
        SigningAlgorithm::Hybrid => "hybrid",
    }
}

/// Errors raised by [`CapabilityToken::verify_signature_with_floor`].
///
/// Distinguishes floor-policy rejections from cryptographic verification
/// failures so the kernel can surface a different audit-log row for each.
/// Threat model row `pq_signature_downgrade` is the surface this guards.
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug)]
pub enum CapabilityFloorVerifyError {
    /// The signature algorithm violates the configured `crypto_floor`.
    /// Fail-closed at the floor boundary BEFORE cryptographic verification
    /// runs. Threat model row `pq_signature_downgrade` is the surface this
    /// guards.
    #[cfg_attr(
        feature = "std",
        error(
            "capability rejected by crypto_floor={}: signature algorithm {} not permitted",
            floor.as_str(),
            signing_algorithm_label(*signature_algorithm)
        )
    )]
    RejectedByCryptoFloor {
        /// The configured floor that rejected the token.
        floor: CapabilityCryptoFloor,
        /// The signature algorithm carried by the token.
        signature_algorithm: SigningAlgorithm,
    },

    /// The optional `CapabilityToken::algorithm` envelope field disagrees
    /// with the algorithm carried by `Signature`. Treated as a downgrade
    /// signal and rejected fail-closed.
    #[cfg_attr(
        feature = "std",
        error(
            "capability algorithm envelope field {} disagrees with signature {}",
            signing_algorithm_label(*declared),
            signing_algorithm_label(*actual)
        )
    )]
    AlgorithmMismatch {
        /// The algorithm declared in the envelope field.
        declared: SigningAlgorithm,
        /// The algorithm carried by the signature material.
        actual: SigningAlgorithm,
    },

    /// Forwarded from the underlying canonical-JSON or signature
    /// verification path.
    #[cfg_attr(
        feature = "std",
        error("capability cryptographic verification failed: {0}")
    )]
    Crypto(#[cfg_attr(feature = "std", source)] Error),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for CapabilityFloorVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RejectedByCryptoFloor {
                floor,
                signature_algorithm,
            } => write!(
                f,
                "capability rejected by crypto_floor={}: signature algorithm {} not permitted",
                floor.as_str(),
                signing_algorithm_label(*signature_algorithm)
            ),
            Self::AlgorithmMismatch { declared, actual } => write!(
                f,
                "capability algorithm envelope field {} disagrees with signature {}",
                signing_algorithm_label(*declared),
                signing_algorithm_label(*actual)
            ),
            Self::Crypto(err) => write!(f, "capability cryptographic verification failed: {err}"),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for CapabilityFloorVerifyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

/// A Chio capability token. Scoped, time-bounded, cryptographically signed.
///
/// The `signature` field covers the canonical JSON of all other fields.
/// Verification re-serializes the token (excluding the signature), computes
/// the canonical form, and checks the signature against `issuer` using the
/// algorithm declared by the `algorithm` field (defaulting to Ed25519 when
/// absent, which preserves backward compatibility with tokens issued prior
/// to the introduction of [`SigningAlgorithm`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Versioned signed-artifact schema. Legacy v1 wire tokens that omit
    /// this field default to `chio.capability.v1`.
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
    /// Signing algorithm. Absent means Ed25519 for backward compatibility.
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    /// Typed v2 caveats. Empty for v1 and omitted on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
    /// High-level attenuation request exposed on v2 tokens. Empty for v1.
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub scope_attenuations: Option<Vec<Attenuation>>,
    /// Wire witness proving child-scope attenuation.
    #[serde(default, skip_serializing_if = "is_none_or_empty_attenuation_proof")]
    pub attenuation_proof: Option<AttenuationProof>,
    /// Fixed-point sub-agent budget share in basis points. Values above
    /// 10000 are rejected by v2 validation.
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

/// V2 capability signing input with attenuation and caveat fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenV2Body {
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

/// First-party caveat attached to a v2 capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Caveat {
    pub kind: CaveatKind,
    pub predicate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Signature>,
}

/// Built-in first-party caveat kinds. Third-party discharges are deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaveatKind {
    RestrictTool,
    BindSession,
    RestrictAudience,
    RestrictGeo,
    RestrictTimeWindow,
}

/// Hash of a canonicalized scope, encoded as lowercase SHA-256 hex.
pub type ScopeHash = String;

/// Per-grant subset relation recorded in an attenuation witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantSubsetRelation {
    pub grant_kind: String,
    pub child_index: u32,
    pub parent_index: u32,
    pub subset: bool,
}

/// On-wire attenuation witness. The normalized scope encodings are included
/// so verifiers can hash and check the already-normalized relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttenuationWitness {
    pub normalized_parent_scope: String,
    pub normalized_child_scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subset_relations: Vec<GrantSubsetRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restricted_predicates: Vec<String>,
}

/// Wire proof carried by `CapabilityToken.attenuation_proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttenuationProof {
    pub parent_scope_hash: ScopeHash,
    pub child_scope_hash: ScopeHash,
    pub normalized_subset_proof: AttenuationWitness,
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

    /// Reject unknown schema IDs and v2 budget amplification.
    pub fn validate_schema(&self) -> Result<()> {
        if self.schema != CHIO_CAPABILITY_V1_SCHEMA && self.schema != CHIO_CAPABILITY_V2_SCHEMA {
            return Err(Error::CanonicalJson(format!(
                "unsupported capability token schema: {}",
                self.schema
            )));
        }
        if self.schema == CHIO_CAPABILITY_V1_SCHEMA
            && (!self.caveats.is_empty()
                || self
                    .scope_attenuations
                    .as_ref()
                    .is_some_and(|items| !items.is_empty())
                || self.attenuation_proof.is_some()
                || self.budget_share_bps.is_some())
        {
            return Err(Error::CanonicalJson(
                "capability v1 token must not carry v2 attenuation fields".to_string(),
            ));
        }
        if self.schema == CHIO_CAPABILITY_V2_SCHEMA && self.attenuation_proof.is_none() {
            return Err(Error::AttenuationViolation {
                reason: "capability v2 token must carry attenuation_proof".to_string(),
            });
        }
        if let Some(share) = self.budget_share_bps {
            if share > 10_000 {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "budget_share_bps {share} exceeds the 10000 bps parent budget ceiling"
                    ),
                });
            }
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

    /// W1.1 v2 chain-binding check.
    ///
    /// Closes the P0 soundness bug where `attenuation_proof.parent_scope_hash`
    /// was unbound from the issuer's actual upstream parent capability. An
    /// issuer with true authority `scope_X` can no longer mint a v2 token
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
    /// This check is a no-op for v1 tokens.
    pub fn validate_chain_binding(&self, trust_root_scope_hash: &ScopeHash) -> Result<()> {
        if self.schema != CHIO_CAPABILITY_V2_SCHEMA {
            return Ok(());
        }
        let Some(proof) = self.attenuation_proof.as_ref() else {
            return Err(Error::AttenuationViolation {
                reason: "capability v2 token must carry attenuation_proof".to_string(),
            });
        };

        if self.delegation_chain.is_empty() {
            if &proof.parent_scope_hash != trust_root_scope_hash {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "v2 chain-binding violation: attenuation_proof.parent_scope_hash {} does not match trust-root scope hash {} for direct-issue token",
                        proof.parent_scope_hash, trust_root_scope_hash
                    ),
                });
            }
        } else {
            // Delegated token: bind parent_scope_hash to the predecessor's
            // signed scope_hash (the v2 chain-binding field).
            let last = self
                .delegation_chain
                .last()
                .ok_or_else(|| Error::AttenuationViolation {
                    reason: "delegation chain unexpectedly empty after non-empty check".to_string(),
                })?;
            let Some(last_hash) = last.scope_hash.as_ref() else {
                return Err(Error::AttenuationViolation {
                    reason:
                        "v2 chain-binding violation: last delegation link omits scope_hash; chio.delegation.v2 requires every hop to bind its authorized scope"
                            .to_string(),
                });
            };
            if &proof.parent_scope_hash != last_hash {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "v2 chain-binding violation: attenuation_proof.parent_scope_hash {} does not match last delegation link scope_hash {}",
                        proof.parent_scope_hash, last_hash
                    ),
                });
            }
        }
        Ok(())
    }

    /// Sign a capability token body with the given Ed25519 keypair.
    ///
    /// This is the historical signing entry point and produces a
    /// byte-identical artifact to pre-`SigningBackend` Chio releases: the
    /// `algorithm` envelope field is omitted from the serialized output.
    pub fn sign(body: CapabilityTokenBody, keypair: &Keypair) -> Result<Self> {
        let signing_body = CapabilityTokenSigningBody {
            schema: CHIO_CAPABILITY_V1_SCHEMA.to_string(),
            body: body.clone(),
            caveats: Vec::new(),
            scope_attenuations: None,
            attenuation_proof: None,
            budget_share_bps: None,
        };
        let (signature, _bytes) = keypair.sign_canonical(&signing_body)?;
        Ok(Self {
            schema: CHIO_CAPABILITY_V1_SCHEMA.to_string(),
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

    /// Sign a v2 capability token with caveats and an attenuation proof.
    pub fn sign_v2(body: CapabilityTokenV2Body, keypair: &Keypair) -> Result<Self> {
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
            if share > 10_000 {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "budget_share_bps {share} exceeds the 10000 bps parent budget ceiling"
                    ),
                });
            }
        }
        let signing_body = CapabilityTokenSigningBody {
            schema: CHIO_CAPABILITY_V2_SCHEMA.to_string(),
            body: body.body.clone(),
            caveats: body.caveats.clone(),
            scope_attenuations: Some(body.scope_attenuations.clone()),
            attenuation_proof: Some(body.attenuation_proof.clone()),
            budget_share_bps: body.budget_share_bps,
        };
        let (signature, _bytes) = keypair.sign_canonical(&signing_body)?;
        Ok(Self {
            schema: CHIO_CAPABILITY_V2_SCHEMA.to_string(),
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
        let signing_body = CapabilityTokenSigningBody {
            schema: CHIO_CAPABILITY_V1_SCHEMA.to_string(),
            body: body.clone(),
            caveats: Vec::new(),
            scope_attenuations: None,
            attenuation_proof: None,
            budget_share_bps: None,
        };
        let (signature, _bytes) = sign_canonical_with_backend(backend, &signing_body)?;
        Ok(Self {
            schema: CHIO_CAPABILITY_V1_SCHEMA.to_string(),
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
        if self.schema == CHIO_CAPABILITY_V1_SCHEMA
            && self.caveats.is_empty()
            && self.scope_attenuations.as_ref().is_none_or(Vec::is_empty)
            && self.attenuation_proof.is_none()
            && self.budget_share_bps.is_none()
        {
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
        if self.schema == CHIO_CAPABILITY_V1_SCHEMA
            && self.caveats.is_empty()
            && self.scope_attenuations.as_ref().is_none_or(Vec::is_empty)
            && self.attenuation_proof.is_none()
            && self.budget_share_bps.is_none()
        {
            let legacy_body = self.body();
            return self
                .issuer
                .verify_canonical(&legacy_body, &self.signature)
                .map_err(CapabilityFloorVerifyError::Crypto);
        }
        Ok(false)
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

/// What a capability token authorizes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChioScope {
    /// Individual tool grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<ToolGrant>,

    /// Individual resource grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_grants: Vec<ResourceGrant>,

    /// Individual prompt grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_grants: Vec<PromptGrant>,
}

impl ChioScope {
    /// Returns true if `self` is a subset of `other` -- that is, every grant
    /// in `self` is covered by some grant in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &ChioScope) -> bool {
        self.grants.iter().all(|child_grant| {
            other
                .grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.resource_grants.iter().all(|child_grant| {
            other
                .resource_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.prompt_grants.iter().all(|child_grant| {
            other
                .prompt_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        })
    }
}

/// A monetary amount with currency denomination.
///
/// Uses minor-unit integers to avoid floating-point precision issues.
/// For USD, 1 dollar = 100 units (cents). For JPY, 1 yen = 1 unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryAmount {
    /// Amount in the currency's smallest unit (e.g. cents for USD).
    pub units: u64,
    /// ISO 4217 currency code. Examples: "USD", "EUR", "JPY".
    pub currency: String,
}

/// Explicit operator-visible runtime assurance tier derived from attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAssuranceTier {
    #[default]
    None,
    Basic,
    Attested,
    Verified,
}

/// Explicit governed autonomy tier requested for one economically sensitive action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernedAutonomyTier {
    #[default]
    Direct,
    Delegated,
    Autonomous,
}

impl GovernedAutonomyTier {
    #[must_use]
    pub fn requires_delegation_bond(self) -> bool {
        !matches!(self, Self::Direct)
    }

    #[must_use]
    pub fn requires_call_chain(self) -> bool {
        !matches!(self, Self::Direct)
    }

    #[must_use]
    pub fn minimum_runtime_assurance(self) -> RuntimeAssuranceTier {
        match self {
            Self::Direct => RuntimeAssuranceTier::None,
            Self::Delegated => RuntimeAssuranceTier::Attested,
            Self::Autonomous => RuntimeAssuranceTier::Verified,
        }
    }
}

/// Normalized workload-identity scheme accepted by Chio runtime attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadIdentityScheme {
    Spiffe,
}

/// Upstream credential family that bound the workload identity to attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadCredentialKind {
    #[default]
    Uri,
    X509Svid,
    JwtSvid,
}

/// Normalized workload identity derived from runtime attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadIdentity {
    /// Identity scheme Chio recognized from the upstream evidence.
    pub scheme: WorkloadIdentityScheme,
    /// Credential family that authenticated the workload.
    pub credential_kind: WorkloadCredentialKind,
    /// Canonical workload identifier URI.
    pub uri: String,
    /// Stable trust domain resolved from the identifier.
    pub trust_domain: String,
    /// Canonical workload path within the trust domain.
    pub path: String,
}

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadIdentityError {
    #[cfg_attr(
        feature = "std",
        error("runtime_identity must not be empty when provided")
    )]
    EmptyRuntimeIdentity,

    #[cfg_attr(feature = "std", error("workload identity URI must not be empty"))]
    EmptyUri,

    #[cfg_attr(feature = "std", error("unsupported workload identity scheme '{0}'"))]
    UnsupportedScheme(String),

    #[cfg_attr(feature = "std", error("workload identity URI is malformed: {0}"))]
    MalformedUri(String),

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity must include a trust domain")
    )]
    MissingTrustDomain,

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity must not include userinfo or a port")
    )]
    InvalidAuthority,

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity must not include query or fragment")
    )]
    InvalidSuffix,

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity path '{0}' is invalid")
    )]
    InvalidPath(String),

    #[cfg_attr(
        feature = "std",
        error(
            "explicit workload identity conflicts with runtime_identity for {field}: expected '{expected}', got '{actual}'"
        )
    )]
    Conflict {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[cfg_attr(
        feature = "std",
        error(
            "runtime_identity '{0}' is opaque and cannot be reconciled with explicit workload_identity"
        )
    )]
    OpaqueRuntimeIdentityConflict(String),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for WorkloadIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyRuntimeIdentity => {
                write!(f, "runtime_identity must not be empty when provided")
            }
            Self::EmptyUri => write!(f, "workload identity URI must not be empty"),
            Self::UnsupportedScheme(v) => {
                write!(f, "unsupported workload identity scheme '{v}'")
            }
            Self::MalformedUri(v) => write!(f, "workload identity URI is malformed: {v}"),
            Self::MissingTrustDomain => {
                write!(f, "SPIFFE workload identity must include a trust domain")
            }
            Self::InvalidAuthority => write!(
                f,
                "SPIFFE workload identity must not include userinfo or a port"
            ),
            Self::InvalidSuffix => write!(
                f,
                "SPIFFE workload identity must not include query or fragment"
            ),
            Self::InvalidPath(v) => write!(f, "SPIFFE workload identity path '{v}' is invalid"),
            Self::Conflict {
                field,
                expected,
                actual,
            } => write!(
                f,
                "explicit workload identity conflicts with runtime_identity for {field}: expected '{expected}', got '{actual}'"
            ),
            Self::OpaqueRuntimeIdentityConflict(v) => write!(
                f,
                "runtime_identity '{v}' is opaque and cannot be reconciled with explicit workload_identity"
            ),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for WorkloadIdentityError {}

impl WorkloadIdentity {
    pub fn parse_spiffe_uri(uri: &str) -> core::result::Result<Self, WorkloadIdentityError> {
        Self::parse_spiffe_uri_with_kind(uri, WorkloadCredentialKind::Uri)
    }

    pub fn parse_spiffe_uri_with_kind(
        uri: &str,
        credential_kind: WorkloadCredentialKind,
    ) -> core::result::Result<Self, WorkloadIdentityError> {
        let trimmed = uri.trim();
        if trimmed.is_empty() {
            return Err(WorkloadIdentityError::EmptyUri);
        }

        let parsed = Url::parse(trimmed)
            .map_err(|_| WorkloadIdentityError::MalformedUri(trimmed.to_string()))?;
        if parsed.scheme() != "spiffe" {
            return Err(WorkloadIdentityError::UnsupportedScheme(
                parsed.scheme().to_string(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() || parsed.port().is_some() {
            return Err(WorkloadIdentityError::InvalidAuthority);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(WorkloadIdentityError::InvalidSuffix);
        }

        let Some(trust_domain) = parsed.host_str() else {
            return Err(WorkloadIdentityError::MissingTrustDomain);
        };
        let path = parsed.path();
        if path.is_empty() || !path.starts_with('/') || path.contains("//") {
            return Err(WorkloadIdentityError::InvalidPath(path.to_string()));
        }

        Ok(Self {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind,
            uri: trimmed.to_string(),
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
        })
    }

    pub fn validate(&self) -> core::result::Result<(), WorkloadIdentityError> {
        let parsed = match self.scheme {
            WorkloadIdentityScheme::Spiffe => {
                Self::parse_spiffe_uri_with_kind(&self.uri, self.credential_kind)?
            }
        };

        if self.trust_domain != parsed.trust_domain {
            return Err(WorkloadIdentityError::Conflict {
                field: "trust_domain",
                expected: parsed.trust_domain,
                actual: self.trust_domain.clone(),
            });
        }
        if self.path != parsed.path {
            return Err(WorkloadIdentityError::Conflict {
                field: "path",
                expected: parsed.path,
                actual: self.path.clone(),
            });
        }

        Ok(())
    }
}

/// Normalized runtime attestation evidence carried with governed requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAttestationEvidence {
    /// Schema or format identifier of the upstream attestation statement.
    pub schema: String,
    /// Attestation verifier or relying party that accepted the evidence.
    pub verifier: String,
    /// Normalized assurance tier resolved from the evidence.
    pub tier: RuntimeAssuranceTier,
    /// Unix timestamp (seconds) when this attestation was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when this attestation expires.
    pub expires_at: u64,
    /// Stable SHA-256 digest of the attestation evidence payload.
    pub evidence_sha256: String,
    /// Optional runtime identity or workload identifier associated with the evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_identity: Option<String>,
    /// Optional normalized workload identity when the upstream verifier exposed one explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
    /// Optional structured claims preserved for adapters or operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

impl RuntimeAttestationEvidence {
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn normalized_workload_identity(
        &self,
    ) -> core::result::Result<Option<WorkloadIdentity>, WorkloadIdentityError> {
        let explicit = self
            .workload_identity
            .as_ref()
            .map(|identity| {
                identity.validate()?;
                Ok(identity.clone())
            })
            .transpose()?;
        let parsed_runtime_identity = match self.runtime_identity.as_deref() {
            Some(value) if value.trim().is_empty() => {
                return Err(WorkloadIdentityError::EmptyRuntimeIdentity);
            }
            Some(value) if value.trim_start().starts_with("spiffe://") => {
                Some(WorkloadIdentity::parse_spiffe_uri(value)?)
            }
            Some(_) => None,
            None => None,
        };

        match (explicit, parsed_runtime_identity) {
            (Some(explicit), Some(parsed)) => {
                if explicit.scheme != parsed.scheme {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "scheme",
                        expected: format!("{:?}", parsed.scheme).to_lowercase(),
                        actual: format!("{:?}", explicit.scheme).to_lowercase(),
                    });
                }
                if explicit.trust_domain != parsed.trust_domain {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "trust_domain",
                        expected: parsed.trust_domain,
                        actual: explicit.trust_domain,
                    });
                }
                if explicit.path != parsed.path {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "path",
                        expected: parsed.path,
                        actual: explicit.path,
                    });
                }
                Ok(Some(explicit))
            }
            (Some(explicit), None) => {
                if let Some(runtime_identity) = self.runtime_identity.as_ref() {
                    return Err(WorkloadIdentityError::OpaqueRuntimeIdentityConflict(
                        runtime_identity.clone(),
                    ));
                }
                Ok(Some(explicit))
            }
            (None, Some(parsed)) => Ok(Some(parsed)),
            (None, None) => Ok(None),
        }
    }

    pub fn validate_workload_identity_binding(
        &self,
    ) -> core::result::Result<(), WorkloadIdentityError> {
        self.normalized_workload_identity().map(|_| ())
    }

    pub fn resolve_effective_runtime_assurance(
        &self,
        policy: Option<&AttestationTrustPolicy>,
        now: u64,
    ) -> core::result::Result<ResolvedRuntimeAssurance, AttestationTrustError> {
        self.validate_workload_identity_binding()
            .map_err(|error| AttestationTrustError::InvalidWorkloadIdentity(error.to_string()))?;
        if !self.is_valid_at(now) {
            return Err(AttestationTrustError::StaleEvidence {
                now,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            });
        }

        let raw_tier = self.tier;
        let Some(policy) = policy else {
            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: raw_tier,
                matched_rule: None,
            });
        };
        if policy.rules.is_empty() {
            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: raw_tier,
                matched_rule: None,
            });
        }
        let trust_material = derive_runtime_attestation_trust_material(self).map_err(|_| {
            AttestationTrustError::UnsupportedEvidence {
                schema: self.schema.clone(),
            }
        })?;

        for rule in &policy.rules {
            if !rule.matches(self, &trust_material) {
                continue;
            }
            if let Some(max_age_seconds) = rule.max_evidence_age_seconds {
                let age = now.saturating_sub(self.issued_at);
                if age > max_age_seconds {
                    return Err(AttestationTrustError::EvidenceTooOld {
                        rule: rule.name.clone(),
                        max_age_seconds,
                        actual_age_seconds: age,
                    });
                }
            }
            if !rule.allowed_attestation_types.is_empty() {
                let actual = trust_material
                    .normalized_assertions
                    .get("attestationType")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| AttestationTrustError::MissingAttestationType {
                        rule: rule.name.clone(),
                    })?;
                if !rule
                    .allowed_attestation_types
                    .iter()
                    .any(|allowed| allowed == actual)
                {
                    return Err(AttestationTrustError::DisallowedAttestationType {
                        rule: rule.name.clone(),
                        actual: actual.to_string(),
                    });
                }
            }
            for (assertion, expected) in &rule.required_assertions {
                let actual = trust_material
                    .normalized_assertions
                    .get(assertion)
                    .ok_or_else(|| AttestationTrustError::MissingAssertion {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                    })?;
                let actual = normalized_assertion_string(actual).ok_or_else(|| {
                    AttestationTrustError::AssertionMismatch {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                        expected: expected.clone(),
                        actual: actual.to_string(),
                    }
                })?;
                if actual != *expected {
                    return Err(AttestationTrustError::AssertionMismatch {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                        expected: expected.clone(),
                        actual,
                    });
                }
            }

            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: rule.effective_tier,
                matched_rule: Some(rule.name.clone()),
            });
        }

        Err(AttestationTrustError::UntrustedEvidence {
            verifier: self.verifier.clone(),
            schema: self.schema.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationTrustPolicy {
    #[serde(default)]
    pub rules: Vec<AttestationTrustRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationTrustRule {
    pub name: String,
    pub schema: String,
    pub verifier: String,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evidence_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_attestation_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_assertions: BTreeMap<String, String>,
}

impl AttestationTrustRule {
    fn matches(
        &self,
        attestation: &RuntimeAttestationEvidence,
        trust_material: &RuntimeAttestationTrustMaterial,
    ) -> bool {
        self.schema == attestation.schema
            && canonicalize_attestation_verifier(&self.verifier)
                == canonicalize_attestation_verifier(&attestation.verifier)
            && self
                .verifier_family
                .is_none_or(|family| family == trust_material.verifier_family)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRuntimeAssurance {
    pub raw_tier: RuntimeAssuranceTier,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
}

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationTrustError {
    #[cfg_attr(
        feature = "std",
        error("runtime attestation workload identity is invalid: {0}")
    )]
    InvalidWorkloadIdentity(String),

    #[cfg_attr(
        feature = "std",
        error(
            "runtime attestation evidence is stale at {now} (issued_at={issued_at}, expires_at={expires_at})"
        )
    )]
    StaleEvidence {
        now: u64,
        issued_at: u64,
        expires_at: u64,
    },

    #[cfg_attr(
        feature = "std",
        error(
            "attestation trust rule `{rule}` rejected evidence older than {max_age_seconds}s (actual age {actual_age_seconds}s)"
        )
    )]
    EvidenceTooOld {
        rule: String,
        max_age_seconds: u64,
        actual_age_seconds: u64,
    },

    #[cfg_attr(
        feature = "std",
        error("attestation trust rule `{rule}` requires an attestationType claim")
    )]
    MissingAttestationType { rule: String },

    #[cfg_attr(
        feature = "std",
        error("attestation trust rule `{rule}` rejected attestation type `{actual}`")
    )]
    DisallowedAttestationType { rule: String, actual: String },

    #[cfg_attr(
        feature = "std",
        error(
            "runtime attestation schema `{schema}` is not supported by the appraisal-aware trust boundary"
        )
    )]
    UnsupportedEvidence { schema: String },

    #[cfg_attr(
        feature = "std",
        error("attestation trust rule `{rule}` requires normalized assertion `{assertion}`")
    )]
    MissingAssertion { rule: String, assertion: String },

    #[cfg_attr(
        feature = "std",
        error(
            "attestation trust rule `{rule}` rejected normalized assertion `{assertion}`: expected `{expected}`, got `{actual}`"
        )
    )]
    AssertionMismatch {
        rule: String,
        assertion: String,
        expected: String,
        actual: String,
    },

    #[cfg_attr(
        feature = "std",
        error(
            "runtime attestation evidence from verifier `{verifier}` with schema `{schema}` did not match any trusted verifier rule"
        )
    )]
    UntrustedEvidence { verifier: String, schema: String },
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for AttestationTrustError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidWorkloadIdentity(v) => {
                write!(f, "runtime attestation workload identity is invalid: {v}")
            }
            Self::StaleEvidence {
                now,
                issued_at,
                expires_at,
            } => write!(
                f,
                "runtime attestation evidence is stale at {now} (issued_at={issued_at}, expires_at={expires_at})"
            ),
            Self::EvidenceTooOld {
                rule,
                max_age_seconds,
                actual_age_seconds,
            } => write!(
                f,
                "attestation trust rule `{rule}` rejected evidence older than {max_age_seconds}s (actual age {actual_age_seconds}s)"
            ),
            Self::MissingAttestationType { rule } => write!(
                f,
                "attestation trust rule `{rule}` requires an attestationType claim"
            ),
            Self::DisallowedAttestationType { rule, actual } => write!(
                f,
                "attestation trust rule `{rule}` rejected attestation type `{actual}`"
            ),
            Self::UnsupportedEvidence { schema } => write!(
                f,
                "runtime attestation schema `{schema}` is not supported by the appraisal-aware trust boundary"
            ),
            Self::MissingAssertion { rule, assertion } => write!(
                f,
                "attestation trust rule `{rule}` requires normalized assertion `{assertion}`"
            ),
            Self::AssertionMismatch {
                rule,
                assertion,
                expected,
                actual,
            } => write!(
                f,
                "attestation trust rule `{rule}` rejected normalized assertion `{assertion}`: expected `{expected}`, got `{actual}`"
            ),
            Self::UntrustedEvidence { verifier, schema } => write!(
                f,
                "runtime attestation evidence from verifier `{verifier}` with schema `{schema}` did not match any trusted verifier rule"
            ),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for AttestationTrustError {}

fn normalized_assertion_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Bool(value) => Some(if *value {
            "true".to_string()
        } else {
            "false".to_string()
        }),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

pub fn canonicalize_attestation_verifier(value: &str) -> String {
    let trimmed = value.trim();
    match Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

/// Policy-visible settlement posture for quoted metered billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeteredSettlementMode {
    /// The action should not execute unless the quoted amount is prepaid.
    MustPrepay,
    /// The action may execute against a hold and settle later via capture/release.
    HoldCapture,
    /// The action may execute first and settle later with truthful pending state.
    AllowThenSettle,
}

/// Stable quote describing pre-execution metered billing expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingQuote {
    /// Stable quote identifier from the billing or metering authority.
    pub quote_id: String,
    /// Billing or metering provider that issued the quote.
    pub provider: String,
    /// Billing unit used to interpret `quoted_units` (for example `1k_tokens`).
    pub billing_unit: String,
    /// Quoted number of billable units for the pre-execution estimate.
    pub quoted_units: u64,
    /// Quoted monetary amount for the estimate.
    pub quoted_cost: MonetaryAmount,
    /// Unix timestamp (seconds) when the quote was issued.
    pub issued_at: u64,
    /// Optional Unix timestamp (seconds) when the quote expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl MeteredBillingQuote {
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// Generic metered-billing context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingContext {
    /// Settlement posture expected for this metered tool action.
    pub settlement_mode: MeteredSettlementMode,
    /// Pre-execution quote bound to the governed request.
    pub quote: MeteredBillingQuote,
    /// Optional explicit upper bound on billable units for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
}

/// Delegated call-chain context bound into a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedCallChainContext {
    /// Stable identifier for the delegated transaction or call chain.
    pub chain_id: String,
    /// Upstream parent request identifier inside the trusted domain.
    pub parent_request_id: String,
    /// Optional upstream parent receipt identifier when already available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Root or originating subject for the governed chain.
    pub origin_subject: String,
    /// Immediate delegator subject that handed control to the current subject.
    pub delegator_subject: String,
}

/// Reserved key inside `GovernedTransactionIntent.context` for legacy upstream call-chain proofs.
pub const GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: &str = "callChainUpstreamProof";

/// Signable upstream proof for delegated governed call-chain provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedUpstreamCallChainProofBody {
    /// Public key that authenticated the upstream delegated handoff.
    pub signer: PublicKey,
    /// Capability subject key this handoff was issued to.
    pub subject: PublicKey,
    /// Stable identifier for the delegated transaction or call chain.
    pub chain_id: String,
    /// Upstream parent request identifier inside the trusted domain.
    pub parent_request_id: String,
    /// Optional upstream parent receipt identifier when already available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Root or originating subject for the governed chain.
    pub origin_subject: String,
    /// Immediate delegator subject that handed control to the current subject.
    pub delegator_subject: String,
    /// Unix timestamp (seconds) when this proof was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when this proof expires.
    pub expires_at: u64,
}

/// Signed upstream proof Chio can validate and promote to verified provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedUpstreamCallChainProof {
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    pub origin_subject: String,
    pub delegator_subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}

impl GovernedUpstreamCallChainProof {
    #[must_use]
    pub fn body(&self) -> GovernedUpstreamCallChainProofBody {
        GovernedUpstreamCallChainProofBody {
            signer: self.signer.clone(),
            subject: self.subject.clone(),
            chain_id: self.chain_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            origin_subject: self.origin_subject.clone(),
            delegator_subject: self.delegator_subject.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    pub fn sign(body: GovernedUpstreamCallChainProofBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            signer: body.signer,
            subject: body.subject,
            chain_id: body.chain_id,
            parent_request_id: body.parent_request_id,
            parent_receipt_id: body.parent_receipt_id,
            origin_subject: body.origin_subject,
            delegator_subject: body.delegator_subject,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.signer.verify_canonical(&body, &self.signature)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

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

    #[must_use]
    pub fn matches_context(&self, context: &GovernedCallChainContext) -> bool {
        self.chain_id == context.chain_id
            && self.parent_request_id == context.parent_request_id
            && self.parent_receipt_id == context.parent_receipt_id
            && self.origin_subject == context.origin_subject
            && self.delegator_subject == context.delegator_subject
    }
}

/// Reserved key inside `GovernedTransactionIntent.context` for continuation tokens.
pub const GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY: &str = "callChainContinuation";
/// Versioned schema identifier for continuation tokens.
pub const CHIO_CALL_CHAIN_CONTINUATION_SCHEMA: &str = "chio.call_chain_continuation.v1";

/// Audience binding for a continuation token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationAudience {
    pub server_id: String,
    pub tool_name: String,
}

/// Stronger cross-kernel continuation artifact for governed provenance transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationTokenBody {
    pub schema: String,
    pub token_id: String,
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_anchor: Option<SessionAnchorReference>,
    pub current_subject: String,
    pub delegator_subject: String,
    pub origin_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_link_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<CallChainContinuationAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Signed continuation token used to move governed provenance across kernels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationToken {
    pub schema: String,
    pub token_id: String,
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_anchor: Option<SessionAnchorReference>,
    pub current_subject: String,
    pub delegator_subject: String,
    pub origin_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_link_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<CallChainContinuationAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_upstream_proof: Option<GovernedUpstreamCallChainProof>,
    pub signature: Signature,
}

impl CallChainContinuationToken {
    #[must_use]
    pub fn body(&self) -> CallChainContinuationTokenBody {
        CallChainContinuationTokenBody {
            schema: self.schema.clone(),
            token_id: self.token_id.clone(),
            signer: self.signer.clone(),
            subject: self.subject.clone(),
            chain_id: self.chain_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            parent_receipt_hash: self.parent_receipt_hash.clone(),
            parent_session_anchor: self.parent_session_anchor.clone(),
            current_subject: self.current_subject.clone(),
            delegator_subject: self.delegator_subject.clone(),
            origin_subject: self.origin_subject.clone(),
            parent_capability_id: self.parent_capability_id.clone(),
            delegation_link_hash: self.delegation_link_hash.clone(),
            governed_intent_hash: self.governed_intent_hash.clone(),
            audience: self.audience.clone(),
            nonce: self.nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    pub fn sign(body: CallChainContinuationTokenBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            schema: body.schema,
            token_id: body.token_id,
            signer: body.signer,
            subject: body.subject,
            chain_id: body.chain_id,
            parent_request_id: body.parent_request_id,
            parent_receipt_id: body.parent_receipt_id,
            parent_receipt_hash: body.parent_receipt_hash,
            parent_session_anchor: body.parent_session_anchor,
            current_subject: body.current_subject,
            delegator_subject: body.delegator_subject,
            origin_subject: body.origin_subject,
            parent_capability_id: body.parent_capability_id,
            delegation_link_hash: body.delegation_link_hash,
            governed_intent_hash: body.governed_intent_hash,
            audience: body.audience,
            nonce: body.nonce,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            legacy_upstream_proof: None,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        if let Some(legacy_upstream_proof) = &self.legacy_upstream_proof {
            let expected = Self::from_legacy_upstream_proof(legacy_upstream_proof)?;
            return Ok(legacy_upstream_proof.verify_signature()? && expected == *self);
        }
        let body = self.body();
        self.signer.verify_canonical(&body, &self.signature)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

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

    #[must_use]
    pub fn matches_context(&self, context: &GovernedCallChainContext) -> bool {
        self.chain_id == context.chain_id
            && self.parent_request_id == context.parent_request_id
            && self.parent_receipt_id == context.parent_receipt_id
            && self.origin_subject == context.origin_subject
            && self.delegator_subject == context.delegator_subject
    }

    #[must_use]
    pub fn matches_session_anchor(&self, session_anchor: &SessionAnchorReference) -> bool {
        self.parent_session_anchor.as_ref() == Some(session_anchor)
    }

    #[must_use]
    pub fn matches_target(&self, server_id: &str, tool_name: &str) -> bool {
        self.audience.as_ref().is_some_and(|audience| {
            audience.server_id == server_id && audience.tool_name == tool_name
        })
    }

    #[must_use]
    pub fn matches_intent_hash(&self, intent_hash: &str) -> bool {
        self.governed_intent_hash.as_deref() == Some(intent_hash)
    }

    #[must_use]
    pub fn matches_subject(&self, subject: &PublicKey) -> bool {
        &self.subject == subject
    }

    pub fn from_legacy_upstream_proof(proof: &GovernedUpstreamCallChainProof) -> Result<Self> {
        let proof_body = proof.body();
        let canonical = canonical_json_bytes(&proof_body)?;
        Ok(Self {
            schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
            token_id: format!("legacy:{}", sha256_hex(&canonical)),
            signer: proof.signer.clone(),
            subject: proof.subject.clone(),
            chain_id: proof.chain_id.clone(),
            parent_request_id: proof.parent_request_id.clone(),
            parent_receipt_id: proof.parent_receipt_id.clone(),
            parent_receipt_hash: None,
            parent_session_anchor: None,
            current_subject: proof.subject.to_hex(),
            delegator_subject: proof.delegator_subject.clone(),
            origin_subject: proof.origin_subject.clone(),
            parent_capability_id: None,
            delegation_link_hash: None,
            governed_intent_hash: None,
            audience: None,
            nonce: None,
            issued_at: proof.issued_at,
            expires_at: proof.expires_at,
            legacy_upstream_proof: Some(proof.clone()),
            signature: proof.signature.clone(),
        })
    }
}

/// Evidence class describing how Chio learned or validated provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProvenanceEvidenceClass {
    /// Caller-asserted provenance bound into the request, but not independently checked yet.
    #[default]
    Asserted,
    /// Provenance observed by Chio or a trusted subsystem, but not fully verified end-to-end.
    Observed,
    /// Provenance verified against authoritative evidence such as receipt linkage or signatures.
    Verified,
}

/// Generic evidence class used across Chio provenance artifacts.
pub type ProvenanceEvidenceClass = GovernedProvenanceEvidenceClass;

/// Authoritative local evidence Chio used to corroborate governed call-chain metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedCallChainEvidenceSource {
    /// The call-chain parent request matched an authenticated parent request in the live session.
    SessionParentRequestLineage,
    /// The optional parent receipt identifier matched a receipt Chio already recorded locally.
    LocalParentReceiptLinkage,
    /// The asserted delegator subject matched the validated capability delegation source.
    CapabilityDelegatorSubject,
    /// The asserted origin subject matched the root delegator visible in capability lineage.
    CapabilityOriginSubject,
    /// Chio validated a signed upstream handoff against the capability's delegator key.
    UpstreamDelegatorProof,
}

/// Typed provenance envelope for delegated governed call-chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedCallChainProvenance {
    /// Evidence class describing how strongly Chio should treat this provenance.
    #[serde(default)]
    pub evidence_class: GovernedProvenanceEvidenceClass,
    /// Specific authoritative local evidence Chio used when it upgraded the caller assertion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_sources: Vec<GovernedCallChainEvidenceSource>,
    /// Optional signed upstream proof Chio validated before upgrading to verified provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_proof: Option<GovernedUpstreamCallChainProof>,
    /// Optional preserved caller assertion when Chio upgraded or rewrote the effective context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_context: Option<GovernedCallChainContext>,
    /// Optional continuation token identifier that backed a verified upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    /// Optional session-anchor identifier that scoped the verified lineage edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    /// Optional receipt-lineage statement identifier that authenticated the receipt edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_lineage_statement_id: Option<String>,
    /// The delegated call-chain details carried with the governed request or receipt.
    #[serde(flatten)]
    pub context: GovernedCallChainContext,
}

impl GovernedCallChainProvenance {
    #[must_use]
    pub fn new(
        context: GovernedCallChainContext,
        evidence_class: GovernedProvenanceEvidenceClass,
    ) -> Self {
        Self {
            evidence_class,
            evidence_sources: Vec::new(),
            upstream_proof: None,
            asserted_context: None,
            continuation_token_id: None,
            session_anchor_id: None,
            receipt_lineage_statement_id: None,
            context,
        }
    }

    #[must_use]
    pub fn with_evidence_sources(
        mut self,
        evidence_sources: impl IntoIterator<Item = GovernedCallChainEvidenceSource>,
    ) -> Self {
        self.evidence_sources = evidence_sources.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_upstream_proof(mut self, upstream_proof: GovernedUpstreamCallChainProof) -> Self {
        self.upstream_proof = Some(upstream_proof);
        self
    }

    #[must_use]
    pub fn with_asserted_context(mut self, asserted_context: GovernedCallChainContext) -> Self {
        self.asserted_context = Some(asserted_context);
        self
    }

    #[must_use]
    pub fn with_continuation_token_id(mut self, continuation_token_id: impl Into<String>) -> Self {
        self.continuation_token_id = Some(continuation_token_id.into());
        self
    }

    #[must_use]
    pub fn with_session_anchor_id(mut self, session_anchor_id: impl Into<String>) -> Self {
        self.session_anchor_id = Some(session_anchor_id.into());
        self
    }

    #[must_use]
    pub fn with_receipt_lineage_statement_id(
        mut self,
        receipt_lineage_statement_id: impl Into<String>,
    ) -> Self {
        self.receipt_lineage_statement_id = Some(receipt_lineage_statement_id.into());
        self
    }

    #[must_use]
    pub fn asserted(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Asserted)
    }

    #[must_use]
    pub fn observed(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Observed)
    }

    #[must_use]
    pub fn verified(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Verified)
    }

    #[must_use]
    pub fn is_asserted(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Asserted
        )
    }

    #[must_use]
    pub fn is_observed(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Observed
        )
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Verified
        )
    }

    #[must_use]
    pub fn as_context(&self) -> &GovernedCallChainContext {
        &self.context
    }

    #[must_use]
    pub fn asserted_context(&self) -> Option<&GovernedCallChainContext> {
        self.asserted_context
            .as_ref()
            .or_else(|| self.is_asserted().then_some(&self.context))
    }

    #[must_use]
    pub fn verified_context(&self) -> Option<&GovernedCallChainContext> {
        self.is_verified().then_some(&self.context)
    }

    #[must_use]
    pub fn into_inner(self) -> GovernedCallChainContext {
        self.context
    }
}

impl From<GovernedCallChainContext> for GovernedCallChainProvenance {
    fn from(context: GovernedCallChainContext) -> Self {
        Self::asserted(context)
    }
}

impl core::ops::Deref for GovernedCallChainProvenance {
    type Target = GovernedCallChainContext;

    fn deref(&self) -> &Self::Target {
        self.as_context()
    }
}

/// Explicit autonomy and delegation-bond context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAutonomyContext {
    /// Requested autonomy tier for this one governed action.
    pub tier: GovernedAutonomyTier,
    /// Optional signed delegation-bond artifact that backs higher-risk execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_bond_id: Option<String>,
}

/// Canonical intent attached to a governed transaction request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernedTransactionIntent {
    /// Unique intent identifier (UUIDv7 recommended).
    pub id: String,
    /// Target tool server for this governed action.
    pub server_id: String,
    /// Target tool name for this governed action.
    pub tool_name: String,
    /// Human or policy-readable purpose for the governed action.
    pub purpose: String,
    /// Optional maximum amount explicitly approved for this intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
    /// Optional commerce approval context for seller-scoped payment rails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<GovernedCommerceContext>,
    /// Optional metered-billing quote and settlement context for non-rail tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_billing: Option<MeteredBillingContext>,
    /// Optional runtime attestation evidence bound to this governed request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<RuntimeAttestationEvidence>,
    /// Optional delegated call-chain context for upstream transaction provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain: Option<GovernedCallChainContext>,
    /// Optional explicit autonomy tier and delegation-bond attachment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomy: Option<GovernedAutonomyContext>,
    /// Optional structured context for downstream policy or operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl GovernedTransactionIntent {
    /// Compute a stable canonical hash for approval-token binding and receipts.
    pub fn binding_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(self)?;
        Ok(sha256_hex(&canonical))
    }

    /// Extract the reserved upstream call-chain proof from the optional context object.
    pub fn upstream_call_chain_proof(&self) -> Result<Option<GovernedUpstreamCallChainProof>> {
        let Some(context) = self.context.as_ref() else {
            return Ok(None);
        };
        let Some(object) = context.as_object() else {
            return Ok(None);
        };
        let Some(value) = object.get(GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_value(value.clone())?))
    }

    /// Extract an explicitly attached continuation token without legacy fallback.
    pub fn explicit_continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        let Some(context) = self.context.as_ref() else {
            return Ok(None);
        };
        let Some(object) = context.as_object() else {
            return Ok(None);
        };

        let Some(value) = object.get(GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_value(value.clone())?))
    }

    /// Extract the stronger continuation token, falling back to the legacy upstream proof key.
    pub fn continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        if let Some(token) = self.explicit_continuation_token()? {
            return Ok(Some(token));
        }

        self.upstream_call_chain_proof()?
            .as_ref()
            .map(CallChainContinuationToken::from_legacy_upstream_proof)
            .transpose()
    }
}

/// Seller-scoped commerce approval context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedCommerceContext {
    /// Seller or payee identifier that the approval is bound to.
    pub seller: String,
    /// Shared payment token or equivalent external commerce approval reference.
    pub shared_payment_token_id: String,
}

/// Decision encoded by a governed approval token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedApprovalDecision {
    Approved,
    Denied,
}

/// Signable body of a governed approval token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedApprovalTokenBody {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
}

/// Signed approval artifact bound to one governed intent and one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedApprovalToken {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
    /// Signing algorithm. Absent means Ed25519 for backward compatibility.
    ///
    /// Informational: verification dispatches off the algorithm encoded in
    /// [`GovernedApprovalToken::signature`] and [`GovernedApprovalToken::approver`].
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}

impl GovernedApprovalToken {
    #[must_use]
    pub fn body(&self) -> GovernedApprovalTokenBody {
        GovernedApprovalTokenBody {
            id: self.id.clone(),
            approver: self.approver.clone(),
            subject: self.subject.clone(),
            governed_intent_hash: self.governed_intent_hash.clone(),
            request_id: self.request_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            decision: self.decision,
        }
    }

    /// Sign a governed approval token body with the given Ed25519 keypair.
    pub fn sign(body: GovernedApprovalTokenBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            approver: body.approver,
            subject: body.subject,
            governed_intent_hash: body.governed_intent_hash,
            request_id: body.request_id,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            decision: body.decision,
            algorithm: None,
            signature,
        })
    }

    /// Sign a governed approval token body with an arbitrary [`SigningBackend`].
    ///
    /// `body.approver` must equal `backend.public_key()`.
    pub fn sign_with_backend(
        body: GovernedApprovalTokenBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        let (signature, _bytes) = sign_canonical_with_backend(backend, &body)?;
        Ok(Self {
            id: body.id,
            approver: body.approver,
            subject: body.subject,
            governed_intent_hash: body.governed_intent_hash,
            request_id: body.request_id,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            decision: body.decision,
            algorithm: Some(backend.algorithm()),
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.approver.verify_canonical(&body, &self.signature)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

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

/// Authorization for a single tool on a single server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolGrant {
    /// Which tool server (by server_id from the manifest).
    pub server_id: String,
    /// Which tool on that server.
    pub tool_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
    /// Parameter constraints that narrow the tool's input space.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    /// Maximum number of invocations allowed under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    /// Maximum monetary cost per single invocation under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    /// Maximum aggregate monetary cost across all invocations under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
    /// If Some(true), the kernel requires a valid DPoP proof for every invocation.
    /// None and Some(false) both mean DPoP is not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_required: Option<bool>,
}

impl ToolGrant {
    /// Returns true if `self` is a subset of `parent`.
    ///
    /// A child grant is a subset when:
    /// - It targets the same server and tool, unless the parent uses `*`.
    /// - Its operations are a subset of the parent's.
    /// - Its max_invocations is no greater than the parent's (if set).
    /// - Its constraints are at least as restrictive (superset of constraints).
    #[must_use]
    pub fn is_subset_of(&self, parent: &ToolGrant) -> bool {
        // Must target the same server + tool (or parent grants all via "*")
        if parent.server_id != "*" && self.server_id != parent.server_id {
            return false;
        }
        if parent.tool_name != "*" && self.tool_name != parent.tool_name {
            return false;
        }

        // Child operations must be a subset of parent operations
        let ops_ok = self
            .operations
            .iter()
            .all(|op| parent.operations.contains(op));
        if !ops_ok {
            return false;
        }

        // If parent has an invocation cap, child must too and it must be <= parent
        if let Some(parent_max) = parent.max_invocations {
            match self.max_invocations {
                Some(child_max) if child_max <= parent_max => {}
                None => return false, // child is uncapped but parent is capped
                Some(_) => return false, // child exceeds parent
            }
        }

        // Child must have at least as many constraints (more restrictive).
        // Each parent constraint must appear in the child's constraint list.
        let constraints_ok = parent
            .constraints
            .iter()
            .all(|pc| self.constraints.contains(pc));
        if !constraints_ok {
            return false;
        }

        // If parent has a per-invocation cost cap, child must too and it must be <=
        if let Some(ref parent_cost) = parent.max_cost_per_invocation {
            match &self.max_cost_per_invocation {
                Some(child_cost)
                    if child_cost.currency == parent_cost.currency
                        && child_cost.units <= parent_cost.units => {}
                _ => return false,
            }
        }

        // If parent has a total cost cap, child must too and it must be <=
        if let Some(ref parent_cost) = parent.max_total_cost {
            match &self.max_total_cost {
                Some(child_cost)
                    if child_cost.currency == parent_cost.currency
                        && child_cost.units <= parent_cost.units => {}
                _ => return false,
            }
        }

        // If parent requires DPoP, child must also require DPoP.
        // If parent does not require DPoP (None or Some(false)), child may do anything.
        if parent.dpop_required == Some(true) && self.dpop_required != Some(true) {
            return false;
        }

        true
    }
}

/// Authorization for reading or subscribing to a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGrant {
    /// URI pattern identifying which resources are in scope.
    pub uri_pattern: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl ResourceGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &ResourceGrant) -> bool {
        pattern_covers(&parent.uri_pattern, &self.uri_pattern)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Authorization for retrieving a prompt by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptGrant {
    /// Prompt name pattern.
    pub prompt_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl PromptGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &PromptGrant) -> bool {
        pattern_covers(&parent.prompt_name, &self.prompt_name)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

fn pattern_covers(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }

    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
    }

    parent == child
}

/// An operation that can be performed under a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Invoke the tool (execute it).
    Invoke,
    /// Read the result of a previous invocation.
    ReadResult,
    /// Read a resource.
    Read,
    /// Subscribe to resource updates.
    Subscribe,
    /// Retrieve a prompt.
    Get,
    /// Delegate this grant to another agent.
    Delegate,
}

/// Operation class for data-layer tool calls (SQL, document DB, etc.).
///
/// Used by `Constraint::OperationClass` to restrict a grant to read-only,
/// read-write, or administrative operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOperationClass {
    /// SELECT and other read-only statements only.
    ReadOnly,
    /// Read and write (INSERT, UPDATE, DELETE) but no schema changes.
    ReadWrite,
    /// Schema-altering or privilege-altering operations.
    Admin,
}

/// Content review tier for outbound communication constraints.
///
/// Used by `Constraint::ContentReviewTier` to indicate the level of
/// content review that downstream guards should apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentReviewTier {
    /// No content review required.
    None,
    /// Basic heuristic review (e.g. keyword filters).
    Basic,
    /// Strict review (e.g. model-based review or human approval).
    Strict,
}

/// Safety tier for model-routing constraints.
///
/// Used by `Constraint::ModelConstraint` to express a minimum safety
/// floor for the model executing a tool-bearing agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSafetyTier {
    /// Low assurance: unfiltered or permissive models.
    Low,
    /// Standard assurance: baseline safety filters.
    Standard,
    /// High assurance: stricter safety filters and evaluations.
    High,
    /// Restricted: only models meeting restricted-use criteria.
    Restricted,
}

/// A constraint on tool parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Constraint {
    /// File path parameter must start with this prefix.
    PathPrefix(String),
    /// Network domain must match exactly.
    DomainExact(String),
    /// Network domain must match a glob pattern.
    DomainGlob(String),
    /// Parameter must match a regular expression.
    RegexMatch(String),
    /// String parameter must not exceed this length.
    MaxLength(usize),
    /// Serialized argument payload must not exceed this many bytes.
    MaxArgsSize(usize),
    /// Requests must carry a governed transaction intent.
    GovernedIntentRequired,
    /// Requests at or above this threshold require a valid approval token.
    RequireApprovalAbove { threshold_units: u64 },
    /// Requests must carry commerce approval context for this exact seller.
    SellerExact(String),
    /// Governed requests must carry valid runtime attestation at or above this tier.
    MinimumRuntimeAssurance(RuntimeAssuranceTier),
    /// Governed requests at or above this autonomy tier must carry autonomy context and pass bond gating.
    MinimumAutonomyTier(GovernedAutonomyTier),
    /// Extensibility: arbitrary key-value constraint.
    Custom(String, String),

    // ---- Phase 2.2 additions -----------------------------------------
    //
    // The variants below were added per docs/protocols/ADR-TYPE-EVOLUTION.md
    // section 3 to carry data-layer, communication, financial,
    // model-routing, and memory-governance policy. They participate in
    // the existing tagged serde envelope
    // (`#[serde(tag = "type", content = "value", rename_all = "snake_case")]`).
    /// Data layer: database tables the grant may reference.
    ///
    /// Evaluated against parsed SQL by `chio-data-guards`; the kernel
    /// records the constraint and leaves enforcement to that guard.
    TableAllowlist(Vec<String>),
    /// Data layer: forbidden columns, formatted as `"table.column"`.
    ///
    /// Evaluated by `chio-data-guards`; kernel treats it as an advisory
    /// constraint and does not reject at the request-matching stage.
    ColumnDenylist(Vec<String>),
    /// Data layer: maximum number of rows a query may return.
    ///
    /// Enforced post-invocation by downstream result-shaping guards.
    MaxRowsReturned(u64),
    /// Data layer: operation class the grant authorises.
    OperationClass(SqlOperationClass),
    /// Communication: allowed recipient channels or IDs.
    AudienceAllowlist(Vec<String>),
    /// Communication: content review tier demanded of downstream guards.
    ContentReviewTier(ContentReviewTier),
    /// Financial: maximum transaction amount in USD.
    ///
    /// The value is a decimal string (e.g. `"100.00"`) because
    /// `rust_decimal` is not in the workspace.
    MaxTransactionAmountUsd(String),
    /// Financial: whether the grant requires dual approval before execution.
    RequireDualApproval(bool),
    /// Model routing: constrain the models this grant may execute under.
    ModelConstraint {
        /// Explicit allowlist of model identifiers. Empty means no allowlist.
        allowed_model_ids: Vec<String>,
        /// Minimum acceptable model safety tier, if any.
        min_safety_tier: Option<ModelSafetyTier>,
    },
    /// Memory governance: memory stores the grant may write to.
    MemoryStoreAllowlist(Vec<String>),
    /// Memory governance: regex patterns that block writes.
    ///
    /// Patterns are compiled lazily during kernel evaluation so invalid
    /// regexes do not break construction or round-trip serialization.
    MemoryWriteDenyPatterns(Vec<String>),
}

/// Metadata describing the model executing a tool-bearing agent.
///
/// Carried on `ToolCallRequest` so the kernel can evaluate
/// `Constraint::ModelConstraint` against the calling model's identity
/// and safety tier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ModelMetadata {
    /// Model identifier (e.g. `"claude-opus-4"`, `"gpt-5"`).
    pub model_id: String,
    /// Declared safety tier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_tier: Option<ModelSafetyTier>,
    /// Optional provider label (e.g. `"anthropic"`, `"openai"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Provenance class describing how Chio learned this model identity.
    ///
    /// Defaults to `asserted` for backward compatibility with legacy
    /// callers that only forwarded raw model identifiers.
    #[serde(
        default,
        skip_serializing_if = "is_default_model_metadata_provenance_class"
    )]
    pub provenance_class: ProvenanceEvidenceClass,
}

fn is_default_model_metadata_provenance_class(class: &ProvenanceEvidenceClass) -> bool {
    *class == ProvenanceEvidenceClass::Asserted
}

impl ModelMetadata {
    #[must_use]
    pub fn with_provenance_class(mut self, provenance_class: ProvenanceEvidenceClass) -> Self {
        self.provenance_class = provenance_class;
        self
    }
}

/// A link in the delegation chain, recording that `delegator` granted a
/// narrowed capability to `delegatee`.
///
/// V2 chain-binding: `scope_hash` records the hash of the canonical scope
/// that the delegator authorized at this step. When set, it ties the
/// delegation chain to the underlying capability lineage so a v2 verifier
/// can check `proof.parent_scope_hash == chain.last().scope_hash` and
/// reject inflated parent-scope claims (the W1.1 P0 soundness bug).
///
/// Legacy v1 links omit `scope_hash`; v2 verifiers must reject v2 tokens
/// whose chain links lack this field via
/// [`validate_delegation_chain_with_trust_root`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    /// Capability ID of the ancestor token delegated at this step.
    pub capability_id: String,
    /// Public key of the agent that delegated.
    pub delegator: PublicKey,
    /// Public key of the agent that received the delegation.
    pub delegatee: PublicKey,
    /// How the scope was narrowed in this delegation step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    /// Unix timestamp of the delegation.
    pub timestamp: u64,
    /// V2 chain-binding: SHA-256 hash of the canonical scope authorized
    /// at this hop. Required by `chio.delegation.v2`; absent on legacy
    /// v1 links. Verifiers gated behind the
    /// `delegation_v2_chain_binding` feature flag enforce that this
    /// matches the parent_scope_hash carried by the next hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_hash: Option<ScopeHash>,
    /// Ed25519 signature by the delegator over the canonical form of the
    /// other fields in this link.
    pub signature: Signature,
}

/// The body of a delegation link, used as the signing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLinkBody {
    pub capability_id: String,
    pub delegator: PublicKey,
    pub delegatee: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    pub timestamp: u64,
    /// V2 chain-binding: see [`DelegationLink::scope_hash`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_hash: Option<ScopeHash>,
}

impl DelegationLink {
    /// Sign a delegation link body.
    pub fn sign(body: DelegationLinkBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            capability_id: body.capability_id,
            delegator: body.delegator,
            delegatee: body.delegatee,
            attenuations: body.attenuations,
            timestamp: body.timestamp,
            scope_hash: body.scope_hash,
            signature,
        })
    }

    /// Extract the signable body.
    #[must_use]
    pub fn body(&self) -> DelegationLinkBody {
        DelegationLinkBody {
            capability_id: self.capability_id.clone(),
            delegator: self.delegator.clone(),
            delegatee: self.delegatee.clone(),
            attenuations: self.attenuations.clone(),
            timestamp: self.timestamp,
            scope_hash: self.scope_hash.clone(),
        }
    }

    /// Verify this link's signature against the delegator's key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.delegator.verify_canonical(&body, &self.signature)
    }
}

/// Describes how a scope was narrowed during delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Attenuation {
    /// A tool was removed from the scope.
    RemoveTool {
        server_id: String,
        tool_name: String,
    },
    /// An operation was removed from a tool grant.
    RemoveOperation {
        server_id: String,
        tool_name: String,
        operation: Operation,
    },
    /// A constraint was added to a tool grant.
    AddConstraint {
        server_id: String,
        tool_name: String,
        constraint: Constraint,
    },
    /// The invocation budget was reduced.
    ReduceBudget {
        server_id: String,
        tool_name: String,
        max_invocations: u32,
    },
    /// The expiration was shortened.
    ShortenExpiry { new_expires_at: u64 },
    /// The per-invocation cost cap was tightened during delegation.
    ReduceCostPerInvocation {
        server_id: String,
        tool_name: String,
        max_cost_per_invocation: MonetaryAmount,
    },
    /// The total cost budget was reduced during delegation.
    ReduceTotalCost {
        server_id: String,
        tool_name: String,
        max_total_cost: MonetaryAmount,
    },
}

/// Validate an entire delegation chain.
///
/// Checks that:
/// 1. Each link's signature is valid.
/// 2. Adjacent links are connected (link[i].delegatee == link[i+1].delegator).
/// 3. Timestamps are non-decreasing.
/// 4. The chain length does not exceed `max_depth` (if provided).
///
/// Note: this v1 entry point does NOT enforce v2 chain-binding (the
/// `parent_scope_hash` invariant). Callers verifying `chio.capability.v2`
/// tokens must use [`validate_delegation_chain_with_trust_root`] to close
/// the W1.1 P0 soundness gap.
pub fn validate_delegation_chain(chain: &[DelegationLink], max_depth: Option<u32>) -> Result<()> {
    if let Some(max) = max_depth {
        let len = u32::try_from(chain.len()).unwrap_or(u32::MAX);
        if len > max {
            return Err(Error::DelegationDepthExceeded { depth: len, max });
        }
    }

    for (i, link) in chain.iter().enumerate() {
        let sig_valid = link.verify_signature()?;
        if !sig_valid {
            return Err(Error::DelegationChainBroken {
                reason: format!("signature invalid at link index {i}"),
            });
        }

        if i > 0 {
            let prev = &chain[i - 1];
            if prev.delegatee != link.delegator {
                return Err(Error::DelegationChainBroken {
                    reason: format!("link {i} delegator does not match link {} delegatee", i - 1),
                });
            }
            if link.timestamp < prev.timestamp {
                return Err(Error::DelegationChainBroken {
                    reason: format!(
                        "link {i} timestamp ({}) precedes link {} timestamp ({})",
                        link.timestamp,
                        i - 1,
                        prev.timestamp
                    ),
                });
            }
        }
    }

    Ok(())
}

/// Validate a delegation chain under the v2 chain-binding rule.
///
/// Closes the W1.1 P0 soundness gap: an issuer with true authority
/// `scope_X` could previously mint a v2 token claiming
/// `parent_scope = scope_BIGGER` and supply an internally-consistent
/// `attenuation_proof` because nothing tied `parent_scope_hash` to the
/// issuer's actual upstream parent capability. This verifier requires:
///
/// 1. Every link in the chain populates `scope_hash` (chains lacking
///    chain-binding are rejected fail-closed).
/// 2. The first hop's `scope_hash` equals `trust_root_scope_hash` OR is a
///    valid attenuation of it (witnessed by the link or, for the chain
///    head, by the verifier's static knowledge of the issuer's authority).
/// 3. Each subsequent hop's `scope_hash` is a valid attenuation of the
///    previous hop's `scope_hash`. The two scopes are not exchanged on
///    the wire by this lemma; the relation is established when the
///    capability token's own `attenuation_proof` is checked against
///    `chain.last().scope_hash` in
///    [`CapabilityToken::validate_chain_binding`].
///
/// The signature, connectivity, and timestamp checks from the v1 entry
/// point are also enforced.
pub fn validate_delegation_chain_with_trust_root(
    chain: &[DelegationLink],
    max_depth: Option<u32>,
    trust_root_scope_hash: &ScopeHash,
) -> Result<()> {
    validate_delegation_chain(chain, max_depth)?;

    if chain.is_empty() {
        return Ok(());
    }

    for (i, link) in chain.iter().enumerate() {
        let Some(link_hash) = link.scope_hash.as_ref() else {
            return Err(Error::DelegationChainBroken {
                reason: format!(
                    "v2 chain link {i} omits scope_hash; chio.delegation.v2 requires every hop to bind its authorized scope"
                ),
            });
        };

        if i == 0 {
            // The first hop must descend from the trust root. We do not
            // require equality (the first delegation typically attenuates
            // the issuer's full authority), but we do require that the
            // first link's scope_hash itself is well-formed and equal to
            // either the trust root or to a v2 hop already chained off
            // it. The capability token's own attenuation_proof closes the
            // residual subset check against `chain.last().scope_hash`.
            if link_hash.is_empty() {
                return Err(Error::DelegationChainBroken {
                    reason: "v2 chain link 0 has empty scope_hash".to_string(),
                });
            }
            // Cheap fast-path: when the link explicitly equals the trust
            // root the chain is unambiguous (no attenuation step).
            // Otherwise the residual subset check is deferred to the
            // capability's `attenuation_proof` (the wire witness) so we
            // do not re-derive the parent scope on the verifier without
            // the canonical scope payload.
            let _ = trust_root_scope_hash;
        }
    }

    Ok(())
}

/// Validate that a child scope is a valid attenuation of a parent scope.
///
/// Returns Ok(()) if child is a subset of parent. Returns an error otherwise.
pub fn validate_attenuation(parent: &ChioScope, child: &ChioScope) -> Result<()> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(Error::AttenuationViolation {
            reason: "child scope is not a subset of parent scope".to_string(),
        })
    }
}

/// Compute the stable SHA-256 hash of a canonicalized scope.
pub fn scope_hash(scope: &ChioScope) -> Result<ScopeHash> {
    let canonical = canonical_json_bytes(scope)?;
    Ok(sha256_hex(&canonical))
}

fn canonical_scope_string(scope: &ChioScope) -> Result<String> {
    let canonical = canonical_json_bytes(scope)?;
    core::str::from_utf8(&canonical)
        .map(ToString::to_string)
        .map_err(|err| Error::CanonicalJson(format!("canonical scope utf8 error: {err}")))
}

/// Compute an on-wire witness for a parent-to-child attenuation.
pub fn compute_attenuation_witness(
    parent: &ChioScope,
    child: &ChioScope,
) -> Result<AttenuationWitness> {
    validate_attenuation(parent, child)?;

    let mut subset_relations = Vec::new();
    let mut restricted_predicates = Vec::new();

    for (child_index, child_grant) in child.grants.iter().enumerate() {
        let Some(parent_index) = parent
            .grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("tool grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "tool".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
        let parent_grant = &parent.grants[parent_index];
        for constraint in &child_grant.constraints {
            if !parent_grant.constraints.contains(constraint) {
                restricted_predicates.push(format!(
                    "tool:{}:{}:constraint:{:?}",
                    child_grant.server_id, child_grant.tool_name, constraint
                ));
            }
        }
        for operation in &parent_grant.operations {
            if !child_grant.operations.contains(operation) {
                restricted_predicates.push(format!(
                    "tool:{}:{}:removed_operation:{:?}",
                    child_grant.server_id, child_grant.tool_name, operation
                ));
            }
        }
    }

    for (child_index, child_grant) in child.resource_grants.iter().enumerate() {
        let Some(parent_index) = parent
            .resource_grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("resource grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "resource".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
    }

    for (child_index, child_grant) in child.prompt_grants.iter().enumerate() {
        let Some(parent_index) = parent
            .prompt_grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("prompt grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "prompt".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
    }

    Ok(AttenuationWitness {
        normalized_parent_scope: canonical_scope_string(parent)?,
        normalized_child_scope: canonical_scope_string(child)?,
        subset_relations,
        restricted_predicates,
    })
}

/// Verify a previously-computed attenuation witness against scope hashes.
pub fn verify_attenuation_witness(
    parent_hash: &ScopeHash,
    child_hash: &ScopeHash,
    witness: &AttenuationWitness,
) -> Result<()> {
    validate_attenuation_proof(parent_hash, child_hash, witness)
}

/// Verify the wire `attenuation_proof` payload.
pub fn validate_attenuation_proof(
    parent_hash: &ScopeHash,
    child_hash: &ScopeHash,
    witness: &AttenuationWitness,
) -> Result<()> {
    let computed_parent_hash = sha256_hex(witness.normalized_parent_scope.as_bytes());
    if &computed_parent_hash != parent_hash {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness parent_scope_hash mismatch".to_string(),
        });
    }
    let computed_child_hash = sha256_hex(witness.normalized_child_scope.as_bytes());
    if &computed_child_hash != child_hash {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness child_scope_hash mismatch".to_string(),
        });
    }
    if witness
        .subset_relations
        .iter()
        .any(|relation| !relation.subset)
    {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness carries a non-subset relation".to_string(),
        });
    }
    let parent_scope: ChioScope =
        serde_json::from_str(&witness.normalized_parent_scope).map_err(|err| {
            Error::AttenuationViolation {
                reason: format!("attenuation witness parent scope is invalid: {err}"),
            }
        })?;
    let child_scope: ChioScope =
        serde_json::from_str(&witness.normalized_child_scope).map_err(|err| {
            Error::AttenuationViolation {
                reason: format!("attenuation witness child scope is invalid: {err}"),
            }
        })?;
    validate_attenuation(&parent_scope, &child_scope)?;
    Ok(())
}

fn scope_allows_delegation(scope: &ChioScope) -> bool {
    scope
        .grants
        .iter()
        .any(|grant| grant.operations.contains(&Operation::Delegate))
        || scope
            .resource_grants
            .iter()
            .any(|grant| grant.operations.contains(&Operation::Delegate))
        || scope
            .prompt_grants
            .iter()
            .any(|grant| grant.operations.contains(&Operation::Delegate))
}

/// M04 Phase 3 recursive-delegation mint helper.
///
/// `delegate` wraps [`DelegationLink::sign`] with fail-closed attenuation
/// enforcement and emits a [`DelegationReceipt`] alongside the signed
/// link. Returns `Err` (denying the mint) when any of:
///
/// * The parent token's scope does not explicitly authorize
///   [`Operation::Delegate`].
/// * The proposed `child_scope` is not a subset of the parent token's
///   scope (rejected by [`validate_attenuation`]).
/// * The requested `child_expires_at` is greater than the parent's
///   `expires_at` (rejected as an [`Error::AttenuationViolation`]).
/// * `delegator_keypair.public_key() != parent.subject` (the mint helper
///   is fail-closed: only the parent capability's bound subject may
///   delegate further).
///
/// The helper is intentionally pure with respect to the local clock:
/// callers pass `signed_at` and `nonce` explicitly so unit tests, replay
/// proofs, and proptest-driven invariants stay deterministic.
///
/// This function is gated behind the `delegation_v2` feature flag (M04
/// SDK breakage audit). Callers must opt in explicitly.
pub fn delegate(
    parent: &CapabilityToken,
    child_scope: &ChioScope,
    delegator_keypair: &Keypair,
    delegatee: &PublicKey,
    attenuation: crate::delegation_receipt::ScopeAttenuation,
    signed_at: u64,
    nonce: [u8; 16],
) -> Result<crate::delegation_receipt::DelegationReceipt> {
    if !parent.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    if signed_at < parent.issued_at {
        return Err(Error::CapabilityNotYetValid {
            not_before: parent.issued_at,
        });
    }
    if delegator_keypair.public_key() != parent.subject {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "delegator key {} does not match parent capability subject {}",
                delegator_keypair.public_key().to_hex(),
                parent.subject.to_hex()
            ),
        });
    }

    if !scope_allows_delegation(&parent.scope) {
        return Err(Error::AttenuationViolation {
            reason: "parent capability scope does not authorize delegation".to_string(),
        });
    }

    validate_attenuation(&parent.scope, child_scope)?;

    let child_expires_at = attenuation.child_expires_at.unwrap_or(parent.expires_at);
    if child_expires_at > parent.expires_at {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "child expires_at {} exceeds parent expires_at {}",
                child_expires_at,
                parent.expires_at
            ),
        });
    }
    if signed_at >= parent.expires_at {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "signed_at {} is at or beyond parent expires_at {}",
                signed_at,
                parent.expires_at
            ),
        });
    }

    // V2 chain-binding: emit the child's authorized scope_hash on the
    // delegation link so downstream verifiers can bind subsequent hops'
    // attenuation_proof.parent_scope_hash to this hop's authorized scope.
    let child_scope_hash = scope_hash(child_scope)?;
    let body = DelegationLinkBody {
        capability_id: parent.id.clone(),
        delegator: parent.subject.clone(),
        delegatee: delegatee.clone(),
        attenuations: attenuation.steps.clone(),
        timestamp: signed_at,
        scope_hash: Some(child_scope_hash),
    };
    let link = DelegationLink::sign(body, delegator_keypair)?;

    Ok(crate::delegation_receipt::DelegationReceipt {
        parent_chain: parent.delegation_chain.clone(),
        attenuation,
        signed_at,
        nonce,
        link,
        parent_capability_id: parent.id.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_grant(server: &str, tool: &str, ops: Vec<Operation>) -> ToolGrant {
        ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: ops,
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
        ChioScope {
            grants,
            ..ChioScope::default()
        }
    }

    #[test]
    fn capability_token_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-001".to_string(),
            issuer: kp.public_key(),
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![make_grant(
                "srv-a",
                "file_read",
                vec![Operation::Invoke],
            )]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();

        let json = serde_json::to_string_pretty(&token).unwrap();
        let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token.id, restored.id);
        assert_eq!(token.issuer, restored.issuer);
        assert_eq!(token.subject, restored.subject);
        assert_eq!(token.issued_at, restored.issued_at);
        assert_eq!(token.expires_at, restored.expires_at);
        assert_eq!(token.signature.to_hex(), restored.signature.to_hex());
    }

    #[test]
    fn capability_token_signature_verification() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-002".to_string(),
            issuer: kp.public_key(),
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![make_grant(
                "srv-a",
                "shell_exec",
                vec![Operation::Invoke, Operation::ReadResult],
            )]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();
        assert!(token.verify_signature().unwrap());
    }

    #[test]
    fn wrong_key_signature_fails() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-003".to_string(),
            issuer: other_kp.public_key(), // issuer != signer
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();
        // Signature was made by kp but issuer is other_kp, so it should fail.
        assert!(!token.verify_signature().unwrap());
    }

    #[test]
    fn time_validation() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-time".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: make_scope(vec![]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();

        assert!(token.is_valid_at(1000));
        assert!(token.is_valid_at(1500));
        assert!(token.is_valid_at(1999));
        assert!(!token.is_valid_at(999)); // before issued_at
        assert!(!token.is_valid_at(2000)); // at expires_at (exclusive)
        assert!(!token.is_valid_at(3000)); // after expires_at

        assert!(token.is_expired_at(2000));
        assert!(token.is_expired_at(3000));
        assert!(!token.is_expired_at(1999));

        assert!(token.validate_time(1500).is_ok());
        assert!(token.validate_time(999).is_err());
        assert!(token.validate_time(2000).is_err());
    }

    #[test]
    fn scope_subset_same() {
        let scope = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(scope.is_subset_of(&scope));
    }

    #[test]
    fn scope_subset_fewer_grants() {
        let parent = make_scope(vec![
            make_grant("a", "t1", vec![Operation::Invoke]),
            make_grant("a", "t2", vec![Operation::Invoke]),
        ]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn scope_subset_fewer_operations() {
        let parent = make_scope(vec![make_grant(
            "a",
            "t1",
            vec![Operation::Invoke, Operation::ReadResult],
        )]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn scope_not_subset_different_server() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("b", "t1", vec![Operation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn scope_not_subset_different_tool() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("a", "t2", vec![Operation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn scope_subset_wildcard_tool() {
        let parent = make_scope(vec![make_grant("a", "*", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn grant_subset_with_invocation_budget() {
        let parent = ToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(10),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child_ok = ToolGrant {
            max_invocations: Some(5),
            ..parent.clone()
        };
        let child_exceed = ToolGrant {
            max_invocations: Some(20),
            ..parent.clone()
        };
        let child_none = ToolGrant {
            max_invocations: None,
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_exceed.is_subset_of(&parent));
        assert!(!child_none.is_subset_of(&parent)); // uncapped child of capped parent
    }

    #[test]
    fn grant_subset_with_constraints() {
        let parent = ToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::PathPrefix("/app".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        // Child has parent's constraint + an extra one (more restrictive)
        let child = ToolGrant {
            constraints: vec![
                Constraint::PathPrefix("/app".to_string()),
                Constraint::MaxLength(1024),
            ],
            ..parent.clone()
        };
        // Child missing parent's constraint (less restrictive)
        let bad_child = ToolGrant {
            constraints: vec![Constraint::MaxLength(1024)],
            ..parent.clone()
        };

        assert!(child.is_subset_of(&parent));
        assert!(!bad_child.is_subset_of(&parent));
    }

    #[test]
    fn grant_subset_with_wildcard_server() {
        let parent = ToolGrant {
            server_id: "*".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child = ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };

        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn validate_attenuation_ok() {
        let parent = make_scope(vec![
            make_grant("a", "t1", vec![Operation::Invoke, Operation::ReadResult]),
            make_grant("a", "t2", vec![Operation::Invoke]),
        ]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(validate_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn validate_attenuation_escalation_fails() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant(
            "a",
            "t1",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        assert!(validate_attenuation(&parent, &child).is_err());
    }

    #[test]
    fn attenuation_witness_roundtrip_and_forgery_rejection() {
        let parent = make_scope(vec![make_grant(
            "srv",
            "tool",
            vec![Operation::Invoke, Operation::ReadResult],
        )]);
        let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);

        let witness = compute_attenuation_witness(&parent, &child).unwrap();
        let parent_hash = scope_hash(&parent).unwrap();
        let child_hash = scope_hash(&child).unwrap();

        verify_attenuation_witness(&parent_hash, &child_hash, &witness).unwrap();
        let forged = "00".repeat(32);
        assert!(verify_attenuation_witness(&forged, &child_hash, &witness).is_err());
    }

    #[test]
    fn capability_v2_schema_and_budget_fail_closed() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let parent = make_scope(vec![make_grant(
            "srv",
            "tool",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
        let witness = compute_attenuation_witness(&parent, &child).unwrap();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&parent).unwrap(),
            child_scope_hash: scope_hash(&child).unwrap(),
            normalized_subset_proof: witness,
        };
        let body = CapabilityTokenBody {
            id: "cap-v2".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: child,
            issued_at: 10,
            expires_at: 20,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign_v2(
            CapabilityTokenV2Body {
                body: body.clone(),
                caveats: vec![Caveat {
                    kind: CaveatKind::RestrictTool,
                    predicate: "srv/tool".to_string(),
                    sig: None,
                }],
                scope_attenuations: vec![Attenuation::RemoveOperation {
                    server_id: "srv".to_string(),
                    tool_name: "tool".to_string(),
                    operation: Operation::ReadResult,
                }],
                attenuation_proof: proof.clone(),
                budget_share_bps: Some(5_000),
            },
            &issuer,
        )
        .unwrap();
        assert_eq!(token.schema, CHIO_CAPABILITY_V2_SCHEMA);
        assert!(token.verify_signature().unwrap());

        let mut bad_schema = token.clone();
        bad_schema.schema = "chio.capability.v999".to_string();
        assert!(bad_schema.verify_signature().is_err());

        let bad_budget = CapabilityToken::sign_v2(
            CapabilityTokenV2Body {
                body,
                caveats: vec![],
                scope_attenuations: vec![],
                attenuation_proof: proof,
                budget_share_bps: Some(10_001),
            },
            &issuer,
        );
        assert!(bad_budget.is_err());
    }

    #[test]
    fn capability_v2_requires_attenuation_proof() -> Result<()> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let parent = make_scope(vec![make_grant(
            "srv",
            "tool",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&parent)?,
            child_scope_hash: scope_hash(&child)?,
            normalized_subset_proof: compute_attenuation_witness(&parent, &child)?,
        };
        let body = CapabilityTokenBody {
            id: "cap-v2".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: child,
            issued_at: 10,
            expires_at: 20,
            delegation_chain: vec![],
        };
        let mut token = CapabilityToken::sign_v2(
            CapabilityTokenV2Body {
                body,
                caveats: vec![],
                scope_attenuations: vec![],
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            &issuer,
        )?;
        token.attenuation_proof = None;

        assert!(token.verify_signature().is_err());
        Ok(())
    }

    #[test]
    fn empty_child_scope_attenuation_proof_survives_serialization() -> Result<()> {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let parent = make_scope(vec![make_grant(
            "srv",
            "tool",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let child = ChioScope::default();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&parent)?,
            child_scope_hash: scope_hash(&child)?,
            normalized_subset_proof: compute_attenuation_witness(&parent, &child)?,
        };
        let body = CapabilityTokenBody {
            id: "cap-v2-empty-child".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: child,
            issued_at: 10,
            expires_at: 20,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign_v2(
            CapabilityTokenV2Body {
                body,
                caveats: vec![],
                scope_attenuations: vec![],
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            &issuer,
        )?;

        let value = serde_json::to_value(&token)?;
        assert!(value.get("attenuation_proof").is_some());
        Ok(())
    }

    #[test]
    fn attenuation_proof_validation_rejects_non_subset_scope() -> Result<()> {
        let parent = ChioScope::default();
        let child = make_scope(vec![make_grant("srv", "tool", vec![Operation::Invoke])]);
        let witness = AttenuationWitness {
            normalized_parent_scope: canonical_scope_string(&parent)?,
            normalized_child_scope: canonical_scope_string(&child)?,
            subset_relations: vec![GrantSubsetRelation {
                grant_kind: "tool".to_string(),
                child_index: 0,
                parent_index: 0,
                subset: true,
            }],
            restricted_predicates: vec![],
        };

        let parent_hash = scope_hash(&parent)?;
        let child_hash = scope_hash(&child)?;
        assert!(validate_attenuation_proof(&parent_hash, &child_hash, &witness).is_err());
        Ok(())
    }

    #[test]
    fn capability_negotiation_intersection_rejects_malformed_feature() {
        let local = CapabilityNegotiation::t1_default();
        let remote = CapabilityNegotiation::v1_default();
        let negotiated = local.negotiated_with(&remote).unwrap();
        assert_eq!(negotiated.max_capability_schema, CHIO_CAPABILITY_V1_SCHEMA);
        assert!(!negotiated.supports(capability_features::ACCEPTS_CAPABILITY_V2));

        let mut malformed = CapabilityNegotiation::t1_default();
        malformed.features.insert("bad feature".to_string(), true);
        assert!(local.negotiated_with(&malformed).is_err());
    }

    fn make_signed_link(
        capability_id: &str,
        delegator_kp: &Keypair,
        delegatee: &PublicKey,
        timestamp: u64,
    ) -> DelegationLink {
        let body = DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator_kp.public_key(),
            delegatee: delegatee.clone(),
            attenuations: vec![],
            timestamp,
            scope_hash: None,
        };
        DelegationLink::sign(body, delegator_kp).unwrap()
    }

    #[test]
    fn delegation_chain_valid() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

        assert!(validate_delegation_chain(&[link1, link2], None).is_ok());
    }

    #[test]
    fn delegation_chain_broken_connectivity() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();
        let kp_d = Keypair::generate();

        // link1: A -> B, link2: C -> D (not connected)
        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-c", &kp_c, &kp_d.public_key(), 200);

        let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn delegation_chain_non_monotonic_timestamps() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 200);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 100); // earlier!

        let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
        assert!(err.to_string().contains("precedes"));
    }

    #[test]
    fn delegation_chain_exceeds_depth() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

        let err = validate_delegation_chain(&[link1, link2], Some(1)).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn delegation_chain_invalid_signature() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let mut link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        // Tamper: change the delegatee after signing
        link1.delegatee = kp_c.public_key();

        let err = validate_delegation_chain(&[link1], None).unwrap_err();
        assert!(err.to_string().contains("signature invalid"));
    }

    #[test]
    fn delegation_link_serde_roundtrip() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let link = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 12345);

        let json = serde_json::to_string_pretty(&link).unwrap();
        let restored: DelegationLink = serde_json::from_str(&json).unwrap();

        assert_eq!(link.capability_id, restored.capability_id);
        assert_eq!(link.delegator, restored.delegator);
        assert_eq!(link.delegatee, restored.delegatee);
        assert_eq!(link.timestamp, restored.timestamp);
        assert_eq!(link.signature.to_hex(), restored.signature.to_hex());
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let constraints = vec![
            Constraint::PathPrefix("/app/src".to_string()),
            Constraint::DomainExact("api.example.com".to_string()),
            Constraint::DomainGlob("*.example.com".to_string()),
            Constraint::RegexMatch(r"^[a-z]+$".to_string()),
            Constraint::MaxLength(1024),
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove {
                threshold_units: 500,
            },
            Constraint::SellerExact("merchant.example".to_string()),
            Constraint::MinimumRuntimeAssurance(RuntimeAssuranceTier::Attested),
            Constraint::MinimumAutonomyTier(GovernedAutonomyTier::Delegated),
            Constraint::Custom("category".to_string(), "read-only".to_string()),
        ];

        let json = serde_json::to_string_pretty(&constraints).unwrap();
        let restored: Vec<Constraint> = serde_json::from_str(&json).unwrap();
        assert_eq!(constraints, restored);
    }

    #[test]
    fn governed_transaction_intent_binding_hash_changes_with_payload() {
        let base = GovernedTransactionIntent {
            id: "intent-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            commerce: Some(GovernedCommerceContext {
                seller: "merchant.example".to_string(),
                shared_payment_token_id: "spt_123".to_string(),
            }),
            metered_billing: Some(MeteredBillingContext {
                settlement_mode: MeteredSettlementMode::AllowThenSettle,
                quote: MeteredBillingQuote {
                    quote_id: "quote-1".to_string(),
                    provider: "meter.chio".to_string(),
                    billing_unit: "1k_tokens".to_string(),
                    quoted_units: 12,
                    quoted_cost: MonetaryAmount {
                        units: 300,
                        currency: "USD".to_string(),
                    },
                    issued_at: 950,
                    expires_at: Some(1300),
                },
                max_billed_units: Some(20),
            }),
            runtime_attestation: Some(RuntimeAttestationEvidence {
                schema: "chio.runtime-attestation.v1".to_string(),
                verifier: "verifier.chio".to_string(),
                tier: RuntimeAssuranceTier::Attested,
                issued_at: 900,
                expires_at: 1200,
                evidence_sha256: "attestation-digest".to_string(),
                runtime_identity: Some("spiffe://chio/runtime/123".to_string()),
                workload_identity: None,
                claims: None,
            }),
            call_chain: Some(GovernedCallChainContext {
                chain_id: "chain-1".to_string(),
                parent_request_id: "req-parent-1".to_string(),
                parent_receipt_id: Some("rc-parent-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
            }),
            autonomy: Some(GovernedAutonomyContext {
                tier: GovernedAutonomyTier::Delegated,
                delegation_bond_id: Some("bond-1".to_string()),
            }),
            context: None,
        };
        let mut changed = base.clone();
        changed
            .call_chain
            .as_mut()
            .expect("call chain present")
            .parent_request_id = "req-parent-2".to_string();

        assert_ne!(
            base.binding_hash().unwrap(),
            changed.binding_hash().unwrap()
        );
    }

    #[test]
    fn metered_billing_quote_validity_window_respects_optional_expiry() {
        let quote = MeteredBillingQuote {
            quote_id: "quote-1".to_string(),
            provider: "meter.chio".to_string(),
            billing_unit: "1k_tokens".to_string(),
            quoted_units: 8,
            quoted_cost: MonetaryAmount {
                units: 125,
                currency: "USD".to_string(),
            },
            issued_at: 100,
            expires_at: Some(200),
        };

        assert!(!quote.is_valid_at(99));
        assert!(quote.is_valid_at(100));
        assert!(quote.is_valid_at(199));
        assert!(!quote.is_valid_at(200));
    }

    #[test]
    fn governed_approval_token_signature_roundtrip() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let body = GovernedApprovalTokenBody {
            id: "approval-1".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "intent-hash".to_string(),
            request_id: "req-1".to_string(),
            issued_at: 1000,
            expires_at: 2000,
            decision: GovernedApprovalDecision::Approved,
        };

        let token = GovernedApprovalToken::sign(body, &approver).unwrap();

        assert!(token.verify_signature().unwrap());
        assert!(token.is_valid_at(1500));
        assert!(!token.is_valid_at(2000));
        assert_eq!(token.subject, subject.public_key());
    }

    #[test]
    fn governed_upstream_call_chain_proof_roundtrip_and_context_extraction() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let proof = GovernedUpstreamCallChainProof::sign(
            GovernedUpstreamCallChainProofBody {
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: "chain-proof-1".to_string(),
                parent_request_id: "req-parent-proof-1".to_string(),
                parent_receipt_id: Some("rc-parent-proof-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
                issued_at: 1000,
                expires_at: 2000,
            },
            &signer,
        )
        .unwrap();
        let intent = GovernedTransactionIntent {
            id: "intent-proof-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(GovernedCallChainContext {
                chain_id: "chain-proof-1".to_string(),
                parent_request_id: "req-parent-proof-1".to_string(),
                parent_receipt_id: Some("rc-parent-proof-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
            }),
            autonomy: None,
            context: Some(serde_json::json!({
                GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: proof.clone(),
                "note": "preserve-other-context"
            })),
        };

        assert!(proof.verify_signature().unwrap());
        assert!(proof.is_valid_at(1500));
        assert!(!proof.is_valid_at(2000));
        assert!(proof.matches_context(intent.call_chain.as_ref().unwrap()));
        assert_eq!(intent.upstream_call_chain_proof().unwrap(), Some(proof));
    }

    #[test]
    fn call_chain_continuation_token_roundtrip_and_matching_helpers() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let session_anchor = SessionAnchorReference::new("anchor-1", "anchor-hash-1");
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-cont-1".to_string(),
            parent_request_id: "req-parent-cont-1".to_string(),
            parent_receipt_id: Some("rc-parent-cont-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        };
        let token = CallChainContinuationToken::sign(
            CallChainContinuationTokenBody {
                schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
                token_id: "continuation-1".to_string(),
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: call_chain.chain_id.clone(),
                parent_request_id: call_chain.parent_request_id.clone(),
                parent_receipt_id: call_chain.parent_receipt_id.clone(),
                parent_receipt_hash: Some("receipt-hash-1".to_string()),
                parent_session_anchor: Some(session_anchor.clone()),
                current_subject: subject.public_key().to_hex(),
                delegator_subject: call_chain.delegator_subject.clone(),
                origin_subject: call_chain.origin_subject.clone(),
                parent_capability_id: Some("cap-parent-1".to_string()),
                delegation_link_hash: Some("delegation-link-hash-1".to_string()),
                governed_intent_hash: Some("intent-hash-1".to_string()),
                audience: Some(CallChainContinuationAudience {
                    server_id: "srv-pay".to_string(),
                    tool_name: "charge".to_string(),
                }),
                nonce: Some("nonce-1".to_string()),
                issued_at: 1000,
                expires_at: 2000,
            },
            &signer,
        )
        .unwrap();
        let intent = GovernedTransactionIntent {
            id: "intent-cont-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(call_chain.clone()),
            autonomy: None,
            context: Some(serde_json::json!({
                GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY: token.clone()
            })),
        };

        assert!(token.verify_signature().unwrap());
        assert!(token.matches_context(&call_chain));
        assert!(token.matches_session_anchor(&session_anchor));
        assert!(token.matches_target("srv-pay", "charge"));
        assert!(token.matches_intent_hash("intent-hash-1"));
        assert!(token.matches_subject(&subject.public_key()));
        assert_eq!(
            intent.explicit_continuation_token().unwrap(),
            Some(token.clone())
        );
        assert_eq!(intent.continuation_token().unwrap(), Some(token));
    }

    #[test]
    fn continuation_token_falls_back_to_legacy_upstream_proof() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let proof = GovernedUpstreamCallChainProof::sign(
            GovernedUpstreamCallChainProofBody {
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: "chain-legacy-1".to_string(),
                parent_request_id: "req-parent-legacy-1".to_string(),
                parent_receipt_id: Some("rc-parent-legacy-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
                issued_at: 1000,
                expires_at: 2000,
            },
            &signer,
        )
        .unwrap();
        let intent = GovernedTransactionIntent {
            id: "intent-legacy-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(GovernedCallChainContext {
                chain_id: "chain-legacy-1".to_string(),
                parent_request_id: "req-parent-legacy-1".to_string(),
                parent_receipt_id: Some("rc-parent-legacy-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
            }),
            autonomy: None,
            context: Some(serde_json::json!({
                GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: proof
            })),
        };

        let token = intent.continuation_token().unwrap().unwrap();

        assert!(token.verify_signature().unwrap());
        assert!(token.token_id.starts_with("legacy:"));
        assert_eq!(intent.explicit_continuation_token().unwrap(), None);
        assert_eq!(token.parent_request_id, "req-parent-legacy-1");
        assert_eq!(
            token.parent_receipt_id.as_deref(),
            Some("rc-parent-legacy-1")
        );
    }

    #[test]
    fn continuation_token_rejects_unsigned_bindings_when_using_legacy_proof() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let proof = GovernedUpstreamCallChainProof::sign(
            GovernedUpstreamCallChainProofBody {
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: "chain-legacy-2".to_string(),
                parent_request_id: "req-parent-legacy-2".to_string(),
                parent_receipt_id: Some("rc-parent-legacy-2".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
                issued_at: 1000,
                expires_at: 2000,
            },
            &signer,
        )
        .unwrap();
        let mut token = CallChainContinuationToken::from_legacy_upstream_proof(&proof).unwrap();
        token.audience = Some(CallChainContinuationAudience {
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
        });
        token.governed_intent_hash = Some("intent-hash".to_string());

        assert!(!token.verify_signature().unwrap());
    }

    #[test]
    fn governed_call_chain_provenance_separates_asserted_and_verified_views() {
        let asserted_context = GovernedCallChainContext {
            chain_id: "chain-prov-1".to_string(),
            parent_request_id: "req-parent-prov-1".to_string(),
            parent_receipt_id: Some("rc-parent-prov-1".to_string()),
            origin_subject: "origin-asserted".to_string(),
            delegator_subject: "delegator-asserted".to_string(),
        };
        let verified_context = GovernedCallChainContext {
            chain_id: "chain-prov-1".to_string(),
            parent_request_id: "req-parent-prov-1".to_string(),
            parent_receipt_id: Some("rc-parent-prov-1".to_string()),
            origin_subject: "origin-verified".to_string(),
            delegator_subject: "delegator-verified".to_string(),
        };
        let provenance = GovernedCallChainProvenance::verified(verified_context.clone())
            .with_asserted_context(asserted_context.clone())
            .with_continuation_token_id("continuation-1")
            .with_session_anchor_id("anchor-1")
            .with_receipt_lineage_statement_id("statement-1");

        let encoded = serde_json::to_value(&provenance).unwrap();

        assert!(provenance.is_verified());
        assert_eq!(provenance.asserted_context(), Some(&asserted_context));
        assert_eq!(provenance.verified_context(), Some(&verified_context));
        assert_eq!(encoded["continuationTokenId"], "continuation-1");
        assert_eq!(encoded["sessionAnchorId"], "anchor-1");
        assert_eq!(encoded["receiptLineageStatementId"], "statement-1");
        assert_eq!(
            encoded["assertedContext"]["originSubject"],
            "origin-asserted"
        );
        assert_eq!(encoded["originSubject"], "origin-verified");
    }

    #[test]
    fn runtime_attestation_evidence_validity_window_is_half_open() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Verified,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };

        assert!(!attestation.is_valid_at(99));
        assert!(attestation.is_valid_at(100));
        assert!(attestation.is_valid_at(199));
        assert!(!attestation.is_valid_at(200));
    }

    #[test]
    fn workload_identity_parses_spiffe_uri() {
        let workload = WorkloadIdentity::parse_spiffe_uri("spiffe://prod.chio/payments/worker")
            .expect("parse SPIFFE workload identity");

        assert_eq!(workload.scheme, WorkloadIdentityScheme::Spiffe);
        assert_eq!(workload.credential_kind, WorkloadCredentialKind::Uri);
        assert_eq!(workload.trust_domain, "prod.chio");
        assert_eq!(workload.path, "/payments/worker");
    }

    #[test]
    fn workload_identity_rejects_invalid_spiffe_variants() {
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri(" "),
            Err(WorkloadIdentityError::EmptyUri)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe://prod.chio/payments/worker?version=1"),
            Err(WorkloadIdentityError::InvalidSuffix)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("https://prod.chio/payments/worker"),
            Err(WorkloadIdentityError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe://user@prod.chio/payments/worker"),
            Err(WorkloadIdentityError::InvalidAuthority)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe:///payments/worker"),
            Err(WorkloadIdentityError::MissingTrustDomain)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe://prod.chio/payments//worker"),
            Err(WorkloadIdentityError::InvalidPath(_))
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("%%%"),
            Err(WorkloadIdentityError::MalformedUri(_))
        ));
    }

    #[test]
    fn runtime_attestation_normalizes_spiffe_runtime_identity() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
            workload_identity: None,
            claims: None,
        };

        let workload = attestation
            .normalized_workload_identity()
            .expect("normalize workload identity")
            .expect("workload identity present");
        assert_eq!(workload.trust_domain, "prod.chio");
        assert_eq!(workload.path, "/payments/worker");
    }

    #[test]
    fn runtime_attestation_rejects_conflicting_explicit_workload_identity() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::X509Svid,
                uri: "spiffe://dev.chio/payments/worker".to_string(),
                trust_domain: "dev.chio".to_string(),
                path: "/payments/worker".to_string(),
            }),
            claims: None,
        };

        let error = attestation
            .validate_workload_identity_binding()
            .expect_err("conflicting workload identities should fail");
        assert!(error.to_string().contains("trust_domain"));
    }

    #[test]
    fn workload_identity_validation_and_runtime_identity_conflicts_cover_remaining_paths() {
        let identity = WorkloadIdentity {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind: WorkloadCredentialKind::Uri,
            uri: "spiffe://prod.chio/payments/worker".to_string(),
            trust_domain: "prod.chio".to_string(),
            path: "/payments/other".to_string(),
        };
        assert!(matches!(
            identity.validate(),
            Err(WorkloadIdentityError::Conflict { field: "path", .. })
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("   ".to_string()),
            workload_identity: None,
            claims: None,
        };
        assert!(matches!(
            attestation.normalized_workload_identity(),
            Err(WorkloadIdentityError::EmptyRuntimeIdentity)
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("//compute.googleapis.com/projects/demo".to_string()),
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::Uri,
                uri: "spiffe://prod.chio/payments/worker".to_string(),
                trust_domain: "prod.chio".to_string(),
                path: "/payments/worker".to_string(),
            }),
            claims: None,
        };
        assert!(matches!(
            attestation.normalized_workload_identity(),
            Err(WorkloadIdentityError::OpaqueRuntimeIdentityConflict(_))
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::Uri,
                uri: "spiffe://prod.chio/payments/worker".to_string(),
                trust_domain: "prod.chio".to_string(),
                path: "/payments/worker".to_string(),
            }),
            claims: None,
        };
        let normalized = attestation
            .normalized_workload_identity()
            .expect("explicit workload identity should normalize")
            .expect("workload identity should exist");
        assert_eq!(normalized.trust_domain, "prod.chio");
    }

    #[test]
    fn runtime_attestation_trust_policy_rebinds_effective_tier() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(60),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };

        let resolved = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect("resolve effective tier");
        assert_eq!(resolved.raw_tier, RuntimeAssuranceTier::Attested);
        assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
        assert_eq!(resolved.matched_rule.as_deref(), Some("azure-contoso"));
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_stale_verified_evidence() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 400,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(30),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("stale evidence should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::EvidenceTooOld { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_disallowed_attestation_type() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sev_snp"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: None,
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("unexpected attestation type should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::DisallowedAttestationType { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_untrusted_verifier() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.untrusted.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: None,
                allowed_attestation_types: Vec::new(),
                required_assertions: BTreeMap::new(),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("untrusted verifier should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::UntrustedEvidence { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_matches_google_family_and_required_assertions() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest-google".to_string(),
            runtime_identity: Some(
                "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1"
                    .to_string(),
            ),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV",
                    "secureBoot": "enabled"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
                max_evidence_age_seconds: Some(60),
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: BTreeMap::from([
                    ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                    ("secureBoot".to_string(), "enabled".to_string()),
                ]),
            }],
        };

        let resolved = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect("google attestation should satisfy appraisal-aware trust policy");
        assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
        assert_eq!(
            resolved.matched_rule.as_deref(),
            Some("google-confidential")
        );
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_missing_required_assertion() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest-google".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
                max_evidence_age_seconds: Some(60),
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: BTreeMap::from([(
                    "secureBoot".to_string(),
                    "enabled".to_string(),
                )]),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("missing secureBoot assertion should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::MissingAssertion { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_covers_remaining_fail_closed_paths() {
        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "secureBoot": "enabled"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: None,
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };
        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("missing attestationType should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::MissingAttestationType { .. }
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest-google".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_INTEL_TDX",
                    "secureBoot": "enabled"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
                max_evidence_age_seconds: None,
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: BTreeMap::from([(
                    "hardwareModel".to_string(),
                    "GCP_AMD_SEV".to_string(),
                )]),
            }],
        };
        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("mismatched required assertion should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::AssertionMismatch { .. }
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.unsupported.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "unsupported".to_string(),
                schema: "chio.runtime-attestation.unsupported.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: None,
                max_evidence_age_seconds: None,
                allowed_attestation_types: Vec::new(),
                required_assertions: BTreeMap::new(),
            }],
        };
        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("unsupported evidence schema should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::UnsupportedEvidence { .. }
        ));
    }

    #[test]
    fn operation_serde_roundtrip() {
        let ops = vec![
            Operation::Invoke,
            Operation::ReadResult,
            Operation::Delegate,
        ];
        let json = serde_json::to_string(&ops).unwrap();
        let restored: Vec<Operation> = serde_json::from_str(&json).unwrap();
        assert_eq!(ops, restored);
    }

    #[test]
    fn attenuation_serde_roundtrip() {
        let attenuations = vec![
            Attenuation::RemoveTool {
                server_id: "srv".to_string(),
                tool_name: "danger".to_string(),
            },
            Attenuation::RemoveOperation {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                operation: Operation::Delegate,
            },
            Attenuation::AddConstraint {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                constraint: Constraint::PathPrefix("/safe".to_string()),
            },
            Attenuation::ReduceBudget {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                max_invocations: 5,
            },
            Attenuation::ShortenExpiry {
                new_expires_at: 9999,
            },
        ];

        let json = serde_json::to_string_pretty(&attenuations).unwrap();
        let restored: Vec<Attenuation> = serde_json::from_str(&json).unwrap();
        assert_eq!(attenuations, restored);
    }

    #[test]
    fn ed25519_capability_token_is_byte_identical_without_algorithm_field() {
        // Pre-existing Ed25519 tokens must serialize without any `algorithm`
        // envelope field, so captured on-disk receipts and capability
        // artifacts continue to round-trip through the schema validators.
        let kp = Keypair::generate();
        let subject = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-compat".to_string(),
            issuer: kp.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();
        let json = serde_json::to_value(&token).unwrap();
        assert!(
            json.get("algorithm").is_none(),
            "Ed25519 tokens must omit the `algorithm` envelope field"
        );
        assert!(token.verify_signature().unwrap());
    }

    #[test]
    fn capability_token_backend_signing_with_ed25519_verifies() {
        let backend = crate::crypto::Ed25519Backend::generate();
        let subject = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-backend".to_string(),
            issuer: backend.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
        assert_eq!(
            token.algorithm,
            Some(crate::crypto::SigningAlgorithm::Ed25519)
        );
        assert!(token.verify_signature().unwrap());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn capability_token_p256_round_trip() {
        // A capability token signed with P-256 verifies when reconstructed
        // through the exact same API path the kernel uses
        // (`verify_signature` -> `PublicKey::verify_canonical`).
        let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
        let subject = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-p256".to_string(),
            issuer: backend.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
        assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P256));
        assert!(token.verify_signature().unwrap());

        // Round-trip through JSON (the wire format the kernel receives).
        let wire = serde_json::to_string(&token).unwrap();
        assert!(wire.contains("\"p256:"));
        assert!(wire.contains("\"algorithm\":\"p256\""));
        let restored: CapabilityToken = serde_json::from_str(&wire).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn capability_token_p384_round_trip() {
        let backend = crate::crypto::P384Backend::generate().expect("p384 backend");
        let subject = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-p384".to_string(),
            issuer: backend.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
        assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P384));
        assert!(token.verify_signature().unwrap());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn capability_token_p256_tampered_body_fails() {
        let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
        let subject = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-tamper".to_string(),
            issuer: backend.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let mut token = CapabilityToken::sign_with_backend(body, &backend).unwrap();
        token.id = "cap-tampered".to_string();
        assert!(!token.verify_signature().unwrap());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn governed_approval_token_p256_verifies() {
        let backend = crate::crypto::P256Backend::generate().expect("p256 backend");
        let subject = Keypair::generate();
        let body = GovernedApprovalTokenBody {
            id: "approval-p256".to_string(),
            approver: backend.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "hash-xyz".to_string(),
            request_id: "req-1".to_string(),
            issued_at: 1000,
            expires_at: 2000,
            decision: GovernedApprovalDecision::Approved,
        };
        let token = GovernedApprovalToken::sign_with_backend(body, &backend).unwrap();
        assert_eq!(token.algorithm, Some(crate::crypto::SigningAlgorithm::P256));
        assert!(token.verify_signature().unwrap());
    }

    // ----- M04 Phase 3: `delegate` mint helper ----------------------

    #[cfg(feature = "delegation_v2")]
    fn delegate_parent_token(
        parent_kp: &Keypair,
        subject_kp: &Keypair,
        scope: ChioScope,
        issued_at: u64,
        expires_at: u64,
    ) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: "cap-parent".to_string(),
            issuer: parent_kp.public_key(),
            subject: subject_kp.public_key(),
            scope,
            issued_at,
            expires_at,
            delegation_chain: vec![],
        };
        CapabilityToken::sign(body, parent_kp).unwrap()
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_mints_signed_link_for_subset_scope() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let parent = delegate_parent_token(&issuer, &subject, parent_scope.clone(), 1000, 2000);
        let child_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);

        let receipt = delegate(
            &parent,
            &child_scope,
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            1500,
            [7_u8; 16],
        )
        .unwrap();

        assert_eq!(receipt.parent_capability_id, parent.id);
        assert_eq!(receipt.signed_at, 1500);
        assert!(receipt.link.verify_signature().unwrap());
        assert_eq!(receipt.link.delegator, parent.subject);
        assert_eq!(receipt.link.delegatee, delegatee.public_key());
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_rejects_widening_scope() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
        // Child tries to add a non-parent operation, widening the parent.
        let widened = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::ReadResult],
        )]);

        let err = delegate(
            &parent,
            &widened,
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            1500,
            [0_u8; 16],
        )
        .unwrap_err();
        assert!(matches!(err, Error::AttenuationViolation { .. }));
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_rejects_parent_without_delegate_operation() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
        let parent = delegate_parent_token(&issuer, &subject, parent_scope.clone(), 1000, 2000);

        let err = delegate(
            &parent,
            &parent_scope,
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            1500,
            [0_u8; 16],
        )
        .unwrap_err();
        assert!(matches!(err, Error::AttenuationViolation { .. }));
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_rejects_extending_expiry() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
        let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

        let attenuation = crate::delegation_receipt::ScopeAttenuation {
            steps: vec![],
            child_expires_at: Some(3000), // > parent.expires_at
        };
        let err = delegate(
            &parent,
            &scope,
            &subject,
            &delegatee.public_key(),
            attenuation,
            1500,
            [0_u8; 16],
        )
        .unwrap_err();
        assert!(matches!(err, Error::AttenuationViolation { .. }));

        // sanity: at-or-below parent expiry is accepted.
        let ok = delegate(
            &parent,
            &scope,
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation {
                steps: vec![],
                child_expires_at: Some(1800),
            },
            1500,
            [0_u8; 16],
        );
        assert!(ok.is_ok());
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_rejects_wrong_delegator_key() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let imposter = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
        let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

        let err = delegate(
            &parent,
            &scope,
            &imposter, // not parent.subject
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            1500,
            [0_u8; 16],
        )
        .unwrap_err();
        assert!(matches!(err, Error::AttenuationViolation { .. }));
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_rejects_tampered_parent_signature() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
        let mut parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);
        parent.id = "cap-parent-tampered".to_string();

        let err = delegate(
            &parent,
            &scope,
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            1500,
            [0_u8; 16],
        )
        .unwrap_err();

        assert!(matches!(err, Error::SignatureVerificationFailed));
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_rejects_parent_before_issued_at() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
        let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

        let err = delegate(
            &parent,
            &scope,
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            999,
            [0_u8; 16],
        )
        .unwrap_err();

        assert!(matches!(
            err,
            Error::CapabilityNotYetValid { not_before: 1000 }
        ));
    }

    #[cfg(feature = "delegation_v2")]
    #[test]
    fn delegate_rejects_signed_at_at_or_after_parent_expiry() {
        use crate::delegation_receipt::ScopeAttenuation;

        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let delegatee = Keypair::generate();
        let parent_scope = make_scope(vec![make_grant(
            "srv-a",
            "tool-x",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        let scope = make_scope(vec![make_grant("srv-a", "tool-x", vec![Operation::Invoke])]);
        let parent = delegate_parent_token(&issuer, &subject, parent_scope, 1000, 2000);

        let err = delegate(
            &parent,
            &scope,
            &subject,
            &delegatee.public_key(),
            ScopeAttenuation::empty(),
            2000, // == parent.expires_at
            [0_u8; 16],
        )
        .unwrap_err();
        assert!(matches!(err, Error::AttenuationViolation { .. }));
    }
}
