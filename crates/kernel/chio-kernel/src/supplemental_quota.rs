//! Verification boundary for supplemental invocation quotas.
//!
//! The kernel treats supplemental authorization artifacts as opaque bytes. A
//! trusted verifier installed by the runtime composition root parses and
//! verifies those bytes, then returns a request-bound claim. The kernel checks
//! every request binding again before exposing a quota owner or maximum.

use serde::Serialize;
use std::sync::Arc;

use chio_core::capability::features::CapabilityNegotiation;
use chio_core::crypto::PublicKey;

use crate::{canonical_json_bytes, sha256_hex};

/// The only supplemental invocation-quota profile supported by v1.
pub const BROKER_CAPABILITY_EXECUTION_PROFILE: &str = "chio.broker-capability-execution.v1";

pub const MAX_SUPPLEMENTAL_AUTHORIZATION_BYTES: usize = 64 * 1024;
pub const MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES: usize = 8 * 1024;
pub const MAX_SUPPLEMENTAL_CLAIM_FIELD_BYTES: usize = 1024;
pub const MAX_SUPPLEMENTAL_NEGOTIATED_FEATURES: usize = 32;
pub const MAX_SUPPLEMENTAL_REVOCATION_IDS: usize = 64;
pub const MAX_SUPPLEMENTAL_REVOCATION_ID_BYTES: usize = 512;
pub const MAX_ADMISSION_REVOCATION_IDS: usize = 256;

const SUPPLEMENTAL_REQUEST_BINDING_DOMAIN: &str = "chio.supplemental-quota-request-binding.v1";
const ADMISSION_REVOCATION_SET_DOMAIN: &str = "chio.admission-revocation-set.v1";

/// Request facts supplied by the kernel, never by the supplemental artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplementalQuotaVerificationContext {
    pub capability_id: String,
    pub capability_digest: String,
    /// Digest of the authenticated request namespace used for replay identity.
    pub request_namespace_digest: String,
    /// Deterministic durable admission-operation identifier for this request.
    pub operation_id: String,
    pub subject: PublicKey,
    pub request_id: String,
    pub normalized_destination: String,
    /// Lowercase SHA-256 hex over canonical JSON for the complete normalized,
    /// uncredentialed request arguments. The normalized value must include
    /// every behavior-affecting method, path, query, header, body, and execution
    /// option exposed by the adapter.
    pub arguments_hash: String,
    pub negotiated_profile: String,
    pub negotiated_features: CapabilityNegotiation,
    /// Identity and configuration pinned by the runtime composition root.
    pub verifier_binding: SupplementalQuotaVerifierBinding,
}

/// Runtime evidence identifying the installed supplemental verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplementalQuotaVerifierBinding {
    pub verifier_identity: String,
    pub configuration_digest: String,
}

impl SupplementalQuotaVerifierBinding {
    /// Validate composition-root identity before accepting requests.
    pub fn validate(&self) -> Result<(), SupplementalQuotaError> {
        if self.verifier_identity.is_empty() {
            return Err(SupplementalQuotaError::EmptyContextField(
                "verifier_identity",
            ));
        }
        if self.configuration_digest.is_empty() {
            return Err(SupplementalQuotaError::EmptyContextField(
                "verifier_configuration_digest",
            ));
        }
        ensure_bounded(
            "verifier_identity",
            self.verifier_identity.len(),
            MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES,
        )?;
        ensure_bounded(
            "verifier_configuration_digest",
            self.configuration_digest.len(),
            MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES,
        )?;
        ensure_sha256_hex("verifier_configuration_digest", &self.configuration_digest)
    }
}

/// A claim returned by an installed trusted supplemental verifier.
///
/// This value is not admission authority by itself. The kernel accepts it only
/// as the immediate result of its composition-installed verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSupplementalQuotaClaim {
    pub profile: String,
    pub broker_capability_id: String,
    pub issuer: PublicKey,
    pub request_constraint_digest: String,
    pub max_invocations: u32,
    pub authorization_artifact_digest: String,
    pub supplemental_revocation_ids: Vec<String>,
    pub expires_at: u64,
    pub request_binding_hash: String,
    pub capability_id: String,
    pub capability_digest: String,
    pub request_namespace_digest: String,
    pub operation_id: String,
    pub subject: PublicKey,
    pub request_id: String,
    pub normalized_destination: String,
    pub arguments_hash: String,
    pub negotiated_features: CapabilityNegotiation,
}

/// A supplemental claim rechecked and bound by the kernel.
///
/// Fields are private so request handling cannot substitute a caller-built
/// quota key or maximum after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct KernelVerifiedSupplementalQuotaClaim {
    profile: String,
    owner_id: String,
    broker_capability_id: String,
    max_invocations: u32,
    authorization_artifact_digest: String,
    supplemental_revocation_ids: Vec<String>,
    expires_at: u64,
    request_binding_hash: String,
    capability_id: String,
    capability_digest: String,
    request_namespace_digest: String,
    operation_id: String,
    verifier_binding: SupplementalQuotaVerifierBinding,
}

#[allow(dead_code)]
impl KernelVerifiedSupplementalQuotaClaim {
    #[must_use]
    pub(crate) fn profile(&self) -> &str {
        &self.profile
    }

    #[must_use]
    pub(crate) fn owner_id(&self) -> &str {
        &self.owner_id
    }

    #[must_use]
    pub(crate) fn broker_capability_id(&self) -> &str {
        &self.broker_capability_id
    }

    #[must_use]
    pub(crate) fn max_invocations(&self) -> u32 {
        self.max_invocations
    }

    #[must_use]
    pub(crate) fn authorization_artifact_digest(&self) -> &str {
        &self.authorization_artifact_digest
    }

    #[must_use]
    pub(crate) fn supplemental_revocation_ids(&self) -> &[String] {
        &self.supplemental_revocation_ids
    }

    #[must_use]
    pub(crate) fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub(crate) fn request_binding_hash(&self) -> &str {
        &self.request_binding_hash
    }

    #[must_use]
    pub(crate) fn capability_id(&self) -> &str {
        &self.capability_id
    }

    #[must_use]
    pub(crate) fn capability_digest(&self) -> &str {
        &self.capability_digest
    }

    #[must_use]
    pub(crate) fn request_namespace_digest(&self) -> &str {
        &self.request_namespace_digest
    }

    #[must_use]
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub(crate) fn verifier_binding(&self) -> &SupplementalQuotaVerifierBinding {
        &self.verifier_binding
    }
}

/// Error returned by an installed supplemental verifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SupplementalQuotaVerifierError {
    message: String,
}

impl SupplementalQuotaVerifierError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Trusted extension point installed by the runtime composition root.
pub trait SupplementalQuotaVerifier: Send + Sync {
    /// Verify the opaque signed extension against the kernel-built context.
    fn verify(
        &self,
        signed_extension: &[u8],
        context: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaim, SupplementalQuotaVerifierError>;
}

pub(crate) struct SupplementalQuotaVerifierRuntime {
    verifier: Arc<dyn SupplementalQuotaVerifier>,
    binding: SupplementalQuotaVerifierBinding,
}

impl SupplementalQuotaVerifierRuntime {
    pub(crate) fn new(
        verifier: Arc<dyn SupplementalQuotaVerifier>,
        binding: SupplementalQuotaVerifierBinding,
    ) -> Result<Self, SupplementalQuotaError> {
        binding.validate()?;
        Ok(Self { verifier, binding })
    }

    pub(crate) fn verifier(&self) -> &dyn SupplementalQuotaVerifier {
        self.verifier.as_ref()
    }

    pub(crate) fn binding(&self) -> &SupplementalQuotaVerifierBinding {
        &self.binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SupplementalQuotaError {
    #[error("supplemental authorization requires an installed verifier")]
    MissingVerifier,
    #[error("supplemental authorization bytes are empty")]
    EmptyAuthorization,
    #[error("unsupported supplemental quota profile: {0}")]
    UnknownProfile(String),
    #[error("supplemental quota profile was not negotiated: {0}")]
    ProfileNotNegotiated(String),
    #[error("supplemental quota verifier denied the artifact: {0}")]
    VerifierRejected(#[from] SupplementalQuotaVerifierError),
    #[error("supplemental quota context field is empty: {0}")]
    EmptyContextField(&'static str),
    #[error("supplemental quota verifier result does not match context field: {0}")]
    ContextMismatch(&'static str),
    #[error("supplemental quota authorization artifact digest does not match")]
    ArtifactDigestMismatch,
    #[error("supplemental quota request binding does not match")]
    RequestBindingMismatch,
    #[error("supplemental quota verifier result field is empty: {0}")]
    EmptyClaimField(&'static str),
    #[error("supplemental quota field {field} has size {actual}, maximum is {maximum}")]
    LimitExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("supplemental quota field is not lowercase SHA-256 hex: {0}")]
    InvalidSha256Digest(&'static str),
    #[error("invalid negotiated supplemental quota features: {0}")]
    InvalidNegotiatedFeatures(String),
    #[error("supplemental quota expired at {expires_at}; current time is {now}")]
    Expired { expires_at: u64, now: u64 },
    #[error("revocation id is empty")]
    EmptyRevocationId,
    #[error("admission revocation set is empty")]
    EmptyRevocationSet,
    #[error("duplicate revocation id: {0}")]
    DuplicateRevocationId(String),
    #[error("broker supplemental quota requires at least one revocation id")]
    EmptySupplementalRevocationIds,
    #[error("revocation ids are not in canonical sorted order")]
    RevocationIdsNotCanonical,
    #[error("presented revocation-set digest does not match its ids")]
    RevocationDigestMismatch,
    #[error("presented revocation set does not match the admission-bound set")]
    RevocationSetMismatch,
    #[error("canonical serialization failed: {0}")]
    Canonicalization(String),
}

#[derive(Serialize)]
struct SupplementalRequestBinding<'a> {
    capability_id: &'a str,
    capability_digest: &'a str,
    request_namespace_digest: &'a str,
    operation_id: &'a str,
    subject: &'a PublicKey,
    request_id: &'a str,
    normalized_destination: &'a str,
    arguments_hash: &'a str,
    negotiated_profile: &'a str,
    negotiated_features: &'a CapabilityNegotiation,
    verifier_identity: &'a str,
    verifier_configuration_digest: &'a str,
}

#[derive(Serialize)]
struct BrokerQuotaOwnerBinding<'a> {
    broker_capability_id: &'a str,
    issuer: &'a PublicKey,
    normalized_destination: &'a str,
    request_constraint_digest: &'a str,
}

fn domain_separated_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, SupplementalQuotaError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| SupplementalQuotaError::Canonicalization(error.to_string()))?;
    let mut message = Vec::with_capacity(domain.len() + 1 + canonical.len());
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(&canonical);
    Ok(sha256_hex(&message))
}

/// Hash the opaque authorization artifact exactly as received by the kernel.
#[must_use]
pub fn supplemental_authorization_artifact_digest(signed_extension: &[u8]) -> String {
    sha256_hex(signed_extension)
}

/// Compute the request binding that a trusted verifier must return.
pub fn supplemental_request_binding_hash(
    context: &SupplementalQuotaVerificationContext,
) -> Result<String, SupplementalQuotaError> {
    domain_separated_digest(
        SUPPLEMENTAL_REQUEST_BINDING_DOMAIN,
        &SupplementalRequestBinding {
            capability_id: &context.capability_id,
            capability_digest: &context.capability_digest,
            request_namespace_digest: &context.request_namespace_digest,
            operation_id: &context.operation_id,
            subject: &context.subject,
            request_id: &context.request_id,
            normalized_destination: &context.normalized_destination,
            arguments_hash: &context.arguments_hash,
            negotiated_profile: &context.negotiated_profile,
            negotiated_features: &context.negotiated_features,
            verifier_identity: &context.verifier_binding.verifier_identity,
            verifier_configuration_digest: &context.verifier_binding.configuration_digest,
        },
    )
}

/// Derive the broker quota owner without accepting a caller-provided key.
pub(crate) fn derive_broker_quota_owner_id(
    broker_capability_id: &str,
    issuer: &PublicKey,
    normalized_destination: &str,
    request_constraint_digest: &str,
) -> Result<String, SupplementalQuotaError> {
    domain_separated_digest(
        BROKER_CAPABILITY_EXECUTION_PROFILE,
        &BrokerQuotaOwnerBinding {
            broker_capability_id,
            issuer,
            normalized_destination,
            request_constraint_digest,
        },
    )
}

fn ensure_nonempty_context(
    context: &SupplementalQuotaVerificationContext,
) -> Result<(), SupplementalQuotaError> {
    for (name, value) in [
        ("capability_id", context.capability_id.as_str()),
        ("capability_digest", context.capability_digest.as_str()),
        (
            "request_namespace_digest",
            context.request_namespace_digest.as_str(),
        ),
        ("operation_id", context.operation_id.as_str()),
        ("request_id", context.request_id.as_str()),
        (
            "normalized_destination",
            context.normalized_destination.as_str(),
        ),
        ("arguments_hash", context.arguments_hash.as_str()),
        ("negotiated_profile", context.negotiated_profile.as_str()),
        (
            "verifier_identity",
            context.verifier_binding.verifier_identity.as_str(),
        ),
        (
            "verifier_configuration_digest",
            context.verifier_binding.configuration_digest.as_str(),
        ),
    ] {
        if value.is_empty() {
            return Err(SupplementalQuotaError::EmptyContextField(name));
        }
    }
    Ok(())
}

fn ensure_bounded(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), SupplementalQuotaError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(SupplementalQuotaError::LimitExceeded {
            field,
            actual,
            maximum,
        })
    }
}

fn ensure_sha256_hex(field: &'static str, value: &str) -> Result<(), SupplementalQuotaError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(SupplementalQuotaError::InvalidSha256Digest(field))
    }
}

fn ensure_negotiated_features(
    features: &CapabilityNegotiation,
) -> Result<(), SupplementalQuotaError> {
    ensure_bounded(
        "negotiated_features",
        features.features.len(),
        MAX_SUPPLEMENTAL_NEGOTIATED_FEATURES,
    )?;
    features
        .validate()
        .map_err(|error| SupplementalQuotaError::InvalidNegotiatedFeatures(error.to_string()))
}

fn ensure_context_bounds(
    context: &SupplementalQuotaVerificationContext,
) -> Result<(), SupplementalQuotaError> {
    for (field, value) in [
        ("capability_id", context.capability_id.as_str()),
        ("capability_digest", context.capability_digest.as_str()),
        (
            "request_namespace_digest",
            context.request_namespace_digest.as_str(),
        ),
        ("operation_id", context.operation_id.as_str()),
        ("request_id", context.request_id.as_str()),
        (
            "normalized_destination",
            context.normalized_destination.as_str(),
        ),
        ("arguments_hash", context.arguments_hash.as_str()),
        ("negotiated_profile", context.negotiated_profile.as_str()),
        (
            "verifier_identity",
            context.verifier_binding.verifier_identity.as_str(),
        ),
        (
            "verifier_configuration_digest",
            context.verifier_binding.configuration_digest.as_str(),
        ),
    ] {
        ensure_bounded(field, value.len(), MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES)?;
    }
    for (field, value) in [
        ("capability_digest", context.capability_digest.as_str()),
        (
            "request_namespace_digest",
            context.request_namespace_digest.as_str(),
        ),
        ("operation_id", context.operation_id.as_str()),
        ("arguments_hash", context.arguments_hash.as_str()),
        (
            "verifier_configuration_digest",
            context.verifier_binding.configuration_digest.as_str(),
        ),
    ] {
        ensure_sha256_hex(field, value)?;
    }
    ensure_negotiated_features(&context.negotiated_features)
}

fn ensure_claim_bounds(
    claim: &VerifiedSupplementalQuotaClaim,
) -> Result<(), SupplementalQuotaError> {
    for (name, value) in [
        ("broker_capability_id", claim.broker_capability_id.as_str()),
        (
            "request_constraint_digest",
            claim.request_constraint_digest.as_str(),
        ),
    ] {
        if value.is_empty() {
            return Err(SupplementalQuotaError::EmptyClaimField(name));
        }
    }
    for (field, value) in [
        ("profile", claim.profile.as_str()),
        ("broker_capability_id", claim.broker_capability_id.as_str()),
        (
            "request_constraint_digest",
            claim.request_constraint_digest.as_str(),
        ),
        (
            "authorization_artifact_digest",
            claim.authorization_artifact_digest.as_str(),
        ),
        ("request_binding_hash", claim.request_binding_hash.as_str()),
    ] {
        ensure_bounded(field, value.len(), MAX_SUPPLEMENTAL_CLAIM_FIELD_BYTES)?;
    }
    for (field, value) in [
        ("capability_id", claim.capability_id.as_str()),
        ("capability_digest", claim.capability_digest.as_str()),
        (
            "request_namespace_digest",
            claim.request_namespace_digest.as_str(),
        ),
        ("operation_id", claim.operation_id.as_str()),
        ("request_id", claim.request_id.as_str()),
        (
            "normalized_destination",
            claim.normalized_destination.as_str(),
        ),
        ("arguments_hash", claim.arguments_hash.as_str()),
    ] {
        ensure_bounded(field, value.len(), MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES)?;
    }
    ensure_bounded(
        "supplemental_revocation_ids",
        claim.supplemental_revocation_ids.len(),
        MAX_SUPPLEMENTAL_REVOCATION_IDS,
    )?;
    for id in &claim.supplemental_revocation_ids {
        ensure_bounded(
            "supplemental_revocation_id",
            id.len(),
            MAX_SUPPLEMENTAL_REVOCATION_ID_BYTES,
        )?;
    }
    for (field, value) in [
        (
            "request_constraint_digest",
            claim.request_constraint_digest.as_str(),
        ),
        (
            "authorization_artifact_digest",
            claim.authorization_artifact_digest.as_str(),
        ),
        ("request_binding_hash", claim.request_binding_hash.as_str()),
        ("capability_digest", claim.capability_digest.as_str()),
        (
            "request_namespace_digest",
            claim.request_namespace_digest.as_str(),
        ),
        ("operation_id", claim.operation_id.as_str()),
        ("arguments_hash", claim.arguments_hash.as_str()),
    ] {
        ensure_sha256_hex(field, value)?;
    }
    ensure_negotiated_features(&claim.negotiated_features)
}

fn ensure_supported_profile(profile: &str) -> Result<(), SupplementalQuotaError> {
    if profile == BROKER_CAPABILITY_EXECUTION_PROFILE {
        Ok(())
    } else {
        Err(SupplementalQuotaError::UnknownProfile(profile.to_string()))
    }
}

fn ensure_context_match(
    field: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), SupplementalQuotaError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SupplementalQuotaError::ContextMismatch(field))
    }
}

/// Verify an opaque supplemental authorization and bind it to one request.
///
/// Missing verifier support and every mismatch deny before a quota claim can
/// reach the budget authority.
#[allow(dead_code)]
pub(crate) fn verify_supplemental_quota(
    verifier: Option<&dyn SupplementalQuotaVerifier>,
    signed_extension: &[u8],
    context: &SupplementalQuotaVerificationContext,
    now: u64,
) -> Result<KernelVerifiedSupplementalQuotaClaim, SupplementalQuotaError> {
    let verifier = verifier.ok_or(SupplementalQuotaError::MissingVerifier)?;
    if signed_extension.is_empty() {
        return Err(SupplementalQuotaError::EmptyAuthorization);
    }
    ensure_bounded(
        "signed_extension",
        signed_extension.len(),
        MAX_SUPPLEMENTAL_AUTHORIZATION_BYTES,
    )?;
    ensure_nonempty_context(context)?;
    ensure_context_bounds(context)?;
    ensure_supported_profile(&context.negotiated_profile)?;
    if !context
        .negotiated_features
        .supports(&context.negotiated_profile)
    {
        return Err(SupplementalQuotaError::ProfileNotNegotiated(
            context.negotiated_profile.clone(),
        ));
    }

    let claim = verifier.verify(signed_extension, context)?;
    ensure_claim_bounds(&claim)?;
    ensure_supported_profile(&claim.profile)?;
    ensure_context_match("profile", &claim.profile, &context.negotiated_profile)?;
    ensure_context_match(
        "capability_id",
        &claim.capability_id,
        &context.capability_id,
    )?;
    ensure_context_match(
        "capability_digest",
        &claim.capability_digest,
        &context.capability_digest,
    )?;
    ensure_context_match(
        "request_namespace_digest",
        &claim.request_namespace_digest,
        &context.request_namespace_digest,
    )?;
    ensure_context_match("operation_id", &claim.operation_id, &context.operation_id)?;
    if claim.subject != context.subject {
        return Err(SupplementalQuotaError::ContextMismatch("subject"));
    }
    ensure_context_match("request_id", &claim.request_id, &context.request_id)?;
    ensure_context_match(
        "normalized_destination",
        &claim.normalized_destination,
        &context.normalized_destination,
    )?;
    ensure_context_match(
        "arguments_hash",
        &claim.arguments_hash,
        &context.arguments_hash,
    )?;
    if claim.negotiated_features != context.negotiated_features {
        return Err(SupplementalQuotaError::ContextMismatch(
            "negotiated_features",
        ));
    }

    if claim.expires_at <= now {
        return Err(SupplementalQuotaError::Expired {
            expires_at: claim.expires_at,
            now,
        });
    }
    if claim.authorization_artifact_digest
        != supplemental_authorization_artifact_digest(signed_extension)
    {
        return Err(SupplementalQuotaError::ArtifactDigestMismatch);
    }
    if claim.request_binding_hash != supplemental_request_binding_hash(context)? {
        return Err(SupplementalQuotaError::RequestBindingMismatch);
    }
    let expected_owner_id = derive_broker_quota_owner_id(
        &claim.broker_capability_id,
        &claim.issuer,
        &context.normalized_destination,
        &claim.request_constraint_digest,
    )?;
    if claim.supplemental_revocation_ids.is_empty() {
        return Err(SupplementalQuotaError::EmptySupplementalRevocationIds);
    }
    validate_canonical_revocation_ids(&claim.supplemental_revocation_ids)?;

    Ok(KernelVerifiedSupplementalQuotaClaim {
        profile: claim.profile,
        owner_id: expected_owner_id,
        broker_capability_id: claim.broker_capability_id,
        max_invocations: claim.max_invocations,
        authorization_artifact_digest: claim.authorization_artifact_digest,
        supplemental_revocation_ids: claim.supplemental_revocation_ids,
        expires_at: claim.expires_at,
        request_binding_hash: claim.request_binding_hash,
        capability_id: claim.capability_id,
        capability_digest: claim.capability_digest,
        request_namespace_digest: claim.request_namespace_digest,
        operation_id: claim.operation_id,
        verifier_binding: context.verifier_binding.clone(),
    })
}

/// Combine one rechecked supplemental claim with the capability lineage that
/// the kernel validated for the same request.
#[allow(dead_code)]
pub(crate) fn canonical_revocation_set_for_verified_claim(
    leaf_capability_id: &str,
    ancestor_capability_ids: &[String],
    claim: &KernelVerifiedSupplementalQuotaClaim,
) -> Result<CanonicalRevocationSet, SupplementalQuotaError> {
    ensure_context_match("capability_id", leaf_capability_id, claim.capability_id())?;
    let total_ids = 1usize
        .checked_add(ancestor_capability_ids.len())
        .and_then(|count| count.checked_add(claim.supplemental_revocation_ids().len()))
        .ok_or(SupplementalQuotaError::LimitExceeded {
            field: "admission_revocation_ids",
            actual: usize::MAX,
            maximum: MAX_ADMISSION_REVOCATION_IDS,
        })?;
    ensure_bounded(
        "admission_revocation_ids",
        total_ids,
        MAX_ADMISSION_REVOCATION_IDS,
    )?;

    let mut ids = Vec::with_capacity(total_ids);
    ids.push(leaf_capability_id.to_string());
    ids.extend_from_slice(ancestor_capability_ids);
    ids.extend_from_slice(claim.supplemental_revocation_ids());
    CanonicalRevocationSet::canonicalize(ids)
}

/// The exact sorted revocation identifiers bound into an admission operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRevocationSet {
    ids: Vec<String>,
    digest: String,
}

impl CanonicalRevocationSet {
    /// Sort and bind a set of revocation identifiers by UTF-8 byte order.
    ///
    /// This constructor proves canonicality and digest integrity only. It does
    /// not prove that the caller supplied a complete capability lineage.
    pub fn canonicalize(mut ids: Vec<String>) -> Result<Self, SupplementalQuotaError> {
        if ids.is_empty() {
            return Err(SupplementalQuotaError::EmptyRevocationSet);
        }
        ensure_bounded(
            "admission_revocation_ids",
            ids.len(),
            MAX_ADMISSION_REVOCATION_IDS,
        )?;
        for id in &ids {
            ensure_bounded(
                "admission_revocation_id",
                id.len(),
                MAX_SUPPLEMENTAL_REVOCATION_ID_BYTES,
            )?;
        }
        if ids.iter().any(String::is_empty) {
            return Err(SupplementalQuotaError::EmptyRevocationId);
        }
        ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if let Some(duplicate) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(SupplementalQuotaError::DuplicateRevocationId(
                duplicate[0].clone(),
            ));
        }
        let digest = domain_separated_digest(ADMISSION_REVOCATION_SET_DOMAIN, &ids)?;
        Ok(Self { ids, digest })
    }

    /// Reconstruct a persisted or transported canonical set after checking its
    /// order, bounds, uniqueness, and digest. This does not prove semantic
    /// completeness of the identifiers.
    pub fn from_canonical_parts(
        ids: Vec<String>,
        digest: String,
    ) -> Result<Self, SupplementalQuotaError> {
        if ids.is_empty() {
            return Err(SupplementalQuotaError::EmptyRevocationSet);
        }
        ensure_bounded(
            "admission_revocation_ids",
            ids.len(),
            MAX_ADMISSION_REVOCATION_IDS,
        )?;
        for id in &ids {
            ensure_bounded(
                "admission_revocation_id",
                id.len(),
                MAX_SUPPLEMENTAL_REVOCATION_ID_BYTES,
            )?;
        }
        ensure_sha256_hex("admission_revocation_digest", &digest)?;
        validate_canonical_revocation_ids(&ids)?;
        if domain_separated_digest(ADMISSION_REVOCATION_SET_DOMAIN, &ids)? != digest {
            return Err(SupplementalQuotaError::RevocationDigestMismatch);
        }
        Ok(Self { ids, digest })
    }

    #[must_use]
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Recheck an exact capture-time presentation against the admission-bound
    /// set. The caller must present canonical order and the matching digest.
    pub fn verify_exact(
        &self,
        presented_ids: &[String],
        presented_digest: &str,
    ) -> Result<(), SupplementalQuotaError> {
        ensure_sha256_hex("admission_revocation_digest", presented_digest)?;
        ensure_bounded(
            "admission_revocation_ids",
            presented_ids.len(),
            MAX_ADMISSION_REVOCATION_IDS,
        )?;
        for id in presented_ids {
            ensure_bounded(
                "admission_revocation_id",
                id.len(),
                MAX_SUPPLEMENTAL_REVOCATION_ID_BYTES,
            )?;
        }
        validate_canonical_revocation_ids(presented_ids)?;
        let expected_presented_digest =
            domain_separated_digest(ADMISSION_REVOCATION_SET_DOMAIN, &presented_ids)?;
        if presented_digest != expected_presented_digest {
            return Err(SupplementalQuotaError::RevocationDigestMismatch);
        }
        if presented_ids != self.ids || presented_digest != self.digest {
            return Err(SupplementalQuotaError::RevocationSetMismatch);
        }
        Ok(())
    }
}

fn validate_canonical_revocation_ids(ids: &[String]) -> Result<(), SupplementalQuotaError> {
    if ids.iter().any(String::is_empty) {
        return Err(SupplementalQuotaError::EmptyRevocationId);
    }
    for pair in ids.windows(2) {
        if pair[0] == pair[1] {
            return Err(SupplementalQuotaError::DuplicateRevocationId(
                pair[0].clone(),
            ));
        }
        if pair[0].as_bytes() > pair[1].as_bytes() {
            return Err(SupplementalQuotaError::RevocationIdsNotCanonical);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "supplemental_quota_tests.rs"]
mod tests;
