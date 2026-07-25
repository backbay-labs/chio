use super::*;

pub const FINANCIAL_CROSS_ISSUER_TRUST_PACK_SCHEMA_V1: &str = "chio.financial.cross-issuer-trust-pack.v1";
pub const FINANCIAL_ENTRY_ACTIVATION_DECISION_SCHEMA_V1: &str =
    "chio.financial.cross-issuer-entry-activation-decision.v1";
pub const FINANCIAL_CROSS_ISSUER_MIGRATION_SCHEMA_V1: &str = "chio.financial.cross-issuer-migration.v1";
pub const FINANCIAL_LEGACY_CREDENTIAL_ISSUANCE_ANCHOR_SCHEMA_V1: &str =
    "chio.financial.legacy-credential-issuance-anchor.v1";
pub const FINANCIAL_ISSUER_LIFECYCLE_CHECKPOINT_SCHEMA_V1: &str = "chio.financial.cross-issuer.lifecycle-checkpoint.v1";
pub const FINANCIAL_CROSS_ISSUER_LIFECYCLE_RESULT_SCHEMA_V1: &str = "chio.financial.cross-issuer.lifecycle-result.v1";
pub const FINANCIAL_ISSUER_LIFECYCLE_GENERATION_PIN_SCHEMA_V1: &str =
    "chio.financial.cross-issuer.lifecycle-generation-pin.v1";
pub const FINANCIAL_LIFECYCLE_CHECKPOINT_PIN_SCHEMA_V1: &str =
    "chio.financial.cross-issuer.lifecycle-checkpoint-pin.v1";

const FINANCIAL_POLICY_DIGEST_DOMAIN: &[u8] = b"chio.fincred.verifier-policy-digest.v1\0";
const ENTRY_ACTIVATION_DIGEST_DOMAIN: &[u8] = b"chio.financial.cross-issuer.entry-activation-digest.v1\0";
const CROSS_ISSUER_MIGRATION_DIGEST_DOMAIN: &[u8] = b"chio.financial.cross-issuer.migration-digest.v1\0";
const LEGACY_ISSUANCE_ANCHOR_DIGEST_DOMAIN: &[u8] =
    b"chio.financial.legacy-credential.issuance-anchor-digest.v1\0";
const LIFECYCLE_RESULT_DIGEST_DOMAIN: &[u8] = b"chio.financial.cross-issuer.lifecycle-result-digest.v1\0";
const LIFECYCLE_CHECKPOINT_DIGEST_DOMAIN: &[u8] =
    b"chio.financial.cross-issuer.lifecycle-checkpoint-digest.v1\0";
const LIFECYCLE_GENERATION_PIN_DIGEST_DOMAIN: &[u8] =
    b"chio.financial.cross-issuer.lifecycle-generation-pin-digest.v1\0";
const LIFECYCLE_CHECKPOINT_PIN_DIGEST_DOMAIN: &[u8] =
    b"chio.financial.cross-issuer.lifecycle-checkpoint-pin-digest.v1\0";

fn authority_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, CredentialError> {
    let canonical = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn authority_error(reason: impl Into<String>) -> CredentialError {
    CredentialError::FinancialAuthority(reason.into())
}

pub fn signed_envelope_digest<T: Serialize>(
    envelope: &chio_core::receipt::lineage::SignedExportEnvelope<T>,
) -> Result<String, CredentialError> {
    Ok(sha256_hex(&canonical_json_bytes(envelope)?))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedKeyStatusV2 {
    Active,
    Inactive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryActivationDispositionV2 {
    Activate,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryActivationCredentialBindingV2 {
    pub credential_id: String,
    pub family: FinancialCredentialFamilyV1,
    pub envelope_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryActivationDecisionInputV2 {
    pub pack_id: String,
    pub verifier_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub entry_id: String,
    pub source_passport_id: String,
    pub source_manifest_digest: String,
    pub presentation_digest: String,
    pub credential_bindings: Vec<EntryActivationCredentialBindingV2>,
    pub issuer: String,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    pub certification_refs: Vec<String>,
    pub lifecycle_evidence_digest: String,
    pub lifecycle_pin_digest: String,
    pub migration_envelope_digests: Vec<String>,
    pub decision: EntryActivationDispositionV2,
    pub reason: String,
    pub decided_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryActivationDecisionV2 {
    pub schema: String,
    pub pack_id: String,
    pub verifier_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub entry_id: String,
    pub source_passport_id: String,
    pub source_manifest_digest: String,
    pub presentation_digest: String,
    pub credential_bindings: Vec<EntryActivationCredentialBindingV2>,
    pub issuer: String,
    pub profile_family: String,
    pub source_kind: CrossIssuerPortfolioEntryKind,
    pub certification_refs: Vec<String>,
    pub lifecycle_evidence_digest: String,
    pub lifecycle_pin_digest: String,
    pub migration_envelope_digests: Vec<String>,
    pub decision: EntryActivationDispositionV2,
    pub reason: String,
    pub decided_at: u64,
    pub decision_digest: String,
}

impl EntryActivationDecisionV2 {
    #[must_use]
    pub fn into_input(self) -> EntryActivationDecisionInputV2 {
        EntryActivationDecisionInputV2 {
            pack_id: self.pack_id,
            verifier_id: self.verifier_id,
            signer_key_id: self.signer_key_id,
            signer_key_epoch: self.signer_key_epoch,
            entry_id: self.entry_id,
            source_passport_id: self.source_passport_id,
            source_manifest_digest: self.source_manifest_digest,
            presentation_digest: self.presentation_digest,
            credential_bindings: self.credential_bindings,
            issuer: self.issuer,
            profile_family: self.profile_family,
            source_kind: self.source_kind,
            certification_refs: self.certification_refs,
            lifecycle_evidence_digest: self.lifecycle_evidence_digest,
            lifecycle_pin_digest: self.lifecycle_pin_digest,
            migration_envelope_digests: self.migration_envelope_digests,
            decision: self.decision,
            reason: self.reason,
            decided_at: self.decided_at,
        }
    }
}

pub type SignedEntryActivationDecisionV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<EntryActivationDecisionV2>;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossIssuerTrustPackPolicyV2 {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_issuers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_families: BTreeSet<FinancialCredentialFamilyV1>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_profile_families: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_source_kinds: BTreeSet<CrossIssuerPortfolioEntryKind>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_certification_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossIssuerTrustPackInputV2 {
    pub pack_id: String,
    pub verifier_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy: CrossIssuerTrustPackPolicyV2,
    pub decisions: Vec<SignedEntryActivationDecisionV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossIssuerTrustPackV2 {
    pub schema: String,
    pub pack_id: String,
    pub verifier_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy: CrossIssuerTrustPackPolicyV2,
    pub decisions: Vec<SignedEntryActivationDecisionV2>,
}

pub type SignedCrossIssuerTrustPackV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<CrossIssuerTrustPackV2>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossIssuerMigrationInputV2 {
    pub migration_id: String,
    pub attester_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub from_issuer: String,
    pub to_issuer: String,
    pub from_subject: String,
    pub to_subject: String,
    pub prior_source_passport_ids: Vec<String>,
    pub reason: String,
    pub continuity_ref: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossIssuerMigrationV2 {
    pub schema: String,
    pub migration_id: String,
    pub attester_id: String,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
    pub from_issuer: String,
    pub to_issuer: String,
    pub from_subject: String,
    pub to_subject: String,
    pub prior_source_passport_ids: Vec<String>,
    pub reason: String,
    pub continuity_ref: String,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub migration_digest: String,
}

impl CrossIssuerMigrationV2 {
    #[must_use]
    pub fn into_input(self) -> CrossIssuerMigrationInputV2 {
        CrossIssuerMigrationInputV2 {
            migration_id: self.migration_id,
            attester_id: self.attester_id,
            signer_key_id: self.signer_key_id,
            signer_key_epoch: self.signer_key_epoch,
            from_issuer: self.from_issuer,
            to_issuer: self.to_issuer,
            from_subject: self.from_subject,
            to_subject: self.to_subject,
            prior_source_passport_ids: self.prior_source_passport_ids,
            reason: self.reason,
            continuity_ref: self.continuity_ref,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }
}

pub type SignedCrossIssuerMigrationV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<CrossIssuerMigrationV2>;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedFinancialCredentialBindingV2 {
    pub credential_id: String,
    pub family: FinancialCredentialFamilyV1,
    pub issuer: String,
    pub issuer_key_epoch: u64,
    pub body_digest: String,
    pub envelope_digest: String,
    pub source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    pub presentation_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    pub source_proof_digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedFinancialCredentialSet {
    pub(super) source_passport_id: String,
    pub(super) source_manifest_digest: String,
    pub(super) presentation_digest: String,
    pub(super) credentials: Vec<VerifiedFinancialCredentialBindingV2>,
    pub(super) policy_id: String,
    pub(super) policy_body_digest: String,
    pub(super) policy_generation: u64,
    pub(super) lifecycle_generation: u64,
    pub(super) lifecycle_status_version: u64,
    pub(super) lifecycle_result_digest: String,
    pub(super) lifecycle_generation_pin_digest: String,
    pub(super) lifecycle_checkpoint_pin_digest: String,
    pub(super) lifecycle_checkpoint_digest: String,
    pub(super) lifecycle_source_index_proof_digest: String,
}

impl VerifiedFinancialCredentialSet {
    #[must_use]
    pub fn source_passport_id(&self) -> &str {
        &self.source_passport_id
    }

    #[must_use]
    pub fn source_manifest_digest(&self) -> &str {
        &self.source_manifest_digest
    }

    #[must_use]
    pub fn presentation_digest(&self) -> &str {
        &self.presentation_digest
    }

    #[must_use]
    pub fn credentials(&self) -> &[VerifiedFinancialCredentialBindingV2] {
        &self.credentials
    }

    #[must_use]
    pub fn lifecycle_result_digest(&self) -> &str {
        &self.lifecycle_result_digest
    }

    #[must_use]
    pub fn lifecycle_checkpoint_pin_digest(&self) -> &str {
        &self.lifecycle_checkpoint_pin_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinancialAuthorityAvailabilityError {
    Unavailable,
    Stale,
    Conflict,
}

fn validate_optional_digest(field: &str, value: Option<&str>) -> Result<(), CredentialError> {
    if let Some(value) = value {
        validate_digest(field, value)?;
    }
    Ok(())
}

fn availability_error(
    component: &str,
    error: FinancialAuthorityAvailabilityError,
) -> CredentialError {
    let reason = match error {
        FinancialAuthorityAvailabilityError::Unavailable => "is unavailable",
        FinancialAuthorityAvailabilityError::Stale => "rejected a stale value",
        FinancialAuthorityAvailabilityError::Conflict => "rejected a conflicting value",
    };
    authority_error(format!("{component} {reason}"))
}

#[path = "authority/evaluation.rs"]
mod evaluation;
#[path = "authority/lifecycle.rs"]
mod lifecycle;
#[path = "authority/policy.rs"]
mod policy;
#[path = "authority/trust.rs"]
mod trust;
pub use evaluation::*;
pub use lifecycle::*;
pub use policy::*;
pub use trust::*;

#[cfg(test)]
#[path = "authority/tests.rs"]
mod tests;
