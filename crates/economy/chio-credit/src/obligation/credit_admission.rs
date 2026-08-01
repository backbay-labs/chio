use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::{MonetaryAmount, Operation};
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_core_types::economic_continuity::{
    EconomicEffectStateV1, EconomicEffectTerminalV1, EconomicNoEffectKindV1,
    VerifiedEconomicEffectNotDispatched,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CreditFacilityDisposition, CreditFacilityLifecycleState, SignedCreditFacility,
    CREDIT_FACILITY_ARTIFACT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
};

use super::{
    credit_facility_scope_digest, validate_digest, validate_money, validate_text, ObligationAtomV1,
    ObligationCreditElectionV1, SignedCreditFacilityBindV1, VerifiedCreditFacilityBindV1,
};
mod kernel_projection;
const AUTHORITY_CONFIGURATION_DIGEST_DOMAIN: &[u8] =
    b"chio.credit.authority-configuration.digest.v1\0";
const AUTHORITY_CATALOG_DIGEST_DOMAIN: &[u8] = b"chio.credit.authority-catalog.digest.v1\0";
const AUTHORITY_SET_DIGEST_DOMAIN: &[u8] = b"chio.credit.authority-set.digest.v1\0";
const RESERVATION_DIGEST_DOMAIN: &[u8] = b"chio.credit.exposure-reservation.digest.v1\0";
const PRE_DISPATCH_NO_EFFECT_DIGEST_DOMAIN: &[u8] =
    b"chio.credit.pre-dispatch-no-effect.digest.v1\0";
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CreditAdmissionError {
    #[error("invalid credit admission field `{0}`")]
    InvalidField(&'static str),
    #[error("credit authority set is incomplete")]
    IncompleteAuthoritySet,
    #[error("credit authority set is conflicting")]
    ConflictingAuthoritySet,
    #[error("credit authority artifact is not trusted")]
    UntrustedAuthority,
    #[error("credit authority artifact verification failed")]
    AuthorityVerification,
    #[error("credit authority artifact is not current")]
    AuthorityNotCurrent,
    #[error("credit authority scope does not match")]
    ScopeMismatch,
    #[error("credit authority currency does not match")]
    CurrencyMismatch,
    #[error("credit exposure arithmetic overflow")]
    ArithmeticOverflow,
    #[error("credit exposure exceeds the effective ceiling")]
    ExposureExceeded,
    #[error("illegal credit reservation transition")]
    IllegalReservationTransition,
    #[error("credit reservation conflicts with existing operation state")]
    OperationConflict,
    #[error("credit admission canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("credit admission store failed: {0}")]
    Store(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditAuthorityKindV1 {
    Facility,
    Capability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditAuthoritySourceV1 {
    pub kind: CreditAuthorityKindV1,
    pub authority_id: String,
    pub authority_key: PublicKey,
    pub authority_epoch: u64,
}

pub enum ConfiguredCreditAuthorityArtifactV1 {
    Facility {
        authority_id: String,
        authority_epoch: u64,
        signed: Box<SignedCreditFacility>,
    },
    Capability {
        authority_id: String,
        authority_epoch: u64,
        signed: Box<CapabilityToken>,
    },
}

pub struct CreditAuthorityResolverConfigurationV1 {
    pub complete_sources: Vec<CreditAuthoritySourceV1>,
    pub complete_artifact_catalog: Vec<ConfiguredCreditAuthorityArtifactV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditAuthorityResolutionRequestV1 {
    pub debtor_id: String,
    pub debtor_key: PublicKey,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub currency: String,
    pub trusted_at_unix_seconds: u64,
}

#[derive(Debug, Clone)]
enum ConfiguredCreditAuthorityArtifact {
    Facility {
        source: CreditAuthoritySourceV1,
        artifact_id: String,
        artifact_digest: String,
        signed: Box<SignedCreditFacility>,
    },
    Capability {
        source: CreditAuthoritySourceV1,
        artifact_id: String,
        artifact_digest: String,
        signed: Box<CapabilityToken>,
    },
}

impl ConfiguredCreditAuthorityArtifact {
    const fn kind(&self) -> CreditAuthorityKindV1 {
        match self {
            Self::Facility { .. } => CreditAuthorityKindV1::Facility,
            Self::Capability { .. } => CreditAuthorityKindV1::Capability,
        }
    }

    fn source(&self) -> &CreditAuthoritySourceV1 {
        match self {
            Self::Facility { source, .. } | Self::Capability { source, .. } => source,
        }
    }

    fn artifact_id(&self) -> &str {
        match self {
            Self::Facility { artifact_id, .. } | Self::Capability { artifact_id, .. } => {
                artifact_id
            }
        }
    }

    fn artifact_digest(&self) -> &str {
        match self {
            Self::Facility {
                artifact_digest, ..
            }
            | Self::Capability {
                artifact_digest, ..
            } => artifact_digest,
        }
    }

    fn sort_key(&self) -> (CreditAuthorityKindV1, &str, u64, &str, &str) {
        (
            self.kind(),
            &self.source().authority_id,
            self.source().authority_epoch,
            self.artifact_id(),
            self.artifact_digest(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditAuthorityEvidenceV1 {
    kind: CreditAuthorityKindV1,
    authority_id: String,
    authority_epoch: u64,
    artifact_id: String,
    artifact_digest: String,
    ceiling: MonetaryAmount,
    expires_at_unix_seconds: u64,
}

impl CreditAuthorityEvidenceV1 {
    #[must_use]
    pub const fn kind(&self) -> CreditAuthorityKindV1 {
        self.kind
    }

    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    #[must_use]
    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    #[must_use]
    pub const fn ceiling(&self) -> &MonetaryAmount {
        &self.ceiling
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    fn sort_key(&self) -> (CreditAuthorityKindV1, &str, u64, &str, &str) {
        (
            self.kind,
            &self.authority_id,
            self.authority_epoch,
            &self.artifact_id,
            &self.artifact_digest,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreditAuthoritySetDigestPreimageV1<'a> {
    debtor_id: &'a str,
    debtor_key: String,
    capability_id: &'a str,
    scope_digest: &'a str,
    currency: &'a str,
    configuration_digest: &'a str,
    evidence: &'a [CreditAuthorityEvidenceV1],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCreditAuthoritySet {
    debtor_id: String,
    debtor_key: PublicKey,
    capability_id: String,
    scope_digest: String,
    currency: String,
    effective_ceiling: MonetaryAmount,
    expires_at_unix_seconds: u64,
    resolved_at_unix_seconds: u64,
    configuration_digest: String,
    authority_set_digest: String,
    evidence: Vec<CreditAuthorityEvidenceV1>,
}

impl VerifiedCreditAuthoritySet {
    #[must_use]
    pub fn debtor_id(&self) -> &str {
        &self.debtor_id
    }

    #[must_use]
    pub const fn debtor_key(&self) -> &PublicKey {
        &self.debtor_key
    }

    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    #[must_use]
    pub const fn effective_ceiling(&self) -> &MonetaryAmount {
        &self.effective_ceiling
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub const fn resolved_at_unix_seconds(&self) -> u64 {
        self.resolved_at_unix_seconds
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    #[must_use]
    pub fn authority_set_digest(&self) -> &str {
        &self.authority_set_digest
    }

    #[must_use]
    pub fn evidence(&self) -> &[CreditAuthorityEvidenceV1] {
        &self.evidence
    }

    pub fn ensure_current_at(
        &self,
        trusted_at_unix_seconds: u64,
    ) -> Result<(), CreditAdmissionError> {
        if trusted_at_unix_seconds < self.resolved_at_unix_seconds
            || trusted_at_unix_seconds >= self.expires_at_unix_seconds
        {
            return Err(CreditAdmissionError::AuthorityNotCurrent);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreditAuthorityCatalogEntryV1<'a> {
    kind: CreditAuthorityKindV1,
    authority_id: &'a str,
    authority_epoch: u64,
    artifact_id: &'a str,
    artifact_digest: &'a str,
}

#[derive(Debug, Clone)]
pub struct ConfiguredCreditAuthorityResolverV1 {
    complete_sources: Vec<CreditAuthoritySourceV1>,
    complete_artifact_catalog: Vec<ConfiguredCreditAuthorityArtifact>,
    configuration_digest: String,
    catalog_digest: String,
}

impl ConfiguredCreditAuthorityResolverV1 {
    pub fn new(
        configuration: CreditAuthorityResolverConfigurationV1,
    ) -> Result<Self, CreditAdmissionError> {
        let mut sources = configuration.complete_sources;
        if sources.is_empty() {
            return Err(CreditAdmissionError::IncompleteAuthoritySet);
        }
        for source in &sources {
            validate_source(source)?;
        }
        sources.sort_by(|left, right| source_sort_key(left).cmp(&source_sort_key(right)));
        if sources.windows(2).any(|pair| {
            pair[0].kind == pair[1].kind && pair[0].authority_id == pair[1].authority_id
        }) {
            return Err(CreditAdmissionError::ConflictingAuthoritySet);
        }
        if !sources
            .iter()
            .any(|source| source.kind == CreditAuthorityKindV1::Facility)
            || !sources
                .iter()
                .any(|source| source.kind == CreditAuthorityKindV1::Capability)
        {
            return Err(CreditAdmissionError::IncompleteAuthoritySet);
        }

        let configuration_digest =
            admission_domain_digest(AUTHORITY_CONFIGURATION_DIGEST_DOMAIN, &sources)?;
        let mut artifacts = configuration
            .complete_artifact_catalog
            .into_iter()
            .map(|artifact| configure_artifact(&sources, artifact))
            .collect::<Result<Vec<_>, _>>()?;
        artifacts.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        if artifacts.windows(2).any(|pair| {
            let left = pair[0].sort_key();
            let right = pair[1].sort_key();
            left.0 == right.0 && left.1 == right.1 && left.3 == right.3
        }) {
            return Err(CreditAdmissionError::ConflictingAuthoritySet);
        }
        if sources.iter().any(|source| {
            !artifacts.iter().any(|artifact| {
                artifact.kind() == source.kind
                    && artifact.source().authority_id == source.authority_id
                    && artifact.source().authority_epoch == source.authority_epoch
            })
        }) {
            return Err(CreditAdmissionError::IncompleteAuthoritySet);
        }
        let catalog_entries = artifacts
            .iter()
            .map(|artifact| CreditAuthorityCatalogEntryV1 {
                kind: artifact.kind(),
                authority_id: &artifact.source().authority_id,
                authority_epoch: artifact.source().authority_epoch,
                artifact_id: artifact.artifact_id(),
                artifact_digest: artifact.artifact_digest(),
            })
            .collect::<Vec<_>>();
        let catalog_digest =
            admission_domain_digest(AUTHORITY_CATALOG_DIGEST_DOMAIN, &catalog_entries)?;
        Ok(Self {
            complete_sources: sources,
            complete_artifact_catalog: artifacts,
            configuration_digest,
            catalog_digest,
        })
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    #[must_use]
    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    pub fn resolve(
        &self,
        request: &CreditAuthorityResolutionRequestV1,
    ) -> Result<VerifiedCreditAuthoritySet, CreditAdmissionError> {
        validate_resolution_request(request)?;
        let scope_digest = credit_facility_scope_digest(
            &request.debtor_id,
            &request.capability_id,
            &request.tool_server,
            &request.tool_name,
            &request.currency,
        )
        .map_err(|_| CreditAdmissionError::InvalidField("scope"))?;
        let mut evidence = Vec::new();
        for source in &self.complete_sources {
            let mut source_evidence = Vec::new();
            let mut matched_expired = false;
            for artifact in self.complete_artifact_catalog.iter().filter(|artifact| {
                artifact.kind() == source.kind
                    && artifact.source().authority_id == source.authority_id
                    && artifact.source().authority_epoch == source.authority_epoch
            }) {
                match resolve_artifact(artifact, request)? {
                    AuthorityResolution::Applicable(item) => source_evidence.push(item),
                    AuthorityResolution::Expired => matched_expired = true,
                    AuthorityResolution::NotApplicable => {}
                }
            }
            if source_evidence.is_empty() {
                return Err(if matched_expired {
                    CreditAdmissionError::AuthorityNotCurrent
                } else {
                    CreditAdmissionError::IncompleteAuthoritySet
                });
            }
            evidence.extend(source_evidence);
        }
        evidence.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        if evidence.is_empty() {
            return Err(CreditAdmissionError::IncompleteAuthoritySet);
        }
        let effective_units = evidence
            .iter()
            .map(|entry| entry.ceiling.units)
            .min()
            .ok_or(CreditAdmissionError::IncompleteAuthoritySet)?;
        let expires_at_unix_seconds = evidence
            .iter()
            .map(|entry| entry.expires_at_unix_seconds)
            .min()
            .ok_or(CreditAdmissionError::IncompleteAuthoritySet)?;
        let authority_set_digest = admission_domain_digest(
            AUTHORITY_SET_DIGEST_DOMAIN,
            &CreditAuthoritySetDigestPreimageV1 {
                debtor_id: &request.debtor_id,
                debtor_key: request.debtor_key.to_hex(),
                capability_id: &request.capability_id,
                scope_digest: &scope_digest,
                currency: &request.currency,
                configuration_digest: &self.configuration_digest,
                evidence: &evidence,
            },
        )?;
        Ok(VerifiedCreditAuthoritySet {
            debtor_id: request.debtor_id.clone(),
            debtor_key: request.debtor_key.clone(),
            capability_id: request.capability_id.clone(),
            scope_digest,
            currency: request.currency.clone(),
            effective_ceiling: MonetaryAmount {
                units: effective_units,
                currency: request.currency.clone(),
            },
            expires_at_unix_seconds,
            resolved_at_unix_seconds: request.trusted_at_unix_seconds,
            configuration_digest: self.configuration_digest.clone(),
            authority_set_digest,
            evidence,
        })
    }
}

enum AuthorityResolution {
    Applicable(CreditAuthorityEvidenceV1),
    Expired,
    NotApplicable,
}

fn resolve_artifact(
    artifact: &ConfiguredCreditAuthorityArtifact,
    request: &CreditAuthorityResolutionRequestV1,
) -> Result<AuthorityResolution, CreditAdmissionError> {
    match artifact {
        ConfiguredCreditAuthorityArtifact::Facility {
            source,
            artifact_id,
            artifact_digest,
            signed,
        } => resolve_facility(source, artifact_id, artifact_digest, signed, request),
        ConfiguredCreditAuthorityArtifact::Capability {
            source,
            artifact_id,
            artifact_digest,
            signed,
        } => resolve_capability(source, artifact_id, artifact_digest, signed, request),
    }
}

fn resolve_facility(
    source: &CreditAuthoritySourceV1,
    artifact_id: &str,
    artifact_digest: &str,
    signed: &SignedCreditFacility,
    request: &CreditAuthorityResolutionRequestV1,
) -> Result<AuthorityResolution, CreditAdmissionError> {
    let body = &signed.body;
    let filters = &body.report.filters;
    if filters.agent_subject.as_deref() != Some(request.debtor_id.as_str())
        || !optional_scope_matches(filters.capability_id.as_deref(), &request.capability_id)
        || !optional_scope_matches(filters.tool_server.as_deref(), &request.tool_server)
        || !optional_scope_matches(filters.tool_name.as_deref(), &request.tool_name)
    {
        return Ok(AuthorityResolution::NotApplicable);
    }
    if request.trusted_at_unix_seconds < body.issued_at
        || request.trusted_at_unix_seconds >= body.expires_at
        || body.lifecycle_state != CreditFacilityLifecycleState::Active
    {
        return Ok(AuthorityResolution::Expired);
    }
    if body.report.disposition != CreditFacilityDisposition::Grant
        || body.report.prerequisites.manual_review_required
        || !body.report.prerequisites.runtime_assurance_met
        || (body.report.prerequisites.certification_required
            && !body.report.prerequisites.certification_met)
    {
        return Err(CreditAdmissionError::AuthorityVerification);
    }
    let terms = body
        .report
        .terms
        .as_ref()
        .ok_or(CreditAdmissionError::IncompleteAuthoritySet)?;
    if terms.credit_limit.currency != request.currency {
        return Err(CreditAdmissionError::CurrencyMismatch);
    }
    let effective_units = (u128::from(terms.credit_limit.units)
        * u128::from(terms.utilization_ceiling_bps)
        / u128::from(BASIS_POINTS_DENOMINATOR))
    .try_into()
    .map_err(|_| CreditAdmissionError::ArithmeticOverflow)?;
    if effective_units == 0 || effective_units > I_JSON_MAX_SAFE_INTEGER {
        return Err(CreditAdmissionError::InvalidField("facility_ceiling"));
    }
    Ok(AuthorityResolution::Applicable(CreditAuthorityEvidenceV1 {
        kind: CreditAuthorityKindV1::Facility,
        authority_id: source.authority_id.clone(),
        authority_epoch: source.authority_epoch,
        artifact_id: artifact_id.to_owned(),
        artifact_digest: artifact_digest.to_owned(),
        ceiling: MonetaryAmount {
            units: effective_units,
            currency: request.currency.clone(),
        },
        expires_at_unix_seconds: body.expires_at,
    }))
}

fn resolve_capability(
    source: &CreditAuthoritySourceV1,
    artifact_id: &str,
    artifact_digest: &str,
    signed: &CapabilityToken,
    request: &CreditAuthorityResolutionRequestV1,
) -> Result<AuthorityResolution, CreditAdmissionError> {
    if signed.id != request.capability_id {
        return Ok(AuthorityResolution::NotApplicable);
    }
    if signed.subject != request.debtor_key {
        return Err(CreditAdmissionError::ScopeMismatch);
    }
    if !signed.is_valid_at(request.trusted_at_unix_seconds) {
        return Ok(AuthorityResolution::Expired);
    }
    let mut ceilings = Vec::new();
    for grant in signed.scope.grants.iter().filter(|grant| {
        scope_pattern_matches(&grant.server_id, &request.tool_server)
            && scope_pattern_matches(&grant.tool_name, &request.tool_name)
            && grant.operations.contains(&Operation::Invoke)
    }) {
        for ceiling in [
            grant.max_cost_per_invocation.as_ref(),
            grant.max_total_cost.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if ceiling.currency != request.currency {
                return Err(CreditAdmissionError::CurrencyMismatch);
            }
            validate_amount(ceiling, "capability_ceiling")?;
            ceilings.push(ceiling.units);
        }
    }
    let Some(effective_units) = ceilings.into_iter().min() else {
        return Ok(AuthorityResolution::NotApplicable);
    };
    Ok(AuthorityResolution::Applicable(CreditAuthorityEvidenceV1 {
        kind: CreditAuthorityKindV1::Capability,
        authority_id: source.authority_id.clone(),
        authority_epoch: source.authority_epoch,
        artifact_id: artifact_id.to_owned(),
        artifact_digest: artifact_digest.to_owned(),
        ceiling: MonetaryAmount {
            units: effective_units,
            currency: request.currency.clone(),
        },
        expires_at_unix_seconds: signed.expires_at,
    }))
}

fn configure_artifact(
    sources: &[CreditAuthoritySourceV1],
    artifact: ConfiguredCreditAuthorityArtifactV1,
) -> Result<ConfiguredCreditAuthorityArtifact, CreditAdmissionError> {
    match artifact {
        ConfiguredCreditAuthorityArtifactV1::Facility {
            authority_id,
            authority_epoch,
            signed,
        } => {
            let source = find_source(
                sources,
                CreditAuthorityKindV1::Facility,
                &authority_id,
                authority_epoch,
            )?;
            validate_facility_artifact(&signed, source)?;
            let canonical = canonical_json_bytes(&signed)
                .map_err(|error| CreditAdmissionError::Canonicalization(error.to_string()))?;
            Ok(ConfiguredCreditAuthorityArtifact::Facility {
                source: source.clone(),
                artifact_id: signed.body.facility_id.clone(),
                artifact_digest: sha256_hex(&canonical),
                signed,
            })
        }
        ConfiguredCreditAuthorityArtifactV1::Capability {
            authority_id,
            authority_epoch,
            signed,
        } => {
            let source = find_source(
                sources,
                CreditAuthorityKindV1::Capability,
                &authority_id,
                authority_epoch,
            )?;
            validate_capability_artifact(&signed, source)?;
            let canonical = canonical_json_bytes(&signed)
                .map_err(|error| CreditAdmissionError::Canonicalization(error.to_string()))?;
            Ok(ConfiguredCreditAuthorityArtifact::Capability {
                source: source.clone(),
                artifact_id: signed.id.clone(),
                artifact_digest: sha256_hex(&canonical),
                signed,
            })
        }
    }
}

fn validate_facility_artifact(
    signed: &SignedCreditFacility,
    source: &CreditAuthoritySourceV1,
) -> Result<(), CreditAdmissionError> {
    let body = &signed.body;
    if signed.signer_key != source.authority_key
        || !signed
            .verify_signature()
            .map_err(|_| CreditAdmissionError::AuthorityVerification)?
        || body.schema != CREDIT_FACILITY_ARTIFACT_SCHEMA
        || body.report.schema != CREDIT_FACILITY_REPORT_SCHEMA
    {
        return Err(CreditAdmissionError::AuthorityVerification);
    }
    validate_admission_text("facility_id", &body.facility_id)?;
    validate_seconds("facility_issued_at", body.issued_at)?;
    validate_seconds("facility_expires_at", body.expires_at)?;
    validate_seconds("facility_generated_at", body.report.generated_at)?;
    if body.issued_at >= body.expires_at || body.report.generated_at > body.issued_at {
        return Err(CreditAdmissionError::InvalidField("facility_time"));
    }
    body.report
        .filters
        .validate()
        .map_err(|_| CreditAdmissionError::InvalidField("facility_scope"))?;
    if let Some(terms) = &body.report.terms {
        validate_amount(&terms.credit_limit, "facility_credit_limit")?;
        if terms.utilization_ceiling_bps == 0
            || terms.utilization_ceiling_bps > 10_000
            || terms.reserve_ratio_bps > 10_000
            || terms.concentration_cap_bps > 10_000
            || terms.ttl_seconds == 0
            || terms.ttl_seconds > I_JSON_MAX_SAFE_INTEGER
            || body.expires_at
                > body
                    .issued_at
                    .checked_add(terms.ttl_seconds)
                    .ok_or(CreditAdmissionError::ArithmeticOverflow)?
        {
            return Err(CreditAdmissionError::InvalidField("facility_terms"));
        }
    }
    Ok(())
}

fn validate_capability_artifact(
    signed: &CapabilityToken,
    source: &CreditAuthoritySourceV1,
) -> Result<(), CreditAdmissionError> {
    if signed.issuer != source.authority_key
        || !signed.delegation_chain.is_empty()
        || signed
            .scope_attenuations
            .as_ref()
            .is_some_and(|attenuations| !attenuations.is_empty())
        || signed.attenuation_proof.is_some()
        || signed.budget_share_bps.is_some()
        || !signed
            .verify_signature()
            .map_err(|_| CreditAdmissionError::AuthorityVerification)?
    {
        return Err(CreditAdmissionError::AuthorityVerification);
    }
    validate_admission_text("capability_id", &signed.id)?;
    validate_seconds("capability_issued_at", signed.issued_at)?;
    validate_seconds("capability_expires_at", signed.expires_at)?;
    if signed.issued_at >= signed.expires_at {
        return Err(CreditAdmissionError::InvalidField("capability_time"));
    }
    Ok(())
}

fn find_source<'a>(
    sources: &'a [CreditAuthoritySourceV1],
    kind: CreditAuthorityKindV1,
    authority_id: &str,
    authority_epoch: u64,
) -> Result<&'a CreditAuthoritySourceV1, CreditAdmissionError> {
    sources
        .iter()
        .find(|source| {
            source.kind == kind
                && source.authority_id == authority_id
                && source.authority_epoch == authority_epoch
        })
        .ok_or(CreditAdmissionError::UntrustedAuthority)
}

fn validate_source(source: &CreditAuthoritySourceV1) -> Result<(), CreditAdmissionError> {
    validate_admission_text("authority_id", &source.authority_id)?;
    validate_seconds("authority_epoch", source.authority_epoch)
}

fn validate_resolution_request(
    request: &CreditAuthorityResolutionRequestV1,
) -> Result<(), CreditAdmissionError> {
    for (field, value) in [
        ("debtor_id", request.debtor_id.as_str()),
        ("capability_id", request.capability_id.as_str()),
        ("tool_server", request.tool_server.as_str()),
        ("tool_name", request.tool_name.as_str()),
    ] {
        validate_admission_text(field, value)?;
    }
    validate_seconds("trusted_at_unix_seconds", request.trusted_at_unix_seconds)?;
    validate_currency(&request.currency)
}

fn source_sort_key(source: &CreditAuthoritySourceV1) -> (CreditAuthorityKindV1, &str, u64, String) {
    (
        source.kind,
        &source.authority_id,
        source.authority_epoch,
        source.authority_key.to_hex(),
    )
}

fn optional_scope_matches(configured: Option<&str>, actual: &str) -> bool {
    configured.is_none_or(|configured| scope_pattern_matches(configured, actual))
}

fn scope_pattern_matches(pattern: &str, actual: &str) -> bool {
    pattern == "*" || pattern == actual
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditExposureReservationStateV1 {
    Reserved,
    Committed,
    ReleasedBeforeDispatch,
    OutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditExposureReservationRequest {
    pub operation_id: String,
    pub request_id: String,
    pub action_nonce: String,
    pub economic_intent_digest: String,
    pub debtor_id: String,
    pub amount: MonetaryAmount,
    pub authorities: VerifiedCreditAuthoritySet,
    pub credit_facility_bind: VerifiedCreditFacilityBindV1,
}

impl CreditExposureReservationRequest {
    pub fn validate(&self) -> Result<(), CreditAdmissionError> {
        validate_admission_digest("operation_id", &self.operation_id)?;
        validate_admission_text("request_id", &self.request_id)?;
        validate_admission_text("action_nonce", &self.action_nonce)?;
        validate_admission_digest("economic_intent_digest", &self.economic_intent_digest)?;
        validate_admission_text("debtor_id", &self.debtor_id)?;
        validate_amount(&self.amount, "amount")?;
        let bind = self.credit_facility_bind.body();
        let trusted_at_unix_ms = self
            .authorities
            .resolved_at_unix_seconds
            .checked_mul(1_000)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        self.credit_facility_bind
            .ensure_current_at(trusted_at_unix_ms)
            .map_err(|_| CreditAdmissionError::AuthorityNotCurrent)?;
        let authority_expires_at_unix_ms = self
            .authorities
            .expires_at_unix_seconds
            .checked_mul(1_000)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        let has_facility = self.authorities.evidence.iter().any(|evidence| {
            evidence.kind == CreditAuthorityKindV1::Facility
                && evidence.artifact_id == bind.facility_id()
                && evidence.artifact_digest == bind.facility_artifact_digest()
        });
        let has_capability = self
            .authorities
            .evidence
            .iter()
            .any(|evidence| evidence.kind == CreditAuthorityKindV1::Capability);
        if !has_facility || !has_capability {
            return Err(CreditAdmissionError::IncompleteAuthoritySet);
        }
        if self.operation_id != bind.operation_id()
            || self.request_id != bind.request_id()
            || self.action_nonce != bind.action_nonce()
            || self.economic_intent_digest != bind.economic_intent_digest()
            || self.debtor_id != bind.debtor_id()
            || self.debtor_id != self.authorities.debtor_id
            || bind.scope_digest() != self.authorities.scope_digest
            || bind.capability_id() != self.authorities.capability_id
            || self.amount != *bind.amount()
            || self.amount.currency != self.authorities.currency
            || *bind.effective_ceiling() != self.authorities.effective_ceiling
            || bind.authority_set_digest() != self.authorities.authority_set_digest
            || bind.expires_at_unix_ms() > authority_expires_at_unix_ms
        {
            return Err(CreditAdmissionError::ScopeMismatch);
        }
        if self.amount.units > self.authorities.effective_ceiling.units {
            return Err(CreditAdmissionError::ExposureExceeded);
        }
        Ok(())
    }

    pub fn checked_total_exposure(
        &self,
        open_units: u64,
        reserved_units: u64,
    ) -> Result<u64, CreditAdmissionError> {
        self.validate()?;
        if open_units > I_JSON_MAX_SAFE_INTEGER || reserved_units > I_JSON_MAX_SAFE_INTEGER {
            return Err(CreditAdmissionError::ArithmeticOverflow);
        }
        let total = open_units
            .checked_add(reserved_units)
            .and_then(|units| units.checked_add(self.amount.units))
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        if total > I_JSON_MAX_SAFE_INTEGER {
            return Err(CreditAdmissionError::ArithmeticOverflow);
        }
        if total > self.authorities.effective_ceiling.units {
            return Err(CreditAdmissionError::ExposureExceeded);
        }
        Ok(total)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreditExposureReservationDigestPreimageV1<'a> {
    operation_id: &'a str,
    request_id: &'a str,
    action_nonce: &'a str,
    economic_intent_digest: &'a str,
    credit_facility_bind_digest: &'a str,
    bind_trust_configuration_digest: &'a str,
    amount: &'a MonetaryAmount,
    original_creditor_id: &'a str,
    original_settlement_destination_ref: &'a str,
    payee_binding_digest: &'a str,
    debtor_id: &'a str,
    scope_digest: &'a str,
    currency: &'a str,
    capability_id: &'a str,
    facility_id: &'a str,
    authority_configuration_digest: &'a str,
    authority_set_digest: &'a str,
    source_account_version: u64,
    source_resource_fence: u64,
    account_version: u64,
    resource_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditExposureReservationRecordV1 {
    operation_id: String,
    request_id: String,
    action_nonce: String,
    economic_intent_digest: String,
    reservation_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    obligation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    obligation_atom_digest: Option<String>,
    debtor_id: String,
    debtor_key: PublicKey,
    scope_digest: String,
    capability_id: String,
    amount: MonetaryAmount,
    effective_ceiling: MonetaryAmount,
    facility_id: String,
    facility_artifact_digest: String,
    credit_facility_bind_digest: String,
    credit_facility_bind_canonical: Vec<u8>,
    bind_trust_configuration_digest: String,
    original_creditor_id: String,
    original_settlement_destination_ref: String,
    payee_binding_digest: String,
    bind_issued_at_unix_ms: u64,
    bind_expires_at_unix_ms: u64,
    due_at_unix_ms: u64,
    authority_configuration_digest: String,
    authority_set_digest: String,
    authority_evidence: Vec<CreditAuthorityEvidenceV1>,
    authority_expires_at_unix_seconds: u64,
    source_account_version: u64,
    source_resource_fence: u64,
    account_version: u64,
    resource_fence: u64,
    state: CreditExposureReservationStateV1,
}

impl CreditExposureReservationRecordV1 {
    pub fn prepare_reserved(
        request: &CreditExposureReservationRequest,
        account_version: u64,
        resource_fence: u64,
    ) -> Result<Self, CreditAdmissionError> {
        request.validate()?;
        validate_seconds("account_version", account_version)?;
        validate_seconds("resource_fence", resource_fence)?;
        let bind = request.credit_facility_bind.body();
        if bind
            .expected_exposure_version()
            .checked_add(1)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?
            != account_version
            || bind
                .expected_exposure_fence()
                .checked_add(1)
                .ok_or(CreditAdmissionError::ArithmeticOverflow)?
                != resource_fence
        {
            return Err(CreditAdmissionError::OperationConflict);
        }
        let mut reservation = Self {
            operation_id: request.operation_id.clone(),
            request_id: request.request_id.clone(),
            action_nonce: request.action_nonce.clone(),
            economic_intent_digest: request.economic_intent_digest.clone(),
            reservation_digest: String::new(),
            obligation_id: None,
            obligation_atom_digest: None,
            debtor_id: request.debtor_id.clone(),
            debtor_key: request.authorities.debtor_key.clone(),
            scope_digest: request.authorities.scope_digest.clone(),
            capability_id: request.authorities.capability_id.clone(),
            amount: request.amount.clone(),
            effective_ceiling: request.authorities.effective_ceiling.clone(),
            facility_id: request.credit_facility_bind.body().facility_id().to_owned(),
            facility_artifact_digest: request
                .credit_facility_bind
                .body()
                .facility_artifact_digest()
                .to_owned(),
            credit_facility_bind_digest: request.credit_facility_bind.artifact_digest().to_owned(),
            credit_facility_bind_canonical: request.credit_facility_bind.canonical_bytes().to_vec(),
            bind_trust_configuration_digest: request
                .credit_facility_bind
                .trust_configuration_digest()
                .to_owned(),
            original_creditor_id: request
                .credit_facility_bind
                .body()
                .original_creditor_id()
                .to_owned(),
            original_settlement_destination_ref: request
                .credit_facility_bind
                .body()
                .original_settlement_destination_ref()
                .to_owned(),
            payee_binding_digest: request
                .credit_facility_bind
                .body()
                .payee_binding_digest()
                .to_owned(),
            bind_issued_at_unix_ms: request.credit_facility_bind.body().issued_at_unix_ms(),
            bind_expires_at_unix_ms: request.credit_facility_bind.body().expires_at_unix_ms(),
            due_at_unix_ms: request.credit_facility_bind.body().due_at_unix_ms(),
            authority_configuration_digest: request.authorities.configuration_digest.clone(),
            authority_set_digest: request.authorities.authority_set_digest.clone(),
            authority_evidence: request.authorities.evidence.clone(),
            authority_expires_at_unix_seconds: request.authorities.expires_at_unix_seconds,
            source_account_version: bind.expected_exposure_version(),
            source_resource_fence: bind.expected_exposure_fence(),
            account_version,
            resource_fence,
            state: CreditExposureReservationStateV1::Reserved,
        };
        reservation.reservation_digest = reservation.derived_reservation_digest()?;
        reservation.validate_against_request(request)?;
        Ok(reservation)
    }

    pub fn validate(&self) -> Result<(), CreditAdmissionError> {
        validate_admission_digest("operation_id", &self.operation_id)?;
        validate_admission_text("request_id", &self.request_id)?;
        validate_admission_text("action_nonce", &self.action_nonce)?;
        validate_admission_digest("economic_intent_digest", &self.economic_intent_digest)?;
        validate_admission_digest("reservation_digest", &self.reservation_digest)?;
        if let Some(obligation_id) = &self.obligation_id {
            validate_admission_digest("obligation_id", obligation_id)?;
        }
        if let Some(obligation_atom_digest) = &self.obligation_atom_digest {
            validate_admission_digest("obligation_atom_digest", obligation_atom_digest)?;
        }
        validate_admission_text("debtor_id", &self.debtor_id)?;
        validate_admission_digest("scope_digest", &self.scope_digest)?;
        validate_admission_text("capability_id", &self.capability_id)?;
        validate_amount(&self.amount, "amount")?;
        validate_amount(&self.effective_ceiling, "effective_ceiling")?;
        validate_admission_text("facility_id", &self.facility_id)?;
        validate_admission_digest("facility_artifact_digest", &self.facility_artifact_digest)?;
        validate_admission_digest(
            "credit_facility_bind_digest",
            &self.credit_facility_bind_digest,
        )?;
        validate_admission_digest(
            "bind_trust_configuration_digest",
            &self.bind_trust_configuration_digest,
        )?;
        validate_admission_text("original_creditor_id", &self.original_creditor_id)?;
        validate_admission_text(
            "original_settlement_destination_ref",
            &self.original_settlement_destination_ref,
        )?;
        validate_admission_digest("payee_binding_digest", &self.payee_binding_digest)?;
        validate_seconds("bind_issued_at_unix_ms", self.bind_issued_at_unix_ms)?;
        validate_seconds("bind_expires_at_unix_ms", self.bind_expires_at_unix_ms)?;
        validate_seconds("due_at_unix_ms", self.due_at_unix_ms)?;
        validate_admission_digest(
            "authority_configuration_digest",
            &self.authority_configuration_digest,
        )?;
        validate_admission_digest("authority_set_digest", &self.authority_set_digest)?;
        validate_seconds(
            "authority_expires_at_unix_seconds",
            self.authority_expires_at_unix_seconds,
        )?;
        validate_seconds("source_account_version", self.source_account_version)?;
        validate_seconds("source_resource_fence", self.source_resource_fence)?;
        validate_seconds("account_version", self.account_version)?;
        validate_seconds("resource_fence", self.resource_fence)?;
        let signed_bind =
            SignedCreditFacilityBindV1::from_canonical_bytes(&self.credit_facility_bind_canonical)
                .map_err(|_| CreditAdmissionError::AuthorityVerification)?;
        let bind = signed_bind.body();
        let recomputed_set_digest = admission_domain_digest(
            AUTHORITY_SET_DIGEST_DOMAIN,
            &CreditAuthoritySetDigestPreimageV1 {
                debtor_id: &self.debtor_id,
                debtor_key: self.debtor_key.to_hex(),
                capability_id: &self.capability_id,
                scope_digest: &self.scope_digest,
                currency: &self.amount.currency,
                configuration_digest: &self.authority_configuration_digest,
                evidence: &self.authority_evidence,
            },
        )?;
        let minimum_ceiling = self
            .authority_evidence
            .iter()
            .map(|evidence| evidence.ceiling.units)
            .min()
            .ok_or(CreditAdmissionError::IncompleteAuthoritySet)?;
        let minimum_expiry = self
            .authority_evidence
            .iter()
            .map(|evidence| evidence.expires_at_unix_seconds)
            .min()
            .ok_or(CreditAdmissionError::IncompleteAuthoritySet)?;
        for evidence in &self.authority_evidence {
            validate_authority_evidence(evidence)?;
        }
        if self.amount.currency != self.effective_ceiling.currency
            || self.amount.units > self.effective_ceiling.units
            || self.effective_ceiling.units != minimum_ceiling
            || self.authority_expires_at_unix_seconds != minimum_expiry
            || self.authority_set_digest != recomputed_set_digest
            || self.credit_facility_bind_digest != sha256_hex(&self.credit_facility_bind_canonical)
            || bind.operation_id() != self.operation_id
            || bind.request_id() != self.request_id
            || bind.action_nonce() != self.action_nonce
            || bind.economic_intent_digest() != self.economic_intent_digest
            || bind.debtor_id() != self.debtor_id
            || bind.scope_digest() != self.scope_digest
            || bind.capability_id() != self.capability_id
            || bind.amount() != &self.amount
            || bind.effective_ceiling() != &self.effective_ceiling
            || bind.facility_id() != self.facility_id
            || bind.facility_artifact_digest() != self.facility_artifact_digest
            || bind.authority_set_digest() != self.authority_set_digest
            || bind.original_creditor_id() != self.original_creditor_id
            || bind.original_settlement_destination_ref()
                != self.original_settlement_destination_ref
            || bind.payee_binding_digest() != self.payee_binding_digest
            || bind.issued_at_unix_ms() != self.bind_issued_at_unix_ms
            || bind.expires_at_unix_ms() != self.bind_expires_at_unix_ms
            || bind.due_at_unix_ms() != self.due_at_unix_ms
            || bind.expected_exposure_version() != self.source_account_version
            || bind.expected_exposure_fence() != self.source_resource_fence
            || self.bind_issued_at_unix_ms >= self.bind_expires_at_unix_ms
            || self.bind_expires_at_unix_ms > self.due_at_unix_ms
            || match self.state {
                CreditExposureReservationStateV1::Committed => {
                    self.obligation_id.is_none() || self.obligation_atom_digest.is_none()
                }
                _ => self.obligation_id.is_some() || self.obligation_atom_digest.is_some(),
            }
            || self.authority_evidence.is_empty()
            || !self
                .authority_evidence
                .iter()
                .any(|evidence| evidence.kind == CreditAuthorityKindV1::Facility)
            || !self
                .authority_evidence
                .iter()
                .any(|evidence| evidence.kind == CreditAuthorityKindV1::Capability)
            || !self.authority_evidence.iter().any(|evidence| {
                evidence.kind == CreditAuthorityKindV1::Facility
                    && evidence.artifact_id == self.facility_id
                    && evidence.artifact_digest == self.facility_artifact_digest
            })
            || !self
                .authority_evidence
                .windows(2)
                .all(|pair| pair[0].sort_key() < pair[1].sort_key())
            || self.authority_evidence.iter().any(|evidence| {
                evidence.ceiling.currency != self.amount.currency
                    || evidence.expires_at_unix_seconds < self.authority_expires_at_unix_seconds
            })
            || self.account_version <= self.source_account_version
            || self.resource_fence <= self.source_resource_fence
            || self.source_account_version != self.source_resource_fence
            || self.account_version != self.resource_fence
            || self.reservation_digest != self.derived_reservation_digest()?
            || (self.state == CreditExposureReservationStateV1::Reserved
                && self.account_version
                    != self
                        .source_account_version
                        .checked_add(1)
                        .ok_or(CreditAdmissionError::ArithmeticOverflow)?)
        {
            return Err(CreditAdmissionError::InvalidField("reservation_binding"));
        }
        Ok(())
    }

    pub fn validate_against_request(
        &self,
        request: &CreditExposureReservationRequest,
    ) -> Result<(), CreditAdmissionError> {
        request.validate()?;
        self.validate()?;
        if self.state != CreditExposureReservationStateV1::Reserved
            || self.obligation_id.is_some()
            || self.obligation_atom_digest.is_some()
            || self.operation_id != request.operation_id
            || self.request_id != request.request_id
            || self.action_nonce != request.action_nonce
            || self.economic_intent_digest != request.economic_intent_digest
            || self.debtor_id != request.debtor_id
            || self.debtor_key != request.authorities.debtor_key
            || self.scope_digest != request.authorities.scope_digest
            || self.capability_id != request.authorities.capability_id
            || self.amount != request.amount
            || self.effective_ceiling != request.authorities.effective_ceiling
            || self.authority_configuration_digest != request.authorities.configuration_digest
            || self.authority_set_digest != request.authorities.authority_set_digest
            || self.authority_evidence != request.authorities.evidence
            || self.authority_expires_at_unix_seconds != request.authorities.expires_at_unix_seconds
            || self.credit_facility_bind_digest != request.credit_facility_bind.artifact_digest()
            || self.credit_facility_bind_canonical.as_slice()
                != request.credit_facility_bind.canonical_bytes()
            || self.bind_trust_configuration_digest
                != request.credit_facility_bind.trust_configuration_digest()
            || self
                .source_account_version
                .checked_add(1)
                .ok_or(CreditAdmissionError::ArithmeticOverflow)?
                != self.account_version
            || self
                .source_resource_fence
                .checked_add(1)
                .ok_or(CreditAdmissionError::ArithmeticOverflow)?
                != self.resource_fence
        {
            return Err(CreditAdmissionError::OperationConflict);
        }
        Ok(())
    }

    fn derived_reservation_digest(&self) -> Result<String, CreditAdmissionError> {
        let account_version = self
            .source_account_version
            .checked_add(1)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        let resource_fence = self
            .source_resource_fence
            .checked_add(1)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        admission_domain_digest(
            RESERVATION_DIGEST_DOMAIN,
            &CreditExposureReservationDigestPreimageV1 {
                operation_id: &self.operation_id,
                request_id: &self.request_id,
                action_nonce: &self.action_nonce,
                economic_intent_digest: &self.economic_intent_digest,
                credit_facility_bind_digest: &self.credit_facility_bind_digest,
                bind_trust_configuration_digest: &self.bind_trust_configuration_digest,
                amount: &self.amount,
                original_creditor_id: &self.original_creditor_id,
                original_settlement_destination_ref: &self.original_settlement_destination_ref,
                payee_binding_digest: &self.payee_binding_digest,
                debtor_id: &self.debtor_id,
                scope_digest: &self.scope_digest,
                currency: &self.amount.currency,
                capability_id: &self.capability_id,
                facility_id: &self.facility_id,
                authority_configuration_digest: &self.authority_configuration_digest,
                authority_set_digest: &self.authority_set_digest,
                source_account_version: self.source_account_version,
                source_resource_fence: self.source_resource_fence,
                account_version,
                resource_fence,
            },
        )
    }

    pub fn prepare_committed(
        &self,
        atom: &ObligationAtomV1,
        next_account_version: u64,
        next_resource_fence: u64,
    ) -> Result<Self, CreditAdmissionError> {
        self.validate_obligation_terms(atom)?;
        self.validate_transition(
            CreditExposureReservationStateV1::Committed,
            next_account_version,
            next_resource_fence,
        )?;
        let mut committed = self.clone();
        committed.state = CreditExposureReservationStateV1::Committed;
        committed.account_version = next_account_version;
        committed.resource_fence = next_resource_fence;
        committed.obligation_id = Some(atom.obligation_id().to_owned());
        committed.obligation_atom_digest = Some(
            atom.digest()
                .map_err(|_| CreditAdmissionError::OperationConflict)?,
        );
        committed.validate()?;
        Ok(committed)
    }

    pub fn validate_committed_obligation(
        &self,
        atom: &ObligationAtomV1,
    ) -> Result<(), CreditAdmissionError> {
        self.validate()?;
        self.validate_obligation_terms(atom)?;
        let atom_digest = atom
            .digest()
            .map_err(|_| CreditAdmissionError::OperationConflict)?;
        if self.state != CreditExposureReservationStateV1::Committed
            || self.obligation_id.as_deref() != Some(atom.obligation_id())
            || self.obligation_atom_digest.as_deref() != Some(atom_digest.as_str())
        {
            return Err(CreditAdmissionError::OperationConflict);
        }
        Ok(())
    }

    fn validate_obligation_terms(
        &self,
        atom: &ObligationAtomV1,
    ) -> Result<(), CreditAdmissionError> {
        atom.validate()
            .map_err(|_| CreditAdmissionError::OperationConflict)?;
        let credit_election_matches = matches!(
            atom.credit_election(),
            ObligationCreditElectionV1::CreditFacility {
                facility_id,
                authority_digest,
            } if facility_id == &self.facility_id
                && authority_digest == &self.credit_facility_bind_digest
        );
        if atom.economic_intent_digest() != self.economic_intent_digest
            || atom.debtor_id() != self.debtor_id
            || atom.original_creditor_id() != self.original_creditor_id
            || atom.original_settlement_destination_ref()
                != self.original_settlement_destination_ref
            || atom.payee_binding_digest() != self.payee_binding_digest
            || atom.amount() != &self.amount
            || atom.created_at_unix_ms() < self.bind_issued_at_unix_ms
            || atom.created_at_unix_ms() >= self.bind_expires_at_unix_ms
            || atom.due_at_unix_ms() != self.due_at_unix_ms
            || !credit_election_matches
        {
            return Err(CreditAdmissionError::OperationConflict);
        }
        Ok(())
    }

    pub fn prepare_outcome_unknown(
        &self,
        next_account_version: u64,
        next_resource_fence: u64,
    ) -> Result<Self, CreditAdmissionError> {
        self.transition(
            CreditExposureReservationStateV1::OutcomeUnknown,
            next_account_version,
            next_resource_fence,
        )
    }

    pub fn prepare_released_before_dispatch(
        &self,
        proof: &VerifiedCreditPreDispatchNoEffectProofV1,
        next_account_version: u64,
        next_resource_fence: u64,
    ) -> Result<Self, CreditAdmissionError> {
        proof.validate_for(&self.operation_id)?;
        self.transition(
            CreditExposureReservationStateV1::ReleasedBeforeDispatch,
            next_account_version,
            next_resource_fence,
        )
    }

    fn transition(
        &self,
        next_state: CreditExposureReservationStateV1,
        next_account_version: u64,
        next_resource_fence: u64,
    ) -> Result<Self, CreditAdmissionError> {
        self.validate_transition(next_state, next_account_version, next_resource_fence)?;
        let mut next = self.clone();
        next.state = next_state;
        next.account_version = next_account_version;
        next.resource_fence = next_resource_fence;
        next.validate()?;
        Ok(next)
    }

    fn validate_transition(
        &self,
        next_state: CreditExposureReservationStateV1,
        next_account_version: u64,
        next_resource_fence: u64,
    ) -> Result<(), CreditAdmissionError> {
        self.validate()?;
        if self.state != CreditExposureReservationStateV1::Reserved
            || !matches!(
                next_state,
                CreditExposureReservationStateV1::Committed
                    | CreditExposureReservationStateV1::ReleasedBeforeDispatch
                    | CreditExposureReservationStateV1::OutcomeUnknown
            )
            || self.account_version >= next_account_version
            || self.resource_fence >= next_resource_fence
            || next_account_version != next_resource_fence
        {
            return Err(CreditAdmissionError::IllegalReservationTransition);
        }
        Ok(())
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn action_nonce(&self) -> &str {
        &self.action_nonce
    }

    #[must_use]
    pub fn reservation_digest(&self) -> &str {
        &self.reservation_digest
    }

    #[must_use]
    pub fn obligation_id(&self) -> Option<&str> {
        self.obligation_id.as_deref()
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> Option<&str> {
        self.obligation_atom_digest.as_deref()
    }

    #[must_use]
    pub fn debtor_id(&self) -> &str {
        &self.debtor_id
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    #[must_use]
    pub const fn amount(&self) -> &MonetaryAmount {
        &self.amount
    }

    #[must_use]
    pub const fn effective_ceiling(&self) -> &MonetaryAmount {
        &self.effective_ceiling
    }

    #[must_use]
    pub fn authority_configuration_digest(&self) -> &str {
        &self.authority_configuration_digest
    }

    #[must_use]
    pub fn authority_set_digest(&self) -> &str {
        &self.authority_set_digest
    }

    #[must_use]
    pub fn facility_id(&self) -> &str {
        &self.facility_id
    }

    #[must_use]
    pub fn facility_artifact_digest(&self) -> &str {
        &self.facility_artifact_digest
    }

    #[must_use]
    pub fn credit_facility_bind_digest(&self) -> &str {
        &self.credit_facility_bind_digest
    }

    #[must_use]
    pub fn credit_facility_bind_canonical(&self) -> &[u8] {
        &self.credit_facility_bind_canonical
    }

    #[must_use]
    pub fn bind_trust_configuration_digest(&self) -> &str {
        &self.bind_trust_configuration_digest
    }

    #[must_use]
    pub fn authority_evidence(&self) -> &[CreditAuthorityEvidenceV1] {
        &self.authority_evidence
    }

    #[must_use]
    pub const fn authority_expires_at_unix_seconds(&self) -> u64 {
        self.authority_expires_at_unix_seconds
    }

    #[must_use]
    pub const fn source_account_version(&self) -> u64 {
        self.source_account_version
    }

    #[must_use]
    pub const fn source_resource_fence(&self) -> u64 {
        self.source_resource_fence
    }

    #[must_use]
    pub const fn account_version(&self) -> u64 {
        self.account_version
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        self.resource_fence
    }

    #[must_use]
    pub const fn state(&self) -> CreditExposureReservationStateV1 {
        self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditExposureReservation {
    record: CreditExposureReservationRecordV1,
}

impl CreditExposureReservation {
    fn from_committed_record(
        record: CreditExposureReservationRecordV1,
    ) -> Result<Self, CreditAdmissionError> {
        record.validate()?;
        if record.state() != CreditExposureReservationStateV1::Committed
            || record.obligation_id().is_none()
            || record.obligation_atom_digest().is_none()
        {
            return Err(CreditAdmissionError::OperationConflict);
        }
        Ok(Self { record })
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        self.record.operation_id()
    }

    #[must_use]
    pub fn action_nonce(&self) -> &str {
        self.record.action_nonce()
    }

    #[must_use]
    pub fn reservation_digest(&self) -> &str {
        self.record.reservation_digest()
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.record.request_id
    }

    #[must_use]
    pub fn economic_intent_digest(&self) -> &str {
        &self.record.economic_intent_digest
    }

    #[must_use]
    pub fn obligation_id(&self) -> Option<&str> {
        self.record.obligation_id()
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> Option<&str> {
        self.record.obligation_atom_digest()
    }

    pub fn validate_committed_binding(
        &self,
        atom: &ObligationAtomV1,
        credit_facility_bind: &VerifiedCreditFacilityBindV1,
    ) -> Result<(), CreditAdmissionError> {
        self.record.validate_committed_obligation(atom)?;
        let bind = credit_facility_bind.body();
        if self.record.operation_id != bind.operation_id()
            || self.record.request_id != bind.request_id()
            || self.record.action_nonce != bind.action_nonce()
            || self.record.economic_intent_digest != bind.economic_intent_digest()
            || self.record.debtor_id != bind.debtor_id()
            || self.record.scope_digest != bind.scope_digest()
            || self.record.capability_id != bind.capability_id()
            || self.record.amount != *bind.amount()
            || self.record.effective_ceiling != *bind.effective_ceiling()
            || self.record.facility_id != bind.facility_id()
            || self.record.facility_artifact_digest != bind.facility_artifact_digest()
            || self.record.authority_set_digest != bind.authority_set_digest()
            || self.record.original_creditor_id != bind.original_creditor_id()
            || self.record.original_settlement_destination_ref
                != bind.original_settlement_destination_ref()
            || self.record.payee_binding_digest != bind.payee_binding_digest()
            || self.record.bind_issued_at_unix_ms != bind.issued_at_unix_ms()
            || self.record.bind_expires_at_unix_ms != bind.expires_at_unix_ms()
            || self.record.due_at_unix_ms != bind.due_at_unix_ms()
            || self.record.source_account_version != bind.expected_exposure_version()
            || self.record.source_resource_fence != bind.expected_exposure_fence()
            || self.record.credit_facility_bind_digest != credit_facility_bind.artifact_digest()
            || self.record.credit_facility_bind_canonical.as_slice()
                != credit_facility_bind.canonical_bytes()
            || self.record.bind_trust_configuration_digest
                != credit_facility_bind.trust_configuration_digest()
        {
            return Err(CreditAdmissionError::OperationConflict);
        }
        Ok(())
    }

    #[must_use]
    pub fn debtor_id(&self) -> &str {
        self.record.debtor_id()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        self.record.scope_digest()
    }

    #[must_use]
    pub fn capability_id(&self) -> &str {
        self.record.capability_id()
    }

    #[must_use]
    pub const fn amount(&self) -> &MonetaryAmount {
        self.record.amount()
    }

    #[must_use]
    pub const fn effective_ceiling(&self) -> &MonetaryAmount {
        self.record.effective_ceiling()
    }

    #[must_use]
    pub fn authority_configuration_digest(&self) -> &str {
        self.record.authority_configuration_digest()
    }

    #[must_use]
    pub fn authority_set_digest(&self) -> &str {
        self.record.authority_set_digest()
    }

    #[must_use]
    pub fn facility_id(&self) -> &str {
        self.record.facility_id()
    }

    #[must_use]
    pub fn facility_artifact_digest(&self) -> &str {
        self.record.facility_artifact_digest()
    }

    #[must_use]
    pub fn credit_facility_bind_digest(&self) -> &str {
        self.record.credit_facility_bind_digest()
    }

    #[must_use]
    pub fn credit_facility_bind_canonical(&self) -> &[u8] {
        self.record.credit_facility_bind_canonical()
    }

    #[must_use]
    pub fn bind_trust_configuration_digest(&self) -> &str {
        self.record.bind_trust_configuration_digest()
    }

    #[must_use]
    pub fn authority_evidence(&self) -> &[CreditAuthorityEvidenceV1] {
        self.record.authority_evidence()
    }

    #[must_use]
    pub const fn authority_expires_at_unix_seconds(&self) -> u64 {
        self.record.authority_expires_at_unix_seconds()
    }

    #[must_use]
    pub const fn source_account_version(&self) -> u64 {
        self.record.source_account_version
    }

    #[must_use]
    pub const fn source_resource_fence(&self) -> u64 {
        self.record.source_resource_fence
    }

    #[must_use]
    pub const fn account_version(&self) -> u64 {
        self.record.account_version()
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        self.record.resource_fence()
    }

    #[must_use]
    pub const fn state(&self) -> CreditExposureReservationStateV1 {
        self.record.state()
    }

    #[must_use]
    pub const fn store_record(&self) -> &CreditExposureReservationRecordV1 {
        &self.record
    }
}

pub trait CreditAdmissionStore: Send + Sync {
    fn lookup_record_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<CreditExposureReservationRecordV1>, CreditAdmissionError>;
}

pub struct CreditAdmissionStoreAdapter<B> {
    backend: B,
}

impl<B> CreditAdmissionStoreAdapter<B> {
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    pub fn lookup_committed_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<CreditExposureReservation>, CreditAdmissionError>
    where
        B: CreditAdmissionStore,
    {
        validate_admission_digest("operation_id", operation_id)?;
        self.backend
            .lookup_record_by_operation(operation_id)?
            .map(|record| {
                if record.operation_id() != operation_id {
                    return Err(CreditAdmissionError::OperationConflict);
                }
                CreditExposureReservation::from_committed_record(record)
            })
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreditPreDispatchNoEffectDigestPreimageV1<'a> {
    operation_id: &'a str,
    slot_digest: &'a str,
    terminal_proof_id: &'a str,
    terminal_proof_digest: &'a str,
    expected_head_version: u64,
    expected_head_digest: &'a str,
    expected_lifecycle_fence: u64,
    resulting_head_version: u64,
    resulting_head_digest: &'a str,
    resulting_lifecycle_fence: u64,
    checkpoint_sequence: u64,
    checkpoint_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCreditPreDispatchNoEffectProofV1 {
    operation_id: String,
    slot_digest: String,
    terminal_proof_id: String,
    terminal_proof_digest: String,
    expected_head_version: u64,
    expected_head_digest: String,
    expected_lifecycle_fence: u64,
    resulting_head_version: u64,
    resulting_head_digest: String,
    resulting_lifecycle_fence: u64,
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    proof_digest: String,
}

impl VerifiedCreditPreDispatchNoEffectProofV1 {
    pub fn validate_for(&self, operation_id: &str) -> Result<(), CreditAdmissionError> {
        validate_admission_digest("operation_id", operation_id)?;
        if self.operation_id != operation_id || self.proof_digest != credit_no_effect_digest(self)?
        {
            return Err(CreditAdmissionError::OperationConflict);
        }
        Ok(())
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    #[must_use]
    pub const fn resulting_head_version(&self) -> u64 {
        self.resulting_head_version
    }

    #[must_use]
    pub const fn resulting_lifecycle_fence(&self) -> u64 {
        self.resulting_lifecycle_fence
    }

    #[must_use]
    pub const fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }
}

pub fn verify_credit_pre_dispatch_no_effect(
    operation_id: &str,
    evidence: &VerifiedEconomicEffectNotDispatched,
) -> Result<VerifiedCreditPreDispatchNoEffectProofV1, CreditAdmissionError> {
    validate_admission_digest("operation_id", operation_id)?;
    let slot = evidence.slot();
    slot.validate()
        .map_err(|_| CreditAdmissionError::AuthorityVerification)?;
    let (terminal_proof_id, terminal_proof_digest) = match &slot.terminal {
        Some(EconomicEffectTerminalV1::NoEffect {
            kind: EconomicNoEffectKindV1::PreDispatch,
            proof_id,
            proof_digest,
            ..
        }) => (proof_id.clone(), proof_digest.clone()),
        _ => return Err(CreditAdmissionError::AuthorityVerification),
    };
    if evidence.kind() != EconomicNoEffectKindV1::PreDispatch
        || slot.state != EconomicEffectStateV1::NoEffect
        || slot.operation_id != operation_id
    {
        return Err(CreditAdmissionError::OperationConflict);
    }
    let mut proof = VerifiedCreditPreDispatchNoEffectProofV1 {
        operation_id: operation_id.to_owned(),
        slot_digest: slot
            .digest()
            .map_err(|_| CreditAdmissionError::AuthorityVerification)?,
        terminal_proof_id,
        terminal_proof_digest,
        expected_head_version: evidence.expected_head_version(),
        expected_head_digest: evidence.expected_head_digest().to_owned(),
        expected_lifecycle_fence: evidence.expected_lifecycle_fence(),
        resulting_head_version: evidence.resulting_head_version(),
        resulting_head_digest: evidence.resulting_head_digest().to_owned(),
        resulting_lifecycle_fence: evidence.resulting_lifecycle_fence(),
        checkpoint_sequence: evidence.checkpoint_sequence(),
        checkpoint_digest: evidence.checkpoint_digest().to_owned(),
        proof_digest: String::new(),
    };
    if proof.resulting_head_version <= proof.expected_head_version
        || proof.resulting_lifecycle_fence <= proof.expected_lifecycle_fence
        || proof.checkpoint_sequence == 0
    {
        return Err(CreditAdmissionError::AuthorityVerification);
    }
    proof.proof_digest = credit_no_effect_digest(&proof)?;
    proof.validate_for(operation_id)?;
    Ok(proof)
}

fn credit_no_effect_digest(
    proof: &VerifiedCreditPreDispatchNoEffectProofV1,
) -> Result<String, CreditAdmissionError> {
    admission_domain_digest(
        PRE_DISPATCH_NO_EFFECT_DIGEST_DOMAIN,
        &CreditPreDispatchNoEffectDigestPreimageV1 {
            operation_id: &proof.operation_id,
            slot_digest: &proof.slot_digest,
            terminal_proof_id: &proof.terminal_proof_id,
            terminal_proof_digest: &proof.terminal_proof_digest,
            expected_head_version: proof.expected_head_version,
            expected_head_digest: &proof.expected_head_digest,
            expected_lifecycle_fence: proof.expected_lifecycle_fence,
            resulting_head_version: proof.resulting_head_version,
            resulting_head_digest: &proof.resulting_head_digest,
            resulting_lifecycle_fence: proof.resulting_lifecycle_fence,
            checkpoint_sequence: proof.checkpoint_sequence,
            checkpoint_digest: &proof.checkpoint_digest,
        },
    )
}

fn validate_admission_text(field: &'static str, value: &str) -> Result<(), CreditAdmissionError> {
    validate_text(field, value).map_err(|_| CreditAdmissionError::InvalidField(field))
}

fn validate_admission_digest(field: &'static str, value: &str) -> Result<(), CreditAdmissionError> {
    validate_digest(field, value).map_err(|_| CreditAdmissionError::InvalidField(field))
}

fn validate_amount(
    amount: &MonetaryAmount,
    field: &'static str,
) -> Result<(), CreditAdmissionError> {
    validate_money(amount).map_err(|_| CreditAdmissionError::InvalidField(field))
}

fn validate_authority_evidence(
    evidence: &CreditAuthorityEvidenceV1,
) -> Result<(), CreditAdmissionError> {
    validate_admission_text("authority_id", &evidence.authority_id)?;
    validate_seconds("authority_epoch", evidence.authority_epoch)?;
    validate_admission_text("authority_artifact_id", &evidence.artifact_id)?;
    validate_admission_digest("authority_artifact_digest", &evidence.artifact_digest)?;
    validate_amount(&evidence.ceiling, "authority_ceiling")?;
    validate_seconds(
        "authority_expires_at_unix_seconds",
        evidence.expires_at_unix_seconds,
    )
}

fn validate_seconds(field: &'static str, value: u64) -> Result<(), CreditAdmissionError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        return Err(CreditAdmissionError::InvalidField(field));
    }
    Ok(())
}

fn validate_currency(currency: &str) -> Result<(), CreditAdmissionError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(CreditAdmissionError::InvalidField("currency"));
    }
    Ok(())
}

fn admission_domain_digest(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<String, CreditAdmissionError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| CreditAdmissionError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn proof(
        operation_id: String,
    ) -> Result<VerifiedCreditPreDispatchNoEffectProofV1, CreditAdmissionError> {
        let mut proof = VerifiedCreditPreDispatchNoEffectProofV1 {
            operation_id,
            slot_digest: digest("slot"),
            terminal_proof_id: "proof-1".to_owned(),
            terminal_proof_digest: digest("terminal-proof"),
            expected_head_version: 1,
            expected_head_digest: digest("expected-head"),
            expected_lifecycle_fence: 1,
            resulting_head_version: 2,
            resulting_head_digest: digest("resulting-head"),
            resulting_lifecycle_fence: 2,
            checkpoint_sequence: 3,
            checkpoint_digest: digest("checkpoint"),
            proof_digest: String::new(),
        };
        proof.proof_digest = credit_no_effect_digest(&proof)?;
        Ok(proof)
    }

    #[test]
    fn sealed_credit_no_effect_proof_is_operation_bound() -> Result<(), CreditAdmissionError> {
        let operation_id = digest("operation");
        let proof = proof(operation_id.clone())?;
        assert_eq!(proof.validate_for(&operation_id), Ok(()));
        assert_eq!(
            proof.validate_for(&digest("other-operation")),
            Err(CreditAdmissionError::OperationConflict)
        );
        Ok(())
    }
}
