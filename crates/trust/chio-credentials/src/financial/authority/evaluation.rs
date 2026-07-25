use super::*;
use super::trust::verify_legacy_credential_authority;
use crate::financial_passport_v2::validate_presented_agent_passport_v2_authority_contract;

const FINANCIAL_CREDENTIAL_BODY_DIGEST_DOMAIN: &[u8] = b"chio.fincred.verified-body-digest.v1\0";

pub type FinancialCredentialTrustRegistry = CrossIssuerTrustRegistryV2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFinancialEvidenceV2 {
    source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    proof_digests: Vec<String>,
}

impl ResolvedFinancialEvidenceV2 {
    pub fn authenticated(
        source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
        mut proof_digests: Vec<String>,
    ) -> Result<Self, CredentialError> {
        normalize_proof_digests(&mut proof_digests)?;
        Ok(Self {
            source_evidence_class,
            proof_digests,
        })
    }
}

pub trait FinancialEvidenceSourceResolver {
    fn resolve(
        &self,
        credential: &FinancialCredentialEnvelope,
        now: u64,
    ) -> Result<ResolvedFinancialEvidenceV2, CredentialError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BundledFinancialEvidenceSourceResolver;

impl FinancialEvidenceSourceResolver for BundledFinancialEvidenceSourceResolver {
    fn resolve(
        &self,
        credential: &FinancialCredentialEnvelope,
        _now: u64,
    ) -> Result<ResolvedFinancialEvidenceV2, CredentialError> {
        if !matches!(
            &credential.evidence.source_disclosure,
            FinancialSourceDisclosureV1::Bundled { .. }
        ) {
            return Err(CredentialError::FinancialSourceResolverUnavailable);
        }
        let issued_at = unix_from_rfc3339(&credential.issuance_date)?;
        let expires_at = unix_from_rfc3339(&credential.expiration_date)?;
        validate_financial_evidence(credential, issued_at, expires_at)?;
        let proof_digests = credential
            .evidence
            .source_completeness_attestations
            .iter()
            .map(signed_envelope_digest)
            .collect::<Result<Vec<_>, _>>()?;
        ResolvedFinancialEvidenceV2::authenticated(credential.source_evidence_class, proof_digests)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_financial_credentials(
    presentation: &PresentedAgentPassportV2,
    policy: &VerifiedFinancialVerifierPolicy,
    trust: &FinancialCredentialTrustRegistry,
    lifecycle: &dyn CrossIssuerLifecycleResolver,
    lifecycle_generation: &dyn CrossIssuerLifecycleGenerationAnchor,
    lifecycle_high_water: &dyn CrossIssuerLifecycleHighWaterStore,
    sources: &dyn FinancialEvidenceSourceResolver,
    clock: &dyn TrustedClock,
) -> Result<VerifiedFinancialCredentialSet, CredentialError> {
    evaluate_financial_credentials_inner(
        presentation,
        policy,
        trust,
        lifecycle,
        lifecycle_generation,
        lifecycle_high_water,
        sources,
        None,
        clock,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate_financial_credentials_with_legacy(
    presentation: &PresentedAgentPassportV2,
    policy: &VerifiedFinancialVerifierPolicy,
    trust: &FinancialCredentialTrustRegistry,
    lifecycle: &dyn CrossIssuerLifecycleResolver,
    lifecycle_generation: &dyn CrossIssuerLifecycleGenerationAnchor,
    lifecycle_high_water: &dyn CrossIssuerLifecycleHighWaterStore,
    sources: &dyn FinancialEvidenceSourceResolver,
    legacy_anchors: &dyn LegacyCredentialIssuanceAnchorResolver,
    clock: &dyn TrustedClock,
) -> Result<VerifiedFinancialCredentialSet, CredentialError> {
    evaluate_financial_credentials_inner(
        presentation,
        policy,
        trust,
        lifecycle,
        lifecycle_generation,
        lifecycle_high_water,
        sources,
        Some(legacy_anchors),
        clock,
    )
}

#[allow(clippy::too_many_arguments)]
fn evaluate_financial_credentials_inner(
    presentation: &PresentedAgentPassportV2,
    policy: &VerifiedFinancialVerifierPolicy,
    trust: &FinancialCredentialTrustRegistry,
    lifecycle_resolver: &dyn CrossIssuerLifecycleResolver,
    lifecycle_generation: &dyn CrossIssuerLifecycleGenerationAnchor,
    lifecycle_high_water: &dyn CrossIssuerLifecycleHighWaterStore,
    sources: &dyn FinancialEvidenceSourceResolver,
    legacy_anchors: Option<&dyn LegacyCredentialIssuanceAnchorResolver>,
    clock: &dyn TrustedClock,
) -> Result<VerifiedFinancialCredentialSet, CredentialError> {
    let now = clock
        .now()
        .map_err(|error| evaluation_availability_error("trusted clock", error))?;
    validate_time("financialEvaluation.now", now)?;
    let policy_body = policy.policy();
    if now < policy_body.not_before || now >= policy_body.expires_at {
        return Err(authority_error(
            "financial verifier policy is outside its configured validity",
        ));
    }
    validate_presented_agent_passport_v2_authority_contract(presentation, now)?;
    let manifest = &presentation.source_manifest;
    let source_manifest_digest = sha256_hex(&canonical_json_bytes(manifest)?);
    let mut credentials = Vec::new();
    let manifest_authority =
        trust.manifest_issuer_key(&manifest.body.issuer, &manifest.signer_key)?;
    if manifest_authority.public_key != manifest.signer_key || !manifest.verify_signature()? {
        return Err(authority_error(
            "source manifest signer does not match local issuer trust",
        ));
    }
    for (credential, membership) in presentation
        .credentials
        .iter()
        .zip(&presentation.membership_proofs)
    {
        match credential {
            PassportCredentialV2::Reputation(credential) => {
                let anchors = legacy_anchors.ok_or_else(|| {
                    authority_error(
                        "legacy reputation credentials require a trusted issuance anchor",
                    )
                })?;
                verify_legacy_credential_authority(credential, trust, anchors, now)?;
            }
            PassportCredentialV2::Financial(credential) => {
                let (issued_at, expires_at) = credential.validate_contract_shape()?;
                if now < issued_at {
                    return Err(CredentialError::CredentialNotYetValid);
                }
                if now >= expires_at {
                    return Err(CredentialError::CredentialExpired);
                }
                if now.saturating_sub(issued_at) > policy_body.max_credential_age_seconds {
                    return Err(authority_error(
                        "financial credential exceeds the configured maximum age",
                    ));
                }
                if !policy_body.accepted_issuers.contains(&credential.issuer)
                    || !policy_body.accepted_families.contains(&credential.family)
                {
                    return Err(authority_error(
                        "financial credential issuer or family is outside policy",
                    ));
                }
                let issuer_key = trust.issuer_key(
                    &credential.issuer,
                    &credential.proof.verification_method,
                    credential.issuer_key_epoch,
                )?;
                let signature = Signature::from_hex(&credential.proof.proof_value)?;
                if !issuer_key.public_key.verify(
                    &canonical_json_bytes(&credential.signing_body())?,
                    &signature,
                ) {
                    return Err(authority_error(
                        "financial credential signature does not match local issuer trust",
                    ));
                }
                let resolved = sources.resolve(credential, now)?;
                if resolved.source_evidence_class != credential.source_evidence_class {
                    return Err(authority_error(
                        "financial source resolver evidence class does not match credential",
                    ));
                }
                let body_digest = authority_digest(
                    FINANCIAL_CREDENTIAL_BODY_DIGEST_DOMAIN,
                    &credential.signing_body(),
                )?;
                credentials.push(VerifiedFinancialCredentialBindingV2 {
                    credential_id: credential.credential_id.clone(),
                    family: credential.family,
                    issuer: credential.issuer.clone(),
                    issuer_key_epoch: credential.issuer_key_epoch,
                    body_digest,
                    envelope_digest: membership.leaf.credential_ref_digest.clone(),
                    source_evidence_class: credential.source_evidence_class,
                    presentation_evidence_class: credential.presentation_evidence_class,
                    source_proof_digests: resolved.proof_digests,
                });
            }
        }
    }
    if credentials.is_empty() {
        return Err(authority_error(
            "financial evaluation requires at least one financial credential",
        ));
    }
    evaluate_financial_thresholds(policy_body, &presentation.credentials)?;
    credentials.sort_by(|left, right| left.credential_id.cmp(&right.credential_id));
    if credentials
        .windows(2)
        .any(|pair| pair[0].credential_id == pair[1].credential_id)
    {
        return Err(authority_error(
            "financial evaluation contains duplicate credential IDs",
        ));
    }
    let lifecycle = resolve_cross_issuer_lifecycle_v2(
        &lifecycle_resolver_identity(trust)?,
        &manifest.body.issuer,
        &manifest.body.source_passport_id,
        &source_manifest_digest,
        trust,
        lifecycle_resolver,
        lifecycle_generation,
        lifecycle_high_water,
        clock,
    )?;
    Ok(VerifiedFinancialCredentialSet {
        source_passport_id: manifest.body.source_passport_id.clone(),
        source_manifest_digest,
        presentation_digest: presentation.presentation_digest.clone(),
        credentials,
        policy_id: policy.policy_id().to_string(),
        policy_body_digest: policy.body_digest().to_string(),
        policy_generation: policy.configuration_generation(),
        lifecycle_generation: lifecycle.generation(),
        lifecycle_status_version: lifecycle.status_version(),
        lifecycle_result_digest: lifecycle.result_digest().to_string(),
        lifecycle_generation_pin_digest: lifecycle.generation_pin_digest().to_string(),
        lifecycle_checkpoint_pin_digest: lifecycle.checkpoint_pin_digest().to_string(),
        lifecycle_checkpoint_digest: lifecycle.checkpoint_digest().to_string(),
        lifecycle_source_index_proof_digest: lifecycle.source_index_proof_digest().to_string(),
    })
}

pub fn verify_entry_activation_decision_v2(
    pack: &SignedCrossIssuerTrustPackV2,
    decision: &SignedEntryActivationDecisionV2,
    verified: &VerifiedFinancialCredentialSet,
    trust: &CrossIssuerTrustRegistryV2,
    migrations: &[SignedCrossIssuerMigrationV2],
    now: u64,
) -> Result<(), CredentialError> {
    verify_signed_cross_issuer_trust_pack_v2(pack, trust, now)?;
    if !pack
        .body
        .decisions
        .iter()
        .any(|candidate| candidate == decision)
    {
        return Err(authority_error(
            "entry activation decision is not an exact trust-pack member",
        ));
    }
    let issuers = verified
        .credentials
        .iter()
        .map(|credential| credential.issuer.as_str())
        .collect::<BTreeSet<_>>();
    let issuer = issuers
        .iter()
        .next()
        .copied()
        .filter(|_| issuers.len() == 1)
        .ok_or_else(|| authority_error("entry activation issuer is ambiguous"))?;
    let metadata = trust.activation_metadata(issuer)?;
    let credential_bindings = verified
        .credentials
        .iter()
        .map(|credential| EntryActivationCredentialBindingV2 {
            credential_id: credential.credential_id.clone(),
            family: credential.family,
            envelope_digest: credential.envelope_digest.clone(),
        })
        .collect::<Vec<_>>();
    let mut migration_digests = migrations
        .iter()
        .map(|migration| {
            verify_cross_issuer_migration_v2(migration, trust, now)?;
            signed_envelope_digest(migration)
        })
        .collect::<Result<Vec<_>, CredentialError>>()?;
    migration_digests.sort();
    if migration_digests.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(authority_error(
            "entry activation migrations are duplicated",
        ));
    }
    if decision.body.migration_envelope_digests != migration_digests {
        return Err(authority_error(
            "entry activation migration envelopes do not match verified migrations",
        ));
    }
    let body = &decision.body;
    if body.source_passport_id != verified.source_passport_id
        || body.source_manifest_digest != verified.source_manifest_digest
        || body.presentation_digest != verified.presentation_digest
        || body.credential_bindings != credential_bindings
        || body.issuer != issuer
        || body.profile_family != metadata.profile_family
        || body.source_kind != metadata.source_kind
        || body.certification_refs != metadata.certification_refs
        || body.lifecycle_evidence_digest != verified.lifecycle_result_digest
        || body.lifecycle_pin_digest != verified.lifecycle_checkpoint_pin_digest
        || body.decision != EntryActivationDispositionV2::Activate
    {
        return Err(authority_error(
            "entry activation decision does not match verified evidence",
        ));
    }
    let policy = &pack.body.policy;
    if (!policy.allowed_issuers.is_empty() && !policy.allowed_issuers.contains(issuer))
        || (!policy.allowed_profile_families.is_empty()
            && !policy
                .allowed_profile_families
                .contains(&metadata.profile_family))
        || (!policy.allowed_source_kinds.is_empty()
            && !policy.allowed_source_kinds.contains(&metadata.source_kind))
        || (!policy.allowed_certification_refs.is_empty()
            && !metadata
                .certification_refs
                .iter()
                .all(|reference| policy.allowed_certification_refs.contains(reference)))
        || verified.credentials.iter().any(|credential| {
            !policy.allowed_families.is_empty()
                && !policy.allowed_families.contains(&credential.family)
        })
    {
        return Err(authority_error(
            "entry activation evidence is outside trust-pack policy",
        ));
    }
    Ok(())
}

pub const fn reject_legacy_cross_issuer_v1_activation() -> Result<(), CredentialError> {
    Err(CredentialError::UnsupportedLegacyCrossIssuerV1)
}

fn lifecycle_resolver_identity(
    trust: &CrossIssuerTrustRegistryV2,
) -> Result<String, CredentialError> {
    let identities = trust.lifecycle_resolver_identities();
    if identities.len() != 1 {
        return Err(authority_error(
            "financial evaluation requires one lifecycle resolver identity",
        ));
    }
    identities
        .into_iter()
        .next()
        .ok_or_else(|| authority_error("lifecycle resolver identity is unavailable"))
}

fn evaluate_financial_thresholds(
    policy: &FinancialVerifierPolicyV1,
    credentials: &[PassportCredentialV2],
) -> Result<(), CredentialError> {
    let mut saw_score = false;
    let mut saw_exposure = false;
    let mut saw_reliability = false;
    let mut saw_premium = false;
    let mut saw_loss = false;
    for credential in credentials {
        let PassportCredentialV2::Financial(credential) = credential else {
            continue;
        };
        match &credential.credential_subject {
            FinancialCredentialSubjectV1::CreditScorecard(subject) => {
                saw_score = true;
                if policy
                    .thresholds
                    .min_credit_score
                    .is_some_and(|minimum| subject.overall_score < minimum)
                {
                    return Err(authority_error(
                        "financial credit score is below policy minimum",
                    ));
                }
            }
            FinancialCredentialSubjectV1::ExposureHistory(subject) => {
                saw_exposure = true;
                if let Some(maximum) = policy.thresholds.max_open_exposure_ratio_bps {
                    for position in &subject.positions {
                        let open = [
                            position.reserved.units,
                            position.pending.units,
                            position.failed.units,
                            position.provisional_loss.units,
                        ]
                        .into_iter()
                        .try_fold(0_u128, |total, value| {
                            total
                                .checked_add(u128::from(value))
                                .ok_or_else(|| authority_error("financial open exposure overflows"))
                        })?;
                        let governed = u128::from(position.governed_max.units);
                        if governed == 0 {
                            if open != 0 {
                                return Err(authority_error(
                                    "financial exposure has no governed denominator",
                                ));
                            }
                            continue;
                        }
                        let ratio = open
                            .checked_mul(10_000)
                            .ok_or_else(|| authority_error("financial exposure ratio overflows"))?
                            / governed;
                        if ratio > u128::from(maximum) {
                            return Err(authority_error(
                                "financial open exposure exceeds policy maximum",
                            ));
                        }
                    }
                }
            }
            FinancialCredentialSubjectV1::SettlementReliability(subject) => {
                saw_reliability = true;
                if policy
                    .thresholds
                    .min_settlement_reliability_bps
                    .is_some_and(|minimum| subject.on_time_ratio_bps < minimum)
                {
                    return Err(authority_error(
                        "financial settlement reliability is below policy minimum",
                    ));
                }
            }
            FinancialCredentialSubjectV1::PremiumHistory(subject) => {
                saw_premium = true;
                if !policy.thresholds.max_premium_units_by_currency.is_empty() {
                    for amount in &subject.quoted_amounts {
                        let maximum = policy
                            .thresholds
                            .max_premium_units_by_currency
                            .get(&amount.currency)
                            .ok_or_else(|| {
                                authority_error("financial premium currency is outside policy")
                            })?;
                        if amount.units > *maximum {
                            return Err(authority_error(
                                "financial premium amount exceeds policy maximum",
                            ));
                        }
                    }
                }
            }
            FinancialCredentialSubjectV1::LossHistory(subject) => {
                saw_loss = true;
                if let Some(maximum) = policy.thresholds.max_loss_event_count {
                    let events = [
                        subject.delinquency_count,
                        subject.recovery_count,
                        subject.reserve_release_count,
                        subject.reserve_slash_count,
                        subject.write_off_count,
                    ]
                    .into_iter()
                    .try_fold(0_u64, |total, value| {
                        total
                            .checked_add(value)
                            .ok_or_else(|| authority_error("financial loss event count overflows"))
                    })?;
                    if events > maximum {
                        return Err(authority_error(
                            "financial loss event count exceeds policy maximum",
                        ));
                    }
                }
            }
        }
    }
    if policy.thresholds.min_credit_score.is_some() && !saw_score
        || policy.thresholds.max_open_exposure_ratio_bps.is_some() && !saw_exposure
        || policy.thresholds.min_settlement_reliability_bps.is_some() && !saw_reliability
        || !policy.thresholds.max_premium_units_by_currency.is_empty() && !saw_premium
        || policy.thresholds.max_loss_event_count.is_some() && !saw_loss
    {
        return Err(authority_error(
            "financial policy threshold has no matching credential",
        ));
    }
    Ok(())
}

fn normalize_proof_digests(values: &mut [String]) -> Result<(), CredentialError> {
    if values.is_empty() {
        return Err(authority_error("financial source proof set is empty"));
    }
    for value in values.iter() {
        validate_digest("financialSource.proofDigest", value)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(authority_error(
            "financial source proof digests are duplicated",
        ));
    }
    Ok(())
}

fn evaluation_availability_error(
    component: &str,
    error: FinancialAuthorityAvailabilityError,
) -> CredentialError {
    let reason = match error {
        FinancialAuthorityAvailabilityError::Unavailable => "is unavailable",
        FinancialAuthorityAvailabilityError::Stale => "is stale",
        FinancialAuthorityAvailabilityError::Conflict => "is conflicting",
    };
    authority_error(format!("{component} {reason}"))
}
