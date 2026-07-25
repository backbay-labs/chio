use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyCredentialIssuanceAnchorInputV2 {
    pub authority_id: String,
    pub signer_key_epoch: u64,
    pub registry_generation: u64,
    pub registry_checkpoint_digest: String,
    pub credential_envelope_digest: String,
    pub issuer: String,
    pub verification_method: String,
    pub resolved_key_id: String,
    pub observed_issued_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyCredentialIssuanceAnchorV2 {
    pub schema: String,
    pub authority_id: String,
    pub signer_key_epoch: u64,
    pub registry_generation: u64,
    pub registry_checkpoint_digest: String,
    pub credential_envelope_digest: String,
    pub issuer: String,
    pub verification_method: String,
    pub resolved_key_id: String,
    pub observed_issued_at: u64,
    pub anchor_digest: String,
}

pub type SignedLegacyCredentialIssuanceAnchorV2 =
    chio_core::receipt::lineage::SignedExportEnvelope<LegacyCredentialIssuanceAnchorV2>;

pub trait LegacyCredentialIssuanceAnchorResolver {
    fn resolve(
        &self,
        credential_envelope_digest: &str,
        issuer: &str,
        verification_method: &str,
    ) -> Result<SignedLegacyCredentialIssuanceAnchorV2, FinancialAuthorityAvailabilityError>;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryActivationDigestPreimageV2<'a> {
    schema: &'a str,
    pack_id: &'a str,
    verifier_id: &'a str,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
    entry_id: &'a str,
    source_passport_id: &'a str,
    source_manifest_digest: &'a str,
    presentation_digest: &'a str,
    credential_bindings: &'a [EntryActivationCredentialBindingV2],
    issuer: &'a str,
    profile_family: &'a str,
    source_kind: CrossIssuerPortfolioEntryKind,
    certification_refs: &'a [String],
    lifecycle_evidence_digest: &'a str,
    lifecycle_pin_digest: &'a str,
    migration_envelope_digests: &'a [String],
    decision: EntryActivationDispositionV2,
    reason: &'a str,
    decided_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationDigestPreimageV2<'a> {
    schema: &'a str,
    migration_id: &'a str,
    attester_id: &'a str,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
    from_issuer: &'a str,
    to_issuer: &'a str,
    from_subject: &'a str,
    to_subject: &'a str,
    prior_source_passport_ids: &'a [String],
    reason: &'a str,
    continuity_ref: &'a str,
    issued_at: u64,
    expires_at: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyAnchorDigestPreimageV2<'a> {
    schema: &'a str,
    authority_id: &'a str,
    signer_key_epoch: u64,
    registry_generation: u64,
    registry_checkpoint_digest: &'a str,
    credential_envelope_digest: &'a str,
    issuer: &'a str,
    verification_method: &'a str,
    resolved_key_id: &'a str,
    observed_issued_at: u64,
}

pub fn sign_entry_activation_decision_v2(
    signer: &Keypair,
    input: EntryActivationDecisionInputV2,
) -> Result<SignedEntryActivationDecisionV2, CredentialError> {
    let mut body = EntryActivationDecisionV2 {
        schema: FINANCIAL_ENTRY_ACTIVATION_DECISION_SCHEMA_V1.to_string(),
        pack_id: input.pack_id,
        verifier_id: input.verifier_id,
        signer_key_id: input.signer_key_id,
        signer_key_epoch: input.signer_key_epoch,
        entry_id: input.entry_id,
        source_passport_id: input.source_passport_id,
        source_manifest_digest: input.source_manifest_digest,
        presentation_digest: input.presentation_digest,
        credential_bindings: input.credential_bindings,
        issuer: input.issuer,
        profile_family: input.profile_family,
        source_kind: input.source_kind,
        certification_refs: input.certification_refs,
        lifecycle_evidence_digest: input.lifecycle_evidence_digest,
        lifecycle_pin_digest: input.lifecycle_pin_digest,
        migration_envelope_digests: input.migration_envelope_digests,
        decision: input.decision,
        reason: input.reason,
        decided_at: input.decided_at,
        decision_digest: String::new(),
    };
    normalize_activation_decision(&mut body)?;
    body.decision_digest = recompute_activation_decision_digest(&body)?;
    Ok(SignedEntryActivationDecisionV2::sign(body, signer)?)
}

pub fn sign_cross_issuer_trust_pack_v2(
    signer: &Keypair,
    input: CrossIssuerTrustPackInputV2,
) -> Result<SignedCrossIssuerTrustPackV2, CredentialError> {
    let body = CrossIssuerTrustPackV2 {
        schema: FINANCIAL_CROSS_ISSUER_TRUST_PACK_SCHEMA_V1.to_string(),
        pack_id: input.pack_id,
        verifier_id: input.verifier_id,
        signer_key_id: input.signer_key_id,
        signer_key_epoch: input.signer_key_epoch,
        created_at: input.created_at,
        expires_at: input.expires_at,
        policy: input.policy,
        decisions: input.decisions,
    };
    validate_trust_pack_body(&body)?;
    Ok(SignedCrossIssuerTrustPackV2::sign(body, signer)?)
}

pub fn verify_signed_cross_issuer_trust_pack_v2(
    pack: &SignedCrossIssuerTrustPackV2,
    trust: &CrossIssuerTrustRegistryV2,
    now: u64,
) -> Result<(), CredentialError> {
    validate_trust_pack_body(&pack.body)?;
    if now < pack.body.created_at || now >= pack.body.expires_at {
        return Err(authority_error(
            "cross-issuer trust pack is outside validity",
        ));
    }
    let verifier = trust.verifier_key(
        &pack.body.verifier_id,
        &pack.body.signer_key_id,
        pack.body.signer_key_epoch,
    )?;
    if verifier.public_key != pack.signer_key || !pack.verify_signature()? {
        return Err(authority_error(
            "cross-issuer trust pack signer does not match trusted verifier key",
        ));
    }
    for decision in &pack.body.decisions {
        verify_activation_decision_signature(decision, trust, now)?;
        if decision.body.pack_id != pack.body.pack_id
            || decision.body.verifier_id != pack.body.verifier_id
            || decision.body.signer_key_id != pack.body.signer_key_id
            || decision.body.signer_key_epoch != pack.body.signer_key_epoch
            || decision.signer_key != pack.signer_key
        {
            return Err(authority_error(
                "entry activation decision does not match its trust pack",
            ));
        }
    }
    Ok(())
}

pub fn sign_cross_issuer_migration_v2(
    signer: &Keypair,
    input: CrossIssuerMigrationInputV2,
) -> Result<SignedCrossIssuerMigrationV2, CredentialError> {
    let mut body = CrossIssuerMigrationV2 {
        schema: FINANCIAL_CROSS_ISSUER_MIGRATION_SCHEMA_V1.to_string(),
        migration_id: input.migration_id,
        attester_id: input.attester_id,
        signer_key_id: input.signer_key_id,
        signer_key_epoch: input.signer_key_epoch,
        from_issuer: input.from_issuer,
        to_issuer: input.to_issuer,
        from_subject: input.from_subject,
        to_subject: input.to_subject,
        prior_source_passport_ids: input.prior_source_passport_ids,
        reason: input.reason,
        continuity_ref: input.continuity_ref,
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        migration_digest: String::new(),
    };
    validate_migration_body(&mut body)?;
    body.migration_digest = recompute_migration_digest(&body)?;
    Ok(SignedCrossIssuerMigrationV2::sign(body, signer)?)
}

pub fn verify_cross_issuer_migration_v2(
    migration: &SignedCrossIssuerMigrationV2,
    trust: &CrossIssuerTrustRegistryV2,
    now: u64,
) -> Result<(), CredentialError> {
    let mut body = migration.body.clone();
    validate_migration_body(&mut body)?;
    if body != migration.body
        || recompute_migration_digest(&body)? != body.migration_digest
        || now < body.issued_at
        || body.expires_at.is_some_and(|expires_at| now >= expires_at)
    {
        return Err(authority_error(
            "cross-issuer migration contract is invalid",
        ));
    }
    let attester = trust.migration_key(
        &body.attester_id,
        &body.signer_key_id,
        body.signer_key_epoch,
    )?;
    if attester.public_key != migration.signer_key || !migration.verify_signature()? {
        return Err(authority_error(
            "cross-issuer migration signer does not match local trust",
        ));
    }
    Ok(())
}

pub fn sign_legacy_credential_issuance_anchor_v2(
    signer: &Keypair,
    input: LegacyCredentialIssuanceAnchorInputV2,
) -> Result<SignedLegacyCredentialIssuanceAnchorV2, CredentialError> {
    let mut body = LegacyCredentialIssuanceAnchorV2 {
        schema: FINANCIAL_LEGACY_CREDENTIAL_ISSUANCE_ANCHOR_SCHEMA_V1.to_string(),
        authority_id: input.authority_id,
        signer_key_epoch: input.signer_key_epoch,
        registry_generation: input.registry_generation,
        registry_checkpoint_digest: input.registry_checkpoint_digest,
        credential_envelope_digest: input.credential_envelope_digest,
        issuer: input.issuer,
        verification_method: input.verification_method,
        resolved_key_id: input.resolved_key_id,
        observed_issued_at: input.observed_issued_at,
        anchor_digest: String::new(),
    };
    validate_legacy_anchor_body(&body)?;
    body.anchor_digest = recompute_legacy_anchor_digest(&body)?;
    Ok(SignedLegacyCredentialIssuanceAnchorV2::sign(body, signer)?)
}

pub(in crate::financial_authority) fn verify_legacy_credential_authority(
    credential: &ReputationCredential,
    trust: &CrossIssuerTrustRegistryV2,
    anchors: &dyn LegacyCredentialIssuanceAnchorResolver,
    now: u64,
) -> Result<(), CredentialError> {
    let envelope_digest = sha256_hex(&canonical_json_bytes(credential)?);
    let anchor = anchors
        .resolve(
            &envelope_digest,
            &credential.unsigned.issuer,
            &credential.proof.verification_method,
        )
        .map_err(|_| authority_error("legacy issuance anchor is unavailable"))?;
    validate_legacy_anchor_body(&anchor.body)?;
    trust.verify_legacy_anchor_authority(&anchor)?;
    if !anchor.verify_signature()?
        || recompute_legacy_anchor_digest(&anchor.body)? != anchor.body.anchor_digest
        || anchor.body.credential_envelope_digest != envelope_digest
        || anchor.body.issuer != credential.unsigned.issuer
        || anchor.body.verification_method != credential.proof.verification_method
        || anchor.body.observed_issued_at > now
    {
        return Err(authority_error("legacy issuance anchor binding is invalid"));
    }
    let key = trust.legacy_reputation_key(
        &anchor.body.issuer,
        &anchor.body.verification_method,
        &anchor.body.resolved_key_id,
        anchor.body.observed_issued_at,
    )?;
    let signature = Signature::from_hex(&credential.proof.proof_value)?;
    if !key
        .public_key
        .verify(&canonical_json_bytes(&credential.unsigned)?, &signature)
    {
        return Err(authority_error(
            "legacy reputation signature does not match interval authority",
        ));
    }
    Ok(())
}

fn verify_activation_decision_signature(
    decision: &SignedEntryActivationDecisionV2,
    trust: &CrossIssuerTrustRegistryV2,
    now: u64,
) -> Result<(), CredentialError> {
    let mut normalized = decision.body.clone();
    normalize_activation_decision(&mut normalized)?;
    if normalized != decision.body
        || recompute_activation_decision_digest(&decision.body)? != decision.body.decision_digest
        || decision.body.decided_at > now
    {
        return Err(authority_error(
            "entry activation decision contract is invalid",
        ));
    }
    let verifier = trust.verifier_key(
        &decision.body.verifier_id,
        &decision.body.signer_key_id,
        decision.body.signer_key_epoch,
    )?;
    if verifier.public_key != decision.signer_key || !decision.verify_signature()? {
        return Err(authority_error(
            "entry activation signer does not match trusted verifier key",
        ));
    }
    Ok(())
}

fn validate_trust_pack_body(body: &CrossIssuerTrustPackV2) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_CROSS_ISSUER_TRUST_PACK_SCHEMA_V1
        || body.created_at >= body.expires_at
        || body.decisions.is_empty()
    {
        return Err(authority_error(
            "cross-issuer trust pack contract is invalid",
        ));
    }
    validate_text("trustPack.packId", &body.pack_id)?;
    validate_text("trustPack.verifierId", &body.verifier_id)?;
    validate_text("trustPack.signerKeyId", &body.signer_key_id)?;
    validate_epoch("trustPack.signerKeyEpoch", body.signer_key_epoch)?;
    validate_string_set(&body.policy.allowed_issuers, "allowedIssuers")?;
    validate_string_set(
        &body.policy.allowed_profile_families,
        "allowedProfileFamilies",
    )?;
    validate_string_set(
        &body.policy.allowed_certification_refs,
        "allowedCertificationRefs",
    )?;
    let mut prior = None;
    for decision in &body.decisions {
        if prior
            .as_ref()
            .is_some_and(|prior: &String| prior >= &decision.body.entry_id)
        {
            return Err(authority_error(
                "trust-pack decisions must be sorted and unique",
            ));
        }
        prior = Some(decision.body.entry_id.clone());
    }
    Ok(())
}

fn normalize_activation_decision(
    body: &mut EntryActivationDecisionV2,
) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_ENTRY_ACTIVATION_DECISION_SCHEMA_V1 {
        return Err(authority_error("entry activation schema is invalid"));
    }
    for (field, value) in [
        ("packId", &body.pack_id),
        ("verifierId", &body.verifier_id),
        ("signerKeyId", &body.signer_key_id),
        ("entryId", &body.entry_id),
        ("profileFamily", &body.profile_family),
        ("reason", &body.reason),
    ] {
        validate_text(field, value)?;
    }
    validate_epoch("entryDecision.signerKeyEpoch", body.signer_key_epoch)?;
    DidChio::from_str(&body.issuer)?;
    for (field, digest) in [
        ("sourcePassportId", &body.source_passport_id),
        ("sourceManifestDigest", &body.source_manifest_digest),
        ("presentationDigest", &body.presentation_digest),
        ("lifecycleEvidenceDigest", &body.lifecycle_evidence_digest),
        ("lifecyclePinDigest", &body.lifecycle_pin_digest),
    ] {
        validate_digest(field, digest)?;
    }
    if body.credential_bindings.is_empty() {
        return Err(authority_error(
            "entry activation credential bindings are empty",
        ));
    }
    body.credential_bindings.sort();
    if body
        .credential_bindings
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(authority_error(
            "entry activation credential bindings are duplicated",
        ));
    }
    for binding in &body.credential_bindings {
        validate_digest("activation.credentialId", &binding.credential_id)?;
        validate_digest("activation.envelopeDigest", &binding.envelope_digest)?;
    }
    normalize_strings(&mut body.certification_refs, "certificationRefs")?;
    normalize_optional_digests(
        &mut body.migration_envelope_digests,
        "migrationEnvelopeDigests",
    )?;
    Ok(())
}

fn validate_migration_body(body: &mut CrossIssuerMigrationV2) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_CROSS_ISSUER_MIGRATION_SCHEMA_V1 {
        return Err(authority_error("cross-issuer migration schema is invalid"));
    }
    for value in [
        &body.migration_id,
        &body.attester_id,
        &body.signer_key_id,
        &body.reason,
        &body.continuity_ref,
    ] {
        validate_text("migration.field", value)?;
    }
    validate_epoch("migration.signerKeyEpoch", body.signer_key_epoch)?;
    for value in [
        &body.from_issuer,
        &body.to_issuer,
        &body.from_subject,
        &body.to_subject,
    ] {
        DidChio::from_str(value)?;
    }
    if body
        .expires_at
        .is_some_and(|expires_at| body.issued_at >= expires_at)
    {
        return Err(authority_error(
            "cross-issuer migration validity is invalid",
        ));
    }
    normalize_digests(
        &mut body.prior_source_passport_ids,
        "priorSourcePassportIds",
    )?;
    Ok(())
}

fn validate_legacy_anchor_body(
    body: &LegacyCredentialIssuanceAnchorV2,
) -> Result<(), CredentialError> {
    if body.schema != FINANCIAL_LEGACY_CREDENTIAL_ISSUANCE_ANCHOR_SCHEMA_V1 {
        return Err(authority_error("legacy issuance anchor schema is invalid"));
    }
    validate_text("legacyAnchor.authorityId", &body.authority_id)?;
    validate_text("legacyAnchor.verificationMethod", &body.verification_method)?;
    validate_text("legacyAnchor.resolvedKeyId", &body.resolved_key_id)?;
    validate_epoch("legacyAnchor.signerKeyEpoch", body.signer_key_epoch)?;
    validate_epoch("legacyAnchor.registryGeneration", body.registry_generation)?;
    DidChio::from_str(&body.issuer)?;
    validate_digest(
        "legacyAnchor.registryCheckpointDigest",
        &body.registry_checkpoint_digest,
    )?;
    validate_digest(
        "legacyAnchor.credentialEnvelopeDigest",
        &body.credential_envelope_digest,
    )?;
    if !body.anchor_digest.is_empty() {
        validate_digest("legacyAnchor.anchorDigest", &body.anchor_digest)?;
    }
    Ok(())
}

fn recompute_activation_decision_digest(
    body: &EntryActivationDecisionV2,
) -> Result<String, CredentialError> {
    authority_digest(
        ENTRY_ACTIVATION_DIGEST_DOMAIN,
        &EntryActivationDigestPreimageV2 {
            schema: &body.schema,
            pack_id: &body.pack_id,
            verifier_id: &body.verifier_id,
            signer_key_id: &body.signer_key_id,
            signer_key_epoch: body.signer_key_epoch,
            entry_id: &body.entry_id,
            source_passport_id: &body.source_passport_id,
            source_manifest_digest: &body.source_manifest_digest,
            presentation_digest: &body.presentation_digest,
            credential_bindings: &body.credential_bindings,
            issuer: &body.issuer,
            profile_family: &body.profile_family,
            source_kind: body.source_kind,
            certification_refs: &body.certification_refs,
            lifecycle_evidence_digest: &body.lifecycle_evidence_digest,
            lifecycle_pin_digest: &body.lifecycle_pin_digest,
            migration_envelope_digests: &body.migration_envelope_digests,
            decision: body.decision,
            reason: &body.reason,
            decided_at: body.decided_at,
        },
    )
}

fn recompute_migration_digest(body: &CrossIssuerMigrationV2) -> Result<String, CredentialError> {
    authority_digest(
        CROSS_ISSUER_MIGRATION_DIGEST_DOMAIN,
        &MigrationDigestPreimageV2 {
            schema: &body.schema,
            migration_id: &body.migration_id,
            attester_id: &body.attester_id,
            signer_key_id: &body.signer_key_id,
            signer_key_epoch: body.signer_key_epoch,
            from_issuer: &body.from_issuer,
            to_issuer: &body.to_issuer,
            from_subject: &body.from_subject,
            to_subject: &body.to_subject,
            prior_source_passport_ids: &body.prior_source_passport_ids,
            reason: &body.reason,
            continuity_ref: &body.continuity_ref,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
        },
    )
}

fn recompute_legacy_anchor_digest(
    body: &LegacyCredentialIssuanceAnchorV2,
) -> Result<String, CredentialError> {
    authority_digest(
        LEGACY_ISSUANCE_ANCHOR_DIGEST_DOMAIN,
        &LegacyAnchorDigestPreimageV2 {
            schema: &body.schema,
            authority_id: &body.authority_id,
            signer_key_epoch: body.signer_key_epoch,
            registry_generation: body.registry_generation,
            registry_checkpoint_digest: &body.registry_checkpoint_digest,
            credential_envelope_digest: &body.credential_envelope_digest,
            issuer: &body.issuer,
            verification_method: &body.verification_method,
            resolved_key_id: &body.resolved_key_id,
            observed_issued_at: body.observed_issued_at,
        },
    )
}
