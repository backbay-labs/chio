use super::*;

pub fn validate_financial_source_disclosure(
    source_family: FinancialCredentialFamilyV1,
    subject: &str,
    source_signer_key: &PublicKey,
    disclosure: &FinancialSourceDisclosureV1,
) -> Result<ValidatedFinancialSourceDisclosureV1, FinancialCredentialProjectionError> {
    let artifacts = match disclosure {
        FinancialSourceDisclosureV1::Bundled { artifacts } => artifacts,
        FinancialSourceDisclosureV1::Resolver { .. } => {
            return Err(FinancialCredentialProjectionError::ResolverProofSubstrateUnavailable);
        }
    };
    if artifacts.is_empty() || artifacts.len() > MAX_SOURCE_ARTIFACTS {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let mut source_artifact_digests = Vec::with_capacity(artifacts.len());
    let mut seen = BTreeSet::new();
    for artifact in artifacts {
        validate_bundled_source_artifact(artifact)?;
        if !seen.insert(artifact.artifact_digest.as_str()) {
            return Err(FinancialCredentialProjectionError::IncompleteSource);
        }
        source_artifact_digests.push(artifact.artifact_digest.clone());
    }
    source_artifact_digests.sort();

    let (mut expected_members, maximum_source_evidence_class) = match source_family {
        FinancialCredentialFamilyV1::CreditScorecard => {
            let scorecard_artifact = one_bundled_artifact(
                artifacts,
                FinancialSourceArtifactRoleV1::Claim,
                CREDIT_SCORECARD_SCHEMA,
            )?;
            let exposure_artifact = one_bundled_artifact(
                artifacts,
                FinancialSourceArtifactRoleV1::Claim,
                EXPOSURE_LEDGER_SCHEMA,
            )?;
            let scorecard: SignedCreditScorecardReport =
                parse_bundled_source_artifact(scorecard_artifact)?;
            let exposure: SignedExposureLedgerReport =
                parse_bundled_source_artifact(exposure_artifact)?;
            inspect_source_signature(scorecard.verify_signature())?;
            if &scorecard.signer_key != source_signer_key
                || project_credit_scorecard_subject(&scorecard)?.id != subject
            {
                return Err(FinancialCredentialProjectionError::InvalidSourceSubject);
            }
            validate_scorecard_exposure_binding(&scorecard, &exposure)?;
            let members = parse_member_artifacts(artifacts)?;
            if artifacts.len() != members.len() + 2 {
                return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
            }
            let expected = validate_exposure_report_members(
                &exposure,
                FinancialCredentialFamilyV1::CreditScorecard,
                &members,
            )?
            .1;
            (expected, ProvenanceEvidenceClass::Asserted)
        }
        FinancialCredentialFamilyV1::ExposureHistory => {
            let exposure_artifact = one_bundled_artifact(
                artifacts,
                FinancialSourceArtifactRoleV1::Claim,
                EXPOSURE_LEDGER_SCHEMA,
            )?;
            let exposure: SignedExposureLedgerReport =
                parse_bundled_source_artifact(exposure_artifact)?;
            inspect_source_signature(exposure.verify_signature())?;
            if &exposure.signer_key != source_signer_key
                || project_exposure_history_subject(&exposure)?.id != subject
            {
                return Err(FinancialCredentialProjectionError::InvalidSourceSubject);
            }
            let members = parse_member_artifacts(artifacts)?;
            if artifacts.len() != members.len() + 1 {
                return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
            }
            let expected = validate_exposure_report_members(
                &exposure,
                FinancialCredentialFamilyV1::ExposureHistory,
                &members,
            )?
            .1;
            (expected, ProvenanceEvidenceClass::Asserted)
        }
        FinancialCredentialFamilyV1::PremiumHistory => {
            if artifacts
                .iter()
                .any(|artifact| artifact.role != FinancialSourceArtifactRoleV1::Member)
            {
                return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
            }
            let decisions = artifacts
                .iter()
                .map(|artifact| {
                    if artifact.artifact_schema
                        != crate::underwriting::UNDERWRITING_DECISION_ARTIFACT_SCHEMA
                    {
                        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
                    }
                    parse_bundled_source_artifact::<SignedUnderwritingDecision>(artifact)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let projected = project_premium_history_subject(&decisions)?;
            if projected.id != subject {
                return Err(FinancialCredentialProjectionError::InvalidSourceSubject);
            }
            let ordered = ordered_underwriting_decisions(&decisions)?;
            if ordered
                .first()
                .is_none_or(|decision| &decision.signer_key != source_signer_key)
            {
                return Err(FinancialCredentialProjectionError::InvalidSourceSignature);
            }
            let mut expected = Vec::with_capacity(ordered.len());
            for decision in ordered {
                expected.push(
                    expected_native_member(
                        source_family,
                        subject.to_string(),
                        decision.body.issued_at,
                        decision.body.decision_id.clone(),
                        crate::underwriting::UNDERWRITING_DECISION_ARTIFACT_SCHEMA,
                        decision,
                        ProvenanceEvidenceClass::Asserted,
                    )?
                    .1,
                );
            }
            (expected, ProvenanceEvidenceClass::Asserted)
        }
        FinancialCredentialFamilyV1::LossHistory => {
            if artifacts
                .iter()
                .any(|artifact| artifact.role != FinancialSourceArtifactRoleV1::Member)
            {
                return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
            }
            let events = artifacts
                .iter()
                .map(|artifact| {
                    if artifact.artifact_schema != CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA {
                        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
                    }
                    parse_bundled_source_artifact::<SignedCreditLossLifecycle>(artifact)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let ordered = ordered_loss_events(&events)?;
            validate_loss_lifecycle_continuity(&ordered)?;
            if project_loss_history_subject(&ordered)?.id != subject
                || ordered
                    .first()
                    .is_none_or(|event| &event.signer_key != source_signer_key)
            {
                return Err(FinancialCredentialProjectionError::InvalidSourceSubject);
            }
            let mut expected = Vec::with_capacity(ordered.len());
            for event in ordered {
                expected.push(
                    expected_native_member(
                        source_family,
                        subject.to_string(),
                        event.body.issued_at,
                        event.body.event_id.clone(),
                        CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA,
                        event,
                        ProvenanceEvidenceClass::Asserted,
                    )?
                    .1,
                );
            }
            (expected, ProvenanceEvidenceClass::Observed)
        }
        FinancialCredentialFamilyV1::SettlementReliability => {
            return Err(FinancialCredentialProjectionError::ReliabilityProofSubstrateUnavailable);
        }
    };
    expected_members.sort_by(|left, right| left.query_key.cmp(&right.query_key));
    let mut source_evidence_class = maximum_source_evidence_class;
    for member in &expected_members {
        if evidence_class_rank(member.evidence_class) < evidence_class_rank(source_evidence_class) {
            source_evidence_class = member.evidence_class;
        }
    }
    Ok(ValidatedFinancialSourceDisclosureV1 {
        source_artifact_digests,
        expected_members,
        source_evidence_class,
    })
}

fn validate_bundled_source_artifact(
    artifact: &FinancialSourceBundleArtifactV1,
) -> Result<(), FinancialCredentialProjectionError> {
    if !valid_identifier(&artifact.artifact_schema)
        || !valid_digest(&artifact.artifact_digest)
        || artifact.canonical_artifact.len() > MAX_SOURCE_ARTIFACT_BYTES
        || domain_digest(
            SOURCE_ARTIFACT_DIGEST_DOMAIN,
            artifact.canonical_artifact.as_bytes(),
        ) != artifact.artifact_digest
    {
        return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
    }
    Ok(())
}

fn parse_bundled_source_artifact<T: DeserializeOwned + Serialize>(
    artifact: &FinancialSourceBundleArtifactV1,
) -> Result<T, FinancialCredentialProjectionError> {
    parse_canonical_source_artifact(&artifact.canonical_artifact)
}

fn one_bundled_artifact<'a>(
    artifacts: &'a [FinancialSourceBundleArtifactV1],
    role: FinancialSourceArtifactRoleV1,
    schema: &str,
) -> Result<&'a FinancialSourceBundleArtifactV1, FinancialCredentialProjectionError> {
    let mut matches = artifacts
        .iter()
        .filter(|artifact| artifact.role == role && artifact.artifact_schema == schema);
    let artifact = matches
        .next()
        .ok_or(FinancialCredentialProjectionError::IncompleteSource)?;
    if matches.next().is_some() {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    Ok(artifact)
}

fn parse_member_artifacts(
    artifacts: &[FinancialSourceBundleArtifactV1],
) -> Result<Vec<SignedFinancialSourceMemberV1>, FinancialCredentialProjectionError> {
    artifacts
        .iter()
        .filter(|artifact| artifact.role == FinancialSourceArtifactRoleV1::Member)
        .map(|artifact| {
            if artifact.artifact_schema != FINANCIAL_SOURCE_MEMBER_SCHEMA_V1 {
                return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
            }
            parse_bundled_source_artifact(artifact)
        })
        .collect()
}
