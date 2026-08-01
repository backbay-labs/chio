use chio_core_types::{canonical_json_bytes, Keypair, MerkleTree};
use chio_fincred::{
    FinancialCredentialFamilyV1, FinancialCredentialWindowV1, FinancialSourceArtifactReferenceV1,
    FinancialSourceArtifactRoleV1, FinancialSourceBundleArtifactV1,
    FinancialSourceCheckpointBodyV1, FinancialSourceCommittedLeafProofV1,
    FinancialSourceCommittedLeafV1, FinancialSourceCompletenessAttestationBodyV1,
    FinancialSourceCompletenessBoundaryV1, FinancialSourceDisclosureV1,
    FinancialSourceMemberBodyV1, FinancialSourceMerkleProofV1, FinancialSourceQueryKeyV1,
    SignedFinancialSourceCheckpointV1, SignedFinancialSourceCompletenessAttestationV1,
    SignedFinancialSourceMemberV1, FINANCIAL_SOURCE_CHECKPOINT_SCHEMA_V1,
    FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1, FINANCIAL_SOURCE_MEMBER_SCHEMA_V1,
};

use super::{
    inspect_financial_source_member, prepare_request, settlement_reliability_ratio_bps,
    validate_exposure_report_members, validate_financial_source_disclosure,
    verify_completeness_boundary, verify_source_completeness_attestation,
    FinancialCredentialProjectionError, FinancialSourceAuthorityPinConfigV1,
    FinancialSourceAuthorityPinV1, FinancialSourceCompletenessAttestationRequestV1,
    FinancialSourceExpectedMemberV1, QualifiedFinancialSourceCheckpointV1,
    EXPOSURE_RECEIPT_MEMBER_SCHEMA_V1, SOURCE_CHECKPOINT_DIGEST_DOMAIN,
};
use crate::capability::governance::ProvenanceEvidenceClass;
use crate::{
    ExposureLedgerQuery, ExposureLedgerReport, ExposureLedgerSummary,
    ExposureLedgerSupportBoundary, SignedCreditLossLifecycle, SignedExposureLedgerReport,
    CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA, CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA,
    EXPOSURE_LEDGER_SCHEMA,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn committed_leaf(
    family: FinancialCredentialFamilyV1,
    occurred_at: u64,
    artifact_id: &str,
    digest_byte: u8,
    index: u64,
) -> FinancialSourceCommittedLeafV1 {
    FinancialSourceCommittedLeafV1 {
        index,
        query_key: FinancialSourceQueryKeyV1 {
            source_family: family,
            subject: "did:chio:subject".to_string(),
            occurred_at,
            artifact_id: artifact_id.to_string(),
        },
        source_artifact_digest: format!("{digest_byte:02x}").repeat(32),
    }
}

fn index_fixture(
    leaves: &[FinancialSourceCommittedLeafV1],
) -> TestResult<(MerkleTree, Vec<FinancialSourceCommittedLeafProofV1>)> {
    let bytes = leaves
        .iter()
        .map(canonical_json_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let tree = MerkleTree::from_leaves(&bytes)?;
    let proofs = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            let proof = tree.inclusion_proof(index)?;
            Ok(FinancialSourceCommittedLeafProofV1 {
                leaf: leaf.clone(),
                index_proof: FinancialSourceMerkleProofV1 {
                    tree_size: u64::try_from(proof.tree_size)?,
                    leaf_index: u64::try_from(proof.leaf_index)?,
                    audit_path: proof.audit_path.iter().map(|hash| hash.to_hex()).collect(),
                },
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok((tree, proofs))
}

fn boundary_request(
    family: FinancialCredentialFamilyV1,
) -> FinancialSourceCompletenessAttestationRequestV1 {
    let signer = Keypair::from_seed(&[7; 32]);
    FinancialSourceCompletenessAttestationRequestV1 {
        source_family: family,
        subject: "did:chio:subject".to_string(),
        source_signer_key: signer.public_key().clone(),
        cutoff: 200,
        window: FinancialCredentialWindowV1 {
            starts_at: 100,
            ends_at: 200,
        },
        source_artifact_digests: Vec::new(),
        disclosure: FinancialSourceDisclosureV1::Bundled {
            artifacts: Vec::new(),
        },
        disclosure_digest: "11".repeat(32),
        maximum_source_evidence_class: ProvenanceEvidenceClass::Verified,
        expected_members: Vec::new(),
    }
}

fn checkpoint_body(
    authority: &Keypair,
    store_generation: u64,
    checkpoint_sequence: u64,
) -> FinancialSourceCheckpointBodyV1 {
    FinancialSourceCheckpointBodyV1 {
        schema: FINANCIAL_SOURCE_CHECKPOINT_SCHEMA_V1.to_string(),
        source_id: "source".to_string(),
        checkpoint_authority_epoch: 1,
        checkpoint_authority_key: authority.public_key().clone(),
        store_generation,
        checkpoint_sequence,
        cutoff: 200,
        window: FinancialCredentialWindowV1 {
            starts_at: 100,
            ends_at: 200,
        },
        index_size: 1,
        range_root: "22".repeat(32),
        index_root: "33".repeat(32),
        lower_boundary: FinancialSourceCompletenessBoundaryV1::SourceEdge,
        upper_boundary: FinancialSourceCompletenessBoundaryV1::SourceEdge,
        issued_at: 200,
        expires_at: 300,
    }
}

fn exact_checkpoint_pin(
    body: &FinancialSourceCheckpointBodyV1,
) -> TestResult<FinancialSourceAuthorityPinV1> {
    let digest = super::domain_digest(
        SOURCE_CHECKPOINT_DIGEST_DOMAIN,
        &canonical_json_bytes(body)?,
    );
    Ok(FinancialSourceAuthorityPinV1::from_operator_config(
        FinancialSourceAuthorityPinConfigV1 {
            source_id: body.source_id.clone(),
            checkpoint_authority_epoch: body.checkpoint_authority_epoch,
            checkpoint_authority_key: body.checkpoint_authority_key.clone(),
            store_generation: body.store_generation,
            checkpoint_sequence: body.checkpoint_sequence,
            checkpoint_digest: digest,
            cutoff: body.cutoff,
            index_root: body.index_root.clone(),
        },
    )?)
}

fn signed_underwriting_decision_fixture(
    subject_key: &str,
    signer: &Keypair,
    issued_at: u64,
) -> TestResult<crate::underwriting::SignedUnderwritingDecision> {
    let generated_at = issued_at - 1;
    let input = crate::underwriting::UnderwritingPolicyInput {
        schema: crate::underwriting::UNDERWRITING_POLICY_INPUT_SCHEMA.to_string(),
        generated_at,
        filters: crate::underwriting::UnderwritingPolicyInputQuery {
            agent_subject: Some(subject_key.to_string()),
            receipt_limit: Some(10),
            ..crate::underwriting::UnderwritingPolicyInputQuery::default()
        },
        taxonomy: crate::underwriting::UnderwritingRiskTaxonomy::default(),
        receipts: crate::underwriting::UnderwritingReceiptEvidence {
            matching_receipts: 2,
            returned_receipts: 2,
            allow_count: 2,
            deny_count: 0,
            cancelled_count: 0,
            incomplete_count: 0,
            governed_receipts: 2,
            approval_receipts: 2,
            approved_receipts: 2,
            call_chain_receipts: 0,
            runtime_assurance_receipts: 2,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            actionable_settlement_receipts: 0,
            metered_receipts: 0,
            actionable_metered_receipts: 0,
            shared_evidence_reference_count: 0,
            shared_evidence_proof_required_count: 0,
            receipt_refs: vec![crate::underwriting::UnderwritingEvidenceReference {
                kind: crate::underwriting::UnderwritingEvidenceKind::Receipt,
                reference_id: "unresolved-receipt".to_string(),
                observed_at: Some(generated_at - 1),
                digest_sha256: None,
                locator: Some("receipt:unresolved".to_string()),
            }],
        },
        reputation: Some(crate::underwriting::UnderwritingReputationEvidence {
            subject_key: subject_key.to_string(),
            effective_score: 0.93,
            probationary: false,
            resolved_tier: Some("trusted".to_string()),
            imported_signal_count: 0,
            accepted_imported_signal_count: 0,
        }),
        certification: Some(crate::underwriting::UnderwritingCertificationEvidence {
            tool_server_id: "server-1".to_string(),
            state: crate::underwriting::UnderwritingCertificationState::Active,
            artifact_id: Some("cert-1".to_string()),
            verdict: Some("pass".to_string()),
            checked_at: Some(generated_at),
            published_at: Some(generated_at),
        }),
        runtime_assurance: Some(crate::underwriting::UnderwritingRuntimeAssuranceEvidence {
            governed_receipts: 2,
            runtime_assurance_receipts: 2,
            highest_tier: Some(
                crate::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
            ),
            latest_schema: Some("chio.runtime-attestation.enterprise.v1".to_string()),
            latest_verifier_family: Some(
                crate::appraisal::AttestationVerifierFamily::EnterpriseVerifier,
            ),
            latest_verifier: Some("verifier.chio".to_string()),
            latest_evidence_sha256: Some("unresolved-runtime-evidence".to_string()),
            observed_verifier_families: vec![
                crate::appraisal::AttestationVerifierFamily::EnterpriseVerifier,
            ],
        }),
        compliance_score: None,
        signals: Vec::new(),
    };
    let evaluation = crate::underwriting::evaluate_underwriting_policy_input(
        input,
        &crate::underwriting::UnderwritingDecisionPolicy::default(),
    )?;
    let artifact = crate::underwriting::build_underwriting_decision_artifact(
        evaluation,
        issued_at,
        None,
        Some(crate::capability::scope::MonetaryAmount {
            units: 10_000,
            currency: "USD".to_string(),
        }),
    )?;
    Ok(crate::underwriting::SignedUnderwritingDecision::sign(
        artifact, signer,
    )?)
}

fn signed_loss_event_fixture(
    subject_key: &str,
    signer: &Keypair,
    issued_at: u64,
) -> TestResult<SignedCreditLossLifecycle> {
    let amount = crate::capability::scope::MonetaryAmount {
        units: 1_000,
        currency: "USD".to_string(),
    };
    Ok(SignedCreditLossLifecycle::sign(
        crate::CreditLossLifecycleArtifact {
            schema: CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
            event_id: "loss-1".to_string(),
            issued_at,
            bond_id: "bond-1".to_string(),
            event_kind: crate::CreditLossLifecycleEventKind::Delinquency,
            projected_bond_lifecycle_state: crate::CreditBondLifecycleState::Active,
            reserve_control_source_id: None,
            authority_chain: Vec::new(),
            execution_window: None,
            rail: None,
            observed_execution: None,
            reconciled_state: None,
            execution_state: None,
            appeal_state: None,
            appeal_window_ends_at: None,
            description: Some("signed event without reconciliation evidence".to_string()),
            report: crate::CreditLossLifecycleReport {
                schema: CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
                generated_at: issued_at - 1,
                query: crate::CreditLossLifecycleQuery {
                    bond_id: "bond-1".to_string(),
                    event_kind: crate::CreditLossLifecycleEventKind::Delinquency,
                    amount: Some(amount.clone()),
                },
                summary: crate::CreditLossLifecycleSummary {
                    bond_id: "bond-1".to_string(),
                    facility_id: Some("facility-1".to_string()),
                    capability_id: Some("capability-1".to_string()),
                    agent_subject: Some(subject_key.to_string()),
                    tool_server: Some("server-1".to_string()),
                    tool_name: Some("tool-1".to_string()),
                    current_bond_lifecycle_state: crate::CreditBondLifecycleState::Active,
                    projected_bond_lifecycle_state: crate::CreditBondLifecycleState::Active,
                    current_delinquent_amount: Some(amount.clone()),
                    current_recovered_amount: None,
                    current_written_off_amount: None,
                    current_released_reserve_amount: None,
                    current_slashed_reserve_amount: None,
                    outstanding_delinquent_amount: Some(amount.clone()),
                    releaseable_reserve_amount: Some(amount.clone()),
                    reserve_control_source_id: None,
                    execution_state: None,
                    appeal_state: None,
                    appeal_window_ends_at: None,
                    event_amount: Some(amount),
                },
                support_boundary: crate::CreditLossLifecycleSupportBoundary::default(),
                findings: Vec::new(),
            },
        },
        signer,
    )?)
}

#[test]
fn settlement_reliability_ratio_uses_exact_u128_floor_division() -> TestResult {
    assert_eq!(settlement_reliability_ratio_bps(2, 3)?, 6_666);
    assert_eq!(
        settlement_reliability_ratio_bps(
            chio_fincred::MAX_I_JSON_SAFE_INTEGER,
            chio_fincred::MAX_I_JSON_SAFE_INTEGER,
        )?,
        10_000
    );
    Ok(())
}

#[test]
fn settlement_reliability_ratio_rejects_zero_inconsistent_or_unsafe_counts() {
    assert!(matches!(
        settlement_reliability_ratio_bps(0, 0),
        Err(FinancialCredentialProjectionError::EmptyWindow)
    ));
    assert!(matches!(
        settlement_reliability_ratio_bps(4, 3),
        Err(FinancialCredentialProjectionError::InvalidReliabilityCounts)
    ));
    assert!(matches!(
        settlement_reliability_ratio_bps(1, chio_fincred::MAX_I_JSON_SAFE_INTEGER + 1),
        Err(FinancialCredentialProjectionError::IJsonIntegerOutOfRange)
    ));
}

#[test]
fn unresolved_signed_sources_cannot_overclaim_assurance() -> TestResult {
    let signer = Keypair::from_seed(&[12; 32]);
    let subject = Keypair::from_seed(&[13; 32]).public_key().to_hex();
    let issued_at = 200;
    let window = FinancialCredentialWindowV1 {
        starts_at: 100,
        ends_at: 201,
    };

    let decision = signed_underwriting_decision_fixture(&subject, &signer, issued_at)?;
    let premium = super::prepare_premium_history_financial_source(
        std::slice::from_ref(&decision),
        window.clone(),
    )?;
    assert_eq!(
        premium.maximum_source_evidence_class,
        ProvenanceEvidenceClass::Asserted
    );
    assert!(premium
        .expected_members
        .iter()
        .all(|member| member.evidence_class == ProvenanceEvidenceClass::Asserted));
    assert_eq!(
        validate_financial_source_disclosure(
            premium.source_family,
            &premium.subject,
            &premium.source_signer_key,
            &premium.disclosure,
        )?
        .source_evidence_class(),
        ProvenanceEvidenceClass::Asserted
    );

    let event = signed_loss_event_fixture(&subject, &signer, issued_at)?;
    let loss = super::prepare_loss_history_financial_source(std::slice::from_ref(&event), window)?;
    assert_eq!(
        loss.maximum_source_evidence_class,
        ProvenanceEvidenceClass::Observed
    );
    assert!(loss
        .expected_members
        .iter()
        .all(|member| member.evidence_class == ProvenanceEvidenceClass::Asserted));
    assert_eq!(
        validate_financial_source_disclosure(
            loss.source_family,
            &loss.subject,
            &loss.source_signer_key,
            &loss.disclosure,
        )?
        .source_evidence_class(),
        ProvenanceEvidenceClass::Asserted
    );
    Ok(())
}

#[test]
fn exposure_completeness_rejects_summary_counts_that_do_not_match_rows() -> TestResult {
    let signer = Keypair::from_seed(&[6; 32]);
    let report = SignedExposureLedgerReport::sign(
        ExposureLedgerReport {
            schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
            generated_at: 200,
            filters: ExposureLedgerQuery::default(),
            support_boundary: ExposureLedgerSupportBoundary::default(),
            summary: ExposureLedgerSummary {
                matching_receipts: 1,
                returned_receipts: 1,
                matching_decisions: 0,
                returned_decisions: 0,
                active_decisions: 0,
                superseded_decisions: 0,
                actionable_receipts: 0,
                pending_settlement_receipts: 0,
                failed_settlement_receipts: 0,
                currencies: Vec::new(),
                mixed_currency_book: false,
                truncated_receipts: false,
                truncated_decisions: false,
            },
            positions: Vec::new(),
            receipts: Vec::new(),
            decisions: Vec::new(),
        },
        &signer,
    )?;

    assert_eq!(
        validate_exposure_report_members(
            &report,
            FinancialCredentialFamilyV1::ExposureHistory,
            &[],
        ),
        Err(FinancialCredentialProjectionError::IncompleteSource)
    );
    Ok(())
}

#[test]
fn checkpoint_qualification_rejects_older_sequence_and_rollback_generation() -> TestResult {
    let authority = Keypair::from_seed(&[5; 32]);
    let current_body = checkpoint_body(&authority, 2, 8);
    let current = SignedFinancialSourceCheckpointV1::sign(current_body.clone(), &authority)?;
    let pin = exact_checkpoint_pin(&current_body)?;
    assert!(super::qualify_financial_source_checkpoint(&current, &pin, 250).is_ok());

    let older =
        SignedFinancialSourceCheckpointV1::sign(checkpoint_body(&authority, 2, 7), &authority)?;
    assert!(matches!(
        super::qualify_financial_source_checkpoint(&older, &pin, 250),
        Err(FinancialCredentialProjectionError::InvalidSourceAuthority)
    ));

    let rollback =
        SignedFinancialSourceCheckpointV1::sign(checkpoint_body(&authority, 1, 8), &authority)?;
    assert!(matches!(
        super::qualify_financial_source_checkpoint(&rollback, &pin, 250),
        Err(FinancialCredentialProjectionError::InvalidSourceAuthority)
    ));

    let mut substituted_body = current_body;
    substituted_body.schema = "chio.fincred.source-checkpoint.v9".to_string();
    let substituted =
        SignedFinancialSourceCheckpointV1::sign(substituted_body.clone(), &authority)?;
    let substituted_pin = exact_checkpoint_pin(&substituted_body)?;
    assert!(matches!(
        super::qualify_financial_source_checkpoint(&substituted, &substituted_pin, 250),
        Err(FinancialCredentialProjectionError::InvalidSourceAuthority)
    ));
    Ok(())
}

#[test]
fn source_member_and_resolver_boundaries_fail_closed() -> TestResult {
    let signer = Keypair::from_seed(&[9; 32]);
    let member = SignedFinancialSourceMemberV1::sign(
        FinancialSourceMemberBodyV1 {
            schema: "chio.fincred.source-member.v9".to_string(),
            query_key: FinancialSourceQueryKeyV1 {
                source_family: FinancialCredentialFamilyV1::ExposureHistory,
                subject: "did:chio:subject".to_string(),
                occurred_at: 150,
                artifact_id: "receipt-1".to_string(),
            },
            artifact_schema: EXPOSURE_RECEIPT_MEMBER_SCHEMA_V1.to_string(),
            canonical_artifact: "{}".to_string(),
        },
        &signer,
    )?;
    assert_eq!(
        inspect_financial_source_member(
            &member,
            FinancialCredentialFamilyV1::ExposureHistory,
            &signer.public_key(),
        ),
        Err(FinancialCredentialProjectionError::InvalidSourceSchema)
    );

    let resolver = FinancialSourceDisclosureV1::Resolver {
        resolver_id: "resolver-1".to_string(),
        references: vec![FinancialSourceArtifactReferenceV1 {
            role: FinancialSourceArtifactRoleV1::Member,
            artifact_schema: FINANCIAL_SOURCE_MEMBER_SCHEMA_V1.to_string(),
            artifact_id: "member-1".to_string(),
            artifact_digest: "11".repeat(32),
        }],
    };
    assert_eq!(
        validate_financial_source_disclosure(
            FinancialCredentialFamilyV1::PremiumHistory,
            "did:chio:subject",
            &signer.public_key(),
            &resolver,
        ),
        Err(FinancialCredentialProjectionError::ResolverProofSubstrateUnavailable)
    );
    Ok(())
}

#[test]
fn premium_history_rejects_an_omitted_oldest_member_inside_the_declared_window() -> TestResult {
    let family = FinancialCredentialFamilyV1::PremiumHistory;
    let leaves = [
        committed_leaf(family, 100, "omitted-oldest", 1, 0),
        committed_leaf(family, 150, "included", 2, 1),
        committed_leaf(family, 250, "outside", 3, 2),
    ];
    let (tree, proofs) = index_fixture(&leaves)?;
    let boundary = FinancialSourceCompletenessBoundaryV1::Adjacent {
        leaf_proof: proofs[0].clone(),
    };

    assert_eq!(
        verify_completeness_boundary(
            &boundary,
            1,
            &leaves[1].query_key,
            true,
            &tree.root(),
            3,
            &boundary_request(family),
        ),
        Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)
    );
    Ok(())
}

#[test]
fn loss_history_rejects_an_omitted_newest_member_inside_the_declared_window() -> TestResult {
    let family = FinancialCredentialFamilyV1::LossHistory;
    let leaves = [
        committed_leaf(family, 50, "outside", 1, 0),
        committed_leaf(family, 150, "included", 2, 1),
        committed_leaf(family, 199, "omitted-newest", 3, 2),
    ];
    let (tree, proofs) = index_fixture(&leaves)?;
    let boundary = FinancialSourceCompletenessBoundaryV1::Adjacent {
        leaf_proof: proofs[2].clone(),
    };

    assert_eq!(
        verify_completeness_boundary(
            &boundary,
            1,
            &leaves[1].query_key,
            false,
            &tree.root(),
            3,
            &boundary_request(family),
        ),
        Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)
    );
    Ok(())
}

#[test]
fn exact_window_end_is_rejected_as_a_member_and_accepted_as_upper_adjacent() -> TestResult {
    let family = FinancialCredentialFamilyV1::PremiumHistory;
    let signer = Keypair::from_seed(&[10; 32]);
    let digest = "44".repeat(32);
    let artifact = FinancialSourceBundleArtifactV1 {
        role: FinancialSourceArtifactRoleV1::Member,
        artifact_schema: "artifact".to_string(),
        artifact_digest: digest.clone(),
        canonical_artifact: "{}".to_string(),
    };
    let expected = FinancialSourceExpectedMemberV1 {
        query_key: FinancialSourceQueryKeyV1 {
            source_family: family,
            subject: "did:chio:subject".to_string(),
            occurred_at: 200,
            artifact_id: "at-end".to_string(),
        },
        source_artifact_digest: digest,
        evidence_class: ProvenanceEvidenceClass::Asserted,
    };
    assert!(matches!(
        prepare_request(
            family,
            "did:chio:subject".to_string(),
            signer.public_key().clone(),
            FinancialCredentialWindowV1 {
                starts_at: 100,
                ends_at: 200,
            },
            vec![artifact.clone()],
            ProvenanceEvidenceClass::Asserted,
            vec![expected.clone()],
        ),
        Err(FinancialCredentialProjectionError::IncompleteSource)
    ));
    assert!(matches!(
        prepare_request(
            family,
            "did:chio:subject".to_string(),
            signer.public_key().clone(),
            FinancialCredentialWindowV1 {
                starts_at: 100,
                ends_at: 100,
            },
            vec![artifact],
            ProvenanceEvidenceClass::Asserted,
            vec![FinancialSourceExpectedMemberV1 {
                query_key: FinancialSourceQueryKeyV1 {
                    source_family: family,
                    subject: "did:chio:subject".to_string(),
                    occurred_at: 100,
                    artifact_id: "zero-width".to_string(),
                },
                source_artifact_digest: "44".repeat(32),
                evidence_class: ProvenanceEvidenceClass::Asserted,
            }],
        ),
        Err(FinancialCredentialProjectionError::IncompleteSource)
    ));

    let leaves = [
        committed_leaf(family, 150, "included", 1, 0),
        committed_leaf(family, 200, "upper-adjacent", 2, 1),
    ];
    let (tree, proofs) = index_fixture(&leaves)?;
    assert_eq!(
        verify_completeness_boundary(
            &FinancialSourceCompletenessBoundaryV1::Adjacent {
                leaf_proof: proofs[1].clone(),
            },
            0,
            &leaves[0].query_key,
            false,
            &tree.root(),
            2,
            &boundary_request(family),
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn completeness_attestation_rejects_body_schema_substitution() -> TestResult {
    let authority = Keypair::from_seed(&[11; 32]);
    let request = boundary_request(FinancialCredentialFamilyV1::PremiumHistory);
    let checkpoint_body = checkpoint_body(&authority, 1, 1);
    let checkpoint = QualifiedFinancialSourceCheckpointV1 {
        body: checkpoint_body.clone(),
        checkpoint_digest: "55".repeat(32),
    };
    let proof = SignedFinancialSourceCompletenessAttestationV1::sign(
        FinancialSourceCompletenessAttestationBodyV1 {
            schema: "chio.fincred.source-completeness-attestation.v9".to_string(),
            source_id: checkpoint_body.source_id,
            source_family: request.source_family,
            subject: request.subject.clone(),
            source_signer_key: request.source_signer_key.clone(),
            checkpoint_authority_epoch: checkpoint_body.checkpoint_authority_epoch,
            checkpoint_authority_key: checkpoint_body.checkpoint_authority_key,
            store_generation: checkpoint_body.store_generation,
            checkpoint_sequence: checkpoint_body.checkpoint_sequence,
            checkpoint_digest: checkpoint.checkpoint_digest.clone(),
            cutoff: request.cutoff,
            window: request.window.clone(),
            committed_leaves: Vec::new(),
            range_root: checkpoint_body.range_root,
            index_root: checkpoint_body.index_root,
            lower_boundary: checkpoint_body.lower_boundary,
            upper_boundary: checkpoint_body.upper_boundary,
            source_artifact_digests: Vec::new(),
            disclosure_digest: request.disclosure_digest.clone(),
            attestation_reference: "attestation".to_string(),
            issued_at: 200,
            expires_at: 300,
            source_evidence_class: ProvenanceEvidenceClass::Asserted,
        },
        &authority,
    )?;
    assert_eq!(
        verify_source_completeness_attestation(&request, &proof, &checkpoint, 200),
        Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)
    );
    Ok(())
}

#[test]
fn completeness_proof_rejects_window_shrink_substitution() -> TestResult {
    let authority = Keypair::from_seed(&[8; 32]);
    let request = boundary_request(FinancialCredentialFamilyV1::PremiumHistory);
    let substituted_window = FinancialCredentialWindowV1 {
        starts_at: 125,
        ends_at: 175,
    };
    let checkpoint_body = FinancialSourceCheckpointBodyV1 {
        schema: FINANCIAL_SOURCE_CHECKPOINT_SCHEMA_V1.to_string(),
        source_id: "source".to_string(),
        checkpoint_authority_epoch: 1,
        checkpoint_authority_key: authority.public_key().clone(),
        store_generation: 1,
        checkpoint_sequence: 1,
        cutoff: request.cutoff,
        window: substituted_window.clone(),
        index_size: 1,
        range_root: "22".repeat(32),
        index_root: "33".repeat(32),
        lower_boundary: FinancialSourceCompletenessBoundaryV1::SourceEdge,
        upper_boundary: FinancialSourceCompletenessBoundaryV1::SourceEdge,
        issued_at: 200,
        expires_at: 300,
    };
    let checkpoint = QualifiedFinancialSourceCheckpointV1 {
        body: checkpoint_body.clone(),
        checkpoint_digest: "44".repeat(32),
    };
    let proof = SignedFinancialSourceCompletenessAttestationV1::sign(
        FinancialSourceCompletenessAttestationBodyV1 {
            schema: FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1.to_string(),
            source_id: checkpoint_body.source_id,
            source_family: request.source_family,
            subject: request.subject.clone(),
            source_signer_key: request.source_signer_key.clone(),
            checkpoint_authority_epoch: checkpoint_body.checkpoint_authority_epoch,
            checkpoint_authority_key: checkpoint_body.checkpoint_authority_key,
            store_generation: checkpoint_body.store_generation,
            checkpoint_sequence: checkpoint_body.checkpoint_sequence,
            checkpoint_digest: checkpoint.checkpoint_digest.clone(),
            cutoff: request.cutoff,
            window: substituted_window,
            committed_leaves: Vec::new(),
            range_root: checkpoint_body.range_root,
            index_root: checkpoint_body.index_root,
            lower_boundary: checkpoint_body.lower_boundary,
            upper_boundary: checkpoint_body.upper_boundary,
            source_artifact_digests: Vec::new(),
            disclosure_digest: request.disclosure_digest.clone(),
            attestation_reference: "attestation".to_string(),
            issued_at: 200,
            expires_at: 300,
            source_evidence_class: ProvenanceEvidenceClass::Verified,
        },
        &authority,
    )?;

    assert_eq!(
        verify_source_completeness_attestation(&request, &proof, &checkpoint, 200),
        Err(FinancialCredentialProjectionError::InvalidSourceAttestationBinding)
    );
    Ok(())
}
