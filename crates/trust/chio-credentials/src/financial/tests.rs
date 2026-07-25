use super::*;

use chio_core::{
    capability::{governance::ProvenanceEvidenceClass, scope::MonetaryAmount},
    MerkleTree,
};
use chio_credit::underwriting::{
    SignedUnderwritingDecision, UnderwritingBudgetAction, UnderwritingBudgetRecommendation,
    UnderwritingDecisionArtifact, UnderwritingDecisionLifecycleState, UnderwritingDecisionOutcome,
    UnderwritingDecisionPolicy, UnderwritingDecisionReport, UnderwritingPolicyInput,
    UnderwritingPolicyInputQuery, UnderwritingPremiumQuote, UnderwritingPremiumState,
    UnderwritingReceiptEvidence, UnderwritingReviewState, UnderwritingRiskClass,
    UnderwritingRiskTaxonomy, UNDERWRITING_DECISION_ARTIFACT_SCHEMA,
    UNDERWRITING_DECISION_REPORT_SCHEMA, UNDERWRITING_POLICY_INPUT_SCHEMA,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signed_envelope(
    issuer: &Keypair,
    subject: FinancialCredentialSubjectV1,
    evidence: FinancialCredentialEvidenceV1,
    source_evidence_class: ProvenanceEvidenceClass,
    issued_at: u64,
    expires_at: u64,
) -> TestResult<FinancialCredentialEnvelope> {
    let family = subject.family();
    let issuer_did = DidChio::from_public_key(issuer.public_key())?;
    let issuance_date = rfc3339_from_unix(issued_at)?;
    let mut envelope = FinancialCredentialEnvelope {
        schema: family.schema().to_string(),
        family,
        credential_id: String::new(),
        context: vec![
            VC_CONTEXT_V1.to_string(),
            CHIO_CREDENTIAL_CONTEXT_V1.to_string(),
        ],
        credential_type: vec![VC_TYPE.to_string(), family.credential_type().to_string()],
        issuer: issuer_did.to_string(),
        issuer_key_epoch: 1,
        issuance_date: issuance_date.clone(),
        expiration_date: rfc3339_from_unix(expires_at)?,
        credential_subject: subject,
        evidence,
        source_evidence_class,
        presentation_evidence_class: ProvenanceEvidenceClass::Asserted,
        proof: CredentialProof {
            proof_type: PROOF_TYPE.to_string(),
            created: issuance_date,
            proof_purpose: PROOF_PURPOSE.to_string(),
            verification_method: issuer_did.verification_method_id(),
            proof_value: String::new(),
        },
    };
    envelope.credential_id = envelope.recompute_credential_id()?;
    let signature = issuer.sign_canonical(&envelope.signing_body())?.0;
    assert!(issuer
        .public_key()
        .verify_canonical(&envelope.signing_body(), &signature)?);
    envelope.proof.proof_value = signature.to_hex();
    Ok(envelope)
}

fn signed_underwriting_decision(
    source: &Keypair,
    subject_key: &str,
    issued_at: u64,
) -> TestResult<SignedUnderwritingDecision> {
    let input = UnderwritingPolicyInput {
        schema: UNDERWRITING_POLICY_INPUT_SCHEMA.to_string(),
        generated_at: issued_at - 1,
        filters: UnderwritingPolicyInputQuery {
            agent_subject: Some(subject_key.to_string()),
            ..UnderwritingPolicyInputQuery::default()
        },
        taxonomy: UnderwritingRiskTaxonomy::default(),
        receipts: UnderwritingReceiptEvidence {
            matching_receipts: 0,
            returned_receipts: 0,
            allow_count: 0,
            deny_count: 0,
            cancelled_count: 0,
            incomplete_count: 0,
            governed_receipts: 0,
            approval_receipts: 0,
            approved_receipts: 0,
            call_chain_receipts: 0,
            runtime_assurance_receipts: 0,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            actionable_settlement_receipts: 0,
            metered_receipts: 0,
            actionable_metered_receipts: 0,
            shared_evidence_reference_count: 0,
            shared_evidence_proof_required_count: 0,
            receipt_refs: Vec::new(),
        },
        reputation: None,
        certification: None,
        runtime_assurance: None,
        compliance_score: None,
        signals: Vec::new(),
    };
    Ok(SignedUnderwritingDecision::sign(
        UnderwritingDecisionArtifact {
            schema: UNDERWRITING_DECISION_ARTIFACT_SCHEMA.to_string(),
            decision_id: "decision-at-window-end".to_string(),
            issued_at,
            evaluation: UnderwritingDecisionReport {
                schema: UNDERWRITING_DECISION_REPORT_SCHEMA.to_string(),
                generated_at: issued_at - 1,
                policy: UnderwritingDecisionPolicy::default(),
                outcome: UnderwritingDecisionOutcome::Approve,
                risk_class: UnderwritingRiskClass::Baseline,
                suggested_ceiling_factor: Some(1.0),
                findings: Vec::new(),
                input,
            },
            lifecycle_state: UnderwritingDecisionLifecycleState::Active,
            review_state: UnderwritingReviewState::Approved,
            supersedes_decision_id: None,
            budget: UnderwritingBudgetRecommendation {
                action: UnderwritingBudgetAction::Preserve,
                ceiling_factor: Some(1.0),
                rationale: "test".to_string(),
            },
            premium: UnderwritingPremiumQuote {
                state: UnderwritingPremiumState::Quoted,
                basis_points: Some(100),
                quoted_amount: Some(MonetaryAmount {
                    units: 7,
                    currency: "USD".to_string(),
                }),
                rationale: "test".to_string(),
            },
        },
        source,
    )?)
}

#[test]
fn signed_reliability_credential_is_explicitly_rejected() -> TestResult {
    let issuer = Keypair::from_seed(&[41; 32]);
    let holder = Keypair::from_seed(&[42; 32]);
    let subject = FinancialCredentialSubjectV1::SettlementReliability(
        SettlementReliabilityCredentialSubjectV1 {
            id: DidChio::from_public_key(holder.public_key())?.to_string(),
            on_time_count: 1,
            obligation_count: 1,
            on_time_ratio_bps: 10_000,
        },
    );
    let credential = signed_envelope(
        &issuer,
        subject,
        FinancialCredentialEvidenceV1 {
            window: FinancialCredentialWindowV1 {
                starts_at: 100,
                ends_at: 200,
            },
            source_disclosure: FinancialSourceDisclosureV1::Bundled {
                artifacts: Vec::new(),
            },
            source_completeness_attestations: Vec::new(),
        },
        ProvenanceEvidenceClass::Observed,
        200,
        300,
    )?;
    let bytes = serde_json::to_vec(&credential)?;

    assert!(matches!(
        decode_financial_credential(&bytes),
        Err(CredentialError::FinancialReliabilityProofSubstrateUnavailable)
    ));
    assert!(matches!(
        inspect_financial_credential_signature(&credential, 200),
        Err(CredentialError::FinancialReliabilityProofSubstrateUnavailable)
    ));
    Ok(())
}

#[test]
fn credential_decode_and_inspection_reject_member_at_exact_window_end() -> TestResult {
    let source = Keypair::from_seed(&[43; 32]);
    let holder = Keypair::from_seed(&[44; 32]);
    let issuer = Keypair::from_seed(&[45; 32]);
    let authority = Keypair::from_seed(&[46; 32]);
    let decision = signed_underwriting_decision(&source, &holder.public_key().to_hex(), 200)?;
    let request = chio_credit::financial_credentials::prepare_premium_history_financial_source(
        std::slice::from_ref(&decision),
        FinancialCredentialWindowV1 {
            starts_at: 100,
            ends_at: 201,
        },
    )?;
    let expected = request
        .expected_members
        .first()
        .ok_or_else(|| std::io::Error::other("expected source member"))?;
    let leaf = FinancialSourceCommittedLeafV1 {
        index: 0,
        query_key: expected.query_key.clone(),
        source_artifact_digest: expected.source_artifact_digest.clone(),
    };
    let tree = MerkleTree::from_leaves(&[canonical_json_bytes(&leaf)?])?;
    let root = tree.root().to_hex();
    let window = FinancialCredentialWindowV1 {
        starts_at: 100,
        ends_at: 200,
    };
    let proof = SignedFinancialSourceCompletenessAttestationV1::sign(
        FinancialSourceCompletenessAttestationBodyV1 {
            schema: FINANCIAL_SOURCE_COMPLETENESS_ATTESTATION_SCHEMA_V1.to_string(),
            source_id: "premium-source".to_string(),
            source_family: FinancialCredentialFamilyV1::PremiumHistory,
            subject: request.subject.clone(),
            source_signer_key: source.public_key().clone(),
            checkpoint_authority_epoch: 1,
            checkpoint_authority_key: authority.public_key().clone(),
            store_generation: 1,
            checkpoint_sequence: 1,
            checkpoint_digest: "11".repeat(32),
            cutoff: window.ends_at,
            window: window.clone(),
            committed_leaves: vec![FinancialSourceCommittedLeafProofV1 {
                leaf,
                index_proof: FinancialSourceMerkleProofV1 {
                    tree_size: 1,
                    leaf_index: 0,
                    audit_path: Vec::new(),
                },
            }],
            range_root: root.clone(),
            index_root: root,
            lower_boundary: FinancialSourceCompletenessBoundaryV1::SourceEdge,
            upper_boundary: FinancialSourceCompletenessBoundaryV1::SourceEdge,
            source_artifact_digests: request.source_artifact_digests.clone(),
            disclosure_digest: request.disclosure_digest.clone(),
            attestation_reference: "premium-window-proof".to_string(),
            issued_at: 200,
            expires_at: 300,
            source_evidence_class: ProvenanceEvidenceClass::Asserted,
        },
        &authority,
    )?;
    let credential = signed_envelope(
        &issuer,
        FinancialCredentialSubjectV1::PremiumHistory(PremiumHistoryCredentialSubjectV1 {
            id: request.subject,
            quoted_count: 1,
            quoted_amounts: vec![MonetaryAmount {
                units: 7,
                currency: "USD".to_string(),
            }],
        }),
        FinancialCredentialEvidenceV1 {
            window,
            source_disclosure: request.disclosure,
            source_completeness_attestations: vec![proof],
        },
        ProvenanceEvidenceClass::Asserted,
        200,
        250,
    )?;

    assert!(matches!(
        inspect_financial_credential_signature(&credential, 200),
        Err(CredentialError::InvalidFinancialCredential(reason))
            if reason.contains("committed leaves contain a gap")
    ));
    let bytes = serde_json::to_vec(&credential)?;
    let decoded = decode_financial_credential(&bytes);
    assert!(matches!(
        &decoded,
        Err(CredentialError::InvalidFinancialCredential(reason))
            if reason.contains("committed leaves contain a gap")
    ), "unexpected decode result: {decoded:?}");
    Ok(())
}
