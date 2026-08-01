mod factor_claim_support;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_credit::factor::{
    verify_assignment_acknowledgement, verify_assignment_agreement,
    verify_assignment_bind_authorization, verify_assignment_not_applied,
    AssignmentAcknowledgementBodyV1, AssignmentAcknowledgementInputV1,
    AssignmentAcknowledgementVerificationV1, AssignmentAgreementBodyV1, AssignmentAgreementTrustV1,
    AssignmentAgreementVerificationV1, AssignmentBindAuthorizationBodyV1,
    AssignmentBindAuthorizationInputV1, AssignmentBindAuthorizationTrustV1,
    AssignmentBindAuthorizationVerificationV1, AssignmentNotAppliedBodyV1,
    AssignmentNotAppliedInputV1, AssignmentNotAppliedReasonV1, AssignmentNotAppliedVerificationV1,
    AssignmentOfferV1, AssignmentResultAuthorityTrustV1, FactorError,
    NormalizedAssignmentRequestInputV1, NormalizedAssignmentRequestV1,
    SignedAssignmentAcknowledgementV1, SignedAssignmentAgreementV1,
    SignedAssignmentBindAuthorizationV1, SignedAssignmentNotAppliedV1,
    VerifiedAssignmentAuthorizationSetV1, VerifiedReceivableClaimV1,
};
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, verify_obligation_status_proof,
    ObligationAssignmentCasInputV1, ObligationAssignmentCasV1,
    ObligationAssignmentOperationSnapshotV1, ObligationAtomInputV1, ObligationAtomV1,
    ObligationCreditElectionV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
    ObligationSettlementLifecycleV1, ObligationSettlementTransitionV1, ObligationStatusProofBodyV1,
    ObligationStatusProofContextV1, ObligationStatusProofTrustV1,
    ObligationStatusProofVerificationContextV1, SignedObligationStatusProofV1,
    VerifiedObligationStatusProofV1, OBLIGATION_ASSIGNMENT_CAS_SCHEMA,
};
use factor_claim_support::{build_claim_evidence, ClaimEvidence};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SELLER_ID: &str = "did:chio:seller";
const BUYER_ID: &str = "did:chio:factor";
const BUYER_DESTINATION: &str = "acct:factor";
const AGREEMENT_ID: &str = "assignment-agreement-1";
const RESULT_AUTHORITY_ID: &str = "obligor-disposition-authority";
const RESULT_AUTHORITY_EPOCH: u64 = 3;
const ASSIGNMENT_AUTHORITY_ID: &str = "assignment-authority";
const ASSIGNMENT_AUTHORITY_EPOCH: u64 = 5;
const SELLER_KEY_EPOCH: u64 = 11;
const BUYER_KEY_EPOCH: u64 = 12;
const SNAPSHOT_VERSION: u64 = 7;
const RESOURCE_FENCE: u64 = 11;
const EFFECTIVE_AT: u64 = 1_050;
const OFFER_EXPIRES_AT: u64 = 1_400;
const REQUEST_EXPIRES_AT: u64 = 1_450;
const STATUS_EXPIRES_AT: u64 = 1_600;
const AUTHORIZATION_EXPIRES_AT: u64 = 1_500;
const DUE_AT: u64 = 10_000;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn require_factor_error<T>(result: Result<T, FactorError>) -> FactorError {
    match result {
        Ok(_) => panic!("verification unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn validate_schema(name: &str, artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<factor-result>"),
        &serde_json::to_value(artifact)?,
    )?;
    Ok(())
}

fn signature_digest(canonical_envelope: &[u8]) -> TestResult<String> {
    let value: serde_json::Value = serde_json::from_slice(canonical_envelope)?;
    let signature = match value.get("signature").and_then(serde_json::Value::as_str) {
        Some(signature) => signature,
        None => panic!("signed envelope omitted its signature"),
    };
    Ok(sha256_hex(signature.as_bytes()))
}

fn tamper_signature(canonical_envelope: &[u8]) -> TestResult<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(canonical_envelope)?;
    let signature = match value.get("signature").and_then(serde_json::Value::as_str) {
        Some(signature) => signature,
        None => panic!("signed envelope omitted its signature"),
    };
    let mut tampered = signature.as_bytes().to_vec();
    let last = match tampered.last_mut() {
        Some(last) => last,
        None => panic!("signed envelope contained an empty signature"),
    };
    *last = if *last == b'0' { b'1' } else { b'0' };
    value["signature"] = serde_json::Value::String(String::from_utf8(tampered)?);
    Ok(canonical_json_bytes(&value)?)
}

fn replace_schema(canonical_envelope: &[u8], schema: &str) -> TestResult<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(canonical_envelope)?;
    value["body"]["schema"] = serde_json::Value::String(schema.to_owned());
    Ok(canonical_json_bytes(&value)?)
}

struct Fixture {
    atom: ObligationAtomV1,
    prior_disposition: ObligationDispositionRecordV1,
    resulting_disposition: ObligationDispositionRecordV1,
    settlement_lifecycle: ObligationSettlementLifecycleV1,
    request: NormalizedAssignmentRequestV1,
    verified_claim: VerifiedReceivableClaimV1,
    offer: AssignmentOfferV1,
    authorization: VerifiedAssignmentAuthorizationSetV1,
    status_proof: VerifiedObligationStatusProofV1,
    result_signer: Keypair,
    result_trust: AssignmentResultAuthorityTrustV1,
    operation_id: String,
    no_mutation_proof_digest: String,
}

fn fixture() -> TestResult<Fixture> {
    let ClaimEvidence {
        atom,
        disposition: prior_disposition,
        settlement_lifecycle,
        status_proof,
        verified_claim,
        result_signer,
        ..
    } = build_claim_evidence()?;
    let claim = verified_claim.claim();
    let offer = AssignmentOfferV1::new(claim, 1_000, 1_020, OFFER_EXPIRES_AT)?;
    let request = NormalizedAssignmentRequestV1::new(NormalizedAssignmentRequestInputV1 {
        obligation_id: atom.obligation_id().to_owned(),
        obligation_atom_digest: atom.digest()?,
        claim_digest: claim.digest()?,
        offer_digest: offer.digest()?,
        seller_id: SELLER_ID.to_owned(),
        buyer_id: BUYER_ID.to_owned(),
        buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
        agreed_price: offer.minimum_price().clone(),
        agreed_discount_bps: offer.asking_discount_bps(),
        expected_disposition_version: prior_disposition.version(),
        expected_disposition_lifecycle_fence: prior_disposition.lifecycle_fence(),
        expected_settlement_lifecycle_version: settlement_lifecycle.version(),
        expected_settlement_lifecycle_fence: settlement_lifecycle.lifecycle_fence(),
        action_nonce: "factor-result-assignment-nonce".to_owned(),
        effective_at_unix_ms: EFFECTIVE_AT,
        due_at_unix_ms: atom.due_at_unix_ms(),
        expires_at_unix_ms: REQUEST_EXPIRES_AT,
    })?;
    let request_digest = request.digest()?;
    let operation_id = digest("factor-result-operation");
    let assignment_authority = Keypair::from_seed(&[102; 32]);
    let signed_bind = SignedAssignmentBindAuthorizationV1::sign(
        AssignmentBindAuthorizationBodyV1::new(AssignmentBindAuthorizationInputV1 {
            operation_id: operation_id.clone(),
            normalized_request_digest: request_digest.clone(),
            obligation_atom_digest: atom.digest()?,
            seller_id: SELLER_ID.to_owned(),
            buyer_id: BUYER_ID.to_owned(),
            agreement_id: AGREEMENT_ID.to_owned(),
            buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
            effective_at_unix_ms: EFFECTIVE_AT,
            action_nonce: request.action_nonce().to_owned(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: AUTHORIZATION_EXPIRES_AT,
            authority_id: ASSIGNMENT_AUTHORITY_ID.to_owned(),
            authority_key_epoch: ASSIGNMENT_AUTHORITY_EPOCH,
        })?,
        &assignment_authority,
    )?;
    let bind_bytes = signed_bind.canonical_bytes()?;
    let bind_trust = AssignmentBindAuthorizationTrustV1::new(
        ASSIGNMENT_AUTHORITY_ID.to_owned(),
        assignment_authority.public_key(),
        ASSIGNMENT_AUTHORITY_EPOCH,
        500,
    )?;
    let verified_bind = verify_assignment_bind_authorization(
        &bind_bytes,
        &AssignmentBindAuthorizationVerificationV1 {
            operation_id: &operation_id,
            normalized_request_digest: &request_digest,
            obligation_atom_digest: &atom.digest()?,
            seller_id: SELLER_ID,
            buyer_id: BUYER_ID,
            agreement_id: AGREEMENT_ID,
            buyer_settlement_destination_ref: BUYER_DESTINATION,
            effective_at_unix_ms: EFFECTIVE_AT,
            action_nonce: request.action_nonce(),
            trust: &bind_trust,
            trusted_now_unix_ms: EFFECTIVE_AT,
        },
    )?;
    let seller = Keypair::from_seed(&[103; 32]);
    let buyer = Keypair::from_seed(&[104; 32]);
    let signed_agreement = SignedAssignmentAgreementV1::sign(
        AssignmentAgreementBodyV1::new(
            AGREEMENT_ID.to_owned(),
            operation_id.clone(),
            &request,
            claim,
            &offer,
            &verified_bind,
        )?,
        SELLER_KEY_EPOCH,
        &seller,
        BUYER_KEY_EPOCH,
        &buyer,
    )?;
    let agreement_bytes = signed_agreement.canonical_bytes()?;
    let agreement_trust = AssignmentAgreementTrustV1::new(
        SELLER_ID.to_owned(),
        seller.public_key(),
        SELLER_KEY_EPOCH,
        BUYER_ID.to_owned(),
        buyer.public_key(),
        BUYER_KEY_EPOCH,
    )?;
    let verified_agreement = verify_assignment_agreement(
        &agreement_bytes,
        &AssignmentAgreementVerificationV1 {
            operation_id: &operation_id,
            normalized_request_digest: &request_digest,
            assignment_authority_digest: verified_bind.envelope_digest(),
            trust: &agreement_trust,
        },
    )?;
    let authorization =
        VerifiedAssignmentAuthorizationSetV1::new(verified_bind, verified_agreement)?;
    let operation = ObligationAssignmentOperationSnapshotV1::new(
        operation_id.clone(),
        request_digest.clone(),
        &prior_disposition,
        &settlement_lifecycle,
        SNAPSHOT_VERSION,
        RESOURCE_FENCE,
    )?
    .attach_supplemental_authorization(&authorization)?;
    let assignment = ObligationAssignmentCasV1::new(
        operation,
        ObligationAssignmentCasInputV1 {
            schema: OBLIGATION_ASSIGNMENT_CAS_SCHEMA.to_owned(),
            operation_id: operation_id.clone(),
            normalized_request_digest: request_digest,
            agreement_id: AGREEMENT_ID.to_owned(),
            buyer_id: BUYER_ID.to_owned(),
            buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
            supplemental_authorization_digest: authorization.digest().to_owned(),
            status_proof_digest: status_proof.envelope_digest().to_owned(),
            effective_at_unix_ms: EFFECTIVE_AT,
        },
        authorization.clone(),
        &request,
    )?;
    let resulting_disposition = prior_disposition.compare_and_swap_assignment(
        &atom,
        &settlement_lifecycle,
        &status_proof,
        &assignment,
        EFFECTIVE_AT,
    )?;
    let result_trust = AssignmentResultAuthorityTrustV1::new(
        RESULT_AUTHORITY_ID.to_owned(),
        result_signer.public_key(),
        RESULT_AUTHORITY_EPOCH,
    )?;
    Ok(Fixture {
        atom,
        prior_disposition,
        resulting_disposition,
        settlement_lifecycle,
        request,
        verified_claim,
        offer,
        authorization,
        status_proof,
        result_signer,
        result_trust,
        operation_id,
        no_mutation_proof_digest: digest("factor-result-no-mutation-proof"),
    })
}

fn acknowledgement_input(fixture: &Fixture) -> TestResult<AssignmentAcknowledgementInputV1> {
    Ok(AssignmentAcknowledgementInputV1 {
        operation_id: fixture.operation_id.clone(),
        normalized_request_digest: fixture.request.digest()?,
        agreement_id: AGREEMENT_ID.to_owned(),
        agreement_body_digest: fixture.authorization.agreement().body_digest().to_owned(),
        obligation_id: fixture.atom.obligation_id().to_owned(),
        obligation_atom_digest: fixture.atom.digest()?,
        buyer_id: BUYER_ID.to_owned(),
        buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
        assignment_authorization_set_digest: fixture.authorization.digest().to_owned(),
        status_proof_digest: fixture.status_proof.envelope_digest().to_owned(),
        prior_disposition_version: fixture.prior_disposition.version(),
        prior_disposition_lifecycle_fence: fixture.prior_disposition.lifecycle_fence(),
        prior_disposition_digest: fixture.prior_disposition.digest(&fixture.atom)?,
        resulting_disposition_version: fixture.resulting_disposition.version(),
        resulting_disposition_lifecycle_fence: fixture.resulting_disposition.lifecycle_fence(),
        resulting_disposition_digest: fixture.resulting_disposition.digest(&fixture.atom)?,
        expected_snapshot_version: SNAPSHOT_VERSION,
        resulting_snapshot_version: SNAPSHOT_VERSION + 1,
        expected_resource_fence: RESOURCE_FENCE,
        resulting_resource_fence: RESOURCE_FENCE + 1,
        authority_id: RESULT_AUTHORITY_ID.to_owned(),
        authority_key_epoch: RESULT_AUTHORITY_EPOCH,
        effective_at_unix_ms: EFFECTIVE_AT,
        due_at_unix_ms: DUE_AT,
        acknowledged_at_unix_ms: 1_100,
    })
}

fn signed_acknowledgement(
    fixture: &Fixture,
    input: AssignmentAcknowledgementInputV1,
) -> Result<Vec<u8>, FactorError> {
    SignedAssignmentAcknowledgementV1::sign(
        AssignmentAcknowledgementBodyV1::new(input)?,
        &fixture.result_signer,
    )?
    .canonical_bytes()
}

fn verify_acknowledgement(
    fixture: &Fixture,
    canonical: &[u8],
) -> Result<chio_credit::factor::VerifiedAssignmentAcknowledgementV1, FactorError> {
    verify_assignment_acknowledgement(
        canonical,
        &AssignmentAcknowledgementVerificationV1 {
            atom: &fixture.atom,
            request: &fixture.request,
            claim: &fixture.verified_claim,
            offer: &fixture.offer,
            authorization: &fixture.authorization,
            status_proof: &fixture.status_proof,
            resulting_disposition: &fixture.resulting_disposition,
            trust: &fixture.result_trust,
        },
    )
}

fn not_applied_input(
    fixture: &Fixture,
    observed_disposition: &ObligationDispositionRecordV1,
    observed_settlement: &ObligationSettlementLifecycleV1,
    observed_snapshot_version: u64,
    observed_resource_fence: u64,
    reason: AssignmentNotAppliedReasonV1,
    decided_at_unix_ms: u64,
) -> TestResult<AssignmentNotAppliedInputV1> {
    Ok(AssignmentNotAppliedInputV1 {
        operation_id: fixture.operation_id.clone(),
        normalized_request_digest: fixture.request.digest()?,
        agreement_id: AGREEMENT_ID.to_owned(),
        agreement_body_digest: fixture.authorization.agreement().body_digest().to_owned(),
        obligation_id: fixture.atom.obligation_id().to_owned(),
        obligation_atom_digest: fixture.atom.digest()?,
        assignment_authorization_set_digest: fixture.authorization.digest().to_owned(),
        status_proof_digest: fixture.status_proof.envelope_digest().to_owned(),
        expected_disposition_version: fixture.request.expected_disposition_version(),
        expected_disposition_lifecycle_fence: fixture
            .request
            .expected_disposition_lifecycle_fence(),
        expected_settlement_lifecycle_version: fixture
            .request
            .expected_settlement_lifecycle_version(),
        expected_settlement_lifecycle_fence: fixture.request.expected_settlement_lifecycle_fence(),
        expected_snapshot_version: SNAPSHOT_VERSION,
        expected_resource_fence: RESOURCE_FENCE,
        observed_disposition_version: observed_disposition.version(),
        observed_disposition_lifecycle_fence: observed_disposition.lifecycle_fence(),
        observed_disposition_digest: observed_disposition.digest(&fixture.atom)?,
        observed_settlement_lifecycle_version: observed_settlement.version(),
        observed_settlement_lifecycle_fence: observed_settlement.lifecycle_fence(),
        observed_settlement_lifecycle_digest: observed_settlement.digest(&fixture.atom)?,
        observed_snapshot_version,
        resource_fence: observed_resource_fence,
        reason,
        no_mutation_proof_digest: fixture.no_mutation_proof_digest.clone(),
        authority_id: RESULT_AUTHORITY_ID.to_owned(),
        authority_key_epoch: RESULT_AUTHORITY_EPOCH,
        decided_at_unix_ms,
    })
}

fn signed_not_applied(
    fixture: &Fixture,
    input: AssignmentNotAppliedInputV1,
) -> Result<Vec<u8>, FactorError> {
    SignedAssignmentNotAppliedV1::sign(
        AssignmentNotAppliedBodyV1::new(input)?,
        &fixture.result_signer,
    )?
    .canonical_bytes()
}

fn verify_not_applied(
    fixture: &Fixture,
    canonical: &[u8],
    observed_disposition: &ObligationDispositionRecordV1,
    observed_settlement: &ObligationSettlementLifecycleV1,
    observed_snapshot_version: u64,
    observed_resource_fence: u64,
) -> Result<chio_credit::factor::VerifiedAssignmentNotAppliedV1, FactorError> {
    verify_not_applied_with(
        fixture,
        canonical,
        observed_disposition,
        observed_settlement,
        observed_snapshot_version,
        observed_resource_fence,
        &fixture.offer,
        &fixture.status_proof,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_not_applied_with(
    fixture: &Fixture,
    canonical: &[u8],
    observed_disposition: &ObligationDispositionRecordV1,
    observed_settlement: &ObligationSettlementLifecycleV1,
    observed_snapshot_version: u64,
    observed_resource_fence: u64,
    offer: &AssignmentOfferV1,
    status_proof: &VerifiedObligationStatusProofV1,
) -> Result<chio_credit::factor::VerifiedAssignmentNotAppliedV1, FactorError> {
    verify_assignment_not_applied(
        canonical,
        &AssignmentNotAppliedVerificationV1 {
            atom: &fixture.atom,
            request: &fixture.request,
            claim: &fixture.verified_claim,
            offer,
            authorization: &fixture.authorization,
            status_proof,
            observed_disposition,
            observed_settlement_lifecycle: observed_settlement,
            observed_snapshot_version,
            observed_resource_fence,
            no_mutation_proof_digest: &fixture.no_mutation_proof_digest,
            trust: &fixture.result_trust,
        },
    )
}

fn status_proof_for_other_obligation(
    fixture: &Fixture,
) -> TestResult<VerifiedObligationStatusProofV1> {
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: digest("other-factor-result-intent"),
        source_receipt_id: "other-factor-result-receipt".to_owned(),
        source_receipt_digest: digest("other-factor-result-receipt"),
        debtor_id: "did:chio:other-debtor".to_owned(),
        original_creditor_id: SELLER_ID.to_owned(),
        original_settlement_destination_ref: "acct:seller".to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest(SELLER_ID, "acct:seller")?,
        amount: MonetaryAmount {
            units: 500,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: digest("other-factor-result-authority"),
        created_at_unix_ms: 100,
        due_at_unix_ms: DUE_AT,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    let settlement = ObligationSettlementLifecycleV1::pending(&atom)?;
    let signed = SignedObligationStatusProofV1::sign(
        ObligationStatusProofBodyV1::new(&ObligationStatusProofContextV1 {
            atom: &atom,
            disposition: &disposition,
            settlement_lifecycle: &settlement,
            snapshot_version: SNAPSHOT_VERSION,
            resource_fence: RESOURCE_FENCE,
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: STATUS_EXPIRES_AT,
            authority_id: RESULT_AUTHORITY_ID,
            authority_key_epoch: RESULT_AUTHORITY_EPOCH,
        })?,
        &fixture.result_signer,
    )?;
    let canonical = signed.canonical_bytes()?;
    let trust = ObligationStatusProofTrustV1::new(
        RESULT_AUTHORITY_ID.to_owned(),
        fixture.result_signer.public_key(),
        RESULT_AUTHORITY_EPOCH,
        600,
    )?;
    Ok(verify_obligation_status_proof(
        &canonical,
        &ObligationStatusProofVerificationContextV1 {
            atom: &atom,
            disposition: &disposition,
            settlement_lifecycle: &settlement,
            snapshot_version: SNAPSHOT_VERSION,
            resource_fence: RESOURCE_FENCE,
            trust: &trust,
            trusted_now_unix_ms: EFFECTIVE_AT,
        },
    )?)
}

#[test]
fn assignment_results_are_canonical_schema_valid_and_retain_exact_evidence() -> TestResult {
    let fixture = fixture()?;
    let acknowledgement = signed_acknowledgement(&fixture, acknowledgement_input(&fixture)?)?;
    let signed: SignedAssignmentAcknowledgementV1 = serde_json::from_slice(&acknowledgement)?;
    validate_schema("factor-assignment-acknowledgement.v1.json", &signed)?;
    let verified = verify_acknowledgement(&fixture, &acknowledgement)?;
    assert_eq!(verified.canonical_bytes(), acknowledgement);
    assert_eq!(verified.envelope_digest(), sha256_hex(&acknowledgement));
    assert_eq!(verified.body_digest(), signed.body().digest()?);
    assert_eq!(
        verified.signature_digest(),
        signature_digest(&acknowledgement)?
    );

    let not_applied = signed_not_applied(
        &fixture,
        not_applied_input(
            &fixture,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
            AssignmentNotAppliedReasonV1::OperationConflict,
            1_100,
        )?,
    )?;
    let signed: SignedAssignmentNotAppliedV1 = serde_json::from_slice(&not_applied)?;
    validate_schema("factor-assignment-not-applied.v1.json", &signed)?;
    let verified = verify_not_applied(
        &fixture,
        &not_applied,
        &fixture.prior_disposition,
        &fixture.settlement_lifecycle,
        SNAPSHOT_VERSION + 1,
        RESOURCE_FENCE,
    )?;
    assert_eq!(verified.canonical_bytes(), not_applied);
    assert_eq!(verified.envelope_digest(), sha256_hex(&not_applied));
    assert_eq!(verified.body_digest(), signed.body().digest()?);
    assert_eq!(verified.signature_digest(), signature_digest(&not_applied)?);
    Ok(())
}

#[test]
fn acknowledgement_rejects_tampering_noncanonical_bytes_and_wrong_authority() -> TestResult {
    let fixture = fixture()?;
    let input = acknowledgement_input(&fixture)?;
    let canonical = signed_acknowledgement(&fixture, input.clone())?;
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&canonical);
    assert!(matches!(
        verify_acknowledgement(&fixture, &noncanonical),
        Err(FactorError::Canonicalization(_))
    ));
    assert_eq!(
        require_factor_error(verify_acknowledgement(
            &fixture,
            &tamper_signature(&canonical)?,
        )),
        FactorError::AuthorityVerification
    );
    assert_eq!(
        require_factor_error(verify_acknowledgement(
            &fixture,
            &replace_schema(&canonical, "chio.factor.assignment-acknowledgement.v9")?,
        )),
        FactorError::InvalidField("acknowledgement_schema")
    );
    let rogue = Keypair::from_seed(&[105; 32]);
    let rogue_bytes = SignedAssignmentAcknowledgementV1::sign(
        AssignmentAcknowledgementBodyV1::new(input.clone())?,
        &rogue,
    )?
    .canonical_bytes()?;
    assert_eq!(
        require_factor_error(verify_acknowledgement(&fixture, &rogue_bytes)),
        FactorError::AuthorityVerification
    );
    let rogue_trust = AssignmentResultAuthorityTrustV1::new(
        RESULT_AUTHORITY_ID.to_owned(),
        rogue.public_key(),
        RESULT_AUTHORITY_EPOCH,
    )?;
    assert_eq!(
        require_factor_error(verify_assignment_acknowledgement(
            &rogue_bytes,
            &AssignmentAcknowledgementVerificationV1 {
                atom: &fixture.atom,
                request: &fixture.request,
                claim: &fixture.verified_claim,
                offer: &fixture.offer,
                authorization: &fixture.authorization,
                status_proof: &fixture.status_proof,
                resulting_disposition: &fixture.resulting_disposition,
                trust: &rogue_trust,
            },
        )),
        FactorError::AuthorityVerification
    );
    let mut wrong_authority = input.clone();
    wrong_authority.authority_id = "other-result-authority".to_owned();
    let wrong_authority = signed_acknowledgement(&fixture, wrong_authority)?;
    assert_eq!(
        require_factor_error(verify_acknowledgement(&fixture, &wrong_authority)),
        FactorError::AuthorityVerification
    );
    let mut wrong_epoch = input;
    wrong_epoch.authority_key_epoch += 1;
    let wrong_epoch = signed_acknowledgement(&fixture, wrong_epoch)?;
    assert_eq!(
        require_factor_error(verify_acknowledgement(&fixture, &wrong_epoch)),
        FactorError::AuthorityVerification
    );
    Ok(())
}

#[test]
fn acknowledgement_rejects_every_cross_artifact_cas_mismatch() -> TestResult {
    let fixture = fixture()?;
    let base = acknowledgement_input(&fixture)?;
    let mut mismatches = Vec::new();

    let mut changed = base.clone();
    changed.operation_id = digest("other-operation");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.normalized_request_digest = digest("other-request");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.agreement_id = "other-agreement".to_owned();
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.agreement_body_digest = digest("other-agreement-body");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.obligation_id = digest("other-obligation");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.obligation_atom_digest = digest("other-atom");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.buyer_id = "did:chio:other-factor".to_owned();
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.buyer_settlement_destination_ref = "acct:other-factor".to_owned();
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.assignment_authorization_set_digest = digest("other-authorization-set");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.status_proof_digest = digest("other-status-proof");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.prior_disposition_version += 1;
    changed.prior_disposition_lifecycle_fence += 1;
    changed.resulting_disposition_version += 1;
    changed.resulting_disposition_lifecycle_fence += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.prior_disposition_digest = digest("other-prior-disposition");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.resulting_disposition_digest = digest("other-resulting-disposition");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.expected_snapshot_version += 1;
    changed.resulting_snapshot_version += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.expected_resource_fence += 1;
    changed.resulting_resource_fence += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.effective_at_unix_ms += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.due_at_unix_ms -= 1;
    mismatches.push(changed);
    let mut pre_effective = base.clone();
    pre_effective.acknowledged_at_unix_ms = EFFECTIVE_AT - 1;
    assert_eq!(
        require_factor_error(signed_acknowledgement(&fixture, pre_effective)),
        FactorError::InvalidField("acknowledgement_terms")
    );
    let mut changed = base.clone();
    changed.acknowledged_at_unix_ms = AUTHORIZATION_EXPIRES_AT;
    mismatches.push(changed);
    let mut changed = base;
    changed.acknowledged_at_unix_ms = STATUS_EXPIRES_AT;
    mismatches.push(changed);

    for mismatch in mismatches {
        let canonical = signed_acknowledgement(&fixture, mismatch)?;
        assert_eq!(
            require_factor_error(verify_acknowledgement(&fixture, &canonical)),
            FactorError::BindingMismatch
        );
    }
    Ok(())
}

#[test]
fn not_applied_rejects_tampering_noncanonical_bytes_and_wrong_authority() -> TestResult {
    let fixture = fixture()?;
    let input = not_applied_input(
        &fixture,
        &fixture.prior_disposition,
        &fixture.settlement_lifecycle,
        SNAPSHOT_VERSION + 1,
        RESOURCE_FENCE,
        AssignmentNotAppliedReasonV1::OperationConflict,
        1_100,
    )?;
    let canonical = signed_not_applied(&fixture, input.clone())?;
    let mut noncanonical = vec![b'\n'];
    noncanonical.extend_from_slice(&canonical);
    assert!(matches!(
        verify_not_applied(
            &fixture,
            &noncanonical,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
        ),
        Err(FactorError::Canonicalization(_))
    ));
    assert_eq!(
        require_factor_error(verify_not_applied(
            &fixture,
            &tamper_signature(&canonical)?,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
        )),
        FactorError::AuthorityVerification
    );
    assert_eq!(
        require_factor_error(verify_not_applied(
            &fixture,
            &replace_schema(&canonical, "chio.factor.assignment-not-applied.v9")?,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
        )),
        FactorError::InvalidField("not_applied_schema")
    );
    let rogue = Keypair::from_seed(&[106; 32]);
    let rogue_bytes = SignedAssignmentNotAppliedV1::sign(
        AssignmentNotAppliedBodyV1::new(input.clone())?,
        &rogue,
    )?
    .canonical_bytes()?;
    assert_eq!(
        require_factor_error(verify_not_applied(
            &fixture,
            &rogue_bytes,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
        )),
        FactorError::AuthorityVerification
    );
    let mut wrong_authority = input.clone();
    wrong_authority.authority_id = "other-result-authority".to_owned();
    let wrong_authority = signed_not_applied(&fixture, wrong_authority)?;
    assert_eq!(
        require_factor_error(verify_not_applied(
            &fixture,
            &wrong_authority,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
        )),
        FactorError::AuthorityVerification
    );
    let mut wrong_epoch = input;
    wrong_epoch.authority_key_epoch += 1;
    let wrong_epoch = signed_not_applied(&fixture, wrong_epoch)?;
    assert_eq!(
        require_factor_error(verify_not_applied(
            &fixture,
            &wrong_epoch,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
        )),
        FactorError::AuthorityVerification
    );
    Ok(())
}

#[test]
fn not_applied_rejects_an_unrelated_expired_offer() -> TestResult {
    let fixture = fixture()?;
    let unrelated_offer = AssignmentOfferV1::new(
        fixture.verified_claim.claim(),
        1_100,
        1_010,
        EFFECTIVE_AT + 1,
    )?;
    let canonical = signed_not_applied(
        &fixture,
        not_applied_input(
            &fixture,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION,
            RESOURCE_FENCE,
            AssignmentNotAppliedReasonV1::OfferExpired,
            EFFECTIVE_AT + 50,
        )?,
    )?;
    assert_eq!(
        require_factor_error(verify_not_applied_with(
            &fixture,
            &canonical,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION,
            RESOURCE_FENCE,
            &unrelated_offer,
            &fixture.status_proof,
        )),
        FactorError::BindingMismatch
    );
    Ok(())
}

#[test]
fn not_applied_rejects_a_status_proof_for_another_obligation() -> TestResult {
    let fixture = fixture()?;
    let other_status = status_proof_for_other_obligation(&fixture)?;
    let mut input = not_applied_input(
        &fixture,
        &fixture.prior_disposition,
        &fixture.settlement_lifecycle,
        SNAPSHOT_VERSION + 1,
        RESOURCE_FENCE,
        AssignmentNotAppliedReasonV1::OperationConflict,
        1_100,
    )?;
    input.status_proof_digest = other_status.envelope_digest().to_owned();
    let canonical = signed_not_applied(&fixture, input)?;
    assert_eq!(
        require_factor_error(verify_not_applied_with(
            &fixture,
            &canonical,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
            &fixture.offer,
            &other_status,
        )),
        FactorError::BindingMismatch
    );
    Ok(())
}

#[test]
fn not_applied_rejects_every_cross_artifact_cas_mismatch() -> TestResult {
    let fixture = fixture()?;
    let base = not_applied_input(
        &fixture,
        &fixture.prior_disposition,
        &fixture.settlement_lifecycle,
        SNAPSHOT_VERSION + 1,
        RESOURCE_FENCE,
        AssignmentNotAppliedReasonV1::OperationConflict,
        1_100,
    )?;
    let mut mismatches = Vec::new();

    let mut changed = base.clone();
    changed.operation_id = digest("other-operation");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.normalized_request_digest = digest("other-request");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.agreement_id = "other-agreement".to_owned();
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.agreement_body_digest = digest("other-agreement-body");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.obligation_id = digest("other-obligation");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.obligation_atom_digest = digest("other-atom");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.assignment_authorization_set_digest = digest("other-authorization-set");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.status_proof_digest = digest("other-status-proof");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.expected_disposition_version += 1;
    changed.expected_disposition_lifecycle_fence += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.expected_settlement_lifecycle_version += 1;
    changed.expected_settlement_lifecycle_fence += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.expected_snapshot_version += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.expected_resource_fence += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.observed_disposition_version += 1;
    changed.observed_disposition_lifecycle_fence += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.observed_disposition_digest = digest("other-observed-disposition");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.observed_settlement_lifecycle_version += 1;
    changed.observed_settlement_lifecycle_fence += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.observed_settlement_lifecycle_digest = digest("other-observed-settlement");
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.observed_snapshot_version += 1;
    mismatches.push(changed);
    let mut changed = base.clone();
    changed.resource_fence += 1;
    mismatches.push(changed);
    let mut changed = base;
    changed.no_mutation_proof_digest = digest("other-no-mutation-proof");
    mismatches.push(changed);

    for mismatch in mismatches {
        let canonical = signed_not_applied(&fixture, mismatch)?;
        assert_eq!(
            require_factor_error(verify_not_applied(
                &fixture,
                &canonical,
                &fixture.prior_disposition,
                &fixture.settlement_lifecycle,
                SNAPSHOT_VERSION + 1,
                RESOURCE_FENCE,
            )),
            FactorError::BindingMismatch
        );
    }
    Ok(())
}

#[test]
fn not_applied_reasons_require_matching_observed_state_or_time() -> TestResult {
    let fixture = fixture()?;
    for (reason, decided_at_unix_ms) in [
        (AssignmentNotAppliedReasonV1::AlreadyAssigned, 1_100),
        (AssignmentNotAppliedReasonV1::DispositionConflict, 1_100),
        (AssignmentNotAppliedReasonV1::SettlementNotPending, 1_100),
        (
            AssignmentNotAppliedReasonV1::StatusProofExpired,
            STATUS_EXPIRES_AT - 1,
        ),
        (
            AssignmentNotAppliedReasonV1::AuthorizationExpired,
            AUTHORIZATION_EXPIRES_AT - 1,
        ),
        (
            AssignmentNotAppliedReasonV1::OfferExpired,
            OFFER_EXPIRES_AT - 1,
        ),
        (
            AssignmentNotAppliedReasonV1::RequestExpired,
            REQUEST_EXPIRES_AT - 1,
        ),
        (AssignmentNotAppliedReasonV1::PastDue, DUE_AT - 1),
        (AssignmentNotAppliedReasonV1::OperationConflict, 1_100),
    ] {
        let canonical = signed_not_applied(
            &fixture,
            not_applied_input(
                &fixture,
                &fixture.prior_disposition,
                &fixture.settlement_lifecycle,
                SNAPSHOT_VERSION,
                RESOURCE_FENCE,
                reason,
                decided_at_unix_ms,
            )?,
        )?;
        assert_eq!(
            require_factor_error(verify_not_applied(
                &fixture,
                &canonical,
                &fixture.prior_disposition,
                &fixture.settlement_lifecycle,
                SNAPSHOT_VERSION,
                RESOURCE_FENCE,
            )),
            FactorError::BindingMismatch
        );
    }

    let channelized = fixture.prior_disposition.advance(
        &fixture.atom,
        ObligationDispositionTransitionV1::ReserveChannel {
            channel_id: "channel-1".to_owned(),
            reservation_id: "reservation-1".to_owned(),
            authority_digest: digest("channel-authority"),
        },
    )?;
    let settled = fixture.settlement_lifecycle.advance(
        &fixture.atom,
        ObligationSettlementTransitionV1::Settle {
            settlement_id: "settlement-1".to_owned(),
            evidence_digest: digest("settlement-evidence"),
            authority_digest: digest("settlement-authority"),
        },
    )?;
    let cases = [
        (
            AssignmentNotAppliedReasonV1::AlreadyAssigned,
            &fixture.resulting_disposition,
            &fixture.settlement_lifecycle,
            1_100,
        ),
        (
            AssignmentNotAppliedReasonV1::DispositionConflict,
            &channelized,
            &fixture.settlement_lifecycle,
            1_100,
        ),
        (
            AssignmentNotAppliedReasonV1::SettlementNotPending,
            &fixture.prior_disposition,
            &settled,
            1_100,
        ),
        (
            AssignmentNotAppliedReasonV1::StatusProofExpired,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            STATUS_EXPIRES_AT,
        ),
        (
            AssignmentNotAppliedReasonV1::AuthorizationExpired,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            AUTHORIZATION_EXPIRES_AT,
        ),
        (
            AssignmentNotAppliedReasonV1::OfferExpired,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            OFFER_EXPIRES_AT,
        ),
        (
            AssignmentNotAppliedReasonV1::RequestExpired,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            REQUEST_EXPIRES_AT,
        ),
        (
            AssignmentNotAppliedReasonV1::PastDue,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            DUE_AT,
        ),
    ];
    for (reason, disposition, settlement, decided_at_unix_ms) in cases {
        let canonical = signed_not_applied(
            &fixture,
            not_applied_input(
                &fixture,
                disposition,
                settlement,
                SNAPSHOT_VERSION,
                RESOURCE_FENCE,
                reason,
                decided_at_unix_ms,
            )?,
        )?;
        let verified = verify_not_applied(
            &fixture,
            &canonical,
            disposition,
            settlement,
            SNAPSHOT_VERSION,
            RESOURCE_FENCE,
        )?;
        assert_eq!(verified.body().reason(), reason);
    }

    let operation_conflict = signed_not_applied(
        &fixture,
        not_applied_input(
            &fixture,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION + 1,
            RESOURCE_FENCE,
            AssignmentNotAppliedReasonV1::OperationConflict,
            1_100,
        )?,
    )?;
    let verified = verify_not_applied(
        &fixture,
        &operation_conflict,
        &fixture.prior_disposition,
        &fixture.settlement_lifecycle,
        SNAPSHOT_VERSION + 1,
        RESOURCE_FENCE,
    )?;
    assert_eq!(
        verified.body().reason(),
        AssignmentNotAppliedReasonV1::OperationConflict
    );

    let lower_priority = signed_not_applied(
        &fixture,
        not_applied_input(
            &fixture,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION,
            RESOURCE_FENCE,
            AssignmentNotAppliedReasonV1::OfferExpired,
            REQUEST_EXPIRES_AT,
        )?,
    )?;
    assert_eq!(
        require_factor_error(verify_not_applied(
            &fixture,
            &lower_priority,
            &fixture.prior_disposition,
            &fixture.settlement_lifecycle,
            SNAPSHOT_VERSION,
            RESOURCE_FENCE,
        )),
        FactorError::BindingMismatch
    );
    Ok(())
}
