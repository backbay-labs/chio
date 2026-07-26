use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_credit::factor::{
    verify_assignment_agreement, verify_assignment_bind_authorization, AssignmentAgreementBodyV1,
    AssignmentAgreementTrustV1, AssignmentAgreementVerificationV1,
    AssignmentBindAuthorizationBodyV1, AssignmentBindAuthorizationInputV1,
    AssignmentBindAuthorizationTrustV1, AssignmentBindAuthorizationVerificationV1,
    AssignmentOfferV1, FactorError, NormalizedAssignmentRequestInputV1,
    NormalizedAssignmentRequestV1, ReceivableClaimInputV1, ReceivableClaimV1,
    SignedAssignmentAgreementV1, SignedAssignmentBindAuthorizationV1,
    VerifiedAssignmentAgreementV1, VerifiedAssignmentAuthorizationSetV1,
    VerifiedAssignmentBindAuthorizationV1,
};
use chio_credit::obligation::derive_obligation_payee_binding_digest;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AGREEMENT_ID: &str = "assignment-agreement-1";
const AUTHORITY_ID: &str = "assignment-authority";
const SELLER_ID: &str = "did:chio:seller";
const BUYER_ID: &str = "did:chio:buyer";
const DESTINATION: &str = "acct:buyer";

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn validate_schema(name: &str, artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<factor-authorization>"),
        &serde_json::to_value(artifact)?,
    )?;
    Ok(())
}

struct Fixture {
    operation_id: String,
    request_digest: String,
    claim: ReceivableClaimV1,
    offer: AssignmentOfferV1,
    request: NormalizedAssignmentRequestV1,
    authority: Keypair,
    seller: Keypair,
    buyer: Keypair,
}

fn fixture() -> Result<Fixture, FactorError> {
    let claim = ReceivableClaimV1::new(ReceivableClaimInputV1 {
        obligation_id: digest("obligation"),
        obligation_atom_digest: digest("obligation-atom"),
        seller_id: SELLER_ID.to_owned(),
        receipt_id: "receipt-1".to_owned(),
        receipt_digest: digest("receipt"),
        iou_id: "iou-1".to_owned(),
        iou_digest: digest("iou"),
        payee_binding_digest: derive_obligation_payee_binding_digest(SELLER_ID, "acct:seller")
            .map_err(|_| FactorError::InvalidField("payee_binding_digest"))?,
        status_proof_digest: digest("status-proof"),
        face_value: MonetaryAmount {
            units: 1_001,
            currency: "USD".to_owned(),
        },
        due_at_unix_ms: 10_000,
        built_at_unix_ms: 900,
    })?;
    let offer = AssignmentOfferV1::new(&claim, 1_000, 950, 2_000)?;
    let request = NormalizedAssignmentRequestV1::new(NormalizedAssignmentRequestInputV1 {
        obligation_id: claim.obligation_id().to_owned(),
        obligation_atom_digest: claim.obligation_atom_digest().to_owned(),
        claim_digest: claim.digest()?,
        offer_digest: offer.digest()?,
        seller_id: SELLER_ID.to_owned(),
        buyer_id: BUYER_ID.to_owned(),
        buyer_settlement_destination_ref: DESTINATION.to_owned(),
        agreed_price: offer.minimum_price().clone(),
        agreed_discount_bps: offer.asking_discount_bps(),
        expected_disposition_version: 3,
        expected_disposition_lifecycle_fence: 3,
        expected_settlement_lifecycle_version: 4,
        expected_settlement_lifecycle_fence: 4,
        action_nonce: "assignment-nonce-1".to_owned(),
        effective_at_unix_ms: 1_050,
        due_at_unix_ms: claim.due_at_unix_ms(),
        expires_at_unix_ms: 1_500,
    })?;
    let request_digest = request.digest()?;
    Ok(Fixture {
        operation_id: digest("operation"),
        request_digest,
        claim,
        offer,
        request,
        authority: Keypair::from_seed(&[81; 32]),
        seller: Keypair::from_seed(&[82; 32]),
        buyer: Keypair::from_seed(&[83; 32]),
    })
}

fn bind_bytes(fixture: &Fixture, expires_at_unix_ms: u64) -> Result<Vec<u8>, FactorError> {
    SignedAssignmentBindAuthorizationV1::sign(
        AssignmentBindAuthorizationBodyV1::new(AssignmentBindAuthorizationInputV1 {
            operation_id: fixture.operation_id.clone(),
            normalized_request_digest: fixture.request_digest.clone(),
            obligation_atom_digest: fixture.request.obligation_atom_digest().to_owned(),
            seller_id: SELLER_ID.to_owned(),
            buyer_id: BUYER_ID.to_owned(),
            agreement_id: AGREEMENT_ID.to_owned(),
            buyer_settlement_destination_ref: DESTINATION.to_owned(),
            effective_at_unix_ms: fixture.request.effective_at_unix_ms(),
            action_nonce: fixture.request.action_nonce().to_owned(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms,
            authority_id: AUTHORITY_ID.to_owned(),
            authority_key_epoch: 7,
        })?,
        &fixture.authority,
    )?
    .canonical_bytes()
}

fn bind_context<'a>(
    fixture: &'a Fixture,
    trust: &'a AssignmentBindAuthorizationTrustV1,
) -> AssignmentBindAuthorizationVerificationV1<'a> {
    AssignmentBindAuthorizationVerificationV1 {
        operation_id: &fixture.operation_id,
        normalized_request_digest: &fixture.request_digest,
        obligation_atom_digest: fixture.request.obligation_atom_digest(),
        seller_id: SELLER_ID,
        buyer_id: BUYER_ID,
        agreement_id: AGREEMENT_ID,
        buyer_settlement_destination_ref: DESTINATION,
        effective_at_unix_ms: fixture.request.effective_at_unix_ms(),
        action_nonce: fixture.request.action_nonce(),
        trust,
        trusted_now_unix_ms: 1_050,
    }
}

fn verify_bind(
    fixture: &Fixture,
    bytes: &[u8],
) -> Result<VerifiedAssignmentBindAuthorizationV1, FactorError> {
    let trust = AssignmentBindAuthorizationTrustV1::new(
        AUTHORITY_ID.to_owned(),
        fixture.authority.public_key(),
        7,
        200,
    )?;
    verify_assignment_bind_authorization(bytes, &bind_context(fixture, &trust))
}

fn agreement_bytes(
    fixture: &Fixture,
    bind: &VerifiedAssignmentBindAuthorizationV1,
) -> Result<Vec<u8>, FactorError> {
    let body = AssignmentAgreementBodyV1::new(
        AGREEMENT_ID.to_owned(),
        fixture.operation_id.clone(),
        &fixture.request,
        &fixture.claim,
        &fixture.offer,
        bind,
    )?;
    SignedAssignmentAgreementV1::sign(body, 11, &fixture.seller, 12, &fixture.buyer)?
        .canonical_bytes()
}

fn agreement_trust(fixture: &Fixture) -> Result<AssignmentAgreementTrustV1, FactorError> {
    AssignmentAgreementTrustV1::new(
        SELLER_ID.to_owned(),
        fixture.seller.public_key(),
        11,
        BUYER_ID.to_owned(),
        fixture.buyer.public_key(),
        12,
    )
}

fn verify_agreement(
    fixture: &Fixture,
    bind: &VerifiedAssignmentBindAuthorizationV1,
    bytes: &[u8],
) -> Result<VerifiedAssignmentAgreementV1, FactorError> {
    let trust = agreement_trust(fixture)?;
    verify_assignment_agreement(
        bytes,
        &AssignmentAgreementVerificationV1 {
            operation_id: &fixture.operation_id,
            normalized_request_digest: &fixture.request_digest,
            assignment_authority_digest: bind.envelope_digest(),
            trust: &trust,
        },
    )
}

#[test]
fn bind_authorization_requires_exact_canonical_bytes_and_configured_authority() -> TestResult {
    let fixture = fixture()?;
    let bytes = bind_bytes(&fixture, 1_100)?;
    let signed: SignedAssignmentBindAuthorizationV1 = serde_json::from_slice(&bytes)?;
    validate_schema("factor-assignment-bind-authorization.v1.json", &signed)?;

    let verified = verify_bind(&fixture, &bytes)?;
    assert_eq!(verified.canonical_bytes(), bytes);
    assert_eq!(verified.envelope_digest(), sha256_hex(&bytes));
    assert_eq!(verified.body_digest().len(), 64);

    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&bytes);
    assert!(matches!(
        verify_bind(&fixture, &noncanonical),
        Err(FactorError::Canonicalization(_))
    ));

    let rogue = Keypair::from_seed(&[84; 32]);
    let rogue_trust = AssignmentBindAuthorizationTrustV1::new(
        AUTHORITY_ID.to_owned(),
        rogue.public_key(),
        7,
        200,
    )?;
    assert_eq!(
        verify_assignment_bind_authorization(&bytes, &bind_context(&fixture, &rogue_trust)),
        Err(FactorError::AuthorityVerification)
    );

    let trusted = AssignmentBindAuthorizationTrustV1::new(
        AUTHORITY_ID.to_owned(),
        fixture.authority.public_key(),
        7,
        200,
    )?;
    let mut wrong_binding = bind_context(&fixture, &trusted);
    wrong_binding.buyer_id = "did:chio:other-buyer";
    assert_eq!(
        verify_assignment_bind_authorization(&bytes, &wrong_binding),
        Err(FactorError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn bind_authorization_rejects_tampering_and_unknown_schema() -> TestResult {
    let fixture = fixture()?;
    let bytes = bind_bytes(&fixture, 1_100)?;

    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes)?;
    tampered["body"]["issuedAtUnixMs"] = serde_json::json!(999);
    assert_eq!(
        verify_bind(&fixture, &canonical_json_bytes(&tampered)?),
        Err(FactorError::AuthorityVerification)
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes)?;
    unknown["body"]["schema"] = serde_json::json!("chio.factor.unknown.v1");
    assert_eq!(
        verify_bind(&fixture, &canonical_json_bytes(&unknown)?),
        Err(FactorError::InvalidField("authorization_schema"))
    );
    Ok(())
}

#[test]
fn bilateral_agreement_and_composite_set_pin_both_parties() -> TestResult {
    let fixture = fixture()?;
    let bind_blob = bind_bytes(&fixture, 1_100)?;
    let bind = verify_bind(&fixture, &bind_blob)?;
    let bytes = agreement_bytes(&fixture, &bind)?;
    let signed: SignedAssignmentAgreementV1 = serde_json::from_slice(&bytes)?;
    validate_schema("factor-assignment-agreement.v1.json", &signed)?;

    let verified = verify_agreement(&fixture, &bind, &bytes)?;
    assert_eq!(verified.canonical_bytes(), bytes);
    assert_eq!(verified.artifact_digest(), sha256_hex(&bytes));
    assert_ne!(
        verified.seller_signature_digest(),
        verified.buyer_signature_digest()
    );
    let set = VerifiedAssignmentAuthorizationSetV1::new(bind.clone(), verified.clone())?;
    assert_eq!(set.digest().len(), 64);
    assert_eq!(set.agreement().body_digest(), verified.body_digest());
    assert_eq!(fixture.claim.status_proof_digest(), digest("status-proof"));
    set.validate_submission_binding(&fixture.request, &fixture.claim, &fixture.offer)?;
    assert_eq!(
        set.validate_submission(&fixture.request, &fixture.claim, &fixture.offer, 1_100),
        Err(FactorError::NotCurrent)
    );

    let wrong_buyer = Keypair::from_seed(&[85; 32]);
    let wrong_trust = AssignmentAgreementTrustV1::new(
        SELLER_ID.to_owned(),
        fixture.seller.public_key(),
        11,
        BUYER_ID.to_owned(),
        wrong_buyer.public_key(),
        12,
    )?;
    assert_eq!(
        verify_assignment_agreement(
            &bytes,
            &AssignmentAgreementVerificationV1 {
                operation_id: &fixture.operation_id,
                normalized_request_digest: &fixture.request_digest,
                assignment_authority_digest: bind.envelope_digest(),
                trust: &wrong_trust,
            },
        ),
        Err(FactorError::BindingMismatch)
    );

    let body = AssignmentAgreementBodyV1::new(
        AGREEMENT_ID.to_owned(),
        fixture.operation_id.clone(),
        &fixture.request,
        &fixture.claim,
        &fixture.offer,
        &bind,
    )?;
    assert_eq!(
        SignedAssignmentAgreementV1::sign(body, 11, &fixture.seller, 12, &fixture.seller),
        Err(FactorError::InvalidField("agreement_party_keys"))
    );

    let other_bind = verify_bind(&fixture, &bind_bytes(&fixture, 1_090)?)?;
    assert_eq!(
        VerifiedAssignmentAuthorizationSetV1::new(other_bind, verified),
        Err(FactorError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn agreement_rejects_noncanonical_tampered_and_unknown_artifacts() -> TestResult {
    let fixture = fixture()?;
    let bind = verify_bind(&fixture, &bind_bytes(&fixture, 1_100)?)?;
    let bytes = agreement_bytes(&fixture, &bind)?;

    let mut noncanonical = vec![b'\n'];
    noncanonical.extend_from_slice(&bytes);
    assert!(matches!(
        verify_agreement(&fixture, &bind, &noncanonical),
        Err(FactorError::Canonicalization(_))
    ));

    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes)?;
    tampered["body"]["dueAtUnixMs"] = serde_json::json!(9_999);
    assert_eq!(
        verify_agreement(&fixture, &bind, &canonical_json_bytes(&tampered)?),
        Err(FactorError::AuthorityVerification)
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes)?;
    unknown["body"]["schema"] = serde_json::json!("chio.factor.unknown.v1");
    assert_eq!(
        verify_agreement(&fixture, &bind, &canonical_json_bytes(&unknown)?),
        Err(FactorError::InvalidField("agreement_schema"))
    );
    Ok(())
}
