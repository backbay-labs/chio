#[path = "support/credit_admission.rs"]
mod credit_admission_support;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{
    sha256_hex, sign_canonical_with_backend, Ed25519Backend, Keypair, SigningAlgorithm,
    SigningBackend,
};
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::economics::{
    EconomicAmountBoundsReceiptMetadata, EconomicAuthorizationMode,
    EconomicAuthorizationReceiptMetadata, EconomicAuthorizationReceiptMetadataVersion,
    EconomicBudgetReceiptMetadata, EconomicMerchantReceiptMetadata, EconomicPayeeReceiptMetadata,
    EconomicPayerReceiptMetadata, EconomicRailReceiptMetadata, EconomicSettlementReceiptMetadata,
    FinancialReceiptMetadata, SettlementStatus,
};
use chio_core_types::receipt::governance::{
    GovernedApprovalReceiptMetadata, GovernedTransactionReceiptMetadata,
};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, CreditFacilityBindTrustInputV1,
    CreditFacilityBindTrustV1, ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1,
    ObligationDispositionRecordV1, ObligationSettlementLifecycleV1, VerifiedCreditFacilityBindV1,
};
use chio_credit::{
    verify_iou_envelope_v2, CreditEvaluatorHook, IouEnvelopeCryptoFloorV2,
    IouEnvelopeIssuerTrustV2, IouEnvelopeMintContextV2, IouEnvelopeReceiptTrustV2,
    IouEnvelopeV2Error, IouEnvelopeVerificationContextV2, LocalCreditAccount, SignedIouEnvelopeV2,
    RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA,
};
use credit_admission_support::{
    CreditAdmissionInput, PreparedCreditAdmission, TestCreditAdmissionStore,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const RECEIPT_TIMESTAMP_SECONDS: u64 = 1_710_000_000;
const ATOM_CREATED_AT_MS: u64 = 1_710_000_000_100;
const IOU_ISSUED_AT_MS: u64 = 1_710_000_000_200;
const DUE_AT_MS: u64 = 1_710_000_100_000;
const BIND_ISSUED_AT_MS: u64 = 1_709_999_999_900;
const BIND_EXPIRES_AT_MS: u64 = 1_710_000_050_000;
const DEBTOR_ID: &str = "did:chio:debtor";
const CREDITOR_ID: &str = "did:chio:seller";
const AUTHORITY_ID: &str = "did:chio:credit-authority";
const DESTINATION: &str = "acct:seller:usd";

struct Fixture {
    account: LocalCreditAccount<Ed25519Backend>,
    kernel_signer: Keypair,
    creditor_signer: Keypair,
    issuer_key: chio_core_types::crypto::PublicKey,
    receipt: ChioReceipt,
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    settlement_lifecycle: ObligationSettlementLifecycleV1,
    credit_facility_bind: VerifiedCreditFacilityBindV1,
    credit_facility_bind_trust: CreditFacilityBindTrustV1,
    credit_admission_store: TestCreditAdmissionStore,
}

#[derive(Clone, Copy)]
enum ReceiptCreditAuthority {
    Exact,
    Missing,
    Mismatched,
}

fn financial_metadata(status: SettlementStatus) -> FinancialReceiptMetadata {
    FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 250,
        currency: "USD".to_owned(),
        budget_remaining: 750,
        budget_total: 1_000,
        delegation_depth: 1,
        root_budget_holder: DEBTOR_ID.to_owned(),
        payment_reference: None,
        settlement_status: status,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    }
}

fn economic_authorization(
    beneficiary_id: &str,
    status: SettlementStatus,
    include_authority: bool,
    credit_authority_digest: Option<&str>,
    facility_id: &str,
) -> TestResult<EconomicAuthorizationReceiptMetadata> {
    let economic_intent_digest = include_authority.then(|| sha256_hex(b"intent-credit-1"));
    let payee_binding_digest = include_authority
        .then(|| derive_obligation_payee_binding_digest(CREDITOR_ID, DESTINATION))
        .transpose()?;
    let pre_action_authority_digest =
        include_authority.then(|| sha256_hex(b"pre-action-authority"));
    Ok(EconomicAuthorizationReceiptMetadata {
        version: EconomicAuthorizationReceiptMetadataVersion::V1,
        economic_intent_digest,
        payee_binding_digest,
        pre_action_authority_digest,
        credit_authority_digest: credit_authority_digest.map(str::to_owned),
        economic_mode: EconomicAuthorizationMode::BudgetOnly,
        payer: EconomicPayerReceiptMetadata {
            party_id: DEBTOR_ID.to_owned(),
            funding_source_ref: facility_id.to_owned(),
            custody_provider: None,
            obligor_ref: None,
        },
        merchant: EconomicMerchantReceiptMetadata {
            merchant_id: CREDITOR_ID.to_owned(),
            merchant_of_record: None,
            order_ref: Some("order-1".to_owned()),
        },
        payee: EconomicPayeeReceiptMetadata {
            beneficiary_id: beneficiary_id.to_owned(),
            settlement_destination_ref: DESTINATION.to_owned(),
        },
        rail: EconomicRailReceiptMetadata {
            kind: "credit_facility".to_owned(),
            asset: "USD".to_owned(),
            network: None,
            facilitator: None,
            contract_or_account_ref: Some(facility_id.to_owned()),
        },
        amount_bounds: EconomicAmountBoundsReceiptMetadata {
            approved_max: MonetaryAmount {
                units: 250,
                currency: "USD".to_owned(),
            },
            hold_amount: None,
            settlement_cap: MonetaryAmount {
                units: 250,
                currency: "USD".to_owned(),
            },
        },
        pricing_basis: None,
        metering: None,
        liability_refs: None,
        budget: EconomicBudgetReceiptMetadata {
            grant_index: 0,
            cost_charged: 250,
            currency: "USD".to_owned(),
            budget_remaining: 750,
            budget_total: 1_000,
            delegation_depth: 1,
            root_budget_holder: DEBTOR_ID.to_owned(),
            attempted_cost: None,
        },
        settlement: EconomicSettlementReceiptMetadata {
            settlement_status: status,
        },
    })
}

fn signed_receipt(
    kernel: &Keypair,
    beneficiary_id: &str,
    status: SettlementStatus,
    include_authority: bool,
    credit_authority_digest: Option<&str>,
    facility_id: &str,
) -> TestResult<ChioReceipt> {
    let financial = financial_metadata(status.clone());
    let governed = GovernedTransactionReceiptMetadata {
        intent_id: "intent-credit-1".to_owned(),
        intent_hash: sha256_hex(b"intent-credit-1"),
        purpose: "deferred supplier payment".to_owned(),
        server_id: "tools.seller.example".to_owned(),
        tool_name: "priced_call".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 250,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        approval: Some(GovernedApprovalReceiptMetadata {
            token_id: "approval-credit-1".to_owned(),
            approver_key: "approver-credit-1".to_owned(),
            approval_artifact_digest: include_authority
                .then(|| sha256_hex(b"pre-action-authority")),
            approved: true,
        }),
        runtime_assurance: None,
        call_chain: None,
        autonomy: None,
        economic_authorization: Some(economic_authorization(
            beneficiary_id,
            status,
            include_authority,
            credit_authority_digest,
            facility_id,
        )?),
    };
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-placeholder".to_owned(),
            timestamp: RECEIPT_TIMESTAMP_SECONDS,
            capability_id: "capability-credit-1".to_owned(),
            tool_server: "tools.seller.example".to_owned(),
            tool_name: "priced_call".to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({"units": 1}))?,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"tool-output"),
            policy_hash: sha256_hex(b"credit-policy"),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "financial": financial,
                "governed_transaction": governed,
                "receipt_context": {
                    "request_id": "request-credit-1",
                },
            })),
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-a".to_owned()),
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        kernel,
    )?)
}

fn fixture(beneficiary_id: &str, status: SettlementStatus) -> TestResult<Fixture> {
    fixture_with_receipt_authority(
        beneficiary_id,
        status,
        true,
        ReceiptCreditAuthority::Exact,
        "facility:working-capital",
    )
}

fn fixture_with_authority(
    beneficiary_id: &str,
    status: SettlementStatus,
    include_authority: bool,
) -> TestResult<Fixture> {
    fixture_with_receipt_authority(
        beneficiary_id,
        status,
        include_authority,
        ReceiptCreditAuthority::Exact,
        "facility:working-capital",
    )
}

fn fixture_with_receipt_facility(facility_id: &str) -> TestResult<Fixture> {
    fixture_with_receipt_authority(
        CREDITOR_ID,
        SettlementStatus::Pending,
        true,
        ReceiptCreditAuthority::Exact,
        facility_id,
    )
}

fn fixture_with_receipt_authority(
    beneficiary_id: &str,
    status: SettlementStatus,
    include_authority: bool,
    receipt_credit_authority: ReceiptCreditAuthority,
    receipt_facility_id: &str,
) -> TestResult<Fixture> {
    let kernel = Keypair::generate();
    let authority = Keypair::generate();
    let debtor = Keypair::generate();
    let creditor = Keypair::generate();
    let prepared_credit = PreparedCreditAdmission::new(CreditAdmissionInput {
        operation_id: &sha256_hex(b"operation-credit-1"),
        request_id: "request-credit-1",
        action_nonce: "nonce-credit-1",
        economic_intent_digest: &sha256_hex(b"intent-credit-1"),
        facility_id: "facility:working-capital",
        debtor_id: DEBTOR_ID,
        original_creditor_id: CREDITOR_ID,
        original_settlement_destination_ref: DESTINATION,
        capability_id: "capability-credit-1",
        tool_server: "tools.seller.example",
        tool_name: "priced_call",
        amount: MonetaryAmount {
            units: 250,
            currency: "USD".to_owned(),
        },
        expected_exposure_version: 1,
        due_at_unix_ms: DUE_AT_MS,
        bind_issued_at_unix_ms: BIND_ISSUED_AT_MS,
        bind_expires_at_unix_ms: BIND_EXPIRES_AT_MS,
        trusted_at_unix_ms: ATOM_CREATED_AT_MS,
        bind_authority_id: AUTHORITY_ID,
        bind_authority_epoch: 3,
        debtor_key_epoch: 4,
        creditor_key_epoch: 5,
        bind_authority: &authority,
        debtor: &debtor,
        creditor: &creditor,
    })?;
    let credit_facility_bind = prepared_credit.credit_facility_bind().clone();
    let credit_facility_bind_trust = prepared_credit.bind_trust().clone();
    let receipt_credit_authority_digest = match receipt_credit_authority {
        ReceiptCreditAuthority::Exact => Some(credit_facility_bind.artifact_digest().to_owned()),
        ReceiptCreditAuthority::Missing => None,
        ReceiptCreditAuthority::Mismatched => Some(sha256_hex(b"wrong-credit-authority")),
    };
    let receipt = signed_receipt(
        &kernel,
        beneficiary_id,
        status,
        include_authority,
        receipt_credit_authority_digest.as_deref(),
        receipt_facility_id,
    )?;
    let receipt_digest = sha256_hex(&canonical_json_bytes(&receipt)?);
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: sha256_hex(b"intent-credit-1"),
        source_receipt_id: receipt.id.clone(),
        source_receipt_digest: receipt_digest,
        debtor_id: DEBTOR_ID.to_owned(),
        original_creditor_id: CREDITOR_ID.to_owned(),
        original_settlement_destination_ref: DESTINATION.to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest(CREDITOR_ID, DESTINATION)?,
        amount: MonetaryAmount {
            units: 250,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::CreditFacility {
            facility_id: "facility:working-capital".to_owned(),
            authority_digest: credit_facility_bind.artifact_digest().to_owned(),
        },
        pre_action_authority_digest: sha256_hex(b"pre-action-authority"),
        created_at_unix_ms: ATOM_CREATED_AT_MS,
        due_at_unix_ms: DUE_AT_MS,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    let settlement_lifecycle = ObligationSettlementLifecycleV1::pending(&atom)?;
    let credit_admission_store =
        TestCreditAdmissionStore::committed(prepared_credit.committed_record(&atom)?);
    let issuer = Keypair::generate();
    let issuer_key = issuer.public_key();
    let account = LocalCreditAccount::new_with_receipt_trust(
        Ed25519Backend::new(issuer),
        IouEnvelopeReceiptTrustV2::new([kernel.public_key()], ReceiptCryptoFloor::AllowClassical),
    );
    Ok(Fixture {
        account,
        kernel_signer: kernel,
        creditor_signer: creditor,
        issuer_key,
        receipt,
        atom,
        disposition,
        settlement_lifecycle,
        credit_facility_bind,
        credit_facility_bind_trust,
        credit_admission_store,
    })
}

fn mint(fixture: &Fixture) -> Result<SignedIouEnvelopeV2, IouEnvelopeV2Error> {
    let credit_admission = fixture.credit_admission_store.adapter();
    fixture.account.mint_obligation_iou_v2(
        &credit_admission,
        &IouEnvelopeMintContextV2 {
            atom: &fixture.atom,
            disposition: &fixture.disposition,
            settlement_lifecycle: &fixture.settlement_lifecycle,
            receipt: &fixture.receipt,
            credit_facility_bind: &fixture.credit_facility_bind,
            issuer_id: "economy.credit.issuer",
            issuer_key_epoch: 7,
            trusted_issued_at_unix_ms: IOU_ISSUED_AT_MS,
        },
    )
}

fn replace_receipt_request_id(
    fixture: &Fixture,
    request_id: Option<&str>,
) -> TestResult<(
    ChioReceipt,
    ObligationAtomV1,
    ObligationDispositionRecordV1,
    ObligationSettlementLifecycleV1,
)> {
    let mut body = fixture.receipt.body();
    let metadata = body
        .metadata
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| std::io::Error::other("receipt metadata must be an object"))?;
    match request_id {
        Some(request_id) => {
            metadata.insert(
                "receipt_context".to_owned(),
                serde_json::json!({"request_id": request_id}),
            );
        }
        None => {
            metadata.remove("receipt_context");
        }
    }
    let receipt = ChioReceipt::sign(body, &fixture.kernel_signer)?;
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: fixture.atom.economic_intent_digest().to_owned(),
        source_receipt_id: receipt.id.clone(),
        source_receipt_digest: sha256_hex(&canonical_json_bytes(&receipt)?),
        debtor_id: fixture.atom.debtor_id().to_owned(),
        original_creditor_id: fixture.atom.original_creditor_id().to_owned(),
        original_settlement_destination_ref: fixture
            .atom
            .original_settlement_destination_ref()
            .to_owned(),
        payee_binding_digest: fixture.atom.payee_binding_digest().to_owned(),
        amount: fixture.atom.amount().clone(),
        credit_election: fixture.atom.credit_election().clone(),
        pre_action_authority_digest: fixture.atom.pre_action_authority_digest().to_owned(),
        created_at_unix_ms: fixture.atom.created_at_unix_ms(),
        due_at_unix_ms: fixture.atom.due_at_unix_ms(),
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    let settlement_lifecycle = ObligationSettlementLifecycleV1::pending(&atom)?;
    Ok((receipt, atom, disposition, settlement_lifecycle))
}

fn validate_schema(artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy/receivable-iou-envelope.v1.json");
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<iou-v2>"),
        &serde_json::to_value(artifact)?,
    )?;
    Ok(())
}

#[test]
fn obligation_led_v2_mints_and_verifies_exact_evidence() -> TestResult {
    let fixture = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let signed = mint(&fixture)?;
    let canonical = signed.canonical_bytes()?;
    validate_schema(&signed)?;
    let parsed = SignedIouEnvelopeV2::from_canonical_bytes(&canonical)?;
    assert_eq!(parsed.body().schema(), RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA);
    assert_eq!(
        parsed.body().operation_id(),
        sha256_hex(b"operation-credit-1")
    );
    assert_eq!(parsed.body().obligation_id(), fixture.atom.obligation_id());
    assert_eq!(parsed.body().debtor_id(), DEBTOR_ID);
    assert_eq!(parsed.body().original_creditor_id(), CREDITOR_ID);
    assert_eq!(parsed.body().facility_id(), "facility:working-capital");
    assert_eq!(
        parsed.body().credit_authority_digest(),
        fixture.credit_facility_bind.artifact_digest()
    );
    assert_eq!(parsed.body().issued_at_unix_ms(), IOU_ISSUED_AT_MS);

    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        fixture.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let verified = verify_iou_envelope_v2(
        &canonical,
        &fixture.credit_admission_store.adapter(),
        &IouEnvelopeVerificationContextV2 {
            atom: &fixture.atom,
            disposition: &fixture.disposition,
            settlement_lifecycle: &fixture.settlement_lifecycle,
            receipt: &fixture.receipt,
            receipt_trust: fixture.account.receipt_trust(),
            credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
            issuer_trust: &issuer_trust,
            trusted_now_unix_ms: IOU_ISSUED_AT_MS,
        },
    )?;
    assert_eq!(verified.canonical_bytes(), canonical);
    assert_eq!(verified.envelope_digest(), sha256_hex(&canonical));
    assert_eq!(verified.body_digest().len(), 64);
    assert_eq!(verified.signature_digest().len(), 64);
    assert_eq!(
        verified.credit_facility_bind().artifact_digest(),
        fixture.credit_facility_bind.artifact_digest()
    );
    assert_eq!(mint(&fixture)?.canonical_bytes()?, canonical);
    Ok(())
}

#[test]
fn v2_requires_the_exact_committed_credit_admission() -> TestResult {
    let missing = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let canonical = mint(&missing)?.canonical_bytes()?;
    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        missing.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    missing.credit_admission_store.clear()?;
    assert_eq!(
        mint(&missing),
        Err(IouEnvelopeV2Error::CreditAdmissionVerification)
    );
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &missing.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &missing.atom,
                disposition: &missing.disposition,
                settlement_lifecycle: &missing.settlement_lifecycle,
                receipt: &missing.receipt,
                receipt_trust: missing.account.receipt_trust(),
                credit_facility_bind_trust: &missing.credit_facility_bind_trust,
                issuer_trust: &issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::CreditAdmissionVerification)
    );

    let failed = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    failed
        .credit_admission_store
        .fail("credit store unavailable")?;
    assert_eq!(
        mint(&failed),
        Err(IouEnvelopeV2Error::CreditAdmissionVerification)
    );

    let noncommitted = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let record = noncommitted
        .credit_admission_store
        .record()?
        .ok_or("committed credit admission was missing")?;
    let mut value = serde_json::to_value(record)?;
    value["state"] = serde_json::json!("outcome_unknown");
    let Some(object) = value.as_object_mut() else {
        return Err("credit admission record was not an object".into());
    };
    object.remove("obligationId");
    object.remove("obligationAtomDigest");
    noncommitted
        .credit_admission_store
        .replace(serde_json::from_value(value)?)?;
    assert_eq!(
        mint(&noncommitted),
        Err(IouEnvelopeV2Error::CreditAdmissionVerification)
    );

    let mismatched = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let record = mismatched
        .credit_admission_store
        .record()?
        .ok_or("committed credit admission was missing")?;
    let mut value = serde_json::to_value(record)?;
    value["obligationAtomDigest"] = serde_json::json!(sha256_hex(b"other-obligation-atom"));
    mismatched
        .credit_admission_store
        .replace(serde_json::from_value(value)?)?;
    assert_eq!(
        mint(&mismatched),
        Err(IouEnvelopeV2Error::BindingMismatch(
            "committed_credit_admission"
        ))
    );
    Ok(())
}

#[test]
fn v2_rejects_unknown_noncanonical_legacy_and_untrusted_envelopes() -> TestResult {
    let fixture = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let signed = mint(&fixture)?;
    let canonical = signed.canonical_bytes()?;
    let mut value: serde_json::Value = serde_json::from_slice(&canonical)?;

    let noncanonical = serde_json::to_vec_pretty(&value)?;
    assert!(SignedIouEnvelopeV2::from_canonical_bytes(&noncanonical).is_err());

    value["body"]["schema"] = serde_json::json!("chio.credit.iou-envelope.v9");
    let unknown = canonical_json_bytes(&value)?;
    assert_eq!(
        SignedIouEnvelopeV2::from_canonical_bytes(&unknown),
        Err(IouEnvelopeV2Error::InvalidField("schema"))
    );

    let Some(legacy) = fixture.account.evaluate(&fixture.receipt)? else {
        return Err("priced legacy receipt omitted its v1 IOU".into());
    };
    assert!(SignedIouEnvelopeV2::from_canonical_bytes(&canonical_json_bytes(&legacy)?).is_err());

    let wrong_issuer = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        Keypair::generate().public_key(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                issuer_trust: &wrong_issuer,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::IssuerVerification)
    );

    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        fixture.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let wrong_bind_trust = CreditFacilityBindTrustV1::new(CreditFacilityBindTrustInputV1 {
        authority_id: AUTHORITY_ID.to_owned(),
        authority_key: Keypair::generate().public_key(),
        authority_key_epoch: 3,
        debtor_id: DEBTOR_ID.to_owned(),
        debtor_key: Keypair::generate().public_key(),
        debtor_key_epoch: 4,
        creditor_id: CREDITOR_ID.to_owned(),
        creditor_key: Keypair::generate().public_key(),
        creditor_key_epoch: 5,
        max_lifetime_ms: 100_000,
    })?;
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &wrong_bind_trust,
                issuer_trust: &issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::CreditAuthorityVerification)
    );
    let mut algorithm_value: serde_json::Value = serde_json::from_slice(&canonical)?;
    algorithm_value["algorithm"] = serde_json::json!("p256");
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical_json_bytes(&algorithm_value)?,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                issuer_trust: &issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::IssuerVerification)
    );

    let mut mismatched_receipt = fixture.receipt.clone();
    mismatched_receipt.algorithm = Some(SigningAlgorithm::P256);
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &mismatched_receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                issuer_trust: &issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::ReceiptVerification)
    );
    Ok(())
}

#[test]
fn v2_rejects_payee_substitution_paid_receipts_and_floor_downgrades() -> TestResult {
    let missing_authority = fixture_with_authority(CREDITOR_ID, SettlementStatus::Pending, false)?;
    assert_eq!(
        mint(&missing_authority),
        Err(IouEnvelopeV2Error::BindingMismatch("governed_transaction"))
    );

    let substituted = fixture("tools.seller.example", SettlementStatus::Pending)?;
    assert_eq!(
        mint(&substituted),
        Err(IouEnvelopeV2Error::BindingMismatch("economic_terms"))
    );

    for receipt_credit_authority in [
        ReceiptCreditAuthority::Missing,
        ReceiptCreditAuthority::Mismatched,
    ] {
        let fixture = fixture_with_receipt_authority(
            CREDITOR_ID,
            SettlementStatus::Pending,
            true,
            receipt_credit_authority,
            "facility:working-capital",
        )?;
        assert_eq!(
            mint(&fixture),
            Err(IouEnvelopeV2Error::BindingMismatch("economic_terms"))
        );
    }

    let substituted_facility = fixture_with_receipt_facility("facility:other")?;
    assert_eq!(
        mint(&substituted_facility),
        Err(IouEnvelopeV2Error::BindingMismatch("economic_terms"))
    );

    let fixture = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let raw_atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: sha256_hex(b"intent-credit-1"),
        source_receipt_id: fixture.receipt.id.clone(),
        source_receipt_digest: sha256_hex(&canonical_json_bytes(&fixture.receipt)?),
        debtor_id: DEBTOR_ID.to_owned(),
        original_creditor_id: CREDITOR_ID.to_owned(),
        original_settlement_destination_ref: DESTINATION.to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest(CREDITOR_ID, DESTINATION)?,
        amount: MonetaryAmount {
            units: 250,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::CreditFacility {
            facility_id: "facility:working-capital".to_owned(),
            authority_digest: sha256_hex(b"caller-asserted-credit-authority"),
        },
        pre_action_authority_digest: sha256_hex(b"pre-action-authority"),
        created_at_unix_ms: ATOM_CREATED_AT_MS,
        due_at_unix_ms: DUE_AT_MS,
    })?;
    assert_eq!(
        fixture.account.mint_obligation_iou_v2(
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeMintContextV2 {
                atom: &raw_atom,
                disposition: &ObligationDispositionRecordV1::produced(&raw_atom)?,
                settlement_lifecycle: &ObligationSettlementLifecycleV1::pending(&raw_atom)?,
                receipt: &fixture.receipt,
                credit_facility_bind: &fixture.credit_facility_bind,
                issuer_id: "economy.credit.issuer",
                issuer_key_epoch: 7,
                trusted_issued_at_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::BindingMismatch("credit_facility_bind"))
    );

    let issuer_as_creditor = crate::fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    assert_eq!(
        issuer_as_creditor.account.mint_obligation_iou_v2(
            &issuer_as_creditor.credit_admission_store.adapter(),
            &IouEnvelopeMintContextV2 {
                atom: &issuer_as_creditor.atom,
                disposition: &issuer_as_creditor.disposition,
                settlement_lifecycle: &issuer_as_creditor.settlement_lifecycle,
                receipt: &issuer_as_creditor.receipt,
                credit_facility_bind: &issuer_as_creditor.credit_facility_bind,
                issuer_id: CREDITOR_ID,
                issuer_key_epoch: 7,
                trusted_issued_at_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::InvalidField("issuer_identity"))
    );

    let paid = crate::fixture(CREDITOR_ID, SettlementStatus::Settled)?;
    assert_eq!(
        mint(&paid),
        Err(IouEnvelopeV2Error::NotEligible("settlement_status"))
    );

    let strict_receipt_account = LocalCreditAccount::new_with_receipt_trust(
        Ed25519Backend::new(Keypair::generate()),
        IouEnvelopeReceiptTrustV2::new(
            [fixture.receipt.kernel_key.clone()],
            ReceiptCryptoFloor::PqRequired,
        ),
    );
    assert_eq!(
        strict_receipt_account.mint_obligation_iou_v2(
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeMintContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                credit_facility_bind: &fixture.credit_facility_bind,
                issuer_id: "economy.credit.issuer",
                issuer_key_epoch: 7,
                trusted_issued_at_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::ReceiptVerification)
    );

    let canonical = mint(&fixture)?.canonical_bytes()?;
    let pq_issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        fixture.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::PqRequired,
    )?;
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                issuer_trust: &pq_issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::IssuerVerification)
    );

    assert_eq!(
        fixture.account.mint_obligation_iou_v2(
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeMintContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                credit_facility_bind: &fixture.credit_facility_bind,
                issuer_id: "economy.credit.issuer",
                issuer_key_epoch: 7,
                trusted_issued_at_unix_ms: ATOM_CREATED_AT_MS - 1,
            },
        ),
        Err(IouEnvelopeV2Error::BindingMismatch("issuance_time"))
    );

    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        fixture.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                issuer_trust: &issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS - 1,
            },
        ),
        Err(IouEnvelopeV2Error::BindingMismatch("signed_body"))
    );
    Ok(())
}

#[test]
fn v2_rejects_source_receipt_key_reused_for_iou_minting() -> TestResult {
    let fixture = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let account = LocalCreditAccount::new_with_receipt_trust(
        Ed25519Backend::new(fixture.kernel_signer.clone()),
        fixture.account.receipt_trust().clone(),
    );

    assert_eq!(
        account.mint_obligation_iou_v2(
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeMintContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                credit_facility_bind: &fixture.credit_facility_bind,
                issuer_id: "economy.credit.issuer",
                issuer_key_epoch: 7,
                trusted_issued_at_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"))
    );
    Ok(())
}

#[test]
fn v2_verifier_rejects_source_receipt_key_reused_by_valid_iou_signature() -> TestResult {
    let fixture = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let signed = mint(&fixture)?;
    let mut value = serde_json::to_value(signed)?;
    let backend = Ed25519Backend::new(fixture.kernel_signer.clone());
    let (signature, _) = sign_canonical_with_backend(&backend, &value["body"])?;
    value["signerKey"] = serde_json::to_value(backend.public_key())?;
    value["algorithm"] = serde_json::to_value(backend.algorithm())?;
    value["signature"] = serde_json::to_value(signature)?;
    let canonical = canonical_json_bytes(&value)?;
    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        fixture.receipt.kernel_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;

    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                issuer_trust: &issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"))
    );
    Ok(())
}

#[test]
fn v2_rejects_creditor_key_reused_under_an_issuer_alias() -> TestResult {
    let fixture = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let creditor_account = LocalCreditAccount::new_with_receipt_trust(
        Ed25519Backend::new(fixture.creditor_signer.clone()),
        fixture.account.receipt_trust().clone(),
    );
    assert_eq!(
        creditor_account.mint_obligation_iou_v2(
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeMintContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                credit_facility_bind: &fixture.credit_facility_bind,
                issuer_id: "economy.credit.issuer",
                issuer_key_epoch: 7,
                trusted_issued_at_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"))
    );

    let signed = mint(&fixture)?;
    let mut value = serde_json::to_value(signed)?;
    let backend = Ed25519Backend::new(fixture.creditor_signer.clone());
    value["body"]["issuerId"] = serde_json::json!("economy.credit.issuer");
    let (signature, _) = sign_canonical_with_backend(&backend, &value["body"])?;
    value["signerKey"] = serde_json::to_value(backend.public_key())?;
    value["algorithm"] = serde_json::to_value(backend.algorithm())?;
    value["signature"] = serde_json::to_value(signature)?;
    let canonical = canonical_json_bytes(&value)?;
    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        backend.public_key(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    assert_eq!(
        verify_iou_envelope_v2(
            &canonical,
            &fixture.credit_admission_store.adapter(),
            &IouEnvelopeVerificationContextV2 {
                atom: &fixture.atom,
                disposition: &fixture.disposition,
                settlement_lifecycle: &fixture.settlement_lifecycle,
                receipt: &fixture.receipt,
                receipt_trust: fixture.account.receipt_trust(),
                credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                issuer_trust: &issuer_trust,
                trusted_now_unix_ms: IOU_ISSUED_AT_MS,
            },
        ),
        Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"))
    );
    Ok(())
}

#[test]
fn v2_rejects_missing_or_mismatched_receipt_request_id() -> TestResult {
    let fixture = fixture(CREDITOR_ID, SettlementStatus::Pending)?;
    let canonical = mint(&fixture)?.canonical_bytes()?;
    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        "economy.credit.issuer".to_owned(),
        7,
        fixture.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;

    for request_id in [None, Some("request-credit-replay")] {
        let (receipt, atom, disposition, settlement_lifecycle) =
            replace_receipt_request_id(&fixture, request_id)?;
        assert_eq!(
            fixture.account.mint_obligation_iou_v2(
                &fixture.credit_admission_store.adapter(),
                &IouEnvelopeMintContextV2 {
                    atom: &atom,
                    disposition: &disposition,
                    settlement_lifecycle: &settlement_lifecycle,
                    receipt: &receipt,
                    credit_facility_bind: &fixture.credit_facility_bind,
                    issuer_id: "economy.credit.issuer",
                    issuer_key_epoch: 7,
                    trusted_issued_at_unix_ms: IOU_ISSUED_AT_MS,
                },
            ),
            Err(IouEnvelopeV2Error::BindingMismatch("request_id"))
        );
        assert_eq!(
            verify_iou_envelope_v2(
                &canonical,
                &fixture.credit_admission_store.adapter(),
                &IouEnvelopeVerificationContextV2 {
                    atom: &atom,
                    disposition: &disposition,
                    settlement_lifecycle: &settlement_lifecycle,
                    receipt: &receipt,
                    receipt_trust: fixture.account.receipt_trust(),
                    credit_facility_bind_trust: &fixture.credit_facility_bind_trust,
                    issuer_trust: &issuer_trust,
                    trusted_now_unix_ms: IOU_ISSUED_AT_MS,
                },
            ),
            Err(IouEnvelopeV2Error::BindingMismatch("request_id"))
        );
    }
    Ok(())
}
