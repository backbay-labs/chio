#![allow(dead_code)]

#[path = "../support/credit_admission.rs"]
mod credit_admission_support;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Ed25519Backend, Keypair, PublicKey};
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
use chio_credit::factor::{
    verify_receivable_claim, ReceivableClaimInputV1, ReceivableClaimTrustV1, ReceivableClaimV1,
    ReceivableClaimVerificationV1, VerifiedReceivableClaimV1,
};
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, verify_obligation_status_proof,
    CreditFacilityBindTrustV1, ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1,
    ObligationDispositionRecordV1, ObligationSettlementLifecycleV1, ObligationStatusProofBodyV1,
    ObligationStatusProofContextV1, ObligationStatusProofTrustV1,
    ObligationStatusProofVerificationContextV1, SignedObligationStatusProofV1,
    VerifiedObligationStatusProofV1,
};
use chio_credit::{
    CreditEvaluatorHook, IouEnvelopeCryptoFloorV2, IouEnvelopeIssuerTrustV2,
    IouEnvelopeMintContextV2, IouEnvelopeReceiptTrustV2, LocalCreditAccount,
};
use credit_admission_support::{
    CreditAdmissionInput, PreparedCreditAdmission, TestCreditAdmissionStore,
};

pub const DEBTOR_ID: &str = "did:chio:debtor";
pub const SELLER_ID: &str = "did:chio:seller";
pub const SELLER_DESTINATION: &str = "acct:seller";
pub const RESULT_AUTHORITY_ID: &str = "obligor-disposition-authority";
pub const RESULT_AUTHORITY_EPOCH: u64 = 3;
pub const SNAPSHOT_VERSION: u64 = 7;
pub const RESOURCE_FENCE: u64 = 11;
pub const ATOM_CREATED_AT: u64 = 1_000;
pub const STATUS_ISSUED_AT: u64 = 1_010;
pub const CLAIM_BUILT_AT: u64 = 1_020;
pub const TRUSTED_NOW: u64 = 1_050;
pub const STATUS_EXPIRES_AT: u64 = 1_600;
pub const DUE_AT: u64 = 10_000;
pub const IOU_ISSUER_ID: &str = "economy.credit.issuer";
pub const IOU_ISSUER_EPOCH: u64 = 7;
pub const CREDIT_AUTHORITY_ID: &str = "economy.credit.facility-authority";
pub const CREDIT_AUTHORITY_EPOCH: u64 = 3;
pub const DEBTOR_KEY_EPOCH: u64 = 5;
pub const CREDITOR_KEY_EPOCH: u64 = 7;

pub type SupportResult<T> = Result<T, Box<dyn std::error::Error>>;

pub struct ClaimEvidence {
    pub atom: ObligationAtomV1,
    pub disposition: ObligationDispositionRecordV1,
    pub settlement_lifecycle: ObligationSettlementLifecycleV1,
    pub status_proof: VerifiedObligationStatusProofV1,
    pub verified_claim: VerifiedReceivableClaimV1,
    pub trust: ReceivableClaimTrustV1,
    pub credit_facility_bind_trust: CreditFacilityBindTrustV1,
    pub credit_admission_store: TestCreditAdmissionStore,
    pub receipt: ChioReceipt,
    pub result_signer: Keypair,
    pub kernel_key: PublicKey,
    pub issuer_key: PublicKey,
    pub credit_authority_key: PublicKey,
    pub debtor_key: PublicKey,
    pub creditor_key: PublicKey,
    pub claim_bytes: Vec<u8>,
    pub receipt_bytes: Vec<u8>,
    pub iou_bytes: Vec<u8>,
    pub legacy_iou_bytes: Vec<u8>,
}

pub fn build_claim_evidence() -> SupportResult<ClaimEvidence> {
    let kernel = Keypair::from_seed(&[111; 32]);
    let kernel_key = kernel.public_key();
    let payee_binding_digest =
        derive_obligation_payee_binding_digest(SELLER_ID, SELLER_DESTINATION)?;
    let credit_authority = Keypair::from_seed(&[117; 32]);
    let debtor = Keypair::from_seed(&[118; 32]);
    let creditor = Keypair::from_seed(&[119; 32]);
    let prepared_credit = PreparedCreditAdmission::new(CreditAdmissionInput {
        operation_id: &digest("factor-result-operation"),
        request_id: "factor-result-request",
        action_nonce: "factor-result-credit-action",
        economic_intent_digest: &digest("factor-result-intent"),
        facility_id: "facility:working-capital",
        debtor_id: DEBTOR_ID,
        original_creditor_id: SELLER_ID,
        original_settlement_destination_ref: SELLER_DESTINATION,
        capability_id: "factor-result-capability",
        tool_server: "tools.seller.example",
        tool_name: "priced_call",
        amount: amount(),
        expected_exposure_version: 1,
        due_at_unix_ms: DUE_AT,
        bind_issued_at_unix_ms: 900,
        bind_expires_at_unix_ms: 1_500,
        trusted_at_unix_ms: ATOM_CREATED_AT,
        bind_authority_id: CREDIT_AUTHORITY_ID,
        bind_authority_epoch: CREDIT_AUTHORITY_EPOCH,
        debtor_key_epoch: DEBTOR_KEY_EPOCH,
        creditor_key_epoch: CREDITOR_KEY_EPOCH,
        bind_authority: &credit_authority,
        debtor: &debtor,
        creditor: &creditor,
    })?;
    let credit_facility_bind = prepared_credit.credit_facility_bind().clone();
    let credit_facility_bind_trust = prepared_credit.bind_trust().clone();
    let receipt = signed_receipt(
        &kernel,
        &payee_binding_digest,
        credit_facility_bind.artifact_digest(),
    )?;
    let receipt_bytes = canonical_json_bytes(&receipt)?;
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: digest("factor-result-intent"),
        source_receipt_id: receipt.id.clone(),
        source_receipt_digest: sha256_hex(&receipt_bytes),
        debtor_id: DEBTOR_ID.to_owned(),
        original_creditor_id: SELLER_ID.to_owned(),
        original_settlement_destination_ref: SELLER_DESTINATION.to_owned(),
        payee_binding_digest,
        amount: amount(),
        credit_election: ObligationCreditElectionV1::CreditFacility {
            facility_id: "facility:working-capital".to_owned(),
            authority_digest: credit_facility_bind.artifact_digest().to_owned(),
        },
        pre_action_authority_digest: digest("factor-result-pre-action-authority"),
        created_at_unix_ms: ATOM_CREATED_AT,
        due_at_unix_ms: DUE_AT,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?;
    let settlement_lifecycle = ObligationSettlementLifecycleV1::pending(&atom)?;
    let credit_admission_store =
        TestCreditAdmissionStore::committed(prepared_credit.committed_record(&atom)?);
    let result_signer = Keypair::from_seed(&[101; 32]);
    let status_trust = ObligationStatusProofTrustV1::new(
        RESULT_AUTHORITY_ID.to_owned(),
        result_signer.public_key(),
        RESULT_AUTHORITY_EPOCH,
        600,
    )?;
    let signed_status = SignedObligationStatusProofV1::sign(
        ObligationStatusProofBodyV1::new(&ObligationStatusProofContextV1 {
            atom: &atom,
            disposition: &disposition,
            settlement_lifecycle: &settlement_lifecycle,
            snapshot_version: SNAPSHOT_VERSION,
            resource_fence: RESOURCE_FENCE,
            issued_at_unix_ms: STATUS_ISSUED_AT,
            expires_at_unix_ms: STATUS_EXPIRES_AT,
            authority_id: RESULT_AUTHORITY_ID,
            authority_key_epoch: RESULT_AUTHORITY_EPOCH,
        })?,
        &result_signer,
    )?;
    let status_bytes = signed_status.canonical_bytes()?;
    let status_proof = verify_obligation_status_proof(
        &status_bytes,
        &ObligationStatusProofVerificationContextV1 {
            atom: &atom,
            disposition: &disposition,
            settlement_lifecycle: &settlement_lifecycle,
            snapshot_version: SNAPSHOT_VERSION,
            resource_fence: RESOURCE_FENCE,
            trust: &status_trust,
            trusted_now_unix_ms: TRUSTED_NOW,
        },
    )?;
    let receipt_trust =
        IouEnvelopeReceiptTrustV2::new([kernel_key.clone()], ReceiptCryptoFloor::AllowClassical);
    let issuer = Keypair::from_seed(&[112; 32]);
    let issuer_key = issuer.public_key();
    let account = LocalCreditAccount::new_with_receipt_trust(
        Ed25519Backend::new(issuer),
        receipt_trust.clone(),
    );
    let signed_iou = account.mint_obligation_iou_v2(
        &credit_admission_store.adapter(),
        &IouEnvelopeMintContextV2 {
            atom: &atom,
            disposition: &disposition,
            settlement_lifecycle: &settlement_lifecycle,
            receipt: &receipt,
            credit_facility_bind: &credit_facility_bind,
            issuer_id: IOU_ISSUER_ID,
            issuer_key_epoch: IOU_ISSUER_EPOCH,
            trusted_issued_at_unix_ms: ATOM_CREATED_AT,
        },
    )?;
    let iou_bytes = signed_iou.canonical_bytes()?;
    let legacy_iou =
        account
            .evaluate(&receipt)?
            .ok_or(chio_credit::factor::FactorError::InvalidField(
                "legacy_iou_fixture",
            ))?;
    let legacy_iou_bytes = canonical_json_bytes(&legacy_iou)?;
    let claim = ReceivableClaimV1::new(ReceivableClaimInputV1 {
        obligation_id: atom.obligation_id().to_owned(),
        obligation_atom_digest: atom.digest()?,
        seller_id: SELLER_ID.to_owned(),
        receipt_id: receipt.id.clone(),
        receipt_digest: sha256_hex(&receipt_bytes),
        iou_id: signed_iou.body().iou_id().to_owned(),
        iou_digest: sha256_hex(&iou_bytes),
        payee_binding_digest: atom.payee_binding_digest().to_owned(),
        status_proof_digest: status_proof.envelope_digest().to_owned(),
        face_value: atom.amount().clone(),
        due_at_unix_ms: atom.due_at_unix_ms(),
        built_at_unix_ms: CLAIM_BUILT_AT,
    })?;
    let claim_bytes = claim.canonical_bytes()?;
    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let trust = ReceivableClaimTrustV1::new(
        &status_trust,
        receipt_trust,
        [issuer_trust],
        [credit_facility_bind_trust.clone()],
    )?;
    let verified_claim = verify_receivable_claim(
        &claim_bytes,
        &receipt_bytes,
        &iou_bytes,
        &credit_admission_store.adapter(),
        &ReceivableClaimVerificationV1 {
            atom: &atom,
            disposition: &disposition,
            settlement_lifecycle: &settlement_lifecycle,
            status_proof: &status_proof,
            trusted_now_unix_ms: TRUSTED_NOW,
            trust: &trust,
        },
    )?;
    Ok(ClaimEvidence {
        atom,
        disposition,
        settlement_lifecycle,
        status_proof,
        verified_claim,
        trust,
        credit_facility_bind_trust,
        credit_admission_store,
        receipt,
        result_signer,
        kernel_key,
        issuer_key,
        credit_authority_key: credit_authority.public_key(),
        debtor_key: debtor.public_key(),
        creditor_key: creditor.public_key(),
        claim_bytes,
        receipt_bytes,
        iou_bytes,
        legacy_iou_bytes,
    })
}

fn signed_receipt(
    kernel: &Keypair,
    payee_binding_digest: &str,
    credit_authority_digest: &str,
) -> Result<ChioReceipt, chio_core_types::Error> {
    let governed = GovernedTransactionReceiptMetadata {
        intent_id: "factor-result-intent".to_owned(),
        intent_hash: digest("factor-result-intent"),
        purpose: "deferred supplier payment".to_owned(),
        server_id: "tools.seller.example".to_owned(),
        tool_name: "priced_call".to_owned(),
        max_amount: Some(amount()),
        commerce: None,
        metered_billing: None,
        approval: Some(GovernedApprovalReceiptMetadata {
            token_id: "factor-result-approval".to_owned(),
            approver_key: "factor-result-approver".to_owned(),
            approval_artifact_digest: Some(digest("factor-result-pre-action-authority")),
            approved: true,
        }),
        runtime_assurance: None,
        call_chain: None,
        autonomy: None,
        economic_authorization: Some(economic_authorization(
            payee_binding_digest,
            credit_authority_digest,
        )),
    };
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "factor-result-receipt-placeholder".to_owned(),
            timestamp: 1,
            capability_id: "factor-result-capability".to_owned(),
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
            content_hash: digest("factor-result-output"),
            policy_hash: digest("factor-result-policy"),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "financial": financial_metadata(),
                "governed_transaction": governed,
                "receipt_context": {
                    "request_id": "factor-result-request",
                },
            })),
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-a".to_owned()),
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        kernel,
    )
}

fn financial_metadata() -> FinancialReceiptMetadata {
    FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 500,
        currency: "USD".to_owned(),
        budget_remaining: 500,
        budget_total: 1_000,
        delegation_depth: 1,
        root_budget_holder: DEBTOR_ID.to_owned(),
        payment_reference: None,
        settlement_status: SettlementStatus::Pending,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    }
}

fn economic_authorization(
    payee_binding_digest: &str,
    credit_authority_digest: &str,
) -> EconomicAuthorizationReceiptMetadata {
    EconomicAuthorizationReceiptMetadata {
        version: EconomicAuthorizationReceiptMetadataVersion::V1,
        economic_intent_digest: Some(digest("factor-result-intent")),
        payee_binding_digest: Some(payee_binding_digest.to_owned()),
        pre_action_authority_digest: Some(digest("factor-result-pre-action-authority")),
        credit_authority_digest: Some(credit_authority_digest.to_owned()),
        economic_mode: EconomicAuthorizationMode::BudgetOnly,
        payer: EconomicPayerReceiptMetadata {
            party_id: DEBTOR_ID.to_owned(),
            funding_source_ref: "facility:working-capital".to_owned(),
            custody_provider: None,
            obligor_ref: None,
        },
        merchant: EconomicMerchantReceiptMetadata {
            merchant_id: SELLER_ID.to_owned(),
            merchant_of_record: None,
            order_ref: Some("factor-result-order".to_owned()),
        },
        payee: EconomicPayeeReceiptMetadata {
            beneficiary_id: SELLER_ID.to_owned(),
            settlement_destination_ref: SELLER_DESTINATION.to_owned(),
        },
        rail: EconomicRailReceiptMetadata {
            kind: "credit_facility".to_owned(),
            asset: "USD".to_owned(),
            network: None,
            facilitator: None,
            contract_or_account_ref: Some("facility:working-capital".to_owned()),
        },
        amount_bounds: EconomicAmountBoundsReceiptMetadata {
            approved_max: amount(),
            hold_amount: None,
            settlement_cap: amount(),
        },
        pricing_basis: None,
        metering: None,
        liability_refs: None,
        budget: EconomicBudgetReceiptMetadata {
            grant_index: 0,
            cost_charged: 500,
            currency: "USD".to_owned(),
            budget_remaining: 500,
            budget_total: 1_000,
            delegation_depth: 1,
            root_budget_holder: DEBTOR_ID.to_owned(),
            attempted_cost: None,
        },
        settlement: EconomicSettlementReceiptMetadata {
            settlement_status: SettlementStatus::Pending,
        },
    }
}

fn amount() -> MonetaryAmount {
    MonetaryAmount {
        units: 500,
        currency: "USD".to_owned(),
    }
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}
