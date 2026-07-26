use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{
    sha256_hex, sign_canonical_with_backend, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core_types::receipt::economics::{
    EconomicAuthorizationReceiptMetadata, FinancialReceiptMetadata, SettlementStatus,
};
pub use chio_core_types::CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::obligation::{
    derive_obligation_payee_binding_digest, verify_credit_facility_bind, CreditAdmissionStore,
    CreditAdmissionStoreAdapter, CreditFacilityBindTrustV1,
    CreditFacilityBindVerificationContextV1, ObligationAtomV1, ObligationCreditElectionV1,
    ObligationDispositionRecordV1, ObligationDispositionV1, ObligationSettlementLifecycleV1,
    ObligationSettlementStateV1, SignedCreditFacilityBindV1, VerifiedCreditFacilityBindV1,
};

pub const RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA: &str = CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA;

const IOU_ID_DOMAIN: &[u8] = b"chio.credit.receivable-iou-envelope.id.v1\0";
const IOU_BODY_DIGEST_DOMAIN: &[u8] = b"chio.credit.receivable-iou-envelope.body.v1\0";
const MAX_TEXT_CHARS: usize = 2_048;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IouEnvelopeV2Error {
    #[error("invalid v2 iou field '{0}'")]
    InvalidField(&'static str),
    #[error("v2 iou source binding does not match: {0}")]
    BindingMismatch(&'static str),
    #[error("v2 iou source is not credit eligible: {0}")]
    NotEligible(&'static str),
    #[error("v2 iou receipt verification failed")]
    ReceiptVerification,
    #[error("v2 iou receipt signer is not trusted")]
    ReceiptSignerUntrusted,
    #[error("v2 iou credit authority verification failed")]
    CreditAuthorityVerification,
    #[error("v2 iou committed credit admission verification failed")]
    CreditAdmissionVerification,
    #[error("v2 iou issuer verification failed")]
    IssuerVerification,
    #[error("v2 iou canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("v2 iou signing failed: {0}")]
    Signing(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IouEnvelopeCryptoFloorV2 {
    AllowClassical,
    AllowHybrid,
    PqRequired,
}

impl IouEnvelopeCryptoFloorV2 {
    #[must_use]
    pub const fn allows(self, algorithm: SigningAlgorithm) -> bool {
        match self {
            Self::AllowClassical => !matches!(algorithm, SigningAlgorithm::Hybrid),
            Self::AllowHybrid => true,
            Self::PqRequired => matches!(algorithm, SigningAlgorithm::Hybrid),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowClassical => "allow_classical",
            Self::AllowHybrid => "allow_hybrid",
            Self::PqRequired => "pq_required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IouEnvelopeReceiptTrustV2 {
    trusted_kernel_key_hexes: Vec<String>,
    crypto_floor: ReceiptCryptoFloor,
}

impl IouEnvelopeReceiptTrustV2 {
    #[must_use]
    pub fn new<I>(trusted_kernel_keys: I, crypto_floor: ReceiptCryptoFloor) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let mut trusted_kernel_key_hexes: Vec<_> = trusted_kernel_keys
            .into_iter()
            .map(|key| key.to_hex())
            .collect();
        trusted_kernel_key_hexes.sort_unstable();
        trusted_kernel_key_hexes.dedup();
        Self {
            trusted_kernel_key_hexes,
            crypto_floor,
        }
    }

    #[must_use]
    pub fn trusted_kernel_key_hexes(&self) -> &[String] {
        &self.trusted_kernel_key_hexes
    }

    #[must_use]
    pub const fn crypto_floor(&self) -> ReceiptCryptoFloor {
        self.crypto_floor
    }

    pub(crate) fn contains(&self, key: &PublicKey) -> bool {
        self.trusted_kernel_key_hexes
            .binary_search(&key.to_hex())
            .is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IouEnvelopeIssuerTrustV2 {
    issuer_id: String,
    issuer_key_epoch: u64,
    issuer_key: PublicKey,
    crypto_floor: IouEnvelopeCryptoFloorV2,
}

impl IouEnvelopeIssuerTrustV2 {
    pub fn new(
        issuer_id: String,
        issuer_key_epoch: u64,
        issuer_key: PublicKey,
        crypto_floor: IouEnvelopeCryptoFloorV2,
    ) -> Result<Self, IouEnvelopeV2Error> {
        validate_text("trusted_issuer_id", &issuer_id)?;
        validate_positive("trusted_issuer_key_epoch", issuer_key_epoch)?;
        Ok(Self {
            issuer_id,
            issuer_key_epoch,
            issuer_key,
            crypto_floor,
        })
    }

    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    #[must_use]
    pub const fn issuer_key_epoch(&self) -> u64 {
        self.issuer_key_epoch
    }

    #[must_use]
    pub const fn issuer_key(&self) -> &PublicKey {
        &self.issuer_key
    }

    #[must_use]
    pub const fn crypto_floor(&self) -> IouEnvelopeCryptoFloorV2 {
        self.crypto_floor
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IouEnvelopeBodyV2 {
    schema: String,
    iou_id: String,
    operation_id: String,
    obligation_id: String,
    obligation_atom_digest: String,
    receipt_id: String,
    receipt_digest: String,
    receipt_timestamp_unix_seconds: u64,
    issued_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    tool_server: String,
    tool_name: String,
    capability_id: String,
    receipt_content_hash: String,
    receipt_policy_hash: String,
    debtor_id: String,
    original_creditor_id: String,
    original_settlement_destination_ref: String,
    payee_binding_digest: String,
    amount: MonetaryAmount,
    current_disposition_digest: String,
    due_at_unix_ms: u64,
    facility_id: String,
    credit_authority_digest: String,
    credit_facility_bind: SignedCreditFacilityBindV1,
    issuer_id: String,
    issuer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IouIdPreimage<'a> {
    schema: &'a str,
    operation_id: &'a str,
    obligation_id: &'a str,
    obligation_atom_digest: &'a str,
    receipt_digest: &'a str,
}

impl IouEnvelopeBodyV2 {
    fn validate(&self) -> Result<(), IouEnvelopeV2Error> {
        if self.schema != RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA {
            return Err(IouEnvelopeV2Error::InvalidField("schema"));
        }
        for (field, value) in [
            ("iou_id", &self.iou_id),
            ("operation_id", &self.operation_id),
            ("obligation_id", &self.obligation_id),
            ("obligation_atom_digest", &self.obligation_atom_digest),
            ("receipt_digest", &self.receipt_digest),
            ("receipt_content_hash", &self.receipt_content_hash),
            ("receipt_policy_hash", &self.receipt_policy_hash),
            ("payee_binding_digest", &self.payee_binding_digest),
            (
                "current_disposition_digest",
                &self.current_disposition_digest,
            ),
            ("credit_authority_digest", &self.credit_authority_digest),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("receipt_id", &self.receipt_id),
            ("tool_server", &self.tool_server),
            ("tool_name", &self.tool_name),
            ("capability_id", &self.capability_id),
            ("debtor_id", &self.debtor_id),
            ("original_creditor_id", &self.original_creditor_id),
            (
                "original_settlement_destination_ref",
                &self.original_settlement_destination_ref,
            ),
            ("facility_id", &self.facility_id),
            ("issuer_id", &self.issuer_id),
        ] {
            validate_text(field, value)?;
        }
        if let Some(tenant_id) = &self.tenant_id {
            validate_text("tenant_id", tenant_id)?;
        }
        if self.issuer_id == self.original_creditor_id {
            return Err(IouEnvelopeV2Error::InvalidField("issuer_identity"));
        }
        validate_amount(&self.amount)?;
        validate_positive(
            "receipt_timestamp_unix_seconds",
            self.receipt_timestamp_unix_seconds,
        )?;
        validate_positive("issued_at_unix_ms", self.issued_at_unix_ms)?;
        validate_positive("due_at_unix_ms", self.due_at_unix_ms)?;
        validate_positive("issuer_key_epoch", self.issuer_key_epoch)?;
        let credit_bind_bytes = self
            .credit_facility_bind
            .canonical_bytes()
            .map_err(|_| IouEnvelopeV2Error::InvalidField("credit_facility_bind"))?;
        let receipt_timestamp_unix_ms = self
            .receipt_timestamp_unix_seconds
            .checked_mul(1_000)
            .ok_or(IouEnvelopeV2Error::InvalidField(
                "receipt_timestamp_unix_seconds",
            ))?;
        if receipt_timestamp_unix_ms > self.issued_at_unix_ms
            || self.issued_at_unix_ms >= self.due_at_unix_ms
            || self.operation_id != self.credit_facility_bind.body().operation_id()
            || self.facility_id != self.credit_facility_bind.body().facility_id()
            || self.credit_authority_digest != sha256_hex(&credit_bind_bytes)
            || self.iou_id != self.derived_iou_id()?
        {
            return Err(IouEnvelopeV2Error::InvalidField("iou_terms"));
        }
        Ok(())
    }

    fn derived_iou_id(&self) -> Result<String, IouEnvelopeV2Error> {
        domain_digest(
            IOU_ID_DOMAIN,
            &IouIdPreimage {
                schema: &self.schema,
                operation_id: &self.operation_id,
                obligation_id: &self.obligation_id,
                obligation_atom_digest: &self.obligation_atom_digest,
                receipt_digest: &self.receipt_digest,
            },
        )
    }

    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    #[must_use]
    pub fn iou_id(&self) -> &str {
        &self.iou_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> &str {
        &self.obligation_atom_digest
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    #[must_use]
    pub const fn receipt_timestamp_unix_seconds(&self) -> u64 {
        self.receipt_timestamp_unix_seconds
    }

    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    #[must_use]
    pub fn tool_server(&self) -> &str {
        &self.tool_server
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    #[must_use]
    pub fn receipt_content_hash(&self) -> &str {
        &self.receipt_content_hash
    }

    #[must_use]
    pub fn receipt_policy_hash(&self) -> &str {
        &self.receipt_policy_hash
    }

    #[must_use]
    pub fn debtor_id(&self) -> &str {
        &self.debtor_id
    }

    #[must_use]
    pub fn original_creditor_id(&self) -> &str {
        &self.original_creditor_id
    }

    #[must_use]
    pub fn original_settlement_destination_ref(&self) -> &str {
        &self.original_settlement_destination_ref
    }

    #[must_use]
    pub fn payee_binding_digest(&self) -> &str {
        &self.payee_binding_digest
    }

    #[must_use]
    pub const fn amount(&self) -> &MonetaryAmount {
        &self.amount
    }

    #[must_use]
    pub fn current_disposition_digest(&self) -> &str {
        &self.current_disposition_digest
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }

    #[must_use]
    pub fn facility_id(&self) -> &str {
        &self.facility_id
    }

    #[must_use]
    pub fn credit_authority_digest(&self) -> &str {
        &self.credit_authority_digest
    }

    #[must_use]
    pub const fn credit_facility_bind(&self) -> &SignedCreditFacilityBindV1 {
        &self.credit_facility_bind
    }

    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    #[must_use]
    pub const fn issuer_key_epoch(&self) -> u64 {
        self.issuer_key_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedIouEnvelopeV2 {
    body: IouEnvelopeBodyV2,
    signer_key: PublicKey,
    algorithm: SigningAlgorithm,
    signature: Signature,
}

impl SignedIouEnvelopeV2 {
    fn sign_with_backend<B: SigningBackend>(
        body: IouEnvelopeBodyV2,
        backend: &B,
    ) -> Result<Self, IouEnvelopeV2Error> {
        body.validate()?;
        let (signature, _) = sign_canonical_with_backend(backend, &body)
            .map_err(|error| IouEnvelopeV2Error::Signing(error.to_string()))?;
        Ok(Self {
            body,
            signer_key: backend.public_key(),
            algorithm: backend.algorithm(),
            signature,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, IouEnvelopeV2Error> {
        let signed: Self = serde_json::from_slice(bytes)
            .map_err(|error| IouEnvelopeV2Error::Canonicalization(error.to_string()))?;
        signed.body.validate()?;
        if signed.canonical_bytes()?.as_slice() != bytes {
            return Err(IouEnvelopeV2Error::Canonicalization(
                "v2 iou envelope is not canonical".to_owned(),
            ));
        }
        Ok(signed)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IouEnvelopeV2Error> {
        self.body.validate()?;
        canonical_json_bytes(self)
            .map_err(|error| IouEnvelopeV2Error::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &IouEnvelopeBodyV2 {
        &self.body
    }

    #[must_use]
    pub const fn signer_key(&self) -> &PublicKey {
        &self.signer_key
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

pub struct IouEnvelopeMintContextV2<'a> {
    pub atom: &'a ObligationAtomV1,
    pub disposition: &'a ObligationDispositionRecordV1,
    pub settlement_lifecycle: &'a ObligationSettlementLifecycleV1,
    pub receipt: &'a ChioReceipt,
    pub credit_facility_bind: &'a VerifiedCreditFacilityBindV1,
    pub issuer_id: &'a str,
    pub issuer_key_epoch: u64,
    pub trusted_issued_at_unix_ms: u64,
}

pub struct IouEnvelopeVerificationContextV2<'a> {
    pub atom: &'a ObligationAtomV1,
    pub disposition: &'a ObligationDispositionRecordV1,
    pub settlement_lifecycle: &'a ObligationSettlementLifecycleV1,
    pub receipt: &'a ChioReceipt,
    pub receipt_trust: &'a IouEnvelopeReceiptTrustV2,
    pub credit_facility_bind_trust: &'a CreditFacilityBindTrustV1,
    pub issuer_trust: &'a IouEnvelopeIssuerTrustV2,
    pub trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIouEnvelopeV2 {
    signed: SignedIouEnvelopeV2,
    body_digest: String,
    envelope_digest: String,
    signature_digest: String,
    canonical_bytes: Vec<u8>,
    credit_facility_bind: VerifiedCreditFacilityBindV1,
}

impl VerifiedIouEnvelopeV2 {
    #[must_use]
    pub const fn body(&self) -> &IouEnvelopeBodyV2 {
        self.signed.body()
    }

    #[must_use]
    pub const fn signer_key(&self) -> &PublicKey {
        self.signed.signer_key()
    }

    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.signed.algorithm()
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    #[must_use]
    pub fn signature_digest(&self) -> &str {
        &self.signature_digest
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn credit_facility_bind(&self) -> &VerifiedCreditFacilityBindV1 {
        &self.credit_facility_bind
    }
}

pub fn verify_iou_envelope_v2<S: CreditAdmissionStore>(
    canonical_envelope: &[u8],
    credit_admission_store: &CreditAdmissionStoreAdapter<S>,
    context: &IouEnvelopeVerificationContextV2<'_>,
) -> Result<VerifiedIouEnvelopeV2, IouEnvelopeV2Error> {
    let signed = SignedIouEnvelopeV2::from_canonical_bytes(canonical_envelope)?;
    let signature_algorithm = signed.signature.algorithm();
    if signed.body.issuer_id != context.issuer_trust.issuer_id
        || signed.body.issuer_key_epoch != context.issuer_trust.issuer_key_epoch
        || signed.signer_key != context.issuer_trust.issuer_key
        || signed.algorithm != signature_algorithm
        || signed.signer_key.algorithm() != signature_algorithm
        || !context
            .issuer_trust
            .crypto_floor
            .allows(signature_algorithm)
        || !signed
            .signer_key
            .verify_canonical(&signed.body, &signed.signature)
            .map_err(|error| IouEnvelopeV2Error::Canonicalization(error.to_string()))?
    {
        return Err(IouEnvelopeV2Error::IssuerVerification);
    }
    verify_receipt(context.receipt, context.receipt_trust)?;
    if signed.signer_key == context.receipt.kernel_key {
        return Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"));
    }
    let credit_bind_bytes = signed
        .body
        .credit_facility_bind
        .canonical_bytes()
        .map_err(|_| IouEnvelopeV2Error::CreditAuthorityVerification)?;
    let credit_facility_bind = verify_credit_facility_bind(
        &credit_bind_bytes,
        &CreditFacilityBindVerificationContextV1 {
            trust: context.credit_facility_bind_trust,
            trusted_at_unix_ms: context.atom.created_at_unix_ms(),
        },
    )
    .map_err(|_| IouEnvelopeV2Error::CreditAuthorityVerification)?;
    if signed.signer_key()
        == credit_facility_bind
            .signed()
            .creditor_signature()
            .signer_key()
    {
        return Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"));
    }
    let expected = build_body(
        context.atom,
        context.disposition,
        context.settlement_lifecycle,
        context.receipt,
        &credit_facility_bind,
        context.issuer_trust.issuer_id(),
        context.issuer_trust.issuer_key_epoch(),
        signed.body.issued_at_unix_ms,
    )?;
    if signed.body != expected || signed.body.issued_at_unix_ms > context.trusted_now_unix_ms {
        return Err(IouEnvelopeV2Error::BindingMismatch("signed_body"));
    }
    require_committed_credit_admission(
        credit_admission_store,
        context.atom,
        &credit_facility_bind,
    )?;
    Ok(VerifiedIouEnvelopeV2 {
        body_digest: domain_digest(IOU_BODY_DIGEST_DOMAIN, &signed.body)?,
        envelope_digest: sha256_hex(canonical_envelope),
        signature_digest: sha256_hex(signed.signature.to_hex().as_bytes()),
        canonical_bytes: canonical_envelope.to_vec(),
        credit_facility_bind,
        signed,
    })
}

pub(crate) fn mint_iou_envelope_v2<B: SigningBackend, S: CreditAdmissionStore>(
    backend: &B,
    receipt_trust: &IouEnvelopeReceiptTrustV2,
    credit_admission_store: &CreditAdmissionStoreAdapter<S>,
    context: &IouEnvelopeMintContextV2<'_>,
) -> Result<SignedIouEnvelopeV2, IouEnvelopeV2Error> {
    verify_receipt(context.receipt, receipt_trust)?;
    if backend.public_key() == context.receipt.kernel_key {
        return Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"));
    }
    if &backend.public_key()
        == context
            .credit_facility_bind
            .signed()
            .creditor_signature()
            .signer_key()
    {
        return Err(IouEnvelopeV2Error::InvalidField("issuer_key_role"));
    }
    let body = build_body(
        context.atom,
        context.disposition,
        context.settlement_lifecycle,
        context.receipt,
        context.credit_facility_bind,
        context.issuer_id,
        context.issuer_key_epoch,
        context.trusted_issued_at_unix_ms,
    )?;
    require_committed_credit_admission(
        credit_admission_store,
        context.atom,
        context.credit_facility_bind,
    )?;
    SignedIouEnvelopeV2::sign_with_backend(body, backend)
}

fn require_committed_credit_admission<S: CreditAdmissionStore>(
    credit_admission_store: &CreditAdmissionStoreAdapter<S>,
    atom: &ObligationAtomV1,
    credit_facility_bind: &VerifiedCreditFacilityBindV1,
) -> Result<(), IouEnvelopeV2Error> {
    let admission = credit_admission_store
        .lookup_committed_by_operation(credit_facility_bind.body().operation_id())
        .map_err(|_| IouEnvelopeV2Error::CreditAdmissionVerification)?
        .ok_or(IouEnvelopeV2Error::CreditAdmissionVerification)?;
    admission
        .validate_committed_binding(atom, credit_facility_bind)
        .map_err(|_| IouEnvelopeV2Error::BindingMismatch("committed_credit_admission"))
}

#[allow(clippy::too_many_arguments)]
fn build_body(
    atom: &ObligationAtomV1,
    disposition: &ObligationDispositionRecordV1,
    settlement_lifecycle: &ObligationSettlementLifecycleV1,
    receipt: &ChioReceipt,
    credit_facility_bind: &VerifiedCreditFacilityBindV1,
    issuer_id: &str,
    issuer_key_epoch: u64,
    issued_at_unix_ms: u64,
) -> Result<IouEnvelopeBodyV2, IouEnvelopeV2Error> {
    atom.validate()
        .map_err(|_| IouEnvelopeV2Error::BindingMismatch("obligation_atom"))?;
    disposition
        .validate_against(atom)
        .map_err(|_| IouEnvelopeV2Error::BindingMismatch("obligation_disposition"))?;
    settlement_lifecycle
        .validate_against(atom)
        .map_err(|_| IouEnvelopeV2Error::BindingMismatch("settlement_lifecycle"))?;
    let (facility_id, credit_authority_digest) = match atom.credit_election() {
        ObligationCreditElectionV1::CreditFacility {
            facility_id,
            authority_digest,
        } => (facility_id.clone(), authority_digest.clone()),
        ObligationCreditElectionV1::NotCredit => {
            return Err(IouEnvelopeV2Error::NotEligible("credit_election"));
        }
    };
    credit_facility_bind
        .ensure_current_at(atom.created_at_unix_ms())
        .map_err(|_| IouEnvelopeV2Error::CreditAuthorityVerification)?;
    let bind = credit_facility_bind.body();
    if credit_facility_bind.artifact_digest() != credit_authority_digest
        || bind.economic_intent_digest() != atom.economic_intent_digest()
        || bind.facility_id() != facility_id
        || bind.debtor_id() != atom.debtor_id()
        || bind.original_creditor_id() != atom.original_creditor_id()
        || bind.original_settlement_destination_ref() != atom.original_settlement_destination_ref()
        || bind.payee_binding_digest() != atom.payee_binding_digest()
        || bind.amount() != atom.amount()
        || bind.due_at_unix_ms() != atom.due_at_unix_ms()
        || bind.capability_id() != receipt.capability_id
        || bind.tool_server() != receipt.tool_server
        || bind.tool_name() != receipt.tool_name
    {
        return Err(IouEnvelopeV2Error::BindingMismatch("credit_facility_bind"));
    }
    if receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer("/receipt_context/request_id"))
        .and_then(serde_json::Value::as_str)
        != Some(bind.request_id())
    {
        return Err(IouEnvelopeV2Error::BindingMismatch("request_id"));
    }
    if !matches!(disposition.disposition(), ObligationDispositionV1::PerCall) {
        return Err(IouEnvelopeV2Error::NotEligible("disposition"));
    }
    if !matches!(
        settlement_lifecycle.state(),
        ObligationSettlementStateV1::Pending
    ) {
        return Err(IouEnvelopeV2Error::NotEligible("settlement_lifecycle"));
    }
    let receipt_digest = sha256_hex(
        &canonical_json_bytes(receipt)
            .map_err(|error| IouEnvelopeV2Error::Canonicalization(error.to_string()))?,
    );
    if receipt.id != atom.source_receipt_id() || receipt_digest != atom.source_receipt_digest() {
        return Err(IouEnvelopeV2Error::BindingMismatch("source_receipt"));
    }
    let financial = receipt
        .financial_metadata()
        .ok_or(IouEnvelopeV2Error::NotEligible("financial_metadata"))?;
    let economic = economic_authorization(receipt)?;
    validate_economics(
        atom,
        receipt,
        &financial,
        &economic,
        &facility_id,
        credit_facility_bind.artifact_digest(),
    )?;
    let receipt_timestamp_unix_ms =
        receipt
            .timestamp
            .checked_mul(1_000)
            .ok_or(IouEnvelopeV2Error::InvalidField(
                "receipt_timestamp_unix_seconds",
            ))?;
    if receipt_timestamp_unix_ms < bind.issued_at_unix_ms()
        || receipt_timestamp_unix_ms > atom.created_at_unix_ms()
        || atom.created_at_unix_ms() > issued_at_unix_ms
        || issued_at_unix_ms >= atom.due_at_unix_ms()
    {
        return Err(IouEnvelopeV2Error::BindingMismatch("issuance_time"));
    }
    validate_text("issuer_id", issuer_id)?;
    validate_positive("issuer_key_epoch", issuer_key_epoch)?;
    let mut body = IouEnvelopeBodyV2 {
        schema: RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA.to_owned(),
        iou_id: String::new(),
        operation_id: bind.operation_id().to_owned(),
        obligation_id: atom.obligation_id().to_owned(),
        obligation_atom_digest: atom
            .digest()
            .map_err(|_| IouEnvelopeV2Error::BindingMismatch("obligation_atom_digest"))?,
        receipt_id: receipt.id.clone(),
        receipt_digest,
        receipt_timestamp_unix_seconds: receipt.timestamp,
        issued_at_unix_ms,
        tenant_id: receipt.tenant_id.clone(),
        tool_server: receipt.tool_server.clone(),
        tool_name: receipt.tool_name.clone(),
        capability_id: receipt.capability_id.clone(),
        receipt_content_hash: receipt.content_hash.clone(),
        receipt_policy_hash: receipt.policy_hash.clone(),
        debtor_id: atom.debtor_id().to_owned(),
        original_creditor_id: atom.original_creditor_id().to_owned(),
        original_settlement_destination_ref: atom.original_settlement_destination_ref().to_owned(),
        payee_binding_digest: atom.payee_binding_digest().to_owned(),
        amount: atom.amount().clone(),
        current_disposition_digest: disposition
            .digest(atom)
            .map_err(|_| IouEnvelopeV2Error::BindingMismatch("disposition_digest"))?,
        due_at_unix_ms: atom.due_at_unix_ms(),
        facility_id,
        credit_authority_digest,
        credit_facility_bind: credit_facility_bind.signed().clone(),
        issuer_id: issuer_id.to_owned(),
        issuer_key_epoch,
    };
    body.iou_id = body.derived_iou_id()?;
    body.validate()?;
    Ok(body)
}

fn verify_receipt(
    receipt: &ChioReceipt,
    trust: &IouEnvelopeReceiptTrustV2,
) -> Result<(), IouEnvelopeV2Error> {
    if !trust.contains(&receipt.kernel_key) {
        return Err(IouEnvelopeV2Error::ReceiptSignerUntrusted);
    }
    if !receipt
        .verify_signature_with_floor(trust.crypto_floor)
        .map_err(|_| IouEnvelopeV2Error::ReceiptVerification)?
    {
        return Err(IouEnvelopeV2Error::ReceiptVerification);
    }
    if !receipt
        .action
        .verify_hash()
        .map_err(|_| IouEnvelopeV2Error::ReceiptVerification)?
        || !receipt.is_allowed()
    {
        return Err(IouEnvelopeV2Error::ReceiptVerification);
    }
    Ok(())
}

fn economic_authorization(
    receipt: &ChioReceipt,
) -> Result<EconomicAuthorizationReceiptMetadata, IouEnvelopeV2Error> {
    let governed = receipt
        .governed_transaction_metadata()
        .ok_or(IouEnvelopeV2Error::NotEligible("economic_authorization"))?;
    let approval_artifact_digest = governed
        .approval
        .as_ref()
        .filter(|approval| approval.approved)
        .and_then(|approval| approval.approval_artifact_digest.clone())
        .ok_or(IouEnvelopeV2Error::BindingMismatch("governed_transaction"))?;
    if governed.server_id != receipt.tool_server || governed.tool_name != receipt.tool_name {
        return Err(IouEnvelopeV2Error::BindingMismatch("governed_transaction"));
    }
    let economic = governed
        .economic_authorization
        .ok_or(IouEnvelopeV2Error::NotEligible("economic_authorization"))?;
    if economic.economic_intent_digest.as_deref() != Some(governed.intent_hash.as_str())
        || economic.pre_action_authority_digest.as_deref()
            != Some(approval_artifact_digest.as_str())
    {
        return Err(IouEnvelopeV2Error::BindingMismatch("economic_intent"));
    }
    Ok(economic)
}

fn validate_economics(
    atom: &ObligationAtomV1,
    receipt: &ChioReceipt,
    financial: &FinancialReceiptMetadata,
    economic: &EconomicAuthorizationReceiptMetadata,
    facility_id: &str,
    credit_authority_digest: &str,
) -> Result<(), IouEnvelopeV2Error> {
    if financial.cost_charged == 0
        || financial.settlement_status != SettlementStatus::Pending
        || economic.settlement.settlement_status != SettlementStatus::Pending
    {
        return Err(IouEnvelopeV2Error::NotEligible("settlement_status"));
    }
    let amount = atom.amount();
    if financial.cost_charged != amount.units
        || financial.currency != amount.currency
        || economic.budget.cost_charged != amount.units
        || economic.budget.currency != amount.currency
        || economic.rail.asset != amount.currency
        || economic.economic_intent_digest.as_deref() != Some(atom.economic_intent_digest())
        || economic.payee_binding_digest.as_deref() != Some(atom.payee_binding_digest())
        || economic.pre_action_authority_digest.as_deref()
            != Some(atom.pre_action_authority_digest())
        || economic.credit_authority_digest.as_deref() != Some(credit_authority_digest)
        || economic.payer.funding_source_ref != facility_id
        || economic.rail.kind != "credit_facility"
        || economic.rail.contract_or_account_ref.as_deref() != Some(facility_id)
        || economic.payer.party_id != atom.debtor_id()
        || economic.payee.beneficiary_id != atom.original_creditor_id()
        || economic.payee.settlement_destination_ref != atom.original_settlement_destination_ref()
        || economic.amount_bounds.approved_max.currency != amount.currency
        || economic.amount_bounds.settlement_cap.currency != amount.currency
        || economic.amount_bounds.approved_max.units < amount.units
        || economic.amount_bounds.settlement_cap.units < amount.units
        || financial.grant_index != economic.budget.grant_index
        || financial.budget_remaining != economic.budget.budget_remaining
        || financial.budget_total != economic.budget.budget_total
        || financial.delegation_depth != economic.budget.delegation_depth
        || financial.root_budget_holder != economic.budget.root_budget_holder
        || economic.budget.root_budget_holder != atom.debtor_id()
    {
        return Err(IouEnvelopeV2Error::BindingMismatch("economic_terms"));
    }
    if economic
        .amount_bounds
        .hold_amount
        .as_ref()
        .is_some_and(|hold| hold.currency != amount.currency || hold.units < amount.units)
    {
        return Err(IouEnvelopeV2Error::BindingMismatch("amount_bounds"));
    }
    let payee_binding_digest = derive_obligation_payee_binding_digest(
        &economic.payee.beneficiary_id,
        &economic.payee.settlement_destination_ref,
    )
    .map_err(|_| IouEnvelopeV2Error::BindingMismatch("payee_binding_digest"))?;
    if payee_binding_digest != atom.payee_binding_digest()
        || receipt.content_hash.len() != 64
        || receipt.policy_hash.len() != 64
    {
        return Err(IouEnvelopeV2Error::BindingMismatch("receipt_economics"));
    }
    Ok(())
}

fn domain_digest(domain: &[u8], value: &impl Serialize) -> Result<String, IouEnvelopeV2Error> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| IouEnvelopeV2Error::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn validate_text(field: &'static str, value: &str) -> Result<(), IouEnvelopeV2Error> {
    let disallowed_control =
        |character: char| matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f);
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_TEXT_CHARS
        || value.chars().any(disallowed_control)
    {
        Err(IouEnvelopeV2Error::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), IouEnvelopeV2Error> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(IouEnvelopeV2Error::InvalidField(field))
    }
}

fn validate_positive(field: &'static str, value: u64) -> Result<(), IouEnvelopeV2Error> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(IouEnvelopeV2Error::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_amount(amount: &MonetaryAmount) -> Result<(), IouEnvelopeV2Error> {
    validate_positive("amount_units", amount.units)?;
    if amount.currency.len() != 3
        || !amount
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(IouEnvelopeV2Error::InvalidField("amount_currency"));
    }
    Ok(())
}
