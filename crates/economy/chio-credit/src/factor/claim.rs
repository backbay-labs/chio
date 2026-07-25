use std::collections::BTreeMap;

use chio_core_types::receipt::body::ChioReceipt;

use crate::iou_v2::{
    verify_iou_envelope_v2, IouEnvelopeIssuerTrustV2, IouEnvelopeReceiptTrustV2,
    IouEnvelopeV2Error, IouEnvelopeVerificationContextV2, SignedIouEnvelopeV2,
    VerifiedIouEnvelopeV2,
};
use crate::obligation::{
    derive_obligation_payee_binding_digest, verify_credit_facility_bind, CreditAdmissionStore,
    CreditAdmissionStoreAdapter, CreditFacilityBindTrustV1,
    CreditFacilityBindVerificationContextV1, ObligationAtomV1, ObligationDispositionRecordV1,
    ObligationDispositionV1, ObligationSettlementLifecycleV1, ObligationSettlementStateV1,
    ObligationStatusProofTrustV1, VerifiedObligationStatusProofV1,
};

use super::*;

const CLAIM_TRUST_CONFIGURATION_DOMAIN: &[u8] =
    b"chio.factor.receivable-claim-trust.configuration.v1\0";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaimIssuerTrustPreimageV1 {
    issuer_id: String,
    issuer_key_epoch: u64,
    issuer_key: String,
    crypto_floor: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaimTrustConfigurationPreimageV1 {
    status_proof_trust_configuration_digest: String,
    receipt_kernel_keys: Vec<String>,
    receipt_crypto_floor: String,
    retained_iou_issuers: Vec<ClaimIssuerTrustPreimageV1>,
    retained_credit_facility_bind_trusts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivableClaimTrustV1 {
    status_proof_trust_configuration_digest: String,
    receipt_trust: IouEnvelopeReceiptTrustV2,
    retained_iou_issuers: Vec<IouEnvelopeIssuerTrustV2>,
    retained_credit_facility_bind_trusts: Vec<CreditFacilityBindTrustV1>,
    configuration_digest: String,
}

impl ReceivableClaimTrustV1 {
    pub fn new<I, B>(
        status_proof_trust: &ObligationStatusProofTrustV1,
        receipt_trust: IouEnvelopeReceiptTrustV2,
        retained_iou_issuers: I,
        retained_credit_facility_bind_trusts: B,
    ) -> Result<Self, FactorError>
    where
        I: IntoIterator<Item = IouEnvelopeIssuerTrustV2>,
        B: IntoIterator<Item = CreditFacilityBindTrustV1>,
    {
        if receipt_trust.trusted_kernel_key_hexes().is_empty() {
            return Err(FactorError::InvalidField("claim_receipt_trust"));
        }
        let mut retained_iou_issuers: Vec<_> = retained_iou_issuers.into_iter().collect();
        if retained_iou_issuers.is_empty() {
            return Err(FactorError::InvalidField("claim_iou_issuer_trust"));
        }
        let mut coordinates = BTreeMap::new();
        for issuer in &retained_iou_issuers {
            let coordinate = (issuer.issuer_id().to_owned(), issuer.issuer_key_epoch());
            let key = issuer.issuer_key().to_hex();
            if receipt_trust
                .trusted_kernel_key_hexes()
                .binary_search(&key)
                .is_ok()
            {
                return Err(FactorError::InvalidField("claim_iou_issuer_key_role"));
            }
            if let Some(existing) = coordinates.insert(coordinate, key.clone()) {
                return Err(FactorError::InvalidField(if existing == key {
                    "claim_iou_issuer_coordinate"
                } else {
                    "claim_iou_issuer_key"
                }));
            }
        }
        retained_iou_issuers.sort_unstable_by(|left, right| {
            (left.issuer_id(), left.issuer_key_epoch())
                .cmp(&(right.issuer_id(), right.issuer_key_epoch()))
        });
        let mut retained_credit_facility_bind_trusts: Vec<_> =
            retained_credit_facility_bind_trusts.into_iter().collect();
        if retained_credit_facility_bind_trusts.is_empty() {
            return Err(FactorError::InvalidField(
                "claim_credit_facility_bind_trust",
            ));
        }
        retained_credit_facility_bind_trusts.sort_unstable_by(|left, right| {
            left.configuration_digest()
                .cmp(right.configuration_digest())
        });
        if retained_credit_facility_bind_trusts
            .windows(2)
            .any(|window| window[0].configuration_digest() == window[1].configuration_digest())
        {
            return Err(FactorError::InvalidField(
                "claim_credit_facility_bind_trust_coordinate",
            ));
        }
        let configuration_digest = domain_digest(
            CLAIM_TRUST_CONFIGURATION_DOMAIN,
            &ClaimTrustConfigurationPreimageV1 {
                status_proof_trust_configuration_digest: status_proof_trust
                    .configuration_digest()
                    .to_owned(),
                receipt_kernel_keys: receipt_trust.trusted_kernel_key_hexes().to_vec(),
                receipt_crypto_floor: receipt_trust.crypto_floor().as_str().to_owned(),
                retained_iou_issuers: retained_iou_issuers
                    .iter()
                    .map(|issuer| ClaimIssuerTrustPreimageV1 {
                        issuer_id: issuer.issuer_id().to_owned(),
                        issuer_key_epoch: issuer.issuer_key_epoch(),
                        issuer_key: issuer.issuer_key().to_hex(),
                        crypto_floor: issuer.crypto_floor().as_str().to_owned(),
                    })
                    .collect(),
                retained_credit_facility_bind_trusts: retained_credit_facility_bind_trusts
                    .iter()
                    .map(|trust| trust.configuration_digest().to_owned())
                    .collect(),
            },
        )?;
        Ok(Self {
            status_proof_trust_configuration_digest: status_proof_trust
                .configuration_digest()
                .to_owned(),
            receipt_trust,
            retained_iou_issuers,
            retained_credit_facility_bind_trusts,
            configuration_digest,
        })
    }

    #[must_use]
    pub const fn receipt_trust(&self) -> &IouEnvelopeReceiptTrustV2 {
        &self.receipt_trust
    }

    #[must_use]
    pub fn status_proof_trust_configuration_digest(&self) -> &str {
        &self.status_proof_trust_configuration_digest
    }

    #[must_use]
    pub fn retained_iou_issuers(&self) -> &[IouEnvelopeIssuerTrustV2] {
        &self.retained_iou_issuers
    }

    #[must_use]
    pub fn retained_credit_facility_bind_trusts(&self) -> &[CreditFacilityBindTrustV1] {
        &self.retained_credit_facility_bind_trusts
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    fn issuer(&self, issuer_id: &str, issuer_key_epoch: u64) -> Option<&IouEnvelopeIssuerTrustV2> {
        self.retained_iou_issuers.iter().find(|issuer| {
            issuer.issuer_id() == issuer_id && issuer.issuer_key_epoch() == issuer_key_epoch
        })
    }

    fn credit_facility_bind_trust(
        &self,
        signed_iou: &SignedIouEnvelopeV2,
        trusted_at_unix_ms: u64,
    ) -> Result<&CreditFacilityBindTrustV1, FactorError> {
        let canonical_bind = signed_iou
            .body()
            .credit_facility_bind()
            .canonical_bytes()
            .map_err(|error| FactorError::Canonicalization(error.to_string()))?;
        let mut matching = self
            .retained_credit_facility_bind_trusts
            .iter()
            .filter(|trust| {
                verify_credit_facility_bind(
                    &canonical_bind,
                    &CreditFacilityBindVerificationContextV1 {
                        trust,
                        trusted_at_unix_ms,
                    },
                )
                .is_ok()
            });
        let selected = matching.next().ok_or(FactorError::AuthorityVerification)?;
        if matching.next().is_some() {
            return Err(FactorError::AuthorityVerification);
        }
        Ok(selected)
    }
}

pub struct ReceivableClaimVerificationV1<'a> {
    pub atom: &'a ObligationAtomV1,
    pub disposition: &'a ObligationDispositionRecordV1,
    pub settlement_lifecycle: &'a ObligationSettlementLifecycleV1,
    pub status_proof: &'a VerifiedObligationStatusProofV1,
    pub trusted_now_unix_ms: u64,
    pub trust: &'a ReceivableClaimTrustV1,
}

#[derive(Debug, Clone)]
pub struct VerifiedReceivableClaimV1 {
    claim: ReceivableClaimV1,
    receipt: ChioReceipt,
    iou: VerifiedIouEnvelopeV2,
    claim_digest: String,
    receipt_digest: String,
    iou_digest: String,
    trust_configuration_digest: String,
    claim_canonical_bytes: Vec<u8>,
    receipt_canonical_bytes: Vec<u8>,
}

impl VerifiedReceivableClaimV1 {
    #[must_use]
    pub const fn claim(&self) -> &ReceivableClaimV1 {
        &self.claim
    }

    #[must_use]
    pub const fn receipt(&self) -> &ChioReceipt {
        &self.receipt
    }

    #[must_use]
    pub const fn iou(&self) -> &VerifiedIouEnvelopeV2 {
        &self.iou
    }

    #[must_use]
    pub fn claim_digest(&self) -> &str {
        &self.claim_digest
    }

    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    #[must_use]
    pub fn iou_digest(&self) -> &str {
        &self.iou_digest
    }

    #[must_use]
    pub fn trust_configuration_digest(&self) -> &str {
        &self.trust_configuration_digest
    }

    #[must_use]
    pub fn claim_canonical_bytes(&self) -> &[u8] {
        &self.claim_canonical_bytes
    }

    #[must_use]
    pub fn receipt_canonical_bytes(&self) -> &[u8] {
        &self.receipt_canonical_bytes
    }

    #[must_use]
    pub fn iou_canonical_bytes(&self) -> &[u8] {
        self.iou.canonical_bytes()
    }
}

pub fn verify_receivable_claim<S: CreditAdmissionStore>(
    canonical_claim: &[u8],
    canonical_receipt: &[u8],
    canonical_iou: &[u8],
    credit_admission_store: &CreditAdmissionStoreAdapter<S>,
    context: &ReceivableClaimVerificationV1<'_>,
) -> Result<VerifiedReceivableClaimV1, FactorError> {
    validate_positive("claim_trusted_now_unix_ms", context.trusted_now_unix_ms)?;
    if context.status_proof.trust_configuration_digest()
        != context.trust.status_proof_trust_configuration_digest()
    {
        return Err(FactorError::AuthorityVerification);
    }
    context
        .atom
        .validate()
        .map_err(|_| FactorError::BindingMismatch)?;
    context
        .disposition
        .validate_against(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    context
        .settlement_lifecycle
        .validate_against(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    let status = context.status_proof.body();
    status
        .validate()
        .map_err(|_| FactorError::BindingMismatch)?;
    let atom_digest = context
        .atom
        .digest()
        .map_err(|_| FactorError::BindingMismatch)?;
    let disposition_digest = context
        .disposition
        .digest(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    let settlement_digest = context
        .settlement_lifecycle
        .digest(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    let payee_binding_digest = derive_obligation_payee_binding_digest(
        context.atom.original_creditor_id(),
        context.atom.original_settlement_destination_ref(),
    )
    .map_err(|_| FactorError::BindingMismatch)?;
    if !matches!(
        context.disposition.disposition(),
        ObligationDispositionV1::PerCall
    ) || !matches!(
        context.settlement_lifecycle.state(),
        ObligationSettlementStateV1::Pending
    ) || status.obligation_id() != context.atom.obligation_id()
        || status.obligation_atom_digest() != atom_digest
        || status.current_creditor_id() != context.atom.original_creditor_id()
        || status.current_settlement_destination_ref()
            != context.atom.original_settlement_destination_ref()
        || status.disposition() != context.disposition.disposition()
        || status.disposition_digest() != disposition_digest
        || status.disposition_version() != context.disposition.version()
        || status.disposition_lifecycle_fence() != context.disposition.lifecycle_fence()
        || status.settlement_state() != context.settlement_lifecycle.state()
        || status.settlement_lifecycle_digest() != settlement_digest
        || status.settlement_lifecycle_version() != context.settlement_lifecycle.version()
        || status.settlement_lifecycle_fence() != context.settlement_lifecycle.lifecycle_fence()
        || status.due_at_unix_ms() != context.atom.due_at_unix_ms()
        || context.atom.payee_binding_digest() != payee_binding_digest
    {
        return Err(FactorError::BindingMismatch);
    }
    if context.trusted_now_unix_ms < status.issued_at_unix_ms()
        || context.trusted_now_unix_ms >= status.expires_at_unix_ms()
        || context.trusted_now_unix_ms >= context.atom.due_at_unix_ms()
    {
        return Err(FactorError::NotCurrent);
    }

    let claim: ReceivableClaimV1 = parse_canonical(canonical_claim, "receivable claim")?;
    claim.validate_against_atom(context.atom)?;
    let receipt: ChioReceipt = parse_canonical(canonical_receipt, "claim receipt")?;
    let signed_iou =
        SignedIouEnvelopeV2::from_canonical_bytes(canonical_iou).map_err(map_iou_error)?;
    let issuer = context
        .trust
        .issuer(
            signed_iou.body().issuer_id(),
            signed_iou.body().issuer_key_epoch(),
        )
        .ok_or(FactorError::AuthorityVerification)?;
    let credit_facility_bind_trust = context
        .trust
        .credit_facility_bind_trust(&signed_iou, context.atom.created_at_unix_ms())?;
    let iou = verify_iou_envelope_v2(
        canonical_iou,
        credit_admission_store,
        &IouEnvelopeVerificationContextV2 {
            atom: context.atom,
            disposition: context.disposition,
            settlement_lifecycle: context.settlement_lifecycle,
            receipt: &receipt,
            receipt_trust: context.trust.receipt_trust(),
            credit_facility_bind_trust,
            issuer_trust: issuer,
            trusted_now_unix_ms: context.trusted_now_unix_ms,
        },
    )
    .map_err(map_iou_error)?;
    let receipt_digest = sha256_hex(canonical_receipt);
    let claim_digest = claim.digest()?;
    let iou_digest = iou.envelope_digest().to_owned();
    let receipt_timestamp_unix_ms = receipt
        .timestamp
        .checked_mul(1_000)
        .ok_or(FactorError::ArithmeticOverflow)?;
    validate_claim_causality(
        receipt_timestamp_unix_ms,
        context.atom.created_at_unix_ms(),
        status.issued_at_unix_ms(),
        claim.built_at_unix_ms(),
    )?;
    if claim.receipt_id() != receipt.id
        || claim.receipt_digest() != receipt_digest
        || claim.iou_id() != iou.body().iou_id()
        || claim.iou_digest() != iou_digest
        || claim.status_proof_digest() != context.status_proof.envelope_digest()
        || claim.seller_id() != context.atom.original_creditor_id()
        || claim.payee_binding_digest() != payee_binding_digest
        || claim.face_value() != context.atom.amount()
        || claim.due_at_unix_ms() != context.atom.due_at_unix_ms()
        || iou.body().issued_at_unix_ms() > claim.built_at_unix_ms()
        || claim.built_at_unix_ms() > context.trusted_now_unix_ms
        || claim.built_at_unix_ms() >= status.expires_at_unix_ms()
        || claim.built_at_unix_ms() >= context.atom.due_at_unix_ms()
    {
        return Err(FactorError::BindingMismatch);
    }
    Ok(VerifiedReceivableClaimV1 {
        claim,
        receipt,
        iou,
        claim_digest,
        receipt_digest,
        iou_digest,
        trust_configuration_digest: context.trust.configuration_digest().to_owned(),
        claim_canonical_bytes: canonical_claim.to_vec(),
        receipt_canonical_bytes: canonical_receipt.to_vec(),
    })
}

fn validate_claim_causality(
    receipt_timestamp_unix_ms: u64,
    atom_created_at_unix_ms: u64,
    status_issued_at_unix_ms: u64,
    claim_built_at_unix_ms: u64,
) -> Result<(), FactorError> {
    if receipt_timestamp_unix_ms > atom_created_at_unix_ms
        || atom_created_at_unix_ms > status_issued_at_unix_ms
        || status_issued_at_unix_ms > claim_built_at_unix_ms
    {
        Err(FactorError::BindingMismatch)
    } else {
        Ok(())
    }
}

fn map_iou_error(error: IouEnvelopeV2Error) -> FactorError {
    match error {
        IouEnvelopeV2Error::ReceiptVerification
        | IouEnvelopeV2Error::ReceiptSignerUntrusted
        | IouEnvelopeV2Error::CreditAuthorityVerification
        | IouEnvelopeV2Error::CreditAdmissionVerification
        | IouEnvelopeV2Error::IssuerVerification => FactorError::AuthorityVerification,
        IouEnvelopeV2Error::BindingMismatch(_) | IouEnvelopeV2Error::NotEligible(_) => {
            FactorError::BindingMismatch
        }
        IouEnvelopeV2Error::InvalidField(_)
        | IouEnvelopeV2Error::Canonicalization(_)
        | IouEnvelopeV2Error::Signing(_) => FactorError::Canonicalization(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_causality_rejects_each_reversed_edge() {
        assert_eq!(
            validate_claim_causality(2, 1, 2, 3),
            Err(FactorError::BindingMismatch)
        );
        assert_eq!(
            validate_claim_causality(1, 2, 1, 3),
            Err(FactorError::BindingMismatch)
        );
        assert_eq!(
            validate_claim_causality(1, 2, 3, 2),
            Err(FactorError::BindingMismatch)
        );
        assert_eq!(validate_claim_causality(1, 1, 1, 1), Ok(()));
    }
}
