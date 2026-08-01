mod factor_claim_support;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_credit::factor::{
    verify_receivable_claim, FactorError, ReceivableClaimInputV1, ReceivableClaimTrustV1,
    ReceivableClaimV1, ReceivableClaimVerificationV1,
};
use chio_credit::obligation::{
    CreditFacilityBindTrustInputV1, CreditFacilityBindTrustV1, ObligationSettlementTransitionV1,
    ObligationStatusProofTrustV1,
};
use chio_credit::{IouEnvelopeCryptoFloorV2, IouEnvelopeIssuerTrustV2, IouEnvelopeReceiptTrustV2};
use factor_claim_support::{
    build_claim_evidence, ClaimEvidence, SupportResult, ATOM_CREATED_AT, CREDITOR_KEY_EPOCH,
    CREDIT_AUTHORITY_EPOCH, CREDIT_AUTHORITY_ID, DEBTOR_ID, DEBTOR_KEY_EPOCH, IOU_ISSUER_EPOCH,
    IOU_ISSUER_ID, RESULT_AUTHORITY_EPOCH, RESULT_AUTHORITY_ID, SELLER_ID, STATUS_EXPIRES_AT,
    TRUSTED_NOW,
};

fn require_factor_error<T>(result: Result<T, FactorError>) -> FactorError {
    match result {
        Ok(_) => panic!("verification unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn verify_with(
    evidence: &ClaimEvidence,
    receipt: &[u8],
    iou: &[u8],
    trust: &ReceivableClaimTrustV1,
    trusted_now_unix_ms: u64,
) -> Result<chio_credit::factor::VerifiedReceivableClaimV1, FactorError> {
    verify_receivable_claim(
        &evidence.claim_bytes,
        receipt,
        iou,
        &evidence.credit_admission_store.adapter(),
        &ReceivableClaimVerificationV1 {
            atom: &evidence.atom,
            disposition: &evidence.disposition,
            settlement_lifecycle: &evidence.settlement_lifecycle,
            status_proof: &evidence.status_proof,
            trusted_now_unix_ms,
            trust,
        },
    )
}

fn tamper_signature(canonical: &[u8]) -> SupportResult<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(canonical)?;
    let signature = match value.get("signature").and_then(serde_json::Value::as_str) {
        Some(signature) => signature,
        None => return Err("signed evidence omitted its signature".into()),
    };
    let mut tampered = signature.as_bytes().to_vec();
    let last = match tampered.last_mut() {
        Some(last) => last,
        None => return Err("signed evidence contained an empty signature".into()),
    };
    *last = if *last == b'0' { b'1' } else { b'0' };
    value["signature"] = serde_json::Value::String(String::from_utf8(tampered)?);
    Ok(canonical_json_bytes(&value)?)
}

fn rotated_credit_facility_bind_trust(
    evidence: &ClaimEvidence,
) -> SupportResult<CreditFacilityBindTrustV1> {
    Ok(CreditFacilityBindTrustV1::new(
        CreditFacilityBindTrustInputV1 {
            authority_id: CREDIT_AUTHORITY_ID.to_owned(),
            authority_key: Keypair::from_seed(&[120; 32]).public_key(),
            authority_key_epoch: CREDIT_AUTHORITY_EPOCH + 1,
            debtor_id: DEBTOR_ID.to_owned(),
            debtor_key: evidence.debtor_key.clone(),
            debtor_key_epoch: DEBTOR_KEY_EPOCH,
            creditor_id: SELLER_ID.to_owned(),
            creditor_key: evidence.creditor_key.clone(),
            creditor_key_epoch: CREDITOR_KEY_EPOCH,
            max_lifetime_ms: 600,
        },
    )?)
}

fn overlapping_credit_facility_bind_trust(
    evidence: &ClaimEvidence,
) -> SupportResult<CreditFacilityBindTrustV1> {
    Ok(CreditFacilityBindTrustV1::new(
        CreditFacilityBindTrustInputV1 {
            authority_id: CREDIT_AUTHORITY_ID.to_owned(),
            authority_key: evidence.credit_authority_key.clone(),
            authority_key_epoch: CREDIT_AUTHORITY_EPOCH,
            debtor_id: DEBTOR_ID.to_owned(),
            debtor_key: evidence.debtor_key.clone(),
            debtor_key_epoch: DEBTOR_KEY_EPOCH,
            creditor_id: SELLER_ID.to_owned(),
            creditor_key: evidence.creditor_key.clone(),
            creditor_key_epoch: CREDITOR_KEY_EPOCH,
            max_lifetime_ms: 700,
        },
    )?)
}

#[test]
fn sealed_claim_retains_exact_verified_evidence() -> SupportResult<()> {
    let evidence = build_claim_evidence()?;
    let verified = verify_with(
        &evidence,
        &evidence.receipt_bytes,
        &evidence.iou_bytes,
        &evidence.trust,
        TRUSTED_NOW,
    )?;
    assert_eq!(verified.claim_canonical_bytes(), evidence.claim_bytes);
    assert_eq!(verified.receipt_canonical_bytes(), evidence.receipt_bytes);
    assert_eq!(verified.iou_canonical_bytes(), evidence.iou_bytes);
    assert_eq!(verified.claim_digest(), verified.claim().digest()?);
    assert_eq!(
        verified.receipt_digest(),
        sha256_hex(&evidence.receipt_bytes)
    );
    assert_eq!(verified.iou_digest(), sha256_hex(&evidence.iou_bytes));
    assert_eq!(
        evidence.status_proof.trust_configuration_digest(),
        evidence.trust.status_proof_trust_configuration_digest()
    );
    assert_eq!(
        verified.trust_configuration_digest(),
        evidence.trust.configuration_digest()
    );
    assert_eq!(verified.receipt().id, evidence.receipt.id);
    assert_eq!(verified.iou().body().iou_id(), verified.claim().iou_id());
    assert!(verified.receipt().timestamp * 1_000 <= evidence.atom.created_at_unix_ms());
    assert!(evidence.atom.created_at_unix_ms() <= evidence.status_proof.body().issued_at_unix_ms());
    assert!(
        evidence.status_proof.body().issued_at_unix_ms() <= verified.claim().built_at_unix_ms()
    );
    assert_eq!(evidence.trust.configuration_digest().len(), 64);
    Ok(())
}

#[test]
fn claim_trust_is_deterministic_and_role_separated() -> SupportResult<()> {
    let evidence = build_claim_evidence()?;
    let status_trust = ObligationStatusProofTrustV1::new(
        RESULT_AUTHORITY_ID.to_owned(),
        evidence.result_signer.public_key(),
        RESULT_AUTHORITY_EPOCH,
        600,
    )?;
    let receipt_trust = IouEnvelopeReceiptTrustV2::new(
        [evidence.kernel_key.clone()],
        ReceiptCryptoFloor::AllowClassical,
    );
    let retained = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        evidence.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let rotated = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH + 1,
        Keypair::from_seed(&[113; 32]).public_key(),
        IouEnvelopeCryptoFloorV2::PqRequired,
    )?;
    let retained_bind = evidence.credit_facility_bind_trust.clone();
    let rotated_bind = rotated_credit_facility_bind_trust(&evidence)?;
    let first = ReceivableClaimTrustV1::new(
        &status_trust,
        receipt_trust.clone(),
        [rotated.clone(), retained.clone()],
        [rotated_bind.clone(), retained_bind.clone()],
    )?;
    let second = ReceivableClaimTrustV1::new(
        &status_trust,
        receipt_trust.clone(),
        [retained.clone(), rotated],
        [retained_bind.clone(), rotated_bind.clone()],
    )?;
    assert_eq!(first.configuration_digest(), second.configuration_digest());
    assert_eq!(
        first.retained_iou_issuers()[0].issuer_key_epoch(),
        IOU_ISSUER_EPOCH
    );
    assert_eq!(
        ReceivableClaimTrustV1::new(
            &status_trust,
            IouEnvelopeReceiptTrustV2::new(
                std::iter::empty::<chio_core_types::crypto::PublicKey>(),
                ReceiptCryptoFloor::AllowClassical,
            ),
            [retained.clone()],
            [retained_bind.clone()],
        ),
        Err(FactorError::InvalidField("claim_receipt_trust"))
    );
    assert_eq!(
        ReceivableClaimTrustV1::new(
            &status_trust,
            receipt_trust.clone(),
            std::iter::empty::<IouEnvelopeIssuerTrustV2>(),
            [retained_bind.clone()],
        ),
        Err(FactorError::InvalidField("claim_iou_issuer_trust"))
    );
    assert_eq!(
        ReceivableClaimTrustV1::new(
            &status_trust,
            receipt_trust.clone(),
            [retained.clone(), retained.clone()],
            [retained_bind.clone()],
        ),
        Err(FactorError::InvalidField("claim_iou_issuer_coordinate"))
    );
    let conflicting = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        Keypair::from_seed(&[114; 32]).public_key(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    assert_eq!(
        ReceivableClaimTrustV1::new(
            &status_trust,
            receipt_trust.clone(),
            [retained.clone(), conflicting],
            [retained_bind.clone()],
        ),
        Err(FactorError::InvalidField("claim_iou_issuer_key"))
    );
    let cross_role = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        evidence.kernel_key,
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    assert_eq!(
        ReceivableClaimTrustV1::new(
            &status_trust,
            receipt_trust.clone(),
            [cross_role],
            [retained_bind.clone()],
        ),
        Err(FactorError::InvalidField("claim_iou_issuer_key_role"))
    );
    assert_eq!(
        ReceivableClaimTrustV1::new(
            &status_trust,
            receipt_trust.clone(),
            [retained.clone()],
            std::iter::empty::<CreditFacilityBindTrustV1>(),
        ),
        Err(FactorError::InvalidField(
            "claim_credit_facility_bind_trust"
        ))
    );
    assert_eq!(
        ReceivableClaimTrustV1::new(
            &status_trust,
            receipt_trust,
            [retained],
            [retained_bind.clone(), retained_bind],
        ),
        Err(FactorError::InvalidField(
            "claim_credit_facility_bind_trust_coordinate"
        ))
    );
    Ok(())
}

#[test]
fn sealed_claim_rejects_tampered_receipt_and_iou() -> SupportResult<()> {
    let evidence = build_claim_evidence()?;
    let tampered_receipt = tamper_signature(&evidence.receipt_bytes)?;
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &tampered_receipt,
            &evidence.iou_bytes,
            &evidence.trust,
            TRUSTED_NOW,
        )),
        FactorError::AuthorityVerification
    );
    let tampered_iou = tamper_signature(&evidence.iou_bytes)?;
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &tampered_iou,
            &evidence.trust,
            TRUSTED_NOW,
        )),
        FactorError::AuthorityVerification
    );
    Ok(())
}

#[test]
fn sealed_claim_rejects_legacy_and_untrusted_evidence() -> SupportResult<()> {
    let evidence = build_claim_evidence()?;
    let status_trust = ObligationStatusProofTrustV1::new(
        RESULT_AUTHORITY_ID.to_owned(),
        evidence.result_signer.public_key(),
        RESULT_AUTHORITY_EPOCH,
        600,
    )?;
    assert!(matches!(
        verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &evidence.legacy_iou_bytes,
            &evidence.trust,
            TRUSTED_NOW,
        ),
        Err(FactorError::Canonicalization(_))
    ));
    let wrong_issuer = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        Keypair::from_seed(&[115; 32]).public_key(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let untrusted_issuer = ReceivableClaimTrustV1::new(
        &status_trust,
        IouEnvelopeReceiptTrustV2::new(
            [evidence.kernel_key.clone()],
            ReceiptCryptoFloor::AllowClassical,
        ),
        [wrong_issuer],
        [evidence.credit_facility_bind_trust.clone()],
    )?;
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &untrusted_issuer,
            TRUSTED_NOW,
        )),
        FactorError::AuthorityVerification
    );
    let retained_issuer = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        evidence.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let untrusted_receipt = ReceivableClaimTrustV1::new(
        &status_trust,
        IouEnvelopeReceiptTrustV2::new(
            [Keypair::from_seed(&[116; 32]).public_key()],
            ReceiptCryptoFloor::AllowClassical,
        ),
        [retained_issuer],
        [evidence.credit_facility_bind_trust.clone()],
    )?;
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &untrusted_receipt,
            TRUSTED_NOW,
        )),
        FactorError::AuthorityVerification
    );
    let retained_issuer = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        evidence.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let untrusted_bind = ReceivableClaimTrustV1::new(
        &status_trust,
        IouEnvelopeReceiptTrustV2::new(
            [evidence.kernel_key.clone()],
            ReceiptCryptoFloor::AllowClassical,
        ),
        [retained_issuer],
        [rotated_credit_facility_bind_trust(&evidence)?],
    )?;
    assert_ne!(
        untrusted_bind.configuration_digest(),
        evidence.trust.configuration_digest()
    );
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &untrusted_bind,
            TRUSTED_NOW,
        )),
        FactorError::AuthorityVerification
    );
    let retained_issuer = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        evidence.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let ambiguous_bind = ReceivableClaimTrustV1::new(
        &status_trust,
        IouEnvelopeReceiptTrustV2::new(
            [evidence.kernel_key.clone()],
            ReceiptCryptoFloor::AllowClassical,
        ),
        [retained_issuer],
        [
            evidence.credit_facility_bind_trust.clone(),
            overlapping_credit_facility_bind_trust(&evidence)?,
        ],
    )?;
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &ambiguous_bind,
            TRUSTED_NOW,
        )),
        FactorError::AuthorityVerification
    );
    Ok(())
}

#[test]
fn sealed_claim_rejects_mixed_status_trust_and_premature_build() -> SupportResult<()> {
    let evidence = build_claim_evidence()?;
    let mismatched_status_trust = ObligationStatusProofTrustV1::new(
        RESULT_AUTHORITY_ID.to_owned(),
        evidence.result_signer.public_key(),
        RESULT_AUTHORITY_EPOCH,
        601,
    )?;
    let issuer_trust = IouEnvelopeIssuerTrustV2::new(
        IOU_ISSUER_ID.to_owned(),
        IOU_ISSUER_EPOCH,
        evidence.issuer_key.clone(),
        IouEnvelopeCryptoFloorV2::AllowClassical,
    )?;
    let mismatched_claim_trust = ReceivableClaimTrustV1::new(
        &mismatched_status_trust,
        IouEnvelopeReceiptTrustV2::new(
            [evidence.kernel_key.clone()],
            ReceiptCryptoFloor::AllowClassical,
        ),
        [issuer_trust],
        [evidence.credit_facility_bind_trust.clone()],
    )?;
    assert_ne!(
        mismatched_claim_trust.configuration_digest(),
        evidence.trust.configuration_digest()
    );
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &mismatched_claim_trust,
            TRUSTED_NOW,
        )),
        FactorError::AuthorityVerification
    );

    let premature_claim = ReceivableClaimV1::new(ReceivableClaimInputV1 {
        obligation_id: evidence.atom.obligation_id().to_owned(),
        obligation_atom_digest: evidence.atom.digest()?,
        seller_id: evidence.atom.original_creditor_id().to_owned(),
        receipt_id: evidence.receipt.id.clone(),
        receipt_digest: sha256_hex(&evidence.receipt_bytes),
        iou_id: evidence.verified_claim.iou().body().iou_id().to_owned(),
        iou_digest: sha256_hex(&evidence.iou_bytes),
        payee_binding_digest: evidence.atom.payee_binding_digest().to_owned(),
        status_proof_digest: evidence.status_proof.envelope_digest().to_owned(),
        face_value: evidence.atom.amount().clone(),
        due_at_unix_ms: evidence.atom.due_at_unix_ms(),
        built_at_unix_ms: ATOM_CREATED_AT,
    })?;
    assert_eq!(
        require_factor_error(verify_receivable_claim(
            &premature_claim.canonical_bytes()?,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &evidence.credit_admission_store.adapter(),
            &ReceivableClaimVerificationV1 {
                atom: &evidence.atom,
                disposition: &evidence.disposition,
                settlement_lifecycle: &evidence.settlement_lifecycle,
                status_proof: &evidence.status_proof,
                trusted_now_unix_ms: TRUSTED_NOW,
                trust: &evidence.trust,
            },
        )),
        FactorError::BindingMismatch
    );
    Ok(())
}

#[test]
fn sealed_claim_rejects_expiry_and_nonpending_state() -> SupportResult<()> {
    let evidence = build_claim_evidence()?;
    assert_eq!(
        require_factor_error(verify_with(
            &evidence,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &evidence.trust,
            STATUS_EXPIRES_AT,
        )),
        FactorError::NotCurrent
    );
    let settled = evidence.settlement_lifecycle.advance(
        &evidence.atom,
        ObligationSettlementTransitionV1::Settle {
            settlement_id: "settlement-1".to_owned(),
            evidence_digest: sha256_hex(b"settlement-evidence"),
            authority_digest: sha256_hex(b"settlement-authority"),
        },
    )?;
    assert_eq!(
        require_factor_error(verify_receivable_claim(
            &evidence.claim_bytes,
            &evidence.receipt_bytes,
            &evidence.iou_bytes,
            &evidence.credit_admission_store.adapter(),
            &ReceivableClaimVerificationV1 {
                atom: &evidence.atom,
                disposition: &evidence.disposition,
                settlement_lifecycle: &settled,
                status_proof: &evidence.status_proof,
                trusted_now_unix_ms: TRUSTED_NOW,
                trust: &evidence.trust,
            },
        )),
        FactorError::BindingMismatch
    );
    Ok(())
}
