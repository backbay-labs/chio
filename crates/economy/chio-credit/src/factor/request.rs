use super::*;
use crate::obligation::ObligationAtomV1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAssignmentRequestInputV1 {
    pub obligation_id: String,
    pub obligation_atom_digest: String,
    pub claim_digest: String,
    pub offer_digest: String,
    pub seller_id: String,
    pub buyer_id: String,
    pub buyer_settlement_destination_ref: String,
    pub agreed_price: MonetaryAmount,
    pub agreed_discount_bps: u16,
    pub expected_disposition_version: u64,
    pub expected_disposition_lifecycle_fence: u64,
    pub expected_settlement_lifecycle_version: u64,
    pub expected_settlement_lifecycle_fence: u64,
    pub action_nonce: String,
    pub effective_at_unix_ms: u64,
    pub due_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NormalizedAssignmentRequestV1 {
    schema: String,
    obligation_id: String,
    obligation_atom_digest: String,
    claim_digest: String,
    offer_digest: String,
    seller_id: String,
    buyer_id: String,
    buyer_settlement_destination_ref: String,
    agreed_price: MonetaryAmount,
    agreed_discount_bps: u16,
    expected_disposition_version: u64,
    expected_disposition_lifecycle_fence: u64,
    expected_settlement_lifecycle_version: u64,
    expected_settlement_lifecycle_fence: u64,
    action_nonce: String,
    effective_at_unix_ms: u64,
    due_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl NormalizedAssignmentRequestV1 {
    pub fn new(input: NormalizedAssignmentRequestInputV1) -> Result<Self, FactorError> {
        let request = Self {
            schema: FACTOR_NORMALIZED_ASSIGNMENT_REQUEST_SCHEMA.to_owned(),
            obligation_id: input.obligation_id,
            obligation_atom_digest: input.obligation_atom_digest,
            claim_digest: input.claim_digest,
            offer_digest: input.offer_digest,
            seller_id: input.seller_id,
            buyer_id: input.buyer_id,
            buyer_settlement_destination_ref: input.buyer_settlement_destination_ref,
            agreed_price: input.agreed_price,
            agreed_discount_bps: input.agreed_discount_bps,
            expected_disposition_version: input.expected_disposition_version,
            expected_disposition_lifecycle_fence: input.expected_disposition_lifecycle_fence,
            expected_settlement_lifecycle_version: input.expected_settlement_lifecycle_version,
            expected_settlement_lifecycle_fence: input.expected_settlement_lifecycle_fence,
            action_nonce: input.action_nonce,
            effective_at_unix_ms: input.effective_at_unix_ms,
            due_at_unix_ms: input.due_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_NORMALIZED_ASSIGNMENT_REQUEST_SCHEMA {
            return Err(FactorError::InvalidField("normalized_request_schema"));
        }
        for (field, value) in [
            ("obligation_id", &self.obligation_id),
            ("obligation_atom_digest", &self.obligation_atom_digest),
            ("claim_digest", &self.claim_digest),
            ("offer_digest", &self.offer_digest),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("seller_id", &self.seller_id),
            ("buyer_id", &self.buyer_id),
            (
                "buyer_settlement_destination_ref",
                &self.buyer_settlement_destination_ref,
            ),
            ("action_nonce", &self.action_nonce),
        ] {
            validate_text(field, value)?;
        }
        validate_amount("agreed_price", &self.agreed_price, true)?;
        validate_basis_points(self.agreed_discount_bps)?;
        for (field, value) in [
            (
                "expected_disposition_version",
                self.expected_disposition_version,
            ),
            (
                "expected_disposition_lifecycle_fence",
                self.expected_disposition_lifecycle_fence,
            ),
            (
                "expected_settlement_lifecycle_version",
                self.expected_settlement_lifecycle_version,
            ),
            (
                "expected_settlement_lifecycle_fence",
                self.expected_settlement_lifecycle_fence,
            ),
            ("effective_at_unix_ms", self.effective_at_unix_ms),
            ("due_at_unix_ms", self.due_at_unix_ms),
            ("expires_at_unix_ms", self.expires_at_unix_ms),
        ] {
            validate_positive(field, value)?;
        }
        if self.seller_id == self.buyer_id
            || self.expected_disposition_version != self.expected_disposition_lifecycle_fence
            || self.expected_settlement_lifecycle_version
                != self.expected_settlement_lifecycle_fence
            || self.effective_at_unix_ms >= self.expires_at_unix_ms
            || self.expires_at_unix_ms > self.due_at_unix_ms
        {
            return Err(FactorError::InvalidField("normalized_request_terms"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<String, FactorError> {
        self.validate()?;
        domain_digest(NORMALIZED_REQUEST_DIGEST_DOMAIN, self)
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
    pub fn claim_digest(&self) -> &str {
        &self.claim_digest
    }

    #[must_use]
    pub fn offer_digest(&self) -> &str {
        &self.offer_digest
    }

    #[must_use]
    pub fn seller_id(&self) -> &str {
        &self.seller_id
    }

    #[must_use]
    pub fn buyer_id(&self) -> &str {
        &self.buyer_id
    }

    #[must_use]
    pub fn buyer_settlement_destination_ref(&self) -> &str {
        &self.buyer_settlement_destination_ref
    }

    #[must_use]
    pub const fn agreed_price(&self) -> &MonetaryAmount {
        &self.agreed_price
    }

    #[must_use]
    pub const fn agreed_discount_bps(&self) -> u16 {
        self.agreed_discount_bps
    }

    #[must_use]
    pub const fn expected_disposition_version(&self) -> u64 {
        self.expected_disposition_version
    }

    #[must_use]
    pub const fn expected_disposition_lifecycle_fence(&self) -> u64 {
        self.expected_disposition_lifecycle_fence
    }

    #[must_use]
    pub const fn expected_settlement_lifecycle_version(&self) -> u64 {
        self.expected_settlement_lifecycle_version
    }

    #[must_use]
    pub const fn expected_settlement_lifecycle_fence(&self) -> u64 {
        self.expected_settlement_lifecycle_fence
    }

    #[must_use]
    pub fn action_nonce(&self) -> &str {
        &self.action_nonce
    }

    #[must_use]
    pub const fn effective_at_unix_ms(&self) -> u64 {
        self.effective_at_unix_ms
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivableClaimInputV1 {
    pub obligation_id: String,
    pub obligation_atom_digest: String,
    pub seller_id: String,
    pub receipt_id: String,
    pub receipt_digest: String,
    pub iou_id: String,
    pub iou_digest: String,
    pub payee_binding_digest: String,
    pub status_proof_digest: String,
    pub face_value: MonetaryAmount,
    pub due_at_unix_ms: u64,
    pub built_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceivableClaimV1 {
    schema: String,
    claim_id: String,
    obligation_id: String,
    obligation_atom_digest: String,
    seller_id: String,
    receipt_id: String,
    receipt_digest: String,
    iou_id: String,
    iou_digest: String,
    payee_binding_digest: String,
    status_proof_digest: String,
    face_value: MonetaryAmount,
    due_at_unix_ms: u64,
    built_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceivableClaimIdPreimage<'a> {
    schema: &'a str,
    obligation_id: &'a str,
    obligation_atom_digest: &'a str,
    seller_id: &'a str,
    receipt_id: &'a str,
    receipt_digest: &'a str,
    iou_id: &'a str,
    iou_digest: &'a str,
    payee_binding_digest: &'a str,
    status_proof_digest: &'a str,
    face_value: &'a MonetaryAmount,
    due_at_unix_ms: u64,
    built_at_unix_ms: u64,
}

impl ReceivableClaimV1 {
    pub fn new(input: ReceivableClaimInputV1) -> Result<Self, FactorError> {
        let mut claim = Self {
            schema: FACTOR_RECEIVABLE_CLAIM_SCHEMA.to_owned(),
            claim_id: String::new(),
            obligation_id: input.obligation_id,
            obligation_atom_digest: input.obligation_atom_digest,
            seller_id: input.seller_id,
            receipt_id: input.receipt_id,
            receipt_digest: input.receipt_digest,
            iou_id: input.iou_id,
            iou_digest: input.iou_digest,
            payee_binding_digest: input.payee_binding_digest,
            status_proof_digest: input.status_proof_digest,
            face_value: input.face_value,
            due_at_unix_ms: input.due_at_unix_ms,
            built_at_unix_ms: input.built_at_unix_ms,
        };
        claim.claim_id = claim.derived_claim_id()?;
        claim.validate()?;
        Ok(claim)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_RECEIVABLE_CLAIM_SCHEMA {
            return Err(FactorError::InvalidField("claim_schema"));
        }
        for (field, value) in [
            ("claim_id", &self.claim_id),
            ("obligation_id", &self.obligation_id),
            ("obligation_atom_digest", &self.obligation_atom_digest),
            ("receipt_digest", &self.receipt_digest),
            ("iou_digest", &self.iou_digest),
            ("payee_binding_digest", &self.payee_binding_digest),
            ("status_proof_digest", &self.status_proof_digest),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("seller_id", &self.seller_id),
            ("receipt_id", &self.receipt_id),
            ("iou_id", &self.iou_id),
        ] {
            validate_text(field, value)?;
        }
        validate_amount("face_value", &self.face_value, false)?;
        validate_positive("due_at_unix_ms", self.due_at_unix_ms)?;
        validate_positive("built_at_unix_ms", self.built_at_unix_ms)?;
        if self.built_at_unix_ms >= self.due_at_unix_ms
            || self.claim_id != self.derived_claim_id()?
        {
            return Err(FactorError::InvalidField("claim_terms"));
        }
        Ok(())
    }

    fn derived_claim_id(&self) -> Result<String, FactorError> {
        domain_digest(
            CLAIM_ID_DOMAIN,
            &ReceivableClaimIdPreimage {
                schema: &self.schema,
                obligation_id: &self.obligation_id,
                obligation_atom_digest: &self.obligation_atom_digest,
                seller_id: &self.seller_id,
                receipt_id: &self.receipt_id,
                receipt_digest: &self.receipt_digest,
                iou_id: &self.iou_id,
                iou_digest: &self.iou_digest,
                payee_binding_digest: &self.payee_binding_digest,
                status_proof_digest: &self.status_proof_digest,
                face_value: &self.face_value,
                due_at_unix_ms: self.due_at_unix_ms,
                built_at_unix_ms: self.built_at_unix_ms,
            },
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<String, FactorError> {
        self.validate()?;
        domain_digest(CLAIM_DIGEST_DOMAIN, self)
    }

    pub fn validate_against_atom(&self, atom: &ObligationAtomV1) -> Result<(), FactorError> {
        self.validate()?;
        atom.validate().map_err(|_| FactorError::BindingMismatch)?;
        if self.obligation_id != atom.obligation_id()
            || self.obligation_atom_digest
                != atom.digest().map_err(|_| FactorError::BindingMismatch)?
            || self.receipt_id != atom.source_receipt_id()
            || self.receipt_digest != atom.source_receipt_digest()
            || self.seller_id != atom.original_creditor_id()
            || self.payee_binding_digest != atom.payee_binding_digest()
            || self.face_value != *atom.amount()
            || self.due_at_unix_ms != atom.due_at_unix_ms()
            || self.built_at_unix_ms < atom.created_at_unix_ms()
        {
            return Err(FactorError::BindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
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
    pub fn seller_id(&self) -> &str {
        &self.seller_id
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
    pub fn iou_id(&self) -> &str {
        &self.iou_id
    }

    #[must_use]
    pub fn iou_digest(&self) -> &str {
        &self.iou_digest
    }

    #[must_use]
    pub fn payee_binding_digest(&self) -> &str {
        &self.payee_binding_digest
    }

    #[must_use]
    pub fn status_proof_digest(&self) -> &str {
        &self.status_proof_digest
    }

    #[must_use]
    pub const fn face_value(&self) -> &MonetaryAmount {
        &self.face_value
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }

    #[must_use]
    pub const fn built_at_unix_ms(&self) -> u64 {
        self.built_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentOfferV1 {
    schema: String,
    offer_id: String,
    claim_id: String,
    claim_digest: String,
    seller_id: String,
    asking_discount_bps: u16,
    minimum_price: MonetaryAmount,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    due_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentOfferIdPreimage<'a> {
    schema: &'a str,
    claim_id: &'a str,
    claim_digest: &'a str,
    seller_id: &'a str,
    asking_discount_bps: u16,
    minimum_price: &'a MonetaryAmount,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    due_at_unix_ms: u64,
}

impl AssignmentOfferV1 {
    pub fn new(
        claim: &ReceivableClaimV1,
        asking_discount_bps: u16,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, FactorError> {
        claim.validate()?;
        let mut offer = Self {
            schema: FACTOR_ASSIGNMENT_OFFER_SCHEMA.to_owned(),
            offer_id: String::new(),
            claim_id: claim.claim_id.clone(),
            claim_digest: claim.digest()?,
            seller_id: claim.seller_id.clone(),
            asking_discount_bps,
            minimum_price: discounted_amount(claim.face_value(), asking_discount_bps)?,
            issued_at_unix_ms,
            expires_at_unix_ms,
            due_at_unix_ms: claim.due_at_unix_ms,
        };
        offer.offer_id = offer.derived_offer_id()?;
        offer.validate()?;
        Ok(offer)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_ASSIGNMENT_OFFER_SCHEMA {
            return Err(FactorError::InvalidField("offer_schema"));
        }
        for (field, value) in [
            ("offer_id", &self.offer_id),
            ("claim_id", &self.claim_id),
            ("claim_digest", &self.claim_digest),
        ] {
            validate_digest(field, value)?;
        }
        validate_text("seller_id", &self.seller_id)?;
        validate_basis_points(self.asking_discount_bps)?;
        validate_amount("minimum_price", &self.minimum_price, true)?;
        for (field, value) in [
            ("issued_at_unix_ms", self.issued_at_unix_ms),
            ("expires_at_unix_ms", self.expires_at_unix_ms),
            ("due_at_unix_ms", self.due_at_unix_ms),
        ] {
            validate_positive(field, value)?;
        }
        if self.issued_at_unix_ms >= self.expires_at_unix_ms
            || self.expires_at_unix_ms >= self.due_at_unix_ms
            || self.offer_id != self.derived_offer_id()?
        {
            return Err(FactorError::InvalidField("offer_terms"));
        }
        Ok(())
    }

    fn derived_offer_id(&self) -> Result<String, FactorError> {
        domain_digest(
            OFFER_ID_DOMAIN,
            &AssignmentOfferIdPreimage {
                schema: &self.schema,
                claim_id: &self.claim_id,
                claim_digest: &self.claim_digest,
                seller_id: &self.seller_id,
                asking_discount_bps: self.asking_discount_bps,
                minimum_price: &self.minimum_price,
                issued_at_unix_ms: self.issued_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
                due_at_unix_ms: self.due_at_unix_ms,
            },
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<String, FactorError> {
        self.validate()?;
        domain_digest(OFFER_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn offer_id(&self) -> &str {
        &self.offer_id
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    #[must_use]
    pub fn claim_digest(&self) -> &str {
        &self.claim_digest
    }

    #[must_use]
    pub fn seller_id(&self) -> &str {
        &self.seller_id
    }

    #[must_use]
    pub const fn asking_discount_bps(&self) -> u16 {
        self.asking_discount_bps
    }

    #[must_use]
    pub const fn minimum_price(&self) -> &MonetaryAmount {
        &self.minimum_price
    }

    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiscountQuoteOutcomeV1 {
    Quoted {
        resolved_discount_bps: u16,
        quoted_price: MonetaryAmount,
    },
    Refused {
        refusal_reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscountQuoteV1 {
    schema: String,
    quote_id: String,
    claim_id: String,
    claim_digest: String,
    underwriting_decision_digest: String,
    scorecard_digest: String,
    outcome: DiscountQuoteOutcomeV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiscountQuoteIdPreimage<'a> {
    schema: &'a str,
    claim_id: &'a str,
    claim_digest: &'a str,
    underwriting_decision_digest: &'a str,
    scorecard_digest: &'a str,
    outcome: &'a DiscountQuoteOutcomeV1,
}

impl DiscountQuoteV1 {
    pub fn quoted(
        claim: &ReceivableClaimV1,
        underwriting_decision_digest: String,
        scorecard_digest: String,
        resolved_discount_bps: u16,
    ) -> Result<Self, FactorError> {
        let quoted_price = discounted_amount(claim.face_value(), resolved_discount_bps)?;
        Self::new(
            claim,
            underwriting_decision_digest,
            scorecard_digest,
            DiscountQuoteOutcomeV1::Quoted {
                resolved_discount_bps,
                quoted_price,
            },
        )
    }

    pub fn refused(
        claim: &ReceivableClaimV1,
        underwriting_decision_digest: String,
        scorecard_digest: String,
        refusal_reason: String,
    ) -> Result<Self, FactorError> {
        Self::new(
            claim,
            underwriting_decision_digest,
            scorecard_digest,
            DiscountQuoteOutcomeV1::Refused { refusal_reason },
        )
    }

    fn new(
        claim: &ReceivableClaimV1,
        underwriting_decision_digest: String,
        scorecard_digest: String,
        outcome: DiscountQuoteOutcomeV1,
    ) -> Result<Self, FactorError> {
        claim.validate()?;
        let mut quote = Self {
            schema: FACTOR_DISCOUNT_QUOTE_SCHEMA.to_owned(),
            quote_id: String::new(),
            claim_id: claim.claim_id.clone(),
            claim_digest: claim.digest()?,
            underwriting_decision_digest,
            scorecard_digest,
            outcome,
        };
        quote.quote_id = quote.derived_quote_id()?;
        quote.validate_against_claim(claim)?;
        Ok(quote)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_DISCOUNT_QUOTE_SCHEMA {
            return Err(FactorError::InvalidField("discount_quote_schema"));
        }
        for (field, value) in [
            ("quote_id", &self.quote_id),
            ("claim_id", &self.claim_id),
            ("claim_digest", &self.claim_digest),
            (
                "underwriting_decision_digest",
                &self.underwriting_decision_digest,
            ),
            ("scorecard_digest", &self.scorecard_digest),
        ] {
            validate_digest(field, value)?;
        }
        match &self.outcome {
            DiscountQuoteOutcomeV1::Quoted {
                resolved_discount_bps,
                quoted_price,
            } => {
                validate_basis_points(*resolved_discount_bps)?;
                validate_amount("quoted_price", quoted_price, true)?;
            }
            DiscountQuoteOutcomeV1::Refused { refusal_reason } => {
                validate_text("refusal_reason", refusal_reason)?;
            }
        }
        if self.quote_id != self.derived_quote_id()? {
            return Err(FactorError::InvalidField("quote_id"));
        }
        Ok(())
    }

    pub fn validate_against_claim(&self, claim: &ReceivableClaimV1) -> Result<(), FactorError> {
        self.validate()?;
        claim.validate()?;
        if self.claim_id != claim.claim_id() || self.claim_digest != claim.digest()? {
            return Err(FactorError::BindingMismatch);
        }
        if let DiscountQuoteOutcomeV1::Quoted {
            resolved_discount_bps,
            quoted_price,
        } = &self.outcome
        {
            let expected = discounted_amount(claim.face_value(), *resolved_discount_bps)?;
            if quoted_price != &expected {
                return Err(FactorError::BindingMismatch);
            }
        }
        Ok(())
    }

    fn derived_quote_id(&self) -> Result<String, FactorError> {
        domain_digest(
            QUOTE_ID_DOMAIN,
            &DiscountQuoteIdPreimage {
                schema: &self.schema,
                claim_id: &self.claim_id,
                claim_digest: &self.claim_digest,
                underwriting_decision_digest: &self.underwriting_decision_digest,
                scorecard_digest: &self.scorecard_digest,
                outcome: &self.outcome,
            },
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn digest(&self) -> Result<String, FactorError> {
        self.validate()?;
        domain_digest(QUOTE_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn quote_id(&self) -> &str {
        &self.quote_id
    }

    #[must_use]
    pub const fn outcome(&self) -> &DiscountQuoteOutcomeV1 {
        &self.outcome
    }
}
