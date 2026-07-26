use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentBindAuthorizationInputV1 {
    pub operation_id: String,
    pub normalized_request_digest: String,
    pub obligation_atom_digest: String,
    pub seller_id: String,
    pub buyer_id: String,
    pub agreement_id: String,
    pub buyer_settlement_destination_ref: String,
    pub effective_at_unix_ms: u64,
    pub action_nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub authority_id: String,
    pub authority_key_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentBindAuthorizationBodyV1 {
    schema: String,
    action: String,
    operation_id: String,
    normalized_request_digest: String,
    obligation_atom_digest: String,
    seller_id: String,
    buyer_id: String,
    agreement_id: String,
    buyer_settlement_destination_ref: String,
    effective_at_unix_ms: u64,
    action_nonce: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    authority_id: String,
    authority_key_epoch: u64,
}

impl AssignmentBindAuthorizationBodyV1 {
    pub fn new(input: AssignmentBindAuthorizationInputV1) -> Result<Self, FactorError> {
        let body = Self {
            schema: FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_SCHEMA.to_owned(),
            action: FACTOR_ASSIGNMENT_BIND_ACTION.to_owned(),
            operation_id: input.operation_id,
            normalized_request_digest: input.normalized_request_digest,
            obligation_atom_digest: input.obligation_atom_digest,
            seller_id: input.seller_id,
            buyer_id: input.buyer_id,
            agreement_id: input.agreement_id,
            buyer_settlement_destination_ref: input.buyer_settlement_destination_ref,
            effective_at_unix_ms: input.effective_at_unix_ms,
            action_nonce: input.action_nonce,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
            authority_id: input.authority_id,
            authority_key_epoch: input.authority_key_epoch,
        };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_SCHEMA {
            return Err(FactorError::InvalidField("authorization_schema"));
        }
        if self.action != FACTOR_ASSIGNMENT_BIND_ACTION {
            return Err(FactorError::InvalidField("authorization_action"));
        }
        for (field, value) in [
            ("operation_id", &self.operation_id),
            ("normalized_request_digest", &self.normalized_request_digest),
            ("obligation_atom_digest", &self.obligation_atom_digest),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("seller_id", &self.seller_id),
            ("buyer_id", &self.buyer_id),
            ("agreement_id", &self.agreement_id),
            (
                "buyer_settlement_destination_ref",
                &self.buyer_settlement_destination_ref,
            ),
            ("action_nonce", &self.action_nonce),
            ("authority_id", &self.authority_id),
        ] {
            validate_text(field, value)?;
        }
        for (field, value) in [
            ("effective_at_unix_ms", self.effective_at_unix_ms),
            ("issued_at_unix_ms", self.issued_at_unix_ms),
            ("expires_at_unix_ms", self.expires_at_unix_ms),
            ("authority_key_epoch", self.authority_key_epoch),
        ] {
            validate_positive(field, value)?;
        }
        if self.seller_id == self.buyer_id
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.effective_at_unix_ms < self.issued_at_unix_ms
            || self.effective_at_unix_ms >= self.expires_at_unix_ms
        {
            return Err(FactorError::InvalidField("authorization_terms"));
        }
        Ok(())
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn normalized_request_digest(&self) -> &str {
        &self.normalized_request_digest
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
    pub fn buyer_id(&self) -> &str {
        &self.buyer_id
    }

    #[must_use]
    pub fn agreement_id(&self) -> &str {
        &self.agreement_id
    }

    #[must_use]
    pub fn buyer_settlement_destination_ref(&self) -> &str {
        &self.buyer_settlement_destination_ref
    }

    #[must_use]
    pub const fn effective_at_unix_ms(&self) -> u64 {
        self.effective_at_unix_ms
    }

    #[must_use]
    pub fn action_nonce(&self) -> &str {
        &self.action_nonce
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
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    #[must_use]
    pub const fn authority_key_epoch(&self) -> u64 {
        self.authority_key_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedAssignmentBindAuthorizationV1(
    SignedExportEnvelope<AssignmentBindAuthorizationBodyV1>,
);

impl SignedAssignmentBindAuthorizationV1 {
    pub fn sign(
        body: AssignmentBindAuthorizationBodyV1,
        signer: &Keypair,
    ) -> Result<Self, FactorError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| FactorError::Canonicalization(error.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        canonical_bytes(self)
    }

    #[must_use]
    pub const fn body(&self) -> &AssignmentBindAuthorizationBodyV1 {
        &self.0.body
    }
}

#[derive(Debug, Clone)]
pub struct AssignmentBindAuthorizationTrustV1 {
    authority_id: String,
    authority_key: PublicKey,
    authority_key_epoch: u64,
    max_lifetime_ms: u64,
}

impl AssignmentBindAuthorizationTrustV1 {
    pub fn new(
        authority_id: String,
        authority_key: PublicKey,
        authority_key_epoch: u64,
        max_lifetime_ms: u64,
    ) -> Result<Self, FactorError> {
        validate_text("trusted_authority_id", &authority_id)?;
        validate_positive("trusted_authority_key_epoch", authority_key_epoch)?;
        validate_positive("max_lifetime_ms", max_lifetime_ms)?;
        Ok(Self {
            authority_id,
            authority_key,
            authority_key_epoch,
            max_lifetime_ms,
        })
    }

    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    #[must_use]
    pub const fn authority_key_epoch(&self) -> u64 {
        self.authority_key_epoch
    }

    #[must_use]
    pub const fn authority_key(&self) -> &PublicKey {
        &self.authority_key
    }

    #[must_use]
    pub const fn max_lifetime_ms(&self) -> u64 {
        self.max_lifetime_ms
    }
}

pub struct AssignmentBindAuthorizationVerificationV1<'a> {
    pub operation_id: &'a str,
    pub normalized_request_digest: &'a str,
    pub obligation_atom_digest: &'a str,
    pub seller_id: &'a str,
    pub buyer_id: &'a str,
    pub agreement_id: &'a str,
    pub buyer_settlement_destination_ref: &'a str,
    pub effective_at_unix_ms: u64,
    pub action_nonce: &'a str,
    pub trust: &'a AssignmentBindAuthorizationTrustV1,
    pub trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssignmentBindAuthorizationV1 {
    signed: SignedAssignmentBindAuthorizationV1,
    body_digest: String,
    envelope_digest: String,
    canonical_bytes: Vec<u8>,
}

impl VerifiedAssignmentBindAuthorizationV1 {
    #[must_use]
    pub const fn body(&self) -> &AssignmentBindAuthorizationBodyV1 {
        self.signed.body()
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
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn ensure_current(&self, trusted_now_unix_ms: u64) -> Result<(), FactorError> {
        if trusted_now_unix_ms < self.body().issued_at_unix_ms
            || trusted_now_unix_ms >= self.body().expires_at_unix_ms
        {
            return Err(FactorError::NotCurrent);
        }
        Ok(())
    }
}

pub fn verify_assignment_bind_authorization(
    canonical_authorization: &[u8],
    context: &AssignmentBindAuthorizationVerificationV1<'_>,
) -> Result<VerifiedAssignmentBindAuthorizationV1, FactorError> {
    let signed: SignedAssignmentBindAuthorizationV1 =
        parse_canonical(canonical_authorization, "assignment bind authorization")?;
    signed.body().validate()?;
    let body = signed.body();
    if body.operation_id != context.operation_id
        || body.normalized_request_digest != context.normalized_request_digest
        || body.obligation_atom_digest != context.obligation_atom_digest
        || body.seller_id != context.seller_id
        || body.buyer_id != context.buyer_id
        || body.agreement_id != context.agreement_id
        || body.buyer_settlement_destination_ref != context.buyer_settlement_destination_ref
        || body.effective_at_unix_ms != context.effective_at_unix_ms
        || body.action_nonce != context.action_nonce
    {
        return Err(FactorError::BindingMismatch);
    }
    if body.authority_id != context.trust.authority_id
        || body.authority_key_epoch != context.trust.authority_key_epoch
        || signed.0.signer_key != context.trust.authority_key
        || !signed
            .0
            .verify_signature()
            .map_err(|error| FactorError::Canonicalization(error.to_string()))?
    {
        return Err(FactorError::AuthorityVerification);
    }
    let lifetime = body
        .expires_at_unix_ms
        .checked_sub(body.issued_at_unix_ms)
        .ok_or(FactorError::NotCurrent)?;
    if lifetime > context.trust.max_lifetime_ms {
        return Err(FactorError::NotCurrent);
    }
    let verified = VerifiedAssignmentBindAuthorizationV1 {
        body_digest: domain_digest(AUTHORIZATION_BODY_DIGEST_DOMAIN, body)?,
        envelope_digest: sha256_hex(canonical_authorization),
        canonical_bytes: canonical_authorization.to_vec(),
        signed,
    };
    verified.ensure_current(context.trusted_now_unix_ms)?;
    Ok(verified)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentAgreementBodyV1 {
    schema: String,
    agreement_id: String,
    operation_id: String,
    normalized_request_digest: String,
    obligation_id: String,
    obligation_atom_digest: String,
    claim_id: String,
    claim_digest: String,
    offer_id: String,
    offer_digest: String,
    seller_id: String,
    buyer_id: String,
    buyer_settlement_destination_ref: String,
    agreed_discount_bps: u16,
    agreed_price: MonetaryAmount,
    assignment_authority_digest: String,
    expected_disposition_version: u64,
    expected_disposition_lifecycle_fence: u64,
    expected_settlement_lifecycle_version: u64,
    expected_settlement_lifecycle_fence: u64,
    effective_at_unix_ms: u64,
    due_at_unix_ms: u64,
}

impl AssignmentAgreementBodyV1 {
    pub fn new(
        agreement_id: String,
        operation_id: String,
        request: &NormalizedAssignmentRequestV1,
        claim: &ReceivableClaimV1,
        offer: &AssignmentOfferV1,
        authorization: &VerifiedAssignmentBindAuthorizationV1,
    ) -> Result<Self, FactorError> {
        request.validate()?;
        claim.validate()?;
        offer.validate()?;
        if request.claim_digest() != claim.digest()?
            || request.offer_digest() != offer.digest()?
            || claim.claim_id() != offer.claim_id()
            || claim.digest()? != offer.claim_digest()
            || request.obligation_id() != claim.obligation_id()
            || request.obligation_atom_digest() != claim.obligation_atom_digest()
            || request.seller_id() != claim.seller_id()
            || request.seller_id() != offer.seller_id()
            || request.due_at_unix_ms() != claim.due_at_unix_ms()
            || request.effective_at_unix_ms() >= offer.expires_at_unix_ms()
            || request.agreed_discount_bps() > offer.asking_discount_bps()
            || request.agreed_price()
                != &discounted_amount(claim.face_value(), request.agreed_discount_bps())?
            || request.agreed_price().units < offer.minimum_price().units
            || authorization.body().agreement_id() != agreement_id
            || authorization.body().operation_id() != operation_id
            || authorization.body().normalized_request_digest() != request.digest()?
            || authorization.body().obligation_atom_digest() != request.obligation_atom_digest()
            || authorization.body().seller_id() != request.seller_id()
            || authorization.body().buyer_id() != request.buyer_id()
            || authorization.body().buyer_settlement_destination_ref()
                != request.buyer_settlement_destination_ref()
            || authorization.body().effective_at_unix_ms() != request.effective_at_unix_ms()
            || authorization.body().action_nonce() != request.action_nonce()
        {
            return Err(FactorError::BindingMismatch);
        }
        let body = Self {
            schema: FACTOR_ASSIGNMENT_AGREEMENT_SCHEMA.to_owned(),
            agreement_id,
            operation_id,
            normalized_request_digest: request.digest()?,
            obligation_id: request.obligation_id().to_owned(),
            obligation_atom_digest: request.obligation_atom_digest().to_owned(),
            claim_id: claim.claim_id().to_owned(),
            claim_digest: claim.digest()?,
            offer_id: offer.offer_id().to_owned(),
            offer_digest: offer.digest()?,
            seller_id: request.seller_id().to_owned(),
            buyer_id: request.buyer_id().to_owned(),
            buyer_settlement_destination_ref: request.buyer_settlement_destination_ref().to_owned(),
            agreed_discount_bps: request.agreed_discount_bps(),
            agreed_price: request.agreed_price().clone(),
            assignment_authority_digest: authorization.envelope_digest().to_owned(),
            expected_disposition_version: request.expected_disposition_version(),
            expected_disposition_lifecycle_fence: request.expected_disposition_lifecycle_fence(),
            expected_settlement_lifecycle_version: request.expected_settlement_lifecycle_version(),
            expected_settlement_lifecycle_fence: request.expected_settlement_lifecycle_fence(),
            effective_at_unix_ms: request.effective_at_unix_ms(),
            due_at_unix_ms: request.due_at_unix_ms(),
        };
        body.validate_against_artifacts(request, claim, offer)?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_ASSIGNMENT_AGREEMENT_SCHEMA {
            return Err(FactorError::InvalidField("agreement_schema"));
        }
        for (field, value) in [
            ("operation_id", &self.operation_id),
            ("normalized_request_digest", &self.normalized_request_digest),
            ("obligation_id", &self.obligation_id),
            ("obligation_atom_digest", &self.obligation_atom_digest),
            ("claim_id", &self.claim_id),
            ("claim_digest", &self.claim_digest),
            ("offer_id", &self.offer_id),
            ("offer_digest", &self.offer_digest),
            (
                "assignment_authority_digest",
                &self.assignment_authority_digest,
            ),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("agreement_id", &self.agreement_id),
            ("seller_id", &self.seller_id),
            ("buyer_id", &self.buyer_id),
            (
                "buyer_settlement_destination_ref",
                &self.buyer_settlement_destination_ref,
            ),
        ] {
            validate_text(field, value)?;
        }
        validate_basis_points(self.agreed_discount_bps)?;
        validate_amount("agreed_price", &self.agreed_price, true)?;
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
        ] {
            validate_positive(field, value)?;
        }
        if self.seller_id == self.buyer_id
            || self.expected_disposition_version != self.expected_disposition_lifecycle_fence
            || self.expected_settlement_lifecycle_version
                != self.expected_settlement_lifecycle_fence
            || self.effective_at_unix_ms >= self.due_at_unix_ms
        {
            return Err(FactorError::InvalidField("agreement_terms"));
        }
        Ok(())
    }

    pub fn validate_against_request(
        &self,
        request: &NormalizedAssignmentRequestV1,
    ) -> Result<(), FactorError> {
        self.validate()?;
        request.validate()?;
        if self.normalized_request_digest != request.digest()?
            || self.obligation_id != request.obligation_id()
            || self.obligation_atom_digest != request.obligation_atom_digest()
            || self.claim_digest != request.claim_digest()
            || self.offer_digest != request.offer_digest()
            || self.seller_id != request.seller_id()
            || self.buyer_id != request.buyer_id()
            || self.buyer_settlement_destination_ref != request.buyer_settlement_destination_ref()
            || self.agreed_discount_bps != request.agreed_discount_bps()
            || self.agreed_price != *request.agreed_price()
            || self.expected_disposition_version != request.expected_disposition_version()
            || self.expected_disposition_lifecycle_fence
                != request.expected_disposition_lifecycle_fence()
            || self.expected_settlement_lifecycle_version
                != request.expected_settlement_lifecycle_version()
            || self.expected_settlement_lifecycle_fence
                != request.expected_settlement_lifecycle_fence()
            || self.effective_at_unix_ms != request.effective_at_unix_ms()
            || self.due_at_unix_ms != request.due_at_unix_ms()
        {
            return Err(FactorError::BindingMismatch);
        }
        Ok(())
    }

    pub fn validate_against_artifacts(
        &self,
        request: &NormalizedAssignmentRequestV1,
        claim: &ReceivableClaimV1,
        offer: &AssignmentOfferV1,
    ) -> Result<(), FactorError> {
        self.validate_against_request(request)?;
        claim.validate()?;
        offer.validate()?;
        if self.claim_id != claim.claim_id()
            || self.claim_digest != claim.digest()?
            || self.offer_id != offer.offer_id()
            || self.offer_digest != offer.digest()?
            || claim.claim_id() != offer.claim_id()
            || claim.digest()? != offer.claim_digest()
            || request.obligation_id() != claim.obligation_id()
            || request.obligation_atom_digest() != claim.obligation_atom_digest()
            || request.seller_id() != claim.seller_id()
            || request.seller_id() != offer.seller_id()
            || request.due_at_unix_ms() != claim.due_at_unix_ms()
            || request.effective_at_unix_ms() >= offer.expires_at_unix_ms()
            || request.agreed_discount_bps() > offer.asking_discount_bps()
            || request.agreed_price()
                != &discounted_amount(claim.face_value(), request.agreed_discount_bps())?
            || request.agreed_price().units < offer.minimum_price().units
        {
            return Err(FactorError::BindingMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, FactorError> {
        self.validate()?;
        domain_digest(AGREEMENT_BODY_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn agreement_id(&self) -> &str {
        &self.agreement_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn normalized_request_digest(&self) -> &str {
        &self.normalized_request_digest
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
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    #[must_use]
    pub fn claim_digest(&self) -> &str {
        &self.claim_digest
    }

    #[must_use]
    pub fn offer_id(&self) -> &str {
        &self.offer_id
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
    pub fn assignment_authority_digest(&self) -> &str {
        &self.assignment_authority_digest
    }

    #[must_use]
    pub const fn agreed_discount_bps(&self) -> u16 {
        self.agreed_discount_bps
    }

    #[must_use]
    pub const fn agreed_price(&self) -> &MonetaryAmount {
        &self.agreed_price
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
    pub const fn effective_at_unix_ms(&self) -> u64 {
        self.effective_at_unix_ms
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentAgreementSignatureV1 {
    party_id: String,
    party_key_epoch: u64,
    signer_key: PublicKey,
    signature: Signature,
}

impl AssignmentAgreementSignatureV1 {
    fn sign(
        body: &AssignmentAgreementBodyV1,
        party_id: String,
        party_key_epoch: u64,
        signer: &Keypair,
    ) -> Result<Self, FactorError> {
        validate_text("agreement_party_id", &party_id)?;
        validate_positive("agreement_party_key_epoch", party_key_epoch)?;
        let (signature, _) = signer
            .sign_canonical(body)
            .map_err(|error| FactorError::Canonicalization(error.to_string()))?;
        Ok(Self {
            party_id,
            party_key_epoch,
            signer_key: signer.public_key(),
            signature,
        })
    }

    fn verify(&self, body: &AssignmentAgreementBodyV1) -> Result<bool, FactorError> {
        self.signer_key
            .verify_canonical(body, &self.signature)
            .map_err(|error| FactorError::Canonicalization(error.to_string()))
    }

    fn digest(&self) -> Result<String, FactorError> {
        domain_digest(AGREEMENT_SIGNATURE_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn party_id(&self) -> &str {
        &self.party_id
    }

    #[must_use]
    pub const fn party_key_epoch(&self) -> u64 {
        self.party_key_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAssignmentAgreementV1 {
    body: AssignmentAgreementBodyV1,
    seller_signature: AssignmentAgreementSignatureV1,
    buyer_signature: AssignmentAgreementSignatureV1,
}

impl SignedAssignmentAgreementV1 {
    pub fn sign(
        body: AssignmentAgreementBodyV1,
        seller_key_epoch: u64,
        seller: &Keypair,
        buyer_key_epoch: u64,
        buyer: &Keypair,
    ) -> Result<Self, FactorError> {
        body.validate()?;
        if seller.public_key() == buyer.public_key() {
            return Err(FactorError::InvalidField("agreement_party_keys"));
        }
        let seller_signature = AssignmentAgreementSignatureV1::sign(
            &body,
            body.seller_id.clone(),
            seller_key_epoch,
            seller,
        )?;
        let buyer_signature = AssignmentAgreementSignatureV1::sign(
            &body,
            body.buyer_id.clone(),
            buyer_key_epoch,
            buyer,
        )?;
        Ok(Self {
            body,
            seller_signature,
            buyer_signature,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        canonical_bytes(self)
    }

    #[must_use]
    pub const fn body(&self) -> &AssignmentAgreementBodyV1 {
        &self.body
    }

    #[must_use]
    pub const fn seller_signature(&self) -> &AssignmentAgreementSignatureV1 {
        &self.seller_signature
    }

    #[must_use]
    pub const fn buyer_signature(&self) -> &AssignmentAgreementSignatureV1 {
        &self.buyer_signature
    }
}

#[derive(Debug, Clone)]
pub struct AssignmentAgreementTrustV1 {
    seller_id: String,
    seller_key: PublicKey,
    seller_key_epoch: u64,
    buyer_id: String,
    buyer_key: PublicKey,
    buyer_key_epoch: u64,
}

impl AssignmentAgreementTrustV1 {
    pub fn new(
        seller_id: String,
        seller_key: PublicKey,
        seller_key_epoch: u64,
        buyer_id: String,
        buyer_key: PublicKey,
        buyer_key_epoch: u64,
    ) -> Result<Self, FactorError> {
        validate_text("trusted_seller_id", &seller_id)?;
        validate_positive("trusted_seller_key_epoch", seller_key_epoch)?;
        validate_text("trusted_buyer_id", &buyer_id)?;
        validate_positive("trusted_buyer_key_epoch", buyer_key_epoch)?;
        if seller_id == buyer_id || seller_key == buyer_key {
            return Err(FactorError::InvalidField("trusted_agreement_parties"));
        }
        Ok(Self {
            seller_id,
            seller_key,
            seller_key_epoch,
            buyer_id,
            buyer_key,
            buyer_key_epoch,
        })
    }

    #[must_use]
    pub fn seller_id(&self) -> &str {
        &self.seller_id
    }

    #[must_use]
    pub const fn seller_key_epoch(&self) -> u64 {
        self.seller_key_epoch
    }

    #[must_use]
    pub const fn seller_key(&self) -> &PublicKey {
        &self.seller_key
    }

    #[must_use]
    pub fn buyer_id(&self) -> &str {
        &self.buyer_id
    }

    #[must_use]
    pub const fn buyer_key_epoch(&self) -> u64 {
        self.buyer_key_epoch
    }

    #[must_use]
    pub const fn buyer_key(&self) -> &PublicKey {
        &self.buyer_key
    }
}

pub struct AssignmentAgreementVerificationV1<'a> {
    pub operation_id: &'a str,
    pub normalized_request_digest: &'a str,
    pub assignment_authority_digest: &'a str,
    pub trust: &'a AssignmentAgreementTrustV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssignmentAgreementV1 {
    signed: SignedAssignmentAgreementV1,
    body_digest: String,
    seller_signature_digest: String,
    buyer_signature_digest: String,
    artifact_digest: String,
    canonical_bytes: Vec<u8>,
}

impl VerifiedAssignmentAgreementV1 {
    #[must_use]
    pub const fn body(&self) -> &AssignmentAgreementBodyV1 {
        &self.signed.body
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn seller_signature_digest(&self) -> &str {
        &self.seller_signature_digest
    }

    #[must_use]
    pub fn buyer_signature_digest(&self) -> &str {
        &self.buyer_signature_digest
    }

    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn seller_key_epoch(&self) -> u64 {
        self.signed.seller_signature.party_key_epoch
    }

    #[must_use]
    pub const fn buyer_key_epoch(&self) -> u64 {
        self.signed.buyer_signature.party_key_epoch
    }
}

pub fn verify_assignment_agreement(
    canonical_agreement: &[u8],
    context: &AssignmentAgreementVerificationV1<'_>,
) -> Result<VerifiedAssignmentAgreementV1, FactorError> {
    let signed: SignedAssignmentAgreementV1 =
        parse_canonical(canonical_agreement, "assignment agreement")?;
    signed.body.validate()?;
    let seller = &signed.seller_signature;
    let buyer = &signed.buyer_signature;
    if signed.body.operation_id != context.operation_id
        || signed.body.normalized_request_digest != context.normalized_request_digest
        || signed.body.assignment_authority_digest != context.assignment_authority_digest
        || signed.body.seller_id != context.trust.seller_id
        || seller.party_id != context.trust.seller_id
        || seller.party_key_epoch != context.trust.seller_key_epoch
        || seller.signer_key != context.trust.seller_key
        || signed.body.buyer_id != context.trust.buyer_id
        || buyer.party_id != context.trust.buyer_id
        || buyer.party_key_epoch != context.trust.buyer_key_epoch
        || buyer.signer_key != context.trust.buyer_key
        || seller.signer_key == buyer.signer_key
    {
        return Err(FactorError::BindingMismatch);
    }
    if !seller.verify(&signed.body)? || !buyer.verify(&signed.body)? {
        return Err(FactorError::AuthorityVerification);
    }
    Ok(VerifiedAssignmentAgreementV1 {
        body_digest: signed.body.digest()?,
        seller_signature_digest: seller.digest()?,
        buyer_signature_digest: buyer.digest()?,
        artifact_digest: sha256_hex(canonical_agreement),
        canonical_bytes: canonical_agreement.to_vec(),
        signed,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationSetPreimage<'a> {
    schema: &'static str,
    operation_id: &'a str,
    normalized_request_digest: &'a str,
    bind_authorization_body_digest: &'a str,
    bind_authorization_envelope_digest: &'a str,
    agreement_body_digest: &'a str,
    seller_signature_digest: &'a str,
    buyer_signature_digest: &'a str,
    agreement_artifact_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssignmentAuthorizationSetV1 {
    bind_authorization: VerifiedAssignmentBindAuthorizationV1,
    agreement: VerifiedAssignmentAgreementV1,
    set_digest: String,
}

impl VerifiedAssignmentAuthorizationSetV1 {
    pub fn new(
        bind_authorization: VerifiedAssignmentBindAuthorizationV1,
        agreement: VerifiedAssignmentAgreementV1,
    ) -> Result<Self, FactorError> {
        let authorization_body = bind_authorization.body();
        let agreement_body = agreement.body();
        if authorization_body.operation_id != agreement_body.operation_id
            || authorization_body.normalized_request_digest
                != agreement_body.normalized_request_digest
            || authorization_body.obligation_atom_digest != agreement_body.obligation_atom_digest
            || authorization_body.seller_id != agreement_body.seller_id
            || authorization_body.buyer_id != agreement_body.buyer_id
            || authorization_body.agreement_id != agreement_body.agreement_id
            || authorization_body.buyer_settlement_destination_ref
                != agreement_body.buyer_settlement_destination_ref
            || authorization_body.effective_at_unix_ms != agreement_body.effective_at_unix_ms
            || bind_authorization.envelope_digest != agreement_body.assignment_authority_digest
        {
            return Err(FactorError::BindingMismatch);
        }
        let set_digest = domain_digest(
            AUTHORIZATION_SET_DIGEST_DOMAIN,
            &AuthorizationSetPreimage {
                schema: "chio.factor.assignment-authorization-set.v1",
                operation_id: authorization_body.operation_id(),
                normalized_request_digest: authorization_body.normalized_request_digest(),
                bind_authorization_body_digest: bind_authorization.body_digest(),
                bind_authorization_envelope_digest: bind_authorization.envelope_digest(),
                agreement_body_digest: agreement.body_digest(),
                seller_signature_digest: agreement.seller_signature_digest(),
                buyer_signature_digest: agreement.buyer_signature_digest(),
                agreement_artifact_digest: agreement.artifact_digest(),
            },
        )?;
        Ok(Self {
            bind_authorization,
            agreement,
            set_digest,
        })
    }

    #[must_use]
    pub const fn body(&self) -> &AssignmentBindAuthorizationBodyV1 {
        self.bind_authorization.body()
    }

    #[must_use]
    pub const fn bind_authorization(&self) -> &VerifiedAssignmentBindAuthorizationV1 {
        &self.bind_authorization
    }

    #[must_use]
    pub const fn agreement(&self) -> &VerifiedAssignmentAgreementV1 {
        &self.agreement
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.set_digest
    }

    pub fn validate_submission(
        &self,
        request: &NormalizedAssignmentRequestV1,
        claim: &ReceivableClaimV1,
        offer: &AssignmentOfferV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FactorError> {
        self.validate_submission_binding(request, claim, offer)?;
        self.ensure_current(trusted_now_unix_ms)?;
        if trusted_now_unix_ms < request.effective_at_unix_ms()
            || trusted_now_unix_ms >= request.expires_at_unix_ms()
            || trusted_now_unix_ms >= offer.expires_at_unix_ms()
            || trusted_now_unix_ms >= request.due_at_unix_ms()
        {
            return Err(FactorError::NotCurrent);
        }
        Ok(())
    }

    pub fn validate_submission_binding(
        &self,
        request: &NormalizedAssignmentRequestV1,
        claim: &ReceivableClaimV1,
        offer: &AssignmentOfferV1,
    ) -> Result<(), FactorError> {
        self.agreement
            .body()
            .validate_against_artifacts(request, claim, offer)?;
        let body = self.bind_authorization.body();
        if body.normalized_request_digest() != request.digest()?
            || body.obligation_atom_digest() != request.obligation_atom_digest()
            || body.seller_id() != request.seller_id()
            || body.buyer_id() != request.buyer_id()
            || body.buyer_settlement_destination_ref() != request.buyer_settlement_destination_ref()
            || body.effective_at_unix_ms() != request.effective_at_unix_ms()
            || body.action_nonce() != request.action_nonce()
        {
            return Err(FactorError::BindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn ensure_current(&self, trusted_now_unix_ms: u64) -> Result<(), FactorError> {
        self.bind_authorization.ensure_current(trusted_now_unix_ms)
    }
}
