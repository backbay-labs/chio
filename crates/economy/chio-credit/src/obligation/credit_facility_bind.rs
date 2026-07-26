use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey, Signature};
pub use chio_core_types::CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    derive_obligation_payee_binding_digest, validate_digest, validate_money, validate_text,
    validate_time,
};

pub const CREDIT_FACILITY_BIND_SCHEMA: &str = CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA;

const BIND_ID_DOMAIN: &[u8] = b"chio.credit.facility-bind.id.v1\0";
const BIND_SCOPE_DOMAIN: &[u8] = b"chio.credit.facility-bind.scope.v1\0";
const BIND_BODY_DIGEST_DOMAIN: &[u8] = b"chio.credit.facility-bind.body.v1\0";
const BIND_SIGNATURE_DIGEST_DOMAIN: &[u8] = b"chio.credit.facility-bind.signature.v1\0";
const BIND_TRUST_CONFIGURATION_DOMAIN: &[u8] =
    b"chio.credit.facility-bind.trust-configuration.v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CreditFacilityBindError {
    #[error("invalid credit facility bind field `{0}`")]
    InvalidField(&'static str),
    #[error("credit facility bind does not match `{0}`")]
    BindingMismatch(&'static str),
    #[error("credit facility bind signature verification failed")]
    SignatureVerification,
    #[error("credit facility bind is not current")]
    NotCurrent,
    #[error("credit facility bind canonicalization failed: {0}")]
    Canonicalization(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditFacilityBindInputV1 {
    pub operation_id: String,
    pub request_id: String,
    pub economic_intent_digest: String,
    pub facility_id: String,
    pub facility_artifact_digest: String,
    pub authority_set_digest: String,
    pub debtor_id: String,
    pub original_creditor_id: String,
    pub original_settlement_destination_ref: String,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub amount: MonetaryAmount,
    pub effective_ceiling: MonetaryAmount,
    pub expected_exposure_version: u64,
    pub expected_exposure_fence: u64,
    pub due_at_unix_ms: u64,
    pub action_nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub authority_id: String,
    pub authority_key_epoch: u64,
    pub debtor_key_epoch: u64,
    pub creditor_key_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditFacilityBindBodyV1 {
    schema: String,
    bind_id: String,
    operation_id: String,
    request_id: String,
    economic_intent_digest: String,
    scope_digest: String,
    facility_id: String,
    facility_artifact_digest: String,
    authority_set_digest: String,
    debtor_id: String,
    original_creditor_id: String,
    original_settlement_destination_ref: String,
    payee_binding_digest: String,
    capability_id: String,
    tool_server: String,
    tool_name: String,
    amount: MonetaryAmount,
    effective_ceiling: MonetaryAmount,
    expected_exposure_version: u64,
    expected_exposure_fence: u64,
    due_at_unix_ms: u64,
    action_nonce: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    authority_id: String,
    authority_key_epoch: u64,
    debtor_key_epoch: u64,
    creditor_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreditFacilityScopePreimageV1<'a> {
    debtor_id: &'a str,
    capability_id: &'a str,
    tool_server: &'a str,
    tool_name: &'a str,
    currency: &'a str,
}

impl CreditFacilityBindBodyV1 {
    pub fn new(input: CreditFacilityBindInputV1) -> Result<Self, CreditFacilityBindError> {
        let scope_digest = credit_facility_scope_digest(
            &input.debtor_id,
            &input.capability_id,
            &input.tool_server,
            &input.tool_name,
            &input.amount.currency,
        )?;
        let payee_binding_digest = derive_obligation_payee_binding_digest(
            &input.original_creditor_id,
            &input.original_settlement_destination_ref,
        )
        .map_err(|error| CreditFacilityBindError::Canonicalization(error.to_string()))?;
        let mut body = Self {
            schema: CREDIT_FACILITY_BIND_SCHEMA.to_owned(),
            bind_id: String::new(),
            operation_id: input.operation_id,
            request_id: input.request_id,
            economic_intent_digest: input.economic_intent_digest,
            scope_digest,
            facility_id: input.facility_id,
            facility_artifact_digest: input.facility_artifact_digest,
            authority_set_digest: input.authority_set_digest,
            debtor_id: input.debtor_id,
            original_creditor_id: input.original_creditor_id,
            original_settlement_destination_ref: input.original_settlement_destination_ref,
            payee_binding_digest,
            capability_id: input.capability_id,
            tool_server: input.tool_server,
            tool_name: input.tool_name,
            amount: input.amount,
            effective_ceiling: input.effective_ceiling,
            expected_exposure_version: input.expected_exposure_version,
            expected_exposure_fence: input.expected_exposure_fence,
            due_at_unix_ms: input.due_at_unix_ms,
            action_nonce: input.action_nonce,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
            authority_id: input.authority_id,
            authority_key_epoch: input.authority_key_epoch,
            debtor_key_epoch: input.debtor_key_epoch,
            creditor_key_epoch: input.creditor_key_epoch,
        };
        body.bind_id = body.derived_bind_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), CreditFacilityBindError> {
        if self.schema != CREDIT_FACILITY_BIND_SCHEMA {
            return Err(CreditFacilityBindError::InvalidField("schema"));
        }
        for (field, value) in [
            ("bind_id", &self.bind_id),
            ("operation_id", &self.operation_id),
            ("economic_intent_digest", &self.economic_intent_digest),
            ("scope_digest", &self.scope_digest),
            ("facility_artifact_digest", &self.facility_artifact_digest),
            ("authority_set_digest", &self.authority_set_digest),
            ("payee_binding_digest", &self.payee_binding_digest),
        ] {
            validate_digest(field, value)
                .map_err(|_| CreditFacilityBindError::InvalidField(field))?;
        }
        for (field, value) in [
            ("request_id", &self.request_id),
            ("facility_id", &self.facility_id),
            ("debtor_id", &self.debtor_id),
            ("original_creditor_id", &self.original_creditor_id),
            (
                "original_settlement_destination_ref",
                &self.original_settlement_destination_ref,
            ),
            ("capability_id", &self.capability_id),
            ("tool_server", &self.tool_server),
            ("tool_name", &self.tool_name),
            ("action_nonce", &self.action_nonce),
            ("authority_id", &self.authority_id),
        ] {
            validate_text(field, value)
                .map_err(|_| CreditFacilityBindError::InvalidField(field))?;
        }
        validate_money(&self.amount)
            .map_err(|_| CreditFacilityBindError::InvalidField("amount"))?;
        validate_money(&self.effective_ceiling)
            .map_err(|_| CreditFacilityBindError::InvalidField("effective_ceiling"))?;
        for (field, value) in [
            ("expected_exposure_version", self.expected_exposure_version),
            ("expected_exposure_fence", self.expected_exposure_fence),
            ("due_at_unix_ms", self.due_at_unix_ms),
            ("issued_at_unix_ms", self.issued_at_unix_ms),
            ("expires_at_unix_ms", self.expires_at_unix_ms),
            ("authority_key_epoch", self.authority_key_epoch),
            ("debtor_key_epoch", self.debtor_key_epoch),
            ("creditor_key_epoch", self.creditor_key_epoch),
        ] {
            validate_time(field, value)
                .map_err(|_| CreditFacilityBindError::InvalidField(field))?;
        }
        if self.debtor_id == self.original_creditor_id
            || self.authority_id == self.debtor_id
            || self.authority_id == self.original_creditor_id
            || self.amount.currency != self.effective_ceiling.currency
            || self.amount.units > self.effective_ceiling.units
            || self.issued_at_unix_ms >= self.expires_at_unix_ms
            || self.expires_at_unix_ms > self.due_at_unix_ms
        {
            return Err(CreditFacilityBindError::InvalidField("terms"));
        }
        let expected_scope = credit_facility_scope_digest(
            &self.debtor_id,
            &self.capability_id,
            &self.tool_server,
            &self.tool_name,
            &self.amount.currency,
        )?;
        let expected_payee = derive_obligation_payee_binding_digest(
            &self.original_creditor_id,
            &self.original_settlement_destination_ref,
        )
        .map_err(|error| CreditFacilityBindError::Canonicalization(error.to_string()))?;
        if self.scope_digest != expected_scope
            || self.payee_binding_digest != expected_payee
            || self.bind_id != self.derived_bind_id()?
        {
            return Err(CreditFacilityBindError::InvalidField("derived_binding"));
        }
        Ok(())
    }

    fn derived_bind_id(&self) -> Result<String, CreditFacilityBindError> {
        let mut preimage = self.clone();
        preimage.bind_id.clear();
        bind_domain_digest(BIND_ID_DOMAIN, &preimage)
    }

    pub fn body_digest(&self) -> Result<String, CreditFacilityBindError> {
        self.validate()?;
        bind_domain_digest(BIND_BODY_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn bind_id(&self) -> &str {
        &self.bind_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn economic_intent_digest(&self) -> &str {
        &self.economic_intent_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    #[must_use]
    pub fn facility_id(&self) -> &str {
        &self.facility_id
    }

    #[must_use]
    pub fn facility_artifact_digest(&self) -> &str {
        &self.facility_artifact_digest
    }

    #[must_use]
    pub fn authority_set_digest(&self) -> &str {
        &self.authority_set_digest
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
    pub fn capability_id(&self) -> &str {
        &self.capability_id
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
    pub const fn amount(&self) -> &MonetaryAmount {
        &self.amount
    }

    #[must_use]
    pub const fn effective_ceiling(&self) -> &MonetaryAmount {
        &self.effective_ceiling
    }

    #[must_use]
    pub const fn expected_exposure_version(&self) -> u64 {
        self.expected_exposure_version
    }

    #[must_use]
    pub const fn expected_exposure_fence(&self) -> u64 {
        self.expected_exposure_fence
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
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

    #[must_use]
    pub const fn debtor_key_epoch(&self) -> u64 {
        self.debtor_key_epoch
    }

    #[must_use]
    pub const fn creditor_key_epoch(&self) -> u64 {
        self.creditor_key_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditFacilityBindSignatureV1 {
    party_id: String,
    party_key_epoch: u64,
    signer_key: PublicKey,
    signature: Signature,
}

impl CreditFacilityBindSignatureV1 {
    fn sign(
        body: &CreditFacilityBindBodyV1,
        party_id: String,
        party_key_epoch: u64,
        signer: &Keypair,
    ) -> Result<Self, CreditFacilityBindError> {
        validate_text("signature_party_id", &party_id)
            .map_err(|_| CreditFacilityBindError::InvalidField("signature_party_id"))?;
        validate_time("signature_party_key_epoch", party_key_epoch)
            .map_err(|_| CreditFacilityBindError::InvalidField("signature_party_key_epoch"))?;
        let (signature, _) = signer
            .sign_canonical(body)
            .map_err(|error| CreditFacilityBindError::Canonicalization(error.to_string()))?;
        Ok(Self {
            party_id,
            party_key_epoch,
            signer_key: signer.public_key(),
            signature,
        })
    }

    fn verify(&self, body: &CreditFacilityBindBodyV1) -> Result<bool, CreditFacilityBindError> {
        self.signer_key
            .verify_canonical(body, &self.signature)
            .map_err(|error| CreditFacilityBindError::Canonicalization(error.to_string()))
    }

    fn digest(&self) -> Result<String, CreditFacilityBindError> {
        bind_domain_digest(BIND_SIGNATURE_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn party_id(&self) -> &str {
        &self.party_id
    }

    #[must_use]
    pub const fn party_key_epoch(&self) -> u64 {
        self.party_key_epoch
    }

    #[must_use]
    pub const fn signer_key(&self) -> &PublicKey {
        &self.signer_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCreditFacilityBindV1 {
    body: CreditFacilityBindBodyV1,
    authority_signature: CreditFacilityBindSignatureV1,
    debtor_signature: CreditFacilityBindSignatureV1,
    creditor_signature: CreditFacilityBindSignatureV1,
}

impl SignedCreditFacilityBindV1 {
    pub fn sign(
        body: CreditFacilityBindBodyV1,
        authority: &Keypair,
        debtor: &Keypair,
        creditor: &Keypair,
    ) -> Result<Self, CreditFacilityBindError> {
        body.validate()?;
        let authority_key = authority.public_key();
        let debtor_key = debtor.public_key();
        let creditor_key = creditor.public_key();
        if authority_key == debtor_key
            || authority_key == creditor_key
            || debtor_key == creditor_key
        {
            return Err(CreditFacilityBindError::InvalidField("signature_roles"));
        }
        Ok(Self {
            authority_signature: CreditFacilityBindSignatureV1::sign(
                &body,
                body.authority_id.clone(),
                body.authority_key_epoch,
                authority,
            )?,
            debtor_signature: CreditFacilityBindSignatureV1::sign(
                &body,
                body.debtor_id.clone(),
                body.debtor_key_epoch,
                debtor,
            )?,
            creditor_signature: CreditFacilityBindSignatureV1::sign(
                &body,
                body.original_creditor_id.clone(),
                body.creditor_key_epoch,
                creditor,
            )?,
            body,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CreditFacilityBindError> {
        self.body.validate()?;
        canonical_json_bytes(self)
            .map_err(|error| CreditFacilityBindError::Canonicalization(error.to_string()))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CreditFacilityBindError> {
        let signed: Self = serde_json::from_slice(bytes)
            .map_err(|error| CreditFacilityBindError::Canonicalization(error.to_string()))?;
        signed.body.validate()?;
        if signed.canonical_bytes()?.as_slice() != bytes {
            return Err(CreditFacilityBindError::Canonicalization(
                "credit facility bind is not canonical".to_owned(),
            ));
        }
        Ok(signed)
    }

    #[must_use]
    pub const fn body(&self) -> &CreditFacilityBindBodyV1 {
        &self.body
    }

    #[must_use]
    pub const fn authority_signature(&self) -> &CreditFacilityBindSignatureV1 {
        &self.authority_signature
    }

    #[must_use]
    pub const fn debtor_signature(&self) -> &CreditFacilityBindSignatureV1 {
        &self.debtor_signature
    }

    #[must_use]
    pub const fn creditor_signature(&self) -> &CreditFacilityBindSignatureV1 {
        &self.creditor_signature
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreditFacilityBindTrustConfigurationPreimageV1<'a> {
    authority_id: &'a str,
    authority_key: String,
    authority_key_epoch: u64,
    debtor_id: &'a str,
    debtor_key: String,
    debtor_key_epoch: u64,
    creditor_id: &'a str,
    creditor_key: String,
    creditor_key_epoch: u64,
    max_lifetime_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditFacilityBindTrustV1 {
    authority_id: String,
    authority_key: PublicKey,
    authority_key_epoch: u64,
    debtor_id: String,
    debtor_key: PublicKey,
    debtor_key_epoch: u64,
    creditor_id: String,
    creditor_key: PublicKey,
    creditor_key_epoch: u64,
    max_lifetime_ms: u64,
    configuration_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditFacilityBindTrustInputV1 {
    pub authority_id: String,
    pub authority_key: PublicKey,
    pub authority_key_epoch: u64,
    pub debtor_id: String,
    pub debtor_key: PublicKey,
    pub debtor_key_epoch: u64,
    pub creditor_id: String,
    pub creditor_key: PublicKey,
    pub creditor_key_epoch: u64,
    pub max_lifetime_ms: u64,
}

impl CreditFacilityBindTrustV1 {
    pub fn new(input: CreditFacilityBindTrustInputV1) -> Result<Self, CreditFacilityBindError> {
        let CreditFacilityBindTrustInputV1 {
            authority_id,
            authority_key,
            authority_key_epoch,
            debtor_id,
            debtor_key,
            debtor_key_epoch,
            creditor_id,
            creditor_key,
            creditor_key_epoch,
            max_lifetime_ms,
        } = input;
        for (field, value) in [
            ("trusted_authority_id", authority_id.as_str()),
            ("trusted_debtor_id", debtor_id.as_str()),
            ("trusted_creditor_id", creditor_id.as_str()),
        ] {
            validate_text(field, value)
                .map_err(|_| CreditFacilityBindError::InvalidField(field))?;
        }
        for (field, value) in [
            ("trusted_authority_key_epoch", authority_key_epoch),
            ("trusted_debtor_key_epoch", debtor_key_epoch),
            ("trusted_creditor_key_epoch", creditor_key_epoch),
            ("max_lifetime_ms", max_lifetime_ms),
        ] {
            validate_time(field, value)
                .map_err(|_| CreditFacilityBindError::InvalidField(field))?;
        }
        if authority_id == debtor_id
            || authority_id == creditor_id
            || debtor_id == creditor_id
            || authority_key == debtor_key
            || authority_key == creditor_key
            || debtor_key == creditor_key
        {
            return Err(CreditFacilityBindError::InvalidField("trusted_roles"));
        }
        let configuration_digest = bind_domain_digest(
            BIND_TRUST_CONFIGURATION_DOMAIN,
            &CreditFacilityBindTrustConfigurationPreimageV1 {
                authority_id: &authority_id,
                authority_key: authority_key.to_hex(),
                authority_key_epoch,
                debtor_id: &debtor_id,
                debtor_key: debtor_key.to_hex(),
                debtor_key_epoch,
                creditor_id: &creditor_id,
                creditor_key: creditor_key.to_hex(),
                creditor_key_epoch,
                max_lifetime_ms,
            },
        )?;
        Ok(Self {
            authority_id,
            authority_key,
            authority_key_epoch,
            debtor_id,
            debtor_key,
            debtor_key_epoch,
            creditor_id,
            creditor_key,
            creditor_key_epoch,
            max_lifetime_ms,
            configuration_digest,
        })
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
}

pub struct CreditFacilityBindVerificationContextV1<'a> {
    pub trust: &'a CreditFacilityBindTrustV1,
    pub trusted_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCreditFacilityBindV1 {
    signed: SignedCreditFacilityBindV1,
    body_digest: String,
    artifact_digest: String,
    authority_signature_digest: String,
    debtor_signature_digest: String,
    creditor_signature_digest: String,
    canonical_bytes: Vec<u8>,
    trust_configuration_digest: String,
}

impl VerifiedCreditFacilityBindV1 {
    #[must_use]
    pub const fn body(&self) -> &CreditFacilityBindBodyV1 {
        self.signed.body()
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    #[must_use]
    pub fn authority_signature_digest(&self) -> &str {
        &self.authority_signature_digest
    }

    #[must_use]
    pub fn debtor_signature_digest(&self) -> &str {
        &self.debtor_signature_digest
    }

    #[must_use]
    pub fn creditor_signature_digest(&self) -> &str {
        &self.creditor_signature_digest
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn trust_configuration_digest(&self) -> &str {
        &self.trust_configuration_digest
    }

    pub fn ensure_current_at(
        &self,
        trusted_at_unix_ms: u64,
    ) -> Result<(), CreditFacilityBindError> {
        if trusted_at_unix_ms < self.body().issued_at_unix_ms
            || trusted_at_unix_ms >= self.body().expires_at_unix_ms
        {
            return Err(CreditFacilityBindError::NotCurrent);
        }
        Ok(())
    }

    pub(crate) const fn signed(&self) -> &SignedCreditFacilityBindV1 {
        &self.signed
    }
}

pub fn verify_credit_facility_bind(
    canonical_bind: &[u8],
    context: &CreditFacilityBindVerificationContextV1<'_>,
) -> Result<VerifiedCreditFacilityBindV1, CreditFacilityBindError> {
    let signed = SignedCreditFacilityBindV1::from_canonical_bytes(canonical_bind)?;
    let body = signed.body();
    let trust = context.trust;
    let authority = signed.authority_signature();
    let debtor = signed.debtor_signature();
    let creditor = signed.creditor_signature();
    if body.authority_id != trust.authority_id
        || body.authority_key_epoch != trust.authority_key_epoch
        || authority.party_id != trust.authority_id
        || authority.party_key_epoch != trust.authority_key_epoch
        || authority.signer_key != trust.authority_key
        || body.debtor_id != trust.debtor_id
        || body.debtor_key_epoch != trust.debtor_key_epoch
        || debtor.party_id != trust.debtor_id
        || debtor.party_key_epoch != trust.debtor_key_epoch
        || debtor.signer_key != trust.debtor_key
        || body.original_creditor_id != trust.creditor_id
        || body.creditor_key_epoch != trust.creditor_key_epoch
        || creditor.party_id != trust.creditor_id
        || creditor.party_key_epoch != trust.creditor_key_epoch
        || creditor.signer_key != trust.creditor_key
        || !authority.verify(body)?
        || !debtor.verify(body)?
        || !creditor.verify(body)?
    {
        return Err(CreditFacilityBindError::SignatureVerification);
    }
    let lifetime = body
        .expires_at_unix_ms
        .checked_sub(body.issued_at_unix_ms)
        .ok_or(CreditFacilityBindError::NotCurrent)?;
    if lifetime > trust.max_lifetime_ms {
        return Err(CreditFacilityBindError::NotCurrent);
    }
    let verified = VerifiedCreditFacilityBindV1 {
        body_digest: body.body_digest()?,
        artifact_digest: sha256_hex(canonical_bind),
        authority_signature_digest: authority.digest()?,
        debtor_signature_digest: debtor.digest()?,
        creditor_signature_digest: creditor.digest()?,
        canonical_bytes: canonical_bind.to_vec(),
        trust_configuration_digest: trust.configuration_digest.clone(),
        signed,
    };
    verified.ensure_current_at(context.trusted_at_unix_ms)?;
    Ok(verified)
}

pub fn credit_facility_scope_digest(
    debtor_id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    currency: &str,
) -> Result<String, CreditFacilityBindError> {
    for (field, value) in [
        ("scope_debtor_id", debtor_id),
        ("scope_capability_id", capability_id),
        ("scope_tool_server", tool_server),
        ("scope_tool_name", tool_name),
    ] {
        validate_text(field, value).map_err(|_| CreditFacilityBindError::InvalidField(field))?;
    }
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(CreditFacilityBindError::InvalidField("scope_currency"));
    }
    bind_domain_digest(
        BIND_SCOPE_DOMAIN,
        &CreditFacilityScopePreimageV1 {
            debtor_id,
            capability_id,
            tool_server,
            tool_name,
            currency,
        },
    )
}

fn bind_domain_digest(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<String, CreditFacilityBindError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| CreditFacilityBindError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}
