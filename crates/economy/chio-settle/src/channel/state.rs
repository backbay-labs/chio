use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, PublicKey};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::economics::{
    ChannelSettlementModeV1, SettlementStatus, CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA,
};
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, ObligationAtomV1, ObligationCreditElectionV1,
};
use serde::{Deserialize, Serialize};

use super::validation::{
    digest, parse_base_units, validate_currency, validate_digest, validate_text,
    I_JSON_MAX_SAFE_INTEGER,
};
use super::{
    ChannelError, ChannelLifecycleStatusV1, ChannelOpenTrustV1, ChannelSignatureV1,
    VerifiedAdmittedChannelReservationV1, VerifiedChannelOpenConsentV1,
};

pub const CHANNEL_STATE_SCHEMA: &str = "chio.channel.state.v1";

const CHANNEL_STATE_BODY_DIGEST_DOMAIN: &[u8] = b"chio.channel.state.body.digest.v1\0";
const CHANNEL_STATE_DIGEST_DOMAIN: &[u8] = b"chio.channel.state.digest.v1\0";
const CHANNEL_RECEIPT_ROOT_DOMAIN: &[u8] = b"chio.channel.receipt-root.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelStateBodyV1 {
    pub schema: String,
    pub channel_id: String,
    pub seq: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub prev_state_digest: Option<String>,
    pub cumulative_owed: MonetaryAmount,
    pub receipt_id_root: String,
    pub receipt_count: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub receipt_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub receipt_digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub receipt_authority_digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub obligation_atom_digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub reservation_digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub actual_charge: Option<MonetaryAmount>,
    pub cumulative_token_base_units: String,
    pub asset_binding_digest: String,
}

impl ChannelStateBodyV1 {
    pub fn initial(
        channel_id: String,
        currency: String,
        asset_binding_digest: String,
    ) -> Result<Self, ChannelError> {
        let state = Self {
            schema: CHANNEL_STATE_SCHEMA.to_owned(),
            channel_id,
            seq: 0,
            prev_state_digest: None,
            cumulative_owed: MonetaryAmount { units: 0, currency },
            receipt_id_root: empty_receipt_root()?,
            receipt_count: 0,
            receipt_id: None,
            receipt_digest: None,
            receipt_authority_digest: None,
            obligation_atom_digest: None,
            reservation_digest: None,
            actual_charge: None,
            cumulative_token_base_units: "0".to_owned(),
            asset_binding_digest,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_STATE_SCHEMA {
            return Err(ChannelError::InvalidField("channel_state_schema"));
        }
        validate_digest("state_channel_id", &self.channel_id)?;
        validate_currency(&self.cumulative_owed.currency)?;
        validate_digest("receipt_id_root", &self.receipt_id_root)?;
        validate_digest("state_asset_binding_digest", &self.asset_binding_digest)?;
        parse_base_units(&self.cumulative_token_base_units)?;
        if self.seq > I_JSON_MAX_SAFE_INTEGER || self.receipt_count > I_JSON_MAX_SAFE_INTEGER {
            return Err(ChannelError::InvalidField("channel_state_sequence"));
        }
        if self.cumulative_owed.units > I_JSON_MAX_SAFE_INTEGER {
            return Err(ChannelError::InvalidField("channel_state_amount"));
        }
        for value in [
            self.prev_state_digest.as_deref(),
            self.receipt_digest.as_deref(),
            self.receipt_authority_digest.as_deref(),
            self.obligation_atom_digest.as_deref(),
            self.reservation_digest.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest("channel_state_digest_binding", value)?;
        }
        if let Some(receipt_id) = self.receipt_id.as_deref() {
            validate_text("channel_receipt_id", receipt_id)?;
        }
        if let Some(actual_charge) = &self.actual_charge {
            validate_currency(&actual_charge.currency)?;
            if actual_charge.currency != self.cumulative_owed.currency {
                return Err(ChannelError::InvalidField("actual_charge_currency"));
            }
            if actual_charge.units > I_JSON_MAX_SAFE_INTEGER {
                return Err(ChannelError::InvalidField("actual_charge_amount"));
            }
        }
        let bindings = [
            self.prev_state_digest.is_some(),
            self.receipt_id.is_some(),
            self.receipt_digest.is_some(),
            self.receipt_authority_digest.is_some(),
            self.obligation_atom_digest.is_some(),
            self.reservation_digest.is_some(),
            self.actual_charge.is_some(),
        ];
        if self.seq == 0 {
            if self.receipt_count != 0
                || self.receipt_id_root != empty_receipt_root()?
                || self.cumulative_owed.units != 0
                || self.cumulative_token_base_units != "0"
                || bindings.into_iter().any(|present| present)
            {
                return Err(ChannelError::InvalidField("initial_channel_state"));
            }
        } else {
            let required = [
                self.prev_state_digest.is_some(),
                self.receipt_id.is_some(),
                self.receipt_digest.is_some(),
                self.receipt_authority_digest.is_some(),
                self.reservation_digest.is_some(),
                self.actual_charge.is_some(),
            ];
            let obligation_matches_charge = self
                .actual_charge
                .as_ref()
                .is_some_and(|charge| (charge.units == 0) == self.obligation_atom_digest.is_none());
            if self.receipt_count != self.seq
                || required.into_iter().any(|present| !present)
                || !obligation_matches_charge
            {
                return Err(ChannelError::InvalidField("channel_state_binding"));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(CHANNEL_STATE_BODY_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelStateV1 {
    pub body: ChannelStateBodyV1,
    pub payee_signature: ChannelSignatureV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelStateV1 {
    body: ChannelStateBodyV1,
    payee_signature: Option<ChannelSignatureV1>,
}

impl VerifiedChannelStateV1 {
    pub(super) fn initial(body: ChannelStateBodyV1) -> Self {
        Self {
            body,
            payee_signature: None,
        }
    }

    #[must_use]
    pub const fn body(&self) -> &ChannelStateBodyV1 {
        &self.body
    }

    #[must_use]
    pub const fn payee_signature(&self) -> Option<&ChannelSignatureV1> {
        self.payee_signature.as_ref()
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        match &self.payee_signature {
            Some(payee_signature) => SignedChannelStateV1 {
                body: self.body.clone(),
                payee_signature: payee_signature.clone(),
            }
            .digest(),
            None => self.body.digest(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelReceiptBindingV1 {
    channel_id: String,
    open_digest: String,
    reservation_digest: String,
    sequence: u64,
    receipt_id: String,
    receipt_digest: String,
    receipt_authority_digest: String,
    receipt_timestamp_unix_ms: u64,
    obligation_atom_id: Option<String>,
    obligation_atom_digest: Option<String>,
    obligation_atom: Option<ObligationAtomV1>,
    actual_charge: MonetaryAmount,
}

impl VerifiedChannelReceiptBindingV1 {
    #[must_use]
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    #[must_use]
    pub fn open_digest(&self) -> &str {
        &self.open_digest
    }

    #[must_use]
    pub fn reservation_digest(&self) -> &str {
        &self.reservation_digest
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
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
    pub fn receipt_authority_digest(&self) -> &str {
        &self.receipt_authority_digest
    }

    #[must_use]
    pub const fn receipt_timestamp_unix_ms(&self) -> u64 {
        self.receipt_timestamp_unix_ms
    }

    #[must_use]
    pub fn obligation_atom_id(&self) -> Option<&str> {
        self.obligation_atom_id.as_deref()
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> Option<&str> {
        self.obligation_atom_digest.as_deref()
    }

    #[must_use]
    pub const fn obligation_atom(&self) -> Option<&ObligationAtomV1> {
        self.obligation_atom.as_ref()
    }

    #[must_use]
    pub const fn actual_charge(&self) -> &MonetaryAmount {
        &self.actual_charge
    }
}

pub fn derive_channel_receipt_authority_digest(
    kernel_key: &PublicKey,
) -> Result<String, ChannelError> {
    digest(b"chio.channel.receipt-authority.digest.v1\0", kernel_key)
}

pub fn derive_channel_payee_binding_digest(
    payee_id: &str,
    settlement_destination_ref: &str,
) -> Result<String, ChannelError> {
    validate_text("channel_payee_id", payee_id)?;
    super::validation::validate_evm_address(
        "channel_payee_destination",
        settlement_destination_ref,
    )?;
    derive_obligation_payee_binding_digest(payee_id, settlement_destination_ref)
        .map_err(|_| ChannelError::AuthorityVerification)
}

pub fn verify_channel_receipt_binding(
    receipt: &ChioReceipt,
    trusted_kernel_key: &PublicKey,
    reservation: &VerifiedAdmittedChannelReservationV1,
    open: &VerifiedChannelOpenConsentV1,
    obligation: Option<&ObligationAtomV1>,
) -> Result<VerifiedChannelReceiptBindingV1, ChannelError> {
    let reservation = reservation.artifact();
    let intent = open.intent();
    let open_artifact = open.artifact();
    let receipt_digest = sha256_hex(
        &canonical_json_bytes(receipt)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    );
    let receipt_authority_digest = derive_channel_receipt_authority_digest(trusted_kernel_key)?;
    let receipt_timestamp_unix_ms = receipt
        .timestamp
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let metadata = receipt
        .channel_metadata()
        .ok_or(ChannelError::AuthorityVerification)?;
    let financial = receipt
        .financial_metadata()
        .ok_or(ChannelError::AuthorityVerification)?;
    let actual_charge = MonetaryAmount {
        units: financial.cost_charged,
        currency: financial.currency.clone(),
    };
    let terminal_settlement_matches = if actual_charge.units == 0 {
        (receipt.is_allowed() || receipt.is_denied())
            && financial.settlement_status == SettlementStatus::NotApplicable
    } else {
        receipt.is_allowed() && financial.settlement_status == SettlementStatus::Pending
    };
    validate_currency(&actual_charge.currency)?;
    if !metadata.is_valid()
        || actual_charge.units > I_JSON_MAX_SAFE_INTEGER
        || &receipt.kernel_key != trusted_kernel_key
        || !receipt
            .verify_signature()
            .map_err(|_| ChannelError::AuthorityVerification)?
        || reservation.body.receipt_authority_digest != receipt_authority_digest
        || reservation.body.channel_id != open_artifact.body.channel_id
        || reservation.body.open_digest != open_artifact.digest()?
        || metadata.schema != CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA
        || metadata.channel_id != reservation.body.channel_id
        || metadata.open_digest != reservation.body.open_digest
        || metadata.reservation_id != reservation.body.reservation_id
        || metadata.reservation_digest != reservation.digest()?
        || metadata.sequence != reservation.body.next_sequence
        || metadata.settlement_mode != ChannelSettlementModeV1::Channelized
        || !terminal_settlement_matches
        || financial.payment_reference.is_some()
        || actual_charge.currency != reservation.body.maximum_charge.currency
        || actual_charge.units > reservation.body.maximum_charge.units
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let (obligation_atom_id, obligation_atom_digest) = match (actual_charge.units, obligation) {
        (0, None) => (None, None),
        (0, Some(_)) | (_, None) => return Err(ChannelError::AuthorityVerification),
        (_, Some(atom)) => {
            atom.validate()
                .map_err(|_| ChannelError::AuthorityVerification)?;
            let reservation_digest = reservation.digest()?;
            let reservation_proposal_digest = reservation.body.proposal_digest()?;
            let payee_binding_digest = derive_channel_payee_binding_digest(
                &intent.body.payee_id,
                &intent.body.payee_beneficiary_address,
            )?;
            if atom.source_receipt_id() != receipt.id
                || atom.economic_intent_digest() != reservation_proposal_digest
                || atom.source_receipt_digest() != receipt_digest
                || atom.amount() != &actual_charge
                || atom.debtor_id() != intent.body.payer_id
                || atom.original_creditor_id() != intent.body.payee_id
                || atom.original_settlement_destination_ref()
                    != intent.body.payee_beneficiary_address
                || atom.payee_binding_digest() != payee_binding_digest
                || atom.pre_action_authority_digest() != reservation_digest
                || atom.credit_election() != &ObligationCreditElectionV1::NotCredit
            {
                return Err(ChannelError::AuthorityVerification);
            }
            (
                Some(atom.obligation_id().to_owned()),
                Some(
                    atom.digest()
                        .map_err(|_| ChannelError::AuthorityVerification)?,
                ),
            )
        }
    };
    Ok(VerifiedChannelReceiptBindingV1 {
        channel_id: metadata.channel_id,
        open_digest: metadata.open_digest,
        reservation_digest: metadata.reservation_digest,
        sequence: metadata.sequence,
        receipt_id: receipt.id.clone(),
        receipt_digest,
        receipt_authority_digest,
        receipt_timestamp_unix_ms,
        obligation_atom_id,
        obligation_atom_digest,
        obligation_atom: obligation.cloned(),
        actual_charge,
    })
}

pub fn build_channel_state_transition(
    prior: &VerifiedChannelStateV1,
    reservation: &VerifiedAdmittedChannelReservationV1,
    receipt: &VerifiedChannelReceiptBindingV1,
    open: &VerifiedChannelOpenConsentV1,
) -> Result<ChannelStateBodyV1, ChannelError> {
    let prior_digest = prior.digest()?;
    let prior = prior.body();
    let reservation = reservation.artifact();
    let intent = open.intent();
    prior.validate()?;
    reservation.body.validate()?;
    intent.body.validate()?;
    let body = &reservation.body;
    let sequence = next_sequence(prior.seq)?;
    let reservation_digest = reservation.digest()?;
    let open_digest = open.artifact().digest()?;
    let cumulative_units = prior
        .cumulative_owed
        .units
        .checked_add(receipt.actual_charge.units)
        .filter(|units| *units <= I_JSON_MAX_SAFE_INTEGER)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let cumulative_owed = MonetaryAmount {
        units: cumulative_units,
        currency: intent.body.currency.clone(),
    };
    let cumulative_token_base_units = intent
        .body
        .asset_binding
        .token_base_units(&cumulative_owed)?;
    let actual_token_base_units = intent
        .body
        .asset_binding
        .token_base_units(&receipt.actual_charge)?;
    if receipt.channel_id != body.channel_id
        || receipt.open_digest != open_digest
        || receipt.reservation_digest != reservation_digest
        || receipt.sequence != body.next_sequence
        || body.channel_id != prior.channel_id
        || body.prior_state_digest != prior_digest
        || body.next_sequence != sequence
        || body.receipt_authority_digest != receipt.receipt_authority_digest
        || body.maximum_charge.currency != receipt.actual_charge.currency
        || receipt.actual_charge.currency != intent.body.currency
        || receipt.actual_charge.units > body.maximum_charge.units
        || parse_base_units(&actual_token_base_units)?
            > parse_base_units(&body.maximum_token_base_units)?
        || cumulative_units > intent.body.bound.units
        || parse_base_units(&cumulative_token_base_units)?
            > parse_base_units(&intent.body.bound_token_base_units)?
        || prior.asset_binding_digest != intent.body.asset_binding.digest()?
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let state = ChannelStateBodyV1 {
        schema: CHANNEL_STATE_SCHEMA.to_owned(),
        channel_id: prior.channel_id.clone(),
        seq: sequence,
        prev_state_digest: Some(prior_digest),
        cumulative_owed,
        receipt_id_root: append_receipt_root(&prior.receipt_id_root, &receipt.receipt_id)?,
        receipt_count: next_sequence(prior.receipt_count)?,
        receipt_id: Some(receipt.receipt_id.clone()),
        receipt_digest: Some(receipt.receipt_digest.clone()),
        receipt_authority_digest: Some(receipt.receipt_authority_digest.clone()),
        obligation_atom_digest: receipt.obligation_atom_digest.clone(),
        reservation_digest: Some(reservation_digest),
        actual_charge: Some(receipt.actual_charge.clone()),
        cumulative_token_base_units,
        asset_binding_digest: prior.asset_binding_digest.clone(),
    };
    state.validate()?;
    Ok(state)
}

pub fn verify_channel_state_transition(
    state: &SignedChannelStateV1,
    prior: &VerifiedChannelStateV1,
    reservation: &VerifiedAdmittedChannelReservationV1,
    receipt: &VerifiedChannelReceiptBindingV1,
    open: &VerifiedChannelOpenConsentV1,
    trust: &ChannelOpenTrustV1,
) -> Result<VerifiedChannelStateV1, ChannelError> {
    let lifecycle = reservation.snapshot().lifecycle();
    lifecycle.validate()?;
    trust.validate()?;
    if !trust.matches_intent(&open.intent().body) {
        return Err(ChannelError::AuthorityVerification);
    }
    let prior_digest = prior.digest()?;
    let expected_state_version = reservation
        .artifact()
        .body
        .channel_state_expected_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_fence = reservation
        .artifact()
        .body
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    if lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.channel_id != open.artifact().body.channel_id
        || lifecycle.latest_state_digest != prior_digest
        || lifecycle.latest_sequence != prior.body().seq
        || lifecycle.state_version != expected_state_version
        || lifecycle.lifecycle_fence != expected_fence
        || lifecycle.live_reservation_id.as_deref()
            != Some(&reservation.artifact().body.reservation_id)
        || lifecycle.operation_id.as_deref() != Some(&reservation.artifact().body.operation_id)
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let expected = build_channel_state_transition(prior, reservation, receipt, open)?;
    state.body.validate()?;
    state.payee_signature.verify(
        &state.body,
        &trust.payee_id,
        trust.payee_key_epoch,
        &trust.payee_key,
    )?;
    if state.body != expected {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelStateV1 {
        body: state.body.clone(),
        payee_signature: Some(state.payee_signature.clone()),
    })
}

pub(super) fn verify_retained_signed_channel_state(
    state: &SignedChannelStateV1,
    open: &VerifiedChannelOpenConsentV1,
    trust: &ChannelOpenTrustV1,
) -> Result<VerifiedChannelStateV1, ChannelError> {
    state.body.validate()?;
    trust.validate()?;
    state.payee_signature.verify(
        &state.body,
        &trust.payee_id,
        trust.payee_key_epoch,
        &trust.payee_key,
    )?;
    let intent = &open.intent().body;
    if !trust.matches_intent(intent)
        || state.body.seq == 0
        || state.body.channel_id != open.artifact().body.channel_id
        || state.body.cumulative_owed.currency != intent.currency
        || state.body.cumulative_owed.units > intent.bound.units
        || state.body.asset_binding_digest != intent.asset_binding.digest()?
        || parse_base_units(&state.body.cumulative_token_base_units)?
            > parse_base_units(&intent.bound_token_base_units)?
    {
        return Err(ChannelError::AuthorityVerification);
    }
    intent.asset_binding.verify_round_trip(
        &state.body.cumulative_owed,
        &state.body.cumulative_token_base_units,
    )?;
    Ok(VerifiedChannelStateV1 {
        body: state.body.clone(),
        payee_signature: Some(state.payee_signature.clone()),
    })
}

impl SignedChannelStateV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(CHANNEL_STATE_DIGEST_DOMAIN, self)
    }
}

pub fn empty_receipt_root() -> Result<String, ChannelError> {
    digest(CHANNEL_RECEIPT_ROOT_DOMAIN, &Vec::<String>::new())
}

pub fn append_receipt_root(prior_root: &str, receipt_id: &str) -> Result<String, ChannelError> {
    validate_digest("prior_receipt_root", prior_root)?;
    validate_text("channel_receipt_id", receipt_id)?;
    digest(CHANNEL_RECEIPT_ROOT_DOMAIN, &(prior_root, receipt_id))
}

pub(super) fn next_sequence(value: u64) -> Result<u64, ChannelError> {
    value
        .checked_add(1)
        .filter(|value| *value <= I_JSON_MAX_SAFE_INTEGER)
        .ok_or(ChannelError::ArithmeticOverflow)
}
