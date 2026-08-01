use chio_core::capability::scope::MonetaryAmount;
use chio_core::federation::frost::{
    FrostActionPreimageV1, FrostChannelCloseActionV1, CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA,
};
use serde::{Deserialize, Serialize};

use super::validation::{
    digest, parse_base_units, validate_currency, validate_digest, validate_positive,
    I_JSON_MAX_SAFE_INTEGER,
};
use super::{
    ChannelError, ChannelEscrowReservationStatusV1, ChannelLifecycleStatusV1, ChannelOpenTrustV1,
    ChannelSignatureV1, VerifiedChannelDisputeV1, VerifiedChannelLifecycleSnapshotV1,
    VerifiedChannelOpenConsentV1, VerifiedChannelStateV1,
};

pub const CHANNEL_CLOSE_SCHEMA: &str = "chio.channel.close.v1";

const CHANNEL_CLOSE_BODY_DIGEST_DOMAIN: &[u8] = b"chio.channel.close.body.digest.v1\0";
const CHANNEL_CLOSE_DIGEST_DOMAIN: &[u8] = b"chio.channel.close.digest.v1\0";
const CHANNEL_EFFECTIVE_CLOSE_DIGEST_DOMAIN: &[u8] = b"chio.channel.effective-close.digest.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelCloseKindV1 {
    Cooperative,
    Contested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelCloseBodyV1 {
    pub schema: String,
    pub channel_id: String,
    pub open_digest: String,
    pub close_kind: ChannelCloseKindV1,
    pub final_state_digest: String,
    pub final_state_sequence: u64,
    pub final_cumulative_owed: MonetaryAmount,
    pub expected_release_token_base_units: String,
    pub expected_refund_after_release_token_base_units: String,
    pub dispute_window_secs: u64,
    pub proposed_at_unix_ms: u64,
    pub dispute_deadline_unix_ms: u64,
    pub close_submission_cutoff_unix_secs: u64,
    pub channel_state_version: u64,
    pub escrow_reservation_version: u64,
    pub lifecycle_fence: u64,
}

impl ChannelCloseBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_CLOSE_SCHEMA {
            return Err(ChannelError::InvalidField("channel_close_schema"));
        }
        for (field, value) in [
            ("close_channel_id", &self.channel_id),
            ("close_open_digest", &self.open_digest),
            ("close_final_state_digest", &self.final_state_digest),
        ] {
            validate_digest(field, value)?;
        }
        validate_currency(&self.final_cumulative_owed.currency)?;
        if self.final_state_sequence > I_JSON_MAX_SAFE_INTEGER
            || self.final_cumulative_owed.units > I_JSON_MAX_SAFE_INTEGER
        {
            return Err(ChannelError::InvalidField("channel_close_amount"));
        }
        parse_base_units(&self.expected_release_token_base_units)?;
        parse_base_units(&self.expected_refund_after_release_token_base_units)?;
        for (field, value) in [
            ("close_dispute_window", self.dispute_window_secs),
            ("close_proposed_at", self.proposed_at_unix_ms),
            ("close_dispute_deadline", self.dispute_deadline_unix_ms),
            (
                "close_submission_cutoff",
                self.close_submission_cutoff_unix_secs,
            ),
            ("close_channel_state_version", self.channel_state_version),
            (
                "close_escrow_reservation_version",
                self.escrow_reservation_version,
            ),
            ("close_lifecycle_fence", self.lifecycle_fence),
        ] {
            validate_positive(field, value)?;
        }
        if self.dispute_deadline_unix_ms <= self.proposed_at_unix_ms {
            return Err(ChannelError::InvalidField("close_dispute_deadline"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(CHANNEL_CLOSE_BODY_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelCloseV1 {
    pub body: ChannelCloseBodyV1,
    pub payee_signature: ChannelSignatureV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub payer_signature: Option<ChannelSignatureV1>,
}

impl SignedChannelCloseV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(CHANNEL_CLOSE_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelCloseV1 {
    close: SignedChannelCloseV1,
    open: VerifiedChannelOpenConsentV1,
    final_state: VerifiedChannelStateV1,
    snapshot: VerifiedChannelLifecycleSnapshotV1,
}

impl VerifiedChannelCloseV1 {
    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelCloseV1 {
        &self.close
    }

    #[must_use]
    pub const fn open(&self) -> &VerifiedChannelOpenConsentV1 {
        &self.open
    }

    #[must_use]
    pub const fn final_state(&self) -> &VerifiedChannelStateV1 {
        &self.final_state
    }

    #[must_use]
    pub const fn snapshot(&self) -> &VerifiedChannelLifecycleSnapshotV1 {
        &self.snapshot
    }
}

pub fn build_channel_close_body(
    close_kind: ChannelCloseKindV1,
    open: &VerifiedChannelOpenConsentV1,
    final_state: &VerifiedChannelStateV1,
    snapshot: &VerifiedChannelLifecycleSnapshotV1,
    proposed_at_unix_ms: u64,
) -> Result<ChannelCloseBodyV1, ChannelError> {
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    lifecycle.validate()?;
    escrow.validate()?;
    let intent = open.intent();
    let final_state_digest = final_state.digest()?;
    let final_state_body = final_state.body();
    let open_digest = open.artifact().digest()?;
    if snapshot.settlement_authority_scope_id() != intent.body.settlement_authority_scope_id
        || lifecycle.status != ChannelLifecycleStatusV1::Open
        || lifecycle.channel_id != open.artifact().body.channel_id
        || lifecycle.latest_state_digest != final_state_digest
        || lifecycle.latest_sequence != final_state_body.seq
        || lifecycle.live_reservation_id.is_some()
        || lifecycle.operation_id.is_some()
        || escrow.open_digest != open_digest
        || escrow.escrow_reference != intent.body.escrow_reference
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.channel_id != lifecycle.channel_id
        || escrow.lifecycle_fence != lifecycle.lifecycle_fence
        || final_state_body.channel_id != lifecycle.channel_id
    {
        return Err(ChannelError::IllegalTransition);
    }
    let dispute_window_ms = intent
        .body
        .dispute_window_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let dispute_deadline_unix_ms = proposed_at_unix_ms
        .checked_add(dispute_window_ms)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let cutoff_unix_ms = intent
        .body
        .close_submission_cutoff_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    if dispute_deadline_unix_ms >= cutoff_unix_ms {
        return Err(ChannelError::IllegalTransition);
    }
    let expected_release_token_base_units = intent
        .body
        .asset_binding
        .token_base_units(&final_state_body.cumulative_owed)?;
    let expected_refund_after_release_token_base_units =
        parse_base_units(&intent.body.bound_token_base_units)?
            .checked_sub(parse_base_units(&expected_release_token_base_units)?)
            .ok_or(ChannelError::ArithmeticOverflow)?
            .to_string();
    let body = ChannelCloseBodyV1 {
        schema: CHANNEL_CLOSE_SCHEMA.to_owned(),
        channel_id: lifecycle.channel_id.clone(),
        open_digest,
        close_kind,
        final_state_digest,
        final_state_sequence: final_state_body.seq,
        final_cumulative_owed: final_state_body.cumulative_owed.clone(),
        expected_release_token_base_units,
        expected_refund_after_release_token_base_units,
        dispute_window_secs: intent.body.dispute_window_secs,
        proposed_at_unix_ms,
        dispute_deadline_unix_ms,
        close_submission_cutoff_unix_secs: intent.body.close_submission_cutoff_unix_secs,
        channel_state_version: lifecycle
            .state_version
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        escrow_reservation_version: escrow
            .version
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        lifecycle_fence: lifecycle
            .lifecycle_fence
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
    };
    body.validate()?;
    Ok(body)
}

pub fn verify_channel_close(
    close: &SignedChannelCloseV1,
    open: &VerifiedChannelOpenConsentV1,
    final_state: &VerifiedChannelStateV1,
    snapshot: &VerifiedChannelLifecycleSnapshotV1,
    trust: &ChannelOpenTrustV1,
) -> Result<VerifiedChannelCloseV1, ChannelError> {
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    close.body.validate()?;
    lifecycle.validate()?;
    escrow.validate()?;
    trust.validate()?;
    if !trust.matches_intent(&open.intent().body) {
        return Err(ChannelError::AuthorityVerification);
    }
    let body = &close.body;
    let close_body_digest = body.digest()?;
    let final_state_digest = final_state.digest()?;
    let final_state_body = final_state.body();
    close.payee_signature.verify(
        body,
        &trust.payee_id,
        trust.payee_key_epoch,
        &trust.payee_key,
    )?;
    if let Some(signature) = &close.payer_signature {
        signature.verify(
            body,
            &trust.payer_id,
            trust.payer_key_epoch,
            &trust.payer_key,
        )?;
    }
    let cutoff_unix_ms = body
        .close_submission_cutoff_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let dispute_deadline_unix_ms = body
        .dispute_window_secs
        .checked_mul(1_000)
        .and_then(|window| body.proposed_at_unix_ms.checked_add(window))
        .ok_or(ChannelError::ArithmeticOverflow)?;
    if snapshot.settlement_authority_scope_id() != open.intent().body.settlement_authority_scope_id
        || body.channel_id != open.artifact().body.channel_id
        || body.open_digest != open.artifact().digest()?
        || body.final_state_digest != final_state_digest
        || body.final_state_sequence != final_state_body.seq
        || body.final_cumulative_owed != final_state_body.cumulative_owed
        || body.dispute_window_secs != open.intent().body.dispute_window_secs
        || body.dispute_deadline_unix_ms != dispute_deadline_unix_ms
        || body.close_submission_cutoff_unix_secs
            != open.intent().body.close_submission_cutoff_unix_secs
        || lifecycle.status != ChannelLifecycleStatusV1::ClosePending
        || lifecycle.channel_id != body.channel_id
        || lifecycle.latest_state_digest != body.final_state_digest
        || lifecycle.latest_sequence != body.final_state_sequence
        || lifecycle.state_version != body.channel_state_version
        || lifecycle.lifecycle_fence != body.lifecycle_fence
        || lifecycle.pending_close_body_digest.as_deref() != Some(&close_body_digest)
        || lifecycle.admitted_dispute_digest.is_some()
        || lifecycle.live_reservation_id.is_some()
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.channel_id != body.channel_id
        || escrow.open_digest != body.open_digest
        || escrow.escrow_reference != open.intent().body.escrow_reference
        || escrow.version != body.escrow_reservation_version
        || escrow.lifecycle_fence != body.lifecycle_fence
        || escrow.pending_close_body_digest.as_deref() != Some(&close_body_digest)
        || body.proposed_at_unix_ms != trust.trusted_time_unix_ms
        || snapshot.observed_at_unix_ms() < body.proposed_at_unix_ms
        || snapshot.observed_at_unix_ms() >= body.dispute_deadline_unix_ms
        || body.dispute_deadline_unix_ms >= cutoff_unix_ms
        || trust.trusted_time_unix_ms > body.dispute_deadline_unix_ms
        || trust.trusted_time_unix_ms >= cutoff_unix_ms
        || body.close_kind == ChannelCloseKindV1::Cooperative && close.payer_signature.is_none()
    {
        return Err(ChannelError::AuthorityVerification);
    }
    open.intent().body.asset_binding.verify_round_trip(
        &body.final_cumulative_owed,
        &body.expected_release_token_base_units,
    )?;
    let expected_refund = parse_base_units(&open.intent().body.bound_token_base_units)?
        .checked_sub(parse_base_units(&body.expected_release_token_base_units)?)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    if expected_refund.to_string() != body.expected_refund_after_release_token_base_units {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelCloseV1 {
        close: close.clone(),
        open: open.clone(),
        final_state: final_state.clone(),
        snapshot: snapshot.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct VerifiedEffectiveChannelCloseV1 {
    close: VerifiedChannelCloseV1,
    effective_state: VerifiedChannelStateV1,
    snapshot: VerifiedChannelLifecycleSnapshotV1,
    admitted_dispute_digest: Option<String>,
    expected_release_token_base_units: String,
    expected_refund_after_release_token_base_units: String,
    effective_close_digest: String,
}

impl VerifiedEffectiveChannelCloseV1 {
    #[must_use]
    pub const fn close(&self) -> &VerifiedChannelCloseV1 {
        &self.close
    }

    #[must_use]
    pub const fn effective_state(&self) -> &VerifiedChannelStateV1 {
        &self.effective_state
    }

    #[must_use]
    pub const fn snapshot(&self) -> &VerifiedChannelLifecycleSnapshotV1 {
        &self.snapshot
    }

    #[must_use]
    pub fn admitted_dispute_digest(&self) -> Option<&str> {
        self.admitted_dispute_digest.as_deref()
    }

    #[must_use]
    pub fn expected_release_token_base_units(&self) -> &str {
        &self.expected_release_token_base_units
    }

    #[must_use]
    pub fn expected_refund_after_release_token_base_units(&self) -> &str {
        &self.expected_refund_after_release_token_base_units
    }

    #[must_use]
    pub fn effective_close_digest(&self) -> &str {
        &self.effective_close_digest
    }
}

pub fn verify_effective_channel_close(
    close: &VerifiedChannelCloseV1,
) -> Result<VerifiedEffectiveChannelCloseV1, ChannelError> {
    let body = &close.artifact().body;
    let lifecycle = close.snapshot().lifecycle();
    let escrow = close.snapshot().escrow();
    if lifecycle.state_version != body.channel_state_version
        || escrow.version != body.escrow_reservation_version
        || lifecycle.lifecycle_fence != body.lifecycle_fence
        || close.final_state().digest()? != body.final_state_digest
    {
        return Err(ChannelError::AuthorityVerification);
    }
    effective_close_from_authority(close, close.final_state(), close.snapshot(), None)
}

pub fn verify_effective_channel_dispute_advance(
    current: &VerifiedEffectiveChannelCloseV1,
    dispute: &VerifiedChannelDisputeV1,
    next_snapshot: &VerifiedChannelLifecycleSnapshotV1,
) -> Result<VerifiedEffectiveChannelCloseV1, ChannelError> {
    let close = current.close();
    let close_digest = close.artifact().digest()?;
    let close_body_digest = close.artifact().body.digest()?;
    let chain = dispute.chain();
    let terminal_state = chain.terminal_state();
    let terminal_digest = terminal_state.digest()?;
    let dispute_digest = dispute.artifact().digest()?;
    let current_digest = current.effective_state().digest()?;
    let current_sequence = current.effective_state().body().seq;
    let current_on_chain = if current_sequence == close.artifact().body.final_state_sequence {
        chain.proof().base_state_digest == current_digest
    } else {
        chain.proof().states.iter().any(|state| {
            state.body.seq == current_sequence
                && state.digest().is_ok_and(|digest| digest == current_digest)
        })
    };
    let lifecycle = next_snapshot.lifecycle();
    let escrow = next_snapshot.escrow();
    let current_lifecycle = current.snapshot().lifecycle();
    let current_escrow = current.snapshot().escrow();
    let expected_state_version = current_lifecycle
        .state_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_escrow_version = current_escrow
        .version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let expected_fence = current_lifecycle
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let dispute_body = &dispute.artifact().body;
    if dispute_body.close_digest != close_digest
        || chain.proof().base_state_digest != close.artifact().body.final_state_digest
        || !current_on_chain
        || terminal_state.body().seq <= current_sequence
        || dispute_body.competing_state_digest != terminal_digest
        || dispute_body.competing_state_sequence != terminal_state.body().seq
        || lifecycle.status != ChannelLifecycleStatusV1::ClosePending
        || lifecycle.latest_state_digest != terminal_digest
        || lifecycle.latest_sequence != terminal_state.body().seq
        || lifecycle.state_version != expected_state_version
        || lifecycle.lifecycle_fence != expected_fence
        || lifecycle.pending_close_body_digest.as_deref() != Some(close_body_digest.as_str())
        || lifecycle.admitted_dispute_digest.as_deref() != Some(dispute_digest.as_str())
        || lifecycle.live_reservation_id.is_some()
        || lifecycle.operation_id.is_some()
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.version != expected_escrow_version
        || escrow.lifecycle_fence != expected_fence
        || escrow.pending_close_body_digest.as_deref() != Some(close_body_digest.as_str())
        || next_snapshot.settlement_authority_scope_id()
            != current.snapshot().settlement_authority_scope_id()
        || next_snapshot.observed_at_unix_ms() < current.snapshot().observed_at_unix_ms()
        || next_snapshot.observed_at_unix_ms() < dispute_body.submitted_at_unix_ms
        || next_snapshot.observed_at_unix_ms() >= close.artifact().body.dispute_deadline_unix_ms
        || current
            .snapshot()
            .channel_head()
            .validate_successor(next_snapshot.channel_head())
            .is_err()
        || current
            .snapshot()
            .escrow_head()
            .validate_successor(next_snapshot.escrow_head())
            .is_err()
    {
        return Err(ChannelError::AuthorityVerification);
    }
    effective_close_from_authority(close, terminal_state, next_snapshot, Some(dispute_digest))
}

fn effective_close_from_authority(
    close: &VerifiedChannelCloseV1,
    effective_state: &VerifiedChannelStateV1,
    snapshot: &VerifiedChannelLifecycleSnapshotV1,
    admitted_dispute_digest: Option<String>,
) -> Result<VerifiedEffectiveChannelCloseV1, ChannelError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct EffectiveCloseDigestBody<'a> {
        close_digest: &'a str,
        close_body_digest: &'a str,
        effective_state_digest: &'a str,
        effective_state_sequence: u64,
        final_cumulative_owed: &'a MonetaryAmount,
        expected_release_token_base_units: &'a str,
        expected_refund_after_release_token_base_units: &'a str,
        channel_state_version: u64,
        escrow_reservation_version: u64,
        lifecycle_fence: u64,
        checkpoint_digest: &'a str,
        channel_head_digest: &'a str,
        escrow_head_digest: &'a str,
        observed_at_unix_ms: u64,
        admitted_dispute_digest: Option<&'a str>,
    }

    let open = close.open();
    let close_body = &close.artifact().body;
    let close_digest = close.artifact().digest()?;
    let close_body_digest = close_body.digest()?;
    let effective_state_digest = effective_state.digest()?;
    let effective_state_body = effective_state.body();
    let lifecycle = snapshot.lifecycle();
    let escrow = snapshot.escrow();
    if snapshot.settlement_authority_scope_id() != open.intent().body.settlement_authority_scope_id
        || lifecycle.status != ChannelLifecycleStatusV1::ClosePending
        || lifecycle.channel_id != close_body.channel_id
        || lifecycle.latest_state_digest != effective_state_digest
        || lifecycle.latest_sequence != effective_state_body.seq
        || lifecycle.pending_close_body_digest.as_deref() != Some(close_body_digest.as_str())
        || lifecycle.admitted_dispute_digest.as_deref() != admitted_dispute_digest.as_deref()
        || lifecycle.live_reservation_id.is_some()
        || lifecycle.operation_id.is_some()
        || escrow.status != ChannelEscrowReservationStatusV1::Open
        || escrow.channel_id != close_body.channel_id
        || escrow.open_digest != close_body.open_digest
        || escrow.escrow_reference != open.intent().body.escrow_reference
        || escrow.lifecycle_fence != lifecycle.lifecycle_fence
        || escrow.pending_close_body_digest.as_deref() != Some(close_body_digest.as_str())
        || effective_state_body.channel_id != close_body.channel_id
        || effective_state_body.cumulative_owed.currency != open.intent().body.currency
        || effective_state_body.cumulative_owed.units > open.intent().body.bound.units
    {
        return Err(ChannelError::AuthorityVerification);
    }
    let expected_release_token_base_units = open
        .intent()
        .body
        .asset_binding
        .token_base_units(&effective_state_body.cumulative_owed)?;
    open.intent().body.asset_binding.verify_round_trip(
        &effective_state_body.cumulative_owed,
        &expected_release_token_base_units,
    )?;
    let expected_refund_after_release_token_base_units =
        parse_base_units(&open.intent().body.bound_token_base_units)?
            .checked_sub(parse_base_units(&expected_release_token_base_units)?)
            .ok_or(ChannelError::ArithmeticOverflow)?
            .to_string();
    let effective_close_digest = digest(
        CHANNEL_EFFECTIVE_CLOSE_DIGEST_DOMAIN,
        &EffectiveCloseDigestBody {
            close_digest: &close_digest,
            close_body_digest: &close_body_digest,
            effective_state_digest: &effective_state_digest,
            effective_state_sequence: effective_state_body.seq,
            final_cumulative_owed: &effective_state_body.cumulative_owed,
            expected_release_token_base_units: &expected_release_token_base_units,
            expected_refund_after_release_token_base_units:
                &expected_refund_after_release_token_base_units,
            channel_state_version: lifecycle.state_version,
            escrow_reservation_version: escrow.version,
            lifecycle_fence: lifecycle.lifecycle_fence,
            checkpoint_digest: snapshot.checkpoint_digest(),
            channel_head_digest: snapshot.channel_head_digest(),
            escrow_head_digest: snapshot.escrow_head_digest(),
            observed_at_unix_ms: snapshot.observed_at_unix_ms(),
            admitted_dispute_digest: admitted_dispute_digest.as_deref(),
        },
    )?;
    Ok(VerifiedEffectiveChannelCloseV1 {
        close: close.clone(),
        effective_state: effective_state.clone(),
        snapshot: snapshot.clone(),
        admitted_dispute_digest,
        expected_release_token_base_units,
        expected_refund_after_release_token_base_units,
        effective_close_digest,
    })
}

pub fn channel_close_frost_action(
    close: &VerifiedEffectiveChannelCloseV1,
    publisher_fence: u64,
) -> Result<FrostActionPreimageV1, ChannelError> {
    validate_positive("close_publisher_fence", publisher_fence)?;
    let body = &close.close().artifact().body;
    let state = close.effective_state().body();
    let lifecycle = close.snapshot().lifecycle();
    let escrow = close.snapshot().escrow();
    let action = FrostActionPreimageV1::ChannelClose(FrostChannelCloseActionV1 {
        schema: CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA.to_owned(),
        close_body_digest: body.digest()?,
        effective_close_digest: close.effective_close_digest().to_owned(),
        channel_id: body.channel_id.clone(),
        final_state_digest: close.effective_state().digest()?,
        final_state_sequence: state.seq,
        final_cumulative_owed: state.cumulative_owed.clone(),
        channel_state_version: lifecycle.state_version,
        escrow_reservation_version: escrow.version,
        token_base_unit_release: close.expected_release_token_base_units().to_owned(),
        publisher_fence,
        lifecycle_fence: lifecycle.lifecycle_fence,
    });
    action
        .validate()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    Ok(action)
}
