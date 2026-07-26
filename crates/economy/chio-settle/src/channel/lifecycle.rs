use chio_core::economic_continuity::{
    EconomicContentV1, EconomicResourceHeadV1, EconomicResourceKeyV1, VerifiedEconomicStateView,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::validation::{validate_digest, validate_positive, I_JSON_MAX_SAFE_INTEGER};
use super::{ChannelError, ChannelEscrowReferenceV1};

pub const CHANNEL_LIFECYCLE_SCHEMA: &str = "chio.channel.lifecycle.v1";
pub const CHANNEL_LIFECYCLE_RESOURCE_FAMILY: &str = "channel_lifecycle";
pub const CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY: &str = "channel_escrow_reservation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelLifecycleStatusV1 {
    Open,
    ClosePending,
    Closing,
    Released,
    Refunded,
    Incident,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelLifecycleViewV1 {
    pub schema: String,
    pub channel_id: String,
    pub status: ChannelLifecycleStatusV1,
    pub latest_state_digest: String,
    pub latest_sequence: u64,
    pub state_version: u64,
    pub lifecycle_fence: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub pending_close_body_digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub admitted_dispute_digest: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub live_reservation_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub operation_id: Option<String>,
}

impl ChannelLifecycleViewV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_LIFECYCLE_SCHEMA {
            return Err(ChannelError::InvalidField("channel_lifecycle_schema"));
        }
        validate_digest("lifecycle_channel_id", &self.channel_id)?;
        validate_digest("lifecycle_latest_state_digest", &self.latest_state_digest)?;
        validate_positive("lifecycle_state_version", self.state_version)?;
        validate_positive("lifecycle_fence", self.lifecycle_fence)?;
        if self.latest_sequence > I_JSON_MAX_SAFE_INTEGER {
            return Err(ChannelError::InvalidField("lifecycle_latest_sequence"));
        }
        match (&self.live_reservation_id, &self.operation_id) {
            (Some(reservation_id), Some(operation_id)) => {
                validate_digest("lifecycle_live_reservation_id", reservation_id)?;
                validate_digest("lifecycle_operation_id", operation_id)?;
                if self.status != ChannelLifecycleStatusV1::Open {
                    return Err(ChannelError::IllegalTransition);
                }
            }
            (None, None) => {}
            _ => return Err(ChannelError::InvalidField("lifecycle_live_reservation")),
        }
        match (self.status, &self.pending_close_body_digest) {
            (
                ChannelLifecycleStatusV1::ClosePending | ChannelLifecycleStatusV1::Closing,
                Some(digest),
            ) => {
                validate_digest("lifecycle_pending_close_body_digest", digest)?;
            }
            (ChannelLifecycleStatusV1::ClosePending | ChannelLifecycleStatusV1::Closing, None) => {
                return Err(ChannelError::InvalidField("lifecycle_pending_close"));
            }
            (_, None) => {}
            (_, Some(_)) => return Err(ChannelError::InvalidField("lifecycle_pending_close")),
        }
        if let Some(digest) = &self.admitted_dispute_digest {
            validate_digest("lifecycle_admitted_dispute_digest", digest)?;
            if self.status != ChannelLifecycleStatusV1::ClosePending {
                return Err(ChannelError::InvalidField(
                    "lifecycle_admitted_dispute_digest",
                ));
            }
        }
        Ok(())
    }

    const fn lifecycle_state(&self) -> &'static str {
        match self.status {
            ChannelLifecycleStatusV1::Open => "open",
            ChannelLifecycleStatusV1::ClosePending => "close_pending",
            ChannelLifecycleStatusV1::Closing => "closing",
            ChannelLifecycleStatusV1::Released => "released",
            ChannelLifecycleStatusV1::Refunded => "refunded",
            ChannelLifecycleStatusV1::Incident => "incident",
        }
    }
}

pub const CHANNEL_ESCROW_RESERVATION_SCHEMA: &str = "chio.channel.escrow-reservation.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelEscrowReservationStatusV1 {
    Open,
    Closing,
    Released,
    Refunded,
    Incident,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelEscrowReservationViewV1 {
    pub schema: String,
    pub channel_id: String,
    pub open_digest: String,
    pub escrow_reference: ChannelEscrowReferenceV1,
    pub status: ChannelEscrowReservationStatusV1,
    pub version: u64,
    pub lifecycle_fence: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    pub pending_close_body_digest: Option<String>,
}

impl ChannelEscrowReservationViewV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_ESCROW_RESERVATION_SCHEMA {
            return Err(ChannelError::InvalidField(
                "channel_escrow_reservation_schema",
            ));
        }
        validate_digest("escrow_reservation_channel_id", &self.channel_id)?;
        validate_digest("escrow_reservation_open_digest", &self.open_digest)?;
        self.escrow_reference.validate()?;
        validate_positive("escrow_reservation_version", self.version)?;
        validate_positive("escrow_reservation_fence", self.lifecycle_fence)?;
        match (self.status, &self.pending_close_body_digest) {
            (
                ChannelEscrowReservationStatusV1::Open | ChannelEscrowReservationStatusV1::Closing,
                Some(digest),
            ) => {
                validate_digest("escrow_reservation_pending_close", digest)?;
            }
            (ChannelEscrowReservationStatusV1::Closing, None) => {
                return Err(ChannelError::InvalidField(
                    "escrow_reservation_pending_close",
                ));
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(ChannelError::InvalidField(
                    "escrow_reservation_pending_close",
                ));
            }
        }
        Ok(())
    }

    const fn lifecycle_state(&self) -> &'static str {
        match self.status {
            ChannelEscrowReservationStatusV1::Open => "open",
            ChannelEscrowReservationStatusV1::Closing => "closing",
            ChannelEscrowReservationStatusV1::Released => "released",
            ChannelEscrowReservationStatusV1::Refunded => "refunded",
            ChannelEscrowReservationStatusV1::Incident => "incident",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelLifecycleSnapshotV1 {
    lifecycle: ChannelLifecycleViewV1,
    escrow: ChannelEscrowReservationViewV1,
    settlement_authority_scope_id: String,
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    channel_head_digest: String,
    escrow_head_digest: String,
    observed_at_unix_ms: u64,
    channel_head: EconomicResourceHeadV1,
    escrow_head: EconomicResourceHeadV1,
}

impl VerifiedChannelLifecycleSnapshotV1 {
    #[must_use]
    pub const fn lifecycle(&self) -> &ChannelLifecycleViewV1 {
        &self.lifecycle
    }

    #[must_use]
    pub const fn escrow(&self) -> &ChannelEscrowReservationViewV1 {
        &self.escrow
    }

    #[must_use]
    pub fn settlement_authority_scope_id(&self) -> &str {
        &self.settlement_authority_scope_id
    }

    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    #[must_use]
    pub const fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub fn channel_head_digest(&self) -> &str {
        &self.channel_head_digest
    }

    #[must_use]
    pub fn escrow_head_digest(&self) -> &str {
        &self.escrow_head_digest
    }

    #[must_use]
    pub fn channel_predecessor_digest(&self) -> Option<&str> {
        self.channel_head.predecessor_digest.as_deref()
    }

    #[must_use]
    pub fn escrow_predecessor_digest(&self) -> Option<&str> {
        self.escrow_head.predecessor_digest.as_deref()
    }

    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    pub(super) const fn channel_head(&self) -> &EconomicResourceHeadV1 {
        &self.channel_head
    }

    pub(super) const fn escrow_head(&self) -> &EconomicResourceHeadV1 {
        &self.escrow_head
    }
}

pub fn verify_channel_lifecycle_snapshot(
    current: &VerifiedEconomicStateView,
    settlement_authority_scope_id: &str,
    channel_id: &str,
) -> Result<VerifiedChannelLifecycleSnapshotV1, ChannelError> {
    validate_digest("anchored_channel_id", channel_id)?;
    super::validation::validate_text(
        "anchored_settlement_authority_scope_id",
        settlement_authority_scope_id,
    )?;
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: settlement_authority_scope_id.to_owned(),
        resource_id: channel_id.to_owned(),
    };
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: settlement_authority_scope_id.to_owned(),
        resource_id: channel_id.to_owned(),
    };
    let channel_head = current
        .view()
        .head(&channel_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let escrow_head = current
        .view()
        .head(&escrow_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let lifecycle: ChannelLifecycleViewV1 = decode_inline(channel_head)?;
    let escrow: ChannelEscrowReservationViewV1 = decode_inline(escrow_head)?;
    lifecycle.validate()?;
    escrow.validate()?;
    if lifecycle.channel_id != channel_id
        || escrow.channel_id != channel_id
        || channel_head.resource_version != lifecycle.state_version
        || channel_head.lifecycle_fence != lifecycle.lifecycle_fence
        || channel_head.lifecycle_state != lifecycle.lifecycle_state()
        || channel_head.operation_id != lifecycle.operation_id
        || escrow_head.resource_version != escrow.version
        || escrow_head.lifecycle_fence != escrow.lifecycle_fence
        || escrow_head.lifecycle_state != escrow.lifecycle_state()
        || escrow_head.operation_id != lifecycle.operation_id
        || lifecycle.lifecycle_fence != escrow.lifecycle_fence
        || lifecycle.pending_close_body_digest != escrow.pending_close_body_digest
        || !statuses_match(lifecycle.status, escrow.status)
        || channel_head.trusted_clock_high_water > current.view().observed_at
        || escrow_head.trusted_clock_high_water > current.view().observed_at
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelLifecycleSnapshotV1 {
        lifecycle,
        escrow,
        settlement_authority_scope_id: settlement_authority_scope_id.to_owned(),
        checkpoint_sequence: current.view().checkpoint_sequence,
        checkpoint_digest: current.view().checkpoint_digest.clone(),
        channel_head_digest: channel_head
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        escrow_head_digest: escrow_head
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        observed_at_unix_ms: current.view().observed_at,
        channel_head: channel_head.clone(),
        escrow_head: escrow_head.clone(),
    })
}

fn decode_inline<T: DeserializeOwned>(head: &EconomicResourceHeadV1) -> Result<T, ChannelError> {
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err(ChannelError::AuthorityVerification);
    };
    serde_json::from_value(value.clone()).map_err(|_| ChannelError::AuthorityVerification)
}

const fn statuses_match(
    lifecycle: ChannelLifecycleStatusV1,
    escrow: ChannelEscrowReservationStatusV1,
) -> bool {
    matches!(
        (lifecycle, escrow),
        (
            ChannelLifecycleStatusV1::Open,
            ChannelEscrowReservationStatusV1::Open
        ) | (
            ChannelLifecycleStatusV1::ClosePending,
            ChannelEscrowReservationStatusV1::Open
        ) | (
            ChannelLifecycleStatusV1::Closing,
            ChannelEscrowReservationStatusV1::Closing
        ) | (
            ChannelLifecycleStatusV1::Released,
            ChannelEscrowReservationStatusV1::Released
        ) | (
            ChannelLifecycleStatusV1::Refunded,
            ChannelEscrowReservationStatusV1::Refunded
        ) | (
            ChannelLifecycleStatusV1::Incident,
            ChannelEscrowReservationStatusV1::Incident
        )
    )
}
