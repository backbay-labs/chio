use chio_core::canonical::canonical_json_bytes;
#[cfg(test)]
use chio_core::crypto::Keypair;
use chio_core::crypto::{sha256_hex, PublicKey, Signature};
use chio_core::economic_continuity::EconomicTerminalResultV1;
use chio_core::receipt::body::ChioReceipt;
use serde::{Deserialize, Serialize};

use super::validation::{validate_digest, validate_positive};
use super::{ChannelError, VerifiedAdmittedChannelReservationV1};

pub const CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA: &str =
    "chio.channel.terminal-outcome-commitment.v1";

const CHANNEL_TERMINAL_OUTCOME_SIGNING_DOMAIN: &[u8] =
    b"CHIO-CHANNEL-TERMINAL-OUTCOME-COMMITMENT-V1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelTerminalOutcomeCommitmentBodyV1 {
    pub schema: String,
    pub operation_id: String,
    pub reservation_id: String,
    pub reservation_digest: String,
    pub receipt_id: String,
    pub receipt_digest: String,
    pub terminal_result: EconomicTerminalResultV1,
    pub outcome_recorded_at_unix_ms: u64,
    pub terminalized_at_unix_ms: u64,
}

impl ChannelTerminalOutcomeCommitmentBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA {
            return Err(ChannelError::InvalidField(
                "channel_terminal_outcome_schema",
            ));
        }
        validate_digest("channel_terminal_outcome_operation_id", &self.operation_id)?;
        validate_digest(
            "channel_terminal_outcome_reservation_id",
            &self.reservation_id,
        )?;
        validate_digest(
            "channel_terminal_outcome_reservation_digest",
            &self.reservation_digest,
        )?;
        super::validation::validate_text("channel_terminal_outcome_receipt_id", &self.receipt_id)?;
        validate_digest(
            "channel_terminal_outcome_receipt_digest",
            &self.receipt_digest,
        )?;
        self.terminal_result
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        validate_positive(
            "channel_terminal_outcome_recorded_at",
            self.outcome_recorded_at_unix_ms,
        )?;
        validate_positive(
            "channel_terminal_outcome_terminalized_at",
            self.terminalized_at_unix_ms,
        )?;
        if self.outcome_recorded_at_unix_ms > self.terminalized_at_unix_ms {
            return Err(ChannelError::AuthorityVerification);
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ChannelError> {
        self.validate()?;
        let canonical = canonical_json_bytes(self)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
        let mut bytes =
            Vec::with_capacity(CHANNEL_TERMINAL_OUTCOME_SIGNING_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(CHANNEL_TERMINAL_OUTCOME_SIGNING_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelTerminalOutcomeCommitmentV1 {
    pub body: ChannelTerminalOutcomeCommitmentBodyV1,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    pub kernel_key: PublicKey,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_signature")]
    pub kernel_signature: Signature,
}

impl SignedChannelTerminalOutcomeCommitmentV1 {
    #[cfg(test)]
    pub(crate) fn sign_for_test(
        reservation: &VerifiedAdmittedChannelReservationV1,
        receipt: &ChioReceipt,
        terminal_result: EconomicTerminalResultV1,
        outcome_recorded_at_unix_ms: u64,
        terminalized_at_unix_ms: u64,
        kernel_keypair: &Keypair,
    ) -> Result<Self, ChannelError> {
        let artifact = reservation.artifact();
        let body = ChannelTerminalOutcomeCommitmentBodyV1 {
            schema: CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA.to_owned(),
            operation_id: artifact.body.operation_id.clone(),
            reservation_id: artifact.body.reservation_id.clone(),
            reservation_digest: artifact.digest()?,
            receipt_id: receipt.id.clone(),
            receipt_digest: receipt_digest(receipt)?,
            terminal_result,
            outcome_recorded_at_unix_ms,
            terminalized_at_unix_ms,
        };
        let kernel_signature = kernel_keypair.sign(&body.signing_bytes()?);
        Ok(Self {
            body,
            kernel_key: kernel_keypair.public_key(),
            kernel_signature,
        })
    }

    pub fn verify_signature(&self) -> Result<(), ChannelError> {
        if self
            .kernel_key
            .verify(&self.body.signing_bytes()?, &self.kernel_signature)
        {
            Ok(())
        } else {
            Err(ChannelError::AuthorityVerification)
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedChannelTerminalOutcomeCommitmentV1 {
    artifact: SignedChannelTerminalOutcomeCommitmentV1,
}

impl VerifiedChannelTerminalOutcomeCommitmentV1 {
    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelTerminalOutcomeCommitmentV1 {
        &self.artifact
    }

    #[must_use]
    pub const fn terminal_result(&self) -> &EconomicTerminalResultV1 {
        &self.artifact.body.terminal_result
    }

    #[must_use]
    pub const fn outcome_recorded_at_unix_ms(&self) -> u64 {
        self.artifact.body.outcome_recorded_at_unix_ms
    }

    #[must_use]
    pub const fn terminalized_at_unix_ms(&self) -> u64 {
        self.artifact.body.terminalized_at_unix_ms
    }
}

pub fn verify_channel_terminal_outcome_commitment(
    artifact: &SignedChannelTerminalOutcomeCommitmentV1,
    trusted_kernel_key: &PublicKey,
    reservation: &VerifiedAdmittedChannelReservationV1,
    receipt: &ChioReceipt,
) -> Result<VerifiedChannelTerminalOutcomeCommitmentV1, ChannelError> {
    artifact.body.validate()?;
    artifact.verify_signature()?;
    let reservation = reservation.artifact();
    if &artifact.kernel_key != trusted_kernel_key
        || &receipt.kernel_key != trusted_kernel_key
        || !receipt
            .verify_signature()
            .map_err(|_| ChannelError::AuthorityVerification)?
        || artifact.body.operation_id != reservation.body.operation_id
        || artifact.body.reservation_id != reservation.body.reservation_id
        || artifact.body.reservation_digest != reservation.digest()?
        || artifact.body.receipt_id != receipt.id
        || artifact.body.receipt_digest != receipt_digest(receipt)?
        || receipt.timestamp != artifact.body.terminalized_at_unix_ms / 1_000
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelTerminalOutcomeCommitmentV1 {
        artifact: artifact.clone(),
    })
}

fn receipt_digest(receipt: &ChioReceipt) -> Result<String, ChannelError> {
    Ok(sha256_hex(&canonical_json_bytes(receipt).map_err(
        |error| ChannelError::Canonicalization(error.to_string()),
    )?))
}
