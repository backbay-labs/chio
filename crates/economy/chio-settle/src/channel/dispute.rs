use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};

use super::validation::{
    digest, validate_digest, validate_positive, validate_text, I_JSON_MAX_SAFE_INTEGER,
};
use super::{
    ChannelError, ChannelSignatureV1, SignedChannelStateV1, VerifiedChannelCloseV1,
    VerifiedChannelStateV1,
};

pub const CHANNEL_DISPUTE_SCHEMA: &str = "chio.channel.dispute.v1";

const CHANNEL_STATE_CHAIN_DIGEST_DOMAIN: &[u8] = b"chio.channel.state-chain.digest.v1\0";
const CHANNEL_DISPUTE_ID_DOMAIN: &[u8] = b"chio.channel.dispute.id.v1\0";
const CHANNEL_DISPUTE_DIGEST_DOMAIN: &[u8] = b"chio.channel.dispute.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelStateChainProofV1 {
    pub base_state_digest: String,
    pub states: Vec<SignedChannelStateV1>,
}

impl ChannelStateChainProofV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        validate_digest("chain_base_state_digest", &self.base_state_digest)?;
        if self.states.is_empty() {
            return Err(ChannelError::InvalidField("channel_state_chain"));
        }
        digest(CHANNEL_STATE_CHAIN_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelStateChainV1 {
    proof: ChannelStateChainProofV1,
    terminal_state: VerifiedChannelStateV1,
}

impl VerifiedChannelStateChainV1 {
    #[must_use]
    pub const fn proof(&self) -> &ChannelStateChainProofV1 {
        &self.proof
    }

    #[must_use]
    pub const fn terminal_state(&self) -> &VerifiedChannelStateV1 {
        &self.terminal_state
    }
}

pub fn build_channel_state_chain(
    base: &VerifiedChannelStateV1,
    descendants: &[VerifiedChannelStateV1],
) -> Result<VerifiedChannelStateChainV1, ChannelError> {
    if descendants.is_empty() {
        return Err(ChannelError::InvalidField("channel_state_chain"));
    }
    let base_state_digest = base.digest()?;
    let mut prior_state_digest = base_state_digest.clone();
    let mut prior_channel_id = base.body().channel_id.clone();
    let mut prior_sequence = base.body().seq;
    let mut states = Vec::with_capacity(descendants.len());
    for descendant in descendants {
        let body = descendant.body();
        let expected_sequence = prior_sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        let signature = descendant
            .payee_signature()
            .ok_or(ChannelError::AuthorityVerification)?;
        if body.channel_id != prior_channel_id
            || body.seq != expected_sequence
            || body.prev_state_digest.as_deref() != Some(&prior_state_digest)
        {
            return Err(ChannelError::AuthorityVerification);
        }
        states.push(SignedChannelStateV1 {
            body: body.clone(),
            payee_signature: signature.clone(),
        });
        prior_state_digest = descendant.digest()?;
        prior_channel_id.clone_from(&body.channel_id);
        prior_sequence = body.seq;
    }
    let proof = ChannelStateChainProofV1 {
        base_state_digest,
        states,
    };
    proof.digest()?;
    let terminal_state = descendants
        .last()
        .cloned()
        .ok_or(ChannelError::InvalidField("channel_state_chain"))?;
    Ok(VerifiedChannelStateChainV1 {
        proof,
        terminal_state,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelDisputeBodyV1 {
    pub schema: String,
    pub dispute_id: String,
    pub channel_id: String,
    pub close_digest: String,
    pub close_state_digest: String,
    pub close_state_sequence: u64,
    pub competing_state_digest: String,
    pub competing_state_sequence: u64,
    pub state_chain_proof_digest: String,
    pub reason: String,
    pub submitted_at_unix_ms: u64,
}

impl ChannelDisputeBodyV1 {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.schema != CHANNEL_DISPUTE_SCHEMA {
            return Err(ChannelError::InvalidField("channel_dispute_schema"));
        }
        for (field, value) in [
            ("channel_dispute_id", &self.dispute_id),
            ("dispute_channel_id", &self.channel_id),
            ("dispute_close_digest", &self.close_digest),
            ("dispute_close_state_digest", &self.close_state_digest),
            (
                "dispute_competing_state_digest",
                &self.competing_state_digest,
            ),
            (
                "dispute_state_chain_proof_digest",
                &self.state_chain_proof_digest,
            ),
        ] {
            validate_digest(field, value)?;
        }
        validate_text("channel_dispute_reason", &self.reason)?;
        validate_positive("channel_dispute_submitted_at", self.submitted_at_unix_ms)?;
        if self.close_state_sequence > I_JSON_MAX_SAFE_INTEGER
            || self.competing_state_sequence > I_JSON_MAX_SAFE_INTEGER
            || self.competing_state_sequence <= self.close_state_sequence
        {
            return Err(ChannelError::InvalidField("channel_dispute_sequence"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelDisputeV1 {
    pub body: ChannelDisputeBodyV1,
    pub submitter_signature: ChannelSignatureV1,
}

impl SignedChannelDisputeV1 {
    pub fn digest(&self) -> Result<String, ChannelError> {
        self.body.validate()?;
        digest(CHANNEL_DISPUTE_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDisputeSubmitterV1 {
    pub submitter_id: String,
    pub submitter_key_epoch: u64,
    pub submitter_key: PublicKey,
    pub trusted_time_unix_ms: u64,
}

impl ChannelDisputeSubmitterV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        validate_text("channel_dispute_submitter_id", &self.submitter_id)?;
        validate_positive(
            "channel_dispute_submitter_key_epoch",
            self.submitter_key_epoch,
        )?;
        validate_positive("channel_dispute_trusted_time", self.trusted_time_unix_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelDisputeV1 {
    dispute: SignedChannelDisputeV1,
    chain: VerifiedChannelStateChainV1,
}

impl VerifiedChannelDisputeV1 {
    #[must_use]
    pub const fn artifact(&self) -> &SignedChannelDisputeV1 {
        &self.dispute
    }

    #[must_use]
    pub const fn chain(&self) -> &VerifiedChannelStateChainV1 {
        &self.chain
    }
}

pub fn derive_channel_dispute_id(
    close_digest: &str,
    competing_state_digest: &str,
) -> Result<String, ChannelError> {
    validate_digest("dispute_close_digest", close_digest)?;
    validate_digest("dispute_competing_state_digest", competing_state_digest)?;
    digest(
        CHANNEL_DISPUTE_ID_DOMAIN,
        &(close_digest, competing_state_digest),
    )
}

pub fn build_channel_dispute_body(
    close: &VerifiedChannelCloseV1,
    chain: &VerifiedChannelStateChainV1,
    reason: String,
    submitted_at_unix_ms: u64,
) -> Result<ChannelDisputeBodyV1, ChannelError> {
    let close_digest = close.artifact().digest()?;
    let competing_state_digest = chain.terminal_state().digest()?;
    let competing_state = chain.terminal_state().body();
    let body = ChannelDisputeBodyV1 {
        schema: CHANNEL_DISPUTE_SCHEMA.to_owned(),
        dispute_id: derive_channel_dispute_id(&close_digest, &competing_state_digest)?,
        channel_id: close.artifact().body.channel_id.clone(),
        close_digest,
        close_state_digest: close.artifact().body.final_state_digest.clone(),
        close_state_sequence: close.artifact().body.final_state_sequence,
        competing_state_digest,
        competing_state_sequence: competing_state.seq,
        state_chain_proof_digest: chain.proof().digest()?,
        reason,
        submitted_at_unix_ms,
    };
    if chain.proof().base_state_digest != body.close_state_digest {
        return Err(ChannelError::AuthorityVerification);
    }
    body.validate()?;
    Ok(body)
}

pub fn verify_channel_dispute(
    dispute: &SignedChannelDisputeV1,
    close: &VerifiedChannelCloseV1,
    chain: &VerifiedChannelStateChainV1,
    submitter: &ChannelDisputeSubmitterV1,
) -> Result<VerifiedChannelDisputeV1, ChannelError> {
    dispute.body.validate()?;
    submitter.validate()?;
    dispute.submitter_signature.verify(
        &dispute.body,
        &submitter.submitter_id,
        submitter.submitter_key_epoch,
        &submitter.submitter_key,
    )?;
    let expected = build_channel_dispute_body(
        close,
        chain,
        dispute.body.reason.clone(),
        dispute.body.submitted_at_unix_ms,
    )?;
    if dispute.body != expected
        || dispute.body.submitted_at_unix_ms > submitter.trusted_time_unix_ms
        || submitter.trusted_time_unix_ms >= close.artifact().body.dispute_deadline_unix_ms
    {
        return Err(ChannelError::AuthorityVerification);
    }
    Ok(VerifiedChannelDisputeV1 {
        dispute: dispute.clone(),
        chain: chain.clone(),
    })
}
