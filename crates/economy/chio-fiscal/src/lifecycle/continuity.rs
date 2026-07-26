use std::collections::BTreeSet;

use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    fiscal_signer_key_id, FiscalDomain, FiscalError, SignedFiscalCharter, SignedFiscalSchedule,
    VerifiedFiscalCharter, VerifiedFiscalSchedule,
};

use super::activation::{
    FiscalActivationTarget, FiscalScheduleHead, SignedFiscalActivation, VerifiedFiscalActivation,
};
use super::proposal::FiscalGenesisPolicy;
use super::readiness::{
    FiscalRuntimeAdapterRegistry, SignedFiscalRuntimeReadiness, VerifiedFiscalRuntimeReadiness,
};
use super::support::{
    all_fiscal_domains, is_digest, lifecycle_digest, require_digest, require_positive,
    require_text, signed_envelope_digest, verify_envelope, MAX_SIGNED_LIFECYCLE_BYTES,
};

pub const FISCAL_CONTINUITY_CHECKPOINT_SCHEMA: &str = "chio.fiscal.continuity-checkpoint.v1";
pub const FISCAL_CONTINUITY_CHECKPOINT_ID_DOMAIN: &str = "chio.fiscal.continuity-checkpoint.id.v1";
pub const FISCAL_CONTINUITY_ADVANCE_PROOF_SCHEMA: &str = "chio.fiscal.continuity-advance-proof.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalDomainState {
    pub domain: FiscalDomain,
    pub ever_activated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<FiscalScheduleHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_good: Option<FiscalScheduleHead>,
}

impl FiscalDomainState {
    pub fn never_activated(domain: FiscalDomain) -> Self {
        Self {
            domain,
            ever_activated: false,
            active: None,
            last_known_good: None,
        }
    }

    pub fn activated(
        domain: FiscalDomain,
        active: FiscalScheduleHead,
        last_known_good: FiscalScheduleHead,
    ) -> Result<Self, FiscalError> {
        let state = Self {
            domain,
            ever_activated: true,
            active: Some(active),
            last_known_good: Some(last_known_good),
        };
        state.validate()?;
        Ok(state)
    }

    pub(super) fn validate(&self) -> Result<(), FiscalError> {
        if self.ever_activated {
            self.active
                .as_ref()
                .ok_or(FiscalError::InvalidField("domain_state.active"))?
                .validate()?;
            self.last_known_good
                .as_ref()
                .ok_or(FiscalError::InvalidField("domain_state.last_known_good"))?
                .validate()?;
        } else if self.active.is_some() || self.last_known_good.is_some() {
            return Err(FiscalError::InvalidField("domain_state.never_activated"));
        }
        Ok(())
    }
}

fn validate_domain_states(states: &[FiscalDomainState]) -> Result<(), FiscalError> {
    if states.len() != all_fiscal_domains().len()
        || states
            .iter()
            .map(|state| state.domain)
            .ne(all_fiscal_domains())
    {
        return Err(FiscalError::InvalidField("domain_states.order"));
    }
    for state in states {
        state.validate()?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FiscalBootstrapState {
    BootstrapUnconfigured,
    CharterPinned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalAuthorityState {
    pub governing_operator_id: String,
    pub genesis_policy_id: String,
    pub genesis_policy_digest: String,
    pub current_charter_id: String,
    pub current_charter_digest: String,
    pub current_charter_sequence: u64,
    pub bootstrap_state: FiscalBootstrapState,
    pub domains: Vec<FiscalDomainState>,
    pub finalized_checkpoint_digest: String,
}

impl FiscalAuthorityState {
    pub fn genesis(
        policy: &FiscalGenesisPolicy,
        checkpoint_digest: String,
        bootstrap_state: FiscalBootstrapState,
    ) -> Result<Self, FiscalError> {
        let state = Self {
            governing_operator_id: policy.governing_operator_id.clone(),
            genesis_policy_id: policy.policy_id.clone(),
            genesis_policy_digest: policy.digest()?,
            current_charter_id: policy.genesis_charter_id.clone(),
            current_charter_digest: policy.genesis_charter_digest.clone(),
            current_charter_sequence: 1,
            bootstrap_state,
            domains: all_fiscal_domains()
                .into_iter()
                .map(FiscalDomainState::never_activated)
                .collect(),
            finalized_checkpoint_digest: checkpoint_digest,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), FiscalError> {
        require_text(
            &self.governing_operator_id,
            "authority.governing_operator_id",
        )?;
        require_digest(&self.genesis_policy_id, "authority.genesis_policy_id")?;
        require_digest(
            &self.genesis_policy_digest,
            "authority.genesis_policy_digest",
        )?;
        require_digest(&self.current_charter_id, "authority.current_charter_id")?;
        require_digest(
            &self.current_charter_digest,
            "authority.current_charter_digest",
        )?;
        require_positive(
            self.current_charter_sequence,
            "authority.current_charter_sequence",
        )?;
        require_digest(
            &self.finalized_checkpoint_digest,
            "authority.finalized_checkpoint_digest",
        )?;
        validate_domain_states(&self.domains)
    }

    pub fn from_checkpoint(
        policy: &FiscalGenesisPolicy,
        checkpoint: &VerifiedFiscalContinuityCheckpoint,
        bootstrap_state: FiscalBootstrapState,
    ) -> Result<Self, FiscalError> {
        let state = Self {
            governing_operator_id: checkpoint.body().governing_operator_id.clone(),
            genesis_policy_id: checkpoint.body().genesis_policy_id.clone(),
            genesis_policy_digest: checkpoint.body().genesis_policy_digest.clone(),
            current_charter_id: checkpoint.body().pinned_charter_id.clone(),
            current_charter_digest: checkpoint.body().pinned_charter_digest.clone(),
            current_charter_sequence: checkpoint.body().pinned_charter_sequence,
            bootstrap_state,
            domains: checkpoint.body().domains.clone(),
            finalized_checkpoint_digest: checkpoint.digest().to_owned(),
        };
        if state.genesis_policy_id != policy.policy_id
            || state.genesis_policy_digest != policy.digest()?
        {
            return Err(FiscalError::InvalidField("authority.genesis_policy"));
        }
        state.validate()?;
        Ok(state)
    }

    #[must_use]
    pub fn domain(&self, domain: FiscalDomain) -> Option<&FiscalDomainState> {
        self.domains
            .binary_search_by_key(&domain, |state| state.domain)
            .ok()
            .and_then(|index| self.domains.get(index))
    }
}

#[derive(Debug, Clone, Default)]
pub struct FiscalCharterRegistry {
    charters: Vec<SignedFiscalCharter>,
}

impl FiscalCharterRegistry {
    pub fn new(mut charters: Vec<SignedFiscalCharter>) -> Result<Self, FiscalError> {
        let mut ids = BTreeSet::new();
        for charter in &charters {
            let verified = VerifiedFiscalCharter::verify(charter.clone())?;
            if !ids.insert(verified.body().charter_id.clone()) {
                return Err(FiscalError::InvalidField("charter_registry.duplicate"));
            }
        }
        charters.sort_by(|left, right| {
            left.body
                .sequence
                .cmp(&right.body.sequence)
                .then_with(|| left.body.charter_id.cmp(&right.body.charter_id))
        });
        Ok(Self { charters })
    }

    pub fn resolve(
        &self,
        charter_id: &str,
        charter_digest: &str,
    ) -> Result<VerifiedFiscalCharter, FiscalError> {
        let signed = self
            .charters
            .iter()
            .find(|charter| charter.body.charter_id == charter_id)
            .ok_or(FiscalError::InvalidField("charter_registry.missing"))?;
        let verified = VerifiedFiscalCharter::verify(signed.clone())?;
        if verified.digest() != charter_digest {
            return Err(FiscalError::InvalidCharterBinding);
        }
        Ok(verified)
    }

    pub fn resolve_digest(
        &self,
        charter_digest: &str,
    ) -> Result<VerifiedFiscalCharter, FiscalError> {
        for signed in &self.charters {
            let verified = VerifiedFiscalCharter::verify(signed.clone())?;
            if verified.digest() == charter_digest {
                return Ok(verified);
            }
        }
        Err(FiscalError::InvalidField("charter_registry.missing"))
    }

    pub fn resolve_lineage(
        &self,
        charter_id: &str,
        charter_digest: &str,
        genesis_charter_id: &str,
        genesis_charter_digest: &str,
    ) -> Result<VerifiedFiscalCharter, FiscalError> {
        let target = self.resolve(charter_id, charter_digest)?;
        let operator = target.body().governing_operator_id.clone();
        let mut current = target.clone();
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current.digest().to_owned()) {
                return Err(FiscalError::InvalidLineage);
            }
            if current.body().sequence == 1 {
                if current.body().charter_id != genesis_charter_id
                    || current.digest() != genesis_charter_digest
                {
                    return Err(FiscalError::InvalidLineage);
                }
                return Ok(target);
            }
            let predecessor_digest = current
                .body()
                .predecessor_charter_digest
                .as_deref()
                .ok_or(FiscalError::InvalidLineage)?;
            let predecessor = self.resolve_digest(predecessor_digest)?;
            let expected_sequence = predecessor
                .body()
                .sequence
                .checked_add(1)
                .ok_or(FiscalError::InvalidLineage)?;
            if current.body().sequence != expected_sequence
                || current.body().governing_operator_id != operator
                || predecessor.body().governing_operator_id != operator
            {
                return Err(FiscalError::InvalidLineage);
            }
            current = predecessor;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalStagedTransition {
    pub transition_id: String,
    pub transition_digest: String,
}

impl FiscalStagedTransition {
    pub fn new(transition_id: String, transition_digest: String) -> Result<Self, FiscalError> {
        require_digest(&transition_id, "staged_transition.transition_id")?;
        require_digest(&transition_digest, "staged_transition.transition_digest")?;
        Ok(Self {
            transition_id,
            transition_digest,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalContinuityCheckpoint {
    pub schema: String,
    pub checkpoint_id: String,
    pub anchor_id: String,
    pub anchor_namespace: String,
    pub governing_operator_id: String,
    pub continuity_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_digest: Option<String>,
    pub genesis_policy_id: String,
    pub genesis_policy_digest: String,
    pub pinned_charter_id: String,
    pub pinned_charter_digest: String,
    pub pinned_charter_sequence: u64,
    pub runtime_readiness_digest: String,
    pub domains: Vec<FiscalDomainState>,
    pub trusted_clock_high_water: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_transition: Option<FiscalStagedTransition>,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalContinuityCheckpointIdPreimage<'a> {
    schema: &'a str,
    anchor_id: &'a str,
    anchor_namespace: &'a str,
    governing_operator_id: &'a str,
    continuity_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_checkpoint_digest: &'a Option<String>,
    genesis_policy_id: &'a str,
    genesis_policy_digest: &'a str,
    pinned_charter_id: &'a str,
    pinned_charter_digest: &'a str,
    pinned_charter_sequence: u64,
    runtime_readiness_digest: &'a str,
    domains: &'a [FiscalDomainState],
    trusted_clock_high_water: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    staged_transition: &'a Option<FiscalStagedTransition>,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
}

impl FiscalContinuityCheckpoint {
    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_CONTINUITY_CHECKPOINT_ID_DOMAIN,
            &FiscalContinuityCheckpointIdPreimage {
                schema: &self.schema,
                anchor_id: &self.anchor_id,
                anchor_namespace: &self.anchor_namespace,
                governing_operator_id: &self.governing_operator_id,
                continuity_sequence: self.continuity_sequence,
                previous_checkpoint_digest: &self.previous_checkpoint_digest,
                genesis_policy_id: &self.genesis_policy_id,
                genesis_policy_digest: &self.genesis_policy_digest,
                pinned_charter_id: &self.pinned_charter_id,
                pinned_charter_digest: &self.pinned_charter_digest,
                pinned_charter_sequence: self.pinned_charter_sequence,
                runtime_readiness_digest: &self.runtime_readiness_digest,
                domains: &self.domains,
                trusted_clock_high_water: self.trusted_clock_high_water,
                staged_transition: &self.staged_transition,
                signer_key_id: &self.signer_key_id,
                signer_key_epoch: self.signer_key_epoch,
            },
        )
    }
}

pub type SignedFiscalContinuityCheckpoint = SignedExportEnvelope<FiscalContinuityCheckpoint>;

#[derive(Debug, Clone)]
pub struct FiscalContinuityCheckpointBuilder {
    pub continuity_sequence: u64,
    pub previous_checkpoint_digest: Option<String>,
    pub pinned_charter_id: String,
    pub pinned_charter_digest: String,
    pub pinned_charter_sequence: u64,
    pub runtime_readiness_digest: String,
    pub domains: Vec<FiscalDomainState>,
    pub trusted_clock_high_water: u64,
    pub staged_transition: Option<FiscalStagedTransition>,
}

impl FiscalContinuityCheckpointBuilder {
    pub fn sign(
        self,
        policy: &FiscalGenesisPolicy,
        keypair: &Keypair,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalError> {
        let mut body = FiscalContinuityCheckpoint {
            schema: FISCAL_CONTINUITY_CHECKPOINT_SCHEMA.to_owned(),
            checkpoint_id: String::new(),
            anchor_id: policy.anchor_id.clone(),
            anchor_namespace: policy.anchor_namespace.clone(),
            governing_operator_id: policy.governing_operator_id.clone(),
            continuity_sequence: self.continuity_sequence,
            previous_checkpoint_digest: self.previous_checkpoint_digest,
            genesis_policy_id: policy.policy_id.clone(),
            genesis_policy_digest: policy.digest()?,
            pinned_charter_id: self.pinned_charter_id,
            pinned_charter_digest: self.pinned_charter_digest,
            pinned_charter_sequence: self.pinned_charter_sequence,
            runtime_readiness_digest: self.runtime_readiness_digest,
            domains: self.domains,
            trusted_clock_high_water: self.trusted_clock_high_water,
            staged_transition: self.staged_transition,
            signer_key_id: fiscal_signer_key_id(&keypair.public_key())?,
            signer_key_epoch: policy.anchor_signer_key_epoch,
        };
        body.checkpoint_id = body.expected_id()?;
        SignedFiscalContinuityCheckpoint::sign(body, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalContinuityCheckpoint {
    signed: SignedFiscalContinuityCheckpoint,
    digest: String,
}

impl VerifiedFiscalContinuityCheckpoint {
    pub fn verify(
        signed: SignedFiscalContinuityCheckpoint,
        policy: &FiscalGenesisPolicy,
        charters: &FiscalCharterRegistry,
    ) -> Result<Self, FiscalError> {
        let body = &signed.body;
        if body.schema != FISCAL_CONTINUITY_CHECKPOINT_SCHEMA {
            return Err(FiscalError::UnknownSchema(body.schema.clone()));
        }
        let genesis =
            charters.resolve(&policy.genesis_charter_id, &policy.genesis_charter_digest)?;
        policy.validate(&genesis)?;
        let pinned = charters.resolve_lineage(
            &body.pinned_charter_id,
            &body.pinned_charter_digest,
            &policy.genesis_charter_id,
            &policy.genesis_charter_digest,
        )?;
        if body.checkpoint_id != body.expected_id()?
            || body.anchor_id != policy.anchor_id
            || body.anchor_namespace != policy.anchor_namespace
            || body.governing_operator_id != policy.governing_operator_id
            || body.genesis_policy_id != policy.policy_id
            || body.genesis_policy_digest != policy.digest()?
            || body.pinned_charter_sequence != pinned.body().sequence
            || pinned.body().governing_operator_id != policy.governing_operator_id
            || body.signer_key_id != policy.anchor_signer_key_id
            || body.signer_key_epoch != policy.anchor_signer_key_epoch
            || signed.signer_key != policy.anchor_authority_key
        {
            return Err(FiscalError::InvalidField("continuity.binding"));
        }
        match (body.continuity_sequence, &body.previous_checkpoint_digest) {
            (0, None) => {}
            (1.., Some(digest)) if is_digest(digest) => {}
            _ => return Err(FiscalError::InvalidLineage),
        }
        if body.continuity_sequence == 0
            && (body.pinned_charter_id != policy.genesis_charter_id
                || body.pinned_charter_digest != policy.genesis_charter_digest
                || body.pinned_charter_sequence != 1
                || body.staged_transition.is_some()
                || body.domains.iter().any(|state| state.ever_activated))
        {
            return Err(FiscalError::InvalidLineage);
        }
        require_digest(
            &body.runtime_readiness_digest,
            "continuity.runtime_readiness_digest",
        )?;
        validate_domain_states(&body.domains)?;
        if let Some(staged) = &body.staged_transition {
            require_digest(&staged.transition_id, "continuity.staged_transition_id")?;
            require_digest(
                &staged.transition_digest,
                "continuity.staged_transition_digest",
            )?;
        }
        verify_envelope(&signed)?;
        let digest = signed_envelope_digest(&signed)?;
        Ok(Self { signed, digest })
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        policy: &FiscalGenesisPolicy,
        charters: &FiscalCharterRegistry,
    ) -> Result<Self, FiscalError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_LIFECYCLE_BYTES {
            return Err(FiscalError::InvalidField("signed_continuity.size"));
        }
        let signed: SignedFiscalContinuityCheckpoint = serde_json::from_slice(bytes)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        let verified = Self::verify(signed, policy, charters)?;
        if verified.canonical_bytes()?.as_slice() != bytes {
            return Err(FiscalError::Canonicalization(
                "signed fiscal continuity checkpoint is not canonical".to_owned(),
            ));
        }
        Ok(verified)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FiscalError> {
        canonical_json_bytes(&self.signed)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalContinuityCheckpoint {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalContinuityCheckpoint {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Clone)]
pub enum FiscalContinuityChange {
    ClockOnly,
    Readiness {
        current: Box<VerifiedFiscalRuntimeReadiness>,
        next: Box<VerifiedFiscalRuntimeReadiness>,
    },
    Activation {
        activation: Box<VerifiedFiscalActivation>,
        readiness: Box<VerifiedFiscalRuntimeReadiness>,
        domain: FiscalDomain,
        schedule: Box<VerifiedFiscalSchedule>,
    },
    CharterRotation {
        activation: Box<VerifiedFiscalActivation>,
        readiness: Box<VerifiedFiscalRuntimeReadiness>,
        predecessor_schedules: Vec<VerifiedFiscalSchedule>,
        replacement_domains: Vec<FiscalDomainState>,
    },
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalContinuityAdvance {
    current: VerifiedFiscalContinuityCheckpoint,
    next: VerifiedFiscalContinuityCheckpoint,
    change: FiscalContinuityChange,
    proof_bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalContinuityAdvanceProof<'a> {
    schema: &'static str,
    current: &'a SignedFiscalContinuityCheckpoint,
    next: &'a SignedFiscalContinuityCheckpoint,
    change: FiscalContinuityAdvanceProofChange<'a>,
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum FiscalContinuityAdvanceProofChange<'a> {
    ClockOnly,
    Readiness {
        current: &'a SignedFiscalRuntimeReadiness,
        current_runtime_registry: &'a FiscalRuntimeAdapterRegistry,
        next: &'a SignedFiscalRuntimeReadiness,
        next_runtime_registry: &'a FiscalRuntimeAdapterRegistry,
    },
    Activation {
        activation: &'a SignedFiscalActivation,
        readiness: &'a SignedFiscalRuntimeReadiness,
        runtime_registry: &'a FiscalRuntimeAdapterRegistry,
        domain: FiscalDomain,
        schedule: &'a SignedFiscalSchedule,
    },
    CharterRotation {
        activation: &'a SignedFiscalActivation,
        readiness: &'a SignedFiscalRuntimeReadiness,
        runtime_registry: &'a FiscalRuntimeAdapterRegistry,
        predecessor_schedules: Vec<&'a SignedFiscalSchedule>,
        replacement_domains: &'a [FiscalDomainState],
    },
}

impl VerifiedFiscalContinuityAdvance {
    pub fn verify(
        current: &VerifiedFiscalContinuityCheckpoint,
        next_signed: SignedFiscalContinuityCheckpoint,
        policy: &FiscalGenesisPolicy,
        charters: &FiscalCharterRegistry,
        change: &FiscalContinuityChange,
    ) -> Result<Self, FiscalError> {
        let next = VerifiedFiscalContinuityCheckpoint::verify(next_signed, policy, charters)?;
        let current_body = current.body();
        let next_body = next.body();
        let expected_sequence = current_body
            .continuity_sequence
            .checked_add(1)
            .ok_or(FiscalError::InvalidLineage)?;
        if next_body.anchor_id != current_body.anchor_id
            || next_body.anchor_namespace != current_body.anchor_namespace
            || next_body.governing_operator_id != current_body.governing_operator_id
            || next_body.continuity_sequence != expected_sequence
            || next_body.previous_checkpoint_digest.as_deref() != Some(current.digest())
            || next_body.genesis_policy_id != current_body.genesis_policy_id
            || next_body.genesis_policy_digest != current_body.genesis_policy_digest
            || next_body.trusted_clock_high_water < current_body.trusted_clock_high_water
            || next_body
                .domains
                .iter()
                .zip(&current_body.domains)
                .any(|(next, current)| current.ever_activated && !next.ever_activated)
        {
            return Err(FiscalError::InvalidLineage);
        }
        match change {
            FiscalContinuityChange::ClockOnly => {
                if next_body.pinned_charter_id != current_body.pinned_charter_id
                    || next_body.pinned_charter_digest != current_body.pinned_charter_digest
                    || next_body.pinned_charter_sequence != current_body.pinned_charter_sequence
                    || next_body.runtime_readiness_digest != current_body.runtime_readiness_digest
                    || next_body.domains != current_body.domains
                    || next_body.staged_transition != current_body.staged_transition
                {
                    return Err(FiscalError::InvalidLineage);
                }
            }
            FiscalContinuityChange::Readiness { current, next } => {
                let expected_readiness_sequence = current
                    .body()
                    .readiness_sequence
                    .checked_add(1)
                    .ok_or(FiscalError::InvalidLineage)?;
                if current.digest() != current_body.runtime_readiness_digest
                    || next.digest() != next_body.runtime_readiness_digest
                    || current.body().governing_operator_id != current_body.governing_operator_id
                    || next.body().governing_operator_id != current_body.governing_operator_id
                    || current.body().genesis_policy_id != current_body.genesis_policy_id
                    || next.body().genesis_policy_id != current_body.genesis_policy_id
                    || current.body().genesis_policy_digest != current_body.genesis_policy_digest
                    || next.body().genesis_policy_digest != current_body.genesis_policy_digest
                    || next.body().readiness_sequence != expected_readiness_sequence
                    || next.body().attested_at < current.body().attested_at
                    || next.body().attested_at < current_body.trusted_clock_high_water
                    || next.body().attested_at > next_body.trusted_clock_high_water
                    || next_body.pinned_charter_id != current_body.pinned_charter_id
                    || next_body.pinned_charter_digest != current_body.pinned_charter_digest
                    || next_body.pinned_charter_sequence != current_body.pinned_charter_sequence
                    || next_body.domains != current_body.domains
                    || next_body.staged_transition != current_body.staged_transition
                {
                    return Err(FiscalError::InvalidLineage);
                }
            }
            FiscalContinuityChange::Activation {
                activation,
                readiness,
                domain,
                schedule,
            } => {
                verify_activation_readiness(readiness, activation, current_body)?;
                let schedule_head = FiscalScheduleHead::from_signed(schedule.signed())?;
                schedule_head.validate()?;
                let schedule_transition = activation
                    .schedule_transition
                    .as_ref()
                    .ok_or(FiscalError::InvalidLineage)?;
                let FiscalActivationTarget::Schedule { schedule_id, .. } =
                    &activation.body().target
                else {
                    return Err(FiscalError::InvalidLineage);
                };
                let current_state = current_body
                    .domains
                    .iter()
                    .find(|state| state.domain == *domain)
                    .ok_or(FiscalError::InvalidLineage)?;
                let transition = FiscalStagedTransition::new(
                    activation.body().activation_id.clone(),
                    activation.digest().to_owned(),
                )?;
                if next_body.pinned_charter_id != current_body.pinned_charter_id
                    || next_body.pinned_charter_digest != current_body.pinned_charter_digest
                    || next_body.pinned_charter_sequence != current_body.pinned_charter_sequence
                    || next_body.runtime_readiness_digest != current_body.runtime_readiness_digest
                    || activation.body().charter_id != current_body.pinned_charter_id
                    || activation.body().charter_digest != current_body.pinned_charter_digest
                    || !activation.admission_consumed
                    || schedule_head.schedule_id.as_str() != schedule_id.as_str()
                    || schedule_transition.domain != *domain
                    || schedule_transition.candidate != schedule_head
                    || current_state.active.as_ref() != schedule_transition.predecessor.as_ref()
                    || activation.body().activated_at < current_body.trusted_clock_high_water
                    || activation.body().activated_at > next_body.trusted_clock_high_water
                    || next_body.staged_transition.as_ref() != Some(&transition)
                {
                    return Err(FiscalError::InvalidLineage);
                }
                let expected_domains = current_body
                    .domains
                    .iter()
                    .map(|state| {
                        if state.domain == *domain {
                            FiscalDomainState::activated(
                                *domain,
                                schedule_head.clone(),
                                schedule_head.clone(),
                            )
                        } else {
                            Ok(state.clone())
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if next_body.domains != expected_domains {
                    return Err(FiscalError::InvalidLineage);
                }
            }
            FiscalContinuityChange::CharterRotation {
                activation,
                readiness,
                predecessor_schedules,
                replacement_domains,
            } => {
                verify_activation_readiness(readiness, activation, current_body)?;
                let FiscalActivationTarget::CharterRotation {
                    successor_charter_digest,
                    predecessor_charter_digest,
                    successor_schedules,
                } = &activation.body().target
                else {
                    return Err(FiscalError::InvalidLineage);
                };
                let current_charter = charters.resolve(
                    &current_body.pinned_charter_id,
                    &current_body.pinned_charter_digest,
                )?;
                let successor = charters.resolve_lineage(
                    &next_body.pinned_charter_id,
                    successor_charter_digest,
                    &policy.genesis_charter_id,
                    &policy.genesis_charter_digest,
                )?;
                let expected_charter_sequence = current_charter
                    .body()
                    .sequence
                    .checked_add(1)
                    .ok_or(FiscalError::InvalidLineage)?;
                validate_domain_states(replacement_domains)?;
                let activated_domain_count = current_body
                    .domains
                    .iter()
                    .filter(|state| state.ever_activated)
                    .count();
                let predecessor_heads = predecessor_schedules
                    .iter()
                    .map(|schedule| {
                        Ok((
                            schedule.body().domain,
                            FiscalScheduleHead::from_signed(schedule.signed())?,
                        ))
                    })
                    .collect::<Result<Vec<_>, FiscalError>>()?;
                if successor.body().sequence != expected_charter_sequence
                    || predecessor_charter_digest != current_charter.digest()
                    || successor.body().predecessor_charter_digest.as_deref()
                        != Some(current_charter.digest())
                    || next_body.pinned_charter_id != successor.body().charter_id
                    || next_body.pinned_charter_digest.as_str() != successor_charter_digest.as_str()
                    || next_body.pinned_charter_sequence != expected_charter_sequence
                    || next_body.runtime_readiness_digest != current_body.runtime_readiness_digest
                    || next_body.domains != *replacement_domains
                    || activation.body().charter_id != current_body.pinned_charter_id
                    || activation.body().charter_digest != current_body.pinned_charter_digest
                    || !activation.admission_consumed
                    || successor_schedules.len() != activated_domain_count
                    || activation.rotation_predecessors.len() != activated_domain_count
                    || predecessor_heads.len() != activated_domain_count
                    || predecessor_heads
                        .iter()
                        .zip(&activation.rotation_predecessors)
                        .any(|((domain, head), retained)| {
                            *domain != retained.domain || head != &retained.head
                        })
                    || activation.body().activated_at < current_body.trusted_clock_high_water
                    || activation.body().activated_at > next_body.trusted_clock_high_water
                    || current_body.domains.iter().zip(replacement_domains).any(
                        |(current, replacement)| {
                            current.domain != replacement.domain
                                || current.ever_activated != replacement.ever_activated
                        },
                    )
                {
                    return Err(FiscalError::InvalidLineage);
                }
                let transition = FiscalStagedTransition::new(
                    activation.body().activation_id.clone(),
                    activation.digest().to_owned(),
                )?;
                if next_body.staged_transition.as_ref() != Some(&transition) {
                    return Err(FiscalError::InvalidLineage);
                }
                for ((current_state, replacement), predecessor) in current_body
                    .domains
                    .iter()
                    .filter(|state| state.ever_activated)
                    .zip(successor_schedules)
                    .zip(&predecessor_heads)
                {
                    let replacement_state = replacement_domains
                        .iter()
                        .find(|state| state.domain == current_state.domain)
                        .ok_or(FiscalError::InvalidLineage)?;
                    let expected_head = FiscalScheduleHead::from_signed(replacement)?;
                    if replacement.body.domain != current_state.domain
                        || predecessor.0 != current_state.domain
                        || (current_state.active.as_ref() != Some(&predecessor.1)
                            && current_state.last_known_good.as_ref() != Some(&predecessor.1))
                        || replacement_state.active.as_ref() != Some(&expected_head)
                        || replacement_state.last_known_good.as_ref() != Some(&expected_head)
                    {
                        return Err(FiscalError::InvalidLineage);
                    }
                }
            }
        }
        let proof_bytes = canonical_advance_proof(current, &next, change)?;
        Ok(Self {
            current: current.clone(),
            next,
            change: change.clone(),
            proof_bytes,
        })
    }

    #[must_use]
    pub const fn current(&self) -> &VerifiedFiscalContinuityCheckpoint {
        &self.current
    }

    #[must_use]
    pub const fn next(&self) -> &VerifiedFiscalContinuityCheckpoint {
        &self.next
    }

    #[must_use]
    pub fn canonical_proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }

    pub fn reverify(
        &self,
        policy: &FiscalGenesisPolicy,
        charters: &FiscalCharterRegistry,
    ) -> Result<(), FiscalError> {
        let verified = Self::verify(
            &self.current,
            self.next.signed().clone(),
            policy,
            charters,
            &self.change,
        )?;
        if verified.proof_bytes != self.proof_bytes {
            return Err(FiscalError::InvalidField("continuity.advance_proof"));
        }
        Ok(())
    }

    fn activation(&self) -> Option<&VerifiedFiscalActivation> {
        match &self.change {
            FiscalContinuityChange::Activation { activation, .. }
            | FiscalContinuityChange::CharterRotation { activation, .. } => Some(activation),
            FiscalContinuityChange::ClockOnly | FiscalContinuityChange::Readiness { .. } => None,
        }
    }
}

fn canonical_advance_proof(
    current: &VerifiedFiscalContinuityCheckpoint,
    next: &VerifiedFiscalContinuityCheckpoint,
    change: &FiscalContinuityChange,
) -> Result<Vec<u8>, FiscalError> {
    let change = match change {
        FiscalContinuityChange::ClockOnly => FiscalContinuityAdvanceProofChange::ClockOnly,
        FiscalContinuityChange::Readiness { current, next } => {
            FiscalContinuityAdvanceProofChange::Readiness {
                current: current.signed(),
                current_runtime_registry: current.runtime_registry(),
                next: next.signed(),
                next_runtime_registry: next.runtime_registry(),
            }
        }
        FiscalContinuityChange::Activation {
            activation,
            readiness,
            domain,
            schedule,
        } => FiscalContinuityAdvanceProofChange::Activation {
            activation: activation.signed(),
            readiness: readiness.signed(),
            runtime_registry: readiness.runtime_registry(),
            domain: *domain,
            schedule: schedule.signed(),
        },
        FiscalContinuityChange::CharterRotation {
            activation,
            readiness,
            predecessor_schedules,
            replacement_domains,
        } => FiscalContinuityAdvanceProofChange::CharterRotation {
            activation: activation.signed(),
            readiness: readiness.signed(),
            runtime_registry: readiness.runtime_registry(),
            predecessor_schedules: predecessor_schedules
                .iter()
                .map(VerifiedFiscalSchedule::signed)
                .collect(),
            replacement_domains,
        },
    };
    canonical_json_bytes(&FiscalContinuityAdvanceProof {
        schema: FISCAL_CONTINUITY_ADVANCE_PROOF_SCHEMA,
        current: current.signed(),
        next: next.signed(),
        change,
    })
    .map_err(|error| FiscalError::Canonicalization(error.to_string()))
}

fn verify_activation_readiness(
    readiness: &VerifiedFiscalRuntimeReadiness,
    activation: &VerifiedFiscalActivation,
    current: &FiscalContinuityCheckpoint,
) -> Result<(), FiscalError> {
    if readiness.digest() != current.runtime_readiness_digest
        || readiness.body().governing_operator_id != current.governing_operator_id
        || readiness.body().genesis_policy_id != current.genesis_policy_id
        || readiness.body().genesis_policy_digest != current.genesis_policy_digest
        || readiness.body().attested_at > activation.body().activated_at
    {
        return Err(FiscalError::InvalidField("continuity.activation_readiness"));
    }
    Ok(())
}

#[derive(Debug)]
pub struct VerifiedFiscalActivationAuthority {
    pub(super) activation: VerifiedFiscalActivation,
    pub(super) checkpoint_digest: String,
}

impl VerifiedFiscalActivationAuthority {
    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    pub(super) fn into_activation(self) -> VerifiedFiscalActivation {
        self.activation
    }
}

#[derive(Debug)]
pub struct VerifiedFiscalContinuityCommit {
    checkpoint: VerifiedFiscalContinuityCheckpoint,
    activation_authority: Option<VerifiedFiscalActivationAuthority>,
}

impl VerifiedFiscalContinuityCommit {
    #[must_use]
    pub const fn checkpoint(&self) -> &VerifiedFiscalContinuityCheckpoint {
        &self.checkpoint
    }

    pub fn into_activation_authority(
        self,
    ) -> Result<VerifiedFiscalActivationAuthority, FiscalStateAnchorError> {
        self.activation_authority
            .ok_or(FiscalStateAnchorError::Divergence)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FiscalStateAnchorError {
    #[error("fiscal state anchor is unavailable")]
    Unavailable,
    #[error("fiscal state anchor compare-and-swap conflicted")]
    Conflict,
    #[error("fiscal state anchor diverged")]
    Divergence,
}

pub trait FiscalStateAnchor: Send + Sync {
    fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError>;

    fn compare_and_swap(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFiscalContinuityAdvance,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError>;
}

pub fn commit_fiscal_continuity_advance(
    anchor: &dyn FiscalStateAnchor,
    advance: VerifiedFiscalContinuityAdvance,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
) -> Result<VerifiedFiscalContinuityCommit, FiscalStateAnchorError> {
    advance
        .reverify(policy, charters)
        .map_err(|_| FiscalStateAnchorError::Divergence)?;
    let acknowledged = anchor.compare_and_swap(advance.current().digest(), &advance)?;
    verify_fiscal_continuity_acknowledgement(acknowledged, advance, policy, charters)
}

pub fn recover_fiscal_continuity_advance(
    anchor: &dyn FiscalStateAnchor,
    advance: VerifiedFiscalContinuityAdvance,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
) -> Result<VerifiedFiscalContinuityCommit, FiscalStateAnchorError> {
    advance
        .reverify(policy, charters)
        .map_err(|_| FiscalStateAnchorError::Divergence)?;
    let acknowledged = anchor.read()?;
    verify_fiscal_continuity_acknowledgement(acknowledged, advance, policy, charters)
}

fn verify_fiscal_continuity_acknowledgement(
    acknowledged: SignedFiscalContinuityCheckpoint,
    advance: VerifiedFiscalContinuityAdvance,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
) -> Result<VerifiedFiscalContinuityCommit, FiscalStateAnchorError> {
    let checkpoint = VerifiedFiscalContinuityCheckpoint::verify(acknowledged, policy, charters)
        .map_err(|_| FiscalStateAnchorError::Divergence)?;
    if checkpoint.signed() != advance.next().signed() {
        return Err(FiscalStateAnchorError::Divergence);
    }
    let checkpoint_digest = checkpoint.digest().to_owned();
    let activation_authority =
        advance
            .activation()
            .cloned()
            .map(|activation| VerifiedFiscalActivationAuthority {
                activation,
                checkpoint_digest,
            });
    Ok(VerifiedFiscalContinuityCommit {
        checkpoint,
        activation_authority,
    })
}

pub fn read_verified_fiscal_checkpoint(
    anchor: &dyn FiscalStateAnchor,
    policy: &FiscalGenesisPolicy,
    charters: &FiscalCharterRegistry,
) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
    let signed = anchor.read()?;
    VerifiedFiscalContinuityCheckpoint::verify(signed, policy, charters)
        .map_err(|_| FiscalStateAnchorError::Divergence)
}
