use std::collections::BTreeSet;

use crate::{FiscalDomain, FiscalError, FiscalParams, SignedFiscalSchedule, VerifiedFiscalCharter};

use super::activation::{FiscalActivationHistory, FiscalScheduleHead};
use super::continuity::{
    FiscalAuthorityState, FiscalBootstrapState, FiscalCharterRegistry,
    VerifiedFiscalContinuityCheckpoint,
};
use super::proposal::FiscalGenesisPolicy;
use super::readiness::VerifiedFiscalRuntimeReadiness;
use super::support::{signed_envelope_digest, verify_envelope};

#[derive(Debug, Clone, Copy)]
pub enum FiscalContinuitySnapshot<'a> {
    Verified(&'a VerifiedFiscalContinuityCheckpoint),
    Unavailable,
    Divergent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedSource {
    Active,
    LastKnownGood,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiscalFallbackReason {
    AuthoritativeBootstrap,
    NeverActivated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiscalDenialReason {
    AnchorUnavailable,
    AnchorRollbackOrDivergence,
    ActivatedStateUnavailable,
    NoValidLastKnownGood,
    ClockRollback,
    VerificationFailed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FiscalResolution<P> {
    Governed {
        schedule_id: String,
        sequence: u64,
        source: GovernedSource,
        params: P,
    },
    Fallback(FiscalFallbackReason),
    Denied(FiscalDenialReason),
}

pub trait FiscalDomainParams: Sized {
    fn from_fiscal_params(params: &FiscalParams) -> Option<Self>;
}

impl FiscalDomainParams for FiscalParams {
    fn from_fiscal_params(params: &FiscalParams) -> Option<Self> {
        Some(params.clone())
    }
}

pub struct FiscalResolver<'a> {
    pub continuity: FiscalContinuitySnapshot<'a>,
    pub policy: &'a FiscalGenesisPolicy,
    pub readiness: &'a VerifiedFiscalRuntimeReadiness,
    pub activation_history: &'a FiscalActivationHistory,
    pub authority: &'a FiscalAuthorityState,
    pub charters: &'a FiscalCharterRegistry,
    pub schedules: &'a [SignedFiscalSchedule],
    pub verify_at: u64,
}

impl FiscalResolver<'_> {
    pub fn resolve<P: FiscalDomainParams>(
        &self,
        domain: FiscalDomain,
        request_currency: Option<&str>,
    ) -> FiscalResolution<P> {
        resolve_fiscal_schedule(
            self.continuity,
            self.policy,
            self.readiness,
            self.activation_history,
            self.authority,
            self.charters,
            self.schedules,
            domain,
            request_currency,
            self.verify_at,
        )
    }

    #[must_use]
    pub fn bootstrap_tier_limits(&self, currency: &str) -> Option<&[u64; 4]> {
        self.policy.bootstrap_tier_limits.get(currency)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_fiscal_schedule<P: FiscalDomainParams>(
    continuity: FiscalContinuitySnapshot<'_>,
    policy: &FiscalGenesisPolicy,
    readiness: &VerifiedFiscalRuntimeReadiness,
    activation_history: &FiscalActivationHistory,
    authority: &FiscalAuthorityState,
    charters: &FiscalCharterRegistry,
    schedules: &[SignedFiscalSchedule],
    domain: FiscalDomain,
    request_currency: Option<&str>,
    verify_at: u64,
) -> FiscalResolution<P> {
    let checkpoint = match continuity {
        FiscalContinuitySnapshot::Verified(checkpoint) => checkpoint,
        FiscalContinuitySnapshot::Unavailable => {
            return FiscalResolution::Denied(FiscalDenialReason::AnchorUnavailable)
        }
        FiscalContinuitySnapshot::Divergent => {
            return FiscalResolution::Denied(FiscalDenialReason::AnchorRollbackOrDivergence)
        }
    };
    if checkpoint.body().trusted_clock_high_water > verify_at {
        return FiscalResolution::Denied(FiscalDenialReason::ClockRollback);
    }
    if checkpoint.body().trusted_clock_high_water < verify_at {
        return FiscalResolution::Denied(FiscalDenialReason::AnchorRollbackOrDivergence);
    }
    if readiness.digest() != checkpoint.body().runtime_readiness_digest
        || readiness.body().governing_operator_id != checkpoint.body().governing_operator_id
        || readiness.body().genesis_policy_id != checkpoint.body().genesis_policy_id
        || readiness.body().genesis_policy_digest != checkpoint.body().genesis_policy_digest
        || readiness.body().attested_at > verify_at
    {
        return FiscalResolution::Denied(FiscalDenialReason::VerificationFailed);
    }
    let policy_digest = match policy.digest() {
        Ok(digest) => digest,
        Err(_) => return FiscalResolution::Denied(FiscalDenialReason::VerificationFailed),
    };
    if authority.validate().is_err()
        || authority.finalized_checkpoint_digest != checkpoint.digest()
        || authority.governing_operator_id != checkpoint.body().governing_operator_id
        || authority.genesis_policy_id != checkpoint.body().genesis_policy_id
        || authority.genesis_policy_digest != checkpoint.body().genesis_policy_digest
        || authority.genesis_policy_id != policy.policy_id
        || authority.genesis_policy_digest != policy_digest
        || authority.current_charter_id != checkpoint.body().pinned_charter_id
        || authority.current_charter_digest != checkpoint.body().pinned_charter_digest
        || authority.current_charter_sequence != checkpoint.body().pinned_charter_sequence
        || authority.domains != checkpoint.body().domains
    {
        return FiscalResolution::Denied(FiscalDenialReason::AnchorRollbackOrDivergence);
    }
    let charter = match charters.resolve(
        &authority.current_charter_id,
        &authority.current_charter_digest,
    ) {
        Ok(charter) => charter,
        Err(_) => return FiscalResolution::Denied(FiscalDenialReason::VerificationFailed),
    };
    if charter.body().sequence != authority.current_charter_sequence
        || charter.body().governing_operator_id != authority.governing_operator_id
        || verify_at >= charter.body().expires_at
    {
        return FiscalResolution::Denied(FiscalDenialReason::VerificationFailed);
    }
    let Some(state) = authority.domain(domain) else {
        return FiscalResolution::Denied(FiscalDenialReason::AnchorRollbackOrDivergence);
    };
    if !state.ever_activated {
        if domain == FiscalDomain::TierLimits
            && request_currency
                .is_none_or(|currency| !policy.bootstrap_tier_limits.contains_key(currency))
        {
            return FiscalResolution::Denied(FiscalDenialReason::VerificationFailed);
        }
        return FiscalResolution::Fallback(match authority.bootstrap_state {
            FiscalBootstrapState::BootstrapUnconfigured
                if checkpoint.body().continuity_sequence == 0 =>
            {
                FiscalFallbackReason::AuthoritativeBootstrap
            }
            FiscalBootstrapState::BootstrapUnconfigured | FiscalBootstrapState::CharterPinned => {
                FiscalFallbackReason::NeverActivated
            }
        });
    }
    let Some(active) = &state.active else {
        return FiscalResolution::Denied(FiscalDenialReason::ActivatedStateUnavailable);
    };
    let schedule_resolver = FiscalScheduleResolver {
        activation_history,
        current_charter: &charter,
        charters,
        schedules,
    };
    if let Some(params) =
        schedule_resolver.resolve::<P>(active, domain, request_currency, verify_at)
    {
        return FiscalResolution::Governed {
            schedule_id: active.schedule_id.clone(),
            sequence: active.sequence,
            source: GovernedSource::Active,
            params,
        };
    }
    let Some(last_known_good) = &state.last_known_good else {
        return FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood);
    };
    match schedule_resolver.resolve::<P>(last_known_good, domain, request_currency, verify_at) {
        Some(params) => FiscalResolution::Governed {
            schedule_id: last_known_good.schedule_id.clone(),
            sequence: last_known_good.sequence,
            source: GovernedSource::LastKnownGood,
            params,
        },
        None => FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood),
    }
}

struct FiscalScheduleResolver<'a> {
    activation_history: &'a FiscalActivationHistory,
    current_charter: &'a VerifiedFiscalCharter,
    charters: &'a FiscalCharterRegistry,
    schedules: &'a [SignedFiscalSchedule],
}

impl FiscalScheduleResolver<'_> {
    fn resolve<P: FiscalDomainParams>(
        &self,
        head: &FiscalScheduleHead,
        domain: FiscalDomain,
        request_currency: Option<&str>,
        verify_at: u64,
    ) -> Option<P> {
        self.activation_history
            .verify_head(head, domain, verify_at)
            .ok()?;
        let target = self.schedules.iter().find(|schedule| {
            schedule.body.schedule_id == head.schedule_id
                && signed_envelope_digest(*schedule).ok().as_deref()
                    == Some(head.schedule_digest.as_str())
        })?;
        if target.body.domain != domain
            || target.body.charter_id != self.current_charter.body().charter_id
            || target.body.charter_digest != self.current_charter.digest()
            || target.body.sequence != head.sequence
            || verify_at < target.body.valid_from
            || verify_at >= target.body.valid_until
            || !schedule_currency_matches(&target.body.params, request_currency)
            || verify_schedule_chain(
                target,
                domain,
                verify_at,
                self.activation_history,
                self.charters,
                self.schedules,
            )
            .is_err()
        {
            return None;
        }
        P::from_fiscal_params(&target.body.params)
    }
}

fn verify_schedule_chain(
    target: &SignedFiscalSchedule,
    domain: FiscalDomain,
    verify_at: u64,
    activation_history: &FiscalActivationHistory,
    charters: &FiscalCharterRegistry,
    schedules: &[SignedFiscalSchedule],
) -> Result<(), FiscalError> {
    let mut current = target;
    let mut visited = BTreeSet::new();
    loop {
        let current_head = FiscalScheduleHead::from_signed(current)?;
        activation_history.verify_head(&current_head, domain, verify_at)?;
        if !visited.insert(current.body.schedule_id.as_str()) {
            return Err(FiscalError::InvalidLineage);
        }
        let charter = charters.resolve(&current.body.charter_id, &current.body.charter_digest)?;
        current.body.validate_against(&charter)?;
        verify_envelope(current)?;
        match (current.body.sequence, &current.body.supersedes_schedule_id) {
            (1, None) => return Ok(()),
            (2.., Some(predecessor_id)) => {
                let predecessor_head = activation_history
                    .predecessor_for_head(&current_head, domain, verify_at)?
                    .ok_or(FiscalError::InvalidLineage)?;
                if predecessor_head.schedule_id != *predecessor_id {
                    return Err(FiscalError::InvalidLineage);
                }
                let predecessor = schedules
                    .iter()
                    .find(|schedule| {
                        schedule.body.schedule_id == *predecessor_id
                            && FiscalScheduleHead::from_signed(schedule)
                                .is_ok_and(|head| head == predecessor_head)
                    })
                    .ok_or(FiscalError::InvalidLineage)?;
                let expected_sequence = predecessor
                    .body
                    .sequence
                    .checked_add(1)
                    .ok_or(FiscalError::InvalidLineage)?;
                if current.body.domain != predecessor.body.domain
                    || current.body.sequence != expected_sequence
                {
                    return Err(FiscalError::InvalidLineage);
                }
                if current.body.charter_digest == predecessor.body.charter_digest {
                    if current.body.charter_id != predecessor.body.charter_id {
                        return Err(FiscalError::InvalidLineage);
                    }
                } else {
                    let predecessor_charter = charters.resolve(
                        &predecessor.body.charter_id,
                        &predecessor.body.charter_digest,
                    )?;
                    if charter.body().predecessor_charter_digest.as_deref()
                        != Some(predecessor_charter.digest())
                        || current.body.params != predecessor.body.params
                        || current.body.valid_from != predecessor.body.valid_from
                        || current.body.valid_until != predecessor.body.valid_until
                    {
                        return Err(FiscalError::InvalidLineage);
                    }
                }
                current = predecessor;
            }
            _ => return Err(FiscalError::InvalidLineage),
        }
    }
}

fn schedule_currency_matches(params: &FiscalParams, request_currency: Option<&str>) -> bool {
    match (params, request_currency) {
        (FiscalParams::TierLimits { ceilings }, Some(currency)) => {
            ceilings.iter().all(|ceiling| ceiling.currency == currency)
        }
        (FiscalParams::TierLimits { .. }, None) => false,
        (_, _) => true,
    }
}
