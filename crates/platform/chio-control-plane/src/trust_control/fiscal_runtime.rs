use super::*;
use chio_core::crypto::Keypair;
use chio_fiscal::{
    FiscalActivationHistory, FiscalActivationTarget, FiscalAdmissionAuthority,
    FiscalAdmissionTrustRegistry, FiscalAuthorityState, FiscalContinuityChange, FiscalDomain,
    FiscalGenesisPolicy, FiscalParams, FiscalProposalTarget, FiscalResolution, FiscalResolver,
    FiscalRuntimeAdapterRegistry, FiscalScheduleHead, FiscalStateAnchor, SignedFiscalActivation,
    SignedFiscalApproval, SignedFiscalContinuityCheckpoint, SignedFiscalProposal,
    SignedFiscalProposalAdmission, VerifiedFiscalActivation, VerifiedFiscalApproval,
    VerifiedFiscalCharter, VerifiedFiscalContinuityAdvance, VerifiedFiscalProposal,
    VerifiedFiscalProposalAdmission, VerifiedFiscalSchedule,
};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_open_market::fiscal_adapter::FiscalLegacyFeeScheduleBinding;
use chio_store_sqlite::fiscal_store::SqliteFiscalStore;

use crate::fiscal_runtime_readiness::production_fiscal_runtime_assembler;
use crate::fiscal_runtime_startup::{reconcile_fiscal_runtime_startup, FiscalRuntimeStartup};
use crate::fiscal_state_anchor::{compose_fiscal_state_anchor, RemoteFiscalStateAnchorConfig};
use crate::fiscal_state_commit::{
    commit_fiscal_activation, commit_fiscal_charter_rotation, FiscalStateCommitError,
};

const FISCAL_RUNTIME_SCHEMA_VERSION: &str = "chio.fiscal.runtime.v1";

pub(crate) struct TrustFiscalRuntime {
    store: SqliteFiscalStore,
    fence: StoreMutationFence,
    anchor: Arc<dyn FiscalStateAnchor>,
    policy: FiscalGenesisPolicy,
    registry: FiscalRuntimeAdapterRegistry,
    admission_authority_id: String,
    admission_signer_key_epoch: u64,
    admission_signer: Keypair,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TrustFiscalOperationError {
    #[error("{0}")]
    Startup(String),
    #[error("invalid fiscal artifact: {0}")]
    InvalidArtifact(#[source] chio_fiscal::FiscalError),
    #[error("fiscal persistence failed: {0}")]
    Store(#[source] chio_store_sqlite::fiscal_store::FiscalStoreError),
    #[error("fiscal activation commit failed: {0}")]
    Commit(#[source] FiscalStateCommitError),
}

impl TrustFiscalRuntime {
    pub(crate) fn reconcile(&self) -> Result<FiscalRuntimeStartup, CliError> {
        reconcile_fiscal_runtime_startup(
            &self.store,
            self.anchor.as_ref(),
            &self.policy,
            &self.registry,
            &self.fence,
        )
        .map_err(fiscal_startup_error)
    }

    pub(crate) fn preview_proposal(
        &self,
        signed: SignedFiscalProposal,
    ) -> Result<VerifiedFiscalProposal, TrustFiscalOperationError> {
        let startup = self
            .reconcile()
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        self.verify_proposal_at(signed, &startup)
    }

    fn verify_proposal_at(
        &self,
        signed: SignedFiscalProposal,
        startup: &FiscalRuntimeStartup,
    ) -> Result<VerifiedFiscalProposal, TrustFiscalOperationError> {
        let charter = current_charter(startup)
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let predecessor = match &signed.body.target {
            FiscalProposalTarget::Schedule { candidate } => {
                let state = startup
                    .checkpoint
                    .body()
                    .domains
                    .iter()
                    .find(|state| state.domain == candidate.body.domain)
                    .ok_or_else(|| {
                        TrustFiscalOperationError::Startup(
                            "fiscal domain state is missing".to_owned(),
                        )
                    })?;
                match state.active.as_ref() {
                    Some(head) => {
                        let predecessor = self
                            .store
                            .load_verified_schedule(&head.schedule_id, &startup.charters)
                            .map_err(TrustFiscalOperationError::Store)?;
                        if FiscalScheduleHead::from_signed(predecessor.signed())
                            .map_err(TrustFiscalOperationError::InvalidArtifact)?
                            != *head
                        {
                            return Err(TrustFiscalOperationError::Startup(
                                "active fiscal schedule differs from the anchored head".to_owned(),
                            ));
                        }
                        Some(predecessor)
                    }
                    None if !state.ever_activated => None,
                    None => {
                        return Err(TrustFiscalOperationError::Startup(
                            "activated fiscal domain has no anchored active schedule".to_owned(),
                        ));
                    }
                }
            }
            FiscalProposalTarget::CharterRotation { .. } => None,
        };
        VerifiedFiscalProposal::verify(signed, &charter, predecessor.as_ref())
            .map_err(TrustFiscalOperationError::InvalidArtifact)
    }

    pub(crate) fn persist_proposal(
        &self,
        signed: SignedFiscalProposal,
    ) -> Result<VerifiedFiscalProposal, TrustFiscalOperationError> {
        let startup = self
            .reconcile()
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let proposal = self.verify_proposal_at(signed, &startup)?;
        let charter = current_charter(&startup)
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        match &proposal.body().target {
            FiscalProposalTarget::Schedule { candidate } => {
                let state = startup
                    .checkpoint
                    .body()
                    .domains
                    .iter()
                    .find(|state| state.domain == candidate.body.domain)
                    .ok_or_else(|| {
                        TrustFiscalOperationError::Startup(
                            "fiscal domain state is missing".to_owned(),
                        )
                    })?;
                let predecessor = state
                    .active
                    .as_ref()
                    .map(|head| {
                        self.store
                            .load_verified_schedule(&head.schedule_id, &startup.charters)
                    })
                    .transpose()
                    .map_err(TrustFiscalOperationError::Store)?;
                let candidate = VerifiedFiscalSchedule::verify(
                    candidate.as_ref().clone(),
                    &charter,
                    predecessor.as_ref(),
                )
                .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                self.store
                    .persist_schedule(&candidate, &self.fence)
                    .map_err(TrustFiscalOperationError::Store)?;
            }
            FiscalProposalTarget::CharterRotation { successor } => {
                let successor = VerifiedFiscalCharter::verify(successor.as_ref().clone())
                    .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                self.store
                    .persist_charter(&successor, &self.fence)
                    .map_err(TrustFiscalOperationError::Store)?;
            }
        }
        self.store
            .persist_proposal(&proposal, &self.fence)
            .map_err(TrustFiscalOperationError::Store)?;
        Ok(proposal)
    }

    pub(crate) fn admit_proposal(
        &self,
        signed: SignedFiscalProposal,
    ) -> Result<VerifiedFiscalProposalAdmission, TrustFiscalOperationError> {
        let startup = self
            .reconcile()
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let proposal = self.verify_proposal_at(signed, &startup)?;
        let charter = current_charter(&startup)
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let admitted_at = trusted_now(&startup)?;
        self.store
            .admit_proposal(
                &proposal,
                &charter,
                &self.admission_authority_id,
                self.admission_signer_key_epoch,
                &self.admission_signer,
                admitted_at,
                &self.fence,
            )
            .map_err(TrustFiscalOperationError::Store)
    }

    pub(crate) fn persist_approval(
        &self,
        signed_proposal: SignedFiscalProposal,
        signed_admission: SignedFiscalProposalAdmission,
        signed_approval: SignedFiscalApproval,
    ) -> Result<VerifiedFiscalApproval, TrustFiscalOperationError> {
        let startup = self
            .reconcile()
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let proposal = self.verify_proposal_at(signed_proposal, &startup)?;
        let charter = current_charter(&startup)
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let verify_at = trusted_now(&startup)?;
        let retained = self
            .store
            .load_admission_state(&signed_admission.body.admission_id)
            .map_err(TrustFiscalOperationError::Store)?;
        let trust = self.admission_trust(&charter, Some(&retained))?;
        let admission = VerifiedFiscalProposalAdmission::verify(
            signed_admission,
            &proposal,
            &charter,
            &trust,
            verify_at,
        )
        .map_err(TrustFiscalOperationError::InvalidArtifact)?;
        if retained.signed_admission != *admission.signed()
            || retained.admission_digest != admission.digest()
            || retained.status != chio_fiscal::FiscalProposalAdmissionStatus::Admitted
        {
            return Err(TrustFiscalOperationError::Store(
                chio_store_sqlite::fiscal_store::FiscalStoreError::Conflict,
            ));
        }
        let approval = VerifiedFiscalApproval::verify(
            signed_approval,
            &proposal,
            &admission,
            &charter,
            verify_at,
        )
        .map_err(TrustFiscalOperationError::InvalidArtifact)?;
        self.store
            .persist_approval(&approval, &self.fence)
            .map_err(TrustFiscalOperationError::Store)?;
        Ok(approval)
    }

    pub(crate) fn activate(
        &self,
        signed_proposal: SignedFiscalProposal,
        signed_admission: SignedFiscalProposalAdmission,
        signed_activation: SignedFiscalActivation,
        next_checkpoint: SignedFiscalContinuityCheckpoint,
    ) -> Result<chio_fiscal::VerifiedFiscalContinuityCheckpoint, TrustFiscalOperationError> {
        let startup = self
            .reconcile()
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let proposal = self.verify_proposal_at(signed_proposal, &startup)?;
        let charter = current_charter(&startup)
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let activated_at = signed_activation.body.activated_at;
        if activated_at > trusted_now(&startup)? {
            return Err(TrustFiscalOperationError::InvalidArtifact(
                chio_fiscal::FiscalError::InvalidField("activation.activated_at"),
            ));
        }
        let admitted = self
            .store
            .load_admission_state(&signed_admission.body.admission_id)
            .map_err(TrustFiscalOperationError::Store)?;
        let trust = self.admission_trust(&charter, Some(&admitted))?;
        let admission = VerifiedFiscalProposalAdmission::verify(
            signed_admission,
            &proposal,
            &charter,
            &trust,
            activated_at,
        )
        .map_err(TrustFiscalOperationError::InvalidArtifact)?;
        if admitted.signed_admission != *admission.signed()
            || admitted.admission_digest != admission.digest()
            || admitted.status != chio_fiscal::FiscalProposalAdmissionStatus::Admitted
        {
            return Err(TrustFiscalOperationError::Store(
                chio_store_sqlite::fiscal_store::FiscalStoreError::Conflict,
            ));
        }
        for signed_approval in &signed_activation.body.approvals {
            let approval = VerifiedFiscalApproval::verify(
                signed_approval.clone(),
                &proposal,
                &admission,
                &charter,
                activated_at,
            )
            .map_err(TrustFiscalOperationError::InvalidArtifact)?;
            self.store
                .require_approval(&approval)
                .map_err(TrustFiscalOperationError::Store)?;
        }

        match (&proposal.body().target, &signed_activation.body.target) {
            (
                FiscalProposalTarget::Schedule { candidate },
                FiscalActivationTarget::Schedule { .. },
            ) => {
                let domain = candidate.body.domain;
                let predecessor = active_schedule(&self.store, &startup, domain)?;
                let candidate = VerifiedFiscalSchedule::verify(
                    candidate.as_ref().clone(),
                    &charter,
                    predecessor.as_ref(),
                )
                .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                let activation = verify_consumed_activation(
                    signed_activation,
                    &proposal,
                    &admission,
                    &admitted,
                    &charter,
                    &trust,
                    predecessor.as_ref(),
                    &[],
                    candidate.body().sequence,
                    activated_at,
                )?;
                let change = FiscalContinuityChange::Activation {
                    activation: Box::new(activation.clone()),
                    readiness: Box::new(startup.readiness.clone()),
                    domain,
                    schedule: Box::new(candidate.clone()),
                };
                let advance = VerifiedFiscalContinuityAdvance::verify(
                    &startup.checkpoint,
                    next_checkpoint,
                    &self.policy,
                    &startup.charters,
                    &change,
                )
                .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                let next_authority = next_authority(&self.store, &self.policy, advance.next())?;
                self.store
                    .persist_activation(&activation, &self.fence)
                    .map_err(TrustFiscalOperationError::Store)?;
                commit_fiscal_activation(
                    &self.store,
                    self.anchor.as_ref(),
                    advance,
                    &next_authority,
                    &activation,
                    &admitted
                        .activate(activation.digest().to_owned(), candidate.body().sequence)
                        .map_err(TrustFiscalOperationError::InvalidArtifact)?,
                    &candidate,
                    predecessor.as_ref(),
                    &self.policy,
                    &startup.charters,
                    &self.fence,
                )
                .map_err(TrustFiscalOperationError::Commit)
            }
            (
                FiscalProposalTarget::CharterRotation { successor },
                FiscalActivationTarget::CharterRotation {
                    successor_schedules,
                    ..
                },
            ) => {
                let successor = VerifiedFiscalCharter::verify(successor.as_ref().clone())
                    .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                let predecessors = active_schedules(&self.store, &startup)?;
                let candidates = successor_schedules
                    .iter()
                    .zip(&predecessors)
                    .map(|(candidate, predecessor)| {
                        VerifiedFiscalSchedule::verify_rotation_replacement(
                            candidate.clone(),
                            &successor,
                            predecessor,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                let activated_sequence = candidates
                    .iter()
                    .map(|schedule| schedule.body().sequence)
                    .max()
                    .ok_or({
                        TrustFiscalOperationError::InvalidArtifact(
                            chio_fiscal::FiscalError::InvalidField(
                                "activation.successor_schedules",
                            ),
                        )
                    })?;
                let activation = verify_consumed_activation(
                    signed_activation,
                    &proposal,
                    &admission,
                    &admitted,
                    &charter,
                    &trust,
                    None,
                    &predecessors,
                    activated_sequence,
                    activated_at,
                )?;
                let replacement_domains = startup
                    .checkpoint
                    .body()
                    .domains
                    .iter()
                    .map(|state| {
                        candidates
                            .iter()
                            .find(|schedule| schedule.body().domain == state.domain)
                            .map(|schedule| {
                                let head = FiscalScheduleHead::from_signed(schedule.signed())?;
                                chio_fiscal::FiscalDomainState::activated(
                                    state.domain,
                                    head.clone(),
                                    head,
                                )
                            })
                            .unwrap_or_else(|| Ok(state.clone()))
                    })
                    .collect::<Result<Vec<_>, chio_fiscal::FiscalError>>()
                    .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                let change = FiscalContinuityChange::CharterRotation {
                    activation: Box::new(activation.clone()),
                    readiness: Box::new(startup.readiness.clone()),
                    predecessor_schedules: predecessors.clone(),
                    replacement_domains,
                };
                let advance = VerifiedFiscalContinuityAdvance::verify(
                    &startup.checkpoint,
                    next_checkpoint,
                    &self.policy,
                    &startup.charters,
                    &change,
                )
                .map_err(TrustFiscalOperationError::InvalidArtifact)?;
                let next_authority = next_authority(&self.store, &self.policy, advance.next())?;
                self.store
                    .persist_activation(&activation, &self.fence)
                    .map_err(TrustFiscalOperationError::Store)?;
                commit_fiscal_charter_rotation(
                    &self.store,
                    self.anchor.as_ref(),
                    advance,
                    &next_authority,
                    &activation,
                    &admitted
                        .activate(activation.digest().to_owned(), activated_sequence)
                        .map_err(TrustFiscalOperationError::InvalidArtifact)?,
                    &successor,
                    &candidates,
                    &charter,
                    &predecessors,
                    &self.policy,
                    &startup.charters,
                    &self.fence,
                )
                .map_err(TrustFiscalOperationError::Commit)
            }
            _ => Err(TrustFiscalOperationError::InvalidArtifact(
                chio_fiscal::FiscalError::InvalidField("activation.target"),
            )),
        }
    }

    pub(crate) fn resolve(
        &self,
        domain: FiscalDomain,
        request_currency: Option<&str>,
    ) -> Result<FiscalResolution<FiscalParams>, TrustFiscalOperationError> {
        self.with_resolver(|resolver| resolver.resolve(domain, request_currency))
    }

    pub(crate) fn with_resolver<T>(
        &self,
        resolve: impl FnOnce(&FiscalResolver<'_>) -> T,
    ) -> Result<T, TrustFiscalOperationError> {
        let startup = self
            .reconcile()
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let authority = self
            .store
            .load_authority_state()
            .map_err(TrustFiscalOperationError::Store)?;
        let schedules = self
            .store
            .load_signed_schedules()
            .map_err(TrustFiscalOperationError::Store)?;
        let history = self.activation_history(&startup)?;
        Ok(resolve(&FiscalResolver {
            continuity: chio_fiscal::FiscalContinuitySnapshot::Verified(&startup.checkpoint),
            policy: &self.policy,
            readiness: &startup.readiness,
            activation_history: &history,
            authority: &authority,
            charters: &startup.charters,
            schedules: &schedules,
            verify_at: startup.checkpoint.body().trusted_clock_high_water,
        }))
    }

    pub(crate) fn legacy_fee_schedule_binding(
        &self,
        fiscal_schedule_id: &str,
    ) -> Result<Option<FiscalLegacyFeeScheduleBinding>, TrustFiscalOperationError> {
        match self
            .store
            .load_legacy_fee_schedule_binding(fiscal_schedule_id)
        {
            Ok(binding) => Ok(Some(FiscalLegacyFeeScheduleBinding {
                fiscal_schedule_id: binding.fiscal_schedule_id,
                legacy_envelope_digest: binding.legacy_envelope_digest,
            })),
            Err(chio_store_sqlite::fiscal_store::FiscalStoreError::NotFound) => Ok(None),
            Err(error) => Err(TrustFiscalOperationError::Store(error)),
        }
    }

    pub(crate) fn bind_legacy_fee_schedule(
        &self,
        fiscal_schedule_id: &str,
        legacy: &chio_fiscal::fee_schedule::SignedOpenMarketFeeSchedule,
    ) -> Result<(), TrustFiscalOperationError> {
        let startup = self
            .reconcile()
            .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?;
        let schedule = self
            .store
            .load_verified_schedule(fiscal_schedule_id, &startup.charters)
            .map_err(TrustFiscalOperationError::Store)?;
        self.store
            .bind_legacy_fee_schedule(legacy, &schedule, &self.fence)
            .map_err(TrustFiscalOperationError::Store)
    }

    fn activation_history(
        &self,
        startup: &FiscalRuntimeStartup,
    ) -> Result<FiscalActivationHistory, TrustFiscalOperationError> {
        let proposals = self
            .store
            .load_signed_proposals()
            .map_err(TrustFiscalOperationError::Store)?;
        let activations = self
            .store
            .load_signed_activations()
            .map_err(TrustFiscalOperationError::Store)?;
        let mut verified = Vec::with_capacity(activations.len());
        for signed_activation in activations {
            let activated_at = signed_activation.body.activated_at;
            let charter = startup
                .charters
                .resolve(
                    &signed_activation.body.charter_id,
                    &signed_activation.body.charter_digest,
                )
                .map_err(TrustFiscalOperationError::InvalidArtifact)?;
            let signed_proposal = proposals
                .iter()
                .find(|proposal| proposal.body.proposal_id == signed_activation.body.proposal_id)
                .ok_or_else(|| {
                    TrustFiscalOperationError::Startup(
                        "activated fiscal proposal is missing".to_owned(),
                    )
                })?;
            let predecessor = match &signed_proposal.body.target {
                FiscalProposalTarget::Schedule { candidate } => candidate
                    .body
                    .supersedes_schedule_id
                    .as_deref()
                    .map(|id| self.store.load_verified_schedule(id, &startup.charters))
                    .transpose()
                    .map_err(TrustFiscalOperationError::Store)?,
                FiscalProposalTarget::CharterRotation { .. } => None,
            };
            let proposal = VerifiedFiscalProposal::verify(
                signed_proposal.clone(),
                &charter,
                predecessor.as_ref(),
            )
            .map_err(TrustFiscalOperationError::InvalidArtifact)?;
            let state = self
                .store
                .load_admission_state(&signed_activation.body.admission_id)
                .map_err(TrustFiscalOperationError::Store)?;
            let trust = self.admission_trust(&charter, Some(&state))?;
            let admission = VerifiedFiscalProposalAdmission::verify(
                state.signed_admission.clone(),
                &proposal,
                &charter,
                &trust,
                signed_activation.body.activated_at,
            )
            .map_err(TrustFiscalOperationError::InvalidArtifact)?;
            let rotation_predecessors = match &signed_activation.body.target {
                FiscalActivationTarget::Schedule { .. } => Vec::new(),
                FiscalActivationTarget::CharterRotation {
                    successor_schedules,
                    ..
                } => successor_schedules
                    .iter()
                    .map(|schedule| {
                        schedule
                            .body
                            .supersedes_schedule_id
                            .as_deref()
                            .ok_or(chio_store_sqlite::fiscal_store::FiscalStoreError::Conflict)
                            .and_then(|id| self.store.load_verified_schedule(id, &startup.charters))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(TrustFiscalOperationError::Store)?,
            };
            let activation = VerifiedFiscalActivation::verify(
                signed_activation,
                &proposal,
                &admission,
                &state,
                &charter,
                &trust,
                predecessor.as_ref(),
                &rotation_predecessors,
                activated_at,
            )
            .map_err(TrustFiscalOperationError::InvalidArtifact)?;
            verified.push(activation);
        }
        let checkpoints = self
            .store
            .load_finalized_checkpoints(&self.policy, &startup.charters)
            .map_err(TrustFiscalOperationError::Store)?;
        FiscalActivationHistory::from_checkpoint_history(
            verified,
            &checkpoints,
            &startup.checkpoint,
        )
        .map_err(TrustFiscalOperationError::InvalidArtifact)
    }

    fn admission_trust(
        &self,
        charter: &VerifiedFiscalCharter,
        retained: Option<&chio_fiscal::FiscalProposalAdmissionState>,
    ) -> Result<FiscalAdmissionTrustRegistry, TrustFiscalOperationError> {
        let current = FiscalAdmissionAuthority::new(
            charter.body().governing_operator_id.clone(),
            self.admission_authority_id.clone(),
            self.admission_signer_key_epoch,
            self.admission_signer.public_key(),
        )
        .map_err(TrustFiscalOperationError::InvalidArtifact)?;
        let mut authorities = vec![current.clone()];
        if let Some(retained) = retained {
            let signed = &retained.signed_admission;
            let historical = FiscalAdmissionAuthority::new(
                signed.body.governing_operator_id.clone(),
                signed.body.admission_authority_id.clone(),
                signed.body.signer_key_epoch,
                signed.signer_key.clone(),
            )
            .map_err(TrustFiscalOperationError::InvalidArtifact)?;
            if historical != current {
                authorities.push(historical);
            }
        }
        FiscalAdmissionTrustRegistry::new(authorities)
            .map_err(TrustFiscalOperationError::InvalidArtifact)
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_consumed_activation(
    signed: SignedFiscalActivation,
    proposal: &VerifiedFiscalProposal,
    admission: &VerifiedFiscalProposalAdmission,
    admitted: &chio_fiscal::FiscalProposalAdmissionState,
    charter: &VerifiedFiscalCharter,
    trust: &FiscalAdmissionTrustRegistry,
    predecessor: Option<&VerifiedFiscalSchedule>,
    rotation_predecessors: &[VerifiedFiscalSchedule],
    activated_sequence: u64,
    activated_at: u64,
) -> Result<VerifiedFiscalActivation, TrustFiscalOperationError> {
    let staged = VerifiedFiscalActivation::verify(
        signed.clone(),
        proposal,
        admission,
        admitted,
        charter,
        trust,
        predecessor,
        rotation_predecessors,
        activated_at,
    )
    .map_err(TrustFiscalOperationError::InvalidArtifact)?;
    let activated = admitted
        .activate(staged.digest().to_owned(), activated_sequence)
        .map_err(TrustFiscalOperationError::InvalidArtifact)?;
    VerifiedFiscalActivation::verify(
        signed,
        proposal,
        admission,
        &activated,
        charter,
        trust,
        predecessor,
        rotation_predecessors,
        activated_at,
    )
    .map_err(TrustFiscalOperationError::InvalidArtifact)
}

fn active_schedule(
    store: &SqliteFiscalStore,
    startup: &FiscalRuntimeStartup,
    domain: chio_fiscal::FiscalDomain,
) -> Result<Option<VerifiedFiscalSchedule>, TrustFiscalOperationError> {
    let state = startup
        .checkpoint
        .body()
        .domains
        .iter()
        .find(|state| state.domain == domain)
        .ok_or_else(|| {
            TrustFiscalOperationError::Startup("fiscal domain state is missing".to_owned())
        })?;
    state
        .active
        .as_ref()
        .map(|head| store.load_verified_schedule(&head.schedule_id, &startup.charters))
        .transpose()
        .map_err(TrustFiscalOperationError::Store)
}

fn active_schedules(
    store: &SqliteFiscalStore,
    startup: &FiscalRuntimeStartup,
) -> Result<Vec<VerifiedFiscalSchedule>, TrustFiscalOperationError> {
    startup
        .checkpoint
        .body()
        .domains
        .iter()
        .filter(|state| state.ever_activated)
        .map(|state| {
            let head = state.active.as_ref().ok_or_else(|| {
                TrustFiscalOperationError::Startup(
                    "activated fiscal domain has no anchored active schedule".to_owned(),
                )
            })?;
            store
                .load_verified_schedule(&head.schedule_id, &startup.charters)
                .map_err(TrustFiscalOperationError::Store)
        })
        .collect()
}

fn next_authority(
    store: &SqliteFiscalStore,
    policy: &FiscalGenesisPolicy,
    checkpoint: &chio_fiscal::VerifiedFiscalContinuityCheckpoint,
) -> Result<FiscalAuthorityState, TrustFiscalOperationError> {
    let current = store
        .load_authority_state()
        .map_err(TrustFiscalOperationError::Store)?;
    FiscalAuthorityState::from_checkpoint(policy, checkpoint, current.bootstrap_state)
        .map_err(TrustFiscalOperationError::InvalidArtifact)
}

fn trusted_now(startup: &FiscalRuntimeStartup) -> Result<u64, TrustFiscalOperationError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| TrustFiscalOperationError::Startup(error.to_string()))?
        .as_secs();
    if now < startup.checkpoint.body().trusted_clock_high_water {
        return Err(TrustFiscalOperationError::Startup(
            "system clock is below the anchored fiscal high-water mark".to_owned(),
        ));
    }
    Ok(now)
}

fn current_charter(startup: &FiscalRuntimeStartup) -> Result<VerifiedFiscalCharter, CliError> {
    startup
        .charters
        .resolve(
            &startup.checkpoint.body().pinned_charter_id,
            &startup.checkpoint.body().pinned_charter_digest,
        )
        .map_err(fiscal_startup_error)
}

pub(crate) fn compose_trust_fiscal_runtime(
    authority: Option<&Arc<SqliteAuthorityStore>>,
    config: Option<&TrustFiscalRuntimeConfig>,
) -> Result<Option<Arc<TrustFiscalRuntime>>, CliError> {
    let Some(config) = config else {
        return Ok(None);
    };
    let authority = authority.ok_or_else(|| {
        CliError::cli_other_error("fiscal runtime requires the joint authority database".to_owned())
    })?;
    let store = authority.fiscal_store();
    let charters = store
        .load_charter_registry()
        .map_err(fiscal_startup_error)?;
    let anchor = compose_fiscal_state_anchor(RemoteFiscalStateAnchorConfig {
        base_url: config.anchor_url.clone(),
        bearer_token: config.anchor_bearer_token.clone(),
        timeout: config.anchor_timeout,
        policy: config.genesis_policy.clone(),
        charters,
    })
    .map_err(fiscal_startup_error)?;
    compose_trust_fiscal_runtime_with_anchor(authority, config, anchor).map(Some)
}

fn compose_trust_fiscal_runtime_with_anchor(
    authority: &SqliteAuthorityStore,
    config: &TrustFiscalRuntimeConfig,
    anchor: Arc<dyn FiscalStateAnchor>,
) -> Result<Arc<TrustFiscalRuntime>, CliError> {
    let store = authority.fiscal_store();
    let fence = authority.mutation_fence();
    let registry = production_fiscal_runtime_assembler()
        .and_then(|assembler| {
            assembler.self_test_and_build_registry(
                env!("CARGO_PKG_VERSION"),
                FISCAL_RUNTIME_SCHEMA_VERSION,
            )
        })
        .map_err(fiscal_startup_error)?;
    let seed_hex =
        std::fs::read_to_string(&config.admission_signing_seed_path).map_err(|error| {
            fiscal_startup_error(format!(
                "failed to read fiscal admission signing seed {}: {error}",
                config.admission_signing_seed_path.display()
            ))
        })?;
    let admission_signer = Keypair::from_seed_hex(seed_hex.trim()).map_err(fiscal_startup_error)?;
    reconcile_fiscal_runtime_startup(
        &store,
        anchor.as_ref(),
        &config.genesis_policy,
        &registry,
        &fence,
    )
    .map_err(fiscal_startup_error)?;
    Ok(Arc::new(TrustFiscalRuntime {
        store,
        fence,
        anchor,
        policy: config.genesis_policy.clone(),
        registry,
        admission_authority_id: config.admission_authority_id.clone(),
        admission_signer_key_epoch: config.admission_signer_key_epoch,
        admission_signer,
    }))
}

fn fiscal_startup_error(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!(
        "fiscal runtime failed closed during trust-control startup: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::scope::MonetaryAmount;
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_fiscal::{
        FiscalAuthorityState, FiscalBootstrapState, FiscalCharterRegistry,
        FiscalContinuityCheckpointBuilder, FiscalDomain, FiscalDomainState, FiscalParams,
        FiscalProposalBuilder, FiscalProposalTarget, FiscalRuntimeReadinessBuilder,
        FiscalScheduleBuilder, FiscalStateAnchorError, SignedFiscalCharter,
        SignedFiscalContinuityCheckpoint, VerifiedFiscalCharter,
        VerifiedFiscalContinuityCheckpoint, VerifiedFiscalRuntimeReadiness,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct FixedAnchor(SignedFiscalContinuityCheckpoint);

    impl FiscalStateAnchor for FixedAnchor {
        fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
            Ok(self.0.clone())
        }

        fn compare_and_swap(
            &self,
            _expected_checkpoint_digest: &str,
            _advance: &chio_fiscal::VerifiedFiscalContinuityAdvance,
        ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
            Err(FiscalStateAnchorError::Conflict)
        }
    }

    fn fixture_bytes(name: &str) -> TestResult<Vec<u8>> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
        ));
        Ok(std::fs::read(path)?)
    }

    #[test]
    fn service_composition_recomputes_readiness_before_serving() -> TestResult {
        let policy: FiscalGenesisPolicy =
            serde_json::from_slice(&fixture_bytes("genesis-policy")?)?;
        let charter = VerifiedFiscalCharter::verify(
            serde_json::from_slice::<SignedFiscalCharter>(&fixture_bytes("charter")?)?,
        )?;
        let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()])?;
        let registry = production_fiscal_runtime_assembler()?.self_test_and_build_registry(
            env!("CARGO_PKG_VERSION"),
            FISCAL_RUNTIME_SCHEMA_VERSION,
        )?;
        let anchor_key = Keypair::from_seed(&[8; 32]);
        let readiness = VerifiedFiscalRuntimeReadiness::verify(
            FiscalRuntimeReadinessBuilder {
                readiness_sequence: 1,
                runtime_registry: registry.clone(),
                attested_at: 50,
            }
            .sign(&policy, &anchor_key)?,
            &policy,
            registry,
        )?;
        let checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
            FiscalContinuityCheckpointBuilder {
                continuity_sequence: 0,
                previous_checkpoint_digest: None,
                pinned_charter_id: charter.body().charter_id.clone(),
                pinned_charter_digest: charter.digest().to_owned(),
                pinned_charter_sequence: charter.body().sequence,
                runtime_readiness_digest: readiness.digest().to_owned(),
                domains: [
                    FiscalDomain::TierLimits,
                    FiscalDomain::MarketplaceDiscountPerHundred,
                    FiscalDomain::DecisionPremiumBasisPoints,
                    FiscalDomain::InsurancePremiumSchedule,
                    FiscalDomain::OpenMarketFeeAndBondSchedule,
                ]
                .into_iter()
                .map(FiscalDomainState::never_activated)
                .collect(),
                trusted_clock_high_water: 50,
                staged_transition: None,
            }
            .sign(&policy, &anchor_key)?,
            &policy,
            &charters,
        )?;
        let authority_state = FiscalAuthorityState::from_checkpoint(
            &policy,
            &checkpoint,
            FiscalBootstrapState::CharterPinned,
        )?;
        let temp = tempfile::tempdir()?;
        crate::create_private_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        crate::create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        authority.fiscal_store().initialize_genesis(
            &policy,
            &authority_state,
            &charter,
            &readiness,
            &checkpoint,
            &authority.mutation_fence(),
        )?;
        let admission_seed_path = temp.path().join("fiscal-admission.seed");
        std::fs::write(
            &admission_seed_path,
            format!("{}\n", Keypair::from_seed(&[7; 32]).seed_hex()),
        )?;
        let config = TrustFiscalRuntimeConfig {
            genesis_policy: policy,
            anchor_url: "https://fiscal-anchor.example".to_owned(),
            anchor_bearer_token: "fixture-token".to_owned(),
            anchor_timeout: Duration::from_secs(1),
            admission_authority_id: "fiscal-admission".to_owned(),
            admission_signer_key_epoch: 1,
            admission_signing_seed_path: admission_seed_path,
        };

        let runtime = compose_trust_fiscal_runtime_with_anchor(
            &authority,
            &config,
            Arc::new(FixedAnchor(checkpoint.signed().clone())),
        )?;

        let reconciled = runtime.reconcile()?;
        assert_eq!(reconciled.checkpoint.digest(), checkpoint.digest());
        assert_eq!(reconciled.readiness.digest(), readiness.digest());
        assert_eq!(runtime.policy, config.genesis_policy);
        assert_eq!(runtime.store.load_authority_state()?, authority_state);
        assert_eq!(runtime.fence, authority.mutation_fence());
        assert_eq!(runtime.anchor.read()?, *checkpoint.signed());

        let price = runtime.with_resolver(|resolver| {
            chio_appraisal::compute_fiscal_marketplace_invocation_price(
                &chio_appraisal::MarketplaceBasePrice::new(1_000, "USD"),
                &chio_appraisal::MarketplacePricingContext::new(
                    "tenant-a",
                    chio_appraisal::MarketplaceReputationTier::Tier1,
                ),
                resolver,
            )
        })??;
        assert_eq!(price.units, 950);
        let limit = runtime
            .with_resolver(|resolver| {
                chio_underwriting::compute_fiscal_marketplace_credit_limit(
                    &chio_underwriting::MarketplaceCreditLimitRequest {
                        tenant_id: "tenant-a".to_owned(),
                        reputation_tier: chio_underwriting::MarketplaceLimitTier::Tier1,
                        currency: "USD".to_owned(),
                        publisher_revoked: false,
                    },
                    resolver,
                )
            })?
            .map_err(|reason| {
                std::io::Error::other(format!(
                    "fiscal marketplace credit-limit resolution denied: {reason:?}"
                ))
            })?;
        assert_eq!(limit.limit_units, 200);

        let candidate = FiscalScheduleBuilder {
            domain: FiscalDomain::TierLimits,
            params: FiscalParams::TierLimits {
                ceilings: [100, 200, 300, 400].map(|units| MonetaryAmount {
                    units,
                    currency: "USD".to_owned(),
                }),
            },
            valid_from: 60,
            valid_until: 900,
            issued_at: 50,
            issued_by: "operator.example".to_owned(),
        }
        .sign(&charter, None, &Keypair::from_seed(&[1; 32]))?;
        let signed_proposal = FiscalProposalBuilder {
            target: FiscalProposalTarget::Schedule {
                candidate: Box::new(candidate.clone()),
            },
            rationale_digest: sha256_hex(b"fixture rationale"),
            proposed_at: 50,
        }
        .sign(&Keypair::from_seed(&[2; 32]))?;
        assert_eq!(
            runtime.preview_proposal(signed_proposal.clone())?.signed(),
            &signed_proposal
        );
        let persisted = runtime.persist_proposal(signed_proposal)?;
        assert_eq!(
            persisted.body().proposal_id,
            persisted.signed().body.proposal_id
        );
        assert_eq!(
            runtime
                .store
                .load_verified_schedule(&candidate.body.schedule_id, &charters)?
                .signed(),
            &candidate
        );

        let historical_signer = Keypair::from_seed(&[6; 32]);
        let historical_signed = chio_fiscal::FiscalProposalAdmissionBuilder {
            admission_sequence: 1,
            admitted_at: 55,
            admission_authority_id: "fiscal-admission".to_owned(),
            signer_key_epoch: 7,
        }
        .sign(&persisted, &charter, &historical_signer)?;
        let historical_trust =
            FiscalAdmissionTrustRegistry::new(vec![FiscalAdmissionAuthority::new(
                charter.body().governing_operator_id.clone(),
                "fiscal-admission".to_owned(),
                7,
                historical_signer.public_key(),
            )?])?;
        let historical = VerifiedFiscalProposalAdmission::verify(
            historical_signed,
            &persisted,
            &charter,
            &historical_trust,
            55,
        )?;
        let retained = chio_fiscal::FiscalProposalAdmissionState::admitted(&historical);
        let rotated_trust = runtime.admission_trust(&charter, Some(&retained))?;
        assert!(VerifiedFiscalProposalAdmission::verify(
            retained.signed_admission.clone(),
            &persisted,
            &charter,
            &rotated_trust,
            55,
        )
        .is_ok());
        Ok(())
    }
}
