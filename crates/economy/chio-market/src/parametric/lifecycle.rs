use chio_core_types::economic_continuity::{
    EconomicContentV1, EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError,
    EconomicStateBatchV1, EconomicStateTransitionV1, EconomicTransitionAuthorizationV1,
    EconomicTransitionProofVerifier, VerifiedEconomicStateView, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    canonical_digest, domain_digest, EvidenceCorpusManifestV1, ParametricClaimError,
    ParametricClaimIdentity, ParametricClaimRecordV1, ParametricClaimStateV1,
    ParametricContractError, ParametricTriggerWindow, SignedParametricPolicy, TriggerMagnitude,
    VerifiedEvidenceCorpusV1, VerifiedFiredTriggerV1, VerifiedParametricPolicy,
    VerifiedTriggerVerdictV1, TRIGGER_PREDICATE_DIGEST_DOMAIN,
};

pub const PARAMETRIC_TRIGGER_RESOURCE_FAMILY: &str = "parametric_trigger";
pub const PARAMETRIC_CLAIM_RESOURCE_FAMILY: &str = "parametric_claim";
pub const PARAMETRIC_CLAIM_OPENING_STATE_SCHEMA: &str = "chio.parametric.claim-opening-state.v1";
pub const PARAMETRIC_FIRED_TRIGGER_RECORD_SCHEMA: &str = "chio.parametric.fired-trigger-record.v1";
pub const PARAMETRIC_CLAIM_OPENING_PROOF_DOMAIN: &str = "chio.parametric.claim-opening-proof.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParametricLifecycleError {
    #[error(transparent)]
    Contract(#[from] ParametricContractError),
    #[error(transparent)]
    Claim(#[from] ParametricClaimError),
    #[error("parametric claim opening conflicts with retained economic state")]
    Conflict,
    #[error("parametric claim opening economic projection is invalid")]
    InvalidEconomicProjection,
    #[error("parametric claim opening trusted time regressed authenticated state")]
    StaleTrustedTime,
    #[error("parametric claim opening checkpoint sequence overflowed")]
    CheckpointOverflow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricFiredTriggerRecordV1 {
    schema: String,
    signed_policy: SignedParametricPolicy,
    evidence_manifest: EvidenceCorpusManifestV1,
    identity: ParametricClaimIdentity,
    magnitude: TriggerMagnitude,
}

impl ParametricFiredTriggerRecordV1 {
    fn from_verified(
        policy: &VerifiedParametricPolicy,
        corpus: &VerifiedEvidenceCorpusV1,
        trigger: &VerifiedFiredTriggerV1,
    ) -> Result<Self, ParametricLifecycleError> {
        let evaluated = policy.evaluate_trigger(corpus)?;
        if !matches!(evaluated, VerifiedTriggerVerdictV1::Fired(ref fired) if fired.as_ref() == trigger)
        {
            return Err(ParametricLifecycleError::Conflict);
        }
        let record = Self {
            schema: PARAMETRIC_FIRED_TRIGGER_RECORD_SCHEMA.to_owned(),
            signed_policy: policy.signed().clone(),
            evidence_manifest: corpus.manifest().clone(),
            identity: trigger.identity().clone(),
            magnitude: trigger.magnitude().clone(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), ParametricLifecycleError> {
        if self.schema != PARAMETRIC_FIRED_TRIGGER_RECORD_SCHEMA {
            return Err(ParametricLifecycleError::Conflict);
        }
        self.signed_policy.body.validate()?;
        if !self
            .signed_policy
            .verify_signature()
            .map_err(|_| ParametricLifecycleError::Conflict)?
        {
            return Err(ParametricLifecycleError::Conflict);
        }
        self.identity.validate()?;
        let policy = &self.signed_policy.body;
        let window = ParametricTriggerWindow {
            start_at: self.identity.key.window_start,
            end_at: self.identity.key.window_end,
        };
        policy.validate_window(&window)?;
        if canonical_digest(policy)? != self.identity.key.parametric_policy_body_digest
            || policy.bound_coverage_body_digest != self.identity.key.bound_coverage_body_digest
            || policy.subject_key != self.identity.key.subject_key
            || domain_digest(TRIGGER_PREDICATE_DIGEST_DOMAIN, &policy.predicate)?
                != self.identity.key.trigger_predicate_body_digest
            || self.evidence_manifest.semantic_digest(
                &policy.predicate,
                &policy.subject_key,
                &window,
                policy.max_checkpoint_lag_seconds,
            )? != self.identity.key.evidence_range_digest
            || self.magnitude.unit() != policy.predicate.magnitude_unit()
        {
            return Err(ParametricLifecycleError::Conflict);
        }
        policy.payout_schedule.evaluate(
            &policy.predicate,
            &self.magnitude,
            &policy.coverage_amount,
        )?;
        Ok(())
    }

    fn matches_verified(
        &self,
        policy: &VerifiedParametricPolicy,
        corpus: &VerifiedEvidenceCorpusV1,
        trigger: &VerifiedFiredTriggerV1,
    ) -> Result<(), ParametricLifecycleError> {
        self.validate()?;
        let incoming = Self::from_verified(policy, corpus, trigger)?;
        if self.signed_policy != *policy.signed()
            || self.identity != incoming.identity
            || self.magnitude != incoming.magnitude
        {
            return Err(ParametricLifecycleError::Conflict);
        }
        Ok(())
    }

    #[must_use]
    pub const fn identity(&self) -> &ParametricClaimIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn magnitude(&self) -> &TriggerMagnitude {
        &self.magnitude
    }

    #[must_use]
    pub const fn signed_policy(&self) -> &SignedParametricPolicy {
        &self.signed_policy
    }

    #[must_use]
    pub const fn evidence_manifest(&self) -> &EvidenceCorpusManifestV1 {
        &self.evidence_manifest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricClaimOpeningStateV1 {
    schema: String,
    trigger: ParametricFiredTriggerRecordV1,
    claim: ParametricClaimRecordV1,
    trusted_opened_at: u64,
}

impl ParametricClaimOpeningStateV1 {
    fn from_verified(
        policy: &VerifiedParametricPolicy,
        corpus: &VerifiedEvidenceCorpusV1,
        trigger: &VerifiedFiredTriggerV1,
        trusted_opened_at: u64,
    ) -> Result<Self, ParametricLifecycleError> {
        let trigger_authority =
            ParametricFiredTriggerRecordV1::from_verified(policy, corpus, trigger)?;
        let claim = ParametricClaimRecordV1::open(policy, trigger, trusted_opened_at)?;
        claim.verify_semantic_replay(policy, trigger)?;
        let state = Self {
            schema: PARAMETRIC_CLAIM_OPENING_STATE_SCHEMA.to_owned(),
            trigger: trigger_authority,
            claim,
            trusted_opened_at,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), ParametricLifecycleError> {
        if self.schema != PARAMETRIC_CLAIM_OPENING_STATE_SCHEMA || self.trusted_opened_at == 0 {
            return Err(ParametricLifecycleError::Conflict);
        }
        self.trigger.validate()?;
        self.claim.validate()?;
        if self.claim.claim_id() != self.trigger.identity.claim_id
            || self.claim.trigger_instance_id() != self.trigger.identity.trigger_instance_id
            || self.claim.opened_at() != self.trusted_opened_at
            || self.claim.trigger_magnitude() != self.trigger.magnitude()
        {
            return Err(ParametricLifecycleError::Conflict);
        }
        Ok(())
    }

    fn proof_digest(&self) -> Result<String, ParametricLifecycleError> {
        self.validate()?;
        Ok(domain_digest(PARAMETRIC_CLAIM_OPENING_PROOF_DOMAIN, self)?)
    }

    #[must_use]
    pub const fn trigger(&self) -> &ParametricFiredTriggerRecordV1 {
        &self.trigger
    }

    #[must_use]
    pub const fn claim(&self) -> &ParametricClaimRecordV1 {
        &self.claim
    }

    #[must_use]
    pub const fn trusted_opened_at(&self) -> u64 {
        self.trusted_opened_at
    }
}

#[must_use]
pub fn parametric_trigger_resource_key(
    identity: &ParametricClaimIdentity,
) -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: PARAMETRIC_TRIGGER_RESOURCE_FAMILY.to_owned(),
        scope_id: identity.key.bound_coverage_body_digest.clone(),
        resource_id: identity.trigger_instance_id.clone(),
    }
}

#[must_use]
pub fn parametric_claim_resource_key(identity: &ParametricClaimIdentity) -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: PARAMETRIC_CLAIM_RESOURCE_FAMILY.to_owned(),
        scope_id: identity.key.bound_coverage_body_digest.clone(),
        resource_id: identity.claim_id.clone(),
    }
}

#[derive(Debug, Clone)]
pub struct ParametricClaimOpeningBatchTemplateV1 {
    unsigned_batch: EconomicStateBatchV1,
}

impl ParametricClaimOpeningBatchTemplateV1 {
    #[must_use]
    pub const fn unsigned_batch(&self) -> &EconomicStateBatchV1 {
        &self.unsigned_batch
    }

    #[must_use]
    pub fn into_unsigned_batch(self) -> EconomicStateBatchV1 {
        self.unsigned_batch
    }

    fn matches_sealed(&self, batch: &EconomicStateBatchV1) -> bool {
        let mut actual = batch.clone();
        actual.batch_id.clear();
        actual.checkpoint_digest.clear();
        actual.expected_heads_root.clear();
        actual.next_heads_root.clear();
        actual.anchor_signature.clear();
        actual == self.unsigned_batch
    }
}

#[derive(Debug, Clone)]
pub struct ParametricClaimOpeningProjectionV1 {
    current: VerifiedEconomicStateView,
    state: ParametricClaimOpeningStateV1,
    proof_digest: String,
    template: ParametricClaimOpeningBatchTemplateV1,
}

impl ParametricClaimOpeningProjectionV1 {
    #[must_use]
    pub const fn current(&self) -> &VerifiedEconomicStateView {
        &self.current
    }

    #[must_use]
    pub const fn state(&self) -> &ParametricClaimOpeningStateV1 {
        &self.state
    }

    #[must_use]
    pub const fn claim(&self) -> &ParametricClaimRecordV1 {
        self.state.claim()
    }

    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    #[must_use]
    pub const fn batch_template(&self) -> &ParametricClaimOpeningBatchTemplateV1 {
        &self.template
    }
}

#[derive(Debug, Clone)]
pub struct ParametricClaimOpeningReplayV1 {
    state: ParametricClaimOpeningStateV1,
    trigger_head: EconomicResourceHeadV1,
    claim_head: EconomicResourceHeadV1,
}

impl ParametricClaimOpeningReplayV1 {
    #[must_use]
    pub const fn state(&self) -> &ParametricClaimOpeningStateV1 {
        &self.state
    }

    #[must_use]
    pub const fn claim(&self) -> &ParametricClaimRecordV1 {
        self.state.claim()
    }

    #[must_use]
    pub const fn trigger_head(&self) -> &EconomicResourceHeadV1 {
        &self.trigger_head
    }

    #[must_use]
    pub const fn claim_head(&self) -> &EconomicResourceHeadV1 {
        &self.claim_head
    }
}

#[derive(Debug, Clone)]
pub enum ParametricClaimOpeningOutcomeV1 {
    Projected(Box<ParametricClaimOpeningProjectionV1>),
    Replay(Box<ParametricClaimOpeningReplayV1>),
}

pub fn prepare_parametric_claim_opening(
    current: &VerifiedEconomicStateView,
    policy: &VerifiedParametricPolicy,
    corpus: &VerifiedEvidenceCorpusV1,
    trigger: &VerifiedFiredTriggerV1,
    trusted_opened_at: u64,
) -> Result<ParametricClaimOpeningOutcomeV1, ParametricLifecycleError> {
    let trigger_key = parametric_trigger_resource_key(trigger.identity());
    let claim_key = parametric_claim_resource_key(trigger.identity());
    match (
        current.view().head(&trigger_key),
        current.view().head(&claim_key),
    ) {
        (Some(retained_trigger), Some(retained_claim)) => {
            ensure_trusted_time(
                current,
                trusted_opened_at,
                [retained_trigger, retained_claim],
            )?;
            let trigger_state = retained_opening_state(retained_trigger)?;
            let claim_state = retained_opening_state(retained_claim)?;
            validate_retained_trigger_head(retained_trigger, &trigger_key, &trigger_state)?;
            validate_retained_claim_head(retained_claim, &claim_key, &claim_state)?;
            trigger_state
                .trigger()
                .matches_verified(policy, corpus, trigger)
                .map_err(|_| ParametricLifecycleError::Conflict)?;
            trigger_state
                .claim()
                .verify_semantic_replay(policy, trigger)
                .map_err(|_| ParametricLifecycleError::Conflict)?;
            claim_state
                .claim()
                .verify_semantic_replay(policy, trigger)
                .map_err(|_| ParametricLifecycleError::Conflict)?;
            if trigger_state.trigger() != claim_state.trigger()
                || trigger_state.trusted_opened_at() != claim_state.trusted_opened_at()
            {
                return Err(ParametricLifecycleError::Conflict);
            }
            return Ok(ParametricClaimOpeningOutcomeV1::Replay(Box::new(
                ParametricClaimOpeningReplayV1 {
                    state: claim_state,
                    trigger_head: retained_trigger.clone(),
                    claim_head: retained_claim.clone(),
                },
            )));
        }
        (None, None)
            if current.view().proves_resource_absent(&trigger_key)
                && current.view().proves_resource_absent(&claim_key) => {}
        _ => return Err(ParametricLifecycleError::Conflict),
    }

    ensure_trusted_time(current, trusted_opened_at, [])?;
    let state =
        ParametricClaimOpeningStateV1::from_verified(policy, corpus, trigger, trusted_opened_at)?;
    let proof_digest = state.proof_digest()?;
    let trigger_head = genesis_head(current, trigger_key, "fired", &state, trusted_opened_at)?;
    let claim_head = genesis_head(
        current,
        claim_key,
        claim_lifecycle_state(state.claim()),
        &state,
        trusted_opened_at,
    )?;

    let mut transitions = vec![
        genesis_transition(trigger_head, &proof_digest),
        genesis_transition(claim_head, &proof_digest),
    ];
    transitions.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let checkpoint_sequence = current
        .view()
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ParametricLifecycleError::CheckpointOverflow)?;
    let unsigned_batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: current.view().anchor_id.clone(),
        namespace: current.view().namespace.clone(),
        checkpoint_sequence,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: None,
        issued_at: trusted_opened_at,
        signer_key_id: current.view().signer_key_id.clone(),
        signer_key_epoch: current.view().signer_key_epoch,
        anchor_signature: String::new(),
    };
    Ok(ParametricClaimOpeningOutcomeV1::Projected(Box::new(
        ParametricClaimOpeningProjectionV1 {
            current: current.clone(),
            state,
            proof_digest,
            template: ParametricClaimOpeningBatchTemplateV1 { unsigned_batch },
        },
    )))
}

#[derive(Debug, Clone)]
pub struct ParametricClaimOpeningBatchVerifier {
    projection: ParametricClaimOpeningProjectionV1,
}

impl ParametricClaimOpeningBatchVerifier {
    #[must_use]
    pub const fn new(projection: ParametricClaimOpeningProjectionV1) -> Self {
        Self { projection }
    }
}

impl EconomicTransitionProofVerifier for ParametricClaimOpeningBatchVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::TransitionProofRejected(
            transition.resource_key.clone(),
        ))
    }

    fn verify_batch(
        &self,
        current: &VerifiedEconomicStateView,
        batch: &EconomicStateBatchV1,
    ) -> Result<Vec<EconomicTransitionAuthorizationV1>, EconomicStateAnchorError> {
        let rejected = || rejected_batch(batch);
        batch.validate().map_err(|_| rejected())?;
        if current.view() != self.projection.current.view()
            || !self.projection.template.matches_sealed(batch)
        {
            return Err(rejected());
        }
        Ok(vec![
            EconomicTransitionAuthorizationV1::Direct;
            batch.transitions.len()
        ])
    }
}

fn ensure_trusted_time<'a>(
    current: &VerifiedEconomicStateView,
    trusted_time: u64,
    retained_heads: impl IntoIterator<Item = &'a EconomicResourceHeadV1>,
) -> Result<(), ParametricLifecycleError> {
    if trusted_time < current.view().observed_at {
        return Err(ParametricLifecycleError::StaleTrustedTime);
    }
    for head in retained_heads {
        if head.trusted_clock_high_water > current.view().observed_at
            || trusted_time < head.trusted_clock_high_water
        {
            return Err(ParametricLifecycleError::StaleTrustedTime);
        }
    }
    Ok(())
}

fn retained_opening_state(
    head: &EconomicResourceHeadV1,
) -> Result<ParametricClaimOpeningStateV1, ParametricLifecycleError> {
    head.validate()
        .map_err(|_| ParametricLifecycleError::Conflict)?;
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err(ParametricLifecycleError::Conflict);
    };
    let state = serde_json::from_value::<ParametricClaimOpeningStateV1>(value.clone())
        .map_err(|_| ParametricLifecycleError::Conflict)?;
    state
        .validate()
        .map_err(|_| ParametricLifecycleError::Conflict)?;
    Ok(state)
}

fn validate_retained_trigger_head(
    head: &EconomicResourceHeadV1,
    expected_key: &EconomicResourceKeyV1,
    state: &ParametricClaimOpeningStateV1,
) -> Result<(), ParametricLifecycleError> {
    if &head.resource_key != expected_key
        || head.lifecycle_state != "fired"
        || head.head_version != 1
        || head.resource_version != 1
        || head.lifecycle_fence != 1
        || head.trusted_clock_high_water != state.trusted_opened_at()
        || head.predecessor_digest.is_some()
        || head.operation_id.is_some()
        || head.effect_idempotency_key.is_some()
        || head.frost.is_some()
        || head.terminal_result.is_some()
        || state.claim().version() != 1
        || state.claim().lifecycle_fence() != 1
        || !matches!(
            state.claim().state(),
            ParametricClaimStateV1::Ready | ParametricClaimStateV1::ContestOpen
        )
    {
        return Err(ParametricLifecycleError::Conflict);
    }
    Ok(())
}

fn validate_retained_claim_head(
    head: &EconomicResourceHeadV1,
    expected_key: &EconomicResourceKeyV1,
    state: &ParametricClaimOpeningStateV1,
) -> Result<(), ParametricLifecycleError> {
    if &head.resource_key != expected_key
        || head.lifecycle_state != claim_lifecycle_state(state.claim())
        || head.head_version != state.claim().version()
        || head.resource_version != state.claim().version()
        || head.lifecycle_fence != state.claim().lifecycle_fence()
        || head.trusted_clock_high_water < state.trusted_opened_at()
    {
        return Err(ParametricLifecycleError::Conflict);
    }
    Ok(())
}

fn genesis_head(
    current: &VerifiedEconomicStateView,
    resource_key: EconomicResourceKeyV1,
    lifecycle_state: &str,
    state: &ParametricClaimOpeningStateV1,
    trusted_opened_at: u64,
) -> Result<EconomicResourceHeadV1, ParametricLifecycleError> {
    let content = EconomicContentV1::Inline {
        value: serde_json::to_value(state)
            .map_err(|_| ParametricLifecycleError::InvalidEconomicProjection)?,
    };
    let state_digest = content
        .digest()
        .map_err(|_| ParametricLifecycleError::InvalidEconomicProjection)?;
    let head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.view().anchor_id.clone(),
        namespace: current.view().namespace.clone(),
        resource_key,
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: lifecycle_state.to_owned(),
        state_digest,
        state: content,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: trusted_opened_at,
        predecessor_digest: None,
    };
    head.validate()
        .map_err(|_| ParametricLifecycleError::InvalidEconomicProjection)?;
    Ok(head)
}

fn genesis_transition(
    next_head: EconomicResourceHeadV1,
    proof_digest: &str,
) -> EconomicStateTransitionV1 {
    EconomicStateTransitionV1 {
        resource_key: next_head.resource_key.clone(),
        expected_head_digest: None,
        next_head,
        transition_proof_digest: proof_digest.to_owned(),
        prepared_effect: None,
    }
}

const fn claim_lifecycle_state(claim: &ParametricClaimRecordV1) -> &'static str {
    match claim.state() {
        ParametricClaimStateV1::Ready => "ready",
        ParametricClaimStateV1::ContestOpen => "contest_open",
        ParametricClaimStateV1::Contested => "contested",
        ParametricClaimStateV1::UncontestedReleased => "uncontested_released",
        ParametricClaimStateV1::PayoutReserved => "payout_reserved",
    }
}

fn rejected_batch(batch: &EconomicStateBatchV1) -> EconomicStateAnchorError {
    EconomicStateAnchorError::TransitionProofRejected(
        batch
            .transitions
            .first()
            .map(|transition| transition.resource_key.clone())
            .unwrap_or(EconomicResourceKeyV1 {
                resource_family: PARAMETRIC_CLAIM_RESOURCE_FAMILY.to_owned(),
                scope_id: "invalid".to_owned(),
                resource_id: "invalid".to_owned(),
            }),
    )
}
