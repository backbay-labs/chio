use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::receipt::decision::Decision;
use serde::{Deserialize, Serialize};

use crate::intern::Interner;
use crate::itf::build_itf;
use crate::{ObservationEvent, TraceError, ValidatedTrace};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionCoverage {
    pub revoke: u64,
    pub evaluate: u64,
    pub post_revocation_evaluate: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvariantWitnessCoverage {
    pub allow_receipt: u64,
    pub ordered_receipt_pair: u64,
    pub attenuated_admission: u64,
    pub nonzero_revocation_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectedEvent {
    pub sequence: u64,
    pub source_sequence: u64,
    pub authority: u32,
    pub capability: u32,
    pub action: ProjectedAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectedAction {
    Revoke {
        epoch: u64,
    },
    Evaluate {
        receipt_id: String,
        verdict: String,
        receipt_time: u64,
        seen_epoch: u64,
        admission_sequence: u64,
        delegation_depth: u32,
    },
}

#[derive(Debug, Clone)]
pub struct RevocationProjection {
    pub(crate) trace_id: String,
    pub(crate) events: Vec<ProjectedEvent>,
    pub(crate) authority_count: usize,
    pub(crate) capability_count: usize,
    pub(crate) depth_max: u32,
    pub(crate) action_coverage: ActionCoverage,
    pub(crate) invariant_witnesses: InvariantWitnessCoverage,
    pub(crate) observer_keys: Vec<String>,
    pub(crate) log_sha256: String,
    pub(crate) itf_json: Vec<u8>,
    pub(crate) states: Vec<serde_json::Value>,
}

impl RevocationProjection {
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    #[must_use]
    pub fn events(&self) -> &[ProjectedEvent] {
        &self.events
    }

    #[must_use]
    pub fn authority_count(&self) -> usize {
        self.authority_count
    }

    #[must_use]
    pub fn capability_count(&self) -> usize {
        self.capability_count
    }

    #[must_use]
    pub fn depth_max(&self) -> u32 {
        self.depth_max
    }

    #[must_use]
    pub fn action_coverage(&self) -> ActionCoverage {
        self.action_coverage
    }

    #[must_use]
    pub fn invariant_witnesses(&self) -> InvariantWitnessCoverage {
        self.invariant_witnesses
    }

    #[must_use]
    pub fn observer_keys(&self) -> &[String] {
        &self.observer_keys
    }

    #[must_use]
    pub fn log_sha256(&self) -> &str {
        &self.log_sha256
    }

    #[must_use]
    pub fn itf_json(&self) -> &[u8] {
        &self.itf_json
    }
}

pub fn project_revocation_trace(
    validated_trace: &ValidatedTrace,
) -> Result<RevocationProjection, TraceError> {
    let observations = &validated_trace.observations;
    let trace_id = observations
        .first()
        .map(|observation| observation.body.trace_id.clone())
        .ok_or_else(|| TraceError::InvalidInput("observation trace is empty".to_string()))?;
    if observations
        .iter()
        .any(|observation| observation.body.trace_id != trace_id)
    {
        return Err(TraceError::InvalidInput(
            "observation trace contains multiple trace ids".to_string(),
        ));
    }
    let mut authorities = Interner::default();
    let mut capabilities = Interner::default();
    let mut events = Vec::with_capacity(observations.len());
    let mut coverage = ActionCoverage::default();
    let mut observer_keys = BTreeSet::new();
    let mut known_epochs: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut invariant_witnesses = InvariantWitnessCoverage::default();
    let mut receipts_by_authority: BTreeMap<u32, u64> = BTreeMap::new();
    let depth_max = observations
        .first()
        .map(|observation| observation.body.delegation_depth_limit)
        .ok_or_else(|| TraceError::InvalidInput("observation trace is empty".to_string()))?;

    for observation in observations {
        observer_keys.insert(observation.observer_key.to_hex());
        let authority_hex = observation.body.authority_key.to_hex();
        let authority = authorities.intern(&authority_hex, "authority")?;
        let (capability_id, action) = match &observation.body.event {
            ObservationEvent::Revoke {
                capability_id,
                epoch,
            } => {
                known_epochs
                    .entry(capability_id.clone())
                    .or_default()
                    .insert(*epoch);
                coverage.revoke = coverage.revoke.checked_add(1).ok_or_else(|| {
                    TraceError::InvalidInput("revoke counter overflow".to_string())
                })?;
                (
                    capability_id.as_str(),
                    ProjectedAction::Revoke { epoch: *epoch },
                )
            }
            ObservationEvent::Evaluate {
                receipt,
                receipt_time,
                seen_epoch,
                revocation_source_id,
                admission_sequence,
                delegation_depth,
                ..
            } => {
                if receipt.kernel_key != observation.body.authority_key {
                    return Err(TraceError::InvalidInput(format!(
                        "evaluation event {} authority does not match its receipt kernel key",
                        observation.body.sequence
                    )));
                }
                if !receipt.verify_signature()? {
                    return Err(TraceError::InvalidInput(format!(
                        "evaluation event {} has an invalid receipt signature",
                        observation.body.sequence
                    )));
                }
                if !receipt.action.verify_hash()? {
                    return Err(TraceError::InvalidInput(format!(
                        "evaluation event {} has an invalid receipt action hash",
                        observation.body.sequence
                    )));
                }
                let verdict = match receipt.decision.as_ref() {
                    Some(Decision::Allow) => {
                        invariant_witnesses.allow_receipt = invariant_witnesses
                            .allow_receipt
                            .checked_add(1)
                            .ok_or_else(|| {
                                TraceError::InvalidInput(
                                    "allow-receipt witness counter overflow".to_string(),
                                )
                            })?;
                        "allow"
                    }
                    Some(Decision::Deny { .. }) => "deny",
                    _ => {
                        return Err(TraceError::InvalidInput(format!(
                            "evaluation event {} must carry an allow or deny receipt",
                            observation.body.sequence
                        )))
                    }
                };
                let effective_capability_id = if *seen_epoch > 0 {
                    let source_id = revocation_source_id.as_deref().ok_or_else(|| {
                        TraceError::InvalidInput(format!(
                            "evaluation event {} omits its revocation source",
                            observation.body.sequence
                        ))
                    })?;
                    if !known_epochs
                        .get(source_id)
                        .is_some_and(|epochs| epochs.contains(seen_epoch))
                    {
                        return Err(TraceError::InvalidInput(format!(
                            "evaluation event {} cites unseen revocation epoch {} for {}",
                            observation.body.sequence, seen_epoch, source_id
                        )));
                    }
                    source_id
                } else {
                    receipt.capability_id.as_str()
                };
                coverage.evaluate = coverage.evaluate.checked_add(1).ok_or_else(|| {
                    TraceError::InvalidInput("evaluate counter overflow".to_string())
                })?;
                if *seen_epoch > 0 {
                    coverage.post_revocation_evaluate = coverage
                        .post_revocation_evaluate
                        .checked_add(1)
                        .ok_or_else(|| {
                            TraceError::InvalidInput(
                                "post-revocation evaluate counter overflow".to_string(),
                            )
                        })?;
                }
                if *delegation_depth > 0 {
                    invariant_witnesses.attenuated_admission = invariant_witnesses
                        .attenuated_admission
                        .checked_add(1)
                        .ok_or_else(|| {
                            TraceError::InvalidInput(
                                "attenuated-admission witness counter overflow".to_string(),
                            )
                        })?;
                }
                let prior_receipts = receipts_by_authority.entry(authority).or_default();
                invariant_witnesses.ordered_receipt_pair = invariant_witnesses
                    .ordered_receipt_pair
                    .checked_add(*prior_receipts)
                    .ok_or_else(|| {
                        TraceError::InvalidInput(
                            "ordered-receipt witness counter overflow".to_string(),
                        )
                    })?;
                *prior_receipts = prior_receipts.checked_add(1).ok_or_else(|| {
                    TraceError::InvalidInput("authority receipt counter overflow".to_string())
                })?;
                (
                    effective_capability_id,
                    ProjectedAction::Evaluate {
                        receipt_id: receipt.id.clone(),
                        verdict: verdict.to_string(),
                        receipt_time: *receipt_time,
                        seen_epoch: *seen_epoch,
                        admission_sequence: *admission_sequence,
                        delegation_depth: *delegation_depth,
                    },
                )
            }
        };
        let capability = capabilities.intern(capability_id, "capability")?;
        events.push(ProjectedEvent {
            sequence: observation.body.sequence,
            source_sequence: observation.body.source_sequence,
            authority,
            capability,
            action,
        });
    }

    let authority_count = authorities.len();
    let capability_count = capabilities.len();
    let log_sha256 = validated_trace.log_sha256.clone();
    invariant_witnesses.nonzero_revocation_epoch = coverage.revoke;
    let (itf_json, states) = build_itf(
        &events,
        authority_count,
        capability_count,
        depth_max,
        &log_sha256,
    )?;
    Ok(RevocationProjection {
        trace_id,
        events,
        authority_count,
        capability_count,
        depth_max,
        action_coverage: coverage,
        invariant_witnesses,
        observer_keys: observer_keys.into_iter().collect(),
        log_sha256,
        itf_json,
        states,
    })
}
