use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::body::ChioReceipt;
use chio_kernel::{RuntimeTraceEvent, RuntimeTraceObserver};
use serde::Serialize;

use crate::{
    encode_observations, ObservationBody, ObservationEvent, SignedObservation, TraceError,
    TRACE_OBSERVATION_SCHEMA,
};

/// Deliberate trace-export mutations used only to calibrate the validator's
/// registered negative lanes against callbacks from a real kernel execution.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTraceMutation {
    /// No mutation. This is the production recording mode.
    #[default]
    None,
    /// Reuse the first receipt time for a later real receipt callback.
    DuplicateReceiptTime,
    /// Project real admission depth above the signed kernel limit.
    DepthAboveLimit,
    /// Project a real revocation callback to a future model epoch.
    FutureRevocationEpoch,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum CapturedEvent {
    Revoke {
        source_sequence: u64,
        capability_id: String,
    },
    Evaluate {
        source_sequence: u64,
        admission_sequence: u64,
        request_id: String,
        capability_id: String,
        revocation_subject_ids: Vec<String>,
        revocation_source_id: Option<String>,
        delegation_depth: u32,
        revocation_admitted: bool,
        receipt: Box<ChioReceipt>,
    },
}

impl CapturedEvent {
    fn source_sequence(&self) -> u64 {
        match self {
            Self::Revoke {
                source_sequence, ..
            }
            | Self::Evaluate {
                source_sequence, ..
            } => *source_sequence,
        }
    }
}

#[derive(Debug, Clone)]
struct Admission {
    source_sequence: u64,
    capability_id: String,
    revocation_subject_ids: Vec<String>,
    revoked_capability_id: Option<String>,
    delegation_depth: u32,
    admitted: bool,
}

#[derive(Debug, Default)]
struct RecorderState {
    source_sequences: BTreeSet<u64>,
    max_source_sequence: u64,
    delegation_depth_limit: Option<u32>,
    events: Vec<CapturedEvent>,
    pending_admissions: BTreeMap<String, Admission>,
    revoke_sources: BTreeMap<String, u64>,
    error: Option<String>,
    finished: bool,
}

/// Captures the kernel callbacks needed to build an authenticated revocation
/// trace. The recorder signs only after a complete, unambiguous event stream
/// has been finalized.
pub struct RuntimeTraceRecorder {
    authority_key: PublicKey,
    observer: Keypair,
    context: String,
    mutation: RuntimeTraceMutation,
    state: Mutex<RecorderState>,
}

impl RuntimeTraceRecorder {
    pub fn new(
        authority_key: PublicKey,
        observer: Keypair,
        context: impl Into<String>,
    ) -> Result<Self, TraceError> {
        Self::new_with_mutation(authority_key, observer, context, RuntimeTraceMutation::None)
    }

    #[doc(hidden)]
    pub fn new_with_mutation(
        authority_key: PublicKey,
        observer: Keypair,
        context: impl Into<String>,
        mutation: RuntimeTraceMutation,
    ) -> Result<Self, TraceError> {
        let context = context.into();
        validate_context(&context)?;
        Ok(Self {
            authority_key,
            observer,
            context,
            mutation,
            state: Mutex::new(RecorderState::default()),
        })
    }

    #[must_use]
    pub fn observer_key(&self) -> PublicKey {
        self.observer.public_key()
    }

    pub fn finish(&self) -> Result<Vec<u8>, TraceError> {
        let mut state = self.state.lock().map_err(|_| {
            TraceError::InvalidInput("runtime trace recorder lock is poisoned".to_string())
        })?;
        if state.finished {
            return Err(TraceError::InvalidInput(
                "runtime trace recorder was already finalized".to_string(),
            ));
        }
        state.finished = true;
        if let Some(error) = &state.error {
            return Err(TraceError::InvalidInput(format!(
                "runtime trace recorder rejected its event stream: {error}"
            )));
        }
        if !state.pending_admissions.is_empty() {
            return Err(TraceError::InvalidInput(format!(
                "runtime trace has {} admission callbacks without receipt appends",
                state.pending_admissions.len()
            )));
        }
        if state.events.is_empty() {
            return Err(TraceError::InvalidInput(
                "runtime trace contains no completed model events".to_string(),
            ));
        }
        let accounted_source_sequences =
            u64::try_from(state.source_sequences.len()).map_err(|_| {
                TraceError::InvalidInput("runtime callback count exceeds u64".to_string())
            })?;
        if accounted_source_sequences != state.max_source_sequence {
            return Err(TraceError::InvalidInput(
                "runtime trace does not account for every callback exactly once".to_string(),
            ));
        }
        let delegation_depth_limit = state.delegation_depth_limit.ok_or_else(|| {
            TraceError::InvalidInput(
                "runtime trace contains no kernel delegation depth limit".to_string(),
            )
        })?;

        state.events.sort_by_key(CapturedEvent::source_sequence);
        let trace_length = u64::try_from(state.events.len())
            .map_err(|_| TraceError::InvalidInput("trace length exceeds u64".to_string()))?;
        let event_bytes = canonical_json_bytes(&(
            state.events.as_slice(),
            delegation_depth_limit,
            self.mutation,
        ))?;
        let context_hash = chio_core_types::sha256_hex(self.context.as_bytes());
        let event_hash = chio_core_types::sha256_hex(&event_bytes);
        let trace_id = format!("runtime:{context_hash}:{event_hash}");
        let revoke_sources = state.revoke_sources.clone();
        let revocation_epoch_by_source = state
            .events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| match event {
                CapturedEvent::Revoke {
                    source_sequence, ..
                } => Some((index, *source_sequence)),
                CapturedEvent::Evaluate { .. } => None,
            })
            .map(|(index, source_sequence)| {
                let sequence = u64::try_from(index + 1).map_err(|_| {
                    TraceError::InvalidInput("model sequence exceeds u64".to_string())
                })?;
                let epoch = if self.mutation == RuntimeTraceMutation::FutureRevocationEpoch {
                    trace_length.checked_add(1).ok_or_else(|| {
                        TraceError::InvalidInput("calibrated revocation epoch overflow".to_string())
                    })?
                } else {
                    sequence
                };
                Ok((source_sequence, epoch))
            })
            .collect::<Result<BTreeMap<_, _>, TraceError>>()?;

        let mut observations = Vec::with_capacity(state.events.len());
        let mut first_receipt_time = None;
        for (index, event) in state.events.iter().enumerate() {
            let sequence = u64::try_from(index + 1)
                .map_err(|_| TraceError::InvalidInput("model sequence exceeds u64".to_string()))?;
            let (source_sequence, event) = match event {
                CapturedEvent::Revoke {
                    source_sequence,
                    capability_id,
                } => (
                    *source_sequence,
                    ObservationEvent::Revoke {
                        capability_id: capability_id.clone(),
                        epoch: if self.mutation == RuntimeTraceMutation::FutureRevocationEpoch {
                            trace_length.checked_add(1).ok_or_else(|| {
                                TraceError::InvalidInput(
                                    "calibrated revocation epoch overflow".to_string(),
                                )
                            })?
                        } else {
                            sequence
                        },
                    },
                ),
                CapturedEvent::Evaluate {
                    source_sequence,
                    admission_sequence,
                    request_id,
                    capability_id: _,
                    revocation_subject_ids,
                    revocation_source_id,
                    delegation_depth,
                    revocation_admitted,
                    receipt,
                    ..
                } => {
                    if *revocation_admitted {
                        if let Some((interval_source_id, _)) = revocation_subject_ids
                            .iter()
                            .filter_map(|subject_id| {
                                revoke_sources
                                    .get(subject_id)
                                    .copied()
                                    .map(|source| (subject_id, source))
                            })
                            .find(|(_, source)| {
                                *admission_sequence < *source && *source < *source_sequence
                            })
                        {
                            return Err(TraceError::InvalidInput(format!(
                                "revocation of {interval_source_id} occurred between admission and receipt append"
                            )));
                        }
                    }
                    let revocation_source_id = if *revocation_admitted {
                        revocation_subject_ids
                            .iter()
                            .filter_map(|subject_id| {
                                revoke_sources
                                    .get(subject_id)
                                    .copied()
                                    .map(|source| (subject_id, source))
                            })
                            .filter(|(_, source)| *source < *admission_sequence)
                            .min_by_key(|(_, source)| *source)
                            .map(|(subject_id, _)| subject_id.clone())
                    } else {
                        revocation_source_id.clone()
                    };
                    if !*revocation_admitted && revocation_source_id.is_none() {
                        return Err(TraceError::InvalidInput(format!(
                            "rejected admission {request_id} has no exact revocation source"
                        )));
                    }
                    let observed_revoke_source = revocation_source_id
                        .as_ref()
                        .map(|capability_id| {
                            let source = revoke_sources.get(capability_id).copied().ok_or_else(|| {
                                TraceError::InvalidInput(format!(
                                    "admission refers to missing revoke callback for {capability_id}"
                                ))
                            })?;
                            if source >= *admission_sequence {
                                return Err(TraceError::InvalidInput(format!(
                                    "revocation source for admission {request_id} does not precede admission"
                                )));
                            }
                            Ok(source)
                        })
                        .transpose()?;
                    let seen_epoch = observed_revoke_source
                        .map(|source| {
                            revocation_epoch_by_source
                                .get(&source)
                                .copied()
                                .ok_or_else(|| {
                                    TraceError::InvalidInput(format!(
                                        "admission refers to missing revoke callback {source}"
                                    ))
                                })
                        })
                        .transpose()?
                        .unwrap_or(0);
                    let receipt_time = match (self.mutation, first_receipt_time) {
                        (RuntimeTraceMutation::DuplicateReceiptTime, Some(first)) => first,
                        _ => sequence,
                    };
                    if first_receipt_time.is_none() {
                        first_receipt_time = Some(receipt_time);
                    }
                    let delegation_depth = if self.mutation == RuntimeTraceMutation::DepthAboveLimit
                    {
                        delegation_depth_limit.checked_add(1).ok_or_else(|| {
                            TraceError::InvalidInput(
                                "calibrated delegation depth overflow".to_string(),
                            )
                        })?
                    } else {
                        *delegation_depth
                    };
                    let mut revocation_subject_ids = revocation_subject_ids.clone();
                    if self.mutation == RuntimeTraceMutation::DepthAboveLimit {
                        let required_subjects = usize::try_from(delegation_depth)
                            .ok()
                            .and_then(|depth| depth.checked_add(1))
                            .ok_or_else(|| {
                                TraceError::InvalidInput(
                                    "calibrated revocation subject count overflow".to_string(),
                                )
                            })?;
                        while revocation_subject_ids.len() < required_subjects {
                            revocation_subject_ids.push(format!(
                                "trace-depth-subject-{}",
                                revocation_subject_ids.len()
                            ));
                        }
                    }
                    (
                        *source_sequence,
                        ObservationEvent::Evaluate {
                            receipt: receipt.clone(),
                            receipt_time,
                            seen_epoch,
                            revocation_subject_ids,
                            revocation_source_id,
                            request_id: request_id.clone(),
                            admission_sequence: *admission_sequence,
                            delegation_depth,
                            revocation_admitted: *revocation_admitted,
                        },
                    )
                }
            };
            observations.push(SignedObservation::sign(
                ObservationBody {
                    schema: TRACE_OBSERVATION_SCHEMA.to_string(),
                    trace_id: trace_id.clone(),
                    trace_length,
                    sequence,
                    runtime_event_count: state.max_source_sequence,
                    source_sequence,
                    delegation_depth_limit,
                    authority_key: self.authority_key.clone(),
                    event,
                },
                &self.observer,
            )?);
        }
        encode_observations(&observations)
    }

    fn record_error(state: &mut RecorderState, error: impl Into<String>) {
        if state.error.is_none() {
            state.error = Some(error.into());
        }
    }

    fn record_source_sequence(state: &mut RecorderState, source_sequence: u64) -> bool {
        if source_sequence == 0 {
            Self::record_error(state, "runtime callback source sequence must be positive");
            return false;
        }
        if !state.source_sequences.insert(source_sequence) {
            Self::record_error(
                state,
                format!("duplicate runtime callback source sequence {source_sequence}"),
            );
            return false;
        }
        state.max_source_sequence = state.max_source_sequence.max(source_sequence);
        true
    }

    fn record_depth_limit(state: &mut RecorderState, limit: u32) {
        if limit == 0 || limit > 64 {
            Self::record_error(
                state,
                format!("kernel delegation depth limit {limit} is outside 1..=64"),
            );
            return;
        }
        match state.delegation_depth_limit {
            None => state.delegation_depth_limit = Some(limit),
            Some(expected) if expected == limit => {}
            Some(expected) => Self::record_error(
                state,
                format!("kernel delegation depth limit changed from {expected} to {limit}"),
            ),
        }
    }
}

impl RuntimeTraceObserver for RuntimeTraceRecorder {
    fn observe(&self, event: RuntimeTraceEvent) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.finished {
            Self::record_error(&mut state, "runtime callback arrived after finalization");
            return;
        }
        let source_sequence = match &event {
            RuntimeTraceEvent::RevocationCommitted {
                source_sequence, ..
            }
            | RuntimeTraceEvent::RevocationAdmission {
                source_sequence, ..
            }
            | RuntimeTraceEvent::ReceiptAppended {
                source_sequence, ..
            } => *source_sequence,
        };
        if !Self::record_source_sequence(&mut state, source_sequence) {
            return;
        }
        match event {
            RuntimeTraceEvent::RevocationCommitted {
                source_sequence: _,
                capability_id,
                newly_revoked,
                delegation_depth_limit,
            } => {
                Self::record_depth_limit(&mut state, delegation_depth_limit);
                if !newly_revoked {
                    Self::record_error(
                        &mut state,
                        format!("duplicate revocation callback for {capability_id}"),
                    );
                    return;
                }
                if state
                    .revoke_sources
                    .insert(capability_id.clone(), source_sequence)
                    .is_some()
                {
                    Self::record_error(
                        &mut state,
                        format!("multiple effective revocations for {capability_id}"),
                    );
                    return;
                }
                state.events.push(CapturedEvent::Revoke {
                    source_sequence,
                    capability_id,
                });
            }
            RuntimeTraceEvent::RevocationAdmission {
                source_sequence: _,
                request_id,
                capability_id,
                revocation_subject_ids,
                revoked_capability_id,
                delegation_depth,
                delegation_depth_limit,
                admitted,
            } => {
                Self::record_depth_limit(&mut state, delegation_depth_limit);
                let expected_subjects = usize::try_from(delegation_depth)
                    .ok()
                    .and_then(|depth| depth.checked_add(1));
                if revocation_subject_ids.first() != Some(&capability_id)
                    || expected_subjects != Some(revocation_subject_ids.len())
                {
                    Self::record_error(
                        &mut state,
                        format!(
                            "revocation subjects do not match admission lineage for {request_id}"
                        ),
                    );
                    return;
                }
                let unique_subjects = revocation_subject_ids.iter().collect::<BTreeSet<_>>();
                if unique_subjects.len() != revocation_subject_ids.len() {
                    Self::record_error(
                        &mut state,
                        format!("revocation subjects repeat for admission {request_id}"),
                    );
                    return;
                }
                if revoked_capability_id
                    .as_ref()
                    .is_some_and(|source_id| !unique_subjects.contains(source_id))
                {
                    Self::record_error(
                        &mut state,
                        format!("revocation source is outside admission lineage for {request_id}"),
                    );
                    return;
                }
                if !admitted && revoked_capability_id.is_none() {
                    Self::record_error(
                        &mut state,
                        format!(
                            "rejected admission {request_id} has no exact revocation source for {capability_id}"
                        ),
                    );
                }
                if admitted && revoked_capability_id.is_some() {
                    Self::record_error(
                        &mut state,
                        format!(
                            "admitted revocation callback has a denial source for {request_id}"
                        ),
                    );
                }
                if state
                    .pending_admissions
                    .insert(
                        request_id.clone(),
                        Admission {
                            source_sequence,
                            capability_id,
                            revocation_subject_ids,
                            revoked_capability_id,
                            delegation_depth,
                            admitted,
                        },
                    )
                    .is_some()
                {
                    Self::record_error(
                        &mut state,
                        format!("duplicate pending admission for request {request_id}"),
                    );
                }
            }
            RuntimeTraceEvent::ReceiptAppended {
                source_sequence: _,
                receipt,
            } => {
                let Some(request_id) = receipt_request_id(&receipt) else {
                    Self::record_error(
                        &mut state,
                        format!("receipt {} has no signed request-id context", receipt.id),
                    );
                    return;
                };
                let Some(admission) = state.pending_admissions.remove(request_id) else {
                    Self::record_error(
                        &mut state,
                        format!("receipt {} has no matching admission callback", receipt.id),
                    );
                    return;
                };
                if admission.capability_id != receipt.capability_id {
                    Self::record_error(
                        &mut state,
                        format!(
                            "receipt {} capability differs from its admission",
                            receipt.id
                        ),
                    );
                    return;
                }
                state.events.push(CapturedEvent::Evaluate {
                    source_sequence,
                    admission_sequence: admission.source_sequence,
                    request_id: request_id.to_string(),
                    capability_id: admission.capability_id,
                    revocation_subject_ids: admission.revocation_subject_ids,
                    revocation_source_id: admission.revoked_capability_id,
                    delegation_depth: admission.delegation_depth,
                    revocation_admitted: admission.admitted,
                    receipt,
                });
            }
        }
    }
}

fn receipt_request_id(receipt: &ChioReceipt) -> Option<&str> {
    receipt
        .metadata
        .as_ref()?
        .get("receipt_context")?
        .get("request_id")?
        .as_str()
        .filter(|request_id| !request_id.is_empty())
}

fn validate_context(context: &str) -> Result<(), TraceError> {
    if context.is_empty()
        || context.len() > 1024
        || context.trim() != context
        || context.chars().any(char::is_control)
    {
        return Err(TraceError::InvalidInput(
            "runtime trace context must be normalized text of at most 1024 bytes".to_string(),
        ));
    }
    Ok(())
}
