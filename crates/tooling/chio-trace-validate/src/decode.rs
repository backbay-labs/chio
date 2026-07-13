use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::PublicKey;

use crate::{SignedObservation, TraceError};

pub(crate) const MAX_TRACE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRACE_EVENTS: usize = 500;

#[derive(Debug, Clone)]
pub struct ValidatedTrace {
    pub(crate) observations: Vec<SignedObservation>,
    pub(crate) log_sha256: String,
}

impl ValidatedTrace {
    #[must_use]
    pub fn observations(&self) -> &[SignedObservation] {
        &self.observations
    }
}

pub fn decode_observations(
    input: &[u8],
    trusted_observer_keys: &[PublicKey],
) -> Result<ValidatedTrace, TraceError> {
    if trusted_observer_keys.is_empty() {
        return Err(TraceError::InvalidInput(
            "at least one trusted observer key is required".to_string(),
        ));
    }
    if input.is_empty() {
        return Err(TraceError::InvalidInput(
            "observation log is empty".to_string(),
        ));
    }
    if input.len() > MAX_TRACE_BYTES {
        return Err(TraceError::InvalidInput(format!(
            "observation log exceeds {MAX_TRACE_BYTES} bytes"
        )));
    }
    if !input.ends_with(b"\n") {
        return Err(TraceError::InvalidInput(
            "observation log must end with a newline".to_string(),
        ));
    }

    let mut observations = Vec::new();
    let mut trace_id = None;
    let mut trace_length = None;
    let mut runtime_event_count = None;
    let mut delegation_depth_limit = None;
    let mut source_sequences = std::collections::BTreeSet::new();
    let mut previous_source_sequence = 0;
    for (index, line) in input[..input.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        let line_number = index + 1;
        if line.is_empty() {
            return Err(TraceError::InvalidInput(format!(
                "observation line {line_number} is empty"
            )));
        }
        let observation: SignedObservation = serde_json::from_slice(line).map_err(|error| {
            TraceError::InvalidInput(format!(
                "observation line {line_number} is not valid JSON: {error}"
            ))
        })?;
        let canonical = canonical_json_bytes(&observation)?;
        if canonical != line {
            return Err(TraceError::InvalidInput(format!(
                "observation line {line_number} is not canonical JSON"
            )));
        }
        let expected_sequence = u64::try_from(line_number).map_err(|_| {
            TraceError::InvalidInput("observation sequence exceeds u64".to_string())
        })?;
        if observation.body.sequence != expected_sequence {
            return Err(TraceError::InvalidInput(format!(
                "observation line {line_number} expected sequence {expected_sequence}, got {}",
                observation.body.sequence
            )));
        }
        observation.verify(trusted_observer_keys).map_err(|error| {
            TraceError::InvalidInput(format!("observation line {line_number}: {error}"))
        })?;
        if observation.body.source_sequence <= previous_source_sequence {
            return Err(TraceError::InvalidInput(format!(
                "observation line {line_number} is not in increasing runtime source order"
            )));
        }
        previous_source_sequence = observation.body.source_sequence;
        match (
            &trace_id,
            trace_length,
            runtime_event_count,
            delegation_depth_limit,
        ) {
            (None, None, None, None) => {
                let max_events = u64::try_from(MAX_TRACE_EVENTS).map_err(|_| {
                    TraceError::InvalidInput("maximum trace event count exceeds u64".to_string())
                })?;
                if observation.body.trace_length > max_events {
                    return Err(TraceError::InvalidInput(format!(
                        "observation log declares more than {MAX_TRACE_EVENTS} events"
                    )));
                }
                trace_id = Some(observation.body.trace_id.clone());
                trace_length = Some(observation.body.trace_length);
                runtime_event_count = Some(observation.body.runtime_event_count);
                delegation_depth_limit = Some(observation.body.delegation_depth_limit);
            }
            (
                Some(expected_id),
                Some(expected_length),
                Some(expected_runtime_count),
                Some(expected_depth_limit),
            ) if expected_id == &observation.body.trace_id
                && expected_length == observation.body.trace_length
                && expected_runtime_count == observation.body.runtime_event_count
                && expected_depth_limit == observation.body.delegation_depth_limit => {}
            _ => {
                return Err(TraceError::InvalidInput(format!(
                    "observation line {line_number} disagrees on trace identity or length"
                )))
            }
        }
        if !source_sequences.insert(observation.body.source_sequence) {
            return Err(TraceError::InvalidInput(format!(
                "observation line {line_number} repeats runtime source sequence {}",
                observation.body.source_sequence
            )));
        }
        if let crate::ObservationEvent::Evaluate {
            admission_sequence, ..
        } = &observation.body.event
        {
            if !source_sequences.insert(*admission_sequence) {
                return Err(TraceError::InvalidInput(format!(
                    "observation line {line_number} repeats runtime admission sequence {admission_sequence}"
                )));
            }
        }
        observations.push(observation);
        if observations.len() > MAX_TRACE_EVENTS {
            return Err(TraceError::InvalidInput(format!(
                "observation log exceeds {MAX_TRACE_EVENTS} events"
            )));
        }
    }
    let declared = trace_length.ok_or_else(|| {
        TraceError::InvalidInput("observation log contains no records".to_string())
    })?;
    let actual = u64::try_from(observations.len())
        .map_err(|_| TraceError::InvalidInput("observation count exceeds u64".to_string()))?;
    if actual != declared {
        return Err(TraceError::InvalidInput(format!(
            "observation log declares {declared} events but contains {actual}"
        )));
    }
    let runtime_count = runtime_event_count.ok_or_else(|| {
        TraceError::InvalidInput("observation log has no runtime event count".to_string())
    })?;
    let accounted_runtime_sequences = u64::try_from(source_sequences.len())
        .map_err(|_| TraceError::InvalidInput("runtime callback count exceeds u64".to_string()))?;
    if accounted_runtime_sequences != runtime_count {
        return Err(TraceError::InvalidInput(
            "observation log does not account for every runtime callback exactly once".to_string(),
        ));
    }
    Ok(ValidatedTrace {
        observations,
        log_sha256: chio_core_types::sha256_hex(input),
    })
}

pub fn encode_observations(observations: &[SignedObservation]) -> Result<Vec<u8>, TraceError> {
    let mut output = Vec::new();
    for observation in observations {
        output.extend_from_slice(&canonical_json_bytes(observation)?);
        output.push(b'\n');
    }
    Ok(output)
}
