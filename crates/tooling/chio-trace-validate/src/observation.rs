use chio_core_types::crypto::{Keypair, PublicKey, Signature};
use chio_core_types::receipt::body::ChioReceipt;
use serde::{Deserialize, Serialize};

use crate::TraceError;

pub const TRACE_OBSERVATION_SCHEMA: &str = "chio.trace-observation.v1";
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationBody {
    pub schema: String,
    pub trace_id: String,
    pub trace_length: u64,
    pub sequence: u64,
    pub runtime_event_count: u64,
    pub source_sequence: u64,
    pub delegation_depth_limit: u32,
    pub authority_key: PublicKey,
    pub event: ObservationEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationEvent {
    Revoke {
        capability_id: String,
        epoch: u64,
    },
    Evaluate {
        receipt: Box<ChioReceipt>,
        receipt_time: u64,
        seen_epoch: u64,
        revocation_subject_ids: Vec<String>,
        revocation_source_id: Option<String>,
        request_id: String,
        admission_sequence: u64,
        delegation_depth: u32,
        revocation_admitted: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedObservation {
    pub body: ObservationBody,
    pub observer_key: PublicKey,
    pub signature: Signature,
}

impl ObservationBody {
    pub fn validate(&self) -> Result<(), TraceError> {
        if self.schema != TRACE_OBSERVATION_SCHEMA {
            return Err(TraceError::InvalidInput(format!(
                "unsupported observation schema: {}",
                self.schema
            )));
        }
        if self.sequence == 0 {
            return Err(TraceError::InvalidInput(
                "observation sequence must be positive".to_string(),
            ));
        }
        validate_trace_id(&self.trace_id)?;
        if self.trace_length == 0 {
            return Err(TraceError::InvalidInput(
                "trace length must be positive".to_string(),
            ));
        }
        if self.sequence > self.trace_length {
            return Err(TraceError::InvalidInput(format!(
                "observation sequence {} exceeds declared trace length {}",
                self.sequence, self.trace_length
            )));
        }
        if self.runtime_event_count == 0 || self.source_sequence == 0 {
            return Err(TraceError::InvalidInput(
                "runtime event count and source sequence must be positive".to_string(),
            ));
        }
        if self.delegation_depth_limit == 0 || self.delegation_depth_limit > 64 {
            return Err(TraceError::InvalidInput(
                "delegation depth limit must be in 1..=64".to_string(),
            ));
        }
        if self.source_sequence > self.runtime_event_count {
            return Err(TraceError::InvalidInput(format!(
                "source sequence {} exceeds runtime event count {}",
                self.source_sequence, self.runtime_event_count
            )));
        }
        match &self.event {
            ObservationEvent::Revoke {
                capability_id,
                epoch,
            } => {
                validate_identifier(capability_id, "capability id")?;
                if *epoch == 0 {
                    return Err(TraceError::InvalidInput(
                        "revocation epoch must be positive".to_string(),
                    ));
                }
            }
            ObservationEvent::Evaluate {
                receipt,
                receipt_time,
                seen_epoch,
                revocation_subject_ids,
                revocation_source_id,
                request_id,
                admission_sequence,
                delegation_depth,
                revocation_admitted,
                ..
            } => {
                validate_identifier(&receipt.capability_id, "receipt capability id")?;
                validate_identifier(request_id, "request id")?;
                let expected_subjects = usize::try_from(*delegation_depth)
                    .ok()
                    .and_then(|depth| depth.checked_add(1))
                    .ok_or_else(|| {
                        TraceError::InvalidInput(
                            "evaluation revocation subject count overflow".to_string(),
                        )
                    })?;
                if revocation_subject_ids.len() != expected_subjects
                    || revocation_subject_ids.first() != Some(&receipt.capability_id)
                {
                    return Err(TraceError::InvalidInput(
                        "evaluation revocation subjects do not match the presented capability and delegation depth"
                            .to_string(),
                    ));
                }
                let mut unique_subjects = std::collections::BTreeSet::new();
                for capability_id in revocation_subject_ids {
                    validate_identifier(capability_id, "revocation subject id")?;
                    if !unique_subjects.insert(capability_id) {
                        return Err(TraceError::InvalidInput(
                            "evaluation revocation subjects must be unique".to_string(),
                        ));
                    }
                }
                if let Some(capability_id) = revocation_source_id {
                    validate_identifier(capability_id, "revocation source id")?;
                    if !unique_subjects.contains(capability_id) {
                        return Err(TraceError::InvalidInput(
                            "evaluation revocation source is outside the checked lineage"
                                .to_string(),
                        ));
                    }
                }
                if (*seen_epoch > 0) != revocation_source_id.is_some() {
                    return Err(TraceError::InvalidInput(
                        "evaluation revocation source must be present exactly when its seen epoch is nonzero"
                            .to_string(),
                    ));
                }
                if *receipt_time == 0 {
                    return Err(TraceError::InvalidInput(
                        "evaluation receipt time must be positive".to_string(),
                    ));
                }
                if *delegation_depth > 64 {
                    return Err(TraceError::InvalidInput(
                        "evaluation delegation depth exceeds the calibrated maximum".to_string(),
                    ));
                }
                if receipt_request_id(receipt) != Some(request_id.as_str()) {
                    return Err(TraceError::InvalidInput(
                        "evaluation request id does not match signed receipt context".to_string(),
                    ));
                }
                if *admission_sequence == 0
                    || *admission_sequence >= self.source_sequence
                    || *admission_sequence > self.runtime_event_count
                {
                    return Err(TraceError::InvalidInput(
                        "evaluation admission sequence must precede its receipt append".to_string(),
                    ));
                }
                if !*revocation_admitted && revocation_source_id.is_none() {
                    return Err(TraceError::InvalidInput(
                        "a rejected revocation admission must identify its exact revocation source"
                            .to_string(),
                    ));
                }
                if !*revocation_admitted
                    && !matches!(
                        &receipt.decision,
                        Some(chio_core_types::receipt::decision::Decision::Deny { .. })
                    )
                {
                    return Err(TraceError::InvalidInput(
                        "a rejected revocation admission must produce a deny receipt".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl SignedObservation {
    pub fn sign(body: ObservationBody, observer: &Keypair) -> Result<Self, TraceError> {
        body.validate()?;
        let (signature, _) = observer.sign_canonical(&body)?;
        Ok(Self {
            body,
            observer_key: observer.public_key(),
            signature,
        })
    }

    pub fn verify(&self, trusted_observer_keys: &[PublicKey]) -> Result<(), TraceError> {
        self.body.validate()?;
        if !trusted_observer_keys
            .iter()
            .any(|trusted| trusted == &self.observer_key)
        {
            return Err(TraceError::InvalidInput(format!(
                "observer key is not trusted: {}",
                self.observer_key.to_hex()
            )));
        }
        if !self
            .observer_key
            .verify_canonical(&self.body, &self.signature)?
        {
            return Err(TraceError::InvalidInput(
                "observation signature is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<(), TraceError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(TraceError::InvalidInput(format!(
            "{label} must be a non-empty normalized identifier of at most {MAX_IDENTIFIER_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_trace_id(value: &str) -> Result<(), TraceError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(TraceError::InvalidInput(format!(
            "trace id must contain 1 to {MAX_IDENTIFIER_BYTES} ASCII letters, digits, dots, underscores, colons, or hyphens"
        )));
    }
    Ok(())
}

fn receipt_request_id(receipt: &ChioReceipt) -> Option<&str> {
    receipt
        .metadata
        .as_ref()?
        .get("receipt_context")?
        .get("request_id")?
        .as_str()
}
