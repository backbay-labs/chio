#![allow(dead_code)]

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
};
use chio_trace_validate::{
    encode_observations, ObservationBody, ObservationEvent, SignedObservation, TraceError,
    TRACE_OBSERVATION_SCHEMA,
};

pub struct TraceFixture {
    pub ndjson: Vec<u8>,
    pub observer_key: PublicKey,
}

impl TraceFixture {
    pub fn tamper_last_receipt_tool_name(&mut self) -> Result<(), TraceError> {
        let mut values = self
            .ndjson
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(serde_json::from_slice::<SignedObservation>)
            .collect::<Result<Vec<_>, _>>()?;
        let last = values
            .last_mut()
            .ok_or_else(|| TraceError::InvalidInput("trace is empty".to_string()))?;
        let ObservationEvent::Evaluate { receipt, .. } = &mut last.body.event else {
            return Err(TraceError::InvalidInput(
                "last trace event is not an evaluation".to_string(),
            ));
        };
        receipt.tool_name = "tampered".to_string();
        *last = SignedObservation::sign(last.body.clone(), &Keypair::from_seed(&[41; 32]))?;
        self.ndjson = encode_observations(&values)?;
        Ok(())
    }
}

pub fn good_trace() -> Result<TraceFixture, TraceError> {
    trace(false, "cap-trace-parent", "revocation-good-fixture")
}

pub fn bad_trace() -> Result<TraceFixture, TraceError> {
    trace(true, "cap-trace-child", "allow-after-revoke-fixture")
}

pub fn invalid_action_hash_trace() -> Result<TraceFixture, TraceError> {
    let observer = Keypair::from_seed(&[41; 32]);
    let authority = Keypair::from_seed(&[43; 32]);
    let observation = SignedObservation::sign(
        ObservationBody {
            schema: TRACE_OBSERVATION_SCHEMA.to_string(),
            trace_id: "invalid-action-hash".to_string(),
            trace_length: 1,
            sequence: 1,
            runtime_event_count: 2,
            source_sequence: 2,
            delegation_depth_limit: 4,
            authority_key: authority.public_key(),
            event: ObservationEvent::Evaluate {
                receipt: Box::new(receipt(
                    &authority,
                    "cap-trace-1",
                    Decision::Allow,
                    1,
                    true,
                )?),
                receipt_time: 1,
                seen_epoch: 0,
                revocation_subject_ids: vec!["cap-trace-1".to_string()],
                revocation_source_id: None,
                request_id: "trace-request-1".to_string(),
                admission_sequence: 1,
                delegation_depth: 0,
                revocation_admitted: true,
            },
        },
        &observer,
    )?;
    Ok(TraceFixture {
        ndjson: encode_observations(&[observation])?,
        observer_key: observer.public_key(),
    })
}

fn trace(
    allow_after_revoke: bool,
    revoked_capability_id: &str,
    trace_id: &str,
) -> Result<TraceFixture, TraceError> {
    let observer = Keypair::from_seed(&[41; 32]);
    let authority = Keypair::from_seed(&[43; 32]);
    let capability_id = "cap-trace-child";
    let mut observations = Vec::new();
    observations.push(SignedObservation::sign(
        ObservationBody {
            schema: TRACE_OBSERVATION_SCHEMA.to_string(),
            trace_id: trace_id.to_string(),
            trace_length: 3,
            sequence: 1,
            runtime_event_count: 5,
            source_sequence: 2,
            delegation_depth_limit: 4,
            authority_key: authority.public_key(),
            event: ObservationEvent::Evaluate {
                receipt: Box::new(receipt(
                    &authority,
                    capability_id,
                    Decision::Allow,
                    1,
                    false,
                )?),
                receipt_time: 1,
                seen_epoch: 0,
                revocation_subject_ids: vec![
                    capability_id.to_string(),
                    "cap-trace-parent".to_string(),
                ],
                revocation_source_id: None,
                request_id: "trace-request-1".to_string(),
                admission_sequence: 1,
                delegation_depth: 1,
                revocation_admitted: true,
            },
        },
        &observer,
    )?);
    observations.push(SignedObservation::sign(
        ObservationBody {
            schema: TRACE_OBSERVATION_SCHEMA.to_string(),
            trace_id: trace_id.to_string(),
            trace_length: 3,
            sequence: 2,
            runtime_event_count: 5,
            source_sequence: 3,
            delegation_depth_limit: 4,
            authority_key: authority.public_key(),
            event: ObservationEvent::Revoke {
                capability_id: revoked_capability_id.to_string(),
                epoch: 2,
            },
        },
        &observer,
    )?);
    observations.push(SignedObservation::sign(
        ObservationBody {
            schema: TRACE_OBSERVATION_SCHEMA.to_string(),
            trace_id: trace_id.to_string(),
            trace_length: 3,
            sequence: 3,
            runtime_event_count: 5,
            source_sequence: 5,
            delegation_depth_limit: 4,
            authority_key: authority.public_key(),
            event: ObservationEvent::Evaluate {
                receipt: Box::new(receipt(
                    &authority,
                    capability_id,
                    if allow_after_revoke {
                        Decision::Allow
                    } else {
                        Decision::Deny {
                            reason: "capability revoked".to_string(),
                            guard: "revocation_store".to_string(),
                        }
                    },
                    3,
                    false,
                )?),
                receipt_time: 3,
                seen_epoch: 2,
                revocation_subject_ids: vec![
                    capability_id.to_string(),
                    "cap-trace-parent".to_string(),
                ],
                revocation_source_id: Some(revoked_capability_id.to_string()),
                request_id: "trace-request-3".to_string(),
                admission_sequence: 4,
                delegation_depth: 1,
                revocation_admitted: allow_after_revoke,
            },
        },
        &observer,
    )?);

    Ok(TraceFixture {
        ndjson: encode_observations(&observations)?,
        observer_key: observer.public_key(),
    })
}

pub fn receipt(
    authority: &Keypair,
    capability_id: &str,
    decision: Decision,
    nonce: u64,
    invalid_action_hash: bool,
) -> Result<ChioReceipt, TraceError> {
    let mut action = ToolCallAction::from_parameters(serde_json::json!({"nonce": nonce}))?;
    if invalid_action_hash {
        action.parameter_hash = "0".repeat(64);
    }
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("trace-receipt-{nonce}"),
            timestamp: 1_700_000_000 + nonce,
            capability_id: capability_id.to_string(),
            tool_server: "conformance".to_string(),
            tool_name: "echo".to_string(),
            action,
            decision: Some(decision),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"trace-output"),
            policy_hash: chio_core_types::sha256_hex(b"trace-policy"),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "receipt_context": {
                    "request_id": format!("trace-request-{nonce}")
                }
            })),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: authority.public_key(),
            bbs_projection_version: None,
        },
        authority,
    )?)
}
