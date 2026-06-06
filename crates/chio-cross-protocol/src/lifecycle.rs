use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Shared lifecycle surfaces for claim-eligible and compatibility routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLifecycleSurface {
    A2aAuthoritative,
    A2aCompatibility,
    AcpAuthoritative,
    AcpCompatibility,
}

/// Canonical runtime lifecycle contract surfaced by claim-eligible bridges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLifecycleContract {
    pub surface: String,
    pub blocking_entrypoint: String,
    pub stream_entrypoint: String,
    pub follow_up_entrypoint: String,
    pub cancel_entrypoint: String,
    pub stream_delivery: String,
    pub partial_output_delivery: String,
    pub claim_eligible: bool,
    pub compatibility_only: bool,
}

#[must_use]
pub fn runtime_lifecycle_contract(surface: RuntimeLifecycleSurface) -> RuntimeLifecycleContract {
    match surface {
        RuntimeLifecycleSurface::A2aAuthoritative => RuntimeLifecycleContract {
            surface: "a2a_authoritative".to_string(),
            blocking_entrypoint: "message/send".to_string(),
            stream_entrypoint: "message/stream".to_string(),
            follow_up_entrypoint: "task/get".to_string(),
            cancel_entrypoint: "task/cancel".to_string(),
            stream_delivery: "collated_terminal_payload".to_string(),
            partial_output_delivery: "collated_terminal_payload".to_string(),
            claim_eligible: true,
            compatibility_only: false,
        },
        RuntimeLifecycleSurface::A2aCompatibility => RuntimeLifecycleContract {
            surface: "a2a_compatibility".to_string(),
            blocking_entrypoint: "message/send".to_string(),
            stream_entrypoint: "unsupported".to_string(),
            follow_up_entrypoint: "unsupported".to_string(),
            cancel_entrypoint: "unsupported".to_string(),
            stream_delivery: "collected_final_payload_only".to_string(),
            partial_output_delivery: "collected_final_payload_only".to_string(),
            claim_eligible: false,
            compatibility_only: true,
        },
        RuntimeLifecycleSurface::AcpAuthoritative => RuntimeLifecycleContract {
            surface: "acp_authoritative".to_string(),
            blocking_entrypoint: "tool/invoke".to_string(),
            stream_entrypoint: "tool/stream".to_string(),
            follow_up_entrypoint: "tool/resume".to_string(),
            cancel_entrypoint: "tool/cancel".to_string(),
            stream_delivery: "resumed_terminal_payload".to_string(),
            partial_output_delivery: "resumed_terminal_payload".to_string(),
            claim_eligible: true,
            compatibility_only: false,
        },
        RuntimeLifecycleSurface::AcpCompatibility => RuntimeLifecycleContract {
            surface: "acp_compatibility".to_string(),
            blocking_entrypoint: "tool/invoke".to_string(),
            stream_entrypoint: "unsupported".to_string(),
            follow_up_entrypoint: "unsupported".to_string(),
            cancel_entrypoint: "unsupported".to_string(),
            stream_delivery: "collected_final_payload_only".to_string(),
            partial_output_delivery: "collected_final_payload_only".to_string(),
            claim_eligible: false,
            compatibility_only: true,
        },
    }
}

#[must_use]
pub fn runtime_lifecycle_metadata(surface: RuntimeLifecycleSurface) -> Value {
    match serde_json::to_value(runtime_lifecycle_contract(surface)) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}
