//! Integration test entry point for populated chio-spec-codegen threat-model
//! regressions.
//!
//! Each `mod` declaration below names a threat ID with a populated test body.
//! The threat-model coverage gate validates that the generated inventory and
//! the compiled regression set stay aligned.
//!
//! Covered threat IDs cited in the threat-model success criteria and
//! the advisory reclassification:
//!
//! - capability_token_theft
//! - kernel_impersonation
//! - tool_server_escape
//! - native_channel_replay
//! - resource_exhaustion_dos
//! - delegation_chain_abuse
//! - weights_hash_spoof
//! - pq_signature_downgrade
//! - tee_quote_forgery
//! - passkey_credential_theft
//! - audience_confusion
//! - ssrf_via_http_substrate
//! - pii_phi_exposure
//! - agent_velocity_abuse
//! - cumulative_data_exfiltration
//! - behavioral_sequence_attack
//! - wasm_guard_resource_exhaustion
//! - mobile_attestation_replay
//! - device_key_extraction
//! - play_integrity_token_replay

#[path = "threats/common.rs"]
mod common;

#[path = "threats/mobile_attestation_common.rs"]
mod mobile_attestation_common;

#[path = "threats/capability_token_theft.rs"]
mod capability_token_theft;

#[path = "threats/kernel_impersonation.rs"]
mod kernel_impersonation;

#[path = "threats/tool_server_escape.rs"]
mod tool_server_escape;

#[path = "threats/native_channel_replay.rs"]
mod native_channel_replay;

#[path = "threats/resource_exhaustion_dos.rs"]
mod resource_exhaustion_dos;

#[path = "threats/delegation_chain_abuse.rs"]
mod delegation_chain_abuse;

#[path = "threats/weights_hash_spoof.rs"]
mod weights_hash_spoof;

#[path = "threats/pq_signature_downgrade.rs"]
mod pq_signature_downgrade;

#[path = "threats/tee_quote_forgery.rs"]
mod tee_quote_forgery;

#[path = "threats/passkey_credential_theft.rs"]
mod passkey_credential_theft;

#[path = "threats/audience_confusion.rs"]
mod audience_confusion;

#[path = "threats/ssrf_via_http_substrate.rs"]
mod ssrf_via_http_substrate;

#[path = "threats/pii_phi_exposure.rs"]
mod pii_phi_exposure;

#[path = "threats/agent_velocity_abuse.rs"]
mod agent_velocity_abuse;

#[path = "threats/cumulative_data_exfiltration.rs"]
mod cumulative_data_exfiltration;

#[path = "threats/behavioral_sequence_attack.rs"]
mod behavioral_sequence_attack;

#[path = "threats/wasm_guard_resource_exhaustion.rs"]
mod wasm_guard_resource_exhaustion;

#[path = "threats/mobile_attestation_replay.rs"]
mod mobile_attestation_replay;

#[path = "threats/device_key_extraction.rs"]
mod device_key_extraction;

#[path = "threats/play_integrity_token_replay.rs"]
mod play_integrity_token_replay;
