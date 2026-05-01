//! Integration test entry point for chio-spec-codegen threat-model
//! stubs.
//!
//! Owner: M05.P5.T3.
//!
//! Each `mod` declaration below names a threat ID whose test body has
//! been populated. The stub files `tests/threats/<id>.rs` for threat
//! IDs that are not yet covered remain on disk with `unimplemented!()`
//! bodies (see M05.P5.T2) but are intentionally NOT pulled into this
//! integration test, so they neither compile nor run until a follow-up
//! ticket fills the body in. The threat-model-coverage CI gate
//! (M05.P5.T4) inspects the on-disk file set for `unimplemented!`
//! markers to decide which threat IDs still need tests.
//!
//! The six initial threat IDs cited in the M05 success criteria:
//!
//! - capability_token_theft
//! - kernel_impersonation
//! - tool_server_escape
//! - native_channel_replay
//! - resource_exhaustion_dos
//! - delegation_chain_abuse

#[path = "threats/common.rs"]
mod common;

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
