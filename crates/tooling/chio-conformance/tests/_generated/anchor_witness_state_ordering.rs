// DO NOT EDIT - regenerate via 'cargo xtask codegen rust'.
//
// Source: spec/statemachines/anchor_witness_state.toml
// Tool:   chio-spec-codegen state machine pass
// Owner:  chio-conformance
//
// Manual edits will be overwritten.

#![allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionSpec {
    pub from: &'static str,
    pub message: &'static str,
    pub to: &'static str,
    pub guards: &'static [&'static str],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonEdge {
    pub state: &'static str,
    pub message: &'static str,
}
pub const MACHINE: &str = "anchor_witness_state";
pub const SCOPE: &str = "Producer-carried AnchorBatch WitnessState metadata changes only. This relation does not encode verifier routing, witness admission policy, or a transport protocol.";
pub const DOC_REFS: &[&str] = &["spec/PROTOCOL.md#anchor-batch-public-witness-lane-w23"];
pub const STATES: &[&str] = &["Pending", "Witnessed", "Stale"];
pub const TERMINAL_STATES: &[&str] = &[];
pub const MESSAGES: &[&str] = &["record_verification_failure", "record_verified_receipt"];
pub const TRANSITIONS: &[TransitionSpec] = &[
    TransitionSpec {
        from: "Pending",
        message: "record_verified_receipt",
        to: "Witnessed",
        guards: &["receipt_matches_batch"],
    },
    TransitionSpec {
        from: "Witnessed",
        message: "record_verified_receipt",
        to: "Witnessed",
        guards: &["receipt_matches_batch"],
    },
    TransitionSpec {
        from: "Witnessed",
        message: "record_verification_failure",
        to: "Stale",
        guards: &["prior_verification_exists"],
    },
    TransitionSpec {
        from: "Stale",
        message: "record_verified_receipt",
        to: "Witnessed",
        guards: &["receipt_matches_batch"],
    },
    TransitionSpec {
        from: "Stale",
        message: "record_verification_failure",
        to: "Stale",
        guards: &["prior_verification_exists"],
    },
];
pub const NON_EDGES: &[NonEdge] = &[NonEdge {
    state: "Pending",
    message: "record_verification_failure",
}];
