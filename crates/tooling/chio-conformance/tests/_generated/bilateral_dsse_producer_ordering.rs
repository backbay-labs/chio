// DO NOT EDIT - regenerate via 'cargo xtask codegen rust'.
//
// Source: spec/statemachines/bilateral_dsse_producer.toml
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
pub const MACHINE: &str = "bilateral_dsse_producer";
pub const SCOPE: &str = "The strict bilateral DSSE producer from canonical statement construction through local host signing, origin co-signing, and final envelope verification.";
pub const DOC_REFS: &[&str] =
    &["spec/CHIO_BILATERAL_COSIGN_INVOCATION.md#7-verification-algorithm"];
pub const STATES: &[&str] = &["Drafted", "HostSigned", "Cosigned", "EnvelopeVerified"];
pub const TERMINAL_STATES: &[&str] = &["EnvelopeVerified"];
pub const MESSAGES: &[&str] = &["request_cosignature", "sign_host", "verify_envelope"];
pub const TRANSITIONS: &[TransitionSpec] = &[
    TransitionSpec {
        from: "Drafted",
        message: "sign_host",
        to: "HostSigned",
        guards: &["host_signature_created"],
    },
    TransitionSpec {
        from: "HostSigned",
        message: "request_cosignature",
        to: "Cosigned",
        guards: &["cosigning_schema_matches", "origin_signature_valid"],
    },
    TransitionSpec {
        from: "Cosigned",
        message: "verify_envelope",
        to: "EnvelopeVerified",
        guards: &["signer_keys_independent", "strict_envelope_valid"],
    },
];
pub const NON_EDGES: &[NonEdge] = &[
    NonEdge {
        state: "Drafted",
        message: "request_cosignature",
    },
    NonEdge {
        state: "Drafted",
        message: "verify_envelope",
    },
    NonEdge {
        state: "HostSigned",
        message: "sign_host",
    },
    NonEdge {
        state: "HostSigned",
        message: "verify_envelope",
    },
    NonEdge {
        state: "Cosigned",
        message: "request_cosignature",
    },
    NonEdge {
        state: "Cosigned",
        message: "sign_host",
    },
    NonEdge {
        state: "EnvelopeVerified",
        message: "request_cosignature",
    },
    NonEdge {
        state: "EnvelopeVerified",
        message: "sign_host",
    },
    NonEdge {
        state: "EnvelopeVerified",
        message: "verify_envelope",
    },
];
