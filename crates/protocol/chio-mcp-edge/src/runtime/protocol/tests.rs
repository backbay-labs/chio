use std::io::{self, Read};
use std::time::Duration;

use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalTokenBody, ThresholdApprovalProposalBody,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::Keypair;

fn threshold_approval_artifacts() -> (Vec<GovernedApprovalToken>, ThresholdApprovalProposal) {
    let subject = Keypair::generate();
    let policy_authority = Keypair::generate();
    let approver_a = Keypair::generate();
    let approver_b = Keypair::generate();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: "proposal-mcp-001".to_string(),
            request_id: "request-mcp-001".to_string(),
            governed_intent_hash: "a".repeat(64),
            subject: subject.public_key(),
            authorizing_capability_digest: "b".repeat(64),
            policy_hash: "c".repeat(64),
            threshold: 2,
            eligible_set_digest: "d".repeat(64),
            proposal_created_at: 100,
            proposal_deadline: 200,
            policy_authority: policy_authority.public_key(),
        },
        &policy_authority,
    )
    .unwrap_or_else(|error| panic!("proposal must sign: {error}"));
    let proposal_hash = proposal
        .artifact_digest()
        .unwrap_or_else(|error| panic!("proposal must hash: {error}"));
    let tokens = [&approver_a, &approver_b]
        .into_iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("approval-mcp-{index}"),
                    approver: approver.public_key(),
                    subject: subject.public_key(),
                    governed_intent_hash: "a".repeat(64),
                    request_id: "request-mcp-001".to_string(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    issued_at: 100,
                    expires_at: 200,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap_or_else(|error| panic!("approval must sign: {error}"))
        })
        .collect();
    (tokens, proposal)
}

#[test]
fn mcp_meta_preserves_complete_threshold_approval_set() {
    let (tokens, proposal) = threshold_approval_artifacts();
    let params = json!({
        "_meta": {
            "chioApprovalTokens": tokens,
            "chioThresholdApprovalProposal": proposal,
        }
    });

    let (singular, parsed_tokens, parsed_proposal) =
        parse_request_approval_artifacts(&json!("request-mcp-001"), &params)
            .unwrap_or_else(|error| panic!("approval metadata must parse: {error:?}"));

    assert!(singular.is_none());
    assert_eq!(parsed_tokens, tokens);
    assert_eq!(parsed_proposal, Some(proposal));
}

#[test]
fn mcp_meta_rejects_mixed_singular_and_threshold_approvals() {
    let (tokens, proposal) = threshold_approval_artifacts();
    let params = json!({
        "_meta": {
            "chioApprovalToken": tokens[0],
            "chioApprovalTokens": tokens,
            "chioThresholdApprovalProposal": proposal,
        }
    });

    let Err(error) = parse_request_approval_artifacts(&json!("request-mcp-001"), &params) else {
        panic!("mixed approval forms must fail closed");
    };

    assert_eq!(error["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(
        error["error"]["message"],
        "singular and threshold approval tokens must not be mixed"
    );
}

#[test]
fn mcp_meta_keeps_supplemental_authorization_opaque() {
    let params = json!({
        "_meta": {
            "chioSupplementalAuthorization": {
                "signed_extension": "b3BhcXVl"
            }
        }
    });

    let authorization =
        parse_request_supplemental_authorization(&json!("request-mcp-opaque"), &params)
            .unwrap_or_else(|error| panic!("opaque authorization must parse: {error:?}"));

    assert_eq!(
        authorization.map(|value| value.signed_extension),
        Some("b3BhcXVl".to_string())
    );
}

#[test]
fn mcp_meta_rejects_caller_supplied_supplemental_claim_fields() {
    let params = json!({
        "_meta": {
            "chioSupplementalAuthorization": {
                "signed_extension": "b3BhcXVl",
                "max_invocations": 1000
            }
        }
    });

    let Err(error) = parse_request_supplemental_authorization(&json!("request-mcp-claim"), &params)
    else {
        panic!("caller-built supplemental claim must fail closed");
    };

    assert_eq!(error["error"]["code"], JSONRPC_INVALID_PARAMS);
}

#[test]
fn parse_jsonrpc_envelope_preserves_id_method_and_default_params() {
    let envelope = match parse_jsonrpc_envelope(&json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/list",
    })) {
        Ok(envelope) => envelope,
        Err(error) => panic!("valid envelope should parse, got: {error:?}"),
    };

    assert_eq!(envelope.id, Some(json!("req-1")));
    assert_eq!(envelope.method, "tools/list");
    assert_eq!(envelope.params, json!({}));
}

#[test]
fn parse_jsonrpc_envelope_rejects_non_scalar_request_ids() {
    for invalid_id in [json!(true), json!([]), json!({"nested": "bad"})] {
        let Err(response) = parse_jsonrpc_envelope(&json!({
            "jsonrpc": "2.0",
            "id": invalid_id,
            "method": "tools/list",
        })) else {
            panic!("non-scalar request id must fail closed");
        };

        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], JSONRPC_INVALID_REQUEST);
        assert_eq!(
            response["error"]["message"],
            "request id must be string, number, or null"
        );
    }
}

#[test]
fn parse_jsonrpc_envelope_returns_structured_errors() {
    let Err(response) = parse_jsonrpc_envelope(&json!({
        "jsonrpc": "1.0",
        "id": "req-1",
        "method": "tools/list",
    })) else {
        panic!("invalid jsonrpc version must fail closed");
    };
    assert_eq!(response["id"], Value::Null);
    assert_eq!(response["error"]["code"], JSONRPC_INVALID_REQUEST);
    assert_eq!(response["error"]["message"], "invalid jsonrpc envelope");

    let Err(response) = parse_jsonrpc_envelope(&json!({
        "jsonrpc": "2.0",
        "id": "req-2",
    })) else {
        panic!("missing method must fail closed");
    };
    assert_eq!(response["id"], json!("req-2"));
    assert_eq!(response["error"]["code"], JSONRPC_INVALID_REQUEST);
    assert_eq!(response["error"]["message"], "request missing method");
}

#[test]
fn known_notification_params_gate_rejects_non_object_known_params() {
    assert!(known_notification_params_are_object(
        "notifications/initialized",
        &json!({})
    ));
    assert!(known_notification_params_are_object(
        "notifications/initialized",
        &json!({"client": "ready"})
    ));
    assert!(!known_notification_params_are_object(
        "notifications/initialized",
        &json!([])
    ));
    assert!(known_notification_params_are_object(
        "notifications/unknown",
        &json!([])
    ));
}

#[test]
fn cancelled_notification_side_channel_requires_object_params() {
    assert!(is_cancellation_side_channel_signal(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {
            "requestId": "edge-client-1"
        }
    })));
    assert!(!is_cancellation_side_channel_signal(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": []
    })));
    assert!(!is_cancellation_side_channel_signal(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled"
    })));
}

#[derive(Default)]
struct OneErrorThenEofReader {
    emitted_error: bool,
}

impl Read for OneErrorThenEofReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl BufRead for OneErrorThenEofReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.emitted_error {
            Ok(&[])
        } else {
            self.emitted_error = true;
            Err(io::Error::other("synthetic reader failure"))
        }
    }

    fn consume(&mut self, _amt: usize) {}
}

#[test]
fn pump_client_messages_stops_after_read_error() {
    let (sender, receiver) = mpsc::channel();
    let (cancel_sender, _cancel_receiver) = mpsc::channel();

    pump_client_messages(OneErrorThenEofReader::default(), sender, cancel_sender);

    match receiver
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or_else(|error| panic!("expected read error from pump: {error}"))
    {
        ClientInbound::ReadError(message) => {
            assert!(message.contains("synthetic reader failure"));
        }
        ClientInbound::Message(_) => panic!("expected read error, got message"),
        ClientInbound::ParseError(message) => {
            panic!("expected read error, got parse error: {message}")
        }
        ClientInbound::Closed => panic!("expected read error, got closed"),
    }
    assert!(
        receiver.recv_timeout(Duration::from_millis(50)).is_err(),
        "pump should close after read error without emitting EOF"
    );
}

#[test]
fn task_cancel_related_task_requires_request_id() {
    let notification_shaped_cancel = json!({
        "jsonrpc": "2.0",
        "method": "tasks/cancel",
        "params": {
            "taskId": "mcp-edge-task-1"
        }
    });
    assert!(!task_cancel_matches_related_task(
        &notification_shaped_cancel,
        Some("mcp-edge-task-1")
    ));

    let malformed_request_id_cancel = json!({
        "jsonrpc": "2.0",
        "id": { "nested": "bad" },
        "method": "tasks/cancel",
        "params": {
            "taskId": "mcp-edge-task-1"
        }
    });
    assert!(!task_cancel_matches_related_task(
        &malformed_request_id_cancel,
        Some("mcp-edge-task-1")
    ));

    let request_shaped_cancel = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tasks/cancel",
        "params": {
            "taskId": "mcp-edge-task-1"
        }
    });
    assert!(task_cancel_matches_related_task(
        &request_shaped_cancel,
        Some("mcp-edge-task-1")
    ));
}
