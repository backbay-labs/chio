#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use serde_json::json;

use support::{start_http_server, start_http_server_with_lifecycle_tuning, LifecycleTuning};

#[test]
fn hosted_mcp_sessions_initialize_resume_and_report_ready_state() {
    let server = start_http_server("test-token");
    let session = server.initialize_session();

    let trust = server.get_admin_session_trust(&session.id);
    assert_eq!(trust.status(), reqwest::StatusCode::OK);
    let trust: serde_json::Value = trust.json().expect("session trust json");
    assert_eq!(trust["sessionId"].as_str(), Some(session.id.as_str()));
    assert_eq!(trust["lifecycle"]["state"].as_str(), Some("ready"));
    assert_eq!(
        trust["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(true)
    );
    assert_eq!(
        trust["ownership"]["hostedIsolation"].as_str(),
        Some("dedicated_per_session")
    );
    assert_eq!(
        trust["ownership"]["hostedIdentityProfile"].as_str(),
        Some("strong_dedicated_session")
    );

    let list = server.list_tools(&session);
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"].as_str(), Some("echo_json"));

    let repeat_trust = server.get_admin_session_trust(&session.id);
    assert_eq!(repeat_trust.status(), reqwest::StatusCode::OK);
    let repeat_trust: serde_json::Value = repeat_trust.json().expect("repeat trust json");
    assert_eq!(repeat_trust["lifecycle"]["state"].as_str(), Some("ready"));
}

#[test]
fn hosted_mcp_sessions_expire_under_ttl_and_cannot_be_reused() {
    let server = start_http_server_with_lifecycle_tuning(
        "test-token",
        LifecycleTuning {
            idle_expiry_millis: Some(250),
            drain_grace_millis: Some(250),
            reaper_interval_millis: Some(50),
            ..LifecycleTuning::default()
        },
    );
    let session = server.initialize_session();

    let expired = server.wait_for_session_state(&session.id, "expired");
    assert_eq!(
        expired["lifecycle"]["reconnect"]["resumable"].as_bool(),
        Some(false)
    );
    assert!(expired["lifecycle"]["reconnect"]["terminalStates"]
        .as_array()
        .expect("terminal states")
        .iter()
        .any(|value| value.as_str() == Some("expired")));

    let resumed_post = server.post_json(
        Some(&session.id),
        Some(&session.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    assert_eq!(resumed_post.status(), reqwest::StatusCode::GONE);

    let resumed_get = server.get_session_stream(&session.id, Some(&session.protocol_version), None);
    assert_eq!(resumed_get.status(), reqwest::StatusCode::GONE);

    let fresh_session = server.initialize_session();
    assert_ne!(fresh_session.id, session.id);
    assert_eq!(fresh_session.protocol_version, session.protocol_version);
}
