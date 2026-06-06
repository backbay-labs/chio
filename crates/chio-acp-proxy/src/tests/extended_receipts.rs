#[test]
fn receipt_content_hash_deterministic_same_input() {
    let logger = ReceiptLogger::new("srv-1");
    let event = ToolCallEvent {
        tool_call_id: "tc-det".to_string(),
        title: Some("Hash test".to_string()),
        kind: Some("test".to_string()),
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let entry1 = logger.log_tool_call("session-det", &event, None);
    let entry2 = logger.log_tool_call("session-det", &event, None);
    assert_eq!(entry1.content_hash, entry2.content_hash);
    assert_eq!(entry1.content_hash.len(), 64);
}

#[test]
fn receipt_different_inputs_produce_different_hashes() {
    let logger = ReceiptLogger::new("srv-1");
    let event_a = ToolCallEvent {
        tool_call_id: "tc-a".to_string(),
        title: Some("Event A".to_string()),
        kind: Some("test".to_string()),
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let event_b = ToolCallEvent {
        tool_call_id: "tc-b".to_string(),
        title: Some("Event B".to_string()),
        kind: Some("test".to_string()),
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let entry_a = logger.log_tool_call("session-diff", &event_a, None);
    let entry_b = logger.log_tool_call("session-diff", &event_b, None);
    assert_ne!(
        entry_a.content_hash, entry_b.content_hash,
        "different events should produce different hashes"
    );
}

#[test]
fn receipt_missing_optional_fields_handled_gracefully() {
    let logger = ReceiptLogger::new("srv-1");
    let event = ToolCallEvent {
        tool_call_id: "tc-minimal".to_string(),
        title: None,
        kind: None,
        status: None,
        extra: Default::default(),
    };
    let entry = logger.log_tool_call("session-minimal", &event, None);
    assert_eq!(entry.tool_call_id, "tc-minimal");
    assert_eq!(
        entry.title, "",
        "missing title should default to empty string"
    );
    assert!(entry.kind.is_none());
    assert_eq!(
        entry.status, "started",
        "missing status should default to 'started'"
    );
    assert!(!entry.content_hash.is_empty());
    assert_eq!(entry.content_hash.len(), 64);
}

#[test]
fn receipt_tool_call_update_without_status_returns_none() {
    let logger = ReceiptLogger::new("srv-1");
    let event = ToolCallUpdateEvent {
        tool_call_id: "tc-no-status".to_string(),
        status: None,
        extra: Default::default(),
    };
    let result = logger.log_tool_call_update("session-none", &event, None);
    assert!(result.is_none());
}

#[test]
fn receipt_tool_call_update_with_status_returns_some() {
    let logger = ReceiptLogger::new("srv-1");
    let event = ToolCallUpdateEvent {
        tool_call_id: "tc-with-status".to_string(),
        status: Some("error".to_string()),
        extra: Default::default(),
    };
    let result = logger.log_tool_call_update("session-status", &event, None);
    assert!(result.is_some());
    if let Some(entry) = result {
        assert_eq!(entry.tool_call_id, "tc-with-status");
        assert_eq!(entry.status, "error");
        assert_eq!(entry.content_hash.len(), 64);
    }
}

#[test]
fn receipt_update_content_hash_deterministic() {
    let logger = ReceiptLogger::new("srv-1");
    let event = ToolCallUpdateEvent {
        tool_call_id: "tc-upd-det".to_string(),
        status: Some("completed".to_string()),
        extra: Default::default(),
    };
    let entry1 = logger.log_tool_call_update("session-upd", &event, None);
    let entry2 = logger.log_tool_call_update("session-upd", &event, None);
    assert!(entry1.is_some());
    assert!(entry2.is_some());
    if let (Some(e1), Some(e2)) = (entry1, entry2) {
        assert_eq!(e1.content_hash, e2.content_hash);
    }
}

#[test]
fn receipt_server_id_matches_logger_config() {
    let logger = ReceiptLogger::new("custom-server-id");
    let event = ToolCallEvent {
        tool_call_id: "tc-srv".to_string(),
        title: Some("Server ID test".to_string()),
        kind: None,
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let entry = logger.log_tool_call("s1", &event, None);
    assert_eq!(entry.server_id, "custom-server-id");
}

#[test]
fn receipt_timestamp_is_numeric_string() {
    let logger = ReceiptLogger::new("srv-1");
    let event = ToolCallEvent {
        tool_call_id: "tc-ts".to_string(),
        title: Some("Timestamp test".to_string()),
        kind: None,
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let entry = logger.log_tool_call("s1", &event, None);
    assert!(!entry.timestamp.is_empty(), "timestamp should not be empty");
    let parsed: Result<u64, _> = entry.timestamp.parse();
    assert!(
        parsed.is_ok(),
        "timestamp should be a parseable numeric string, got: {}",
        entry.timestamp
    );
}

// ================================================================
// 7. AcpProxy Lifecycle / Config
// ================================================================

#[test]
fn audit_entry_serialization_round_trip() {
    let entry = AcpToolCallAuditEntry {
        tool_call_id: "tc-rt".to_string(),
        title: "Round trip".to_string(),
        kind: Some("test".to_string()),
        status: "completed".to_string(),
        session_id: "s-rt".to_string(),
        timestamp: "1700000000".to_string(),
        server_id: "srv-rt".to_string(),
        content_hash: "a".repeat(64),
        capability_id: Some("cap-rt".to_string()),
        authorization_receipt_id: None,
        authorization_request_id: None,
        authorization_tool_call_id: None,
        authorization_correlation_id: None,
        authorization_operation: None,
        authorization_resource: None,
        authorization_parameter_hash: None,
        enforcement_mode: Some(AcpEnforcementMode::CryptographicallyEnforced),
    };
    let json_result = serde_json::to_string(&entry);
    assert!(json_result.is_ok(), "audit entry should serialize to JSON");
    if let Ok(json_str) = json_result {
        let deserialized: Result<AcpToolCallAuditEntry, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok(), "audit entry should deserialize back");
        if let Ok(entry2) = deserialized {
            assert_eq!(entry2.tool_call_id, "tc-rt");
            assert_eq!(entry2.title, "Round trip");
            assert_eq!(entry2.status, "completed");
            assert_eq!(entry2.content_hash, "a".repeat(64));
        }
    }
}

#[test]
fn tool_call_event_serialization_round_trip() {
    let event = ToolCallEvent {
        tool_call_id: "tc-ser".to_string(),
        title: Some("Serialize test".to_string()),
        kind: Some("execute".to_string()),
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let json_result = serde_json::to_value(&event);
    assert!(json_result.is_ok());
    if let Ok(val) = json_result {
        assert_eq!(val["toolCallId"], "tc-ser");
        assert_eq!(val["title"], "Serialize test");
        assert_eq!(val["kind"], "execute");
        assert_eq!(val["status"], "running");
    }
}

#[test]
fn tool_call_event_with_none_fields_omitted() {
    let event = ToolCallEvent {
        tool_call_id: "tc-none".to_string(),
        title: None,
        kind: None,
        status: None,
        extra: Default::default(),
    };
    let json_result = serde_json::to_value(&event);
    assert!(json_result.is_ok());
    if let Ok(val) = json_result {
        assert_eq!(val["toolCallId"], "tc-none");
        // None fields with skip_serializing_if should not be present.
        assert!(val.get("title").is_none());
        assert!(val.get("kind").is_none());
        assert!(val.get("status").is_none());
    }
}

// ================================================================
// 9. Method parsing and parameter-handling edge cases
// ================================================================
