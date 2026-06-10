#[test]
fn receipt_logger_generates_tool_call_receipt() {
    let logger = ReceiptLogger::new("test-server");
    let event = ToolCallEvent {
        tool_call_id: "tc-1".to_string(),
        title: Some("Read file".to_string()),
        kind: Some("fs_read".to_string()),
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let receipt = logger.log_tool_call("session-1", &event, None);
    assert_eq!(receipt.tool_call_id, "tc-1");
    assert_eq!(receipt.title, "Read file");
    assert_eq!(receipt.kind, Some("fs_read".to_string()));
    assert_eq!(receipt.status, "running");
    assert_eq!(receipt.session_id, "session-1");
    assert_eq!(receipt.server_id, "test-server");
    assert!(!receipt.timestamp.is_empty());
    assert!(!receipt.content_hash.is_empty());
    assert_eq!(receipt.capability_id, None);
    assert_eq!(
        receipt.enforcement_mode,
        Some(AcpEnforcementMode::AuditOnly)
    );
    // SHA-256 hex is 64 chars
    assert_eq!(receipt.content_hash.len(), 64);
}

#[test]
fn receipt_logger_generates_update_receipt_with_status() {
    let logger = ReceiptLogger::new("test-server");
    let event = ToolCallUpdateEvent {
        tool_call_id: "tc-2".to_string(),
        status: Some("completed".to_string()),
        extra: Default::default(),
    };
    let receipt = logger.log_tool_call_update("session-2", &event, None);
    assert!(receipt.is_some());
    let receipt = receipt.unwrap();
    assert_eq!(receipt.tool_call_id, "tc-2");
    assert_eq!(receipt.status, "completed");
    assert_eq!(receipt.capability_id, None);
    assert_eq!(
        receipt.enforcement_mode,
        Some(AcpEnforcementMode::AuditOnly)
    );
    assert!(!receipt.content_hash.is_empty());
    assert_eq!(receipt.content_hash.len(), 64);
}

#[test]
fn receipt_logger_skips_update_without_status() {
    let logger = ReceiptLogger::new("test-server");
    let event = ToolCallUpdateEvent {
        tool_call_id: "tc-3".to_string(),
        status: None,
        extra: Default::default(),
    };
    let receipt = logger.log_tool_call_update("session-3", &event, None);
    assert!(receipt.is_none());
}

// -- Protocol deserialization tests --

#[test]
fn audit_entry_content_hash_is_deterministic() {
    let logger = ReceiptLogger::new("test-server");
    let event = ToolCallEvent {
        tool_call_id: "tc-hash".to_string(),
        title: Some("Determinism check".to_string()),
        kind: Some("test".to_string()),
        status: Some("running".to_string()),
        extra: Default::default(),
    };
    let entry1 = logger.log_tool_call("session-hash", &event, None);
    let entry2 = logger.log_tool_call("session-hash", &event, None);
    assert_eq!(entry1.content_hash, entry2.content_hash);
}

#[test]
fn tool_call_event_content_hash_ignores_unknown_extra_fields() {
    let logger = ReceiptLogger::new("test-server");
    // Two events with identical explicit ACP wire fields but a
    // different `extra` map. The `extra` map captures
    // `#[serde(flatten)]` overflow so unknown future ACP fields
    // round-trip on the wire; it must NOT participate in the
    // content_hash, otherwise downstream `entry.content_hash`
    // comparisons break whenever the agent or client adds a new
    // optional field.
    let mut extra_a = std::collections::BTreeMap::new();
    extra_a.insert(
        "futureFieldA".to_string(),
        serde_json::Value::String("alpha".to_string()),
    );
    let mut extra_b = std::collections::BTreeMap::new();
    extra_b.insert(
        "futureFieldB".to_string(),
        serde_json::Value::Number(serde_json::Number::from(42)),
    );
    extra_b.insert(
        "anotherUnknown".to_string(),
        serde_json::Value::Bool(true),
    );

    let event_a = ToolCallEvent {
        tool_call_id: "tc-extra".to_string(),
        title: Some("Same explicit fields".to_string()),
        kind: Some("fs_read".to_string()),
        status: Some("running".to_string()),
        extra: extra_a,
    };
    let event_b = ToolCallEvent {
        tool_call_id: "tc-extra".to_string(),
        title: Some("Same explicit fields".to_string()),
        kind: Some("fs_read".to_string()),
        status: Some("running".to_string()),
        extra: extra_b,
    };
    let entry_a = logger.log_tool_call("session-extra", &event_a, None);
    let entry_b = logger.log_tool_call("session-extra", &event_b, None);
    assert_eq!(
        entry_a.content_hash, entry_b.content_hash,
        "content_hash must be stable across unknown extra fields"
    );

    // Same property for ToolCallUpdateEvent.
    let mut update_extra_a = std::collections::BTreeMap::new();
    update_extra_a.insert(
        "futureUpdateField".to_string(),
        serde_json::Value::String("first".to_string()),
    );
    let mut update_extra_b = std::collections::BTreeMap::new();
    update_extra_b.insert(
        "futureUpdateField".to_string(),
        serde_json::Value::String("second".to_string()),
    );
    update_extra_b.insert(
        "yetAnother".to_string(),
        serde_json::Value::Null,
    );
    let update_a = ToolCallUpdateEvent {
        tool_call_id: "tc-extra".to_string(),
        status: Some("completed".to_string()),
        extra: update_extra_a,
    };
    let update_b = ToolCallUpdateEvent {
        tool_call_id: "tc-extra".to_string(),
        status: Some("completed".to_string()),
        extra: update_extra_b,
    };
    let update_entry_a = logger
        .log_tool_call_update("session-extra", &update_a, None)
        .expect("update entry should exist");
    let update_entry_b = logger
        .log_tool_call_update("session-extra", &update_b, None)
        .expect("update entry should exist");
    assert_eq!(
        update_entry_a.content_hash, update_entry_b.content_hash,
        "update content_hash must be stable across unknown extra fields"
    );
}
