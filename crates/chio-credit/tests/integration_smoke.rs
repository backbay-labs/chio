use chio_credit::ExposureLedgerQuery;

#[test]
fn exposure_ledger_query_requires_an_anchor() {
    let error = match ExposureLedgerQuery::default().validate() {
        Ok(()) => panic!("query without anchors must fail"),
        Err(error) => error,
    };

    assert!(error.contains("require at least one anchor"));
}

#[test]
fn exposure_ledger_query_normalizes_limits() {
    let query = ExposureLedgerQuery {
        tool_server: Some("tool-server".to_string()),
        receipt_limit: Some(0),
        decision_limit: Some(9999),
        ..ExposureLedgerQuery::default()
    };

    assert!(query.validate().is_ok());

    let normalized = query.normalized();
    assert_eq!(normalized.receipt_limit, Some(1));
    assert_eq!(
        normalized.decision_limit,
        Some(query.decision_limit_or_default())
    );
}
