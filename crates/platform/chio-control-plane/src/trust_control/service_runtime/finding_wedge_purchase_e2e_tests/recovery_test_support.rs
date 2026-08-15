fn legacy_custom_recovery_token(
    subject: PublicKey,
    issuer: &Keypair,
    token_id: &str,
    finding_id: &str,
    payload_sha256: &str,
    original_receipt_id: &str,
    original_capability_id: &str,
    now: u64,
) -> Result<CapabilityToken, AnyError> {
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: token_id.to_owned(),
            issuer: issuer.public_key(),
            subject,
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.to_owned(),
                    tool_name: READ_FINDING_TOOL.to_owned(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![
                        Constraint::OutputDigestSha256(payload_sha256.to_owned()),
                        Constraint::Custom(
                            "recovery_of_receipt_id".to_owned(),
                            original_receipt_id.to_owned(),
                        ),
                        Constraint::Custom(
                            "recovery_of_capability_id".to_owned(),
                            original_capability_id.to_owned(),
                        ),
                        Constraint::Custom("finding_id".to_owned(), finding_id.to_owned()),
                    ],
                    max_invocations: Some(2),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: now.saturating_sub(5),
            expires_at: now.saturating_add(600),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )?)
}

fn assert_superseded_reservation_replays(lane: &Lane, web: &MarketWeb) -> TestResult {
    let replayed = lane.coordinator.reserve(
        &lane.purchase.handshake.bid,
        &lane.purchase.handshake.ask,
        &lane.purchase.handshake.buyer_signature_hex,
        &web.admission,
        &web.authorization,
        EXPOSURE_UNITS,
        RESERVATION_TTL_SECS,
        unix_timestamp_now(),
    )?;
    assert_eq!(
        VerifiedReservationReceipt::from_signed(&replayed, &keypair(16).public_key())?.receipt_id(),
        lane.purchase.handshake.reservation_id,
        "a response-loss retry must recover the committed reservation after supersession"
    );
    Ok(())
}
