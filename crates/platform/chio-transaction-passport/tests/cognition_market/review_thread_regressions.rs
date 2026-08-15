#[test]
fn cognition_market_qualified_profile_drops_unknown_transaction_claims() -> TestResult {
    const UNKNOWN_TRANSACTION_CLAIM: &str = "claim.transaction.admin_root";
    let mut bundle = build_bundle()?;
    let mut claim_set: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("claim-set.json")
            .ok_or("claim set missing")?,
    )?;
    claim_set["claims"]
        .as_array_mut()
        .ok_or("claim rows missing")?
        .push(json!({
            "claim_id": UNKNOWN_TRANSACTION_CLAIM,
            "status": "verified",
            "required_evidence": [
                "transaction-passport.json",
                "evidence-graph.json",
                "verifier-policy.json"
            ],
            "evidence_refs": [
                "transaction-passport.json",
                "evidence-graph.json",
                "verifier-policy.json"
            ],
            "verifier_module": "unregistered-transaction-verifier"
        }));
    let claim_set_bytes = canonical_json_bytes(&claim_set)?;
    bundle.passport.claim_set_sha256 =
        replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;

    let mut policy: Value = serde_json::from_slice(&bundle.verifier_policy_bytes)?;
    policy["required_claims"]
        .as_array_mut()
        .ok_or("policy required claims missing")?
        .push(Value::String(UNKNOWN_TRANSACTION_CLAIM.to_string()));
    bundle.verifier_policy_bytes = canonical_json_bytes(&policy)?;
    let policy_bytes = bundle.verifier_policy_bytes.clone();
    bundle.passport.verifier_policy_sha256 =
        replace_graph_artifact(&mut bundle, "verifier-policy.json", policy_bytes)?;
    resign_graph(&mut bundle)?;

    let report = verify_cognition_market_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &bundle.artifacts,
        &bundle.trust,
    )?;
    assert!(report.accepted);
    assert!(!report
        .verified_claims
        .iter()
        .any(|claim| claim == UNKNOWN_TRANSACTION_CLAIM));
    assert!(!report
        .claim_results
        .iter()
        .any(|claim| claim.claim_id == UNKNOWN_TRANSACTION_CLAIM));
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_binds_status_authorization_envelope_digest() -> TestResult {
    let mut bundle = build_bundle()?;
    let status_trust = bundle.trust.status.as_mut().ok_or("status trust missing")?;
    let mut different_authorization = status_trust
        .signed_status_operator_authorization
        .body
        .clone();
    different_authorization.revoked_from = Some(CHECKED_AT);
    status_trust.signed_status_operator_authorization =
        SignedExportEnvelope::sign(different_authorization, &Keypair::from_seed(&[8_u8; 32]))?;

    let error = verify(&bundle)
        .err()
        .ok_or("an authorization body unrelated to the pinned digest was accepted")?
        .to_string();
    assert!(
        error.contains("authorization digest does not bind the signed envelope"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_verifier_as_status_operator() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle
        .trust
        .status
        .as_mut()
        .ok_or("status trust missing")?
        .signed_status_operator_authorization
        .body
        .operator
        .key = bundle.trust.finding_verifier_authority.clone();

    let error = verify(&bundle)
        .err()
        .ok_or("finding verifier was accepted as the status operator")?
        .to_string();
    assert!(
        error.contains("status operator and finding verifier authorities must be distinct"),
        "unexpected error: {error}"
    );
    Ok(())
}
