use super::*;

pub(super) fn finding_fixture_bytes() -> TestResult<Vec<u8>> {
    let mut finding: chio_finding::Finding = serde_json::from_slice(include_bytes!(
        "../../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json"
    ))?;
    chio_finding::verify_finding(&finding)?;
    finding.replay_recipe_sha256 = Some(sha256_hex(&recipe_bytes("bb")?));
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    finding = sign_finding(finding, &Keypair::from_seed(&[9_u8; 32]))?;
    assert_eq!(finding.finding_id, FINDING_ID);
    Ok(canonical_json_bytes(&finding)?)
}

pub(super) fn rebind_recipe_and_finding(
    bundle: &mut QualifiedBundle,
    mutate: impl FnOnce(&mut FindingReplayRecipeInput),
) -> TestResult {
    let mut recipe: FindingReplayRecipeInput = serde_json::from_slice(
        bundle
            .artifacts
            .get("attachments/replay-recipe-input.json")
            .ok_or("recipe missing")?,
    )?;
    mutate(&mut recipe);
    recipe.validate()?;
    let recipe_bytes = canonical_json_bytes(&recipe)?;

    let mut finding: chio_finding::Finding = serde_json::from_slice(
        bundle
            .artifacts
            .get("finding.json")
            .ok_or("Finding missing")?,
    )?;
    finding.replay_recipe_sha256 = Some(sha256_hex(&recipe_bytes));
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    finding = sign_finding(finding, &Keypair::from_seed(&[9_u8; 32]))?;
    let finding_bytes = canonical_json_bytes(&finding)?;
    let finding_sha256 = sha256_hex(&finding_bytes);
    let status_bytes = status_proof_bytes_for_finding(false, &finding.finding_id)?;

    let mut claim_set: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("claim-set.json")
            .ok_or("ClaimSet missing")?,
    )?;
    claim_set["subject"]["id"] = Value::String(finding.finding_id.clone());
    claim_set["subject"]["artifact_sha256"] = Value::String(finding_sha256.clone());

    let mut report: SignedExportEnvelope<FindingVerifierReport> = serde_json::from_slice(
        bundle
            .artifacts
            .get("report.json")
            .ok_or("report missing")?,
    )?;
    report.body.finding_id = finding.finding_id;
    report.body.finding_artifact_sha256 = finding_sha256;
    report.body.replay_recipe_input_sha256 = Some(sha256_hex(&recipe_bytes));
    report.body.status_proof_input_sha256 = Some(sha256_hex(&status_bytes));
    report.body.report_id = compute_report_id(&report.body)?;
    report = SignedExportEnvelope::sign(report.body, &verifier_keypair())?;

    replace_graph_artifact(bundle, "attachments/replay-recipe-input.json", recipe_bytes)?;
    replace_graph_artifact(bundle, "attachments/status-proof-input.json", status_bytes)?;
    replace_graph_artifact(bundle, "finding.json", finding_bytes)?;
    bundle.passport.claim_set_sha256 =
        replace_graph_artifact(bundle, "claim-set.json", canonical_json_bytes(&claim_set)?)?;
    replace_graph_artifact(bundle, "report.json", canonical_json_bytes(&report)?)?;
    resign_graph(bundle)
}

pub(super) fn retract_report_finding(bundle: &mut QualifiedBundle) -> TestResult {
    let report: SignedExportEnvelope<FindingVerifierReport> = serde_json::from_slice(
        bundle
            .artifacts
            .get("report.json")
            .ok_or("report missing")?,
    )?;
    bundle
        .trust
        .status
        .as_mut()
        .ok_or("status trust missing")?
        .status_store = Arc::new(TestStatusStore::with_retracted(&report.body.finding_id));
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_backdated_report_after_profile_expiry() -> TestResult
{
    let mut bundle = build_bundle()?;
    replace_trusted_profile(&mut bundle, |profile| {
        profile.expires_at = CHECKED_AT + 1;
    })?;
    let mut status = bundle
        .trust
        .verifier_authority_status
        .signed_status
        .body
        .clone();
    status.observed_at = CHECKED_AT + 2;
    bundle.trust.verifier_authority_status.signed_status =
        SignedExportEnvelope::sign(status, &Keypair::from_seed(&[10_u8; 32]))?;
    bundle.trust.verifier_authority_status.checked_at = CHECKED_AT + 2;

    let error = verify(&bundle)
        .err()
        .ok_or("backdated report under an expired verifier profile was accepted")?
        .to_string();
    assert!(
        error.contains("after verifier-profile expiration"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_backdated_report_after_finding_expiry() -> TestResult
{
    let finding: chio_finding::Finding = serde_json::from_slice(&finding_fixture_bytes()?)?;
    let mut bundle = build_bundle()?;
    replace_trusted_profile(&mut bundle, |profile| {
        profile.expires_at = finding.expires_at + 600;
        profile.verifier_report_signer.valid_until = finding.expires_at + 600;
    })?;
    let mut status = bundle
        .trust
        .verifier_authority_status
        .signed_status
        .body
        .clone();
    status.observed_at = finding.expires_at;
    bundle.trust.verifier_authority_status.signed_status =
        SignedExportEnvelope::sign(status, &Keypair::from_seed(&[10_u8; 32]))?;
    bundle.trust.verifier_authority_status.checked_at = finding.expires_at;

    let error = verify(&bundle)
        .err()
        .ok_or("backdated report under an expired Finding was accepted")?
        .to_string();
    assert!(
        error.contains("after Finding expiration"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_recipe_must_bind_the_signed_finding_payload() -> TestResult {
    let mut bundle = build_bundle()?;
    rebind_recipe_and_finding(&mut bundle, |recipe| {
        recipe.payload_sha256 = "dd".repeat(32);
    })?;
    let error = verify(&bundle)
        .err()
        .ok_or("recipe for another Finding payload was accepted")?
        .to_string();
    assert!(
        error.contains("signed Finding context and payload"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_recipe_must_use_a_profile_allowed_runner() -> TestResult {
    let mut bundle = build_bundle()?;
    rebind_recipe_and_finding(&mut bundle, |recipe| {
        recipe.runner_manifest_sha256 = "dd".repeat(32);
    })?;
    let error = verify(&bundle)
        .err()
        .ok_or("recipe using a disallowed runner was accepted")?
        .to_string();
    assert!(
        error.contains("not allowed by the deployment-pinned verifier profile"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_status_proof_must_bind_the_finding_feed() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle
        .trust
        .status
        .as_mut()
        .ok_or("status trust missing")?
        .status_operator_authorization
        .feed_id = "finding-status/substituted".to_string();
    let error = verify(&bundle)
        .err()
        .ok_or("status proof for another feed was accepted")?
        .to_string();
    assert!(error.contains("do not bind the Finding status feed"));
    Ok(())
}

#[test]
fn cognition_market_status_proof_must_not_predate_the_finding() -> TestResult {
    let mut bundle = build_bundle()?;
    let status_path = "attachments/status-proof-input.json";
    let mut status: FindingStatusProofInput = serde_json::from_slice(
        bundle
            .artifacts
            .get(status_path)
            .ok_or("status proof missing")?,
    )?;
    match &mut status {
        FindingStatusProofInput::NonInclusion(value) => value.checked_at = GENERATED_AT - 1,
        FindingStatusProofInput::Inclusion(_) => return Err("expected non-inclusion proof".into()),
    }
    let status_bytes = canonical_json_bytes(&status)?;
    let recipe_bytes = bundle
        .artifacts
        .get("attachments/replay-recipe-input.json")
        .ok_or("recipe missing")?
        .clone();
    let report_bytes = report_bytes(&recipe_bytes, &status_bytes)?;
    replace_graph_artifact(&mut bundle, status_path, status_bytes)?;
    replace_graph_artifact(&mut bundle, "report.json", report_bytes)?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("status proof from before Finding issuance was accepted")?
        .to_string();
    assert!(error.contains("status proof predates the signed Finding"));
    Ok(())
}

#[test]
fn cognition_market_enforces_facets_derived_from_the_signed_finding() -> TestResult {
    let mut bundle = build_bundle()?;
    let selected_claim = COGNITION_MARKET_CLAIMS[3];

    let mut claim_set: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("claim-set.json")
            .ok_or("claim set missing")?,
    )?;
    claim_set["claims"]
        .as_array_mut()
        .ok_or("claim rows missing")?
        .retain(|claim| claim.get("claim_id").and_then(Value::as_str) == Some(selected_claim));
    let claim_set_bytes = canonical_json_bytes(&claim_set)?;
    bundle.passport.claim_set_sha256 =
        replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;

    let mut policy: Value = serde_json::from_slice(&bundle.verifier_policy_bytes)?;
    policy["required_claims"] = json!([selected_claim]);
    bundle.verifier_policy_bytes = canonical_json_bytes(&policy)?;
    let policy_bytes = bundle.verifier_policy_bytes.clone();
    bundle.passport.verifier_policy_sha256 =
        replace_graph_artifact(&mut bundle, "verifier-policy.json", policy_bytes)?;

    let report_bytes = bundle
        .artifacts
        .get("report.json")
        .ok_or("report missing")?;
    let signed: SignedExportEnvelope<FindingVerifierReport> = serde_json::from_slice(report_bytes)?;
    let mut report = signed.body;
    let receipt_authenticity = report
        .facets
        .iter_mut()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    receipt_authenticity.outcome = FindingFacetOutcome::Unavailable;
    receipt_authenticity.reason = "production evidence was not supplied".to_string();
    report.report_id = compute_report_id(&report)?;
    let replacement = SignedExportEnvelope::sign(report, &verifier_keypair())?;
    replace_graph_artifact(
        &mut bundle,
        "report.json",
        canonical_json_bytes(&replacement)?,
    )?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("a report below the signed Finding's facet floor was accepted")?
        .to_string();
    assert!(
        error.contains("signed Finding requires verified facet ReceiptAuthenticity"),
        "unexpected error: {error}"
    );
    Ok(())
}
