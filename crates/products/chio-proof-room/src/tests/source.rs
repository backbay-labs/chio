use super::support::*;
use super::*;
use crate::{
    embedded_swarm_authority_bundle, ensure_source_policy_required_claims_verified,
    is_agent_web_evidence_graph_node, merge_source_family_verifier_reports,
    source_verifier_context_with_options, verify_source_standalone_risk_report_with_keys,
};
use chio_core_types::PublicKey;

#[test]
fn swarm_fixture_uses_verification_time_for_freshness() -> Result<(), Box<dyn Error>> {
    let fixture =
        repo_root()?.join("fixtures/proof-room/swarm-authority/valid-recursive-delegation");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.join("evidence-graph.json"))?)?;
    let mut values = std::collections::BTreeMap::new();
    for node in evidence_graph["nodes"]
        .as_array()
        .ok_or("evidence graph nodes missing")?
    {
        let path = node["path"]
            .as_str()
            .ok_or("node path missing")?
            .to_string();
        let mut value: serde_json::Value = serde_json::from_slice(&fs::read(fixture.join(&path))?)?;
        expire_swarm_artifact_before_verification_time(&mut value);
        values.insert(path, value);
    }
    let task_graph_sha256 = canonical_json_sha256(
        values
            .get("task-graph.json")
            .ok_or("mutated task graph missing")?,
    )?;
    for value in values.values_mut() {
        if value.get("graphSha256").is_some() {
            value["graphSha256"] = serde_json::Value::String(task_graph_sha256.clone());
        }
    }
    let mut artifacts = std::collections::BTreeMap::new();
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        let path = node["path"]
            .as_str()
            .ok_or("node path missing")?
            .to_string();
        let value = values.get(&path).ok_or("mutated swarm artifact missing")?;
        let bytes = json_bytes(value)?;
        node["sha256"] = serde_json::Value::String(sha256_hex(&bytes));
        artifacts.insert(path, bytes);
    }
    let evidence_graph_bytes = json_bytes(&evidence_graph)?;
    let bundle = embedded_swarm_authority_bundle(&evidence_graph_bytes, &artifacts)?;

    let error = chio_swarm_authority::verify_swarm_authority_bundle(
        &bundle,
        &swarm_fixture_trusted_witness_keys()?,
    )
    .err()
    .ok_or("expired swarm bundle unexpectedly verified")?;

    assert!(
        error.to_string().contains("swarm task graph is expired"),
        "{error}"
    );
    Ok(())
}

fn expire_swarm_artifact_before_verification_time(value: &mut serde_json::Value) {
    const CREATED_AT_UNIX_MS: u64 = 1_700_000_000_000;
    const EXPIRES_AT_UNIX_MS: u64 = 1_700_000_600_000;

    if value.get("createdAtUnixMs").is_some() {
        value["createdAtUnixMs"] = serde_json::Value::from(CREATED_AT_UNIX_MS);
    }
    if value.get("issuedAtUnixMs").is_some() {
        value["issuedAtUnixMs"] = serde_json::Value::from(CREATED_AT_UNIX_MS);
    }
    if value.get("expiresAtUnixMs").is_some() {
        value["expiresAtUnixMs"] = serde_json::Value::from(EXPIRES_AT_UNIX_MS);
    }
    if value.get("validUntilUnixMs").is_some() {
        value["validUntilUnixMs"] = serde_json::Value::from(EXPIRES_AT_UNIX_MS);
    }
}

#[test]
fn crypto_context_verified_report_rejects_context_report_drift() -> Result<(), Box<dyn Error>> {
    let fixture = repo_root()?.join("fixtures/proof-room/crypto-context/valid-bbs-context");
    let report_bytes = fs::read(fixture.join("crypto-context-report.json"))?;
    let context_bytes = fs::read(fixture.join("verification-context.json"))?;
    let proof_bytes = fs::read(fixture.join("selective-disclosure-proof.json"))?;
    let privacy_profile_bytes = fs::read(fixture.join("verifier-privacy-profile.json"))?;
    let mut context: serde_json::Value = serde_json::from_slice(&context_bytes)?;
    context["audience"] = serde_json::Value::String("https://attacker.example/chio".to_string());
    let context_bytes = serde_json::to_vec(&context)?;

    let error = crypto_context_verified_report_bytes_with_bbs(
        &context_bytes,
        &report_bytes,
        &proof_bytes,
        &privacy_profile_bytes,
        "crypto-context-valid-bbs",
    )
    .err()
    .ok_or("drifted crypto context report unexpectedly verified")?;

    assert!(error.contains("disclosure_context_audience_mismatch"));
    Ok(())
}

#[test]
fn crypto_context_verified_report_rejects_unsigned_report() -> Result<(), Box<dyn Error>> {
    let fixture = repo_root()?.join("fixtures/proof-room/crypto-context/valid-bbs-context");
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.join("crypto-context-report.json"))?)?;
    report
        .as_object_mut()
        .ok_or("crypto context report is not an object")?
        .remove("signature");
    let report_bytes = serde_json::to_vec(&report)?;
    let context_bytes = fs::read(fixture.join("verification-context.json"))?;
    let proof_bytes = fs::read(fixture.join("selective-disclosure-proof.json"))?;
    let privacy_profile_bytes = fs::read(fixture.join("verifier-privacy-profile.json"))?;

    let error = crypto_context_verified_report_bytes_with_bbs(
        &context_bytes,
        &report_bytes,
        &proof_bytes,
        &privacy_profile_bytes,
        "crypto-context-valid-bbs",
    )
    .err()
    .ok_or("unsigned crypto context report unexpectedly verified")?;

    assert!(error.contains("crypto context report signature missing"));
    Ok(())
}

#[test]
fn crypto_context_verified_report_requires_bbs_proof_material() -> Result<(), Box<dyn Error>> {
    let fixture = repo_root()?.join("fixtures/proof-room/crypto-context/valid-bbs-context");
    let report_bytes = fs::read(fixture.join("crypto-context-report.json"))?;
    let context_bytes = fs::read(fixture.join("verification-context.json"))?;

    let error = crypto_context_verified_report_bytes(
        &context_bytes,
        &report_bytes,
        "crypto-context-valid-bbs",
    )
    .err()
    .ok_or("crypto context report unexpectedly verified without BBS proof material")?;

    assert!(error.contains("missing BBS proof material"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_bbs_verified_crypto_context_negative_fixture_report(
) -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/crypto-context-wrong-audience/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.disclosure.crypto-context-report.v1");
    assert_eq!(report["verdict"], "rejected");
    assert_eq!(report["context_id"], "crypto-context-wrong-audience");
    assert_eq!(report["cryptographic_proof_verified"], true);
    assert!(report["rejected_checks"]
        .as_array()
        .ok_or("rejected_checks missing")?
        .iter()
        .any(|check| check["code"] == "disclosure_context_audience_mismatch"));
    assert_eq!(
        report["disclosed_fields"],
        serde_json::json!(["capability_id", "id", "tool_name"])
    );

    let proof_response = router
        .oneshot(
            Request::builder()
                .uri(
                    "/proof-room-fixtures/crypto-context-wrong-audience/selective-disclosure-proof.json",
                )
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(proof_response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_trust_market_fixture_verifier_report(
) -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/trust-market-context/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-trust-market-valid");
    assert_eq!(
        report["trust_market_sections"]["risk_comptroller_report_ref"],
        "risk-comptroller-market-valid"
    );
    assert_eq!(
        report["trust_market_sections"]["selected_provider_subject"],
        "did:chio:provider-alpha"
    );
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.trust_market.provider_selection_bound"));
    Ok(())
}

#[test]
fn source_trust_market_report_ignores_unrelated_family_graph_nodes() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/trust-market/valid-marketplace-context");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let unrelated_bytes = fs::read(
        root.join("fixtures/proof-room/commerce-payments/offline-psp-valid/order-context.json"),
    )?;
    fs::write(
        work.path().join("commerce-order-context.json"),
        &unrelated_bytes,
    )?;

    let evidence_graph_path = work.path().join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
        .push(serde_json::json!({
            "id": "commerce-order-context-unrelated",
            "schema": "chio.commerce.order-context.v1",
            "path": "commerce-order-context.json",
            "sha256": sha256_hex(&unrelated_bytes),
            "role": "commerce-order-context"
        }));
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;

    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;
    let passport_path = work.path().join("transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    fs::write(&passport_path, json_bytes(&passport)?)?;

    let report = verify_transaction_passport_family_report(work.path(), &passport_path)?;

    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.trust_market.provider_selection_bound"));
    Ok(())
}

#[test]
fn source_verifier_accepts_single_family_cli_report_without_wrapper() -> Result<(), Box<dyn Error>>
{
    let root = repo_root()?;
    let fixture = root.join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let passport_path = fixture.join("transaction-passport.json");
    let expected_report = verify_transaction_passport_family_report(&fixture, &passport_path)?;
    let commerce_report = expected_report["family_reports"]
        .as_array()
        .ok_or("family_reports missing")?
        .first()
        .ok_or("commerce report missing")?
        .clone();
    let transaction_passport_artifact = VerifiedManifestArtifact {
        bytes: fs::read(&passport_path)?,
        path: passport_path,
    };

    verify_source_verifier_report(
        &fixture,
        &transaction_passport_artifact,
        &commerce_report,
        true,
    )
    .map_err(|error| format!("single-family source report rejected: {error}"))?;
    Ok(())
}

#[test]
fn source_family_verifier_rejects_tampered_claim_set_artifact() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root
        .join("fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let claim_set_path = work.path().join("roots/claim-set.json");
    let mut claim_set: serde_json::Value = serde_json::from_slice(&fs::read(&claim_set_path)?)?;
    claim_set["id"] = serde_json::Value::String("claim-set-tampered".to_string());
    fs::write(&claim_set_path, json_bytes(&claim_set)?)?;

    let passport_path = work.path().join("roots/transaction-passport.json");
    let error = verify_transaction_passport_family_report(work.path(), &passport_path)
        .err()
        .ok_or("tampered claim-set artifact unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("evidence graph artifact digest mismatch for claim-set.json"),
        "{error}"
    );
    Ok(())
}

#[test]
fn source_family_verifier_rejects_claim_set_required_claim_not_verified(
) -> Result<(), Box<dyn Error>> {
    configure_proof_room_fixture_trust();
    let root = repo_root()?;
    let source = root
        .join("fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let claim_set_path = work.path().join("roots/claim-set.json");
    let mut claim_set: serde_json::Value = serde_json::from_slice(&fs::read(&claim_set_path)?)?;
    let claims = claim_set["claims"]
        .as_array_mut()
        .ok_or("claim set claims missing")?;
    let claim = claims
        .iter_mut()
        .find(|claim| {
            claim.get("claim_id").and_then(serde_json::Value::as_str)
                == Some("claim.commerce.order_replay_consistent")
        })
        .ok_or("commerce replay claim missing")?;
    claim["status"] = serde_json::Value::String("omitted".to_string());
    fs::write(&claim_set_path, json_bytes(&claim_set)?)?;

    let claim_set_sha256 = sha256_file(&claim_set_path)?;
    update_evidence_graph_node_hash(work.path(), "claim-set.json", &claim_set_sha256)?;
    refresh_source_roots_and_manifest(work.path(), Some(("claim-set.json", claim_set_sha256)))?;

    let passport_path = work.path().join("roots/transaction-passport.json");
    let error = verify_transaction_passport_family_report(work.path(), &passport_path)
        .err()
        .ok_or("claim set with omitted required claim unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("claim set required claim was not verified"),
        "{error}"
    );
    Ok(())
}

#[test]
fn source_standalone_verifier_can_skip_passport_signature_check() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/minimal-passport/valid");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let passport_path = work.path().join("transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["signature"] = serde_json::Value::String("00".repeat(64));
    fs::write(
        &passport_path,
        [serde_json::to_vec_pretty(&passport)?.as_slice(), b"\n"].concat(),
    )?;

    let error = verify_transaction_passport_file_with_options(work.path(), &passport_path, true)
        .err()
        .ok_or("tampered signature unexpectedly verified")?;
    assert!(
        error.contains("transaction passport signature invalid"),
        "{error}"
    );

    let report = verify_transaction_passport_file_with_options(work.path(), &passport_path, false)?;

    assert_eq!(report["verdict"], "verified");

    let receipt_path = work.path().join("kernel-receipt.json");
    let mut receipt: serde_json::Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
    receipt["receipt_id"] = serde_json::Value::String("receipt-minimal-tampered".to_string());
    fs::write(
        &receipt_path,
        [serde_json::to_vec_pretty(&receipt)?.as_slice(), b"\n"].concat(),
    )?;

    let error = verify_transaction_passport_file_with_options(work.path(), &passport_path, false)
        .err()
        .ok_or("tampered governed-action artifact unexpectedly verified")?;
    assert!(
        error.contains("evidence graph artifact digest mismatch")
            && error.contains("kernel-receipt.json"),
        "{error}"
    );
    Ok(())
}

#[test]
fn source_family_required_claims_accept_verified_transaction_root_claims(
) -> Result<(), Box<dyn Error>> {
    let report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "verdict": "verified",
        "verified_claims": ["claim.commerce.order_replay_consistent"]
    });
    let required_claims = vec![
        "claim.transaction.passport_root_verified".to_string(),
        "claim.commerce.order_replay_consistent".to_string(),
    ];

    ensure_source_policy_required_claims_verified(&required_claims, &report)
        .map_err(|error| format!("verified transaction root claim rejected: {error}"))?;
    Ok(())
}

#[test]
fn source_agent_web_receipt_scope_uses_schema_not_fixture_filename() {
    let node = serde_json::json!({
        "id": "receipt-webhook-allow",
        "schema": "chio.receipt.v1",
        "path": "receipts/webhook-allow.json",
        "sha256": "4b53ccf5a08beb7e3331e90d6f782b6b2dc77ba29d1324481802ade3c775fba4",
        "role": "receipt"
    });

    assert!(is_agent_web_evidence_graph_node(&node));
}

#[tokio::test]
async fn quickstart_router_serves_enterprise_fixture_verifier_report() -> Result<(), Box<dyn Error>>
{
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/enterprise-autonomous-commerce/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-enterprise-valid");
    assert_eq!(
        report["risk_comptroller_report_ref"],
        "risk-comptroller-enterprise-valid"
    );
    assert_eq!(
        report["enterprise_sections"]["data_governance_report_ref"],
        "data-governance-enterprise-valid"
    );
    assert_eq!(
        report["enterprise_sections"]["control_evidence_map_ref"],
        "control-map-enterprise-valid"
    );
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.enterprise.control_map_bound"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_enterprise_risk_only_fixture_verifier_report(
) -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/enterprise-risk-only-comptroller/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-enterprise-valid");
    assert_eq!(
        report["risk_comptroller_report_ref"],
        "risk-comptroller-enterprise-valid"
    );
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.risk.comptroller_report_bound"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_standalone_risk_fixture_verifier_report(
) -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/risk-standalone-comptroller/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-enterprise-valid");
    assert_eq!(
        report["risk_comptroller_report_ref"],
        "risk-comptroller-enterprise-valid"
    );
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.risk.comptroller_report_bound"));
    Ok(())
}

#[test]
fn source_standalone_risk_rejects_tampered_supporting_evidence() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/enterprise-export/standalone-risk-comptroller");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let report_path = work.path().join("data-governance-report.json");
    let mut report: serde_json::Value = serde_json::from_slice(&fs::read(&report_path)?)?;
    report["observed_region"] = serde_json::json!("EU");
    fs::write(&report_path, json_bytes(&report)?)?;

    let passport_path = work.path().join("transaction-passport.json");
    let error = verify_transaction_passport_family_report(work.path(), &passport_path)
        .err()
        .ok_or("tampered standalone risk evidence unexpectedly verified")?;

    assert!(error
        .to_string()
        .contains("risk facility lifecycle evidence missing"));
    Ok(())
}

#[test]
fn source_standalone_risk_rejects_untrusted_comptroller_signer() -> Result<(), Box<dyn Error>> {
    configure_proof_room_fixture_trust();
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/enterprise-export/standalone-risk-comptroller");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let passport_path = work.path().join("transaction-passport.json");
    let context = source_verifier_context_with_options(work.path(), &passport_path, true)?;
    let untrusted_keys = vec![PublicKey::from_hex(
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    )?];
    let result = verify_source_standalone_risk_report_with_keys(
        &context,
        &["claim.risk.comptroller_report_bound".to_string()],
        &untrusted_keys,
    );
    let error = result
        .err()
        .ok_or("untrusted standalone risk signer unexpectedly verified")?;

    assert!(error
        .to_string()
        .contains("risk comptroller report signer untrusted"));
    Ok(())
}

#[test]
fn merge_source_family_reports_rejects_ok_but_unverified_family_report(
) -> Result<(), Box<dyn Error>> {
    let context = runtime_regeneration_context(false)?;
    // An Ok (non-error) family report whose own verdict is not "verified"
    // must downgrade the merged report; the merge must not hardcode verified.
    let rejected_family_report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": "verifier-report-rejected-family",
        "verdict": "failed",
        "accepted": false,
        "state": "failed",
        "verified_claims": []
    });

    let merged = merge_source_family_verifier_reports(&context, vec![rejected_family_report])?;

    assert_ne!(
        merged.get("verdict").and_then(serde_json::Value::as_str),
        Some("verified"),
        "merge must not report verified when a family report is not verified"
    );
    assert_eq!(
        merged.get("accepted").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_ne!(
        merged.get("state").and_then(serde_json::Value::as_str),
        Some("verified")
    );
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_agent_web_fixture_verifier_report() -> Result<(), Box<dyn Error>>
{
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/agent-web-interop/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        report["schema"],
        "chio.agent-web.interop-verifier-report.v1"
    );
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-agent-web-valid");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.agent_web.sidecar_not_native_authority"));
    assert!(report["projections"]
        .as_array()
        .ok_or("projections missing")?
        .iter()
        .any(|projection| projection["source_protocol"] == "mcp"));
    assert!(report["unsupported_claims"]
        .as_array()
        .ok_or("unsupported_claims missing")?
        .iter()
        .any(|claim| claim == "claim.external.mcp_tool_call_is_chio_authority"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_explains_negative_fixture_verifier_failure() -> Result<(), Box<dyn Error>>
{
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_repo_fixture_root(bundle, ui.path().to_path_buf())?;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/agent-web-external-digest-mismatch/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "failed");
    assert_eq!(report["passport_id"], "passport-agent-web-valid");
    assert_eq!(report["failure_code"], "proof-room.fixture.verify-failed");
    assert!(report["error"]
        .as_str()
        .ok_or("error missing")?
        .contains("external subject digest mismatch"));
    Ok(())
}

#[test]
fn rejects_negative_case_expected_failure_mismatch() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;
    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["negative_cases"][0]["expected_failure_code"] =
        serde_json::Value::String("expected failure that does not occur".to_string());
    fs::write(
        &manifest_path,
        [serde_json::to_vec_pretty(&manifest)?.as_slice(), b"\n"].concat(),
    )?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.negative-case.failure-mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_verifier_report_that_does_not_match_passport() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let verifier_report_path = work.path().join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["passport_id"] =
        serde_json::Value::String("passport-minimal-drifted".to_string());
    let verifier_report_bytes = json_bytes(&verifier_report)?;
    fs::write(&verifier_report_path, &verifier_report_bytes)?;
    let verifier_report_sha256 = super::sha256_hex(&verifier_report_bytes);

    let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    let ui_report_bytes = json_bytes(&ui_report)?;
    fs::write(&ui_report_path, &ui_report_bytes)?;
    let ui_report_sha256 = super::sha256_hex(&ui_report_bytes);

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error.to_string().contains("proof-room.report.mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_disclosure_crypto_context_claim_without_bbs_material() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join(
        "fixtures/proof-room/public-stages/disclosure-and-agent-web-envelope/proof-room-bundle",
    );
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(work.path().join("manifest.json"))?)?;
    let manifest_claims = manifest["claims"]
        .as_array()
        .ok_or("manifest claims missing")?;
    assert!(manifest_claims
        .iter()
        .any(|claim| { claim["claim_id"] == "claim.disclosure.crypto_context_bound" }));

    let top_level_graph_path = work.path().join("evidence-graph.json");
    remove_bbs_material_graph_nodes(&top_level_graph_path)?;
    let top_level_graph_sha256 = sha256_file(&top_level_graph_path)?;
    remove_bbs_material_graph_nodes(&work.path().join("roots/evidence-graph.json"))?;
    refresh_source_roots_and_manifest(
        work.path(),
        Some(("evidence-graph.json", top_level_graph_sha256)),
    )?;

    let evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(work.path().join("roots/evidence-graph.json"))?)?;
    let nodes = evidence_graph["nodes"]
        .as_array()
        .ok_or("evidence graph nodes missing")?;
    assert!(!nodes
        .iter()
        .any(|node| { node["role"] == "selective-disclosure-proof" }));

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or(
            "bundle with crypto context claim but no BBS proof material unexpectedly verified",
        )?;

    assert!(
        error.to_string().contains("missing BBS proof material"),
        "{error}"
    );
    Ok(())
}

fn remove_bbs_material_graph_nodes(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
        .retain(|node| {
            let role = node.get("role").and_then(serde_json::Value::as_str);
            !matches!(
                role,
                Some("crypto-verification-context" | "selective-disclosure-proof")
            )
        });
    fs::write(path, json_bytes(&evidence_graph)?)?;
    Ok(())
}

#[test]
fn rejects_source_report_for_non_transaction_required_claim() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    add_required_claim_to_verifier_policy(work.path(), "claim.runtime.execution_lease_valid")?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("standalone transaction verifier cannot satisfy required claim"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_source_report_for_misspelled_required_claim_prefix() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root
        .join("fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    add_required_claim_to_verifier_policy(work.path(), "claim.commerc.order_replay_consistent")?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("unsupported required proof claim: claim.commerc.order_replay_consistent"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_source_report_for_unhandled_market_required_claim() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root
        .join("fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    add_required_claim_to_verifier_policy(work.path(), "claim.market.not_routed")?;
    let claim_set_path = work.path().join("roots/claim-set.json");
    let mut claim_set: serde_json::Value = serde_json::from_slice(&fs::read(&claim_set_path)?)?;
    claim_set["claims"]
        .as_array_mut()
        .ok_or("claim set claims missing")?
        .push(serde_json::json!({
            "claim_id": "claim.market.not_routed",
            "status": "verified",
            "verifier_module": "chio proof verify",
            "evidence_refs": ["transaction-passport.json"],
            "required_evidence": ["transaction-passport.json"]
        }));
    fs::write(&claim_set_path, json_bytes(&claim_set)?)?;
    let claim_set_sha256 = sha256_file(&claim_set_path)?;
    update_evidence_graph_node_hash(work.path(), "claim-set.json", &claim_set_sha256)?;
    refresh_source_roots_and_manifest(work.path(), Some(("claim-set.json", claim_set_sha256)))?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("required proof claim not verified: claim.market.not_routed"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_evidence_graph_that_transaction_verifier_rejects() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let evidence_graph_path = work.path().join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    let allow_receipt_node_id = evidence_graph["nodes"]
        .as_array()
        .ok_or("evidence graph nodes missing")?
        .iter()
        .find(|node| {
            node.get("path").and_then(serde_json::Value::as_str)
                == Some("artifacts/receipts/allow-receipt.json")
        })
        .and_then(|node| node.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or("allow receipt graph node id missing")?
        .to_string();
    evidence_graph["edges"]
        .as_array_mut()
        .ok_or("evidence graph edges missing")?
        .push(serde_json::json!({
            "from": allow_receipt_node_id,
            "to": "missing-evidence-node",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    let evidence_graph_bytes = json_bytes(&evidence_graph)?;
    fs::write(&evidence_graph_path, &evidence_graph_bytes)?;
    let evidence_graph_sha256 = super::sha256_hex(&evidence_graph_bytes);

    let passport_path = work.path().join("roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    let passport_bytes = json_bytes(&passport)?;
    fs::write(&passport_path, &passport_bytes)?;
    let passport_sha256 = super::sha256_hex(&passport_bytes);

    let verifier_report_path = work.path().join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&verifier_report_path)?)?;
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    let verifier_report_bytes = json_bytes(&verifier_report)?;
    fs::write(&verifier_report_path, &verifier_report_bytes)?;
    let verifier_report_sha256 = super::sha256_hex(&verifier_report_bytes);

    let ui_report_path = work.path().join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value = serde_json::from_slice(&fs::read(&ui_report_path)?)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    let ui_report_bytes = json_bytes(&ui_report)?;
    fs::write(&ui_report_path, &ui_report_bytes)?;
    let ui_report_sha256 = super::sha256_hex(&ui_report_bytes);

    let manifest_path = work.path().join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .ok_or("manifest artifacts missing")?
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            _ => {}
        }
    }
    fs::write(&manifest_path, json_bytes(&manifest)?)?;
    refresh_bundle_signature(work.path())?;

    let error = verify_proof_room_bundle(&manifest_path)
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error.to_string().contains("proof-room.report.mismatch")
            || error
                .to_string()
                .contains("unknown evidence graph edge target"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_authority_evidence_missing_from_graph() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;
    remove_graph_node_and_rehash(work.path(), "artifacts/authority/capability-proof.json")?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.evidence-graph.authority-node-missing"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_authority_guard_report_without_capability_binding() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;
    remove_guard_report_capability_binding_and_rehash(work.path())?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error.to_string().contains(
            "proof-room.authority-evidence.field-missing: artifacts/authority/guard-report.json capability_id"
        ),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_authority_guard_report_with_unexpected_field() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    copy_dir_all(&source, work.path())?;

    let guard_report_path = work.path().join("artifacts/authority/guard-report.json");
    let mut guard_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&guard_report_path)?)?;
    guard_report["ambient_authority"] = serde_json::Value::Bool(true);
    fs::write(&guard_report_path, json_bytes(&guard_report)?)?;
    let guard_report_sha256 = sha256_file(&guard_report_path)?;

    let evidence_graph_path = work.path().join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_graph_path)?)?;
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("evidence graph nodes missing")?
    {
        if node.get("path").and_then(serde_json::Value::as_str)
            == Some("artifacts/authority/guard-report.json")
        {
            node["sha256"] = serde_json::Value::String(guard_report_sha256.clone());
        }
    }
    fs::write(&evidence_graph_path, json_bytes(&evidence_graph)?)?;
    refresh_source_roots_and_manifest(
        work.path(),
        Some(("artifacts/authority/guard-report.json", guard_report_sha256)),
    )?;

    let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
        .err()
        .ok_or("mutated proof room bundle unexpectedly verified")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.schema-violation: authority_evidence"),
        "{error}"
    );
    Ok(())
}

#[test]
fn rejects_first_run_public_artifacts_with_unexpected_fields() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");

    for (artifact_path, expected_error) in [
        (
            "artifacts/release/command-log.json",
            "proof-room.schema-violation: artifact",
        ),
        (
            "roots/request-digest.json",
            "proof-room.schema-violation: artifact",
        ),
        (
            "roots/response-digest.json",
            "proof-room.schema-violation: artifact",
        ),
    ] {
        let work = tempfile::tempdir()?;
        copy_dir_all(&source, work.path())?;
        add_unexpected_field_to_bundle_artifact_and_rehash(work.path(), artifact_path)?;

        let error = verify_proof_room_bundle(&work.path().join("manifest.json"))
            .err()
            .ok_or("mutated proof room bundle unexpectedly verified")?;

        assert!(
            error.to_string().contains(expected_error),
            "{artifact_path}: {error}"
        );
    }
    Ok(())
}
