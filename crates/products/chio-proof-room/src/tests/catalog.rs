use super::support::*;
use super::*;

#[test]
fn proof_room_router_reports_invalid_manifest_serving_paths() -> Result<(), Box<dyn Error>> {
    let bundle = tempfile::tempdir()?;
    fs::write(
        bundle.path().join("manifest.json"),
        br#"{"schema":"chio.proof-room.bundle.v1","artifacts":[{"path":"../secret.json"}]}"#,
    )?;
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;

    let error = build_proof_room_router(bundle.path().to_path_buf(), ui.path().to_path_buf())
        .err()
        .ok_or("invalid manifest serving path unexpectedly built a router")?;

    assert!(
        error
            .to_string()
            .contains("proof-room.serve member path ../secret.json is unsafe"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn proof_room_router_root_opens_proof_room_view() -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router(bundle, ui.path().to_path_buf());

    let response = router
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .ok_or("redirect location missing")?;
    assert_eq!(location, "/proof-room?view=proof-room");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room?view=proof-room")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.contains("Proof Room"));
    Ok(())
}

#[tokio::test]
async fn proof_room_router_serves_dashboard_assets_referenced_by_index(
) -> Result<(), Box<dyn Error>> {
    let bundle = tempfile::tempdir()?;
    let ui = tempfile::tempdir()?;
    let assets = ui.path().join("assets");
    fs::create_dir(&assets)?;
    fs::write(
        ui.path().join("index.html"),
        r#"<!doctype html><script type="module" src="/assets/proof-room.js"></script>"#,
    )?;
    fs::write(
        assets.join("proof-room.js"),
        "window.__proofRoomAssetLoaded = true;",
    )?;
    let router = proof_room_router(bundle.path().to_path_buf(), ui.path().to_path_buf());

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proof-room?view=proof-room")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.contains("/assets/proof-room.js"));

    let response = router
        .oneshot(
            Request::builder()
                .uri("/assets/proof-room.js")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.contains("window.__proofRoomAssetLoaded = true;"));
    Ok(())
}

#[tokio::test]
async fn proof_room_router_uses_ui_fallback_for_unmanifested_root_paths(
) -> Result<(), Box<dyn Error>> {
    let bundle = tempfile::tempdir()?;
    fs::write(
        bundle.path().join("kernel-receipt.json"),
        r#"{"schema":"chio.receipt.v1"}"#,
    )?;
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room shell</main>",
    )?;
    let router = proof_room_router(bundle.path().to_path_buf(), ui.path().to_path_buf());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/kernel-receipt.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.contains("Proof Room shell"));
    assert!(!body.contains("\"schema\":\"chio.receipt.v1\""));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_fixture_catalog() -> Result<(), Box<dyn Error>> {
    configure_proof_room_fixture_trust();
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
                .uri("/proof-room-fixture-catalog.json")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let catalog: serde_json::Value = serde_json::from_slice(&body)?;

    assert_eq!(catalog["schema"], "chio.proof-room.fixture-catalog.v1");
    super::validate_proof_room_schema(
        &catalog,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../spec/schemas/chio-proof-room/v1/fixture-catalog.schema.json"
        )),
        "proof-room fixture catalog",
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    assert_eq!(
        catalog["fixtures"][0]["fixture_id"],
        "single-call-authority"
    );
    assert_eq!(
        catalog["fixtures"][0]["bundle_id"],
        "proof-room-single-call-authority"
    );
    assert_eq!(
        catalog["fixtures"][0]["negative_cases"][0]["observed_failure_code"],
        "proof-room.negative.verifier-policy-digest-mismatch"
    );
    let negative_case_ids = catalog["fixtures"][0]["negative_cases"]
        .as_array()
        .ok_or("negative cases missing")?
        .iter()
        .filter_map(|negative_case| negative_case.get("id").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();
    assert!(negative_case_ids.contains(&"missing-denial-receipt"));
    assert!(negative_case_ids.contains(&"missing-receipt-graph-node"));
    let available_fixtures = catalog["available_fixtures"]
        .as_array()
        .ok_or("available fixtures missing")?;
    let available_fixture_ids = available_fixtures
        .iter()
        .filter_map(|fixture| fixture.get("id").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();
    for public_stage_id in [
        "single-call-authority",
        "commerce-transaction-passport",
        "recursive-runtime-swarm",
        "disclosure-and-agent-web-envelope",
    ] {
        assert!(
            available_fixture_ids
                .iter()
                .any(|id| id == &public_stage_id),
            "served fixture catalog missing public stage fixture: {public_stage_id}"
        );
    }
    for runtime_assurance_id in [
        "runtime-attack-simulation-confused-deputy-route-metadata",
        "runtime-attack-simulation-replayed-continuation-token",
        "runtime-attack-simulation-stale-revocation-epoch",
        "runtime-attack-simulation-policy-hot-reload-widening",
        "runtime-attack-simulation-advisory-evidence-laundering",
        "runtime-attack-simulation-external-payment-success-laundering",
        "runtime-attack-simulation-route-plan-registry-downgrade",
        "runtime-attack-simulation-tool-server-bypass-without-kernel-allow",
        "runtime-attack-simulation-missing-denial-receipt",
        "runtime-attack-simulation-sandbox-profile-mismatch",
        "runtime-chaos-revocation-oracle-unavailable",
        "runtime-chaos-receipt-log-unavailable",
        "runtime-chaos-policy-reload-during-dispatch",
        "runtime-chaos-duplicate-nonce-race",
        "runtime-chaos-tool-restart-lost-lease-cache",
        "runtime-chaos-registry-split-brain",
        "runtime-chaos-clock-skew-expiry-bypass",
        "runtime-chaos-sandbox-profile-drift",
    ] {
        let fixture = available_fixtures
            .iter()
            .find(|fixture| fixture["id"] == runtime_assurance_id)
            .ok_or_else(|| format!("runtime assurance fixture missing: {runtime_assurance_id}"))?;
        assert_eq!(
            fixture["verifier_report"]["status"], 200,
            "{runtime_assurance_id}: {}",
            fixture["verifier_report"]
        );
        assert_eq!(
            fixture["verifier_report"]["verdict"], "verified",
            "{runtime_assurance_id}: {}",
            fixture["verifier_report"]
        );
    }
    let commerce_stage = available_fixtures
        .iter()
        .find(|fixture| fixture["id"] == "commerce-transaction-passport")
        .ok_or("commerce public stage fixture missing")?;
    let commerce_stage_negative_cases = commerce_stage["negative_cases"]
        .as_array()
        .ok_or("commerce public stage negative cases missing")?;
    assert!(
        commerce_stage_negative_cases.iter().any(|negative_case| {
            negative_case["id"] == "commerce-payment-wrong-merchant"
                && negative_case["path"]
                    == "proof-room-bundle/negatives/catalog/commerce-payment-wrong-merchant/transaction-passport.json"
        }),
        "commerce public stage should expose manifest negative cases"
    );
    for fixture in available_fixtures {
        assert!(
            fixture.get("verifier_report").is_some(),
            "available fixture should expose an inspectable verifier report: {}",
            fixture["id"]
        );
    }
    let minimal_fixture = available_fixtures
        .iter()
        .find(|fixture| fixture["id"] == "minimal-passport-valid")
        .ok_or("minimal passport fixture missing")?;
    assert_eq!(minimal_fixture["verifier_report"]["status"], 200);
    assert_eq!(minimal_fixture["verifier_report"]["verdict"], "verified");
    let commerce_fixture = available_fixtures
        .iter()
        .find(|fixture| fixture["id"] == "commerce-offline-psp")
        .ok_or("commerce fixture missing")?;
    let commerce_negative_cases = commerce_fixture["negative_cases"]
        .as_array()
        .ok_or("commerce negative cases missing")?;
    let commerce_wrong_merchant = commerce_negative_cases
        .iter()
        .find(|negative_case| negative_case["id"] == "commerce-payment-wrong-merchant")
        .ok_or("commerce wrong merchant negative case missing")?;
    assert_eq!(commerce_wrong_merchant["path"], "transaction-passport.json");
    let commerce_wrong_merchant_asset = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/proof-room-fixtures/{}/{}",
                    commerce_wrong_merchant["id"]
                        .as_str()
                        .ok_or("commerce wrong merchant id missing")?,
                    commerce_wrong_merchant["path"]
                        .as_str()
                        .ok_or("commerce wrong merchant path missing")?
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(commerce_wrong_merchant_asset.status(), StatusCode::OK);
    assert!(commerce_wrong_merchant["observed_failure_code"]
        .as_str()
        .ok_or("commerce wrong merchant observed failure missing")?
        .contains("proof-room.negative.payment-merchant-mismatch"));
    let agent_web_negative = available_fixtures
        .iter()
        .find(|fixture| fixture["id"] == "agent-web-external-digest-mismatch")
        .ok_or("agent web negative fixture missing")?;
    assert_eq!(
        agent_web_negative["verifier_report"]["status"],
        StatusCode::UNPROCESSABLE_ENTITY.as_u16()
    );
    assert_eq!(agent_web_negative["verifier_report"]["verdict"], "failed");
    assert_eq!(
        agent_web_negative["verifier_report"]["failure_code"],
        "proof-room.fixture.verify-failed"
    );
    assert!(agent_web_negative["verifier_report"]["error"]
        .as_str()
        .ok_or("agent web negative error missing")?
        .contains("external subject digest mismatch"));
    Ok(())
}

#[tokio::test]
async fn proof_room_router_serves_configured_trusted_bundle_signers() -> Result<(), Box<dyn Error>>
{
    configure_proof_room_fixture_trust();
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
                .uri("/proof-room-trusted-bundle-signers.json")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let signers: serde_json::Value = serde_json::from_slice(&body)?;

    assert_eq!(
        signers["schema"],
        "chio.proof-room.trusted-bundle-signers.v1"
    );
    assert!(signers["keys"]
        .as_array()
        .is_some_and(|keys| !keys.is_empty()));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_without_fixture_root_lists_only_embedded_fixture_assets(
) -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router(bundle, ui.path().to_path_buf());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixture-catalog.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let catalog: serde_json::Value = serde_json::from_slice(&body)?;
    let available_fixture_ids = catalog["available_fixtures"]
        .as_array()
        .ok_or("available_fixtures missing")?
        .iter()
        .filter_map(|fixture| fixture.get("id").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();

    assert!(available_fixture_ids.contains(&"single-call-authority"));
    assert!(!available_fixture_ids.contains(&"minimal-passport-valid"));
    Ok(())
}

#[test]
fn fixture_catalog_rejects_load_report_path_escape() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let work = tempfile::tempdir()?;
    let bundle = work.path().join("bundle");
    copy_dir_all(&source, &bundle)?;
    fs::write(
        work.path().join("outside-load-report.json"),
        br#"{"verdict":"forged"}"#,
    )?;

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["proof_room_verifier_report_ref"]["path"] =
        serde_json::Value::String("../outside-load-report.json".to_string());
    fs::write(&manifest_path, json_bytes(&manifest)?)?;

    let error = super::build_proof_room_fixture_catalog(&bundle, None)
        .err()
        .ok_or("catalog unexpectedly read outside load report")?;

    assert!(error.contains("proof-room.artifact.unsafe-path"), "{error}");
    Ok(())
}

#[test]
fn available_fixture_catalog_marks_malformed_verifier_report_failed() {
    let report: super::ProofRoomAvailableFixtureReport =
        super::proof_room_available_fixture_report_from_contents(
            "/proof-room-fixtures/minimal-passport-valid/verifier-report.json".to_string(),
            b"{not valid json",
        );

    assert_eq!(report.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
    assert_eq!(report.verdict, "failed");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("proof-room.fixture.report-invalid")
    );
    assert!(report
        .error
        .as_deref()
        .is_some_and(|error: &str| error.contains("proof-room.fixture.report-invalid")));
}

#[test]
fn available_fixture_catalog_marks_missing_verdict_report_failed() {
    let report: super::ProofRoomAvailableFixtureReport =
        super::proof_room_available_fixture_report_from_contents(
            "/proof-room-fixtures/minimal-passport-valid/verifier-report.json".to_string(),
            br#"{"schema":"chio.transaction.verifier-report.v1"}"#,
        );

    assert_eq!(report.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
    assert_eq!(report.verdict, "failed");
    assert_eq!(
        report.failure_code.as_deref(),
        Some("proof-room.fixture.report-verdict-missing")
    );
    assert_eq!(
        report.error.as_deref(),
        Some("proof-room.fixture.report-verdict-missing")
    );
}

#[test]
fn fixture_catalog_schema_rejects_uninspectable_available_fixture() {
    let catalog = serde_json::json!({
        "schema": "chio.proof-room.fixture-catalog.v1",
        "fixtures": [],
        "available_fixtures": [
            {
                "id": "commerce-transaction-passport",
                "kind": "generated-proof-room",
                "path": "generated/commerce-transaction-passport",
                "description": "Generated Proof Room stage"
            }
        ]
    });

    let result = super::validate_proof_room_schema(
        &catalog,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../spec/schemas/chio-proof-room/v1/fixture-catalog.schema.json"
        )),
        "proof-room fixture catalog",
    );
    let error = match result {
        Err(error) => error,
        Ok(()) => panic!("available fixture without report should be rejected"),
    };

    assert!(error.contains("verifier_report"), "{error}");
}

#[tokio::test]
async fn quickstart_router_serves_available_fixture_asset() -> Result<(), Box<dyn Error>> {
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
                .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let passport: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(passport["schema"], "chio.transaction-passport.v1");
    assert_eq!(passport["id"], "passport-minimal-valid");
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_public_stage_bundle_readme() -> Result<(), Box<dyn Error>> {
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
                .uri(
                    "/proof-room-fixtures/commerce-transaction-passport/proof-room-bundle/README.md",
                )
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.contains("commerce-transaction-passport"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_public_stage_negative_sibling_assets(
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
                .uri(
                    "/proof-room-fixtures/commerce-transaction-passport/proof-room-bundle/negatives/catalog/commerce-payment-wrong-merchant/evidence-graph.json",
                )
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let graph: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(graph["schema"], "chio.transaction.evidence-graph.v1");
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_available_fixture_asset_from_configured_fixture_root(
) -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/minimal-passport/valid");
    let installed = tempfile::tempdir()?;
    let installed_fixture = installed.path().join("minimal-passport/valid");
    copy_dir_all(&source, &installed_fixture)?;
    let passport_path = installed_fixture.join("transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["id"] = serde_json::Value::String("passport-installed-root".to_string());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let bundle = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_fixture_root(
        bundle,
        ui.path().to_path_buf(),
        installed.path().to_path_buf(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let passport: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(passport["id"], "passport-installed-root");
    Ok(())
}

#[tokio::test]
async fn quickstart_router_uses_configured_fixture_root_catalog() -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/minimal-passport/valid");
    let installed = tempfile::tempdir()?;
    let installed_fixture = installed.path().join("minimal-passport/valid");
    copy_dir_all(&source, &installed_fixture)?;
    fs::write(
        installed.path().join("catalog.json"),
        br#"{
  "schema": "chio.proof-room.fixture-root-catalog.v1",
  "fixtures": [
{
  "id": "installed-only-minimal",
  "kind": "transaction-passport",
  "path": "fixtures/proof-room/minimal-passport/valid",
  "description": "Installed fixture root catalog entry"
}
  ]
}"#,
    )?;
    let bundle = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_fixture_root(
        bundle,
        ui.path().to_path_buf(),
        installed.path().to_path_buf(),
    );

    let catalog_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixture-catalog.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(catalog_response.status(), StatusCode::OK);
    let catalog_body = to_bytes(catalog_response.into_body(), 1024 * 1024).await?;
    let catalog: serde_json::Value = serde_json::from_slice(&catalog_body)?;
    let available_fixture_ids = catalog["available_fixtures"]
        .as_array()
        .ok_or("available_fixtures missing")?
        .iter()
        .filter_map(|fixture| fixture.get("id").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(available_fixture_ids, vec!["installed-only-minimal"]);

    let fixture_response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/installed-only-minimal/transaction-passport.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(fixture_response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn quickstart_router_rejects_unadvertised_installed_fixture_asset(
) -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/minimal-passport/valid");
    let installed = tempfile::tempdir()?;
    let installed_fixture = installed.path().join("minimal-passport/valid");
    copy_dir_all(&source, &installed_fixture)?;
    fs::write(
        installed_fixture.join("debug-notes.json"),
        br#"{"debug":"not part of the proof fixture"}"#,
    )?;
    let bundle = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_fixture_root(
        bundle,
        ui.path().to_path_buf(),
        installed.path().to_path_buf(),
    );

    let passport_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(passport_response.status(), StatusCode::OK);

    let verifier_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/minimal-passport-valid/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(verifier_response.status(), StatusCode::OK);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/minimal-passport-valid/debug-notes.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let error = String::from_utf8(body.to_vec())?;
    assert!(error.contains("proof-room.fixture.asset-not-found"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_requires_fixture_root_for_non_shipped_catalog_assets(
) -> Result<(), Box<dyn Error>> {
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router(bundle, ui.path().to_path_buf());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/minimal-passport-valid/transaction-passport.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let error = String::from_utf8(body.to_vec())?;
    assert!(error.contains("proof-room.fixture.asset-not-found"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_generates_verifier_report_from_configured_fixture_root(
) -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/workflow-preflight/valid-child-scope");
    let installed = tempfile::tempdir()?;
    let installed_fixture = installed
        .path()
        .join("workflow-preflight/valid-child-scope");
    copy_dir_all(&source, &installed_fixture)?;
    let plan_path = installed_fixture.join("preflight-plan.json");
    let mut plan: serde_json::Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
    plan["id"] = serde_json::Value::String("workflow-preflight-installed-root".to_string());
    fs::write(&plan_path, json_bytes(&plan)?)?;
    let bundle = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_fixture_root(
        bundle,
        ui.path().to_path_buf(),
        installed.path().to_path_buf(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/workflow-preflight-valid/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    eprintln!(
        "public-settlement fixture response: {status} {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.workflow.preflight-report.v1");
    assert_eq!(report["verdict"], "accepted");
    assert_eq!(report["plan_id"], "workflow-preflight-installed-root");
    Ok(())
}

#[tokio::test]
async fn quickstart_catalog_summarizes_configured_fixture_root_reports(
) -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room");
    let broader_plan =
        root.join("fixtures/proof-room/workflow-preflight/broader-child-scope/preflight-plan.json");
    let installed = tempfile::tempdir()?;
    let installed_fixture = installed
        .path()
        .join("workflow-preflight/valid-child-scope");
    copy_dir_all(&source, installed.path())?;
    fs::copy(broader_plan, installed_fixture.join("preflight-plan.json"))?;
    let bundle = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_fixture_root(
        bundle,
        ui.path().to_path_buf(),
        installed.path().to_path_buf(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixture-catalog.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let catalog: serde_json::Value = serde_json::from_slice(&body)?;
    let fixture = catalog["available_fixtures"]
        .as_array()
        .ok_or("available_fixtures missing")?
        .iter()
        .find(|fixture| fixture["id"] == "workflow-preflight-valid")
        .ok_or("workflow-preflight-valid fixture missing")?;
    assert_eq!(fixture["verifier_report"]["verdict"], "rejected");
    Ok(())
}

#[tokio::test]
async fn quickstart_catalog_fails_public_stage_with_corrupt_nested_bundle(
) -> Result<(), Box<dyn Error>> {
    let root = repo_root()?;
    let source = root.join("fixtures/proof-room/public-stages/commerce-transaction-passport");
    let installed = tempfile::tempdir()?;
    let installed_fixture = installed
        .path()
        .join("public-stages/commerce-transaction-passport");
    copy_dir_all(&source, &installed_fixture)?;
    fs::write(
        installed.path().join("catalog.json"),
        br#"{
  "schema": "chio.proof-room.fixture-root-catalog.v1",
  "fixtures": [
{
  "id": "commerce-transaction-passport",
  "kind": "proof-room",
  "path": "fixtures/proof-room/public-stages/commerce-transaction-passport",
  "description": "Installed public stage"
}
  ]
}"#,
    )?;
    let passport_path = installed_fixture.join("proof-room-bundle/roots/transaction-passport.json");
    let mut passport: serde_json::Value = serde_json::from_slice(&fs::read(&passport_path)?)?;
    passport["id"] = serde_json::Value::String("passport-corrupt-nested-bundle".to_string());
    fs::write(&passport_path, json_bytes(&passport)?)?;
    let bundle = root.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router_with_fixture_root(
        bundle,
        ui.path().to_path_buf(),
        installed.path().to_path_buf(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixture-catalog.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let catalog: serde_json::Value = serde_json::from_slice(&body)?;
    let fixture = catalog["available_fixtures"]
        .as_array()
        .ok_or("available_fixtures missing")?
        .iter()
        .find(|fixture| fixture["id"] == "commerce-transaction-passport")
        .ok_or("commerce-transaction-passport fixture missing")?;
    assert_eq!(fixture["verifier_report"]["verdict"], "failed");
    assert_eq!(
        fixture["verifier_report"]["failure_code"],
        "proof-room.fixture.verify-failed"
    );
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_available_fixture_verifier_report() -> Result<(), Box<dyn Error>>
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
                .uri("/proof-room-fixtures/minimal-passport-valid/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-minimal-valid");
    assert_eq!(report["evidence_graph_path"], "evidence-graph.json");
    assert_eq!(report["verifier_policy_path"], "verifier-policy.json");
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_workflow_preflight_fixture_report() -> Result<(), Box<dyn Error>>
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
                .uri("/proof-room-fixtures/workflow-preflight-valid/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.workflow.preflight-report.v1");
    assert_eq!(report["verdict"], "accepted");
    assert_eq!(report["evidence_class"], "planning");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.workflow.preflight_child_scope_bounded"));
    assert!(report["live_authority_claims"]
        .as_array()
        .ok_or("live_authority_claims missing")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_first_run_fixture_verifier_report() -> Result<(), Box<dyn Error>>
{
    let bundle =
        repo_root()?.join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");
    let ui = tempfile::tempdir()?;
    fs::write(
        ui.path().join("index.html"),
        "<!doctype html><main>Proof Room</main>",
    )?;
    let router = proof_room_router(bundle, ui.path().to_path_buf());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/proof-room-fixtures/single-call-authority/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-minimal-valid");
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_domain_fixture_verifier_report() -> Result<(), Box<dyn Error>> {
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
                .uri("/proof-room-fixtures/commerce-offline-psp/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.commerce.order-passport.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["order_id"], "order-commerce-001");
    assert_eq!(report["current_state"], "completed");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.commerce.order_replay_consistent"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_swarm_fixture_verifier_report() -> Result<(), Box<dyn Error>> {
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
                .uri("/proof-room-fixtures/recursive-runtime-swarm/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.transaction.verifier-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "passport-swarm-valid");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.swarm.task_graph_bound"));
    assert_eq!(
        report["runtime_proof_parity_report"]["schema"],
        "chio.runtime.proof-parity-report.v1"
    );
    assert_eq!(
        report["runtime_proof_parity_report"]["runId"],
        "runtime-loopback-1"
    );
    let family_report = report["family_reports"]
        .as_array()
        .ok_or("family_reports missing")?
        .iter()
        .find(|family_report| family_report["schema"] == "chio.swarm.authority-verifier-report.v1")
        .ok_or("swarm family report missing")?;
    assert_eq!(family_report["graphId"], "swarm-graph-proof-valid");
    assert_eq!(family_report["taskCount"], 4);
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_public_settlement_fixture_verifier_report(
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
                .uri("/proof-room-fixtures/public-settlement-offline-finality/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        report["schema"],
        "chio.public-settlement-verifier-report.v1"
    );
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["bundle_id"], "web3-settlement-proof-public-valid");
    assert_eq!(report["commerce_order_id"], "order-public-settlement-valid");
    assert_eq!(report["finality_decision"]["status"], "final");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.public_settlement.finality_verified"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_runtime_fixture_verifier_report() -> Result<(), Box<dyn Error>> {
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
                .uri("/proof-room-fixtures/runtime-side-effecting-call/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        report["schema"],
        "chio.transaction.runtime-security-report.v1"
    );
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["passport_id"], "runtime-passport-valid");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.runtime.execution_lease_valid"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_disclosure_lineage_fixture_verifier_report(
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
                .uri("/proof-room-fixtures/disclosure-lineage-ledger/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        report["schema"],
        "chio.disclosure.lineage-verifier-report.v1"
    );
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["capsule_id"], "disclosure-capsule-valid");
    assert_eq!(report["lineage_subgraph_ref"], "lineage-subgraph-valid");
    assert_eq!(report["leakage_ledger_ref"], "leakage-ledger-valid");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.disclosure.lineage_subgraph_bound"));
    Ok(())
}

#[tokio::test]
async fn quickstart_router_serves_crypto_context_fixture_verifier_report(
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
                .uri("/proof-room-fixtures/crypto-context-valid-bbs/verifier-report.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let report: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(report["schema"], "chio.disclosure.crypto-context-report.v1");
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["context_id"], "crypto-context-buyer-auditor");
    assert!(report["verified_claims"]
        .as_array()
        .ok_or("verified_claims missing")?
        .iter()
        .any(|claim| claim == "claim.disclosure.crypto_context_bound"));
    Ok(())
}
