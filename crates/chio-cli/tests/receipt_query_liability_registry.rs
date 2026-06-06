#![allow(clippy::expect_used, clippy::too_many_arguments, clippy::unwrap_used)]

mod support;

use support::receipt_query::*;

macro_rules! skip_when_loopback_denied {
    ($test_name:ident) => {
        if chio_test_support::loopback::skip_when_loopback_bind_denied(stringify!($test_name)) {
            return;
        }
    };
}

#[test]
fn test_liability_provider_registry_issue_list_and_resolve_surfaces() {
    skip_when_loopback_denied!(test_liability_provider_registry_issue_list_and_resolve_surfaces);
    let dir = unique_dir("chio-liability-provider-registry");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "liability-provider-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let provider_report = serde_json::json!({
        "schema": "chio.market.provider.v1",
        "providerId": "carrier-alpha",
        "displayName": "Carrier Alpha",
        "providerType": "admitted_carrier",
        "providerUrl": "https://carrier-alpha.example.com",
        "lifecycleState": "active",
        "supportBoundary": {
            "curatedRegistryOnly": true,
            "automaticTrustAdmission": false,
            "permissionlessFederationSupported": false,
            "boundCoverageSupported": false
        },
        "policies": [
            {
                "jurisdiction": "us-ny",
                "coverageClasses": ["tool_execution", "regulatory_response"],
                "supportedCurrencies": ["USD"],
                "requiredEvidence": ["credit_provider_risk_package", "credit_bond"],
                "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                "claimsSupported": true,
                "quoteTtlSeconds": 3600
            },
            {
                "jurisdiction": "eu-de",
                "coverageClasses": ["professional_liability"],
                "supportedCurrencies": ["EUR"],
                "requiredEvidence": ["credit_provider_risk_package", "runtime_attestation_appraisal"],
                "maxCoverageAmount": { "units": 40000, "currency": "EUR" },
                "claimsSupported": true,
                "quoteTtlSeconds": 7200
            }
        ],
        "provenance": {
            "configuredBy": "operator@example.com",
            "configuredAt": unix_now_secs(),
            "sourceRef": "liability-runbook",
            "changeReason": "initial curated provider admission"
        }
    });

    let issue_response = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({ "report": provider_report }))
        .send()
        .expect("issue liability provider");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let issued: SignedLiabilityProvider = issue_response
        .json()
        .expect("parse issued liability provider");
    assert!(issued
        .verify_signature()
        .expect("verify liability provider signature"));
    assert_eq!(issued.body.report.provider_id, "carrier-alpha");

    let list_response = client
        .get(format!("{base_url}/v1/reports/liability-providers"))
        .query(&[
            ("providerId", "carrier-alpha"),
            ("coverageClass", "tool_execution"),
            ("currency", "usd"),
            ("limit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list liability providers");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: LiabilityProviderListReport =
        list_response.json().expect("parse liability provider list");
    assert_eq!(list_report.summary.matching_providers, 1);
    assert_eq!(
        list_report.providers[0].provider.body.provider_record_id,
        issued.body.provider_record_id
    );

    let resolve_response = client
        .get(format!("{base_url}/v1/liability/providers/resolve"))
        .query(&[
            ("providerId", "carrier-alpha"),
            ("jurisdiction", "us-ny"),
            ("coverageClass", "tool_execution"),
            ("currency", "USD"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("resolve liability provider");
    assert_eq!(resolve_response.status(), reqwest::StatusCode::OK);
    let resolve_report: LiabilityProviderResolutionReport = resolve_response
        .json()
        .expect("parse liability provider resolution");
    assert_eq!(resolve_report.matched_policy.jurisdiction, "us-ny");
    assert!(resolve_report
        .matched_policy
        .supported_currencies
        .iter()
        .any(|currency| currency == "USD"));

    let unsupported_response = client
        .get(format!("{base_url}/v1/liability/providers/resolve"))
        .query(&[
            ("providerId", "carrier-alpha"),
            ("jurisdiction", "us-ny"),
            ("coverageClass", "tool_execution"),
            ("currency", "EUR"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("resolve unsupported liability provider");
    assert_eq!(unsupported_response.status(), reqwest::StatusCode::CONFLICT);
    let unsupported_body: serde_json::Value = unsupported_response
        .json()
        .expect("parse unsupported resolution body");
    assert!(unsupported_body["error"]
        .as_str()
        .expect("error message")
        .contains("does not support"));

    let provider_file = dir.join("provider-beta.json");
    std::fs::write(
        &provider_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "chio.market.provider.v1",
            "providerId": "carrier-beta",
            "displayName": "Carrier Beta",
            "providerType": "risk_pool",
            "providerUrl": "https://carrier-beta.example.com",
            "lifecycleState": "active",
            "supportBoundary": {
                "curatedRegistryOnly": true,
                "automaticTrustAdmission": false,
                "permissionlessFederationSupported": false,
                "boundCoverageSupported": false
            },
            "policies": [
                {
                    "jurisdiction": "us-ca",
                    "coverageClasses": ["financial_loss"],
                    "supportedCurrencies": ["USD"],
                    "requiredEvidence": ["credit_provider_risk_package", "authorization_review_pack"],
                    "maxCoverageAmount": { "units": 75000, "currency": "USD" },
                    "claimsSupported": true,
                    "quoteTtlSeconds": 1800
                }
            ],
            "provenance": {
                "configuredBy": "operator@example.com",
                "configuredAt": unix_now_secs(),
                "sourceRef": "liability-runbook",
                "changeReason": "local CLI provider admission"
            }
        }))
        .expect("serialize provider input"),
    )
    .expect("write provider input");

    let cli_issue_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-provider",
            "issue",
            "--input-file",
            provider_file.to_str().expect("provider file path"),
        ])
        .output()
        .expect("run liability provider issue CLI");
    assert!(
        cli_issue_output.status.success(),
        "liability provider issue CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_issue_output.stdout),
        String::from_utf8_lossy(&cli_issue_output.stderr)
    );
    let cli_issued: SignedLiabilityProvider =
        serde_json::from_slice(&cli_issue_output.stdout).expect("parse liability provider CLI");
    assert_eq!(cli_issued.body.report.provider_id, "carrier-beta");

    let cli_resolve_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "liability-provider",
            "resolve",
            "--provider-id",
            "carrier-beta",
            "--jurisdiction",
            "us-ca",
            "--coverage-class",
            "financial_loss",
            "--currency",
            "USD",
        ])
        .output()
        .expect("run liability provider resolve CLI");
    assert!(
        cli_resolve_output.status.success(),
        "liability provider resolve CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_resolve_output.stdout),
        String::from_utf8_lossy(&cli_resolve_output.stderr)
    );
    let cli_resolved: LiabilityProviderResolutionReport =
        serde_json::from_slice(&cli_resolve_output.stdout)
            .expect("parse liability provider resolve CLI");
    assert_eq!(
        cli_resolved.provider.body.report.provider_id,
        "carrier-beta"
    );
    assert_eq!(cli_resolved.matched_policy.jurisdiction, "us-ca");

    let _ = std::fs::remove_dir_all(&dir);
}
