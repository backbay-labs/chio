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
fn test_shared_evidence_reporting_surfaces() {
    skip_when_loopback_denied!(test_shared_evidence_reporting_surfaces);
    let dir = unique_dir("chio-shared-evidence-report");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let remote_issuer_kp = Keypair::generate();
    let remote_root_kp = Keypair::generate();
    let remote_delegate_kp = Keypair::generate();
    let local_issuer_kp = Keypair::generate();
    let local_root_kp = Keypair::generate();
    let local_leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let remote_root_hex = remote_root_kp.public_key().to_hex();
    let remote_delegate_hex = remote_delegate_kp.public_key().to_hex();
    let remote_issuer_hex = remote_issuer_kp.public_key().to_hex();
    let _local_root_hex = local_root_kp.public_key().to_hex();
    let local_leaf_hex = local_leaf_kp.public_key().to_hex();
    let local_issuer_hex = local_issuer_kp.public_key().to_hex();

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let local_root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-local-root".to_string(),
            issuer: local_issuer_kp.public_key(),
            subject: local_root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_500,
            expires_at: 20_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &local_issuer_kp,
    )
    .expect("sign local root capability");
    let local_child = make_delegated_capability_token(
        "cap-local-child",
        &local_leaf_kp,
        &local_root_kp,
        &local_root,
    );
    let remote_root = make_capability_token("cap-remote-root", &remote_root_kp, &remote_issuer_kp);
    let remote_delegate = make_delegated_capability_token(
        "cap-remote-delegate",
        &remote_delegate_kp,
        &remote_root_kp,
        &remote_root,
    );

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .import_federated_evidence_share(&FederatedEvidenceShareImport {
                share_id: "share-cross-org".to_string(),
                manifest_hash: "manifest-cross-org".to_string(),
                exported_at: 1_400,
                issuer: "org-remote".to_string(),
                partner: "org-local".to_string(),
                signer_public_key: remote_issuer_hex.clone(),
                require_proofs: true,
                query_json: r#"{"capabilityId":"cap-remote-root"}"#.to_string(),
                tool_receipts: vec![StoredToolReceipt {
                    seq: 1,
                    receipt: make_financial_receipt(
                        "rc-remote-1",
                        "cap-remote-delegate",
                        Some(&remote_delegate_hex),
                        &remote_issuer_hex,
                        "shell",
                        "bash",
                        Decision::Allow,
                        1_350,
                        300,
                        None,
                        &remote_root_hex,
                        1,
                    ),
                }],
                capability_lineage: vec![
                    signed_snapshot(&remote_root),
                    signed_snapshot(&remote_delegate),
                ],
            })
            .expect("import federated evidence share");
        store
            .record_capability_snapshot(&local_root, None)
            .expect("record local root lineage");
        store
            .record_capability_snapshot(&local_child, Some("cap-local-root"))
            .expect("record local child lineage");
        store
            .record_federated_lineage_bridge(
                "cap-local-root",
                "cap-remote-delegate",
                Some("share-cross-org"),
            )
            .expect("record remote lineage bridge");

        let seq = store
            .append_chio_receipt_returning_seq(&make_financial_receipt_signed_by(
                &checkpoint_kp,
                "rc-local-1",
                "cap-local-child",
                Some(&local_leaf_hex),
                &local_issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                1_700,
                450,
                None,
                &remote_root_hex,
                3,
            ))
            .expect("append shared-evidence receipt");
        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-local-2",
                "cap-local-child",
                Some(&local_leaf_hex),
                &local_issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "policy".to_string(),
                    guard: "kernel".to_string(),
                },
                1_701,
                0,
                Some(200),
                &remote_root_hex,
                3,
            ))
            .expect("append second shared-evidence receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        seed_budget_exposure(&budgets, "cap-local-child", 450);
    }

    let listen = reserve_listen_addr();
    let service_token = "shared-evidence-token";
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

    let operator_response = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("agentSubject", local_leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("budgetLimit", "10"),
            ("attributionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");
    assert_eq!(operator_response.status(), reqwest::StatusCode::OK);
    let operator_body: serde_json::Value = operator_response
        .json()
        .expect("parse operator report body");
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingShares"].as_u64(),
        Some(1)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingReferences"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingLocalReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["remoteLineageRecords"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["references"]
            .as_array()
            .expect("shared evidence references")
            .len(),
        2
    );

    let shared_response = client
        .get(format!("{base_url}/v1/federation/evidence-shares"))
        .query(&[("agentSubject", local_leaf_hex.as_str())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send shared evidence request");
    assert_eq!(shared_response.status(), reqwest::StatusCode::OK);
    let shared_body: serde_json::Value =
        shared_response.json().expect("parse shared evidence body");
    assert_eq!(shared_body["summary"]["matchingShares"].as_u64(), Some(1));
    assert_eq!(
        shared_body["summary"]["matchingReferences"].as_u64(),
        Some(2)
    );
    assert!(shared_body["references"]
        .as_array()
        .expect("references array")
        .iter()
        .all(|row| row["share"]["partner"].as_str() == Some("org-local")));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "evidence-share",
            "list",
            "--agent-subject",
            &local_leaf_hex,
            "--json",
        ])
        .output()
        .expect("run shared evidence CLI");
    assert!(
        cli_output.status.success(),
        "shared evidence CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_body: serde_json::Value =
        serde_json::from_slice(&cli_output.stdout).expect("parse shared evidence CLI json");
    assert_eq!(cli_body["summary"]["matchingShares"].as_u64(), Some(1));
    assert_eq!(cli_body["summary"]["matchingReferences"].as_u64(), Some(2));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_behavioral_feed_export_surfaces() {
    skip_when_loopback_denied!(test_behavioral_feed_export_surfaces);
    let dir = unique_dir("chio-behavioral-feed");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-risk-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_000,
            expires_at: 10_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer_kp,
    )
    .expect("sign root capability");
    let child = make_delegated_capability_token("cap-risk-child", &leaf_kp, &root_kp, &root);

    let rc_risk_2 = make_financial_receipt_with_settlement_status(
        "rc-risk-2",
        "cap-risk-child",
        "shell",
        "bash",
        5_001,
        200,
        SettlementStatus::Pending,
        Some("payment-risk-2"),
    );
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root lineage");
        store
            .record_capability_snapshot(&child, Some("cap-risk-root"))
            .expect("record child lineage");

        let seq = store
            .append_chio_receipt_returning_seq(&make_governed_financial_receipt_signed_by(
                &checkpoint_kp,
                "rc-risk-1",
                "cap-risk-child",
                &leaf_hex,
                &issuer_hex,
                "shell",
                "bash",
                5_000,
                750,
                &root_hex,
            ))
            .expect("append governed receipt");
        store
            .append_chio_receipt(&rc_risk_2)
            .expect("append pending receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        seed_budget_exposure(&budgets, "cap-risk-child", 950);
    }

    let listen = reserve_listen_addr();
    let service_token = "behavioral-feed-token";
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

    let response = client
        .get(format!("{base_url}/v1/reports/behavioral-feed"))
        .query(&[
            ("agentSubject", leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("receiptLimit", "5000"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send behavioral feed request");
    let response_status = response.status();
    let response_text = response.text().expect("read behavioral feed body");
    assert_eq!(
        response_status,
        reqwest::StatusCode::OK,
        "behavioral feed body: {response_text}"
    );
    let feed: SignedBehavioralFeed =
        serde_json::from_str(&response_text).expect("parse behavioral feed");
    assert!(feed
        .verify_signature()
        .expect("verify behavioral feed signature"));
    assert_eq!(feed.body.schema, "chio.behavioral-feed.v1");
    assert_eq!(feed.body.filters.receipt_limit, Some(200));
    assert_eq!(feed.body.privacy.matching_receipts, 2);
    assert_eq!(feed.body.decisions.allow_count, 2);
    assert_eq!(feed.body.governed_actions.governed_receipts, 1);
    assert_eq!(feed.body.governed_actions.approved_receipts, 1);
    assert_eq!(feed.body.settlements.pending_receipts, 1);
    assert_eq!(feed.body.settlements.settled_receipts, 1);
    assert_eq!(feed.body.receipts.len(), 2);
    assert_eq!(
        feed.body
            .reputation
            .as_ref()
            .expect("reputation summary")
            .subject_key,
        leaf_hex
    );
    let budget_authority_row = feed
        .body
        .receipts
        .iter()
        .find(|row| row.receipt_id == rc_risk_2.id)
        .expect("budget authority feed row");
    assert_eq!(
        budget_authority_row
            .budget_authority
            .as_ref()
            .expect("budget authority")
            .guarantee_level,
        "ha_quorum_commit"
    );
    assert_eq!(
        budget_authority_row
            .budget_authority
            .as_ref()
            .expect("budget authority")
            .hold_id,
        "budget-hold:rc-risk-2:capability:0"
    );

    // Sign the CLI export with the same authority the trust service uses so the
    // signer keys match below.
    let authority_seed_path = trust_service_authority_seed_path(&receipt_db_path);
    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-seed-file",
            authority_seed_path
                .to_str()
                .expect("authority seed file path"),
            "trust",
            "behavioral-feed",
            "export",
            "--agent-subject",
            &leaf_hex,
            "--tool-server",
            "shell",
            "--tool-name",
            "bash",
            "--receipt-limit",
            "5000",
        ])
        .output()
        .expect("run behavioral feed CLI");
    assert!(
        cli_output.status.success(),
        "behavioral feed CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_feed: SignedBehavioralFeed =
        serde_json::from_slice(&cli_output.stdout).expect("parse behavioral feed CLI json");
    assert!(cli_feed
        .verify_signature()
        .expect("verify behavioral feed CLI signature"));
    assert_eq!(cli_feed.body.schema, "chio.behavioral-feed.v1");
    assert_eq!(cli_feed.body.filters.receipt_limit, Some(200));
    assert_eq!(cli_feed.body.governed_actions.commerce_receipts, 1);
    assert_eq!(cli_feed.body.privacy.returned_receipts, 2);
    assert_eq!(cli_feed.signer_key, feed.signer_key);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_attestation_appraisal_export_surfaces() {
    skip_when_loopback_denied!(test_runtime_attestation_appraisal_export_surfaces);
    let dir = unique_dir("chio-runtime-appraisal");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let attestation_path = dir.join("runtime-attestation.json");
    let policy_path = dir.join("runtime-policy.yaml");
    let attestation = sample_google_runtime_attestation();
    std::fs::write(
        &attestation_path,
        serde_json::to_vec_pretty(&attestation).expect("serialize attestation"),
    )
    .expect("write attestation file");
    std::fs::write(
        &policy_path,
        r#"hushspec: "0.1.0"
name: runtime-appraisal
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
      verified:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 300
    trusted_verifiers:
      google_prod:
        schema: chio.runtime-attestation.google-confidential-vm.jwt.v1
        verifier: https://confidentialcomputing.googleapis.com
        verifier_family: google_attestation
        effective_tier: verified
        max_evidence_age_seconds: 120
        allowed_attestation_types: [confidential_vm]
        required_assertions:
          hardwareModel: GCP_AMD_SEV
          secureBoot: enabled
"#,
    )
    .expect("write runtime policy file");

    let listen = reserve_listen_addr();
    let service_token = "runtime-appraisal-token";
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

    let response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&RuntimeAttestationAppraisalRequest {
            runtime_attestation: attestation.clone(),
        })
        .send()
        .expect("send runtime appraisal request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedRuntimeAttestationAppraisalReport =
        response.json().expect("parse signed appraisal report");
    assert!(report
        .verify_signature()
        .expect("verify signed runtime appraisal"));
    assert_eq!(
        report.body.schema,
        "chio.runtime-attestation.appraisal-report.v1"
    );
    assert_eq!(
        report.body.appraisal.evidence.schema,
        "chio.runtime-attestation.google-confidential-vm.jwt.v1"
    );
    assert_eq!(
        report.body.appraisal.verifier_family,
        chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation
    );
    assert_eq!(
        report.body.appraisal.normalized_assertions["secureBoot"],
        serde_json::json!("enabled")
    );
    let artifact = report
        .body
        .appraisal
        .artifact
        .as_ref()
        .expect("appraisal export should carry nested artifact");
    assert_eq!(
        artifact.schema,
        "chio.runtime-attestation.appraisal-artifact.v1"
    );
    assert_eq!(artifact.verifier.adapter, "google_confidential_vm");
    assert_eq!(
        artifact.claims.normalized_assertions["secureBoot"],
        serde_json::json!("enabled")
    );
    assert!(artifact.claims.normalized_claims.iter().any(|claim| {
        claim.code == chio_core::appraisal::RuntimeAttestationNormalizedClaimCode::SecureBootState
            && claim.legacy_assertion_key == "secureBoot"
            && claim.provenance
                == chio_core::appraisal::RuntimeAttestationClaimProvenance::VendorClaims
            && claim.value == serde_json::json!("enabled")
    }));
    assert_eq!(
        artifact.policy.effective_tier,
        RuntimeAssuranceTier::Attested
    );
    assert_eq!(
        artifact.policy.reasons,
        vec![
            chio_core::appraisal::RuntimeAttestationAppraisalReason::from_code(
                chio_core::appraisal::RuntimeAttestationAppraisalReasonCode::EvidenceVerified
            )
        ]
    );
    assert!(!report.body.policy_outcome.trust_policy_configured);
    assert!(report.body.policy_outcome.accepted);
    assert_eq!(
        report.body.policy_outcome.effective_tier,
        RuntimeAssuranceTier::Attested
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "appraisal",
            "export",
            "--input",
            attestation_path.to_str().expect("attestation path"),
            "--policy-file",
            policy_path.to_str().expect("policy path"),
        ])
        .output()
        .expect("run runtime appraisal CLI");
    assert!(
        cli_output.status.success(),
        "runtime appraisal CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedRuntimeAttestationAppraisalReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse runtime appraisal CLI json");
    assert!(cli_report
        .verify_signature()
        .expect("verify runtime appraisal CLI signature"));
    assert!(cli_report.body.policy_outcome.trust_policy_configured);
    assert!(cli_report.body.policy_outcome.accepted);
    assert_eq!(
        cli_report.body.policy_outcome.effective_tier,
        RuntimeAssuranceTier::Verified
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_attestation_appraisal_result_import_export_surfaces() {
    skip_when_loopback_denied!(test_runtime_attestation_appraisal_result_import_export_surfaces);
    let dir = unique_dir("chio-runtime-appraisal-result");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let attestation_path = dir.join("runtime-attestation.json");
    let signed_result_path = dir.join("signed-appraisal-result.json");
    let runtime_policy_path = dir.join("runtime-policy.yaml");
    let import_policy_path = dir.join("import-policy.json");
    let rejecting_policy_path = dir.join("rejecting-import-policy.json");
    let attestation = sample_google_runtime_attestation();
    std::fs::write(
        &attestation_path,
        serde_json::to_vec_pretty(&attestation).expect("serialize attestation"),
    )
    .expect("write attestation file");
    std::fs::write(
        &runtime_policy_path,
        r#"hushspec: "0.1.0"
name: runtime-appraisal-result
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
      verified:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 300
    trusted_verifiers:
      google_prod:
        schema: chio.runtime-attestation.google-confidential-vm.jwt.v1
        verifier: https://confidentialcomputing.googleapis.com
        verifier_family: google_attestation
        effective_tier: verified
        max_evidence_age_seconds: 120
        allowed_attestation_types: [confidential_vm]
        required_assertions:
          hardwareModel: GCP_AMD_SEV
          secureBoot: enabled
"#,
    )
    .expect("write runtime policy file");

    let listen = reserve_listen_addr();
    let service_token = "runtime-appraisal-result-token";
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

    let response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal-result"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&RuntimeAttestationAppraisalResultExportRequest {
            issuer: "did:chio:test:remote-exporter".to_string(),
            runtime_attestation: attestation.clone(),
        })
        .send()
        .expect("send runtime appraisal result export request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let exported: SignedRuntimeAttestationAppraisalResult =
        response.json().expect("parse signed appraisal result");
    assert!(exported
        .verify_signature()
        .expect("verify signed appraisal result"));
    assert_eq!(
        exported.body.schema,
        "chio.runtime-attestation.appraisal-result.v1"
    );
    assert_eq!(exported.body.issuer, "did:chio:test:remote-exporter");
    assert_eq!(
        exported.body.subject.runtime_identity.as_deref(),
        Some("spiffe://chio.example/workloads/google")
    );
    std::fs::write(
        &signed_result_path,
        serde_json::to_vec_pretty(&exported).expect("serialize signed result"),
    )
    .expect("write signed result file");

    let import_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec!["did:chio:test:remote-exporter".to_string()],
        trusted_signer_keys: vec![exported.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: Some(RuntimeAssuranceTier::Basic),
        required_claims: std::iter::once((
            RuntimeAttestationNormalizedClaimCode::SecureBootState,
            "enabled".to_string(),
        ))
        .collect(),
    };
    std::fs::write(
        &import_policy_path,
        serde_json::to_vec_pretty(&import_policy).expect("serialize import policy"),
    )
    .expect("write import policy file");

    let import_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported,
            "localPolicy": import_policy,
        }))
        .send()
        .expect("send runtime appraisal import request");
    assert_eq!(import_response.status(), reqwest::StatusCode::OK);
    let import_report: RuntimeAttestationAppraisalImportReport =
        import_response.json().expect("parse import report");
    assert_eq!(
        import_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Attenuate
    );
    assert_eq!(
        import_report.local_policy_outcome.effective_tier,
        RuntimeAssuranceTier::Basic
    );
    assert_eq!(
        import_report.local_policy_outcome.reason_codes,
        vec![RuntimeAttestationImportReasonCode::TierAttenuated]
    );

    let cli_export_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "appraisal",
            "export-result",
            "--issuer",
            "did:chio:test:cli-exporter",
            "--input",
            attestation_path.to_str().expect("attestation path"),
            "--policy-file",
            runtime_policy_path.to_str().expect("runtime policy path"),
        ])
        .output()
        .expect("run appraisal result export CLI");
    assert!(
        cli_export_output.status.success(),
        "runtime appraisal result export CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_export_output.stdout),
        String::from_utf8_lossy(&cli_export_output.stderr)
    );
    let cli_result: SignedRuntimeAttestationAppraisalResult =
        serde_json::from_slice(&cli_export_output.stdout)
            .expect("parse appraisal result export CLI json");
    assert!(cli_result
        .verify_signature()
        .expect("verify appraisal result export CLI signature"));
    assert!(
        cli_result
            .body
            .exporter_policy_outcome
            .trust_policy_configured
    );
    assert_eq!(
        cli_result.body.exporter_policy_outcome.effective_tier,
        RuntimeAssuranceTier::Verified
    );

    let rejecting_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec!["did:chio:test:remote-exporter".to_string()],
        trusted_signer_keys: vec![cli_result.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: std::iter::once((
            RuntimeAttestationNormalizedClaimCode::SecureBootState,
            "disabled".to_string(),
        ))
        .collect(),
    };
    std::fs::write(
        &rejecting_policy_path,
        serde_json::to_vec_pretty(&rejecting_policy).expect("serialize rejecting policy"),
    )
    .expect("write rejecting policy file");

    let cli_import_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "appraisal",
            "import",
            "--input",
            signed_result_path.to_str().expect("signed result path"),
            "--policy-file",
            rejecting_policy_path
                .to_str()
                .expect("rejecting policy path"),
        ])
        .output()
        .expect("run appraisal import CLI");
    assert!(
        cli_import_output.status.success(),
        "runtime appraisal import CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_import_output.stdout),
        String::from_utf8_lossy(&cli_import_output.stderr)
    );
    let cli_import_report: RuntimeAttestationAppraisalImportReport =
        serde_json::from_slice(&cli_import_output.stdout).expect("parse appraisal import CLI json");
    assert_eq!(
        cli_import_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(cli_import_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::ClaimMismatch));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_attestation_appraisal_result_qualification_covers_mixed_providers_and_fail_closed_imports(
) {
    skip_when_loopback_denied!(test_runtime_attestation_appraisal_result_qualification_covers_mixed_providers_and_fail_closed_imports);
    struct ProviderCase {
        name: &'static str,
        attestation: RuntimeAttestationEvidence,
        expected_family: chio_core::appraisal::AttestationVerifierFamily,
        required_claim: (RuntimeAttestationNormalizedClaimCode, &'static str),
    }

    let dir = unique_dir("chio-runtime-appraisal-mixed-provider");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "runtime-appraisal-mixed-provider-token";
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

    let providers = vec![
        ProviderCase {
            name: "azure",
            attestation: sample_azure_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::AzureMaa,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::AttestationType,
                "sgx",
            ),
        },
        ProviderCase {
            name: "aws_nitro",
            attestation: sample_aws_nitro_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::AwsNitro,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::ModuleId,
                "i-chio-nitro-enclave",
            ),
        },
        ProviderCase {
            name: "google",
            attestation: sample_google_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::HardwareModel,
                "GCP_AMD_SEV",
            ),
        },
        ProviderCase {
            name: "enterprise",
            attestation: sample_enterprise_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::EnterpriseVerifier,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::ModuleId,
                "enterprise-module-1",
            ),
        },
    ];

    for provider in &providers {
        let issuer = format!("did:chio:test:{}-exporter", provider.name);
        let response = client
            .post(format!(
                "{base_url}/v1/reports/runtime-attestation-appraisal-result"
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            )
            .json(&RuntimeAttestationAppraisalResultExportRequest {
                issuer: issuer.clone(),
                runtime_attestation: provider.attestation.clone(),
            })
            .send()
            .expect("send runtime appraisal result export request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let exported: SignedRuntimeAttestationAppraisalResult =
            response.json().expect("parse signed appraisal result");
        assert!(exported
            .verify_signature()
            .expect("verify signed appraisal result"));
        assert_eq!(exported.body.issuer, issuer);
        assert_eq!(
            exported.body.appraisal.verifier.verifier_family,
            provider.expected_family
        );
        assert!(
            exported
                .body
                .appraisal
                .claims
                .normalized_claims
                .iter()
                .any(|claim| claim.code == provider.required_claim.0),
            "provider {} should project required normalized claim",
            provider.name
        );

        let import_policy = RuntimeAttestationImportedAppraisalPolicy {
            trusted_issuers: vec![exported.body.issuer.clone()],
            trusted_signer_keys: vec![exported.signer_key.to_hex()],
            allowed_verifier_families: vec![provider.expected_family],
            max_result_age_seconds: Some(300),
            max_evidence_age_seconds: Some(300),
            maximum_effective_tier: None,
            required_claims: BTreeMap::from([(
                provider.required_claim.0,
                provider.required_claim.1.to_string(),
            )]),
        };
        let import_response = client
            .post(format!(
                "{base_url}/v1/reports/runtime-attestation-appraisal/import"
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            )
            .json(&serde_json::json!({
                "signedResult": exported,
                "localPolicy": import_policy,
            }))
            .send()
            .expect("send runtime appraisal import request");
        assert_eq!(import_response.status(), reqwest::StatusCode::OK);
        let import_report: RuntimeAttestationAppraisalImportReport =
            import_response.json().expect("parse import report");
        assert_eq!(
            import_report.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Allow,
            "provider {} should import cleanly",
            provider.name
        );
        assert_eq!(
            import_report.local_policy_outcome.effective_tier,
            RuntimeAssuranceTier::Attested
        );
    }

    let google_export = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal-result"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&RuntimeAttestationAppraisalResultExportRequest {
            issuer: "did:chio:test:google-negative-exporter".to_string(),
            runtime_attestation: sample_google_runtime_attestation(),
        })
        .send()
        .expect("export google result for negative paths");
    assert_eq!(google_export.status(), reqwest::StatusCode::OK);
    let exported_google: SignedRuntimeAttestationAppraisalResult =
        google_export.json().expect("parse exported google result");

    let contradictory_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec![exported_google.body.issuer.clone()],
        trusted_signer_keys: vec![exported_google.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: BTreeMap::from([(
            RuntimeAttestationNormalizedClaimCode::HardwareModel,
            "GCP_INTEL_TDX".to_string(),
        )]),
    };
    let contradictory_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported_google.clone(),
            "localPolicy": contradictory_policy,
        }))
        .send()
        .expect("import contradictory google result");
    assert_eq!(contradictory_response.status(), reqwest::StatusCode::OK);
    let contradictory_report: RuntimeAttestationAppraisalImportReport = contradictory_response
        .json()
        .expect("parse contradictory import report");
    assert_eq!(
        contradictory_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(contradictory_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::ClaimMismatch));

    let unsupported_family_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec![exported_google.body.issuer.clone()],
        trusted_signer_keys: vec![exported_google.signer_key.to_hex()],
        allowed_verifier_families: vec![chio_core::appraisal::AttestationVerifierFamily::AzureMaa],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: BTreeMap::new(),
    };
    let unsupported_family_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported_google.clone(),
            "localPolicy": unsupported_family_policy,
        }))
        .send()
        .expect("import unsupported-family google result");
    assert_eq!(
        unsupported_family_response.status(),
        reqwest::StatusCode::OK
    );
    let unsupported_family_report: RuntimeAttestationAppraisalImportReport =
        unsupported_family_response
            .json()
            .expect("parse unsupported-family import report");
    assert_eq!(
        unsupported_family_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(unsupported_family_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::UnsupportedVerifierFamily));

    let stale_evidence_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec![exported_google.body.issuer.clone()],
        trusted_signer_keys: vec![exported_google.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(1),
        maximum_effective_tier: None,
        required_claims: BTreeMap::new(),
    };
    let stale_evidence_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported_google.clone(),
            "localPolicy": stale_evidence_policy,
        }))
        .send()
        .expect("import stale-evidence google result");
    assert_eq!(stale_evidence_response.status(), reqwest::StatusCode::OK);
    let stale_evidence_report: RuntimeAttestationAppraisalImportReport = stale_evidence_response
        .json()
        .expect("parse stale-evidence import report");
    assert_eq!(
        stale_evidence_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(stale_evidence_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::EvidenceStale));

    let replay_attestation = sample_google_runtime_attestation();
    let replay_appraisal = derive_runtime_attestation_appraisal(&replay_attestation)
        .expect("derive appraisal for stale replay test");
    let stale_replay_report = RuntimeAttestationAppraisalReport {
        schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
        generated_at: unix_now_secs().saturating_sub(600),
        appraisal: replay_appraisal,
        policy_outcome: RuntimeAttestationPolicyOutcome {
            trust_policy_configured: false,
            accepted: true,
            effective_tier: RuntimeAssuranceTier::Attested,
            reason: None,
        },
    };
    let stale_replay_result = RuntimeAttestationAppraisalResult::from_report(
        "did:chio:test:stale-replay-exporter",
        &stale_replay_report,
    )
    .expect("build stale replay result");
    let stale_replay_signer = Keypair::generate();
    let signed_stale_replay =
        SignedRuntimeAttestationAppraisalResult::sign(stale_replay_result, &stale_replay_signer)
            .expect("sign stale replay result");
    let stale_replay_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec!["did:chio:test:stale-replay-exporter".to_string()],
        trusted_signer_keys: vec![stale_replay_signer.public_key().to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(120),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: BTreeMap::new(),
    };
    let stale_replay_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": signed_stale_replay,
            "localPolicy": stale_replay_policy,
        }))
        .send()
        .expect("import stale replay result");
    assert_eq!(stale_replay_response.status(), reqwest::StatusCode::OK);
    let stale_replay_import: RuntimeAttestationAppraisalImportReport = stale_replay_response
        .json()
        .expect("parse stale replay import report");
    assert_eq!(
        stale_replay_import.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(stale_replay_import
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::ResultStale));

    let _ = std::fs::remove_dir_all(&dir);
}
