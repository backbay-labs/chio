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
fn test_authorization_context_report_and_cli() {
    skip_when_loopback_denied!(test_authorization_context_report_and_cli);
    let dir = unique_dir("chio-authorization-context");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let rc_auth_1 = make_governed_authorization_receipt(
        "rc-auth-1",
        "cap-auth-1",
        &subject_hex,
        &issuer_hex,
        "shell",
        "bash",
        7_000,
    );
    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-1",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&rc_auth_1)
            .expect("append authorization receipt");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "rc-auth-2",
                "cap-auth-1",
                "shell",
                "bash",
                7_001,
            ))
            .expect("append second governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-token";
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
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[("capabilityId", "cap-auth-1"), ("authorizationLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization context request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().expect("parse authorization context report");
    assert_eq!(
        body["schema"].as_str(),
        Some("chio.oauth.authorization-context-report.v1")
    );
    assert_eq!(
        body["profile"]["schema"].as_str(),
        Some("chio.oauth.authorization-profile.v1")
    );
    assert_eq!(body["profile"]["id"].as_str(), Some("chio-governed-rar-v1"));
    assert_eq!(
        body["profile"]["authoritativeSource"].as_str(),
        Some("governed_receipt_projection")
    );
    assert_eq!(
        body["profile"]["unsupportedShapesFailClosed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        body["profile"]["portableIdentityBinding"]["portableSubjectClaim"].as_str(),
        Some("sub")
    );
    assert_eq!(
        body["profile"]["portableIdentityBinding"]["chioIssuerProvenanceClaim"].as_str(),
        Some("chio_issuer_dids")
    );
    assert_eq!(
        body["profile"]["governedAuthBinding"]["authoritativeSource"].as_str(),
        Some("metadata.governed_transaction")
    );
    assert!(
        body["profile"]["portableClaimCatalog"]["selectivelyDisclosableClaims"]
            .as_array()
            .expect("portable claim catalog")
            .iter()
            .any(|value| value.as_str() == Some("chio_issuer_dids"))
    );
    assert_eq!(body["summary"]["matchingReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["approvalReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["approvedReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["commerceReceipts"].as_u64(), Some(1));
    assert_eq!(body["summary"]["meteredBillingReceipts"].as_u64(), Some(1));
    assert_eq!(
        body["summary"]["runtimeAssuranceReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(body["summary"]["callChainReceipts"].as_u64(), Some(1));
    assert_eq!(body["summary"]["maxAmountReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["senderBoundReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["dpopBoundReceipts"].as_u64(), Some(2));
    assert_eq!(
        body["summary"]["runtimeAssuranceBoundReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["summary"]["delegatedSenderBoundReceipts"].as_u64(),
        Some(0)
    );

    let auth_row = body["receipts"]
        .as_array()
        .expect("authorization receipts array")
        .iter()
        .find(|row| row["receiptId"] == rc_auth_1.id.as_str())
        .expect("authorization receipt row");
    let detail_types = auth_row["authorizationDetails"]
        .as_array()
        .expect("authorization details")
        .iter()
        .map(|detail| detail["type"].as_str().expect("detail type"))
        .collect::<Vec<_>>();
    assert!(detail_types.contains(&"chio_governed_tool"));
    assert!(detail_types.contains(&"chio_governed_commerce"));
    assert!(detail_types.contains(&"chio_governed_metered_billing"));
    assert_eq!(
        auth_row["transactionContext"]["approvalTokenId"].as_str(),
        Some("approval-auth-1")
    );
    assert_eq!(
        auth_row["transactionContext"]["runtimeAssuranceTier"].as_str(),
        Some("verified")
    );
    assert_eq!(
        auth_row["transactionContext"]["runtimeAssuranceSchema"].as_str(),
        Some("chio.runtime-attestation.azure-maa.jwt.v1")
    );
    assert_eq!(
        auth_row["transactionContext"]["runtimeAssuranceVerifierFamily"].as_str(),
        Some("azure_maa")
    );
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["chainId"].as_str(),
        Some("chain-ext-1")
    );
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["parentReceiptId"].as_str(),
        Some("rcpt-upstream-1")
    );
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["evidenceClass"].as_str(),
        Some("asserted")
    );
    assert_eq!(
        auth_row["senderConstraint"]["subjectKey"].as_str(),
        Some(subject_hex.as_str())
    );
    assert_eq!(
        auth_row["senderConstraint"]["subjectKeySource"].as_str(),
        Some("receipt_attribution")
    );
    assert_eq!(
        auth_row["senderConstraint"]["issuerKey"].as_str(),
        Some(issuer_hex.as_str())
    );
    assert_eq!(
        auth_row["senderConstraint"]["issuerKeySource"].as_str(),
        Some("receipt_attribution")
    );
    assert_eq!(
        auth_row["senderConstraint"]["matchedGrantIndex"].as_u64(),
        Some(0)
    );
    assert_eq!(
        auth_row["senderConstraint"]["proofRequired"].as_bool(),
        Some(true)
    );
    assert_eq!(
        auth_row["senderConstraint"]["proofType"].as_str(),
        Some("chio_dpop_v1")
    );
    assert_eq!(
        auth_row["senderConstraint"]["proofSchema"].as_str(),
        Some("chio.dpop_proof.v1")
    );
    assert_eq!(
        auth_row["senderConstraint"]["runtimeAssuranceBound"].as_bool(),
        Some(true)
    );
    assert_eq!(
        auth_row["senderConstraint"]["delegatedCallChainBound"].as_bool(),
        Some(false)
    );

    let operator = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[("capabilityId", "cap-auth-1"), ("authorizationLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");
    assert_eq!(operator.status(), reqwest::StatusCode::OK);
    let operator_body: serde_json::Value = operator.json().expect("parse operator report");
    assert_eq!(
        operator_body["authorizationContext"]["summary"]["callChainReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        operator_body["authorizationContext"]["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "authorization-context",
            "list",
            "--capability",
            "cap-auth-1",
            "--limit",
            "10",
        ])
        .output()
        .expect("run authorization-context CLI");
    assert!(
        cli_output.status.success(),
        "authorization-context CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: AuthorizationContextReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse authorization CLI json");
    assert_eq!(
        cli_report.schema,
        "chio.oauth.authorization-context-report.v1"
    );
    assert_eq!(cli_report.profile.id, "chio-governed-rar-v1");
    assert_eq!(
        cli_report
            .profile
            .sender_constraints
            .subject_binding
            .as_str(),
        "capability_subject"
    );
    assert_eq!(cli_report.summary.matching_receipts, 2);
    assert_eq!(cli_report.summary.sender_bound_receipts, 2);
    assert_eq!(cli_report.summary.dpop_bound_receipts, 2);
    let cli_row = cli_report
        .receipts
        .iter()
        .find(|row| row.receipt_id == rc_auth_1.id)
        .expect("authorization CLI row");
    assert_eq!(
        cli_row
            .transaction_context
            .runtime_assurance_schema
            .as_deref(),
        Some("chio.runtime-attestation.azure-maa.jwt.v1")
    );
    assert_eq!(
        cli_row
            .transaction_context
            .runtime_assurance_verifier_family,
        Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa)
    );
    assert_eq!(
        cli_row
            .transaction_context
            .call_chain
            .as_ref()
            .expect("call chain")
            .chain_id,
        "chain-ext-1"
    );
    assert!(cli_row.sender_constraint.proof_required);
    assert_eq!(
        cli_row.sender_constraint.proof_type.as_deref(),
        Some("chio_dpop_v1")
    );
    assert_eq!(cli_row.sender_constraint.issuer_key, issuer_hex);
    assert_eq!(
        cli_row.sender_constraint.issuer_key_source.as_str(),
        "receipt_attribution"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn authorization_context_report_does_not_mark_asserted_call_chain_as_sender_bound() {
    skip_when_loopback_denied!(
        authorization_context_report_does_not_mark_asserted_call_chain_as_sender_bound
    );
    let dir = unique_dir("chio-authorization-context-asserted-call-chain");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let rc_auth_asserted = make_governed_authorization_receipt(
        "rc-auth-asserted",
        "cap-auth-asserted",
        &subject_hex,
        &issuer_hex,
        "shell",
        "bash",
        7_050,
    );
    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-asserted",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&rc_auth_asserted)
            .expect("append asserted authorization receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-asserted-token";
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
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-asserted"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization context request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().expect("parse authorization context report");
    assert_eq!(body["summary"]["matchingReceipts"].as_u64(), Some(1));
    assert_eq!(
        body["summary"]["delegatedSenderBoundReceipts"].as_u64(),
        Some(0)
    );
    let auth_row = body["receipts"]
        .as_array()
        .expect("authorization receipts array")
        .iter()
        .find(|row| row["receiptId"] == rc_auth_asserted.id.as_str())
        .expect("asserted authorization receipt row");
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["evidenceClass"].as_str(),
        Some("asserted")
    );
    assert_eq!(
        auth_row["senderConstraint"]["delegatedCallChainBound"].as_bool(),
        Some(false)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_metadata_and_review_pack_surfaces() {
    skip_when_loopback_denied!(test_authorization_metadata_and_review_pack_surfaces);
    let dir = unique_dir("chio-authorization-review-pack");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let rc_auth_pack_1 = make_governed_authorization_receipt(
        "rc-auth-pack-1",
        "cap-auth-pack-1",
        &subject_hex,
        &issuer_hex,
        "shell",
        "bash",
        7_100,
    );
    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-pack-1",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&rc_auth_pack_1)
            .expect("append authorization receipt");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "rc-auth-pack-2",
                "cap-auth-pack-1",
                "shell",
                "bash",
                7_101,
            ))
            .expect("append second governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-review-pack-token";
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

    let metadata_response = client
        .get(format!(
            "{base_url}/v1/reports/authorization-profile-metadata"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization profile metadata request");
    assert_eq!(metadata_response.status(), reqwest::StatusCode::OK);
    let metadata_body: serde_json::Value = metadata_response
        .json()
        .expect("parse authorization profile metadata response");
    assert_eq!(
        metadata_body["schema"].as_str(),
        Some("chio.oauth.authorization-metadata.v1")
    );
    assert_eq!(
        metadata_body["profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        metadata_body["reportSchema"].as_str(),
        Some("chio.oauth.authorization-context-report.v1")
    );
    assert_eq!(
        metadata_body["discovery"]["discoveryInformationalOnly"].as_bool(),
        Some(true)
    );
    assert!(metadata_body["discovery"]["protectedResourceMetadataPaths"]
        .as_array()
        .expect("protected resource metadata paths")
        .iter()
        .any(|value| value.as_str() == Some("/.well-known/oauth-protected-resource/mcp")));
    assert_eq!(
        metadata_body["supportBoundary"]["senderConstrainedProjection"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["supportBoundary"]["hostedRequestTimeAuthorizationSupported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["supportBoundary"]["resourceIndicatorBindingSupported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["supportBoundary"]["reviewerEvidenceRuntimeAuthorizationSupported"].as_bool(),
        Some(false)
    );
    assert!(metadata_body["exampleMapping"]["senderConstraintFields"]
        .as_array()
        .expect("sender constraint field list")
        .iter()
        .any(|value| value.as_str() == Some("subjectKey")));
    assert!(metadata_body["exampleMapping"]["senderConstraintFields"]
        .as_array()
        .expect("sender constraint field list")
        .iter()
        .any(|value| value.as_str() == Some("issuerKey")));
    assert!(metadata_body["exampleMapping"]["transactionContextFields"]
        .as_array()
        .expect("transaction context field list")
        .iter()
        .any(|value| value.as_str() == Some("runtimeAssuranceSchema")));
    assert!(metadata_body["exampleMapping"]["transactionContextFields"]
        .as_array()
        .expect("transaction context field list")
        .iter()
        .any(|value| value.as_str() == Some("runtimeAssuranceVerifierFamily")));
    assert_eq!(
        metadata_body["profile"]["portableIdentityBinding"]["chioProvenanceAnchor"].as_str(),
        Some("did:chio")
    );
    assert_eq!(
        metadata_body["profile"]["governedAuthBinding"]["authoritativeSource"].as_str(),
        Some("metadata.governed_transaction")
    );
    assert_eq!(
        metadata_body["profile"]["requestTimeContract"]["authorizationDetailsParameter"].as_str(),
        Some("authorization_details")
    );
    assert_eq!(
        metadata_body["profile"]["resourceBinding"]["requestResourceMustMatchProtectedResource"]
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["profile"]["artifactBoundary"]["approvalTokensRuntimeAdmissionSupported"]
            .as_bool(),
        Some(false)
    );

    let review_pack_response = client
        .get(format!("{base_url}/v1/reports/authorization-review-pack"))
        .query(&[
            ("capabilityId", "cap-auth-pack-1"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization review pack request");
    assert_eq!(review_pack_response.status(), reqwest::StatusCode::OK);
    let review_pack_body: serde_json::Value = review_pack_response
        .json()
        .expect("parse authorization review pack response");
    assert_eq!(
        review_pack_body["schema"].as_str(),
        Some("chio.oauth.authorization-review-pack.v1")
    );
    assert_eq!(
        review_pack_body["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        review_pack_body["summary"]["returnedReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        review_pack_body["summary"]["dpopRequiredReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        review_pack_body["summary"]["runtimeAssuranceReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        review_pack_body["summary"]["delegatedCallChainReceipts"].as_u64(),
        Some(1)
    );
    let review_record = review_pack_body["records"]
        .as_array()
        .expect("authorization review pack records")
        .iter()
        .find(|row| row["receiptId"] == rc_auth_pack_1.id.as_str())
        .expect("review-pack record for first governed receipt");
    assert_eq!(
        review_record["authorizationContext"]["senderConstraint"]["subjectKey"].as_str(),
        Some(subject_hex.as_str())
    );
    assert_eq!(
        review_record["authorizationContext"]["senderConstraint"]["issuerKey"].as_str(),
        Some(issuer_hex.as_str())
    );
    assert_eq!(
        review_record["governedTransaction"]["intent_id"].as_str(),
        Some("intent-auth-1")
    );
    assert_eq!(
        review_record["signedReceipt"]["id"].as_str(),
        Some(rc_auth_pack_1.id.as_str())
    );

    let cli_metadata_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "authorization-context",
            "metadata",
        ])
        .output()
        .expect("run authorization metadata CLI");
    assert!(
        cli_metadata_output.status.success(),
        "authorization metadata CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_metadata_output.stdout),
        String::from_utf8_lossy(&cli_metadata_output.stderr)
    );
    let cli_metadata_body: serde_json::Value = serde_json::from_slice(&cli_metadata_output.stdout)
        .expect("parse authorization metadata CLI json");
    assert_eq!(
        cli_metadata_body["schema"].as_str(),
        Some("chio.oauth.authorization-metadata.v1")
    );
    assert_eq!(
        cli_metadata_body["profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );

    let cli_review_pack_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "authorization-context",
            "review-pack",
            "--capability",
            "cap-auth-pack-1",
            "--limit",
            "10",
        ])
        .output()
        .expect("run authorization review-pack CLI");
    assert!(
        cli_review_pack_output.status.success(),
        "authorization review-pack CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_review_pack_output.stdout),
        String::from_utf8_lossy(&cli_review_pack_output.stderr)
    );
    let cli_review_pack_body: serde_json::Value =
        serde_json::from_slice(&cli_review_pack_output.stdout)
            .expect("parse authorization review-pack CLI json");
    assert_eq!(
        cli_review_pack_body["schema"].as_str(),
        Some("chio.oauth.authorization-review-pack.v1")
    );
    assert_eq!(
        cli_review_pack_body["summary"]["returnedReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        cli_review_pack_body["metadata"]["profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_invalid_chio_oauth_profile_projection() {
    skip_when_loopback_denied!(
        test_authorization_context_report_rejects_invalid_chio_oauth_profile_projection
    );
    let dir = unique_dir("chio-authorization-context-invalid");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-invalid",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        let keypair = Keypair::generate();
        let invalid_receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "rc-auth-invalid".to_string(),
                timestamp: 8_000,
                capability_id: "cap-auth-invalid".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: tool_action(serde_json::json!({ "invoice_id": "inv-invalid-1" })),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-invalid".to_string(),
                policy_hash: "policy-invalid".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_hex.clone(),
                        issuer_key: issuer_hex.clone(),
                        delegation_depth: 1,
                        grant_index: Some(0),
                    },
                    "governed_transaction": GovernedTransactionReceiptMetadata {
                        intent_id: "intent-auth-invalid".to_string(),
                        intent_hash: "".to_string(),
                        purpose: "broken enterprise profile".to_string(),
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        max_amount: Some(MonetaryAmount {
                            units: 4200,
                            currency: "USD".to_string(),
                        }),
                        commerce: None,
                        metered_billing: None,
                        approval: Some(GovernedApprovalReceiptMetadata {
                            token_id: "approval-auth-invalid".to_string(),
                            approver_key: issuer_hex.clone(),
                            approval_artifact_digest: None,
                            approved: true,
                        }),
                        runtime_assurance: None,
                        call_chain: None,
                        autonomy: None,
                        economic_authorization: None,
                    }
                })),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign invalid authorization receipt");

        store
            .append_chio_receipt(&invalid_receipt)
            .expect("append invalid authorization receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-invalid-token";
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
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-invalid"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send invalid authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse invalid authorization context response");
    let error = body["error"]
        .as_str()
        .expect("authorization context error message");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("transactionContext.intentHash"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_missing_sender_binding_material() {
    skip_when_loopback_denied!(
        test_authorization_context_report_rejects_missing_sender_binding_material
    );
    let dir = unique_dir("chio-authorization-context-missing-sender");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "rc-auth-no-sender",
                "cap-auth-no-sender",
                "shell",
                "bash",
                8_100,
            ))
            .expect("append missing sender authorization receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-missing-sender-token";
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
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-no-sender"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send missing sender authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse missing sender authorization context response");
    let error = body["error"]
        .as_str()
        .expect("missing sender authorization context error");
    assert!(error.contains("sender-constrained profile"));
    assert!(error.contains("subjectKey"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_missing_issuer_binding_material() {
    skip_when_loopback_denied!(
        test_authorization_context_report_rejects_missing_issuer_binding_material
    );
    let dir = unique_dir("chio-authorization-context-missing-issuer");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-no-issuer",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-auth-no-issuer",
                "cap-auth-no-issuer",
                &subject_hex,
                "",
                "shell",
                "bash",
                8_101,
            ))
            .expect("append missing issuer authorization receipt");
    }
    let connection = Connection::open(&receipt_db_path).expect("open raw receipt db");
    connection
        .execute(
            "UPDATE capability_lineage SET issuer_key = '' WHERE capability_id = ?1",
            ["cap-auth-no-issuer"],
        )
        .expect("clear lineage issuer key");

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-missing-issuer-token";
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
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-no-issuer"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send missing issuer authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse missing issuer authorization context response");
    let error = body["error"]
        .as_str()
        .expect("missing issuer authorization context error");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("issuerKey"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_incomplete_runtime_assurance_projection() {
    skip_when_loopback_denied!(
        test_authorization_context_report_rejects_incomplete_runtime_assurance_projection
    );
    let dir = unique_dir("chio-authorization-context-invalid-assurance");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-invalid-assurance",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        let keypair = Keypair::generate();
        let invalid_receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "rc-auth-invalid-assurance".to_string(),
                timestamp: 8_150,
                capability_id: "cap-auth-invalid-assurance".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: tool_action(serde_json::json!({ "cmd": "echo auth" })),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-invalid-assurance".to_string(),
                policy_hash: "policy-invalid-assurance".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_hex.clone(),
                        issuer_key: issuer_hex.clone(),
                        delegation_depth: 1,
                        grant_index: Some(0),
                    },
                    "governed_transaction": GovernedTransactionReceiptMetadata {
                        intent_id: "intent-auth-invalid-assurance".to_string(),
                        intent_hash: "intent-hash-invalid-assurance".to_string(),
                        purpose: "broken runtime assurance profile".to_string(),
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        max_amount: Some(MonetaryAmount {
                            units: 4200,
                            currency: "USD".to_string(),
                        }),
                        commerce: None,
                        metered_billing: None,
                        approval: Some(GovernedApprovalReceiptMetadata {
                            token_id: "approval-auth-invalid-assurance".to_string(),
                            approver_key: issuer_hex.clone(),
                            approval_artifact_digest: None,
                            approved: true,
                        }),
                        runtime_assurance: Some(RuntimeAssuranceReceiptMetadata {
                            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                            verifier_family: Some(
                                chio_core::appraisal::AttestationVerifierFamily::AzureMaa,
                            ),
                            tier: RuntimeAssuranceTier::Verified,
                            verifier: "".to_string(),
                            evidence_sha256: "sha256-invalid-assurance".to_string(),
                            workload_identity: None,
                        }),
                        call_chain: None,
                        autonomy: None,
                        economic_authorization: None,
                    }
                })),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign invalid assurance receipt");

        store
            .append_chio_receipt(&invalid_receipt)
            .expect("append invalid assurance receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-invalid-assurance-token";
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
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-invalid-assurance"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send invalid runtime assurance authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse invalid runtime assurance authorization context response");
    let error = body["error"]
        .as_str()
        .expect("runtime assurance authorization context error");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("transactionContext.runtimeAssuranceVerifier"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_invalid_delegated_call_chain_projection() {
    skip_when_loopback_denied!(
        test_authorization_context_report_rejects_invalid_delegated_call_chain_projection
    );
    let dir = unique_dir("chio-authorization-context-invalid-call-chain");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-invalid-call-chain",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        let keypair = Keypair::generate();
        let invalid_receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "rc-auth-invalid-call-chain".to_string(),
                timestamp: 8_151,
                capability_id: "cap-auth-invalid-call-chain".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: tool_action(serde_json::json!({ "cmd": "echo delegated" })),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-invalid-call-chain".to_string(),
                policy_hash: "policy-invalid-call-chain".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_hex.clone(),
                        issuer_key: issuer_hex.clone(),
                        delegation_depth: 1,
                        grant_index: Some(0),
                    },
                    "governed_transaction": GovernedTransactionReceiptMetadata {
                        intent_id: "intent-auth-invalid-call-chain".to_string(),
                        intent_hash: "intent-hash-invalid-call-chain".to_string(),
                        purpose: "broken delegated profile".to_string(),
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        max_amount: Some(MonetaryAmount {
                            units: 4200,
                            currency: "USD".to_string(),
                        }),
                        commerce: None,
                        metered_billing: None,
                        approval: Some(GovernedApprovalReceiptMetadata {
                            token_id: "approval-auth-invalid-call-chain".to_string(),
                            approver_key: issuer_hex.clone(),
                            approval_artifact_digest: None,
                            approved: true,
                        }),
                        runtime_assurance: None,
                        call_chain: Some(GovernedCallChainProvenance::asserted(
                            GovernedCallChainContext {
                                chain_id: "chain-invalid-1".to_string(),
                                parent_request_id: "parent-invalid-1".to_string(),
                                parent_receipt_id: Some("rcpt-parent-invalid-1".to_string()),
                                origin_subject: "".to_string(),
                                delegator_subject: "upstream-delegator".to_string(),
                            },
                        )),
                        autonomy: None,
                        economic_authorization: None,
                    }
                })),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign invalid delegated receipt");

        store
            .append_chio_receipt(&invalid_receipt)
            .expect("append invalid delegated receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-invalid-call-chain-token";
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
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-invalid-call-chain"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send invalid delegated authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse invalid delegated authorization context response");
    let error = body["error"]
        .as_str()
        .expect("delegated authorization context error");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("transactionContext.callChain.originSubject"));

    let _ = std::fs::remove_dir_all(&dir);
}
