use super::*;

static AGENT_WEB_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct TestEnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl TestEnvGuard {
    fn set(values: &[(&'static str, &std::ffi::OsStr)]) -> Self {
        let mut previous = Vec::with_capacity(values.len());
        for (name, value) in values {
            previous.push((*name, std::env::var_os(name)));
            std::env::set_var(name, value);
        }
        Self(previous)
    }
}

impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        for (name, previous) in self.0.drain(..).rev() {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn proof_test_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn write_verifier_signer_policy(
    directory: &std::path::Path,
    key: chio_core_types::PublicKey,
) -> std::path::PathBuf {
    let path = directory.join("finding-verifier-signer-policy.json");
    let policy = chio_finding::FindingAuthorityKeyPolicy {
        authority_id: "qualified-finding-verifier".to_owned(),
        key,
        key_epoch: 1,
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        rotation_policy_ref: "rotation/qualified-finding-verifier-v1".to_owned(),
        revocation_status_ref: "revocations/qualified-finding-verifier-v1".to_owned(),
    };
    proof_test_ok(
        std::fs::write(
            &path,
            proof_test_ok(
                chio_core_types::canonical_json_bytes(&policy),
                "serialize verifier signer policy",
            ),
        ),
        "write verifier signer policy",
    );
    path
}

#[test]
fn only_verified_finding_claim_set_rows_force_cognition_market_routing() {
    let transaction_claim_set = serde_json::to_vec(&serde_json::json!({
        "claims": [{
            "claim_id": "claim.transaction.passport_root_verified",
            "status": "verified"
        }]
    }))
    .unwrap_or_default();
    assert!(!proof_test_ok(
        claim_set_bytes_advertise_verified_prefix(&transaction_claim_set, CLAIM_PREFIX_FINDING),
        "inspect transaction-only ClaimSet",
    ));

    let finding_claim_set = serde_json::to_vec(&serde_json::json!({
        "claims": [{
            "claim_id": "claim.finding.delivery_digest_bound",
            "status": "verified"
        }]
    }))
    .unwrap_or_default();
    assert!(proof_test_ok(
        claim_set_bytes_advertise_verified_prefix(&finding_claim_set, CLAIM_PREFIX_FINDING),
        "inspect ClaimSet with an advertised finding claim",
    ));
    assert!(proof_test_ok(
        claim_set_bytes_advertise_verified_claim(
            &finding_claim_set,
            "claim.finding.delivery_digest_bound",
        ),
        "inspect exact advertised Finding claim",
    ));
    assert!(!proof_test_ok(
        claim_set_bytes_advertise_verified_claim(
            &finding_claim_set,
            "claim.finding.status_fresh",
        ),
        "distinguish an unselected status claim",
    ));

    for status in ["omitted", "unsupported", "failed"] {
        let non_verified_finding_claim_set = serde_json::to_vec(&serde_json::json!({
            "claims": [{
                "claim_id": "claim.finding.delivery_digest_bound",
                "status": status
            }]
        }))
        .unwrap_or_default();
        assert!(!proof_test_ok(
            claim_set_bytes_advertise_verified_prefix(
                &non_verified_finding_claim_set,
                CLAIM_PREFIX_FINDING,
            ),
            "inspect ClaimSet with a non-verified finding claim",
        ));
    }
}

#[test]
fn cognition_market_trust_skips_status_configuration_for_non_status_claims() {
    let _env_lock = match AGENT_WEB_ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let verifier_key = chio_core_types::Keypair::from_seed(&[84_u8; 32])
        .public_key();
    let tempdir = proof_test_ok(tempfile::tempdir(), "create verifier policy tempdir");
    let signer_policy_path = write_verifier_signer_policy(tempdir.path(), verifier_key.clone());
    let verifier_key = verifier_key.to_hex();
    let profile_digest = "23".repeat(32);
    let _env = TestEnvGuard::set(&[
        (
            "CHIO_FINDING_VERIFIER_AUTHORITY_KEY",
            std::ffi::OsStr::new(&verifier_key),
        ),
        (
            "CHIO_FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256",
            std::ffi::OsStr::new(&profile_digest),
        ),
        (
            "CHIO_FINDING_VERIFIER_PROFILE_REQUIRED_FACETS",
            std::ffi::OsStr::new("[]"),
        ),
        (
            "CHIO_FINDING_TRUST_ROOT_SNAPSHOT_SHA256",
            std::ffi::OsStr::new(
                "4545454545454545454545454545454545454545454545454545454545454545",
            ),
        ),
        (
            "CHIO_FINDING_VERIFIER_SIGNER_POLICY_PATH",
            signer_policy_path.as_os_str(),
        ),
    ]);
    let passport_key = chio_core_types::Keypair::from_seed(&[85_u8; 32]).public_key();

    let trust = proof_test_ok(
        cognition_market_proof_trust_from_env(&[passport_key], &[], false),
        "build non-status Finding trust",
    );
    assert!(trust.status.is_none());
}

fn agent_web_replay_test_env(replay_store_path: &std::path::Path) -> TestEnvGuard {
    let host_now = proof_test_ok(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
        "read host clock",
    )
    .as_secs();
    let verifier_now = host_now.saturating_add(60);
    let replay_max_age = verifier_now
        .saturating_sub(1_770_508_800)
        .saturating_add(300);
    let verifier_now = verifier_now.to_string();
    let replay_max_age = replay_max_age.to_string();
    let env_values = [
        (
            "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
            std::ffi::OsStr::new("chio-agent-web-standard-webhooks-fixture-secret-v1"),
        ),
        (
            "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS",
            std::ffi::OsStr::new(verifier_now.as_str()),
        ),
        (
            "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS",
            std::ffi::OsStr::new(replay_max_age.as_str()),
        ),
        (
            "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
            std::ffi::OsStr::new(concat!(
                "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,",
                "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,",
                "bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,",
                "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21,",
                "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565"
            )),
        ),
        (
            "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
            std::ffi::OsStr::new(
                "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
            ),
        ),
        (
            "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS",
            std::ffi::OsStr::new(concat!(
                "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
                "68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96"
            )),
        ),
        (
            "CHIO_AGENT_WEB_REPLAY_STORE_PATH",
            replay_store_path.as_os_str(),
        ),
        (
            collect::PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX_ENV,
            std::ffi::OsStr::new(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
        ),
    ];
    TestEnvGuard::set(&env_values)
}

#[test]
fn agent_web_receipt_scope_uses_schema_not_fixture_filename() {
    assert!(is_agent_web_evidence_graph_node_parts(
        "receipt",
        "receipts/webhook-allow.json",
        Some("chio.receipt.v1"),
    ));
}

#[test]
fn enterprise_artifact_loader_includes_retained_jurisdiction_receipts() {
    assert!(is_enterprise_evidence_graph_role(
        "adjudication-jurisdiction-receipt"
    ));
    assert!(is_enterprise_artifact_role(
        "adjudication-jurisdiction-receipt"
    ));
}

#[test]
fn trust_market_artifact_loader_includes_retained_receipts() {
    assert!(is_trust_market_evidence_graph_role("receipt"));
    assert!(is_trust_market_artifact_role("receipt"));
}

#[test]
fn runtime_artifact_loader_includes_policy_activation_receipt() {
    assert!(is_runtime_artifact_role("policy-activation-receipt"));
}

#[test]
fn proof_verify_routes_finding_claims_through_the_cognition_verifier() {
    let _env_lock = match AGENT_WEB_ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let tempdir = proof_test_ok(tempfile::tempdir(), "create tempdir");
    let verifier_authority = proof_test_ok(
        chio_core_types::PublicKey::from_hex(
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
        ),
        "parse finding verifier authority",
    );
    let signer_policy_path =
        write_verifier_signer_policy(tempdir.path(), verifier_authority);
    let authorization = chio_finding::FindingStatusOperatorAuthorization {
        role: chio_finding::FindingStatusOperatorRole::FindingStatusOperator,
        feed_id: "qualified-finding-status".to_owned(),
        operator: chio_finding::FindingAuthorityKeyPolicy {
            authority_id: "qualified-status-operator".to_owned(),
            key: proof_test_ok(
                chio_core_types::PublicKey::from_hex(
                    "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61",
                ),
                "parse status operator key",
            ),
            key_epoch: 1,
            valid_from: 1_749_999_940,
            valid_until: 1_750_000_600,
            rotation_policy_ref: "rotation/qualified-status-v1".to_owned(),
            revocation_status_ref: "revocations/qualified-status-v1".to_owned(),
        },
        revoked_from: None,
    };
    let authorization_path = tempdir.path().join("status-operator-authorization.json");
    proof_test_ok(
        std::fs::write(
            &authorization_path,
            proof_test_ok(
                chio_core_types::canonical_json_bytes(&authorization),
                "serialize status authorization",
            ),
        ),
        "write status authorization",
    );
    let authority_database = tempdir.path().join("status-authority.db");
    let authority_lock_root = tempdir.path().join("status-authority-locks");
    proof_test_ok(
        std::fs::create_dir(&authority_lock_root),
        "create status authority lock root",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        proof_test_ok(
            std::fs::set_permissions(
                tempdir.path(),
                std::fs::Permissions::from_mode(0o700),
            ),
            "secure status authority parent",
        );
        proof_test_ok(
            std::fs::set_permissions(
                &authority_lock_root,
                std::fs::Permissions::from_mode(0o700),
            ),
            "secure status authority lock root",
        );
    }
    proof_test_ok(
        chio_store_sqlite::SqliteAuthorityStore::provision(
            &authority_database,
            &authority_lock_root,
        ),
        "provision status authority store",
    );
    let _env = TestEnvGuard::set(&[
        (
            "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS",
            std::ffi::OsStr::new(
                "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            ),
        ),
        (
            "CHIO_FINDING_VERIFIER_AUTHORITY_KEY",
            std::ffi::OsStr::new(
                "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
            ),
        ),
        (
            "CHIO_FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256",
            std::ffi::OsStr::new(
                "2323232323232323232323232323232323232323232323232323232323232323",
            ),
        ),
        (
            "CHIO_FINDING_VERIFIER_PROFILE_REQUIRED_FACETS",
            std::ffi::OsStr::new("[\"kernel_and_revocation_trust\"]"),
        ),
        (
            "CHIO_FINDING_TRUST_ROOT_SNAPSHOT_SHA256",
            std::ffi::OsStr::new(
                "4545454545454545454545454545454545454545454545454545454545454545",
            ),
        ),
        (
            "CHIO_FINDING_VERIFIER_SIGNER_POLICY_PATH",
            signer_policy_path.as_os_str(),
        ),
        (
            "CHIO_FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH",
            authorization_path.as_os_str(),
        ),
        (
            "CHIO_FINDING_STATUS_AUTHORITY_DATABASE_PATH",
            authority_database.as_os_str(),
        ),
        (
            "CHIO_FINDING_STATUS_AUTHORITY_LOCK_ROOT",
            authority_lock_root.as_os_str(),
        ),
        (
            "CHIO_FINDING_STATUS_NOW_UNIX_SECONDS",
            std::ffi::OsStr::new("1750000030"),
        ),
        (
            "CHIO_FINDING_STATUS_MAX_AGE_SECONDS",
            std::ffi::OsStr::new("60"),
        ),
    ]);
    let passport_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("fixtures/proof-room/finding/cognition-market-qualified-profile")
        .join("transaction-passport.json");
    let report = proof_test_ok(
        verify_transaction_passport_file(&passport_path),
        "verify cognition-market proof bundle through the CLI route",
    );
    assert_eq!(
        report.get("accepted").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let verified_claims = report
        .get("verified_claims")
        .and_then(serde_json::Value::as_array)
        .map(|claims| {
            claims
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    for claim in chio_control_plane::transaction_passport::COGNITION_MARKET_CLAIMS {
        assert!(verified_claims.contains(claim), "missing claim {claim}");
    }
}

#[test]
fn later_root_claim_failure_does_not_reserve_agent_web_replay_ids() {
    let _env_lock = match AGENT_WEB_ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let tempdir = proof_test_ok(tempfile::tempdir(), "create tempdir");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle = tempdir.path().join("bundle");
    proof_test_ok(
        fixture::copy_dir_contents(&source, &bundle),
        "copy Agent Web fixture",
    );
    let replay_store_path = tempdir.path().join("agent-web-replay.sqlite");
    let _env = agent_web_replay_test_env(&replay_store_path);
    let passport_path = bundle.join("transaction-passport.json");
    let expected_report = proof_test_ok(
        verify_transaction_passport_file(&passport_path),
        "read-only Agent Web verification",
    );
    fail_before_root_claim_set_verification_once();

    let error = match verify_transaction_passport_file_and_consume_agent_web_replays(
        &passport_path,
        &expected_report,
    ) {
        Ok(_) => panic!("later root claim failure must reject consuming verification"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("claim set"),
        "unexpected later verification error: {error}"
    );
    assert!(
        replay_store_path.is_file(),
        "consuming verification must reach the Agent Web branch before the root claim failure"
    );

    proof_test_ok(
        verify_transaction_passport_file_and_consume_agent_web_replays(
            &passport_path,
            &expected_report,
        ),
        "retry after later failure must still reserve replay ids",
    );
}

#[test]
fn proof_collect_consumes_replays_only_after_sealing_succeeds() {
    let _env_lock = match AGENT_WEB_ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let tempdir = proof_test_ok(tempfile::tempdir(), "create tempdir");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle = tempdir.path().join("bundle");
    proof_test_ok(
        fixture::copy_dir_contents(&source, &bundle),
        "copy Agent Web fixture",
    );
    let replay_store_path = tempdir.path().join("agent-web-replay.sqlite");
    let _env = agent_web_replay_test_env(&replay_store_path);

    let verifier_path = bundle.join("verifier");
    proof_test_ok(
        std::fs::remove_dir_all(&verifier_path),
        "remove fixture verifier directory",
    );
    proof_test_ok(
        std::fs::write(&verifier_path, b"not a directory"),
        "block verifier report directory",
    );
    let sealing_error = collect::seal_collected_proof_bundle(
        ProofCollectKind::AgentWebEnvelope,
        &bundle,
    );
    assert!(
        sealing_error.is_err(),
        "unwritable verifier output must fail sealing"
    );

    proof_test_ok(
        std::fs::remove_file(&verifier_path),
        "remove verifier path blocker",
    );
    collect::fail_after_replay_reservation_once();
    let interrupted = collect::seal_collected_proof_bundle(
        ProofCollectKind::AgentWebEnvelope,
        &bundle,
    );
    assert!(interrupted.is_err_and(|error| error
        .to_string()
        .contains("injected failure after Agent-Web replay reservation")));
    let pending_signature_path = bundle.join(".bundle-signature.dsse.json.pending");
    assert!(pending_signature_path.is_file());
    assert!(!bundle.join("bundle-signature.dsse.json").exists());
    let replay_reservation_id = chio_core::sha256_hex(&proof_test_ok(
        std::fs::read(&pending_signature_path),
        "read pending bundle signature",
    ));
    let replay_store = proof_test_ok(
        chio_store_sqlite::SqliteAgentWebReplayStore::open(&replay_store_path),
        "open replay reservation store",
    );
    assert_eq!(
        proof_test_ok(
            replay_store.replay_reservation_state(&replay_reservation_id),
            "read pending replay reservation state",
        ),
        Some(chio_store_sqlite::SqliteAgentWebReplayReservationState::Pending)
    );
    collect::fail_after_final_signature_link_once();
    let link_interrupted = collect::seal_collected_proof_bundle(
        ProofCollectKind::AgentWebEnvelope,
        &bundle,
    );
    assert!(link_interrupted.is_err_and(|error| error
        .to_string()
        .contains("injected failure after final bundle signature link")));
    assert!(pending_signature_path.is_file());
    assert!(bundle.join("bundle-signature.dsse.json").is_file());
    assert_eq!(
        proof_test_ok(
            replay_store.replay_reservation_state(&replay_reservation_id),
            "read replay reservation after final link failure",
        ),
        Some(chio_store_sqlite::SqliteAgentWebReplayReservationState::Pending)
    );
    proof_test_ok(
        collect::seal_collected_proof_bundle(ProofCollectKind::AgentWebEnvelope, &bundle),
        "retry after post-reservation failure",
    );
    assert_eq!(
        proof_test_ok(
            replay_store.replay_reservation_state(&replay_reservation_id),
            "read completed replay reservation state",
        ),
        Some(chio_store_sqlite::SqliteAgentWebReplayReservationState::Complete)
    );

    let replay_error = collect::seal_collected_proof_bundle(
        ProofCollectKind::AgentWebEnvelope,
        &bundle,
    );
    assert!(replay_error.is_err_and(|error| error
        .to_string()
        .contains("replayed Standard Webhooks id")));
    for relative_path in [
        "bundle-signature.dsse.json",
        ".bundle-signature.dsse.json.pending",
        "manifest.json",
        "verifier/report.json",
    ] {
        assert!(
            !bundle.join(relative_path).exists(),
            "replay failure must remove uncommitted output {relative_path}"
        );
    }
}

#[test]
fn merge_family_reports_rejects_ok_but_unverified_family_report() {
    let passport = chio_control_plane::transaction_passport::TransactionPassport {
        schema: "chio.transaction.passport.v1".to_string(),
        id: "passport-test".to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        not_before: None,
        expires_at: None,
        issuer: "did:example:issuer".to_string(),
        evidence_graph_sha256: "evidence-graph-sha256".to_string(),
        evidence_graph_path: "evidence-graph.json".to_string(),
        claim_set_sha256: "claim-set-sha256".to_string(),
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: "verifier-policy-sha256".to_string(),
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: "signature".to_string(),
    };
    let rejected_family_report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": "verifier-report-rejected-family",
        "verdict": "failed",
        "accepted": false,
        "state": "failed",
        "verified_claims": []
    });

    let merged = merge_family_verifier_reports(
        &passport,
        "transaction-passport.json".to_string(),
        vec![rejected_family_report],
        "complete",
    );

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
}
