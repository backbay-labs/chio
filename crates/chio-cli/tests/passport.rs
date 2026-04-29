#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, respond_to_oid4vp_request,
    respond_to_passport_presentation_challenge, verify_signed_oid4vp_request_object,
    verify_signed_oid4vp_request_object_with_any_key, verify_signed_public_discovery_transparency,
    verify_signed_public_issuer_discovery, verify_signed_public_verifier_discovery,
    AttestationWindow, ChioCredentialEvidence, ChioPassportJwtVcJsonTypeMetadata,
    ChioPassportSdJwtVcTypeMetadata, Oid4vciCredentialIssuerMetadata, Oid4vciCredentialOffer,
    Oid4vciCredentialRequest, Oid4vciCredentialResponse, Oid4vciIssuedCredential,
    Oid4vciTokenRequest, Oid4vciTokenResponse, Oid4vpPresentationVerification, Oid4vpRequestObject,
    Oid4vpVerifierMetadata, PassportPresentationChallenge, PassportPresentationVerification,
    PortableJwkSet, SignedPublicDiscoveryTransparency, SignedPublicIssuerDiscovery,
    SignedPublicVerifierDiscovery, CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID,
    CHIO_PASSPORT_JWT_VC_JSON_FORMAT, CHIO_PASSPORT_OID4VCI_FORMAT,
    CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_SD_JWT_VC_FORMAT,
    OID4VCI_PRE_AUTHORIZED_GRANT_TYPE, OID4VP_VERIFIER_METADATA_PATH,
};
use chio_did::DidChio;
use chio_kernel::build_checkpoint;
use chio_reputation::{LocalReputationScorecard, MetricValue};
use chio_store_sqlite::SqliteReceiptStore;
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;

fn did_from_public_key(public_key: chio_core::PublicKey) -> DidChio {
    DidChio::from_public_key(public_key).expect("ed25519 key")
}

fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn reserve_listen_addr() -> SocketAddr {
    static NEXT_PORT_OFFSET: AtomicU32 = AtomicU32::new(0);
    const TEST_PORT_BASE: u32 = 15_000;
    const TEST_PORT_SPAN: u32 = 10_000;

    let process_offset = std::process::id() % TEST_PORT_SPAN;
    for _ in 0..TEST_PORT_SPAN {
        let offset = NEXT_PORT_OFFSET.fetch_add(1, Ordering::Relaxed);
        let port = TEST_PORT_BASE + ((process_offset + offset) % TEST_PORT_SPAN);
        let addr = SocketAddr::from(([127, 0, 0, 1], port as u16));
        if let Ok(listener) = TcpListener::bind(addr) {
            let addr = listener.local_addr().expect("listener addr");
            drop(listener);
            return addr;
        }
    }

    panic!("could not reserve local passport test port");
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_child_stderr(child: &mut Child) -> String {
    let Some(stderr) = child.stderr.take() else {
        return String::new();
    };
    let mut reader = std::io::BufReader::new(stderr);
    let mut output = String::new();
    let _ = reader.read_to_string(&mut output);
    output
}

fn spawn_passport_issuance_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    passport_issuance_offers_file: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--passport-issuance-offers-file",
            passport_issuance_offers_file
                .to_str()
                .expect("issuance registry path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn spawn_portable_passport_issuance_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    authority_seed_file: &PathBuf,
    passport_issuance_offers_file: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--authority-seed-file",
            authority_seed_file.to_str().expect("authority seed path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--passport-issuance-offers-file",
            passport_issuance_offers_file
                .to_str()
                .expect("issuance registry path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn portable issuance trust service");
    ServerGuard { child }
}

fn spawn_portable_passport_lifecycle_issuance_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    authority_seed_file: &PathBuf,
    passport_issuance_offers_file: &PathBuf,
    passport_statuses_file: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--authority-seed-file",
            authority_seed_file.to_str().expect("authority seed path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--passport-issuance-offers-file",
            passport_issuance_offers_file
                .to_str()
                .expect("issuance registry path"),
            "--passport-statuses-file",
            passport_statuses_file
                .to_str()
                .expect("status registry path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn portable lifecycle issuance trust service");
    ServerGuard { child }
}

fn spawn_passport_lifecycle_issuance_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    passport_issuance_offers_file: &PathBuf,
    passport_statuses_file: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--passport-issuance-offers-file",
            passport_issuance_offers_file
                .to_str()
                .expect("issuance registry path"),
            "--passport-statuses-file",
            passport_statuses_file
                .to_str()
                .expect("status registry path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn spawn_passport_challenge_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    verifier_challenge_db: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--verifier-challenge-db",
            verifier_challenge_db.to_str().expect("challenge db path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn spawn_passport_interop_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    passport_issuance_offers_file: &PathBuf,
    verifier_challenge_db: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--passport-issuance-offers-file",
            passport_issuance_offers_file
                .to_str()
                .expect("issuance registry path"),
            "--verifier-challenge-db",
            verifier_challenge_db.to_str().expect("challenge db path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn interop trust service");
    ServerGuard { child }
}

fn spawn_portable_oid4vp_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    authority_seed_file: &PathBuf,
    passport_issuance_offers_file: &PathBuf,
    verifier_challenge_db: &PathBuf,
    passport_statuses_file: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--authority-seed-file",
            authority_seed_file.to_str().expect("authority seed path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--passport-issuance-offers-file",
            passport_issuance_offers_file
                .to_str()
                .expect("issuance registry path"),
            "--verifier-challenge-db",
            verifier_challenge_db.to_str().expect("verifier db path"),
            "--passport-statuses-file",
            passport_statuses_file
                .to_str()
                .expect("status registry path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn portable oid4vp trust service");
    ServerGuard { child }
}

fn spawn_portable_oid4vp_trust_service_with_authority_db(
    listen: std::net::SocketAddr,
    service_token: &str,
    advertise_url: &str,
    authority_db_file: &PathBuf,
    passport_issuance_offers_file: &PathBuf,
    verifier_challenge_db: &PathBuf,
    passport_statuses_file: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--authority-db",
            authority_db_file.to_str().expect("authority db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--advertise-url",
            advertise_url,
            "--passport-issuance-offers-file",
            passport_issuance_offers_file
                .to_str()
                .expect("issuance registry path"),
            "--verifier-challenge-db",
            verifier_challenge_db.to_str().expect("verifier db path"),
            "--passport-statuses-file",
            passport_statuses_file
                .to_str()
                .expect("status registry path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn portable oid4vp authority-db trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str, service: &mut ServerGuard) {
    for _ in 0..300 {
        if let Some(status) = service.child.try_wait().expect("poll trust service child") {
            panic!(
                "trust service exited before becoming ready (status {status}): {}",
                read_child_stderr(&mut service.child)
            );
        }
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

fn capability_with_id(id: &str, subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Read],
                    constraints: vec![],
                    max_invocations: Some(20),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 100,
            expires_at: 100_000,
            delegation_chain: vec![],
        },
        issuer,
    )
    .expect("sign capability")
}

fn receipt_with_ts(id: &str, capability_id: &str, timestamp: u64) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/readme.md"
            }))
            .expect("action"),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-passport".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign receipt")
}

fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: 1_710_000_000,
        boundary_pressure: chio_reputation::BoundaryPressureMetrics {
            deny_ratio: MetricValue::Known(0.1),
            policies_observed: 1,
            receipts_observed: 3,
        },
        resource_stewardship: chio_reputation::ResourceStewardshipMetrics {
            average_utilization: MetricValue::Known(0.6),
            fit_score: MetricValue::Known(0.9),
            capped_grants_observed: 1,
        },
        least_privilege: chio_reputation::LeastPrivilegeMetrics {
            score: MetricValue::Known(0.8),
            capabilities_observed: 1,
        },
        history_depth: chio_reputation::HistoryDepthMetrics {
            score: MetricValue::Known(0.7),
            receipt_count: 3,
            active_days: 3,
            first_seen: Some(1_709_900_000),
            last_seen: Some(1_710_000_000),
            span_days: 3,
            activity_ratio: MetricValue::Known(1.0),
        },
        specialization: chio_reputation::SpecializationMetrics {
            score: MetricValue::Known(0.5),
            distinct_tools: 2,
        },
        delegation_hygiene: chio_reputation::DelegationHygieneMetrics {
            score: MetricValue::Known(0.9),
            delegations_observed: 1,
            scope_reduction_rate: MetricValue::Known(1.0),
            ttl_reduction_rate: MetricValue::Known(1.0),
            budget_reduction_rate: MetricValue::Known(1.0),
        },
        reliability: chio_reputation::ReliabilityMetrics {
            score: MetricValue::Known(0.95),
            completion_rate: MetricValue::Known(1.0),
            cancellation_rate: MetricValue::Known(0.0),
            incompletion_rate: MetricValue::Known(0.0),
            receipts_observed: 3,
        },
        incident_correlation: chio_reputation::IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        },
        composite_score: MetricValue::Known(0.82),
        effective_weight_sum: 0.9,
    }
}

fn sample_evidence() -> ChioCredentialEvidence {
    ChioCredentialEvidence {
        query: AttestationWindow {
            since: Some(1_709_900_000),
            until: 1_710_000_000,
        },
        receipt_count: 3,
        receipt_ids: vec![
            "rcpt-1".to_string(),
            "rcpt-2".to_string(),
            "rcpt-3".to_string(),
        ],
        checkpoint_roots: vec!["abc123".to_string()],
        receipt_log_urls: vec!["https://trust.example.com/v1/receipts".to_string()],
        lineage_records: 1,
        uncheckpointed_receipts: 0,
        runtime_attestation: None,
    }
}

fn write_enterprise_identity(path: &PathBuf) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "providerId": "enterprise-login",
            "providerRecordId": "enterprise-login",
            "providerKind": "oidc_jwks",
            "federationMethod": "jwt",
            "principal": "oidc:https://issuer.enterprise.example#sub:user-123",
            "subjectKey": "enterprise-subject-key",
            "tenantId": "tenant-123",
            "organizationId": "org-123",
            "groups": ["eng", "ops"],
            "roles": ["operator"],
            "attributeSources": {
                "principal": "sub",
                "groups": "groups",
                "roles": "roles"
            },
            "trustMaterialRef": "jwks:enterprise-login"
        }))
        .expect("serialize enterprise identity"),
    )
    .expect("write enterprise identity");
}

fn write_passport_artifact(
    path: &PathBuf,
    subject: &Keypair,
    issuer: &Keypair,
    issued_at: u64,
    valid_until: u64,
    suffix: &str,
) -> serde_json::Value {
    let subject_public_key = subject.public_key().to_hex();
    let mut evidence = sample_evidence();
    evidence.query.until = issued_at;
    evidence.receipt_ids = vec![
        format!("rcpt-{suffix}-1"),
        format!("rcpt-{suffix}-2"),
        format!("rcpt-{suffix}-3"),
    ];
    evidence.checkpoint_roots = vec![format!("root-{suffix}")];
    let credential = issue_reputation_credential(
        issuer,
        sample_scorecard(&subject_public_key),
        evidence,
        issued_at,
        valid_until,
    )
    .expect("issue credential");
    let passport = build_agent_passport(
        &did_from_public_key(subject.public_key()).to_string(),
        vec![credential],
    )
    .expect("passport");
    fs::write(
        path,
        serde_json::to_vec_pretty(&passport).expect("serialize passport"),
    )
    .expect("write passport");
    serde_json::from_slice(&serde_json::to_vec(&passport).expect("serialize value"))
        .expect("passport json")
}

fn publish_passport_status(passport_path: &PathBuf, registry_path: &PathBuf) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "status",
            "publish",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
            "--resolve-url",
            "https://trust.example.com/v1/passport/statuses/resolve",
            "--cache-ttl-secs",
            "300",
        ])
        .output()
        .expect("run passport status publish");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse passport status publish")
}

#[test]
fn passport_create_verify_and_present_roundtrip() {
    let receipt_db_path = unique_path("passport", ".sqlite3");
    let passport_path = unique_path("passport", ".json");
    let presented_path = unique_path("passport-presented", ".json");
    let challenge_path = unique_path("passport-challenge", ".json");
    let response_path = unique_path("passport-response", ".json");
    let signing_seed_path = unique_path("passport-signing-seed", ".txt");
    let holder_seed_path = unique_path("passport-holder-seed", ".txt");
    let accept_policy_path = unique_path("passport-policy-accept", ".yaml");
    let reject_policy_path = unique_path("passport-policy-reject", ".yaml");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-passport", &subject, &issuer);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-passport", 101))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-2", "cap-passport", 102))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    let subject_public_key = subject.public_key().to_hex();
    let create = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db"),
            "passport",
            "create",
            "--subject-public-key",
            &subject_public_key,
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--validity-days",
            "30",
            "--require-checkpoints",
            "--receipt-log-url",
            "https://trust.example.com/v1/receipts",
        ])
        .output()
        .expect("run passport create");

    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    assert_eq!(passport["schema"], "chio.agent-passport.v1");
    let subject_did = format!("did:chio:{subject_public_key}");
    assert_eq!(passport["subject"], subject_did);
    assert_eq!(
        passport["credentials"]
            .as_array()
            .expect("credentials array")
            .len(),
        1
    );
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did")
        .to_string();
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(&holder_seed_path, format!("{}\n", subject.seed_hex())).expect("write holder seed");

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "verify",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run passport verify");

    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("passport verified"));

    fs::write(
        &accept_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\nmaxAttestationAgeDays: 30\nrequireCheckpointCoverage: true\nrequireReceiptLogUrls: true\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write accept policy");

    let evaluate_accept = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--policy",
            accept_policy_path.to_str().expect("accept policy path"),
        ])
        .output()
        .expect("run passport evaluate accept");

    assert!(
        evaluate_accept.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate_accept.stdout),
        String::from_utf8_lossy(&evaluate_accept.stderr)
    );
    let accept_json: serde_json::Value =
        serde_json::from_slice(&evaluate_accept.stdout).expect("parse evaluate accept output");
    assert_eq!(accept_json["accepted"], true);
    assert_eq!(accept_json["matchedCredentialIndexes"][0], 0);

    fs::write(
        &reject_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 1000\nrequireCheckpointCoverage: true\nrequireReceiptLogUrls: true\n",
            (composite_score + 0.10).min(1.0)
        ),
    )
    .expect("write reject policy");

    let evaluate_reject = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--policy",
            reject_policy_path.to_str().expect("reject policy path"),
        ])
        .output()
        .expect("run passport evaluate reject");

    assert!(
        evaluate_reject.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate_reject.stdout),
        String::from_utf8_lossy(&evaluate_reject.stderr)
    );
    let reject_json: serde_json::Value =
        serde_json::from_slice(&evaluate_reject.stdout).expect("parse evaluate reject output");
    assert_eq!(reject_json["accepted"], false);
    assert!(reject_json["credentialResults"][0]["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .any(|reason| reason
            .as_str()
            .unwrap_or_default()
            .contains("receipt_count")));

    let present = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "present",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            presented_path.to_str().expect("presented path"),
            "--issuer",
            &issuer_did,
            "--max-credentials",
            "1",
        ])
        .output()
        .expect("run passport present");

    assert!(
        present.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&present.stdout),
        String::from_utf8_lossy(&present.stderr)
    );

    let verify_presented = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "verify",
            "--input",
            presented_path.to_str().expect("presented path"),
        ])
        .output()
        .expect("run presented passport verify");

    assert!(
        verify_presented.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify_presented.stdout),
        String::from_utf8_lossy(&verify_presented.stderr)
    );

    let create_challenge = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "create",
            "--output",
            challenge_path.to_str().expect("challenge path"),
            "--verifier",
            "https://rp.example.com",
            "--ttl-secs",
            "300",
            "--issuer",
            &issuer_did,
            "--max-credentials",
            "1",
            "--policy",
            accept_policy_path.to_str().expect("accept policy path"),
        ])
        .output()
        .expect("run challenge create");

    assert!(
        create_challenge.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_challenge.stdout),
        String::from_utf8_lossy(&create_challenge.stderr)
    );
    let challenge_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&challenge_path).expect("read challenge"))
            .expect("parse challenge");
    assert_eq!(
        challenge_json["schema"],
        "chio.agent-passport-presentation-challenge.v1"
    );

    let respond = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "respond",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_path.to_str().expect("response path"),
        ])
        .output()
        .expect("run challenge respond");

    assert!(
        respond.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond.stdout),
        String::from_utf8_lossy(&respond.stderr)
    );
    let response_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&response_path).expect("read response"))
            .expect("parse response");
    assert_eq!(
        response_document["schema"],
        "chio.agent-passport-presentation-response.v1"
    );

    let verify_response = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "challenge",
            "verify",
            "--input",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
        ])
        .output()
        .expect("run challenge verify");

    assert!(
        verify_response.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify_response.stdout),
        String::from_utf8_lossy(&verify_response.stderr)
    );
    let response_json: serde_json::Value =
        serde_json::from_slice(&verify_response.stdout).expect("parse challenge verify output");
    assert_eq!(response_json["accepted"], true);
    assert_eq!(response_json["subject"], subject_did);
    assert_eq!(response_json["verifier"], "https://rp.example.com");
    assert_eq!(response_json["credentialCount"], 1);
    assert_eq!(response_json["policyEvaluation"]["accepted"], true);

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_file(passport_path);
    let _ = fs::remove_file(presented_path);
    let _ = fs::remove_file(challenge_path);
    let _ = fs::remove_file(response_path);
    let _ = fs::remove_file(signing_seed_path);
    let _ = fs::remove_file(holder_seed_path);
    let _ = fs::remove_file(accept_policy_path);
    let _ = fs::remove_file(reject_policy_path);
}

#[test]
fn passport_create_and_verify_surface_enterprise_identity_provenance() {
    let receipt_db_path = unique_path("passport-enterprise", ".sqlite3");
    let passport_path = unique_path("passport-enterprise", ".json");
    let signing_seed_path = unique_path("passport-enterprise-seed", ".txt");
    let enterprise_identity_path = unique_path("passport-enterprise-identity", ".json");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-passport-enterprise", &subject, &issuer);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-enterprise-1",
                "cap-passport-enterprise",
                101,
            ))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq,
            seq,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    write_enterprise_identity(&enterprise_identity_path);

    let subject_public_key = subject.public_key().to_hex();
    let create = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db"),
            "--json",
            "passport",
            "create",
            "--subject-public-key",
            &subject_public_key,
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--enterprise-identity",
            enterprise_identity_path
                .to_str()
                .expect("enterprise identity path"),
            "--require-checkpoints",
        ])
        .output()
        .expect("run passport create");

    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    assert_eq!(
        passport["enterpriseIdentityProvenance"][0]["providerId"],
        "enterprise-login"
    );
    assert_eq!(
        passport["credentials"][0]["enterpriseIdentityProvenance"]["providerId"],
        "enterprise-login"
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "verify",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run passport verify");

    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    let verification: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("parse verification");
    assert_eq!(
        verification["enterpriseIdentityProvenance"][0]["providerId"],
        "enterprise-login"
    );
}

#[test]
fn passport_status_registry_supports_publish_supersede_and_revoke() {
    let passport_a_path = unique_path("passport-lifecycle-a", ".json");
    let passport_b_path = unique_path("passport-lifecycle-b", ".json");
    let registry_path = unique_path("passport-status-registry", ".json");
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let _passport_a = write_passport_artifact(
        &passport_a_path,
        &subject,
        &issuer,
        now.saturating_sub(120),
        now + 86_400,
        "lifecycle-a",
    );
    let _passport_b = write_passport_artifact(
        &passport_b_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 172_800,
        "lifecycle-b",
    );

    let publish_a = publish_passport_status(&passport_a_path, &registry_path);
    assert_eq!(publish_a["status"], "active");
    assert_eq!(publish_a["distribution"]["cacheTtlSecs"], 300);
    assert_eq!(
        publish_a["distribution"]["resolveUrls"][0],
        "https://trust.example.com/v1/passport/statuses/resolve"
    );

    let verify_a = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "verify",
            "--input",
            passport_a_path.to_str().expect("passport a path"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run passport verify");

    assert!(
        verify_a.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify_a.stdout),
        String::from_utf8_lossy(&verify_a.stderr)
    );
    let verify_a_json: serde_json::Value =
        serde_json::from_slice(&verify_a.stdout).expect("parse verify output");
    assert_eq!(verify_a_json["passportLifecycle"]["state"], "active");

    let publish_b = publish_passport_status(&passport_b_path, &registry_path);
    assert_eq!(publish_b["status"], "active");

    let resolve_a = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "status",
            "resolve",
            "--passport-id",
            publish_a["passportId"].as_str().expect("passport id"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run passport status resolve");

    assert!(
        resolve_a.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&resolve_a.stdout),
        String::from_utf8_lossy(&resolve_a.stderr)
    );
    let resolve_a_json: serde_json::Value =
        serde_json::from_slice(&resolve_a.stdout).expect("parse resolve output");
    assert_eq!(resolve_a_json["state"], "superseded");
    assert_eq!(resolve_a_json["supersededBy"], publish_b["passportId"]);

    let revoke_b = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "status",
            "revoke",
            "--passport-id",
            publish_b["passportId"].as_str().expect("passport id"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
            "--reason",
            "operator revoked",
        ])
        .output()
        .expect("run passport status revoke");

    assert!(
        revoke_b.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&revoke_b.stdout),
        String::from_utf8_lossy(&revoke_b.stderr)
    );
    let revoke_b_json: serde_json::Value =
        serde_json::from_slice(&revoke_b.stdout).expect("parse revoke output");
    assert_eq!(revoke_b_json["status"], "revoked");
    assert_eq!(revoke_b_json["revokedReason"], "operator revoked");

    let get_b = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "status",
            "get",
            "--passport-id",
            publish_b["passportId"].as_str().expect("passport id"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run passport status get");

    assert!(
        get_b.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&get_b.stdout),
        String::from_utf8_lossy(&get_b.stderr)
    );
    let get_b_json: serde_json::Value =
        serde_json::from_slice(&get_b.stdout).expect("parse get output");
    assert_eq!(get_b_json["status"], "revoked");

    let _ = fs::remove_file(passport_a_path);
    let _ = fs::remove_file(passport_b_path);
    let _ = fs::remove_file(registry_path);
}

#[test]
fn passport_lifecycle_policy_enforcement_rejects_superseded_and_revoked_passports() {
    let passport_a_path = unique_path("passport-lifecycle-policy-a", ".json");
    let passport_b_path = unique_path("passport-lifecycle-policy-b", ".json");
    let registry_path = unique_path("passport-lifecycle-policy-registry", ".json");
    let policy_path = unique_path("passport-lifecycle-policy", ".yaml");
    let challenge_path = unique_path("passport-lifecycle-challenge", ".json");
    let response_path = unique_path("passport-lifecycle-response", ".json");
    let holder_seed_path = unique_path("passport-lifecycle-holder-seed", ".txt");
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport_a = write_passport_artifact(
        &passport_a_path,
        &subject,
        &issuer,
        now.saturating_sub(120),
        now + 86_400,
        "policy-a",
    );
    let _passport_b = write_passport_artifact(
        &passport_b_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 172_800,
        "policy-b",
    );
    let issuer_did = passport_a["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did")
        .to_string();

    fs::write(
        &policy_path,
        format!("issuerAllowlist:\n  - \"{issuer_did}\"\nrequireActiveLifecycle: true\n"),
    )
    .expect("write lifecycle policy");
    fs::write(&holder_seed_path, format!("{}\n", subject.seed_hex())).expect("write holder seed");

    let _publish_a = publish_passport_status(&passport_a_path, &registry_path);
    let publish_b = publish_passport_status(&passport_b_path, &registry_path);

    let evaluate_a = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_a_path.to_str().expect("passport a path"),
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run evaluate superseded passport");

    assert!(
        evaluate_a.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate_a.stdout),
        String::from_utf8_lossy(&evaluate_a.stderr)
    );
    let evaluate_a_json: serde_json::Value =
        serde_json::from_slice(&evaluate_a.stdout).expect("parse evaluate superseded");
    assert_eq!(evaluate_a_json["accepted"], false);
    assert_eq!(
        evaluate_a_json["verification"]["passportLifecycle"]["state"],
        "superseded"
    );
    assert!(evaluate_a_json["passportReasons"][0]
        .as_str()
        .unwrap_or_default()
        .contains("superseded"));

    let revoke_b = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "status",
            "revoke",
            "--passport-id",
            publish_b["passportId"].as_str().expect("passport id"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
            "--reason",
            "compromised",
        ])
        .output()
        .expect("run revoke passport");

    assert!(
        revoke_b.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&revoke_b.stdout),
        String::from_utf8_lossy(&revoke_b.stderr)
    );

    let evaluate_b = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_b_path.to_str().expect("passport b path"),
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run evaluate revoked passport");

    assert!(
        evaluate_b.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate_b.stdout),
        String::from_utf8_lossy(&evaluate_b.stderr)
    );
    let evaluate_b_json: serde_json::Value =
        serde_json::from_slice(&evaluate_b.stdout).expect("parse evaluate revoked");
    assert_eq!(evaluate_b_json["accepted"], false);
    assert_eq!(
        evaluate_b_json["verification"]["passportLifecycle"]["state"],
        "revoked"
    );
    assert!(evaluate_b_json["passportReasons"][0]
        .as_str()
        .unwrap_or_default()
        .contains("revoked"));

    let create_challenge = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "create",
            "--output",
            challenge_path.to_str().expect("challenge path"),
            "--verifier",
            "https://rp.example.com",
            "--ttl-secs",
            "300",
            "--policy",
            policy_path.to_str().expect("policy path"),
        ])
        .output()
        .expect("run lifecycle challenge create");

    assert!(
        create_challenge.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_challenge.stdout),
        String::from_utf8_lossy(&create_challenge.stderr)
    );

    let respond = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "respond",
            "--input",
            passport_b_path.to_str().expect("passport b path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_path.to_str().expect("response path"),
        ])
        .output()
        .expect("run lifecycle challenge respond");

    assert!(
        respond.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond.stdout),
        String::from_utf8_lossy(&respond.stderr)
    );

    let verify_response = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "challenge",
            "verify",
            "--input",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--passport-statuses-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run lifecycle challenge verify");

    assert!(
        verify_response.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify_response.stdout),
        String::from_utf8_lossy(&verify_response.stderr)
    );
    let verify_response_json: serde_json::Value =
        serde_json::from_slice(&verify_response.stdout).expect("parse challenge verify");
    assert_eq!(verify_response_json["accepted"], false);
    assert_eq!(
        verify_response_json["passportLifecycle"]["state"],
        "revoked"
    );
    assert!(
        verify_response_json["policyEvaluation"]["passportReasons"][0]
            .as_str()
            .unwrap_or_default()
            .contains("revoked")
    );
    assert_eq!(
        verify_response_json["passportId"],
        publish_b["passportId"].as_str().expect("passport id")
    );

    let _ = fs::remove_file(passport_a_path);
    let _ = fs::remove_file(passport_b_path);
    let _ = fs::remove_file(registry_path);
    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(challenge_path);
    let _ = fs::remove_file(response_path);
    let _ = fs::remove_file(holder_seed_path);
}

#[test]
fn passport_create_require_checkpoints_fails_for_uncheckpointed_receipts() {
    let receipt_db_path = unique_path("passport-no-checkpoint", ".sqlite3");
    let passport_path = unique_path("passport-no-checkpoint", ".json");
    let signing_seed_path = unique_path("passport-no-checkpoint-seed", ".txt");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-passport-no-checkpoint", &subject, &issuer);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-uncheckpointed",
                "cap-passport-no-checkpoint",
                101,
            ))
            .expect("append receipt");
    }

    let create = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db"),
            "passport",
            "create",
            "--subject-public-key",
            &subject.public_key().to_hex(),
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--require-checkpoints",
        ])
        .output()
        .expect("run passport create");

    assert!(
        !create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(String::from_utf8_lossy(&create.stderr).contains("uncheckpointed"));

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_file(passport_path);
    let _ = fs::remove_file(signing_seed_path);
}

#[test]
fn passport_policy_reference_flow_is_replay_safe_locally() {
    let receipt_db_path = unique_path("passport-ref", ".sqlite3");
    let passport_path = unique_path("passport-ref", ".json");
    let challenge_path = unique_path("passport-ref-challenge", ".json");
    let response_path = unique_path("passport-ref-response", ".json");
    let signing_seed_path = unique_path("passport-ref-signing-seed", ".txt");
    let holder_seed_path = unique_path("passport-ref-holder-seed", ".txt");
    let verifier_seed_path = unique_path("passport-ref-verifier-seed", ".txt");
    let raw_policy_path = unique_path("passport-ref-policy", ".yaml");
    let signed_policy_path = unique_path("passport-ref-policy-doc", ".json");
    let policy_registry_path = unique_path("passport-ref-policy-registry", ".json");
    let challenge_db_path = unique_path("passport-ref-challenge-store", ".sqlite3");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-passport-ref", &subject, &issuer);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-ref-1",
                "cap-passport-ref",
                101,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-ref-2",
                "cap-passport-ref",
                102,
            ))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    let subject_public_key = subject.public_key().to_hex();
    let create = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db"),
            "passport",
            "create",
            "--subject-public-key",
            &subject_public_key,
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--validity-days",
            "30",
            "--require-checkpoints",
            "--receipt-log-url",
            "https://trust.example.com/v1/receipts",
        ])
        .output()
        .expect("run passport create");
    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did")
        .to_string();
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(&holder_seed_path, format!("{}\n", subject.seed_hex())).expect("write holder seed");
    fs::write(
        &raw_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\nrequireCheckpointCoverage: true\nrequireReceiptLogUrls: true\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write raw verifier policy");

    let create_policy = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "policy",
            "create",
            "--output",
            signed_policy_path.to_str().expect("signed policy path"),
            "--policy-id",
            "rp-default",
            "--verifier",
            "https://rp.example.com",
            "--signing-seed-file",
            verifier_seed_path.to_str().expect("verifier seed path"),
            "--policy",
            raw_policy_path.to_str().expect("raw policy path"),
            "--expires-at",
            "1900000000",
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
        ])
        .output()
        .expect("run passport policy create");
    assert!(
        create_policy.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_policy.stdout),
        String::from_utf8_lossy(&create_policy.stderr)
    );

    let create_challenge = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "create",
            "--output",
            challenge_path.to_str().expect("challenge path"),
            "--verifier",
            "https://rp.example.com",
            "--policy-id",
            "rp-default",
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
            "--verifier-challenge-db",
            challenge_db_path.to_str().expect("challenge db path"),
        ])
        .output()
        .expect("run passport challenge create");
    assert!(
        create_challenge.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_challenge.stdout),
        String::from_utf8_lossy(&create_challenge.stderr)
    );

    let challenge: serde_json::Value =
        serde_json::from_slice(&fs::read(&challenge_path).expect("read challenge"))
            .expect("parse challenge");
    assert_eq!(
        challenge["schema"],
        "chio.agent-passport-presentation-challenge.v1"
    );
    assert_eq!(challenge["policyRef"]["policyId"], "rp-default");
    assert!(challenge["challengeId"].as_str().is_some());
    assert!(challenge["policy"].is_null());

    let respond = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "respond",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_path.to_str().expect("response path"),
        ])
        .output()
        .expect("run challenge respond");
    assert!(
        respond.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond.stdout),
        String::from_utf8_lossy(&respond.stderr)
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "challenge",
            "verify",
            "--input",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
            "--verifier-challenge-db",
            challenge_db_path.to_str().expect("challenge db path"),
        ])
        .output()
        .expect("run challenge verify");
    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("parse challenge verify json");
    assert_eq!(verify_json["accepted"], true);
    assert_eq!(verify_json["policyEvaluated"], true);
    assert_eq!(verify_json["policyId"], "rp-default");
    assert_eq!(verify_json["policySource"], "registry:rp-default");
    assert_eq!(verify_json["replayState"], "consumed");
    assert!(verify_json["challengeId"].as_str().is_some());

    let replay = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "verify",
            "--input",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
            "--verifier-challenge-db",
            challenge_db_path.to_str().expect("challenge db path"),
        ])
        .output()
        .expect("run replay challenge verify");
    assert!(
        !replay.status.success(),
        "replayed challenge verification should fail\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("already been consumed"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[test]
fn passport_cli_supports_multi_issuer_verify_evaluate_and_present() {
    let passport_path = unique_path("passport-multi-issuer", ".json");
    let presented_path = unique_path("passport-multi-issuer-presented", ".json");
    let verify_policy_path = unique_path("passport-multi-issuer-policy", ".yaml");

    let subject_public_key = Keypair::from_seed(&[7u8; 32]).public_key();
    let subject_key = subject_public_key.to_hex();
    let subject_did = did_from_public_key(subject_public_key);
    let credential_a = issue_reputation_credential(
        &Keypair::from_seed(&[1u8; 32]),
        sample_scorecard(&subject_key),
        sample_evidence(),
        1_900_000_000,
        1_900_086_400,
    )
    .expect("credential a");
    let credential_b = issue_reputation_credential(
        &Keypair::from_seed(&[2u8; 32]),
        sample_scorecard(&subject_key),
        sample_evidence(),
        1_900_000_000,
        1_900_086_400,
    )
    .expect("credential b");
    let issuer_a = credential_a.unsigned.issuer.clone();
    let issuer_b = credential_b.unsigned.issuer.clone();
    let passport = build_agent_passport(
        &subject_did.to_string(),
        vec![credential_a.clone(), credential_b.clone()],
    )
    .expect("passport");
    fs::write(
        &passport_path,
        serde_json::to_vec_pretty(&passport).expect("serialize passport"),
    )
    .expect("write passport");
    fs::write(
        &verify_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_a}\"\nminCompositeScore: 0.7\nminReceiptCount: 2\nminLineageRecords: 1\n"
        ),
    )
    .expect("write verifier policy");

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "verify",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run passport verify");
    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("parse verify output");
    assert_eq!(verify_json["issuer"], serde_json::Value::Null);
    assert_eq!(verify_json["issuerCount"], 2);
    let issuers = verify_json["issuers"].as_array().expect("issuers array");
    assert_eq!(issuers.len(), 2);
    assert!(issuers
        .iter()
        .any(|issuer| issuer == &serde_json::json!(issuer_a)));
    assert!(issuers
        .iter()
        .any(|issuer| issuer == &serde_json::json!(issuer_b)));

    let evaluate = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--policy",
            verify_policy_path.to_str().expect("verify policy path"),
        ])
        .output()
        .expect("run passport evaluate");
    assert!(
        evaluate.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate.stdout),
        String::from_utf8_lossy(&evaluate.stderr)
    );
    let evaluate_json: serde_json::Value =
        serde_json::from_slice(&evaluate.stdout).expect("parse evaluate output");
    assert_eq!(evaluate_json["accepted"], true);
    assert_eq!(evaluate_json["verification"]["issuerCount"], 2);
    assert_eq!(
        evaluate_json["matchedCredentialIndexes"],
        serde_json::json!([0])
    );
    assert_eq!(
        evaluate_json["matchedIssuers"],
        serde_json::json!([issuer_a])
    );
    assert_eq!(
        evaluate_json["credentialResults"][0]["issuer"],
        evaluate_json["matchedIssuers"][0]
    );
    assert_eq!(evaluate_json["credentialResults"][0]["accepted"], true);
    assert_eq!(evaluate_json["credentialResults"][1]["issuer"], issuer_b);
    assert_eq!(evaluate_json["credentialResults"][1]["accepted"], false);

    let present = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "present",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            presented_path.to_str().expect("presented path"),
            "--issuer",
            &credential_b.unsigned.issuer,
            "--max-credentials",
            "1",
        ])
        .output()
        .expect("run passport present");
    assert!(
        present.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&present.stdout),
        String::from_utf8_lossy(&present.stderr)
    );
    let presented: serde_json::Value =
        serde_json::from_slice(&fs::read(&presented_path).expect("read presented passport"))
            .expect("parse presented passport");
    assert_eq!(
        presented["credentials"]
            .as_array()
            .expect("credentials")
            .len(),
        1
    );
    assert_eq!(
        presented["credentials"][0]["issuer"],
        credential_b.unsigned.issuer
    );
}

#[test]
fn passport_issuance_cli_local_roundtrip_enforces_single_use() {
    let passport_path = unique_path("passport-issuance-local", ".json");
    let issuance_registry_path = unique_path("passport-issuance-local-registry", ".json");
    let offer_path = unique_path("passport-issuance-offer", ".json");
    let token_path = unique_path("passport-issuance-token", ".json");
    let delivered_path = unique_path("passport-issuance-delivered", ".json");
    let issuer_url = "https://trust.example.com";

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = current_unix_secs();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(3600),
        "issuance-local",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let metadata = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "metadata",
            "--issuer-url",
            issuer_url,
        ])
        .output()
        .expect("run passport issuance metadata");
    assert!(
        metadata.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&metadata.stdout),
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata_json: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("parse metadata output");
    assert_eq!(metadata_json["credentialIssuer"], issuer_url);
    assert_eq!(
        metadata_json["tokenEndpoint"],
        format!("{issuer_url}/v1/passport/issuance/token")
    );
    assert_eq!(
        metadata_json["credentialConfigurationsSupported"]["chio_agent_passport"]["format"],
        "chio-agent-passport+json"
    );

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            offer_path.to_str().expect("offer path"),
            "--issuer-url",
            issuer_url,
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
            "--ttl-secs",
            "300",
        ])
        .output()
        .expect("run passport issuance offer");
    assert!(
        offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    let offer_json: serde_json::Value =
        serde_json::from_slice(&offer.stdout).expect("parse offer output");
    assert_eq!(offer_json["state"], "offered");
    assert_eq!(offer_json["offer"]["credentialIssuer"], issuer_url);
    assert_eq!(
        offer_json["offer"]["credentialConfigurationIds"],
        serde_json::json!(["chio_agent_passport"])
    );

    let token = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "token",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--output",
            token_path.to_str().expect("token path"),
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
        ])
        .output()
        .expect("run passport issuance token");
    assert!(
        token.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&token.stdout),
        String::from_utf8_lossy(&token.stderr)
    );
    let token_json: serde_json::Value =
        serde_json::from_slice(&token.stdout).expect("parse token output");
    assert_eq!(token_json["tokenType"], "Bearer");
    assert!(
        token_json["accessToken"]
            .as_str()
            .expect("access token")
            .len()
            > 10
    );

    let token_replay = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "issuance",
            "token",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
        ])
        .output()
        .expect("run replay token redemption");
    assert!(
        !token_replay.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&token_replay.stdout),
        String::from_utf8_lossy(&token_replay.stderr)
    );
    let replay_error = format!(
        "{}{}",
        String::from_utf8_lossy(&token_replay.stdout),
        String::from_utf8_lossy(&token_replay.stderr)
    );
    assert!(replay_error.contains("already been redeemed"));

    let credential = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--output",
            delivered_path.to_str().expect("delivered path"),
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
        ])
        .output()
        .expect("run passport issuance credential");
    assert!(
        credential.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&credential.stdout),
        String::from_utf8_lossy(&credential.stderr)
    );
    let credential_json: serde_json::Value =
        serde_json::from_slice(&credential.stdout).expect("parse credential output");
    assert_eq!(credential_json["format"], "chio-agent-passport+json");
    assert_eq!(credential_json["credential"]["subject"], subject_did);
    let delivered_passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&delivered_path).expect("read delivered passport"))
            .expect("parse delivered passport");
    assert_eq!(delivered_passport["subject"], subject_did);

    let credential_replay = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
        ])
        .output()
        .expect("run replay credential redemption");
    assert!(
        !credential_replay.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&credential_replay.stdout),
        String::from_utf8_lossy(&credential_replay.stderr)
    );
    let credential_replay_error = format!(
        "{}{}",
        String::from_utf8_lossy(&credential_replay.stdout),
        String::from_utf8_lossy(&credential_replay.stderr)
    );
    assert!(credential_replay_error.contains("already been issued"));
}

#[test]
fn passport_issuance_offer_rejects_unsupported_configuration_id() {
    let passport_path = unique_path("passport-issuance-invalid-config", ".json");
    let issuance_registry_path = unique_path("passport-issuance-invalid-config-registry", ".json");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = current_unix_secs();
    write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(3600),
        "issuance-invalid-config",
    );

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--issuer-url",
            "https://trust.example.com",
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
            "--credential-configuration-id",
            "unsupported_profile",
        ])
        .output()
        .expect("run invalid passport issuance offer");
    assert!(
        !offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    let error_text = format!(
        "{}{}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    assert!(error_text.contains("unsupported credential_configuration_id"));
}

#[test]
fn passport_issuance_remote_roundtrip_uses_public_metadata_and_remote_registry() {
    let passport_path = unique_path("passport-issuance-remote", ".json");
    let issuance_registry_path = unique_path("passport-issuance-remote-registry", ".json");
    let offer_path = unique_path("passport-issuance-remote-offer", ".json");
    let token_path = unique_path("passport-issuance-remote-token", ".json");
    let delivered_path = unique_path("passport-issuance-remote-delivered", ".json");
    let advertise_url = "https://issuer.example.com";

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = current_unix_secs();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(3600),
        "issuance-remote",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let listen = reserve_listen_addr();
    let service_token = "passport-issuance-remote-token";
    let mut service = spawn_passport_issuance_trust_service(
        listen,
        service_token,
        advertise_url,
        &issuance_registry_path,
    );
    let client = Client::builder().build().expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url, &mut service);

    let public_metadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("request issuer metadata");
    assert_eq!(public_metadata.status(), reqwest::StatusCode::OK);
    let public_metadata_json: serde_json::Value =
        public_metadata.json().expect("parse issuer metadata");
    assert_eq!(public_metadata_json["credentialIssuer"], advertise_url);

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            offer_path.to_str().expect("offer path"),
            "--ttl-secs",
            "300",
        ])
        .output()
        .expect("run remote passport issuance offer");
    assert!(
        offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    let offer_json: serde_json::Value =
        serde_json::from_slice(&offer.stdout).expect("parse remote offer output");
    assert_eq!(offer_json["offer"]["credentialIssuer"], advertise_url);

    let token = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "issuance",
            "token",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--output",
            token_path.to_str().expect("token path"),
        ])
        .output()
        .expect("run remote passport issuance token");
    assert!(
        token.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&token.stdout),
        String::from_utf8_lossy(&token.stderr)
    );

    let credential = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--output",
            delivered_path.to_str().expect("delivered path"),
        ])
        .output()
        .expect("run remote passport issuance credential");
    assert!(
        credential.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&credential.stdout),
        String::from_utf8_lossy(&credential.stderr)
    );
    let credential_json: serde_json::Value =
        serde_json::from_slice(&credential.stdout).expect("parse remote credential output");
    assert_eq!(credential_json["format"], "chio-agent-passport+json");
    assert_eq!(credential_json["credential"]["subject"], subject_did);
}

#[test]
fn passport_oid4vci_local_offer_token_and_credential_roundtrip_is_replay_safe() {
    let passport_path = unique_path("passport-oid4vci-local", ".json");
    let offer_path = unique_path("passport-oid4vci-local-offer", ".json");
    let token_path = unique_path("passport-oid4vci-local-token", ".json");
    let delivered_path = unique_path("passport-oid4vci-local-delivered", ".json");
    let registry_path = unique_path("passport-oid4vci-local-registry", ".json");
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(120),
        now + 86_400,
        "oid4vci-local",
    );

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            offer_path.to_str().expect("offer path"),
            "--issuer-url",
            "https://trust.example.com",
            "--passport-issuance-offers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local issuance offer");
    assert!(
        offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    let offer_json: serde_json::Value =
        serde_json::from_slice(&offer.stdout).expect("parse offer output");
    assert_eq!(offer_json["state"], "offered");
    assert_eq!(
        offer_json["offer"]["credentialIssuer"],
        "https://trust.example.com"
    );

    let token = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "token",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--output",
            token_path.to_str().expect("token path"),
            "--passport-issuance-offers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local issuance token");
    assert!(
        token.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&token.stdout),
        String::from_utf8_lossy(&token.stderr)
    );
    let token_json: serde_json::Value =
        serde_json::from_slice(&token.stdout).expect("parse token output");
    assert_eq!(token_json["tokenType"], "Bearer");

    let credential = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--output",
            delivered_path.to_str().expect("delivered path"),
            "--passport-issuance-offers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run local issuance credential");
    assert!(
        credential.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&credential.stdout),
        String::from_utf8_lossy(&credential.stderr)
    );
    let credential_json: serde_json::Value =
        serde_json::from_slice(&credential.stdout).expect("parse credential output");
    assert_eq!(credential_json["format"], CHIO_PASSPORT_OID4VCI_FORMAT);
    assert_eq!(
        credential_json["credential"]["subject"],
        passport["subject"]
    );
    let delivered_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&delivered_path).expect("read delivered passport"))
            .expect("parse delivered passport");
    assert_eq!(delivered_json["subject"], passport["subject"]);

    let replay = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--passport-issuance-offers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("rerun local issuance credential");
    assert!(
        !replay.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(String::from_utf8_lossy(&replay.stderr).contains("already been issued"));
}

#[test]
fn passport_oid4vci_remote_metadata_and_fail_closed_profile_validation() {
    let passport_path = unique_path("passport-oid4vci-remote", ".json");
    let offer_path = unique_path("passport-oid4vci-remote-offer", ".json");
    let token_path = unique_path("passport-oid4vci-remote-token", ".json");
    let delivered_path = unique_path("passport-oid4vci-remote-delivered", ".json");
    let registry_path = unique_path("passport-oid4vci-remote-registry", ".json");
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(120),
        now + 86_400,
        "oid4vci-remote",
    );

    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-issuance-service-token";
    let mut service =
        spawn_passport_issuance_trust_service(listen, service_token, &base_url, &registry_path);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .expect("build client");
    wait_for_trust_service(&client, &base_url, &mut service);

    let metadata = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "issuance",
            "metadata",
        ])
        .output()
        .expect("run remote issuance metadata");
    assert!(
        metadata.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&metadata.stdout),
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata_json: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("parse metadata output");
    assert_eq!(metadata_json["credentialIssuer"], base_url);
    assert_eq!(
        metadata_json["credentialEndpoint"],
        format!("{base_url}/v1/passport/issuance/credential")
    );

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            offer_path.to_str().expect("offer path"),
        ])
        .output()
        .expect("run remote issuance offer");
    assert!(
        offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );

    let token = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "issuance",
            "token",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--output",
            token_path.to_str().expect("token path"),
        ])
        .output()
        .expect("run remote issuance token");
    assert!(
        token.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&token.stdout),
        String::from_utf8_lossy(&token.stderr)
    );

    let wrong_profile = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--credential-configuration-id",
            "unsupported-profile",
        ])
        .output()
        .expect("run remote issuance credential with wrong config");
    assert!(
        !wrong_profile.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&wrong_profile.stdout),
        String::from_utf8_lossy(&wrong_profile.stderr)
    );
    assert!(String::from_utf8_lossy(&wrong_profile.stderr).contains("unsupported"));

    let credential = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--output",
            delivered_path.to_str().expect("delivered path"),
        ])
        .output()
        .expect("run remote issuance credential");
    assert!(
        credential.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&credential.stdout),
        String::from_utf8_lossy(&credential.stderr)
    );
    let credential_json: serde_json::Value =
        serde_json::from_slice(&credential.stdout).expect("parse remote credential output");
    assert_eq!(credential_json["format"], CHIO_PASSPORT_OID4VCI_FORMAT);
    assert_eq!(
        credential_json["credential"]["subject"],
        passport["subject"]
    );
    let delivered_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&delivered_path).expect("read delivered passport"))
            .expect("parse delivered passport");
    assert_eq!(delivered_json["subject"], passport["subject"]);
}

#[test]
fn passport_issuance_local_with_published_status_attaches_portable_lifecycle_reference() {
    let passport_path = unique_path("passport-issuance-local-status", ".json");
    let status_registry_path = unique_path("passport-status-local-registry", ".json");
    let issuance_registry_path = unique_path("passport-issuance-local-status-registry", ".json");
    let offer_path = unique_path("passport-issuance-local-status-offer", ".json");
    let token_path = unique_path("passport-issuance-local-status-token", ".json");
    let delivered_path = unique_path("passport-issuance-local-status-delivered", ".json");
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "issuance-local-status",
    );
    let published = publish_passport_status(&passport_path, &status_registry_path);
    let issuer_url = "https://trust.example.com";
    let public_status_url = "https://trust.example.com/v1/public/passport/statuses/resolve";

    let metadata = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "metadata",
            "--issuer-url",
            issuer_url,
            "--passport-status-url",
            public_status_url,
            "--passport-status-cache-ttl-secs",
            "300",
        ])
        .output()
        .expect("run local passport issuance metadata");
    assert!(
        metadata.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&metadata.stdout),
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata_json: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("parse local metadata");
    assert_eq!(
        metadata_json["chioProfile"]["passportStatusDistribution"]["resolveUrls"][0],
        public_status_url
    );

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            offer_path.to_str().expect("offer path"),
            "--issuer-url",
            issuer_url,
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
            "--passport-statuses-file",
            status_registry_path.to_str().expect("status registry path"),
        ])
        .output()
        .expect("run local issuance offer with status registry");
    assert!(
        offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );

    let token = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "token",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--output",
            token_path.to_str().expect("token path"),
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
        ])
        .output()
        .expect("run local issuance token with status registry");
    assert!(
        token.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&token.stdout),
        String::from_utf8_lossy(&token.stderr)
    );

    let credential = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
            "--output",
            delivered_path.to_str().expect("delivered path"),
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
            "--passport-statuses-file",
            status_registry_path.to_str().expect("status registry path"),
        ])
        .output()
        .expect("run local issuance credential with status registry");
    assert!(
        credential.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&credential.stdout),
        String::from_utf8_lossy(&credential.stderr)
    );
    let credential_json: serde_json::Value =
        serde_json::from_slice(&credential.stdout).expect("parse local credential response");
    assert_eq!(credential_json["format"], CHIO_PASSPORT_OID4VCI_FORMAT);
    assert_eq!(
        credential_json["credential"]["subject"],
        passport["subject"]
    );
    assert_eq!(
        credential_json["chioCredentialContext"]["passportStatus"]["passportId"],
        published["passportId"]
    );
    assert_eq!(
        credential_json["chioCredentialContext"]["passportStatus"]["distribution"]["resolveUrls"]
            [0],
        "https://trust.example.com/v1/passport/statuses/resolve"
    );
}

#[test]
fn passport_issuance_metadata_rejects_public_status_distribution_without_cache_ttl() {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "issuance",
            "metadata",
            "--issuer-url",
            "https://trust.example.com",
            "--passport-status-url",
            "https://trust.example.com/v1/public/passport/statuses/resolve",
        ])
        .output()
        .expect("run local passport issuance metadata without cache ttl");
    assert!(
        !output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("cache_ttl_secs"));
}

#[test]
fn passport_issuance_remote_requires_published_status_and_exposes_public_resolution() {
    let passport_path = unique_path("passport-issuance-remote-status", ".json");
    let issuance_registry_path = unique_path("passport-issuance-remote-status-registry", ".json");
    let status_registry_path = unique_path("passport-status-remote-registry", ".json");
    let offer_path = unique_path("passport-issuance-remote-status-offer", ".json");
    let token_path = unique_path("passport-issuance-remote-status-token", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let advertise_url = format!("https://trust-status-{}.example.com", listen.port());
    let service_token = "passport-issuance-status-service-token";
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "issuance-remote-status",
    );

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .expect("http client");
    let mut service = spawn_passport_lifecycle_issuance_trust_service(
        listen,
        service_token,
        &advertise_url,
        &issuance_registry_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let missing_status_offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            offer_path.to_str().expect("offer path"),
        ])
        .output()
        .expect("run remote issuance offer without published status");
    assert!(
        !missing_status_offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&missing_status_offer.stdout),
        String::from_utf8_lossy(&missing_status_offer.stderr)
    );
    assert!(String::from_utf8_lossy(&missing_status_offer.stderr)
        .contains("must be published into the lifecycle registry"));

    let publish = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "status",
            "publish",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run remote passport status publish");
    assert!(
        publish.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish.stdout),
        String::from_utf8_lossy(&publish.stderr)
    );
    let publish_json: serde_json::Value =
        serde_json::from_slice(&publish.stdout).expect("parse remote publish response");
    assert_eq!(
        publish_json["distribution"]["resolveUrls"][0],
        format!("{advertise_url}/v1/public/passport/statuses/resolve")
    );

    let metadata = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "issuance",
            "metadata",
        ])
        .output()
        .expect("run remote metadata with public lifecycle profile");
    assert!(
        metadata.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&metadata.stdout),
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata_json: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("parse remote metadata");
    assert_eq!(
        metadata_json["chioProfile"]["passportStatusDistribution"]["resolveUrls"][0],
        format!("{advertise_url}/v1/public/passport/statuses/resolve")
    );

    let public_resolve = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "status",
            "resolve",
            "--passport-id",
            publish_json["passportId"].as_str().expect("passport id"),
        ])
        .output()
        .expect("run public passport status resolve");
    assert!(
        public_resolve.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&public_resolve.stdout),
        String::from_utf8_lossy(&public_resolve.stderr)
    );
    let public_resolve_json: serde_json::Value =
        serde_json::from_slice(&public_resolve.stdout).expect("parse public resolve");
    assert_eq!(public_resolve_json["state"], "active");
    assert_eq!(public_resolve_json["source"], "registry:trust-control");

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            offer_path.to_str().expect("offer path"),
        ])
        .output()
        .expect("run remote issuance offer after publish");
    assert!(
        offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );

    let token = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "issuance",
            "token",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--output",
            token_path.to_str().expect("token path"),
        ])
        .output()
        .expect("run remote token after publish");
    assert!(
        token.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&token.stdout),
        String::from_utf8_lossy(&token.stderr)
    );

    let credential = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "passport",
            "issuance",
            "credential",
            "--offer",
            offer_path.to_str().expect("offer path"),
            "--token",
            token_path.to_str().expect("token path"),
        ])
        .output()
        .expect("run remote credential after publish");
    assert!(
        credential.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&credential.stdout),
        String::from_utf8_lossy(&credential.stderr)
    );
    let credential_json: serde_json::Value =
        serde_json::from_slice(&credential.stdout).expect("parse remote credential response");
    assert_eq!(credential_json["format"], CHIO_PASSPORT_OID4VCI_FORMAT);
    assert_eq!(
        credential_json["credential"]["subject"],
        passport["subject"]
    );
    assert_eq!(
        credential_json["chioCredentialContext"]["passportStatus"]["passportId"],
        publish_json["passportId"]
    );
    assert_eq!(
        credential_json["chioCredentialContext"]["passportStatus"]["distribution"]["resolveUrls"]
            [0],
        format!("{advertise_url}/v1/public/passport/statuses/resolve")
    );
}

#[test]
fn passport_public_holder_transport_fetch_submit_and_fail_closed_on_replay() {
    let passport_path = unique_path("passport-public-holder-transport", ".json");
    let challenge_path = unique_path("passport-public-holder-transport-challenge", ".json");
    let response_path = unique_path("passport-public-holder-transport-response", ".json");
    let holder_seed_path = unique_path("passport-public-holder-transport-holder-seed", ".txt");
    let challenge_db_path = unique_path("passport-public-holder-transport-store", ".sqlite3");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let advertise_url = base_url.clone();
    let service_token = "passport-public-holder-transport-service-token";
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let _passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "public-holder-transport",
    );
    fs::write(&holder_seed_path, format!("{}\n", subject.seed_hex())).expect("write holder seed");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .expect("http client");
    let mut service = spawn_passport_challenge_trust_service(
        listen,
        service_token,
        &advertise_url,
        &challenge_db_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let create = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "challenge",
            "create",
            "--output",
            challenge_path.to_str().expect("challenge path"),
            "--verifier",
            "https://wallet-rp.example.com",
        ])
        .output()
        .expect("run remote public-holder challenge create");
    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    let create_json: serde_json::Value =
        serde_json::from_slice(&create.stdout).expect("parse challenge create response");
    let challenge_id = create_json["challengeId"]
        .as_str()
        .expect("challenge id")
        .to_string();
    assert_eq!(
        create_json["transport"]["challengeId"],
        serde_json::Value::String(challenge_id.clone())
    );
    assert_eq!(
        create_json["transport"]["challengeUrl"],
        serde_json::Value::String(format!(
            "{advertise_url}/v1/public/passport/challenges/{challenge_id}"
        ))
    );
    assert_eq!(
        create_json["transport"]["submitUrl"],
        serde_json::Value::String(format!(
            "{advertise_url}/v1/public/passport/challenges/verify"
        ))
    );

    let stored_challenge: serde_json::Value =
        serde_json::from_slice(&fs::read(&challenge_path).expect("read challenge"))
            .expect("parse stored challenge");
    assert_eq!(
        stored_challenge["challengeId"],
        serde_json::Value::String(challenge_id.clone())
    );

    let respond = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "respond",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--challenge-url",
            create_json["transport"]["challengeUrl"]
                .as_str()
                .expect("challenge url"),
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_path.to_str().expect("response path"),
        ])
        .output()
        .expect("run public-holder challenge respond");
    assert!(
        respond.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond.stdout),
        String::from_utf8_lossy(&respond.stderr)
    );

    let submit = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "challenge",
            "submit",
            "--input",
            response_path.to_str().expect("response path"),
            "--submit-url",
            create_json["transport"]["submitUrl"]
                .as_str()
                .expect("submit url"),
        ])
        .output()
        .expect("run public-holder challenge submit");
    assert!(
        submit.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&submit.stdout),
        String::from_utf8_lossy(&submit.stderr)
    );
    let submit_json: serde_json::Value =
        serde_json::from_slice(&submit.stdout).expect("parse submit response");
    assert_eq!(submit_json["accepted"], true);
    assert_eq!(submit_json["challengeId"], challenge_id);
    assert_eq!(submit_json["replayState"], "consumed");

    let replay = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "submit",
            "--input",
            response_path.to_str().expect("response path"),
            "--submit-url",
            create_json["transport"]["submitUrl"]
                .as_str()
                .expect("submit url"),
        ])
        .output()
        .expect("run replay public-holder challenge submit");
    assert!(
        !replay.status.success(),
        "replayed holder submission should fail\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("already been consumed"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[test]
fn passport_external_http_issuance_and_verifier_roundtrip_is_interop_qualified() {
    let passport_path = unique_path("passport-http-interop", ".json");
    let issuance_registry_path = unique_path("passport-http-interop-registry", ".json");
    let challenge_db_path = unique_path("passport-http-interop-challenges", ".sqlite3");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-http-interop-service-token";
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "http-interop",
    );
    let subject_did = passport["subject"].as_str().expect("passport subject");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_passport_interop_trust_service(
        listen,
        service_token,
        &base_url,
        &issuance_registry_path,
        &challenge_db_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    metadata.validate().expect("validate issuer metadata");
    assert_eq!(metadata.credential_issuer, base_url);

    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": "chio_agent_passport",
        }))
        .send()
        .expect("create issuance offer")
        .error_for_status()
        .expect("issuance offer status")
        .json()
        .expect("parse issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    offer
        .validate_against_metadata(&metadata)
        .expect("offer matches metadata");

    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    token_response.validate().expect("validate token response");

    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some("chio_agent_passport".to_string()),
        format: Some(CHIO_PASSPORT_OID4VCI_FORMAT.to_string()),
        subject: subject_did.to_string(),
    };
    let credential_response: Oid4vciCredentialResponse = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&credential_request)
        .send()
        .expect("redeem credential")
        .error_for_status()
        .expect("credential response status")
        .json()
        .expect("parse credential response");
    credential_response
        .validate(
            current_unix_secs(),
            Some(CHIO_PASSPORT_OID4VCI_FORMAT),
            Some(subject_did),
        )
        .expect("validate credential response");

    let challenge_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/challenges"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "verifier": "https://interop-rp.example.com",
            "ttlSeconds": 300,
        }))
        .send()
        .expect("create verifier challenge")
        .error_for_status()
        .expect("challenge create status")
        .json()
        .expect("parse challenge create");
    let challenge_id = challenge_response["transport"]["challengeId"]
        .as_str()
        .expect("transport challenge id");
    let challenge_url = challenge_response["transport"]["challengeUrl"]
        .as_str()
        .expect("transport challenge url");
    let submit_url = challenge_response["transport"]["submitUrl"]
        .as_str()
        .expect("transport submit url");

    let fetched_challenge: PassportPresentationChallenge = client
        .get(challenge_url)
        .send()
        .expect("fetch public challenge")
        .error_for_status()
        .expect("public challenge status")
        .json()
        .expect("parse public challenge");
    assert_eq!(
        fetched_challenge.challenge_id.as_deref(),
        Some(challenge_id)
    );
    let delivered_passport = credential_response
        .credential
        .native_passport()
        .expect("native passport credential");

    let presentation = respond_to_passport_presentation_challenge(
        &subject,
        delivered_passport,
        &fetched_challenge,
        current_unix_secs(),
    )
    .expect("build presentation response");

    let verification: PassportPresentationVerification = client
        .post(submit_url)
        .json(&serde_json::json!({
            "presentation": presentation,
        }))
        .send()
        .expect("submit public verification")
        .error_for_status()
        .expect("public verification status")
        .json()
        .expect("parse verification");
    assert!(verification.accepted);
    assert_eq!(verification.challenge_id.as_deref(), Some(challenge_id));
    assert_eq!(verification.replay_state.as_deref(), Some("consumed"));

    let replay = client
        .post(submit_url)
        .json(&serde_json::json!({
            "presentation": respond_to_passport_presentation_challenge(
                &subject,
                delivered_passport,
                &fetched_challenge,
                current_unix_secs(),
            )
            .expect("rebuild presentation response"),
        }))
        .send()
        .expect("submit replay verification");
    assert_eq!(replay.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(replay
        .text()
        .expect("read replay response")
        .contains("already been consumed"));
}

#[test]
fn passport_portable_sd_jwt_metadata_and_issuance_roundtrip() {
    let passport_path = unique_path("passport-portable-http", ".json");
    let authority_seed_path = unique_path("passport-portable-issuer", ".seed");
    let issuance_registry_path = unique_path("passport-portable-registry", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "portable-http-interop",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_passport_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    metadata.validate().expect("validate issuer metadata");
    assert_eq!(metadata.credential_issuer, base_url);
    let expected_jwks_url = format!("{base_url}/.well-known/jwks.json");
    assert_eq!(
        metadata.jwks_uri.as_deref(),
        Some(expected_jwks_url.as_str())
    );
    assert!(metadata
        .credential_configurations_supported
        .contains_key(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID));
    assert!(metadata
        .credential_configurations_supported
        .contains_key(CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID));

    let jwks: PortableJwkSet = client
        .get(format!("{base_url}/.well-known/jwks.json"))
        .send()
        .expect("fetch issuer jwks")
        .error_for_status()
        .expect("issuer jwks status")
        .json()
        .expect("parse issuer jwks");
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].alg, "EdDSA");

    let type_metadata: ChioPassportSdJwtVcTypeMetadata = client
        .get(format!("{base_url}/.well-known/chio-passport-sd-jwt-vc"))
        .send()
        .expect("fetch type metadata")
        .error_for_status()
        .expect("type metadata status")
        .json()
        .expect("parse type metadata");
    assert_eq!(type_metadata.format, CHIO_PASSPORT_SD_JWT_VC_FORMAT);
    assert_eq!(
        type_metadata.type_metadata_url,
        format!("{base_url}/.well-known/chio-passport-sd-jwt-vc")
    );
    assert_eq!(
        type_metadata.jwks_url,
        format!("{base_url}/.well-known/jwks.json")
    );
    assert_eq!(
        type_metadata.portable_identity_binding.subject_binding,
        type_metadata.subject_binding
    );
    assert_eq!(
        type_metadata.portable_identity_binding.issuer_identity,
        type_metadata.issuer_identity
    );
    assert_eq!(
        type_metadata
            .portable_identity_binding
            .chio_provenance_anchor,
        "did:chio"
    );
    assert!(type_metadata
        .portable_claim_catalog
        .selectively_disclosable_claims
        .iter()
        .any(|claim| claim == "chio_enterprise_identity_provenance"));
    assert!(type_metadata
        .portable_claim_catalog
        .optional_claims
        .iter()
        .any(|claim| claim == "chio_passport_status"));

    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create portable issuance offer")
        .error_for_status()
        .expect("portable issuance offer status")
        .json()
        .expect("parse portable issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    offer
        .validate_against_metadata(&metadata)
        .expect("offer matches metadata");

    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    token_response.validate().expect("validate token response");

    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
        subject: subject_did.clone(),
    };
    let credential_response: Oid4vciCredentialResponse = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&credential_request)
        .send()
        .expect("redeem portable credential")
        .error_for_status()
        .expect("portable credential response status")
        .json()
        .expect("parse portable credential response");
    credential_response
        .validate(
            current_unix_secs(),
            Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT),
            Some(&subject_did),
        )
        .expect("validate portable credential response");
    match &credential_response.credential {
        Oid4vciIssuedCredential::Compact(compact) => {
            assert!(compact.contains('~'));
            assert!(compact.ends_with('~'));
        }
        Oid4vciIssuedCredential::AgentPassport(_) => {
            panic!("portable configuration should return compact credential")
        }
    }
    assert_eq!(
        credential_response.subject_hint(),
        Some(subject_did.as_str())
    );
    assert!(credential_response.chio_credential_context.is_some());
}

#[test]
fn passport_portable_jwt_vc_json_metadata_and_issuance_roundtrip() {
    let passport_path = unique_path("passport-portable-jwt-vc-http", ".json");
    let authority_seed_path = unique_path("passport-portable-jwt-vc-issuer", ".seed");
    let issuance_registry_path = unique_path("passport-portable-jwt-vc-registry", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-jwt-vc-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "portable-jwt-vc-http-interop",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_passport_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    metadata.validate().expect("validate issuer metadata");
    let portable_configuration = metadata
        .credential_configurations_supported
        .get(CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID)
        .expect("jwt vc portable configuration");
    assert_eq!(
        portable_configuration.format,
        CHIO_PASSPORT_JWT_VC_JSON_FORMAT
    );
    let portable_profile = portable_configuration
        .portable_profile
        .as_ref()
        .expect("jwt vc portable profile");
    assert_eq!(portable_profile.proof_family, "vc+jwt");
    assert!(!portable_profile.supports_selective_disclosure);

    let type_metadata: ChioPassportJwtVcJsonTypeMetadata = client
        .get(format!("{base_url}/.well-known/chio-passport-jwt-vc-json"))
        .send()
        .expect("fetch jwt vc type metadata")
        .error_for_status()
        .expect("jwt vc type metadata status")
        .json()
        .expect("parse jwt vc type metadata");
    assert_eq!(type_metadata.format, CHIO_PASSPORT_JWT_VC_JSON_FORMAT);
    assert_eq!(
        type_metadata.type_metadata_url,
        format!("{base_url}/.well-known/chio-passport-jwt-vc-json")
    );
    assert_eq!(type_metadata.proof_family, "vc+jwt");
    assert!(!type_metadata.supports_selective_disclosure);
    assert!(type_metadata
        .portable_claim_catalog
        .always_disclosed_claims
        .iter()
        .any(|claim| claim == "vc.credentialSubject.chioPassportId"));

    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create jwt vc issuance offer")
        .error_for_status()
        .expect("jwt vc issuance offer status")
        .json()
        .expect("parse jwt vc issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    offer
        .validate_against_metadata(&metadata)
        .expect("offer matches metadata");

    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_JWT_VC_JSON_FORMAT.to_string()),
        subject: subject_did.clone(),
    };
    let credential_response: Oid4vciCredentialResponse = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&credential_request)
        .send()
        .expect("redeem jwt vc credential")
        .error_for_status()
        .expect("jwt vc credential response status")
        .json()
        .expect("parse jwt vc credential response");
    credential_response
        .validate(
            current_unix_secs(),
            Some(CHIO_PASSPORT_JWT_VC_JSON_FORMAT),
            Some(&subject_did),
        )
        .expect("validate jwt vc credential response");
    match &credential_response.credential {
        Oid4vciIssuedCredential::Compact(compact) => {
            assert!(compact.matches('.').count() == 2);
            assert!(!compact.contains('~'));
        }
        Oid4vciIssuedCredential::AgentPassport(_) => {
            panic!("jwt vc configuration should return compact credential")
        }
    }
}

#[test]
fn passport_issuance_rejects_mixed_portable_profile_request() {
    let passport_path = unique_path("passport-portable-mixed-profile", ".json");
    let authority_seed_path = unique_path("passport-portable-mixed-profile-issuer", ".seed");
    let issuance_registry_path = unique_path("passport-portable-mixed-profile-registry", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-mixed-profile-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "portable-mixed-profile",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_passport_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create issuance offer")
        .error_for_status()
        .expect("issuance offer status")
        .json()
        .expect("parse issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    let mixed_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
        subject: subject_did,
    };
    let response = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&mixed_request)
        .send()
        .expect("redeem mixed portable credential");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response
        .text()
        .expect("read mixed portable credential error")
        .contains("does not match credential_configuration_id"));
}

#[test]
fn passport_oid4vp_request_uri_and_direct_post_roundtrip_is_replay_safe() {
    let passport_path = unique_path("passport-oid4vp-portable", ".json");
    let authority_seed_path = unique_path("passport-oid4vp-authority", ".seed");
    let issuance_registry_path = unique_path("passport-oid4vp-registry", ".json");
    let verifier_db_path = unique_path("passport-oid4vp-verifier", ".sqlite3");
    let status_registry_path = unique_path("passport-oid4vp-statuses", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-oid4vp-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "oid4vp-http-interop",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_oid4vp_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
        &verifier_db_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    client
        .post(format!("{base_url}/v1/passport/statuses"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "distribution": {
                "resolveUrls": [format!("{base_url}/v1/public/passport/statuses/resolve")],
                "cacheTtlSecs": 300
            }
        }))
        .send()
        .expect("publish portable passport status")
        .error_for_status()
        .expect("portable passport status publish status");

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create portable issuance offer")
        .error_for_status()
        .expect("portable issuance offer status")
        .json()
        .expect("parse portable issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem portable token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
        subject: subject_did.clone(),
    };
    let credential_response: Oid4vciCredentialResponse = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&credential_request)
        .send()
        .expect("redeem portable credential")
        .error_for_status()
        .expect("portable credential response status")
        .json()
        .expect("parse portable credential response");
    let portable_credential = match &credential_response.credential {
        Oid4vciIssuedCredential::Compact(compact) => compact.clone(),
        Oid4vciIssuedCredential::AgentPassport(_) => {
            panic!("portable configuration should return compact credential")
        }
    };

    let create_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/oid4vp/requests"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "disclosureClaims": ["chio_issuer_dids"],
            "issuerAllowlist": [base_url],
            "ttlSeconds": 300,
            "identityAssertion": {
                "subject": "alice@example.com",
                "continuityId": "session-live-oid4vp-1",
                "provider": "oidc",
                "sessionHint": "resume",
                "ttlSeconds": 300
            }
        }))
        .send()
        .expect("create oid4vp request")
        .error_for_status()
        .expect("oid4vp request creation status")
        .json()
        .expect("parse oid4vp request response");
    let request: Oid4vpRequestObject =
        serde_json::from_value(create_response["request"].clone()).expect("typed oid4vp request");
    let request_uri = create_response["transport"]["requestUri"]
        .as_str()
        .expect("request uri")
        .to_string();
    let same_device_url = create_response["transport"]["sameDeviceUrl"]
        .as_str()
        .expect("same-device url");
    let cross_device_url = create_response["transport"]["crossDeviceUrl"]
        .as_str()
        .expect("cross-device url");
    let descriptor_url = create_response["walletExchange"]["descriptor"]["descriptorUrl"]
        .as_str()
        .expect("descriptor url")
        .to_string();
    assert!(same_device_url.starts_with("openid4vp://authorize?request_uri="));
    assert!(cross_device_url.starts_with(&format!("{base_url}/v1/public/passport/oid4vp/launch/")));
    assert_eq!(
        create_response["walletExchange"]["descriptor"]["exchangeId"],
        serde_json::Value::String(request.jti.clone())
    );
    assert_eq!(
        create_response["walletExchange"]["descriptor"]["relayUrl"],
        serde_json::Value::String(cross_device_url.to_string())
    );
    assert_eq!(
        create_response["walletExchange"]["transaction"]["status"],
        serde_json::Value::String("issued".to_string())
    );
    assert_eq!(
        create_response["walletExchange"]["identityAssertion"]["subject"],
        serde_json::Value::String("alice@example.com".to_string())
    );
    assert_eq!(
        create_response["walletExchange"]["identityAssertion"]["continuityId"],
        serde_json::Value::String("session-live-oid4vp-1".to_string())
    );
    assert_eq!(
        create_response["walletExchange"]["identityAssertion"]["boundRequestId"],
        serde_json::Value::String(request.jti.clone())
    );
    assert_eq!(
        request
            .identity_assertion
            .as_ref()
            .expect("identity assertion")
            .verifier_id,
        base_url
    );

    let request_fetch = client
        .get(&request_uri)
        .send()
        .expect("fetch oid4vp request uri")
        .error_for_status()
        .expect("oid4vp request uri status");
    assert_eq!(
        request_fetch
            .headers()
            .get(CONTENT_TYPE)
            .expect("content type")
            .to_str()
            .expect("content type str"),
        "application/oauth-authz-req+jwt"
    );
    let request_jwt = request_fetch.text().expect("request jwt body");
    let verified_request = verify_signed_oid4vp_request_object(
        &request_jwt,
        &authority.public_key(),
        current_unix_secs(),
    )
    .expect("verify oid4vp request jwt");
    assert_eq!(verified_request, request);
    let exchange_before: serde_json::Value = client
        .get(&descriptor_url)
        .send()
        .expect("fetch wallet exchange descriptor")
        .error_for_status()
        .expect("wallet exchange descriptor status")
        .json()
        .expect("parse wallet exchange descriptor");
    assert_eq!(
        exchange_before["transaction"]["status"],
        serde_json::Value::String("issued".to_string())
    );
    assert_eq!(
        exchange_before["identityAssertion"]["verifierId"],
        serde_json::Value::String(base_url.clone())
    );

    let response_jwt = respond_to_oid4vp_request(
        &subject,
        &portable_credential,
        &request,
        current_unix_secs(),
    )
    .expect("respond to oid4vp request");
    let verification: Oid4vpPresentationVerification = client
        .post(format!("{base_url}/v1/public/passport/oid4vp/direct-post"))
        .form(&[("response", response_jwt.as_str())])
        .send()
        .expect("submit oid4vp response")
        .error_for_status()
        .expect("oid4vp response status")
        .json()
        .expect("parse oid4vp verification");
    assert_eq!(verification.request_id, request.jti);
    assert_eq!(verification.subject_did, subject_did);
    assert_eq!(verification.issuer, base_url);
    assert_eq!(verification.disclosure_claims, vec!["chio_issuer_dids"]);
    assert!(verification.passport_status.is_some());
    assert_eq!(
        verification
            .exchange_transaction
            .as_ref()
            .expect("exchange transaction")
            .status
            .label(),
        "consumed"
    );
    assert_eq!(
        verification
            .identity_assertion
            .as_ref()
            .expect("identity assertion")
            .continuity_id,
        "session-live-oid4vp-1"
    );

    let replay = client
        .post(format!("{base_url}/v1/public/passport/oid4vp/direct-post"))
        .form(&[("response", response_jwt.as_str())])
        .send()
        .expect("submit replay oid4vp response");
    assert_eq!(replay.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(replay
        .text()
        .expect("read oid4vp replay body")
        .contains("already been consumed"));
    let exchange_after: serde_json::Value = client
        .get(&descriptor_url)
        .send()
        .expect("fetch consumed wallet exchange descriptor")
        .error_for_status()
        .expect("consumed wallet exchange descriptor status")
        .json()
        .expect("parse consumed wallet exchange descriptor");
    assert_eq!(
        exchange_after["transaction"]["status"],
        serde_json::Value::String("consumed".to_string())
    );
}

#[test]
fn passport_oid4vp_cli_holder_adapter_supports_same_device_and_cross_device_launches() {
    let passport_path = unique_path("passport-oid4vp-cli", ".json");
    let authority_seed_path = unique_path("passport-oid4vp-cli-authority", ".seed");
    let issuance_registry_path = unique_path("passport-oid4vp-cli-registry", ".json");
    let verifier_db_path = unique_path("passport-oid4vp-cli-verifier", ".sqlite3");
    let status_registry_path = unique_path("passport-oid4vp-cli-statuses", ".json");
    let holder_seed_path = unique_path("passport-oid4vp-cli-holder", ".seed");
    let portable_credential_path = unique_path("passport-oid4vp-cli-credential", ".jwt");
    let request_a_path = unique_path("passport-oid4vp-cli-request-a", ".json");
    let request_b_path = unique_path("passport-oid4vp-cli-request-b", ".json");
    let response_a_path = unique_path("passport-oid4vp-cli-response-a", ".jwt");
    let response_b_path = unique_path("passport-oid4vp-cli-response-b", ".jwt");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-oid4vp-cli-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject.seed_hex())).expect("write holder seed");
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "oid4vp-cli-holder-adapter",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_oid4vp_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
        &verifier_db_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    client
        .post(format!("{base_url}/v1/passport/statuses"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "distribution": {
                "resolveUrls": [format!("{base_url}/v1/public/passport/statuses/resolve")],
                "cacheTtlSecs": 300
            }
        }))
        .send()
        .expect("publish portable passport status")
        .error_for_status()
        .expect("portable passport status publish status");

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create portable issuance offer")
        .error_for_status()
        .expect("portable issuance offer status")
        .json()
        .expect("parse portable issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem portable token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
        subject: subject_did.clone(),
    };
    let credential_response: Oid4vciCredentialResponse = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&credential_request)
        .send()
        .expect("redeem portable credential")
        .error_for_status()
        .expect("portable credential response status")
        .json()
        .expect("parse portable credential response");
    let portable_credential = match &credential_response.credential {
        Oid4vciIssuedCredential::Compact(compact) => compact.clone(),
        Oid4vciIssuedCredential::AgentPassport(_) => {
            panic!("portable configuration should return compact credential")
        }
    };
    fs::write(&portable_credential_path, portable_credential.as_bytes()).expect("write credential");

    let create_same = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "oid4vp",
            "create",
            "--output",
            request_a_path.to_str().expect("request a path"),
            "--claim",
            "chio_issuer_dids",
            "--issuer",
            &base_url,
            "--ttl-secs",
            "300",
            "--identity-subject",
            "alice@example.com",
            "--identity-continuity-id",
            "session-cli-oid4vp-1",
            "--identity-provider",
            "oidc",
        ])
        .output()
        .expect("create same-device oid4vp request");
    assert!(
        create_same.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_same.stdout),
        String::from_utf8_lossy(&create_same.stderr)
    );
    let create_same_json: serde_json::Value =
        serde_json::from_slice(&create_same.stdout).expect("parse same-device create output");
    let same_device_url = create_same_json["transport"]["sameDeviceUrl"]
        .as_str()
        .expect("same-device url");
    assert!(same_device_url.starts_with("openid4vp://authorize?request_uri="));
    assert_eq!(
        create_same_json["walletExchange"]["identityAssertion"]["subject"],
        serde_json::Value::String("alice@example.com".to_string())
    );

    let respond_same = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "oid4vp",
            "respond",
            "--input",
            portable_credential_path.to_str().expect("credential path"),
            "--same-device-url",
            same_device_url,
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_a_path.to_str().expect("response a path"),
            "--submit",
        ])
        .output()
        .expect("run same-device oid4vp holder adapter");
    assert!(
        respond_same.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond_same.stdout),
        String::from_utf8_lossy(&respond_same.stderr)
    );
    let respond_same_json: serde_json::Value =
        serde_json::from_slice(&respond_same.stdout).expect("parse same-device respond output");
    assert_eq!(respond_same_json["submitted"], true);
    assert_eq!(respond_same_json["verification"]["subjectDid"], subject_did);

    let create_cross = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "oid4vp",
            "create",
            "--output",
            request_b_path.to_str().expect("request b path"),
            "--claim",
            "chio_issuer_dids",
            "--issuer",
            &base_url,
            "--ttl-secs",
            "300",
        ])
        .output()
        .expect("create cross-device oid4vp request");
    assert!(
        create_cross.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_cross.stdout),
        String::from_utf8_lossy(&create_cross.stderr)
    );
    let create_cross_json: serde_json::Value =
        serde_json::from_slice(&create_cross.stdout).expect("parse cross-device create output");
    let cross_device_url = create_cross_json["transport"]["crossDeviceUrl"]
        .as_str()
        .expect("cross-device url");
    assert!(cross_device_url.starts_with(&format!("{base_url}/v1/public/passport/oid4vp/launch/")));

    let respond_cross = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "oid4vp",
            "respond",
            "--input",
            portable_credential_path.to_str().expect("credential path"),
            "--cross-device-url",
            cross_device_url,
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_b_path.to_str().expect("response b path"),
            "--submit",
        ])
        .output()
        .expect("run cross-device oid4vp holder adapter");
    assert!(
        respond_cross.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond_cross.stdout),
        String::from_utf8_lossy(&respond_cross.stderr)
    );
    let respond_cross_json: serde_json::Value =
        serde_json::from_slice(&respond_cross.stdout).expect("parse cross-device respond output");
    assert_eq!(respond_cross_json["submitted"], true);
    assert_eq!(
        respond_cross_json["verification"]["subjectDid"],
        subject_did
    );
}

#[test]
fn passport_oid4vp_public_verifier_metadata_and_rotation_preserve_active_request_truth() {
    let passport_path = unique_path("passport-oid4vp-rotation", ".json");
    let authority_db_path = unique_path("passport-oid4vp-rotation-authority", ".sqlite3");
    let issuance_registry_path = unique_path("passport-oid4vp-rotation-registry", ".json");
    let verifier_db_path = unique_path("passport-oid4vp-rotation-verifier", ".sqlite3");
    let status_registry_path = unique_path("passport-oid4vp-rotation-statuses", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-oid4vp-rotation-service-token";
    let now = current_unix_secs();

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now + 86_400,
        "oid4vp-verifier-rotation",
    );
    let subject_did = passport["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_oid4vp_trust_service_with_authority_db(
        listen,
        service_token,
        &base_url,
        &authority_db_path,
        &issuance_registry_path,
        &verifier_db_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    client
        .post(format!("{base_url}/v1/passport/statuses"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "distribution": {
                "resolveUrls": [format!("{base_url}/v1/public/passport/statuses/resolve")],
                "cacheTtlSecs": 300
            }
        }))
        .send()
        .expect("publish portable passport status")
        .error_for_status()
        .expect("portable passport status publish status");

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create portable issuance offer")
        .error_for_status()
        .expect("portable issuance offer status")
        .json()
        .expect("parse portable issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem portable token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
        subject: subject_did.clone(),
    };
    let credential_response: Oid4vciCredentialResponse = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&credential_request)
        .send()
        .expect("redeem portable credential")
        .error_for_status()
        .expect("portable credential response status")
        .json()
        .expect("parse portable credential response");
    let portable_credential = match &credential_response.credential {
        Oid4vciIssuedCredential::Compact(compact) => compact.clone(),
        Oid4vciIssuedCredential::AgentPassport(_) => {
            panic!("portable configuration should return compact credential")
        }
    };

    let create_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/oid4vp/requests"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "disclosureClaims": ["chio_issuer_dids"],
            "issuerAllowlist": [base_url],
            "ttlSeconds": 300
        }))
        .send()
        .expect("create oid4vp request")
        .error_for_status()
        .expect("oid4vp request creation status")
        .json()
        .expect("parse oid4vp request response");
    let request: Oid4vpRequestObject =
        serde_json::from_value(create_response["request"].clone()).expect("typed oid4vp request");
    let request_uri = create_response["transport"]["requestUri"]
        .as_str()
        .expect("request uri")
        .to_string();

    let initial_metadata: Oid4vpVerifierMetadata = client
        .get(format!("{base_url}{OID4VP_VERIFIER_METADATA_PATH}"))
        .send()
        .expect("fetch initial verifier metadata")
        .error_for_status()
        .expect("initial verifier metadata status")
        .json()
        .expect("parse initial verifier metadata");
    initial_metadata
        .validate()
        .expect("validate initial verifier metadata");
    assert_eq!(initial_metadata.client_id, base_url);
    assert_eq!(initial_metadata.trusted_key_count, 1);

    let rotate = client
        .post(format!("{base_url}/v1/authority"))
        .bearer_auth(service_token)
        .send()
        .expect("rotate authority");
    assert_eq!(rotate.status(), reqwest::StatusCode::OK);

    let rotated_metadata: Oid4vpVerifierMetadata = client
        .get(format!("{base_url}{OID4VP_VERIFIER_METADATA_PATH}"))
        .send()
        .expect("fetch rotated verifier metadata")
        .error_for_status()
        .expect("rotated verifier metadata status")
        .json()
        .expect("parse rotated verifier metadata");
    rotated_metadata
        .validate()
        .expect("validate rotated verifier metadata");
    assert!(rotated_metadata.trusted_key_count >= 2);
    assert_eq!(
        rotated_metadata.jwks_uri,
        format!("{base_url}/.well-known/jwks.json")
    );

    let verifier_jwks: PortableJwkSet = client
        .get(&rotated_metadata.jwks_uri)
        .send()
        .expect("fetch rotated verifier jwks")
        .error_for_status()
        .expect("rotated verifier jwks status")
        .json()
        .expect("parse rotated verifier jwks");
    assert!(verifier_jwks.keys.len() >= 2);
    let verifier_keys = verifier_jwks
        .keys
        .iter()
        .map(|entry| entry.jwk.to_public_key().expect("jwk to public key"))
        .collect::<Vec<_>>();

    let request_fetch = client
        .get(&request_uri)
        .send()
        .expect("fetch oid4vp request uri after rotation")
        .error_for_status()
        .expect("oid4vp request uri status after rotation");
    let request_jwt = request_fetch.text().expect("request jwt body");
    let verified_request = verify_signed_oid4vp_request_object_with_any_key(
        &request_jwt,
        &verifier_keys,
        current_unix_secs(),
    )
    .expect("verify oid4vp request jwt with rotated jwks");
    assert_eq!(verified_request, request);

    let response_jwt = respond_to_oid4vp_request(
        &subject,
        &portable_credential,
        &request,
        current_unix_secs(),
    )
    .expect("respond to oid4vp request");
    let verification: Oid4vpPresentationVerification = client
        .post(format!("{base_url}/v1/public/passport/oid4vp/direct-post"))
        .form(&[("response", response_jwt.as_str())])
        .send()
        .expect("submit oid4vp response after rotation")
        .error_for_status()
        .expect("oid4vp response status after rotation")
        .json()
        .expect("parse oid4vp verification after rotation");
    assert_eq!(verification.request_id, request.jti);
    assert_eq!(verification.subject_did, subject_did);
}

#[test]
fn passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states() {
    let passport_a_path = unique_path("passport-portable-lifecycle-a", ".json");
    let passport_b_path = unique_path("passport-portable-lifecycle-b", ".json");
    let authority_seed_path = unique_path("passport-portable-lifecycle-issuer", ".seed");
    let issuance_registry_path = unique_path("passport-portable-lifecycle-registry", ".json");
    let status_registry_path = unique_path("passport-portable-lifecycle-statuses", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-lifecycle-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport_a = write_passport_artifact(
        &passport_a_path,
        &subject,
        &issuer,
        now.saturating_sub(120),
        now.saturating_add(86_400),
        "portable-lifecycle-a",
    );
    let passport_b = write_passport_artifact(
        &passport_b_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(172_800),
        "portable-lifecycle-b",
    );
    let subject_did = passport_a["subject"]
        .as_str()
        .expect("passport subject")
        .to_string();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_passport_lifecycle_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let publish_a = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "status",
            "publish",
            "--input",
            passport_a_path.to_str().expect("passport a path"),
        ])
        .output()
        .expect("publish passport a");
    assert!(
        publish_a.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish_a.stdout),
        String::from_utf8_lossy(&publish_a.stderr)
    );
    let publish_a_json: serde_json::Value =
        serde_json::from_slice(&publish_a.stdout).expect("parse publish a");
    let passport_a_id = publish_a_json["passportId"]
        .as_str()
        .expect("passport a id")
        .to_string();

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    metadata.validate().expect("validate issuer metadata");
    assert_eq!(
        metadata
            .chio_profile
            .as_ref()
            .expect("chio profile")
            .passport_status_distribution
            .resolve_urls[0],
        format!("{base_url}/v1/public/passport/statuses/resolve")
    );

    let offer_response: serde_json::Value = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport_a,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create portable issuance offer")
        .error_for_status()
        .expect("portable issuance offer status")
        .json()
        .expect("parse portable issuance offer");
    let offer: Oid4vciCredentialOffer =
        serde_json::from_value(offer_response["offer"].clone()).expect("parse typed offer");
    let token_request = Oid4vciTokenRequest {
        grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer
            .pre_authorized_code()
            .expect("pre-authorized code")
            .to_string(),
    };
    let token_response: Oid4vciTokenResponse = client
        .post(&metadata.token_endpoint)
        .json(&token_request)
        .send()
        .expect("redeem token")
        .error_for_status()
        .expect("token response status")
        .json()
        .expect("parse token response");
    let credential_request = Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
        subject: subject_did.clone(),
    };
    let credential_response: Oid4vciCredentialResponse = client
        .post(&metadata.credential_endpoint)
        .bearer_auth(&token_response.access_token)
        .json(&credential_request)
        .send()
        .expect("redeem portable credential")
        .error_for_status()
        .expect("portable credential response status")
        .json()
        .expect("parse portable credential response");
    credential_response
        .validate(
            current_unix_secs(),
            Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT),
            Some(&subject_did),
        )
        .expect("validate portable credential response");
    let status_ref = credential_response
        .chio_credential_context
        .as_ref()
        .and_then(|context| context.passport_status.as_ref())
        .expect("portable status reference");
    assert_eq!(status_ref.passport_id, passport_a_id);
    assert_eq!(status_ref.distribution.cache_ttl_secs, Some(300));
    let resolve_base = status_ref.distribution.resolve_urls[0].clone();

    let resolve_active: serde_json::Value = client
        .get(format!("{resolve_base}/{passport_a_id}"))
        .send()
        .expect("resolve active status")
        .error_for_status()
        .expect("active status response")
        .json()
        .expect("parse active resolution");
    assert_eq!(resolve_active["state"], "active");
    assert_eq!(resolve_active["source"], "registry:trust-control");

    let publish_b = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "status",
            "publish",
            "--input",
            passport_b_path.to_str().expect("passport b path"),
        ])
        .output()
        .expect("publish passport b");
    assert!(
        publish_b.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish_b.stdout),
        String::from_utf8_lossy(&publish_b.stderr)
    );
    let publish_b_json: serde_json::Value =
        serde_json::from_slice(&publish_b.stdout).expect("parse publish b");
    let passport_b_id = publish_b_json["passportId"]
        .as_str()
        .expect("passport b id")
        .to_string();

    let resolve_superseded: serde_json::Value = client
        .get(format!("{resolve_base}/{passport_a_id}"))
        .send()
        .expect("resolve superseded status")
        .error_for_status()
        .expect("superseded status response")
        .json()
        .expect("parse superseded resolution");
    assert_eq!(resolve_superseded["state"], "superseded");
    assert_eq!(resolve_superseded["supersededBy"], passport_b_id);

    let revoke_b = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "status",
            "revoke",
            "--passport-id",
            &passport_b_id,
            "--reason",
            "compromised",
        ])
        .output()
        .expect("revoke passport b");
    assert!(
        revoke_b.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&revoke_b.stdout),
        String::from_utf8_lossy(&revoke_b.stderr)
    );

    let resolve_revoked: serde_json::Value = client
        .get(format!("{resolve_base}/{passport_b_id}"))
        .send()
        .expect("resolve revoked status")
        .error_for_status()
        .expect("revoked status response")
        .json()
        .expect("parse revoked resolution");
    assert_eq!(resolve_revoked["state"], "revoked");
    assert_eq!(resolve_revoked["revokedReason"], "compromised");

    drop(passport_b);
}

#[test]
fn passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution() {
    let passport_path = unique_path("passport-portable-lifecycle-stale", ".json");
    let authority_seed_path = unique_path("passport-portable-lifecycle-stale-issuer", ".seed");
    let issuance_registry_path = unique_path("passport-portable-lifecycle-stale-registry", ".json");
    let status_registry_path = unique_path("passport-portable-lifecycle-stale-statuses", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-lifecycle-stale-service-token";
    let now = current_unix_secs();

    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let passport = write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(86_400),
        "portable-lifecycle-stale",
    );

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_passport_lifecycle_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let publish = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "status",
            "publish",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("publish stale passport");
    assert!(
        publish.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&publish.stdout),
        String::from_utf8_lossy(&publish.stderr)
    );
    let publish_json: serde_json::Value =
        serde_json::from_slice(&publish.stdout).expect("parse publish response");
    let passport_id = publish_json["passportId"]
        .as_str()
        .expect("passport id")
        .to_string();

    let mut registry_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&status_registry_path).expect("read status registry"))
            .expect("parse status registry");
    let stale_timestamp = now.saturating_sub(301);
    registry_json["passports"][&passport_id]["publishedAt"] = serde_json::json!(stale_timestamp);
    registry_json["passports"][&passport_id]["updatedAt"] = serde_json::json!(stale_timestamp);
    fs::write(
        &status_registry_path,
        serde_json::to_vec_pretty(&registry_json).expect("serialize status registry"),
    )
    .expect("write status registry");

    let resolve_json: serde_json::Value = client
        .get(format!(
            "{base_url}/v1/public/passport/statuses/resolve/{passport_id}"
        ))
        .send()
        .expect("resolve stale status")
        .error_for_status()
        .expect("stale status response")
        .json()
        .expect("parse stale resolution");
    assert_eq!(resolve_json["state"], "stale");
    assert_eq!(resolve_json["source"], "registry:trust-control");

    let stale_offer = client
        .post(format!("{base_url}/v1/passport/issuance/offers"))
        .bearer_auth(service_token)
        .json(&serde_json::json!({
            "passport": passport,
            "ttlSeconds": 300,
            "credentialConfigurationId": CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        }))
        .send()
        .expect("create stale portable issuance offer");
    assert_eq!(stale_offer.status(), reqwest::StatusCode::BAD_REQUEST);
    let stale_offer_body = stale_offer.text().expect("read stale offer body");
    assert!(stale_offer_body.contains("stale lifecycle state"));
}

#[test]
fn passport_issuance_local_portable_offer_requires_signing_seed() {
    let passport_path = unique_path("passport-portable-local", ".json");
    let issuance_registry_path = unique_path("passport-portable-local-registry", ".json");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let now = current_unix_secs();
    write_passport_artifact(
        &passport_path,
        &subject,
        &issuer,
        now.saturating_sub(60),
        now.saturating_add(3600),
        "portable-local",
    );

    let offer = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "issuance",
            "offer",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--issuer-url",
            "https://trust.example.com",
            "--passport-issuance-offers-file",
            issuance_registry_path
                .to_str()
                .expect("issuance registry path"),
            "--credential-configuration-id",
            CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID,
        ])
        .output()
        .expect("run local portable issuance offer");
    assert!(
        !offer.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    let error_text = format!(
        "{}{}",
        String::from_utf8_lossy(&offer.stdout),
        String::from_utf8_lossy(&offer.stderr)
    );
    assert!(error_text.contains("unsupported credential_configuration_id"));
}

#[test]
fn passport_portable_metadata_endpoints_require_signing_key_configuration() {
    let issuance_registry_path = unique_path("passport-portable-metadata-registry", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-portable-metadata-service-token";

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_passport_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &issuance_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let metadata: Oid4vciCredentialIssuerMetadata = client
        .get(format!("{base_url}/.well-known/openid-credential-issuer"))
        .send()
        .expect("fetch issuer metadata")
        .error_for_status()
        .expect("issuer metadata status")
        .json()
        .expect("parse issuer metadata");
    metadata.validate().expect("validate issuer metadata");
    assert!(metadata.jwks_uri.is_none());
    assert!(!metadata
        .credential_configurations_supported
        .contains_key(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID));
    assert!(!metadata
        .credential_configurations_supported
        .contains_key(CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID));

    let jwks = client
        .get(format!("{base_url}/.well-known/jwks.json"))
        .send()
        .expect("fetch jwks without signing key");
    assert_eq!(jwks.status(), reqwest::StatusCode::NOT_FOUND);

    let type_metadata = client
        .get(format!("{base_url}/.well-known/chio-passport-sd-jwt-vc"))
        .send()
        .expect("fetch type metadata without signing key");
    assert_eq!(type_metadata.status(), reqwest::StatusCode::NOT_FOUND);

    let jwt_vc_type_metadata = client
        .get(format!("{base_url}/.well-known/chio-passport-jwt-vc-json"))
        .send()
        .expect("fetch jwt vc type metadata without signing key");
    assert_eq!(
        jwt_vc_type_metadata.status(),
        reqwest::StatusCode::NOT_FOUND
    );
}

#[test]
fn passport_public_discovery_endpoints_require_authority_signing_key() {
    let issuance_registry_path = unique_path("passport-public-discovery-registry", ".json");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-public-discovery-service-token";

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_passport_issuance_trust_service(
        listen,
        service_token,
        &base_url,
        &issuance_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    for path in [
        "/v1/public/passport/discovery/issuer",
        "/v1/public/passport/discovery/verifier",
        "/v1/public/passport/discovery/transparency",
    ] {
        let response = client
            .get(format!("{base_url}{path}"))
            .send()
            .expect("fetch public discovery endpoint");
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    }
}

#[test]
fn passport_public_discovery_surfaces_are_signed_and_informational_only() {
    let issuance_registry_path = unique_path("passport-public-discovery-portable", ".json");
    let verifier_db_path = unique_path("passport-public-discovery-verifier", ".sqlite");
    let status_registry_path = unique_path("passport-public-discovery-status", ".json");
    let authority_seed_path = unique_path("passport-public-discovery-authority", ".seed");
    let authority = Keypair::generate();
    fs::write(&authority_seed_path, format!("{}\n", authority.seed_hex()))
        .expect("write authority seed");

    let listen = reserve_listen_addr();
    let base_url = format!("http://{}", listen);
    let service_token = "passport-public-discovery-portable-token";

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("http client");
    let mut service = spawn_portable_oid4vp_trust_service(
        listen,
        service_token,
        &base_url,
        &authority_seed_path,
        &issuance_registry_path,
        &verifier_db_path,
        &status_registry_path,
    );
    wait_for_trust_service(&client, &base_url, &mut service);

    let issuer_discovery: SignedPublicIssuerDiscovery = client
        .get(format!("{base_url}/v1/public/passport/discovery/issuer"))
        .send()
        .expect("fetch issuer discovery")
        .error_for_status()
        .expect("issuer discovery status")
        .json()
        .expect("parse issuer discovery");
    verify_signed_public_issuer_discovery(&issuer_discovery).expect("verify issuer discovery");
    assert_eq!(
        issuer_discovery.body.metadata_url,
        format!("{base_url}/.well-known/openid-credential-issuer")
    );
    assert!(issuer_discovery.body.import_guardrails.informational_only);
    assert!(
        issuer_discovery
            .body
            .import_guardrails
            .requires_explicit_policy_import
    );
    assert!(
        issuer_discovery
            .body
            .import_guardrails
            .requires_manual_review
    );

    let verifier_discovery: SignedPublicVerifierDiscovery = client
        .get(format!("{base_url}/v1/public/passport/discovery/verifier"))
        .send()
        .expect("fetch verifier discovery")
        .error_for_status()
        .expect("verifier discovery status")
        .json()
        .expect("parse verifier discovery");
    verify_signed_public_verifier_discovery(&verifier_discovery)
        .expect("verify verifier discovery");
    assert_eq!(
        verifier_discovery.body.metadata_url,
        format!("{base_url}{OID4VP_VERIFIER_METADATA_PATH}")
    );
    assert_eq!(
        verifier_discovery.body.jwks_uri,
        format!("{base_url}/.well-known/jwks.json")
    );
    assert!(verifier_discovery
        .body
        .request_uri_prefix
        .starts_with(&format!("{base_url}/v1/public/passport/oid4vp/requests/")));

    let transparency: SignedPublicDiscoveryTransparency = client
        .get(format!(
            "{base_url}/v1/public/passport/discovery/transparency"
        ))
        .send()
        .expect("fetch discovery transparency")
        .error_for_status()
        .expect("discovery transparency status")
        .json()
        .expect("parse discovery transparency");
    verify_signed_public_discovery_transparency(&transparency)
        .expect("verify discovery transparency");
    assert_eq!(transparency.body.entries.len(), 2);
    assert!(transparency
        .body
        .entries
        .iter()
        .any(|entry| entry.metadata_url
            == format!("{base_url}/.well-known/openid-credential-issuer")));
    assert!(transparency
        .body
        .entries
        .iter()
        .any(|entry| entry.metadata_url == format!("{base_url}{OID4VP_VERIFIER_METADATA_PATH}")));
    assert!(transparency.body.import_guardrails.informational_only);
}
