#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::federation_policy::{
    verify_admission_proof_of_work, FederationAdmissionAntiSybilControls,
    FederationAdmissionEvaluationRequest, FederationAdmissionEvaluationResponse,
    FederationAdmissionPolicyRecord, FederationAdmissionRateLimit,
    FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA, FEDERATION_ADMISSION_POLICY_REGISTRY_VERSION,
};
use chio_core::capability::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::federation::{
    FederatedOpenAdmissionPolicyArtifact, FederatedStakeRequirement, FederationArtifactKind,
    FederationArtifactReference, SignedFederatedOpenAdmissionPolicy,
    CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA,
};
use chio_core::listing::GenericTrustAdmissionClass;
use chio_core::open_market::OpenMarketBondClass;
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ReceiptAttributionMetadata, ToolCallAction,
};
use chio_kernel::{BudgetStore, CapabilityAuthority, LocalCapabilityAuthority, ReceiptStore};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
use reqwest::blocking::Client;

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    workspace_root().join("examples/policies").join(name)
}

fn reserve_listen_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
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

fn spawn_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    policy_path: &PathBuf,
    federation_policies_file: &PathBuf,
    receipt_db_path: &PathBuf,
    revocation_db_path: &PathBuf,
    authority_db_path: &PathBuf,
    budget_db_path: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--advertise-url",
            &format!("http://{listen}"),
            "--service-token",
            service_token,
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--federation-policies-file",
            federation_policies_file
                .to_str()
                .expect("federation policies file path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
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

fn sample_artifact_reference(
    kind: FederationArtifactKind,
    artifact_id: &str,
) -> FederationArtifactReference {
    FederationArtifactReference {
        kind,
        schema: "chio.example.v1".to_string(),
        artifact_id: artifact_id.to_string(),
        operator_id: "operator-alpha".to_string(),
        sha256: "ab".repeat(32),
        uri: Some(format!("https://operator.example/{artifact_id}")),
    }
}

fn make_policy_record(
    policy_id: &str,
    allowed_admission_classes: Vec<GenericTrustAdmissionClass>,
    anti_sybil: FederationAdmissionAntiSybilControls,
    minimum_reputation_score: Option<f64>,
) -> FederationAdmissionPolicyRecord {
    let mut stake_requirements = Vec::new();
    if allowed_admission_classes.contains(&GenericTrustAdmissionClass::BondBacked) {
        stake_requirements.push(FederatedStakeRequirement {
            admission_class: GenericTrustAdmissionClass::BondBacked,
            required_bond_class: Some(OpenMarketBondClass::Listing),
            minimum_bond_amount: Some(MonetaryAmount {
                units: 5000,
                currency: "USD".to_string(),
            }),
            slashable: true,
            governance_case_required: true,
        });
    }
    let artifact = FederatedOpenAdmissionPolicyArtifact {
        schema: CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA.to_string(),
        policy_id: policy_id.to_string(),
        issued_at: 1_700_000_000,
        namespace: "chio://federation/open".to_string(),
        governing_operator_id: "operator-alpha".to_string(),
        allowed_admission_classes,
        stake_requirements,
        governing_charter_ref: sample_artifact_reference(
            FederationArtifactKind::GovernanceCharter,
            "charter-1",
        ),
        fee_schedule_ref: sample_artifact_reference(
            FederationArtifactKind::OpenMarketFeeSchedule,
            "fee-schedule-1",
        ),
        explicit_local_review_required: true,
        visibility_only_without_activation: true,
        note: Some("permissionless federation policy".to_string()),
    };
    let signing_key = Keypair::generate();
    let policy = SignedFederatedOpenAdmissionPolicy::sign(artifact, &signing_key)
        .expect("sign open-admission policy");
    FederationAdmissionPolicyRecord {
        schema: FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA.to_string(),
        published_at: 1_700_000_100,
        policy,
        anti_sybil,
        minimum_reputation_score,
        note: Some("published for trust-control".to_string()),
    }
}

fn make_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    timestamp: u64,
) -> ChioReceipt {
    let kernel_kp = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/data.txt"
            }))
            .expect("action"),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: issuer_key.to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_kp.public_key(),
        },
        &kernel_kp,
    )
    .expect("sign receipt")
}

fn seed_subject_history(
    receipt_db_path: &PathBuf,
    budget_db_path: &PathBuf,
    subject_kp: &Keypair,
) -> String {
    let authority = LocalCapabilityAuthority::new(Keypair::generate());
    let capability = authority
        .issue_capability(
            &subject_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Read],
                    constraints: Vec::new(),
                    max_invocations: Some(10),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            300,
        )
        .expect("issue capability");

    let receipt_store = SqliteReceiptStore::open(receipt_db_path).expect("open receipt store");
    receipt_store
        .record_capability_snapshot(&capability, None)
        .expect("record capability snapshot");

    let subject_key = subject_kp.public_key().to_hex();
    let issuer_key = authority.authority_public_key().to_hex();
    receipt_store
        .append_chio_receipt(&make_receipt(
            "rep-1",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_000_000,
        ))
        .expect("append first receipt");
    receipt_store
        .append_chio_receipt(&make_receipt(
            "rep-2",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_086_500,
        ))
        .expect("append second receipt");

    let budget_store = SqliteBudgetStore::open(budget_db_path).expect("open budget store");
    assert!(
        budget_store
            .try_charge_cost(&capability.id, 0, Some(10), 25, Some(50), Some(500))
            .expect("charge cost"),
        "seed budget charge should succeed"
    );

    subject_key
}

fn mine_pow_nonce(policy_id: &str, subject_key: &str, difficulty_bits: u8) -> String {
    for attempt in 0_u64.. {
        let candidate = format!("nonce-{attempt}");
        if verify_admission_proof_of_work(policy_id, subject_key, &candidate, difficulty_bits) {
            return candidate;
        }
    }
    panic!("failed to mine proof-of-work nonce");
}

fn publish_policy(
    client: &Client,
    base_url: &str,
    service_token: &str,
    record: &FederationAdmissionPolicyRecord,
) -> reqwest::blocking::Response {
    client
        .put(format!(
            "{base_url}/v1/federation/open-admission-policies/{}",
            record.policy.body.policy_id
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(record)
        .send()
        .expect("publish federation policy")
}

fn local_reputation_score(
    client: &Client,
    base_url: &str,
    service_token: &str,
    subject_key: &str,
) -> f64 {
    let body: serde_json::Value = client
        .get(format!("{base_url}/v1/reputation/local/{subject_key}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("query local reputation")
        .json()
        .expect("parse local reputation");
    body["effectiveScore"].as_f64().expect("effectiveScore")
}

#[test]
fn federation_policy_cli_supports_upsert_list_get_and_delete() {
    let dir = unique_dir("chio-cli-federation-policy-cli");
    fs::create_dir_all(&dir).expect("create temp dir");
    let registry_path = dir.join("federation-policies.json");
    let input_path = dir.join("policy.json");
    let record = make_policy_record(
        "policy-cli",
        vec![
            GenericTrustAdmissionClass::PublicUntrusted,
            GenericTrustAdmissionClass::Reviewable,
        ],
        FederationAdmissionAntiSybilControls::default(),
        Some(0.55),
    );
    fs::write(
        &input_path,
        serde_json::to_vec_pretty(&record).expect("serialize policy input"),
    )
    .expect("write policy input");

    let upsert = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "federation-policy",
            "upsert",
            "--input",
            input_path.to_str().expect("policy input path"),
            "--federation-policies-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run federation policy upsert");
    assert!(
        upsert.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&upsert.stdout),
        String::from_utf8_lossy(&upsert.stderr)
    );
    let upsert_body: serde_json::Value =
        serde_json::from_slice(&upsert.stdout).expect("parse upsert output");
    assert_eq!(upsert_body["policy"]["body"]["policyId"], "policy-cli");

    let registry_after_upsert: serde_json::Value =
        serde_json::from_slice(&fs::read(&registry_path).expect("read federation registry"))
            .expect("parse federation registry");
    assert_eq!(
        registry_after_upsert["version"],
        FEDERATION_ADMISSION_POLICY_REGISTRY_VERSION
    );

    let list = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "federation-policy",
            "list",
            "--federation-policies-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run federation policy list");
    assert!(
        list.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_body: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("parse list output");
    assert_eq!(list_body["count"], 1);
    assert_eq!(
        list_body["policies"][0]["policy"]["body"]["policyId"],
        "policy-cli"
    );

    let get = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "federation-policy",
            "get",
            "--policy-id",
            "policy-cli",
            "--federation-policies-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run federation policy get");
    assert!(
        get.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&get.stdout),
        String::from_utf8_lossy(&get.stderr)
    );
    let get_body: serde_json::Value =
        serde_json::from_slice(&get.stdout).expect("parse get output");
    assert_eq!(get_body["policy"]["body"]["policyId"], "policy-cli");
    assert_eq!(get_body["minimumReputationScore"], 0.55);

    let delete = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "federation-policy",
            "delete",
            "--policy-id",
            "policy-cli",
            "--federation-policies-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run federation policy delete");
    assert!(
        delete.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&delete.stdout),
        String::from_utf8_lossy(&delete.stderr)
    );
    let delete_body: serde_json::Value =
        serde_json::from_slice(&delete.stdout).expect("parse delete output");
    assert_eq!(delete_body["deleted"], true);
}

#[test]
fn trust_service_evaluates_permissionless_federation_policy_with_reputation_gate() {
    let dir = unique_dir("chio-cli-federation-policy-http");
    fs::create_dir_all(&dir).expect("create temp dir");
    let federation_policies_file = dir.join("federation-policies.json");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let admitted_subject = Keypair::generate();
    let admitted_subject_key =
        seed_subject_history(&receipt_db_path, &budget_db_path, &admitted_subject);
    let denied_subject_key = Keypair::generate().public_key().to_hex();

    let listen = reserve_listen_addr();
    let service_token = "federation-policy-service-token";
    let base_url = format!("http://{listen}");
    let mut service = spawn_trust_service(
        listen,
        service_token,
        &policy_path,
        &federation_policies_file,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url, &mut service);

    let admitted_score =
        local_reputation_score(&client, &base_url, service_token, &admitted_subject_key);
    let record = make_policy_record(
        "policy-reputation",
        vec![
            GenericTrustAdmissionClass::PublicUntrusted,
            GenericTrustAdmissionClass::Reviewable,
        ],
        FederationAdmissionAntiSybilControls::default(),
        Some((admitted_score - 0.01).max(0.01)),
    );

    let publish = publish_policy(&client, &base_url, service_token, &record);
    assert_eq!(
        publish.status(),
        reqwest::StatusCode::OK,
        "publish failed: {}",
        publish.text().unwrap_or_default()
    );

    let health: serde_json::Value = client
        .get(format!("{base_url}/health"))
        .send()
        .expect("get health")
        .json()
        .expect("parse health");
    assert_eq!(
        health["federation"]["openAdmissionPolicies"]["configured"],
        true
    );
    assert_eq!(health["federation"]["openAdmissionPolicies"]["count"], 1);
    assert_eq!(
        health["federation"]["openAdmissionPolicies"]["reputationGatedCount"],
        1
    );

    let accepted: FederationAdmissionEvaluationResponse = client
        .post(format!(
            "{base_url}/v1/federation/open-admission-policies/evaluate"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&FederationAdmissionEvaluationRequest {
            policy_id: "policy-reputation".to_string(),
            subject_key: admitted_subject_key.clone(),
            requested_admission_class: GenericTrustAdmissionClass::Reviewable,
            proof_of_work_nonce: None,
        })
        .send()
        .expect("evaluate admitted subject")
        .json()
        .expect("parse accepted evaluation");
    assert!(accepted.accepted);
    assert_eq!(accepted.policy_id, "policy-reputation");
    assert!(accepted.observed_reputation_score.is_some());

    let denied: FederationAdmissionEvaluationResponse = client
        .post(format!(
            "{base_url}/v1/federation/open-admission-policies/evaluate"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&FederationAdmissionEvaluationRequest {
            policy_id: "policy-reputation".to_string(),
            subject_key: denied_subject_key,
            requested_admission_class: GenericTrustAdmissionClass::Reviewable,
            proof_of_work_nonce: None,
        })
        .send()
        .expect("evaluate denied subject")
        .json()
        .expect("parse denied evaluation");
    assert!(!denied.accepted);
    assert!(
        denied
            .decision_reason
            .contains("below the federation threshold"),
        "unexpected denial reason: {}",
        denied.decision_reason
    );
}

#[test]
fn trust_service_enforces_permissionless_federation_anti_sybil_controls() {
    let dir = unique_dir("chio-cli-federation-policy-anti-sybil");
    fs::create_dir_all(&dir).expect("create temp dir");
    let federation_policies_file = dir.join("federation-policies.json");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject = Keypair::generate();
    let subject_key = seed_subject_history(&receipt_db_path, &budget_db_path, &subject);

    let listen = reserve_listen_addr();
    let service_token = "federation-anti-sybil-token";
    let base_url = format!("http://{listen}");
    let mut service = spawn_trust_service(
        listen,
        service_token,
        &policy_path,
        &federation_policies_file,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url, &mut service);

    let record = make_policy_record(
        "policy-anti-sybil",
        vec![
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustAdmissionClass::BondBacked,
        ],
        FederationAdmissionAntiSybilControls {
            rate_limit: Some(FederationAdmissionRateLimit {
                max_requests: 2,
                window_seconds: 3600,
            }),
            proof_of_work_bits: Some(8),
            bond_backed_only: true,
        },
        None,
    );
    let publish = publish_policy(&client, &base_url, service_token, &record);
    assert_eq!(
        publish.status(),
        reqwest::StatusCode::OK,
        "publish failed: {}",
        publish.text().unwrap_or_default()
    );

    let non_bond: FederationAdmissionEvaluationResponse = client
        .post(format!(
            "{base_url}/v1/federation/open-admission-policies/evaluate"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&FederationAdmissionEvaluationRequest {
            policy_id: "policy-anti-sybil".to_string(),
            subject_key: subject_key.clone(),
            requested_admission_class: GenericTrustAdmissionClass::Reviewable,
            proof_of_work_nonce: Some(mine_pow_nonce("policy-anti-sybil", &subject_key, 8)),
        })
        .send()
        .expect("evaluate non-bond request")
        .json()
        .expect("parse non-bond evaluation");
    assert!(!non_bond.accepted);
    assert!(
        non_bond
            .decision_reason
            .contains("requires bond_backed admission"),
        "unexpected bond denial: {}",
        non_bond.decision_reason
    );

    let missing_pow: FederationAdmissionEvaluationResponse = client
        .post(format!(
            "{base_url}/v1/federation/open-admission-policies/evaluate"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&FederationAdmissionEvaluationRequest {
            policy_id: "policy-anti-sybil".to_string(),
            subject_key: subject_key.clone(),
            requested_admission_class: GenericTrustAdmissionClass::BondBacked,
            proof_of_work_nonce: None,
        })
        .send()
        .expect("evaluate missing pow request")
        .json()
        .expect("parse missing pow evaluation");
    assert!(!missing_pow.accepted);
    assert!(
        missing_pow
            .decision_reason
            .contains("proof-of-work nonce did not satisfy"),
        "unexpected pow denial: {}",
        missing_pow.decision_reason
    );

    let pow_nonce = mine_pow_nonce("policy-anti-sybil", &subject_key, 8);
    let first_allowed: FederationAdmissionEvaluationResponse = client
        .post(format!(
            "{base_url}/v1/federation/open-admission-policies/evaluate"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&FederationAdmissionEvaluationRequest {
            policy_id: "policy-anti-sybil".to_string(),
            subject_key: subject_key.clone(),
            requested_admission_class: GenericTrustAdmissionClass::BondBacked,
            proof_of_work_nonce: Some(pow_nonce.clone()),
        })
        .send()
        .expect("evaluate first allowed request")
        .json()
        .expect("parse first allowed evaluation");
    assert!(first_allowed.accepted);
    assert_eq!(
        first_allowed
            .rate_limit
            .as_ref()
            .map(|value| value.remaining),
        Some(1)
    );

    let second_allowed: FederationAdmissionEvaluationResponse = client
        .post(format!(
            "{base_url}/v1/federation/open-admission-policies/evaluate"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&FederationAdmissionEvaluationRequest {
            policy_id: "policy-anti-sybil".to_string(),
            subject_key: subject_key.clone(),
            requested_admission_class: GenericTrustAdmissionClass::BondBacked,
            proof_of_work_nonce: Some(pow_nonce.clone()),
        })
        .send()
        .expect("evaluate second allowed request")
        .json()
        .expect("parse second allowed evaluation");
    assert!(second_allowed.accepted);
    assert_eq!(
        second_allowed
            .rate_limit
            .as_ref()
            .map(|value| value.remaining),
        Some(0)
    );

    let limited: FederationAdmissionEvaluationResponse = client
        .post(format!(
            "{base_url}/v1/federation/open-admission-policies/evaluate"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&FederationAdmissionEvaluationRequest {
            policy_id: "policy-anti-sybil".to_string(),
            subject_key,
            requested_admission_class: GenericTrustAdmissionClass::BondBacked,
            proof_of_work_nonce: Some(pow_nonce),
        })
        .send()
        .expect("evaluate limited request")
        .json()
        .expect("parse limited evaluation");
    assert!(!limited.accepted);
    assert!(
        limited.decision_reason.contains("rate limit exceeded"),
        "unexpected rate-limit denial: {}",
        limited.decision_reason
    );
    assert!(
        limited
            .rate_limit
            .as_ref()
            .and_then(|status| status.retry_after_seconds)
            .is_some(),
        "expected retry_after_seconds in rate limit response"
    );
}
