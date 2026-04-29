#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::enterprise_federation::EnterpriseProviderRecord;
use chio_control_plane::scim_lifecycle::{
    build_scim_user_record, derive_enterprise_subject_key, ScimLifecycleRegistry, ScimUserResource,
    CHIO_SCIM_USER_EXTENSION_SCHEMA, SCIM_CORE_USER_SCHEMA,
};
use chio_core::capability::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::crypto::Keypair;
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

fn spawn_trust_service(
    listen: std::net::SocketAddr,
    advertise_url: &str,
    service_token: &str,
    receipt_db_path: &PathBuf,
    revocation_db_path: &PathBuf,
    authority_seed_path: &PathBuf,
    budget_db_path: &PathBuf,
    enterprise_providers_file: Option<&PathBuf>,
) -> ServerGuard {
    spawn_trust_service_with_verifier(
        listen,
        advertise_url,
        service_token,
        receipt_db_path,
        revocation_db_path,
        authority_seed_path,
        budget_db_path,
        enterprise_providers_file,
        None,
        None,
        None,
    )
}

fn spawn_trust_service_with_verifier(
    listen: std::net::SocketAddr,
    advertise_url: &str,
    service_token: &str,
    receipt_db_path: &PathBuf,
    revocation_db_path: &PathBuf,
    authority_seed_path: &PathBuf,
    budget_db_path: &PathBuf,
    enterprise_providers_file: Option<&PathBuf>,
    scim_lifecycle_file: Option<&PathBuf>,
    verifier_policies_file: Option<&PathBuf>,
    verifier_challenge_db: Option<&PathBuf>,
) -> ServerGuard {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.current_dir(workspace_root()).args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--revocation-db",
        revocation_db_path.to_str().expect("revocation db path"),
        "--authority-seed-file",
        authority_seed_path.to_str().expect("authority seed path"),
        "--budget-db",
        budget_db_path.to_str().expect("budget db path"),
        "trust",
        "serve",
        "--listen",
        &listen.to_string(),
        "--advertise-url",
        advertise_url,
        "--service-token",
        service_token,
    ]);
    if let Some(path) = enterprise_providers_file {
        command.args([
            "--enterprise-providers-file",
            path.to_str().expect("enterprise providers file path"),
        ]);
    }
    if let Some(path) = scim_lifecycle_file {
        command.args([
            "--scim-lifecycle-file",
            path.to_str().expect("scim lifecycle file path"),
        ]);
    }
    if let Some(path) = verifier_policies_file {
        command.args([
            "--verifier-policies-file",
            path.to_str().expect("verifier policies file path"),
        ]);
    }
    if let Some(path) = verifier_challenge_db {
        command.args([
            "--verifier-challenge-db",
            path.to_str().expect("verifier challenge db path"),
        ]);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str) {
    for _ in 0..100 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
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

fn create_passport(
    receipt_db_path: &PathBuf,
    budget_db_path: &PathBuf,
    subject_hex: &str,
    passport_path: &PathBuf,
    signing_seed_path: &PathBuf,
) {
    create_passport_with_enterprise_identity(
        receipt_db_path,
        budget_db_path,
        subject_hex,
        passport_path,
        signing_seed_path,
        None,
    );
}

fn create_passport_with_enterprise_identity(
    receipt_db_path: &PathBuf,
    budget_db_path: &PathBuf,
    subject_hex: &str,
    passport_path: &PathBuf,
    signing_seed_path: &PathBuf,
    enterprise_identity_path: Option<&PathBuf>,
) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.current_dir(workspace_root());
    command.args([
        "--receipt-db",
        receipt_db_path.to_str().expect("receipt db path"),
        "--budget-db",
        budget_db_path.to_str().expect("budget db path"),
        "passport",
        "create",
        "--subject-public-key",
        subject_hex,
        "--output",
        passport_path.to_str().expect("passport path"),
        "--signing-seed-file",
        signing_seed_path.to_str().expect("signing seed path"),
    ]);
    if let Some(enterprise_identity_path) = enterprise_identity_path {
        command.args([
            "--enterprise-identity",
            enterprise_identity_path
                .to_str()
                .expect("enterprise identity path"),
        ]);
    }
    let output = command.output().expect("run passport create");
    assert!(
        output.status.success(),
        "chio passport create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_challenge(output_path: &PathBuf, verifier: &str, verifier_policy_path: Option<&PathBuf>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.current_dir(workspace_root()).args([
        "passport",
        "challenge",
        "create",
        "--output",
        output_path.to_str().expect("challenge path"),
        "--verifier",
        verifier,
    ]);
    if let Some(verifier_policy_path) = verifier_policy_path {
        command.args([
            "--policy",
            verifier_policy_path.to_str().expect("verifier policy path"),
        ]);
    }
    let output = command.output().expect("run passport challenge create");
    assert!(
        output.status.success(),
        "chio passport challenge create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_remote_challenge(
    base_url: &str,
    service_token: &str,
    output_path: &PathBuf,
    verifier: &str,
    policy_id: &str,
) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            base_url,
            "--control-token",
            service_token,
            "passport",
            "challenge",
            "create",
            "--output",
            output_path.to_str().expect("challenge path"),
            "--verifier",
            verifier,
            "--policy-id",
            policy_id,
        ])
        .output()
        .expect("run remote passport challenge create");
    assert!(
        output.status.success(),
        "remote chio passport challenge create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_signed_verifier_policy(
    output_path: &PathBuf,
    registry_path: &PathBuf,
    signing_seed_path: &PathBuf,
    raw_policy_path: &PathBuf,
    policy_id: &str,
    verifier: &str,
) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "policy",
            "create",
            "--output",
            output_path.to_str().expect("policy output path"),
            "--policy-id",
            policy_id,
            "--verifier",
            verifier,
            "--signing-seed-file",
            signing_seed_path
                .to_str()
                .expect("policy signing seed path"),
            "--policy",
            raw_policy_path.to_str().expect("raw policy path"),
            "--expires-at",
            "1900000000",
            "--verifier-policies-file",
            registry_path.to_str().expect("policy registry path"),
        ])
        .output()
        .expect("run passport policy create");
    assert!(
        output.status.success(),
        "chio passport policy create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_challenge_response(
    passport_path: &PathBuf,
    challenge_path: &PathBuf,
    holder_seed_path: &PathBuf,
    response_path: &PathBuf,
) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
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
        .expect("run passport challenge respond");
    assert!(
        output.status.success(),
        "chio passport challenge respond failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_capability_policy(path: &PathBuf, ttl: u64, tools: &[(&str, &str, &str)]) {
    let mut yaml =
        "kernel:\n  max_capability_ttl: 3600\ncapabilities:\n  default:\n    tools:\n".to_string();
    for (server, tool, operation) in tools {
        yaml.push_str(&format!(
            "      - server: \"{server}\"\n        tool: \"{tool}\"\n        operations: [{operation}]\n        ttl: {ttl}\n"
        ));
    }
    fs::write(path, yaml).expect("write capability policy");
}

fn write_single_capability_policy(path: &PathBuf) {
    write_capability_policy(path, 300, &[("filesystem", "read_file", "read")]);
}

fn write_enterprise_capability_policy(
    path: &PathBuf,
    organization_id: &str,
    groups: &[&str],
    roles: &[&str],
) {
    let mut yaml = String::new();
    yaml.push_str("hushspec: \"0.1.0\"\n");
    yaml.push_str("rules:\n");
    yaml.push_str("  tool_access:\n");
    yaml.push_str("    enabled: true\n");
    yaml.push_str("    allow: [read_file]\n");
    yaml.push_str("    default: block\n");
    yaml.push_str("extensions:\n");
    yaml.push_str("  origins:\n");
    yaml.push_str("    profiles:\n");
    yaml.push_str("      - id: enterprise-allow\n");
    yaml.push_str("        match:\n");
    yaml.push_str("          provider: enterprise-login\n");
    yaml.push_str("          tenant_id: tenant-123\n");
    yaml.push_str(&format!("          organization_id: {organization_id}\n"));
    yaml.push_str("          groups:\n");
    for group in groups {
        yaml.push_str(&format!("            - {group}\n"));
    }
    yaml.push_str("          roles:\n");
    for role in roles {
        yaml.push_str(&format!("            - {role}\n"));
    }
    fs::write(path, yaml).expect("write enterprise capability policy");
}

fn write_enterprise_provider_registry(path: &PathBuf, records: &[serde_json::Value]) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": "chio.enterprise-providers.v1",
            "providers": records.iter().map(|record| {
                let provider_id = record["provider_id"]
                    .as_str()
                    .expect("provider_id");
                (provider_id.to_string(), record.clone())
            }).collect::<serde_json::Map<String, serde_json::Value>>(),
        }))
        .expect("serialize enterprise provider registry"),
    )
    .expect("write enterprise provider registry");
}

fn enterprise_provider_record(
    provider_id: &str,
    enabled: bool,
    organization_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "provider_id": provider_id,
        "kind": "oidc_jwks",
        "enabled": enabled,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": "jwks:enterprise-login",
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_issuers": ["https://issuer.enterprise.example"],
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": [organization_id]
        },
        "issuer": "https://issuer.enterprise.example",
        "jwks_url": "https://issuer.enterprise.example/jwks",
        "tenant_id": "tenant-123",
        "organization_id": organization_id,
        "subject_mapping": {
            "principal_source": "sub",
            "tenant_id_field": "tid",
            "organization_id_field": "org_id",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    })
}

fn scim_enterprise_provider_record(
    provider_id: &str,
    enabled: bool,
    organization_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "provider_id": provider_id,
        "kind": "scim",
        "enabled": enabled,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": "scim:enterprise-login",
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": [organization_id]
        },
        "scim_base_url": "https://issuer.enterprise.example/scim/v2",
        "tenant_id": "tenant-123",
        "organization_id": organization_id,
        "subject_mapping": {
            "principal_source": "userName",
            "tenant_id_field": "tenantId",
            "organization_id_field": "organizationId",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    })
}

fn write_enterprise_identity(
    path: &PathBuf,
    provider_record_id: Option<&str>,
    organization_id: &str,
    groups: &[&str],
    roles: &[&str],
) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "providerId": "enterprise-login",
            "providerRecordId": provider_record_id,
            "providerKind": "oidc_jwks",
            "federationMethod": "jwt",
            "principal": "oidc:https://issuer.enterprise.example#sub:user-123",
            "subjectKey": "enterprise-subject-key",
            "tenantId": "tenant-123",
            "organizationId": organization_id,
            "groups": groups,
            "roles": roles,
            "attributeSources": {
                "principal": "sub",
                "tenantId": "tid",
                "organizationId": "org_id",
                "groups": "groups",
                "roles": "roles"
            },
            "trustMaterialRef": "jwks:enterprise-login"
        }))
        .expect("serialize enterprise identity"),
    )
    .expect("write enterprise identity");
}

fn write_scim_enterprise_identity(
    path: &PathBuf,
    provider_record_id: Option<&str>,
    organization_id: &str,
    groups: &[&str],
    roles: &[&str],
) {
    let principal = "alice@example.com";
    let subject_key = derive_enterprise_subject_key("enterprise-login", principal);
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "providerId": "enterprise-login",
            "providerRecordId": provider_record_id,
            "providerKind": "scim",
            "federationMethod": "scim",
            "principal": principal,
            "subjectKey": subject_key,
            "tenantId": "tenant-123",
            "organizationId": organization_id,
            "groups": groups,
            "roles": roles,
            "attributeSources": {
                "principal": "userName",
                "tenantId": "tenantId",
                "organizationId": "organizationId",
                "groups": "groups",
                "roles": "roles"
            },
            "trustMaterialRef": "scim:enterprise-login"
        }))
        .expect("serialize scim enterprise identity"),
    )
    .expect("write scim enterprise identity");
}

fn write_scim_lifecycle_registry(
    path: &PathBuf,
    provider_id: &str,
    organization_id: &str,
    groups: &[&str],
    roles: &[&str],
) {
    let provider: EnterpriseProviderRecord = serde_json::from_value(
        scim_enterprise_provider_record(provider_id, true, organization_id),
    )
    .expect("parse scim provider record");
    let user: ScimUserResource = serde_json::from_value(serde_json::json!({
        "schemas": [SCIM_CORE_USER_SCHEMA, CHIO_SCIM_USER_EXTENSION_SCHEMA],
        "externalId": "ext-user-123",
        "userName": "alice@example.com",
        "active": true,
        "groups": groups.iter().map(|group| serde_json::json!({ "value": group })).collect::<Vec<_>>(),
        "roles": roles.iter().map(|role| serde_json::json!({ "value": role })).collect::<Vec<_>>(),
        CHIO_SCIM_USER_EXTENSION_SCHEMA: {
            "providerId": provider_id,
            "tenantId": "tenant-123",
            "organizationId": organization_id
        }
    }))
    .expect("parse scim user");
    let record = build_scim_user_record(&provider, user, 1_700_000_000, None)
        .expect("build scim lifecycle record");
    let mut registry = ScimLifecycleRegistry::default();
    registry
        .insert(record)
        .expect("insert scim lifecycle record");
    registry.save(path).expect("save scim lifecycle registry");
}

struct EnterpriseFederatedIssueHarness {
    _service: ServerGuard,
    base_url: String,
    service_token: String,
    challenge_path: PathBuf,
    response_path: PathBuf,
    capability_policy_path: PathBuf,
    enterprise_identity_path: PathBuf,
}

fn run_enterprise_federated_issue(
    harness: &EnterpriseFederatedIssueHarness,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &harness.base_url,
            "--control-token",
            &harness.service_token,
            "trust",
            "federated-issue",
            "--presentation-response",
            harness
                .response_path
                .to_str()
                .expect("presentation response path"),
            "--challenge",
            harness.challenge_path.to_str().expect("challenge path"),
            "--capability-policy",
            harness
                .capability_policy_path
                .to_str()
                .expect("capability policy path"),
            "--enterprise-identity",
            harness
                .enterprise_identity_path
                .to_str()
                .expect("enterprise identity path"),
        ])
        .output()
        .expect("run enterprise federated issue")
}

fn setup_enterprise_federated_issue_case(
    prefix: &str,
    policy_organization_id: &str,
    identity_organization_id: &str,
    identity_groups: &[&str],
    identity_roles: &[&str],
    provider_record_id: Option<&str>,
    provider_registry_records: Option<Vec<serde_json::Value>>,
) -> EnterpriseFederatedIssueHarness {
    let dir = unique_dir(prefix);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_seed_path = dir.join("authority-seed.txt");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let issuer_seed_path = dir.join("issuer-seed.txt");
    let holder_seed_path = dir.join("holder-seed.txt");
    let verifier_policy_path = dir.join("verifier-policy.yaml");
    let challenge_path = dir.join("challenge.json");
    let response_path = dir.join("presentation-response.json");
    let capability_policy_path = dir.join("enterprise-capability-policy.yaml");
    let enterprise_identity_path = dir.join("enterprise-identity.json");
    let enterprise_providers_path = dir.join("enterprise-providers.json");

    let subject_kp = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject_kp.seed_hex()))
        .expect("write holder seed");
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    write_enterprise_identity(
        &enterprise_identity_path,
        provider_record_id,
        identity_organization_id,
        identity_groups,
        identity_roles,
    );
    create_passport_with_enterprise_identity(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &issuer_seed_path,
        Some(&enterprise_identity_path),
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did");
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(
        &verifier_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy");

    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let service_token = format!("{prefix}-token");
    create_challenge(&challenge_path, &base_url, Some(&verifier_policy_path));
    create_challenge_response(
        &passport_path,
        &challenge_path,
        &holder_seed_path,
        &response_path,
    );
    write_enterprise_capability_policy(
        &capability_policy_path,
        policy_organization_id,
        &["eng", "ops"],
        &["operator"],
    );
    let enterprise_providers_file = provider_registry_records.as_ref().map(|records| {
        write_enterprise_provider_registry(&enterprise_providers_path, records);
        enterprise_providers_path
    });

    let service = spawn_trust_service(
        listen,
        &base_url,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_seed_path,
        &budget_db_path,
        enterprise_providers_file.as_ref(),
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    EnterpriseFederatedIssueHarness {
        _service: service,
        base_url,
        service_token,
        challenge_path,
        response_path,
        capability_policy_path,
        enterprise_identity_path,
    }
}

fn create_federated_delegation_policy(
    output_path: &PathBuf,
    signing_seed_path: &PathBuf,
    issuer: &str,
    partner: &str,
    verifier: &str,
    capability_policy_path: &PathBuf,
    parent_capability_id: Option<&str>,
) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.current_dir(workspace_root()).args([
        "trust",
        "federated-delegation-policy-create",
        "--output",
        output_path.to_str().expect("delegation policy path"),
        "--signing-seed-file",
        signing_seed_path.to_str().expect("signing seed path"),
        "--issuer",
        issuer,
        "--partner",
        partner,
        "--verifier",
        verifier,
        "--capability-policy",
        capability_policy_path
            .to_str()
            .expect("delegation capability policy path"),
        "--expires-at",
        "1900000000",
    ]);
    if let Some(parent_capability_id) = parent_capability_id {
        command.args(["--parent-capability-id", parent_capability_id]);
    }
    let output = command
        .output()
        .expect("run federated delegation policy create");
    assert!(
        output.status.success(),
        "chio trust federated-delegation-policy-create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_evidence_federation_policy(
    output_path: &PathBuf,
    signing_seed_path: &PathBuf,
    issuer: &str,
    partner: &str,
    capability_id: &str,
) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "evidence",
            "federation-policy",
            "create",
            "--output",
            output_path.to_str().expect("federation policy path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("signing seed path"),
            "--issuer",
            issuer,
            "--partner",
            partner,
            "--capability",
            capability_id,
            "--expires-at",
            "1900000000",
        ])
        .output()
        .expect("run evidence federation policy create");
    assert!(
        output.status.success(),
        "chio evidence federation-policy create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn trust_service_federated_issue_consumes_challenge_bound_passport_response() {
    let dir = unique_dir("chio-cli-federated-issue");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_seed_path = dir.join("authority-seed.txt");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let issuer_seed_path = dir.join("issuer-seed.txt");
    let holder_seed_path = dir.join("holder-seed.txt");
    let verifier_policy_path = dir.join("verifier-policy.yaml");
    let challenge_path = dir.join("challenge.json");
    let response_path = dir.join("presentation-response.json");
    let capability_policy_path = dir.join("capability-policy.yaml");
    let delegation_policy_capability_path = dir.join("delegation-capability-policy.yaml");
    let delegation_policy_path = dir.join("delegation-policy.json");

    let subject_kp = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject_kp.seed_hex()))
        .expect("write holder seed");
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &issuer_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did");
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(
        &verifier_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy");

    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let service_token = "federated-issue-token";
    create_challenge(&challenge_path, &base_url, Some(&verifier_policy_path));
    create_challenge_response(
        &passport_path,
        &challenge_path,
        &holder_seed_path,
        &response_path,
    );
    write_single_capability_policy(&capability_policy_path);
    write_capability_policy(
        &delegation_policy_capability_path,
        900,
        &[
            ("filesystem", "read_file", "read"),
            ("filesystem", "write_file", "invoke"),
        ],
    );
    create_federated_delegation_policy(
        &delegation_policy_path,
        &authority_seed_path,
        "local-org",
        "remote-org",
        &base_url,
        &delegation_policy_capability_path,
        None,
    );

    let _service = spawn_trust_service(
        listen,
        &base_url,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_seed_path,
        &budget_db_path,
        None,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "federated-issue",
            "--presentation-response",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--capability-policy",
            capability_policy_path
                .to_str()
                .expect("capability policy path"),
            "--delegation-policy",
            delegation_policy_path
                .to_str()
                .expect("delegation policy path"),
        ])
        .output()
        .expect("run trust federated-issue");

    assert!(
        output.status.success(),
        "chio trust federated-issue failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse federated issue output");
    assert_eq!(body["subject"], passport["subject"]);
    assert_eq!(body["subjectPublicKey"], subject_hex);
    assert_eq!(body["verification"]["accepted"], true);
    assert_eq!(body["verification"]["verifier"], base_url);
    assert_eq!(body["capability"]["subject"], subject_hex);
    let delegation_anchor = body["delegationAnchorCapabilityId"]
        .as_str()
        .expect("delegation anchor capability id");
    assert_eq!(
        body["capability"]["scope"]["grants"][0]["tool_name"],
        "read_file"
    );

    let chain_response = client
        .get(format!(
            "{base_url}/v1/lineage/{}/chain",
            body["capability"]["id"].as_str().expect("capability id")
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request lineage chain");
    assert_eq!(chain_response.status(), reqwest::StatusCode::OK);
    let chain: serde_json::Value = chain_response.json().expect("parse lineage chain");
    let chain = chain.as_array().expect("lineage chain array");
    assert_eq!(
        chain.len(),
        2,
        "expected delegation anchor plus issued capability"
    );
    assert_eq!(chain[0]["capability_id"], delegation_anchor);
    assert_eq!(chain[0]["delegation_depth"], 0);
    assert_eq!(chain[1]["capability_id"], body["capability"]["id"]);
    assert_eq!(chain[1]["parent_capability_id"], delegation_anchor);
    assert_eq!(chain[1]["delegation_depth"], 1);
    let authority_seed = fs::read_to_string(&authority_seed_path).expect("read authority seed");
    let authority_public_key = Keypair::from_seed_hex(authority_seed.trim())
        .expect("authority keypair")
        .public_key()
        .to_hex();
    assert_eq!(chain[0]["issuer_key"], authority_public_key);
}

#[test]
fn trust_service_federated_issue_supports_stored_verifier_policy_references_and_replay_safety() {
    let dir = unique_dir("chio-cli-federated-issue-policy-ref");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_seed_path = dir.join("authority-seed.txt");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let issuer_seed_path = dir.join("issuer-seed.txt");
    let holder_seed_path = dir.join("holder-seed.txt");
    let verifier_seed_path = dir.join("verifier-seed.txt");
    let raw_verifier_policy_path = dir.join("verifier-policy.yaml");
    let signed_verifier_policy_path = dir.join("signed-verifier-policy.json");
    let verifier_policies_path = dir.join("verifier-policies.json");
    let verifier_challenge_db_path = dir.join("verifier-challenges.sqlite3");
    let challenge_path = dir.join("challenge.json");
    let response_path = dir.join("presentation-response.json");
    let capability_policy_path = dir.join("capability-policy.yaml");

    let subject_kp = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject_kp.seed_hex()))
        .expect("write holder seed");
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &issuer_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did");
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(
        &raw_verifier_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy");

    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let service_token = "federated-issue-policy-ref-token";
    create_signed_verifier_policy(
        &signed_verifier_policy_path,
        &verifier_policies_path,
        &verifier_seed_path,
        &raw_verifier_policy_path,
        "rp-default",
        &base_url,
    );
    write_single_capability_policy(&capability_policy_path);

    let _service = spawn_trust_service_with_verifier(
        listen,
        &base_url,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_seed_path,
        &budget_db_path,
        None,
        None,
        Some(&verifier_policies_path),
        Some(&verifier_challenge_db_path),
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    create_remote_challenge(
        &base_url,
        service_token,
        &challenge_path,
        &base_url,
        "rp-default",
    );
    let challenge: serde_json::Value =
        serde_json::from_slice(&fs::read(&challenge_path).expect("read challenge"))
            .expect("parse challenge");
    assert_eq!(challenge["policyRef"]["policyId"], "rp-default");
    assert!(challenge["challengeId"].as_str().is_some());
    assert!(challenge["policy"].is_null());

    create_challenge_response(
        &passport_path,
        &challenge_path,
        &holder_seed_path,
        &response_path,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "federated-issue",
            "--presentation-response",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--capability-policy",
            capability_policy_path
                .to_str()
                .expect("capability policy path"),
        ])
        .output()
        .expect("run trust federated-issue");

    assert!(
        output.status.success(),
        "chio trust federated-issue failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse federated issue output");
    assert_eq!(body["subject"], passport["subject"]);
    assert_eq!(body["subjectPublicKey"], subject_hex);
    assert_eq!(body["verification"]["accepted"], true);
    assert_eq!(body["verification"]["verifier"], base_url);
    assert_eq!(body["verification"]["policyId"], "rp-default");
    assert_eq!(body["verification"]["policySource"], "registry:rp-default");
    assert_eq!(body["verification"]["replayState"], "consumed");
    assert!(body["verification"]["challengeId"].as_str().is_some());
    assert_eq!(body["capability"]["subject"], subject_hex);

    let replay = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "federated-issue",
            "--presentation-response",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--capability-policy",
            capability_policy_path
                .to_str()
                .expect("capability policy path"),
        ])
        .output()
        .expect("rerun trust federated-issue");

    assert!(
        !replay.status.success(),
        "replayed federated issue should fail\nstdout={}\nstderr={}",
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
fn trust_service_federated_issue_requires_embedded_or_stored_verifier_policy() {
    let dir = unique_dir("chio-cli-federated-issue-no-policy");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_seed_path = dir.join("authority-seed.txt");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let issuer_seed_path = dir.join("issuer-seed.txt");
    let holder_seed_path = dir.join("holder-seed.txt");
    let challenge_path = dir.join("challenge.json");
    let response_path = dir.join("presentation-response.json");
    let capability_policy_path = dir.join("capability-policy.yaml");

    let subject_kp = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject_kp.seed_hex()))
        .expect("write holder seed");
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &issuer_seed_path,
    );

    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let service_token = "federated-issue-no-policy-token";
    create_challenge(&challenge_path, &base_url, None);
    create_challenge_response(
        &passport_path,
        &challenge_path,
        &holder_seed_path,
        &response_path,
    );
    write_single_capability_policy(&capability_policy_path);

    let _service = spawn_trust_service(
        listen,
        &base_url,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_seed_path,
        &budget_db_path,
        None,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "federated-issue",
            "--presentation-response",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--capability-policy",
            capability_policy_path
                .to_str()
                .expect("capability policy path"),
        ])
        .output()
        .expect("run trust federated-issue");

    assert!(
        !output.status.success(),
        "federated issue should fail without embedded or stored verifier policy"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("embedded or stored verifier policy"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn trust_service_federated_issue_rejects_scope_outside_delegation_policy() {
    let dir = unique_dir("chio-cli-federated-issue-scope-deny");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_seed_path = dir.join("authority-seed.txt");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let issuer_seed_path = dir.join("issuer-seed.txt");
    let holder_seed_path = dir.join("holder-seed.txt");
    let verifier_policy_path = dir.join("verifier-policy.yaml");
    let challenge_path = dir.join("challenge.json");
    let response_path = dir.join("presentation-response.json");
    let child_capability_policy_path = dir.join("child-capability-policy.yaml");
    let delegation_capability_policy_path = dir.join("delegation-capability-policy.yaml");
    let delegation_policy_path = dir.join("delegation-policy.json");

    let subject_kp = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject_kp.seed_hex()))
        .expect("write holder seed");
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &issuer_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did");
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(
        &verifier_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy");

    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let service_token = "federated-issue-scope-token";
    create_challenge(&challenge_path, &base_url, Some(&verifier_policy_path));
    create_challenge_response(
        &passport_path,
        &challenge_path,
        &holder_seed_path,
        &response_path,
    );
    write_capability_policy(
        &child_capability_policy_path,
        300,
        &[
            ("filesystem", "read_file", "read"),
            ("filesystem", "write_file", "invoke"),
        ],
    );
    write_single_capability_policy(&delegation_capability_policy_path);
    create_federated_delegation_policy(
        &delegation_policy_path,
        &authority_seed_path,
        "local-org",
        "remote-org",
        &base_url,
        &delegation_capability_policy_path,
        None,
    );

    let _service = spawn_trust_service(
        listen,
        &base_url,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_seed_path,
        &budget_db_path,
        None,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "federated-issue",
            "--presentation-response",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--capability-policy",
            child_capability_policy_path
                .to_str()
                .expect("child capability policy path"),
            "--delegation-policy",
            delegation_policy_path
                .to_str()
                .expect("delegation policy path"),
        ])
        .output()
        .expect("run trust federated-issue");

    assert!(
        !output.status.success(),
        "federated issue should fail when requested scope exceeds delegation policy"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("delegation policy ceiling"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn trust_service_federated_issue_supports_multi_hop_imported_upstream_parent() {
    let dir = unique_dir("chio-cli-federated-issue-multi-hop");
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let shared_signer_seed_path = dir.join("shared-signer-seed.txt");
    let a_receipt_db_path = dir.join("a-receipts.sqlite3");
    let a_revocation_db_path = dir.join("a-revocations.sqlite3");
    let a_budget_db_path = dir.join("a-budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let issuer_seed_path = dir.join("issuer-seed.txt");
    let holder_seed_path = dir.join("holder-seed.txt");
    let verifier_policy_a_path = dir.join("verifier-policy-a.yaml");
    let challenge_a_path = dir.join("challenge-a.json");
    let response_a_path = dir.join("presentation-response-a.json");
    let capability_policy_a_path = dir.join("capability-policy-a.yaml");
    let delegation_policy_capability_a_path = dir.join("delegation-capability-policy-a.yaml");
    let delegation_policy_a_path = dir.join("delegation-policy-a.json");
    let federation_policy_path = dir.join("evidence-federation-policy.json");
    let evidence_package_dir = dir.join("evidence-package");

    let b_receipt_db_path = dir.join("b-receipts.sqlite3");
    let b_revocation_db_path = dir.join("b-revocations.sqlite3");
    let b_budget_db_path = dir.join("b-budgets.sqlite3");
    let verifier_policy_b_path = dir.join("verifier-policy-b.yaml");
    let challenge_b_path = dir.join("challenge-b.json");
    let response_b_path = dir.join("presentation-response-b.json");
    let capability_policy_b_path = dir.join("capability-policy-b.yaml");
    let delegation_policy_b_path = dir.join("delegation-policy-b.json");

    let subject_kp = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject_kp.seed_hex()))
        .expect("write holder seed");
    let subject_hex = seed_subject_history(&a_receipt_db_path, &a_budget_db_path, &subject_kp);
    create_passport(
        &a_receipt_db_path,
        &a_budget_db_path,
        &subject_hex,
        &passport_path,
        &issuer_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did");
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(
        &verifier_policy_a_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy a");
    fs::write(
        &verifier_policy_b_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy b");

    let listen_a = reserve_listen_addr();
    let base_url_a = format!("http://{listen_a}");
    let service_token_a = "federated-multi-hop-a-token";
    create_challenge(
        &challenge_a_path,
        &base_url_a,
        Some(&verifier_policy_a_path),
    );
    create_challenge_response(
        &passport_path,
        &challenge_a_path,
        &holder_seed_path,
        &response_a_path,
    );
    write_single_capability_policy(&capability_policy_a_path);
    write_capability_policy(
        &delegation_policy_capability_a_path,
        900,
        &[("filesystem", "read_file", "read")],
    );
    create_federated_delegation_policy(
        &delegation_policy_a_path,
        &shared_signer_seed_path,
        "org-alpha",
        "org-beta",
        &base_url_a,
        &delegation_policy_capability_a_path,
        None,
    );

    let _service_a = spawn_trust_service(
        listen_a,
        &base_url_a,
        service_token_a,
        &a_receipt_db_path,
        &a_revocation_db_path,
        &shared_signer_seed_path,
        &a_budget_db_path,
        None,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url_a);

    let first_issue = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_a,
            "--control-token",
            service_token_a,
            "trust",
            "federated-issue",
            "--presentation-response",
            response_a_path.to_str().expect("response a path"),
            "--challenge",
            challenge_a_path.to_str().expect("challenge a path"),
            "--capability-policy",
            capability_policy_a_path
                .to_str()
                .expect("capability policy a path"),
            "--delegation-policy",
            delegation_policy_a_path
                .to_str()
                .expect("delegation policy a path"),
        ])
        .output()
        .expect("run first federated issue");
    assert!(
        first_issue.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&first_issue.stdout),
        String::from_utf8_lossy(&first_issue.stderr)
    );
    let first_body: serde_json::Value =
        serde_json::from_slice(&first_issue.stdout).expect("parse first issue output");
    let first_capability_id = first_body["capability"]["id"]
        .as_str()
        .expect("first capability id")
        .to_string();
    let first_anchor_id = first_body["delegationAnchorCapabilityId"]
        .as_str()
        .expect("first anchor id")
        .to_string();

    let authority_public_key = Keypair::from_seed_hex(
        fs::read_to_string(&shared_signer_seed_path)
            .expect("read shared signer seed")
            .trim(),
    )
    .expect("shared signer keypair")
    .public_key()
    .to_hex();
    {
        let store = SqliteReceiptStore::open(&a_receipt_db_path).expect("open a receipt store");
        store
            .append_chio_receipt(&make_receipt(
                "fed-hop-a-1",
                &first_capability_id,
                &subject_hex,
                &authority_public_key,
                1_700_100_000,
            ))
            .expect("append federated hop receipt");
    }

    create_evidence_federation_policy(
        &federation_policy_path,
        &shared_signer_seed_path,
        "org-alpha",
        "org-beta",
        &first_capability_id,
    );

    let export = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            a_receipt_db_path.to_str().expect("a receipt db path"),
            "evidence",
            "export",
            "--output",
            evidence_package_dir.to_str().expect("evidence package dir"),
            "--capability",
            &first_capability_id,
            "--federation-policy",
            federation_policy_path
                .to_str()
                .expect("federation policy path"),
        ])
        .output()
        .expect("run evidence export");
    assert!(
        export.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&export.stdout),
        String::from_utf8_lossy(&export.stderr)
    );

    let listen_b = reserve_listen_addr();
    let base_url_b = format!("http://{listen_b}");
    let service_token_b = "federated-multi-hop-b-token";
    create_challenge(
        &challenge_b_path,
        &base_url_b,
        Some(&verifier_policy_b_path),
    );
    create_challenge_response(
        &passport_path,
        &challenge_b_path,
        &holder_seed_path,
        &response_b_path,
    );
    write_capability_policy(
        &capability_policy_b_path,
        120,
        &[("filesystem", "read_file", "read")],
    );

    let _service_b = spawn_trust_service(
        listen_b,
        &base_url_b,
        service_token_b,
        &b_receipt_db_path,
        &b_revocation_db_path,
        &shared_signer_seed_path,
        &b_budget_db_path,
        None,
    );
    wait_for_trust_service(&client, &base_url_b);

    let import = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_b,
            "--control-token",
            service_token_b,
            "evidence",
            "import",
            "--input",
            evidence_package_dir
                .to_str()
                .expect("evidence package dir path"),
        ])
        .output()
        .expect("run evidence import");
    assert!(
        import.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&import.stdout),
        String::from_utf8_lossy(&import.stderr)
    );

    create_federated_delegation_policy(
        &delegation_policy_b_path,
        &shared_signer_seed_path,
        "org-alpha",
        "org-gamma",
        &base_url_b,
        &capability_policy_b_path,
        Some(&first_capability_id),
    );

    let second_issue = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url_b,
            "--control-token",
            service_token_b,
            "trust",
            "federated-issue",
            "--presentation-response",
            response_b_path.to_str().expect("response b path"),
            "--challenge",
            challenge_b_path.to_str().expect("challenge b path"),
            "--capability-policy",
            capability_policy_b_path
                .to_str()
                .expect("capability policy b path"),
            "--delegation-policy",
            delegation_policy_b_path
                .to_str()
                .expect("delegation policy b path"),
            "--upstream-capability-id",
            &first_capability_id,
        ])
        .output()
        .expect("run second federated issue");
    assert!(
        second_issue.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&second_issue.stdout),
        String::from_utf8_lossy(&second_issue.stderr)
    );
    let second_body: serde_json::Value =
        serde_json::from_slice(&second_issue.stdout).expect("parse second issue output");
    let second_capability_id = second_body["capability"]["id"]
        .as_str()
        .expect("second capability id");
    let second_anchor_id = second_body["delegationAnchorCapabilityId"]
        .as_str()
        .expect("second anchor id");

    let imported_parent_response = client
        .get(format!("{base_url_b}/v1/lineage/{first_capability_id}"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token_b}"),
        )
        .send()
        .expect("request imported parent lineage");
    assert_eq!(imported_parent_response.status(), reqwest::StatusCode::OK);

    let chain_response = client
        .get(format!(
            "{base_url_b}/v1/lineage/{second_capability_id}/chain"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token_b}"),
        )
        .send()
        .expect("request combined lineage chain");
    assert_eq!(chain_response.status(), reqwest::StatusCode::OK);
    let chain: serde_json::Value = chain_response.json().expect("parse combined lineage chain");
    let chain = chain.as_array().expect("combined lineage chain array");
    assert_eq!(chain.len(), 4, "expected imported + local multi-hop chain");
    assert_eq!(chain[0]["capability_id"], first_anchor_id);
    assert_eq!(chain[1]["capability_id"], first_capability_id);
    assert_eq!(chain[2]["capability_id"], second_anchor_id);
    assert_eq!(chain[3]["capability_id"], second_capability_id);
    assert_eq!(chain[0]["delegation_depth"], 0);
    assert_eq!(chain[1]["delegation_depth"], 1);
    assert_eq!(chain[2]["delegation_depth"], 2);
    assert_eq!(chain[3]["delegation_depth"], 3);
    assert_eq!(chain[1]["parent_capability_id"], first_anchor_id);
    assert_eq!(chain[2]["parent_capability_id"], first_capability_id);
    assert_eq!(chain[3]["parent_capability_id"], second_anchor_id);
}

#[test]
fn federated_issue_enterprise_policy_allows_and_returns_enterprise_audit() {
    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-allow",
        "org-789",
        "org-789",
        &["eng", "ops"],
        &["operator"],
        Some("enterprise-login"),
        Some(vec![enterprise_provider_record(
            "enterprise-login",
            true,
            "org-789",
        )]),
    );

    let output = run_enterprise_federated_issue(&harness);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse enterprise allow response");
    assert_eq!(
        body["enterpriseIdentityProvenance"]["providerId"],
        "enterprise-login"
    );
    assert_eq!(
        body["verification"]["enterpriseIdentityProvenance"][0]["providerId"],
        "enterprise-login"
    );
    assert_eq!(body["enterpriseAudit"]["providerId"], "enterprise-login");
    assert_eq!(
        body["enterpriseAudit"]["providerRecordId"],
        serde_json::json!("enterprise-login")
    );
    assert_eq!(body["enterpriseAudit"]["organizationId"], "org-789");
    assert_eq!(
        body["enterpriseAudit"]["groups"],
        serde_json::json!(["eng", "ops"])
    );
    assert_eq!(
        body["enterpriseAudit"]["roles"],
        serde_json::json!(["operator"])
    );
    assert_eq!(
        body["enterpriseAudit"]["matchedOriginProfile"],
        serde_json::json!("enterprise-allow")
    );
    assert_eq!(
        body["enterpriseAudit"]["trustMaterialRef"],
        serde_json::json!("jwks:enterprise-login")
    );
}

#[test]
fn federated_issue_scim_deprovisioned_identity_fails_closed() {
    let dir = unique_dir("chio-cli-enterprise-federated-scim-deprovision");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_seed_path = dir.join("authority-seed.txt");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let issuer_seed_path = dir.join("issuer-seed.txt");
    let holder_seed_path = dir.join("holder-seed.txt");
    let verifier_policy_path = dir.join("verifier-policy.yaml");
    let challenge_path = dir.join("challenge.json");
    let response_path = dir.join("presentation-response.json");
    let capability_policy_path = dir.join("enterprise-capability-policy.yaml");
    let enterprise_identity_path = dir.join("enterprise-identity.json");
    let enterprise_providers_path = dir.join("enterprise-providers.json");
    let scim_lifecycle_path = dir.join("scim-lifecycle.json");

    let subject_kp = Keypair::generate();
    fs::write(&holder_seed_path, format!("{}\n", subject_kp.seed_hex()))
        .expect("write holder seed");
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    write_scim_enterprise_identity(
        &enterprise_identity_path,
        Some("enterprise-login"),
        "org-789",
        &["eng", "ops"],
        &["operator"],
    );
    create_passport_with_enterprise_identity(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &issuer_seed_path,
        Some(&enterprise_identity_path),
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did");
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(
        &verifier_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy");

    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let service_token = "federated-issue-scim-token";
    create_challenge(&challenge_path, &base_url, Some(&verifier_policy_path));
    create_challenge_response(
        &passport_path,
        &challenge_path,
        &holder_seed_path,
        &response_path,
    );
    write_enterprise_capability_policy(
        &capability_policy_path,
        "org-789",
        &["eng", "ops"],
        &["operator"],
    );
    write_enterprise_provider_registry(
        &enterprise_providers_path,
        &[scim_enterprise_provider_record(
            "enterprise-login",
            true,
            "org-789",
        )],
    );
    write_scim_lifecycle_registry(
        &scim_lifecycle_path,
        "enterprise-login",
        "org-789",
        &["eng", "ops"],
        &["operator"],
    );
    let user_id = ScimLifecycleRegistry::load(&scim_lifecycle_path)
        .expect("load scim lifecycle registry")
        .users
        .keys()
        .next()
        .expect("scim lifecycle user id")
        .to_string();

    let service = spawn_trust_service_with_verifier(
        listen,
        &base_url,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_seed_path,
        &budget_db_path,
        Some(&enterprise_providers_path),
        Some(&scim_lifecycle_path),
        None,
        None,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let harness = EnterpriseFederatedIssueHarness {
        _service: service,
        base_url: base_url.clone(),
        service_token: service_token.to_string(),
        challenge_path,
        response_path,
        capability_policy_path,
        enterprise_identity_path,
    };

    let first = run_enterprise_federated_issue(&harness);
    assert!(
        first.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let registry_after_issue =
        ScimLifecycleRegistry::load(&scim_lifecycle_path).expect("reload scim lifecycle registry");
    let issued_user = registry_after_issue
        .get(&user_id)
        .expect("scim lifecycle user");
    assert_eq!(issued_user.tracked_capability_ids.len(), 1);

    let delete_response = client
        .delete(format!("{base_url}/scim/v2/Users/{user_id}"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send scim delete request");
    assert_eq!(delete_response.status(), reqwest::StatusCode::OK);

    let registry_after_delete =
        ScimLifecycleRegistry::load(&scim_lifecycle_path).expect("reload scim lifecycle registry");
    let deleted_user = registry_after_delete
        .get(&user_id)
        .expect("deleted scim lifecycle user");
    assert!(!deleted_user.active());
    assert_eq!(deleted_user.revoked_capability_ids.len(), 1);

    let second = run_enterprise_federated_issue(&harness);
    assert!(
        !second.status.success(),
        "expected deprovisioned scim identity to fail"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("scim lifecycle identity"),
        "stderr={stderr}"
    );
    assert!(stderr.contains("inactive"), "stderr={stderr}");
}

#[test]
fn federated_issue_enterprise_policy_denies_organization_mismatch() {
    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-org-deny",
        "org-789",
        "org-rogue",
        &["eng", "ops"],
        &["operator"],
        Some("enterprise-login"),
        Some(vec![enterprise_provider_record(
            "enterprise-login",
            true,
            "org-789",
        )]),
    );

    let output = run_enterprise_federated_issue(&harness);
    assert!(
        !output.status.success(),
        "expected enterprise organization mismatch to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("enterpriseAudit"), "stderr={stderr}");
    assert!(stderr.contains("org-rogue"), "stderr={stderr}");
    assert!(
        stderr.contains("did not satisfy any configured origin profile"),
        "stderr={stderr}"
    );
}

#[test]
fn federated_issue_enterprise_policy_denies_missing_group() {
    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-group-deny",
        "org-789",
        "org-789",
        &["eng"],
        &["operator"],
        Some("enterprise-login"),
        Some(vec![enterprise_provider_record(
            "enterprise-login",
            true,
            "org-789",
        )]),
    );

    let output = run_enterprise_federated_issue(&harness);
    assert!(
        !output.status.success(),
        "expected enterprise missing group to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("enterpriseAudit"), "stderr={stderr}");
    assert!(stderr.contains("groups"), "stderr={stderr}");
    assert!(stderr.contains("eng"), "stderr={stderr}");
    assert!(
        stderr.contains("did not satisfy any configured origin profile"),
        "stderr={stderr}"
    );
}

#[test]
fn federated_issue_enterprise_policy_denies_missing_role() {
    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-role-deny",
        "org-789",
        "org-789",
        &["eng", "ops"],
        &["viewer"],
        Some("enterprise-login"),
        Some(vec![enterprise_provider_record(
            "enterprise-login",
            true,
            "org-789",
        )]),
    );

    let output = run_enterprise_federated_issue(&harness);
    assert!(
        !output.status.success(),
        "expected enterprise missing role to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("enterpriseAudit"), "stderr={stderr}");
    assert!(stderr.contains("roles"), "stderr={stderr}");
    assert!(stderr.contains("viewer"), "stderr={stderr}");
    assert!(
        stderr.contains("did not satisfy any configured origin profile"),
        "stderr={stderr}"
    );
}

#[test]
fn federated_issue_legacy_bearer_path_still_allows_enterprise_observability_without_provider_record(
) {
    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-legacy-bearer",
        "org-789",
        "org-rogue",
        &["eng"],
        &["viewer"],
        None,
        None,
    );

    let output = run_enterprise_federated_issue(&harness);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse enterprise legacy response");
    assert_eq!(body["enterpriseAudit"]["providerId"], "enterprise-login");
    assert_eq!(
        body["enterpriseAudit"]["providerRecordId"],
        serde_json::Value::Null
    );
    assert_eq!(
        body["enterpriseAudit"]["decisionReason"],
        serde_json::json!(
            "enterprise observability is present but no validated provider-admin record activated the enterprise-provider lane"
        )
    );
    assert_eq!(
        body["enterpriseAudit"]["matchedOriginProfile"],
        serde_json::Value::Null
    );
}

#[test]
fn federated_issue_enterprise_provider_lane_does_not_fallback_when_provider_record_is_invalid() {
    let mut invalid_provider = enterprise_provider_record("enterprise-login", true, "org-789");
    invalid_provider["provenance"]["trust_material_ref"] = serde_json::Value::Null;
    let harness = setup_enterprise_federated_issue_case(
        "chio-cli-enterprise-federated-invalid-provider",
        "org-789",
        "org-789",
        &["eng", "ops"],
        &["operator"],
        Some("enterprise-login"),
        Some(vec![invalid_provider]),
    );

    let output = run_enterprise_federated_issue(&harness);
    assert!(
        !output.status.success(),
        "expected invalid enterprise provider record to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("enterpriseAudit"), "stderr={stderr}");
    assert!(
        stderr.contains("requires a validated provider record"),
        "stderr={stderr}"
    );
    assert!(stderr.contains("enterprise-login"), "stderr={stderr}");
}
