#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;

static TRUST_SERVICE_START_LOCK: Mutex<()> = Mutex::new(());

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

fn spawn_trust_service_with_policy_registry(
    listen: std::net::SocketAddr,
    service_token: &str,
    enterprise_providers_file: Option<&Path>,
    verifier_policies_file: Option<&Path>,
) -> ServerGuard {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.current_dir(workspace_root()).args([
        "trust",
        "serve",
        "--listen",
        &listen.to_string(),
        "--service-token",
        service_token,
    ]);
    if let Some(path) = enterprise_providers_file {
        command.args([
            "--enterprise-providers-file",
            path.to_str().expect("enterprise providers file path"),
        ]);
    }
    if let Some(path) = verifier_policies_file {
        command.args([
            "--verifier-policies-file",
            path.to_str().expect("verifier policies file path"),
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

fn start_trust_service(
    service_token: &str,
    enterprise_providers_file: &Path,
) -> (ServerGuard, Client, String) {
    start_trust_service_with_policy_registry(service_token, Some(enterprise_providers_file), None)
}

fn start_trust_service_with_policy_registry(
    service_token: &str,
    enterprise_providers_file: Option<&Path>,
    verifier_policies_file: Option<&Path>,
) -> (ServerGuard, Client, String) {
    let _lock = TRUST_SERVICE_START_LOCK
        .lock()
        .expect("trust service start lock poisoned");
    let client = Client::builder().build().expect("build reqwest client");

    for _ in 0..10 {
        let listen = reserve_listen_addr();
        let mut service = spawn_trust_service_with_policy_registry(
            listen,
            service_token,
            enterprise_providers_file,
            verifier_policies_file,
        );
        let base_url = format!("http://{listen}");
        match wait_for_trust_service(&client, &base_url, &mut service) {
            Ok(()) => return (service, client, base_url),
            Err(error) if error.contains("Address already in use") => continue,
            Err(error) => panic!("{error}"),
        }
    }

    panic!("trust service could not reserve an unused listen port");
}

fn wait_for_trust_service(
    client: &Client,
    base_url: &str,
    service: &mut ServerGuard,
) -> Result<(), String> {
    for _ in 0..300 {
        if let Some(status) = service.child.try_wait().expect("poll trust service child") {
            return Err(format!(
                "trust service exited before becoming ready (status {status}): {}",
                read_child_stderr(&mut service.child)
            ));
        }
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return Ok(()),
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    Err("trust service did not become ready".to_string())
}

fn provider_record_json(
    provider_id: &str,
    enabled: bool,
    trust_material_ref: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "provider_id": provider_id,
        "kind": "oidc_jwks",
        "enabled": enabled,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": trust_material_ref,
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_issuers": ["https://issuer.enterprise.example"],
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": ["org-789"]
        },
        "issuer": "https://issuer.enterprise.example",
        "jwks_url": "https://issuer.enterprise.example/jwks",
        "tenant_id": "tenant-123",
        "organization_id": "org-789",
        "subject_mapping": {
            "principal_source": "sub",
            "tenant_id_field": "tid",
            "organization_id_field": "org_id",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    })
}

fn write_registry(path: &Path, records: &[serde_json::Value]) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": "chio.enterprise-providers.v1",
            "providers": records.iter().map(|record| {
                let provider_id = record["provider_id"].as_str().expect("provider_id");
                (provider_id.to_string(), record.clone())
            }).collect::<serde_json::Map<String, serde_json::Value>>(),
        }))
        .expect("serialize registry"),
    )
    .expect("write registry");
}

#[test]
fn provider_admin_cli_supports_upsert_list_get_and_delete() {
    let dir = unique_dir("chio-cli-provider-admin-cli");
    fs::create_dir_all(&dir).expect("create temp dir");
    let registry_path = dir.join("enterprise-providers.json");
    let input_path = dir.join("provider.json");
    fs::write(
        &input_path,
        serde_json::to_vec_pretty(&provider_record_json(
            "enterprise-login",
            true,
            Some("jwks:enterprise-login"),
        ))
        .expect("serialize provider"),
    )
    .expect("write provider input");

    let upsert = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "provider",
            "upsert",
            "--input",
            input_path.to_str().expect("provider input path"),
            "--enterprise-providers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run provider upsert");
    assert!(
        upsert.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&upsert.stdout),
        String::from_utf8_lossy(&upsert.stderr)
    );
    let upsert_body: serde_json::Value =
        serde_json::from_slice(&upsert.stdout).expect("parse upsert output");
    assert_eq!(upsert_body["provider_id"], "enterprise-login");
    assert_eq!(upsert_body["validation_errors"], serde_json::Value::Null);
    let registry_after_upsert: serde_json::Value =
        serde_json::from_slice(&fs::read(&registry_path).expect("read provider registry"))
            .expect("parse provider registry");
    assert_eq!(
        registry_after_upsert["version"],
        "chio.enterprise-providers.v1"
    );

    let list = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "provider",
            "list",
            "--enterprise-providers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run provider list");
    assert!(
        list.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_body: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("parse list output");
    assert_eq!(list_body["count"], 1);
    assert_eq!(list_body["providers"][0]["provider_id"], "enterprise-login");

    let get = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "provider",
            "get",
            "--provider-id",
            "enterprise-login",
            "--enterprise-providers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run provider get");
    assert!(
        get.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&get.stdout),
        String::from_utf8_lossy(&get.stderr)
    );
    let get_body: serde_json::Value =
        serde_json::from_slice(&get.stdout).expect("parse get output");
    assert_eq!(get_body["provider_id"], "enterprise-login");

    let delete = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "provider",
            "delete",
            "--provider-id",
            "enterprise-login",
            "--enterprise-providers-file",
            registry_path.to_str().expect("registry path"),
        ])
        .output()
        .expect("run provider delete");
    assert!(
        delete.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&delete.stdout),
        String::from_utf8_lossy(&delete.stderr)
    );
    let delete_body: serde_json::Value =
        serde_json::from_slice(&delete.stdout).expect("parse delete output");
    assert_eq!(delete_body["providerId"], "enterprise-login");
    assert_eq!(delete_body["deleted"], true);
}

#[test]
fn provider_admin_http_lists_invalid_provider_records_with_validation_errors() {
    if skip_when_loopback_bind_denied(
        "provider_admin_http_lists_invalid_provider_records_with_validation_errors",
    ) {
        return;
    }

    let dir = unique_dir("chio-cli-provider-admin-http");
    fs::create_dir_all(&dir).expect("create temp dir");
    let registry_path = dir.join("enterprise-providers.json");
    write_registry(
        &registry_path,
        &[provider_record_json("enterprise-login", true, None)],
    );

    let service_token = "provider-admin-http-token";
    let (_service, client, base_url) = start_trust_service(service_token, &registry_path);

    let list = client
        .get(format!("{base_url}/v1/federation/providers"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider list");
    assert_eq!(list.status(), reqwest::StatusCode::OK);
    let list_body: serde_json::Value = list.json().expect("parse list body");
    assert_eq!(list_body["count"], 1);
    assert_eq!(list_body["providers"][0]["provider_id"], "enterprise-login");
    assert!(list_body["providers"][0]["validation_errors"]
        .as_array()
        .expect("validation errors array")
        .iter()
        .any(|value| value
            .as_str()
            .unwrap_or_default()
            .contains("trust_material_ref")));

    let get = client
        .get(format!(
            "{base_url}/v1/federation/providers/enterprise-login"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider get");
    assert_eq!(get.status(), reqwest::StatusCode::OK);
    let get_body: serde_json::Value = get.json().expect("parse get body");
    assert_eq!(get_body["provider_id"], "enterprise-login");
    assert!(get_body["validation_errors"]
        .as_array()
        .expect("validation errors array")
        .iter()
        .any(|value| value
            .as_str()
            .unwrap_or_default()
            .contains("trust_material_ref")));
}

#[test]
fn provider_admin_cli_supports_remote_reserved_identifier_paths() {
    if skip_when_loopback_bind_denied(
        "provider_admin_cli_supports_remote_reserved_identifier_paths",
    ) {
        return;
    }

    let dir = unique_dir("chio-cli-provider-admin-remote-reserved");
    fs::create_dir_all(&dir).expect("create temp dir");
    let registry_path = dir.join("enterprise-providers.json");
    let input_path = dir.join("provider.json");
    let provider_id = "enterprise/login?region=east#1";
    write_registry(&registry_path, &[]);
    fs::write(
        &input_path,
        serde_json::to_vec_pretty(&provider_record_json(
            provider_id,
            true,
            Some("jwks:enterprise-login"),
        ))
        .expect("serialize provider"),
    )
    .expect("write provider input");

    let service_token = "provider-admin-remote-reserved-token";
    let (_service, _client, base_url) = start_trust_service(service_token, &registry_path);

    let upsert = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "provider",
            "upsert",
            "--input",
            input_path.to_str().expect("provider input path"),
        ])
        .output()
        .expect("run remote provider upsert");
    assert!(
        upsert.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&upsert.stdout),
        String::from_utf8_lossy(&upsert.stderr)
    );
    let upsert_body: serde_json::Value =
        serde_json::from_slice(&upsert.stdout).expect("parse upsert output");
    assert_eq!(upsert_body["provider_id"], provider_id);

    let get = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "provider",
            "get",
            "--provider-id",
            provider_id,
        ])
        .output()
        .expect("run remote provider get");
    assert!(
        get.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&get.stdout),
        String::from_utf8_lossy(&get.stderr)
    );
    let get_body: serde_json::Value =
        serde_json::from_slice(&get.stdout).expect("parse get output");
    assert_eq!(get_body["provider_id"], provider_id);

    let delete = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "provider",
            "delete",
            "--provider-id",
            provider_id,
        ])
        .output()
        .expect("run remote provider delete");
    assert!(
        delete.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&delete.stdout),
        String::from_utf8_lossy(&delete.stderr)
    );
    let delete_body: serde_json::Value =
        serde_json::from_slice(&delete.stdout).expect("parse delete output");
    assert_eq!(delete_body["providerId"], provider_id);
    assert_eq!(delete_body["deleted"], true);
}

#[test]
fn passport_policy_admin_cli_supports_remote_upsert_list_get_and_delete() {
    if skip_when_loopback_bind_denied(
        "passport_policy_admin_cli_supports_remote_upsert_list_get_and_delete",
    ) {
        return;
    }

    let dir = unique_dir("chio-cli-passport-policy-admin-http");
    fs::create_dir_all(&dir).expect("create temp dir");
    let verifier_policies_path = dir.join("verifier-policies.json");
    let raw_policy_path = dir.join("verifier-policy.json");
    let signed_policy_path = dir.join("signed-verifier-policy.json");
    let verifier_seed_path = dir.join("verifier-seed.txt");

    fs::write(&raw_policy_path, "{}\n").expect("write raw verifier policy");

    let service_token = "passport-policy-admin-http-token";
    let (_service, _client, base_url) = start_trust_service_with_policy_registry(
        service_token,
        None,
        Some(&verifier_policies_path),
    );

    let policy_id = "rp/default?prod#1";

    let create = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "policy",
            "create",
            "--output",
            signed_policy_path
                .to_str()
                .expect("signed policy output path"),
            "--policy-id",
            policy_id,
            "--verifier",
            "https://rp.example.com",
            "--signing-seed-file",
            verifier_seed_path.to_str().expect("verifier seed path"),
            "--policy",
            raw_policy_path.to_str().expect("raw policy path"),
            "--expires-at",
            "1900000000",
        ])
        .output()
        .expect("run remote passport policy create");
    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    let create_body: serde_json::Value =
        serde_json::from_slice(&create.stdout).expect("parse create output");
    assert_eq!(create_body["body"]["policyId"], policy_id);
    assert_eq!(create_body["body"]["verifier"], "https://rp.example.com");

    let list = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "policy",
            "list",
        ])
        .output()
        .expect("run remote passport policy list");
    assert!(
        list.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_body: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("parse list output");
    assert_eq!(list_body["configured"], true);
    assert_eq!(list_body["count"], 1);
    assert_eq!(list_body["policies"][0]["body"]["policyId"], policy_id);

    let get = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "policy",
            "get",
            "--policy-id",
            policy_id,
        ])
        .output()
        .expect("run remote passport policy get");
    assert!(
        get.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&get.stdout),
        String::from_utf8_lossy(&get.stderr)
    );
    let get_body: serde_json::Value =
        serde_json::from_slice(&get.stdout).expect("parse get output");
    assert_eq!(get_body["body"]["policyId"], policy_id);
    assert_eq!(get_body["body"]["verifier"], "https://rp.example.com");

    let delete = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "policy",
            "delete",
            "--policy-id",
            policy_id,
        ])
        .output()
        .expect("run remote passport policy delete");
    assert!(
        delete.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&delete.stdout),
        String::from_utf8_lossy(&delete.stderr)
    );
    let delete_body: serde_json::Value =
        serde_json::from_slice(&delete.stdout).expect("parse delete output");
    assert_eq!(delete_body["policyId"], policy_id);
    assert_eq!(delete_body["deleted"], true);
}

#[test]
fn trust_service_health_reports_enterprise_and_verifier_policy_state() {
    if skip_when_loopback_bind_denied(
        "trust_service_health_reports_enterprise_and_verifier_policy_state",
    ) {
        return;
    }

    let dir = unique_dir("chio-cli-trust-health");
    fs::create_dir_all(&dir).expect("create temp dir");
    let enterprise_providers_path = dir.join("enterprise-providers.json");
    let verifier_policies_path = dir.join("verifier-policies.json");
    let raw_policy_path = dir.join("verifier-policy.json");
    let signed_policy_path = dir.join("signed-verifier-policy.json");
    let verifier_seed_path = dir.join("verifier-seed.txt");

    write_registry(
        &enterprise_providers_path,
        &[provider_record_json(
            "enterprise-login",
            true,
            Some("jwks:enterprise-login"),
        )],
    );
    fs::write(&raw_policy_path, "{}\n").expect("write raw verifier policy");

    let service_token = "trust-health-token";
    let (_service, client, base_url) = start_trust_service_with_policy_registry(
        service_token,
        Some(&enterprise_providers_path),
        Some(&verifier_policies_path),
    );

    let create = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "passport",
            "policy",
            "create",
            "--output",
            signed_policy_path
                .to_str()
                .expect("signed policy output path"),
            "--policy-id",
            "rp-health",
            "--verifier",
            "https://rp.example.com",
            "--signing-seed-file",
            verifier_seed_path.to_str().expect("verifier seed path"),
            "--policy",
            raw_policy_path.to_str().expect("raw policy path"),
            "--expires-at",
            "1900000000",
        ])
        .output()
        .expect("run remote passport policy create");
    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let health = client
        .get(format!("{base_url}/health"))
        .send()
        .expect("send health request");
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let health: serde_json::Value = health.json().expect("health json");
    assert_eq!(health["ok"], true);
    assert_eq!(health["stores"]["receiptsConfigured"], false);
    assert_eq!(
        health["federation"]["enterpriseProviders"]["configured"],
        true
    );
    assert_eq!(health["federation"]["enterpriseProviders"]["count"], 1);
    assert_eq!(
        health["federation"]["enterpriseProviders"]["validatedCount"],
        1
    );
    assert_eq!(health["federation"]["verifierPolicies"]["configured"], true);
    assert_eq!(health["federation"]["verifierPolicies"]["count"], 1);
    assert_eq!(health["federation"]["verifierPolicies"]["activeCount"], 1);
}
