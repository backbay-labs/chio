#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_control_plane::scim_lifecycle::{
    ScimLifecycleRegistry, CHIO_SCIM_USER_EXTENSION_SCHEMA, SCIM_CORE_USER_SCHEMA,
};
use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};

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

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn spawn_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    enterprise_providers_file: &Path,
    scim_lifecycle_file: &Path,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
) -> ServerGuard {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command.current_dir(workspace_root()).args([
        "trust",
        "serve",
        "--listen",
        &listen.to_string(),
        "--service-token",
        service_token,
        "--enterprise-providers-file",
        enterprise_providers_file
            .to_str()
            .expect("enterprise providers file path"),
        "--scim-lifecycle-file",
        scim_lifecycle_file
            .to_str()
            .expect("scim lifecycle file path"),
    ]);
    if let Some(path) = receipt_db_path {
        command.args(["--receipt-db", path.to_str().expect("receipt db path")]);
    }
    if let Some(path) = revocation_db_path {
        command.args([
            "--revocation-db",
            path.to_str().expect("revocation db path"),
        ]);
    }
    if let Some(path) = authority_seed_path {
        command.args([
            "--authority-seed-file",
            path.to_str().expect("authority seed path"),
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

fn spawn_ready_trust_service(
    service_token: &str,
    enterprise_providers_file: &Path,
    scim_lifecycle_file: &Path,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
) -> (Client, std::net::SocketAddr, String, ServerGuard) {
    let client = Client::builder().build().expect("build reqwest client");
    let mut last_bind_error = None;

    for _ in 0..10 {
        let listen = reserve_listen_addr();
        let base_url = format!("http://{listen}");
        let mut service = spawn_trust_service(
            listen,
            service_token,
            enterprise_providers_file,
            scim_lifecycle_file,
            receipt_db_path,
            revocation_db_path,
            authority_seed_path,
        );

        match wait_for_trust_service(&client, &base_url, &mut service) {
            Ok(()) => return (client, listen, base_url, service),
            Err(error) if error.contains("Address already in use") => {
                last_bind_error = Some(error);
            }
            Err(error) => panic!("{error}"),
        }
    }

    panic!(
        "{}",
        last_bind_error.unwrap_or_else(|| "trust service did not become ready".to_string())
    );
}

fn write_provider_registry(path: &Path, provider_id: &str) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "version": "chio.enterprise-providers.v1",
            "providers": {
                provider_id: {
                    "provider_id": provider_id,
                    "kind": "scim",
                    "enabled": true,
                    "provenance": {
                        "configured_from": "manual",
                        "source_ref": "operator",
                        "trust_material_ref": "scim:corp",
                        "subject_mapping_source": "manual"
                    },
                    "trust_boundary": {
                        "allowed_tenants": ["tenant-123"],
                        "allowed_organizations": ["org-789"]
                    },
                    "scim_base_url": "https://id.example.com/scim/v2",
                    "tenant_id": "tenant-123",
                    "organization_id": "org-789",
                    "subject_mapping": {
                        "principal_source": "userName",
                        "tenant_id_field": "tenantId",
                        "organization_id_field": "organizationId",
                        "groups_field": "groups",
                        "roles_field": "roles"
                    }
                }
            }
        }))
        .expect("serialize provider registry"),
    )
    .expect("write provider registry");
}

fn scim_user_payload(provider_id: &str) -> Value {
    json!({
        "schemas": [SCIM_CORE_USER_SCHEMA, CHIO_SCIM_USER_EXTENSION_SCHEMA],
        "externalId": "ext-user-123",
        "userName": "alice@example.com",
        "active": true,
        "name": {
            "formatted": "Alice Example",
            "givenName": "Alice",
            "familyName": "Example"
        },
        "emails": [
            {
                "value": "alice@example.com",
                "primary": true
            }
        ],
        "groups": [
            {
                "value": "eng",
                "display": "Engineering"
            }
        ],
        "roles": [
            {
                "value": "operator"
            }
        ],
        "entitlements": [
            {
                "value": "chio:trust:issue"
            }
        ],
        CHIO_SCIM_USER_EXTENSION_SCHEMA: {
            "providerId": provider_id,
            "tenantId": "tenant-123",
            "organizationId": "org-789",
            "clientId": "client-123",
            "objectId": "object-123"
        }
    })
}

#[test]
fn trust_service_scim_post_users_creates_chio_identity_with_attributes_and_entitlements() {
    if skip_when_loopback_bind_denied(
        "trust_service_scim_post_users_creates_chio_identity_with_attributes_and_entitlements",
    ) {
        return;
    }

    let dir = unique_dir("chio-cli-scim-create");
    fs::create_dir_all(&dir).expect("create temp dir");
    let providers_path = dir.join("enterprise-providers.json");
    let scim_registry_path = dir.join("scim-lifecycle.json");
    write_provider_registry(&providers_path, "scim-corp");

    let service_token = "scim-create-token";
    let (client, _listen, base_url, _service) = spawn_ready_trust_service(
        service_token,
        &providers_path,
        &scim_registry_path,
        None,
        None,
        None,
    );

    let response = client
        .post(format!("{base_url}/scim/v2/Users"))
        .header(AUTHORIZATION, bearer(service_token))
        .header(CONTENT_TYPE, "application/scim+json")
        .json(&scim_user_payload("scim-corp"))
        .send()
        .expect("send scim create request");
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let body: Value = response.json().expect("decode scim create body");
    assert_eq!(body["userName"], "alice@example.com");
    assert_eq!(body["active"], true);
    assert_eq!(body["roles"][0]["value"], "operator");
    assert_eq!(body["entitlements"][0]["value"], "chio:trust:issue");
    assert_eq!(
        body[CHIO_SCIM_USER_EXTENSION_SCHEMA]["providerId"],
        "scim-corp"
    );
    assert_eq!(
        body[CHIO_SCIM_USER_EXTENSION_SCHEMA]["principal"],
        "alice@example.com"
    );
    assert!(
        body[CHIO_SCIM_USER_EXTENSION_SCHEMA]["subjectKey"]
            .as_str()
            .expect("subject key")
            .len()
            > 10
    );

    let user_id = body["id"].as_str().expect("scim user id");
    let registry = ScimLifecycleRegistry::load(&scim_registry_path).expect("load scim registry");
    let record = registry.get(user_id).expect("stored scim user");
    assert!(record.active());
    assert_eq!(record.provider_id, "scim-corp");
    assert_eq!(record.enterprise_identity.principal, "alice@example.com");
    assert_eq!(record.enterprise_identity.groups, vec!["eng".to_string()]);
    assert_eq!(
        record.enterprise_identity.roles,
        vec!["operator".to_string()]
    );
    assert_eq!(record.scim_user.entitlements[0].value, "chio:trust:issue");

    let health: Value = client
        .get(format!("{base_url}/health"))
        .send()
        .expect("send health request")
        .json()
        .expect("decode health");
    assert_eq!(health["federation"]["scimLifecycle"]["configured"], true);
    assert_eq!(health["federation"]["scimLifecycle"]["count"], 1);
}

#[test]
fn trust_service_scim_delete_users_deactivates_identity_revokes_capabilities_and_emits_receipt() {
    if skip_when_loopback_bind_denied(
        "trust_service_scim_delete_users_deactivates_identity_revokes_capabilities_and_emits_receipt",
    ) {
        return;
    }

    let dir = unique_dir("chio-cli-scim-delete");
    fs::create_dir_all(&dir).expect("create temp dir");
    let providers_path = dir.join("enterprise-providers.json");
    let scim_registry_path = dir.join("scim-lifecycle.json");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_seed_path = dir.join("authority-seed.txt");
    write_provider_registry(&providers_path, "scim-corp");

    let service_token = "scim-delete-token";
    let (client, _listen, base_url, _service) = spawn_ready_trust_service(
        service_token,
        &providers_path,
        &scim_registry_path,
        Some(&receipt_db_path),
        Some(&revocation_db_path),
        Some(&authority_seed_path),
    );

    let create_response = client
        .post(format!("{base_url}/scim/v2/Users"))
        .header(AUTHORIZATION, bearer(service_token))
        .header(CONTENT_TYPE, "application/scim+json")
        .json(&scim_user_payload("scim-corp"))
        .send()
        .expect("send scim create request");
    assert_eq!(create_response.status(), reqwest::StatusCode::CREATED);
    let create_body: Value = create_response.json().expect("decode create body");
    let user_id = create_body["id"].as_str().expect("created user id");

    let subject_keypair = Keypair::generate();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Read],
            constraints: Vec::new(),
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    let issue_response = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&json!({
            "subjectPublicKey": subject_keypair.public_key().to_hex(),
            "scope": scope,
            "ttlSeconds": 3600
        }))
        .send()
        .expect("send issue capability request");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let issue_body: Value = issue_response.json().expect("decode issue capability");
    let capability_id = issue_body["capability"]["id"]
        .as_str()
        .expect("issued capability id")
        .to_string();

    let mut registry =
        ScimLifecycleRegistry::load(&scim_registry_path).expect("load scim registry");
    let record = registry
        .users
        .get_mut(user_id)
        .expect("stored scim lifecycle record");
    record.tracked_capability_ids.push(capability_id.clone());
    registry
        .save(&scim_registry_path)
        .expect("save scim registry");

    let delete_response = client
        .delete(format!("{base_url}/scim/v2/Users/{user_id}"))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("send scim delete request");
    assert_eq!(delete_response.status(), reqwest::StatusCode::OK);
    let delete_body: Value = delete_response.json().expect("decode delete body");
    assert_eq!(delete_body["active"], false);

    let registry = ScimLifecycleRegistry::load(&scim_registry_path).expect("reload scim registry");
    let record = registry.get(user_id).expect("stored deactivated user");
    assert!(!record.active());
    assert_eq!(record.revoked_capability_ids, vec![capability_id.clone()]);
    assert!(record.deprovision_receipt_id.is_some());

    let revocations: Value = client
        .get(format!(
            "{base_url}/v1/revocations?capabilityId={capability_id}&limit=10"
        ))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("query revocations")
        .json()
        .expect("decode revocations");
    assert_eq!(revocations["revoked"], true);

    let receipts: Value = client
        .get(format!(
            "{base_url}/v1/receipts/tools?toolServer=chio.scim&toolName=delete_user&limit=10"
        ))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("query receipts")
        .json()
        .expect("decode receipts");
    assert_eq!(receipts["count"], 1);
    assert_eq!(
        receipts["receipts"][0]["metadata"]["scimLifecycle"]["userId"],
        user_id
    );
    assert_eq!(
        receipts["receipts"][0]["metadata"]["scimLifecycle"]["revokedCapabilityIds"][0],
        capability_id
    );
    assert_eq!(receipts["receipts"][0]["tenant_id"], "tenant-123");
}
