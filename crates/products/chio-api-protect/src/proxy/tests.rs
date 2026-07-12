use super::*;
use axum::body::to_bytes;
use chio_core_types::capability::{
    governance::{GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody},
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_http_core::{
    http_status_scope, AuthMethod, RespondResponse, CHIO_HTTP_STATUS_SCOPE_DECISION,
    CHIO_HTTP_STATUS_SCOPE_FINAL,
};
use chio_kernel::{ApprovalOutcome, ApprovalRequest};
use chio_openapi::PolicyDecision;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use tower::ServiceExt;

use chio_test_support::prelude::*;

const PETSTORE_YAML: &str = r#"
openapi: "3.0.0"
info:
  title: Petstore
  version: "1.0.0"
paths:
  /pets:
    get:
      operationId: listPets
      summary: List all pets
      responses:
        "200":
          description: A list of pets
    post:
      operationId: createPet
      summary: Create a pet
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: Created
  /pets/{petId}:
    get:
      operationId: showPetById
      summary: Info for a specific pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: A pet
    delete:
      operationId: deletePet
      summary: Delete a pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Deleted
"#;

fn signed_capability_token_json(issuer: &Keypair, id: &str) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: issuer.public_key(),
            scope: ChioScope {
                grants: vec![chio_http_core::http_authority_tool_grant()],
                ..ChioScope::default()
            },
            issued_at: now.saturating_sub(60),
            expires_at: now + 3600,
            delegation_chain: Vec::new(),
        },
        issuer,
    )
    .test_unwrap();
    serde_json::to_string(&token).test_unwrap()
}

struct MockUpstreamServer {
    base_url: String,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    handle: thread::JoinHandle<()>,
}

impl MockUpstreamServer {
    fn bind_mock_upstream_listener() -> Option<TcpListener> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener),
            Err(error) => match error.kind() {
                std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::Unsupported => {
                    eprintln!(
                            "skipping proxy mock-upstream test because loopback bind is unavailable: {error}"
                        );
                    None
                }
                _ => panic!("bind mock upstream listener: {error}"),
            },
        }
    }

    fn spawn(status: u16, headers: Vec<(&str, &str)>, body: &str) -> Option<Self> {
        let listener = Self::bind_mock_upstream_listener()?;
        let address = listener.local_addr().test_unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        let body = body.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().test_unwrap();
            let request = read_http_request(&mut stream);
            request_log.lock().test_unwrap().push(request);
            write_http_response(&mut stream, status, &headers, &body);
        });
        Some(Self {
            base_url: format!("http://{}", address),
            requests,
            handle,
        })
    }

    /// Accept one connection and read the request, then hold the socket open
    /// without responding so a client with a request timeout must give up on its
    /// own. Stands in for an upstream that received the request but stalls.
    fn spawn_unresponsive() -> Option<Self> {
        let listener = Self::bind_mock_upstream_listener()?;
        let address = listener.local_addr().test_unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request = read_http_request(&mut stream);
                request_log.lock().test_unwrap().push(request);
                // Never write a response. Block reading until the client gives up
                // and closes the connection, modeling an upstream that stalls
                // indefinitely rather than sleeping a fixed interval: the caller's
                // request timeout must be what ends the hop.
                let mut sink = [0_u8; 256];
                while let Ok(read) = stream.read(&mut sink) {
                    if read == 0 {
                        break;
                    }
                }
            }
        });
        Some(Self {
            base_url: format!("http://{}", address),
            requests,
            handle,
        })
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().test_unwrap().clone()
    }

    fn join(self) {
        self.handle.join().test_unwrap();
    }
}

fn test_state(routes: Vec<RouteEntry>, upstream: String) -> Arc<ProxyState> {
    test_state_with_receipt_db(routes, upstream, None)
}

fn test_state_with_receipt_db(
    routes: Vec<RouteEntry>,
    upstream: String,
    receipt_db: Option<&str>,
) -> Arc<ProxyState> {
    let keypair = Keypair::generate();
    let approval_store: Arc<dyn ApprovalStore> = if let Some(path) = receipt_db {
        Arc::new(SqliteApprovalStore::open(path).test_unwrap())
    } else {
        Arc::new(InMemoryApprovalStore::new())
    };
    let (receipt_store, receipts, tool_receipts, revoked_capability_ids) =
        if let Some(path) = receipt_db {
            let store = SqliteReceiptStore::open(path).test_unwrap();
            let receipts = store.load_receipts().test_unwrap();
            let tool_receipts = store.load_tool_receipts().test_unwrap();
            let revoked_capability_ids = store.load_revoked_capability_ids().test_unwrap();
            (
                Some(Mutex::new(store)),
                receipts,
                tool_receipts,
                revoked_capability_ids,
            )
        } else {
            (None, Vec::new(), Vec::new(), HashSet::new())
        };
    let signer_public_key = keypair.public_key();
    let trusted_capability_issuers = vec![signer_public_key.clone()];
    let trusted_receipt_signers = vec![signer_public_key];
    let evaluator = RequestEvaluator::new_with_approval_store(
        routes,
        keypair.clone(),
        "test-policy".to_string(),
        Arc::clone(&approval_store),
    );
    let egress_contract = default_upstream_egress_contract(&upstream).test_unwrap();
    let http_client = client_builder_with_contract(&egress_contract)
        .build()
        .test_unwrap();
    Arc::new(ProxyState {
        evaluator,
        signer_keypair: keypair,
        upstream,
        http_client,
        egress_contract,
        approval_admin: ApprovalAdmin::new(approval_store),
        receipt_log: Mutex::new(ReceiptLog { receipts }),
        tool_receipt_log: Mutex::new(ToolReceiptLog {
            receipts: tool_receipts,
        }),
        receipt_store,
        revoked_capability_ids: Mutex::new(revoked_capability_ids),
        trusted_capability_issuers,
        trusted_receipt_signers,
        sidecar_control_token: None,
    })
}

/// Build proxy state whose upstream client aborts a hop after `timeout`, so a
/// stalled upstream surfaces inside the handler instead of hanging.
fn test_state_with_client_timeout(
    routes: Vec<RouteEntry>,
    upstream: String,
    timeout: std::time::Duration,
) -> Arc<ProxyState> {
    let keypair = Keypair::generate();
    let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
    let signer_public_key = keypair.public_key();
    let trusted_capability_issuers = vec![signer_public_key.clone()];
    let trusted_receipt_signers = vec![signer_public_key];
    let evaluator = RequestEvaluator::new_with_approval_store(
        routes,
        keypair.clone(),
        "test-policy".to_string(),
        Arc::clone(&approval_store),
    );
    let egress_contract = default_upstream_egress_contract(&upstream).test_unwrap();
    let http_client = client_builder_with_contract(&egress_contract)
        .timeout(timeout)
        .build()
        .test_unwrap();
    Arc::new(ProxyState {
        evaluator,
        signer_keypair: keypair,
        upstream,
        http_client,
        egress_contract,
        approval_admin: ApprovalAdmin::new(approval_store),
        receipt_log: Mutex::new(ReceiptLog {
            receipts: Vec::new(),
        }),
        tool_receipt_log: Mutex::new(ToolReceiptLog {
            receipts: Vec::new(),
        }),
        receipt_store: None,
        revoked_capability_ids: Mutex::new(HashSet::new()),
        trusted_capability_issuers,
        trusted_receipt_signers,
        sidecar_control_token: None,
    })
}

fn pending_approval_request(approval_id: &str) -> (ApprovalRequest, Keypair, Keypair) {
    let request_subject = Keypair::generate();
    let approver = Keypair::generate();
    let approval = ApprovalRequest {
        approval_id: approval_id.to_string(),
        policy_id: "policy-hitl".to_string(),
        subject_id: "agent-1".to_string(),
        capability_id: "cap-1".to_string(),
        subject_public_key: Some(request_subject.public_key()),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        action: "invoke".to_string(),
        parameter_hash: "hash-1".to_string(),
        expires_at: 4_000_000_000,
        callback_hint: None,
        created_at: 123,
        summary: "pending approval".to_string(),
        governed_intent: None,
        trusted_approvers: vec![approver.public_key()],
        triggered_by: vec!["force_approval".to_string()],
    };
    (approval, request_subject, approver)
}

fn signed_approval_response_token(
    approval_id: &str,
    subject: &Keypair,
    approver: &Keypair,
    decision: GovernedApprovalDecision,
) -> GovernedApprovalToken {
    let now = chrono::Utc::now().timestamp() as u64;
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("tok-{approval_id}"),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "hash-1".to_string(),
            request_id: approval_id.to_string(),
            issued_at: now.saturating_sub(10),
            expires_at: now + 600,
            decision,
        },
        approver,
    )
    .test_unwrap()
}

fn temp_receipt_db_path() -> String {
    let mut path = std::env::temp_dir();
    path.push(format!("chio-api-protect-test-{}.db", uuid::Uuid::now_v7()));
    path.to_string_lossy().to_string()
}

fn with_peer_addr(mut request: Request<Body>, peer: SocketAddr) -> Request<Body> {
    // The capped serve listener exposes the peer address as `CappedPeerAddr`, so
    // the sidecar-control checks read `ConnectInfo<CappedPeerAddr>`; mirror that
    // extension type here rather than the bare `SocketAddr`.
    request
        .extensions_mut()
        .insert(ConnectInfo(CappedPeerAddr(peer)));
    request
}

fn with_loopback_peer(request: Request<Body>) -> Request<Body> {
    with_peer_addr(request, SocketAddr::from(([127, 0, 0, 1], 4100)))
}

fn read_http_request<R: Read>(stream: &mut R) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0_usize;

    loop {
        let read = stream.read(&mut chunk).test_unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none() {
            header_end = find_header_end(&request);
            if let Some(end) = header_end {
                content_length = parse_content_length(&request[..end]);
            }
        }
        if let Some(end) = header_end {
            if request.len() >= end + content_length {
                break;
            }
        }
    }

    String::from_utf8(request).test_unwrap()
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn write_http_response<W: Write>(
    stream: &mut W,
    status: u16,
    headers: &[(String, String)],
    body: &str,
) {
    let mut response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        http_status_text(status),
        body.len(),
    );
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    stream.write_all(response.as_bytes()).test_unwrap();
}

fn http_status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        502 => "Bad Gateway",
        _ => "Unknown",
    }
}

#[test]
fn build_routes_from_petstore() {
    let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
    assert!(!routes.is_empty());

    // Should have GET and POST for /pets, GET and DELETE for /pets/{petId}
    let get_pets = routes.iter().find(|r| {
        r.method == HttpMethod::Get && r.pattern.contains("/pets") && !r.pattern.contains("{petId}")
    });
    assert!(get_pets.is_some());

    let post_pets = routes.iter().find(|r| r.method == HttpMethod::Post);
    assert!(post_pets.is_some());
    assert_eq!(
        post_pets.map(|r| r.policy),
        Some(PolicyDecision::DenyByDefault)
    );

    let delete_pet = routes.iter().find(|r| r.method == HttpMethod::Delete);
    assert!(delete_pet.is_some());
}

#[test]
fn get_routes_allowed_by_default() {
    let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
    let get_routes: Vec<_> = routes
        .iter()
        .filter(|r| r.method == HttpMethod::Get)
        .collect();
    for route in get_routes {
        assert_eq!(route.policy, PolicyDecision::SessionAllow);
    }
}

#[test]
fn side_effect_routes_denied_by_default() {
    let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).test_unwrap();
    let mut_routes: Vec<_> = routes
        .iter()
        .filter(|r| r.method.requires_capability())
        .collect();
    for route in mut_routes {
        assert_eq!(route.policy, PolicyDecision::DenyByDefault);
    }
}

#[test]
fn x_chio_side_effects_true_overrides_safe_method() {
    let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /dangerous-read:
    get:
      operationId: dangerousRead
      x-chio-side-effects: true
      responses:
        "200":
          description: ok
"#;

    let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
    let route = routes
        .iter()
        .find(|route| route.pattern == "/dangerous-read" && route.method == HttpMethod::Get)
        .test_unwrap();

    assert_eq!(route.policy, PolicyDecision::DenyByDefault);
}

#[test]
fn x_chio_side_effects_false_overrides_mutating_method() {
    let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /safe-post:
    post:
      operationId: safePost
      x-chio-side-effects: false
      responses:
        "200":
          description: ok
"#;

    let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
    let route = routes
        .iter()
        .find(|route| route.pattern == "/safe-post" && route.method == HttpMethod::Post)
        .test_unwrap();

    assert_eq!(route.policy, PolicyDecision::SessionAllow);
}

#[test]
fn x_chio_approval_required_forces_deny() {
    let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /approved-read:
    get:
      operationId: approvedRead
      x-chio-side-effects: false
      x-chio-approval-required: true
      responses:
        "200":
          description: ok
"#;

    let routes = ProtectProxy::routes_from_spec(spec).test_unwrap();
    let route = routes
        .iter()
        .find(|route| route.pattern == "/approved-read" && route.method == HttpMethod::Get)
        .test_unwrap();

    assert_eq!(route.policy, PolicyDecision::DenyByDefault);
}

#[test]
fn forwarded_query_string_strips_chio_capability() {
    let token = signed_capability_token_json(&Keypair::generate(), "cap-query");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("source", "test")
        .append_pair("chio_capability", &token)
        .append_pair("mode", "full")
        .finish();

    assert_eq!(
        forwarded_query_string(Some(&query)).as_deref(),
        Some("source=test&mode=full")
    );
}

#[test]
fn extract_caller_identity_rejects_blank_or_padded_credentials() {
    for (header_name, header_value) in [
        ("authorization", "Bearer "),
        ("authorization", "Bearer token-with-padding "),
        ("authorization", "Bearer token\nwith-control"),
        ("x-api-key", ""),
        ("x-api-key", " api-key-with-padding"),
        ("x-api-key", "api-key\nwith-control"),
    ] {
        let mut headers = HashMap::new();
        headers.insert(header_name.to_string(), header_value.to_string());

        let caller = extract_caller_identity(&headers);

        assert!(
            matches!(caller.auth_method, AuthMethod::Anonymous),
            "expected anonymous caller for {header_name}: {header_value:?}, got {caller:?}"
        );
        assert_eq!(caller.subject, "anonymous");
    }
}

#[test]
fn chio_transport_header_helpers_are_case_insensitive() {
    let token = signed_capability_token_json(&Keypair::generate(), "cap-header-case");
    let mut headers = HashMap::new();
    headers.insert("X-CHIO-CAPABILITY".to_string(), token.clone());
    let query = HashMap::new();

    assert_eq!(
        extract_presented_capability_from_maps(&headers, &query),
        Some(token.as_str())
    );
    assert!(!should_forward_request_header("X-CHIO-CAPABILITY"));
}

#[tokio::test]
async fn evaluation_error_response_surfaces_pending_approval_state() {
    let response = evaluation_error_response(&ProtectError::PendingApproval {
        approval_id: Some("ap-123".to_string()),
        kernel_receipt_id: "kr-456".to_string(),
    });
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_approval_required");
    assert_eq!(json["approval_id"], "ap-123");
    assert_eq!(json["kernel_receipt_id"], "kr-456");
    assert_eq!(json["resume_path"], "/approvals/ap-123/respond");
}

#[tokio::test]
async fn approval_routes_are_handled_before_proxy_catch_all() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let (approval, subject, approver) = pending_approval_request("ap-route-1");
    state
        .approval_admin
        .store()
        .store_pending(&approval)
        .test_unwrap();

    let token = signed_approval_response_token(
        &approval.approval_id,
        &subject,
        &approver,
        GovernedApprovalDecision::Approved,
    );
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/approvals/{}/respond", approval.approval_id))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&RespondRequest {
                    outcome: ApprovalOutcome::Approved,
                    reason: Some("approved".to_string()),
                    approver: approver.public_key(),
                    token,
                })
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: RespondResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json.approval_id, "ap-route-1");
    assert_eq!(json.outcome, ApprovalOutcome::Approved);
    assert!(state
        .approval_admin
        .store()
        .get_pending("ap-route-1")
        .test_unwrap()
        .is_none());
}

#[tokio::test]
async fn metrics_route_serves_rule_pack_families_when_authorized() {
    // Drive at least one guard family so the body is non-trivial.
    chio_metrics_spec::runtime::families::GUARD_VERDICT.incr(&["route-test-guard", "allow"]);
    chio_metrics_spec::runtime::preregister_known_label_sets();

    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = with_loopback_peer(
        Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let body = String::from_utf8(bytes.to_vec()).test_unwrap();
    assert!(
        body.contains("chio_guard_verdict_total"),
        "guard family missing: {body}"
    );
    assert!(
        body.contains("chio_fail_open_suspected_total"),
        "alert-pack family missing: {body}"
    );
    assert!(
        body.contains("chio_dispatch_failure_total"),
        "alert-pack family missing: {body}"
    );
}

#[tokio::test]
async fn metrics_route_is_gated() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    // No loopback peer and no bearer token: the sidecar-control gate must refuse.
    let request = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .test_unwrap();
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "unauthenticated scrape must be refused"
    );
}

#[tokio::test]
async fn submit_approval_creates_pending_record_signed_by_sidecar() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let subject = Keypair::generate();
    let payload = serde_json::json!({
        "capability_id": "cap-submit-1",
        "tool_server": "shell",
        "tool_name": "run_command",
        "parameter_hash": "a".repeat(64),
        "requested_by": subject.public_key().to_hex(),
        "summary": "rm -rf old_build/",
        "ttl_seconds": 300,
        "triggered_by": ["shell.requires_approval"],
    });
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/submit")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).test_unwrap()))
            .test_unwrap(),
    );

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    let approval_id = json["approval_id"].as_str().test_unwrap().to_string();
    assert!(approval_id.starts_with("ap-"));
    assert_eq!(
        json["trusted_approvers"][0],
        state.signer_keypair.public_key().to_hex()
    );

    let stored = state
        .approval_admin
        .store()
        .get_pending(&approval_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(stored.tool_server, "shell");
    assert_eq!(stored.tool_name, "run_command");
    assert_eq!(stored.subject_id, subject.public_key().to_hex());
    assert!(stored
        .trusted_approvers
        .contains(&state.signer_keypair.public_key()));
}

#[tokio::test]
async fn operator_respond_resolves_pending_via_sidecar_signature() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let subject = Keypair::generate();

    // Submit a pending approval first.
    let submit_payload = serde_json::json!({
        "capability_id": "cap-op-1",
        "tool_server": "shell",
        "tool_name": "run_command",
        "parameter_hash": "b".repeat(64),
        "requested_by": subject.public_key().to_hex(),
        "ttl_seconds": 300,
    });
    let submit_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/submit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&submit_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let submit_response = build_app(Arc::clone(&state))
        .oneshot(submit_request)
        .await
        .test_unwrap();
    assert_eq!(submit_response.status(), StatusCode::CREATED);
    let submit_body = to_bytes(submit_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let submit_json: serde_json::Value = serde_json::from_slice(&submit_body).test_unwrap();
    let approval_id = submit_json["approval_id"]
        .as_str()
        .test_unwrap()
        .to_string();

    // Operator-respond approves with sidecar-signed token.
    let respond_payload = serde_json::json!({
        "outcome": "approved",
        "reason": "ok via slash command",
    });
    let respond_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/approvals/{approval_id}/operator-respond"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&respond_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let respond_response = build_app(Arc::clone(&state))
        .oneshot(respond_request)
        .await
        .test_unwrap();
    assert_eq!(respond_response.status(), StatusCode::OK);

    let respond_body = to_bytes(respond_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let resolved: RespondResponse = serde_json::from_slice(&respond_body).test_unwrap();
    assert_eq!(resolved.approval_id, approval_id);
    assert_eq!(resolved.outcome, ApprovalOutcome::Approved);

    // Pending must be cleared.
    assert!(state
        .approval_admin
        .store()
        .get_pending(&approval_id)
        .test_unwrap()
        .is_none());
}

#[tokio::test]
async fn submit_then_operator_respond_works_without_subject_pubkey() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    // requested_by left blank: the sidecar must fall back to its
    // own pubkey for both subject_id and subject_public_key so the
    // operator-respond shortcut can sign a binding token.
    let submit_payload = serde_json::json!({
        "capability_id": "cap-no-sub",
        "tool_server": "shell",
        "tool_name": "run_command",
        "parameter_hash": "c".repeat(64),
        "requested_by": "",
        "ttl_seconds": 300,
    });
    let submit_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/submit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&submit_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let submit_response = build_app(Arc::clone(&state))
        .oneshot(submit_request)
        .await
        .test_unwrap();
    assert_eq!(submit_response.status(), StatusCode::CREATED);
    let submit_body = to_bytes(submit_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let submit_json: serde_json::Value = serde_json::from_slice(&submit_body).test_unwrap();
    let approval_id = submit_json["approval_id"]
        .as_str()
        .test_unwrap()
        .to_string();

    let stored = state
        .approval_admin
        .store()
        .get_pending(&approval_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        stored.subject_id,
        state.signer_keypair.public_key().to_hex()
    );

    let respond_payload = serde_json::json!({"outcome": "approved"});
    let respond_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/approvals/{approval_id}/operator-respond"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&respond_payload).test_unwrap(),
            ))
            .test_unwrap(),
    );
    let respond_response = build_app(Arc::clone(&state))
        .oneshot(respond_request)
        .await
        .test_unwrap();
    assert_eq!(respond_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn operator_respond_rejects_unknown_approval() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let payload = serde_json::json!({"outcome": "approved"});
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/approvals/ap-missing/operator-respond")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).test_unwrap()))
            .test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approval_routes_reject_remote_callers_without_control_access() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let request = with_peer_addr(
        Request::builder()
            .method("GET")
            .uri("/approvals/pending")
            .body(Body::empty())
            .test_unwrap(),
        remote,
    );

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
}

#[test]
fn evaluator_and_approval_routes_share_the_same_store() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let evaluator_store = state.evaluator.approval_store();

    assert!(Arc::ptr_eq(&evaluator_store, state.approval_admin.store()));
}

// These proxy/sidecar handlers reach the kernel through Chio's sync
// tool-dispatch bridge, which requires a multi-thread runtime (the
// documented host requirement); a current-thread test runtime cannot
// drive the async tool server and the handler surfaces a 500 instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_denies_without_capability_and_records_receipt() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let receipt_id = response
        .headers()
        .get("x-chio-receipt-id")
        .and_then(|value| value.to_str().ok())
        .test_unwrap()
        .to_string();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_access_denied");
    assert_eq!(
            json["suggestion"],
            "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter"
        );
    assert!(json["receipt_id"].as_str().is_some());

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt_id);
    assert_eq!(log.receipts[0].response_status, 403);
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
    assert!(log.receipts[0].verify_signature().test_unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_forwards_allowed_requests_and_end_to_end_headers() {
    let Some(server) = MockUpstreamServer::spawn(
        201,
        vec![("content-type", "application/json"), ("x-upstream", "ok")],
        r#"{"ok":true}"#,
    ) else {
        return;
    };
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        server.base_url(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets?source=test")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("user-agent", "chio-test")
        .header("authorization", "Bearer upstream-token")
        .header("x-request-id", "req-123")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&state.signer_keypair, "cap-proxy"),
        )
        .header("x-custom-app", "secret")
        .header("connection", "keep-alive")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    let receipt_id = response
        .headers()
        .get("x-chio-receipt-id")
        .and_then(|value| value.to_str().ok())
        .test_unwrap()
        .to_string();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("x-upstream")
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    assert_eq!(body.as_ref(), br#"{"ok":true}"#);

    let requests = server.requests();
    server.join();

    assert_eq!(requests.len(), 1);
    let request_text = requests[0].to_ascii_lowercase();
    assert!(request_text.contains("post /pets?source=test http/1.1"));
    assert!(request_text.contains("content-type: application/json"));
    assert!(request_text.contains("accept: application/json"));
    assert!(request_text.contains("user-agent: chio-test"));
    assert!(request_text.contains("authorization: bearer upstream-token"));
    assert!(request_text.contains("x-request-id: req-123"));
    assert!(request_text.contains("x-custom-app: secret"));
    assert!(!request_text.contains("x-chio-capability:"));
    assert!(!request_text.contains("connection: keep-alive"));
    assert!(request_text.contains(r#"{"name":"fido"}"#));

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt_id);
    assert_eq!(log.receipts[0].response_status, 201);
    assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-proxy"));
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_strips_query_capability_before_forwarding_upstream() {
    let Some(server) =
        MockUpstreamServer::spawn(200, vec![("content-type", "application/json")], "{}")
    else {
        return;
    };
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        server.base_url(),
    );
    let token = signed_capability_token_json(&state.signer_keypair, "cap-query");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("source", "test")
        .append_pair("chio_capability", &token)
        .append_pair("mode", "full")
        .finish();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/pets?{query}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let requests = server.requests();
    server.join();

    assert_eq!(requests.len(), 1);
    let request_text = requests[0].to_ascii_lowercase();
    assert!(request_text.contains("post /pets?source=test&mode=full http/1.1"));
    assert!(!request_text.contains("chio_capability"));

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-query"));
}

#[tokio::test]
async fn proxy_handler_rejects_unsupported_methods_before_evaluation() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = Request::builder()
        .method("TRACE")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    assert_eq!(body.as_ref(), b"unsupported method");
    let log = state.receipt_log.lock().await;
    assert!(log.receipts.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_surfaces_upstream_failures_after_allowing_request() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let request = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let text = String::from_utf8(body.to_vec()).test_unwrap();
    assert!(text.contains("upstream error:"));

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].response_status, 502);
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_records_receipt_when_upstream_times_out() {
    // An allowed request whose upstream accepts the connection but never responds
    // must still finalize a receipt. The per-hop client timeout fires inside the
    // handler, so the stall is recorded as a bad-gateway receipt rather than
    // leaving the handler parked for an outer timeout to drop mid-flight.
    let Some(server) = MockUpstreamServer::spawn_unresponsive() else {
        return;
    };
    let state = test_state_with_client_timeout(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        server.base_url(),
        std::time::Duration::from_millis(150),
    );
    let request = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .test_unwrap();

    // The handler must return on its own once the upstream call times out; the
    // outer guard only trips (failing the test) if it never does.
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        proxy_handler(State(Arc::clone(&state)), request),
    )
    .await
    .test_unwrap();

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let receipt_id = response
        .headers()
        .get("x-chio-receipt-id")
        .and_then(|value| value.to_str().ok())
        .test_unwrap()
        .to_string();

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt_id);
    assert_eq!(log.receipts[0].response_status, 502);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_denies_invalid_capability_tokens() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("x-chio-capability", "not-json")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_access_denied");

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert!(log.receipts[0].capability_id.is_none());
    assert_eq!(
        http_status_scope(log.receipts[0].metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_denies_get_on_reserved_tools_path_without_capability() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = Request::builder()
        .method("GET")
        .uri("/chio/tools/billing/read")
        .body(Body::empty())
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_access_denied");

    let log = state.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert!(log.receipts[0].capability_id.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_evaluate_returns_200_with_deny_verdict() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let body = ChioHttpRequest::new(
        "req-sidecar-deny".to_string(),
        HttpMethod::Post,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
        .test_unwrap();

    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let evaluation: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(evaluation.receipt.verify_signature().test_unwrap());
    assert!(evaluation.verdict.is_denied());
    assert!(evaluation.receipt.is_denied());
    assert_eq!(
        http_status_scope(evaluation.receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_evaluate_validates_transport_capability_header() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );
    let token = signed_capability_token_json(&state.signer_keypair, "cap-sidecar");
    let mut body = ChioHttpRequest::new(
        "req-sidecar-allow".to_string(),
        HttpMethod::Post,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    body.capability_id = Some("cap-sidecar".to_string());
    let request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .header("x-chio-capability", token)
        .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
        .test_unwrap();

    let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let evaluation: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(evaluation.verdict.is_allowed());
    assert_eq!(
        evaluation.receipt.capability_id.as_deref(),
        Some("cap-sidecar")
    );
    assert_eq!(
        http_status_scope(evaluation.receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
    );
}

#[tokio::test]
async fn sidecar_verify_reports_signature_validity() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let receipt = HttpReceipt::sign(
        chio_http_core::HttpReceiptBody {
            id: "receipt-verify".to_string(),
            request_id: "req-verify".to_string(),
            route_pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            caller_identity_hash: "caller-hash".to_string(),
            session_id: None,
            verdict: chio_http_core::Verdict::Allow,
            receipt_kind: chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            response_status: 200,
            timestamp: 1_700_000_000,
            content_hash: chio_core_types::sha256_hex(b"test-content"),
            policy_hash: "policy".to_string(),
            trust_level: chio_core_types::receipt::kinds::TrustLevel::Mediated,
            capability_id: None,
            metadata: None,
            kernel_key: state.signer_keypair.public_key(),
        },
        &state.signer_keypair,
    )
    .test_unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/chio/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&receipt).test_unwrap()))
        .test_unwrap();

    let response = sidecar_verify_handler(State(state), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let verification: VerifyReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(verification.signature_valid);
    assert!(verification.signer_trusted);
    assert!(verification.authorized);
    assert!(verification.ok);
}

#[tokio::test]
async fn sidecar_verify_does_not_authorize_self_signed_receipts() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let keypair = Keypair::generate();
    let receipt = HttpReceipt::sign(
        chio_http_core::HttpReceiptBody {
            id: "receipt-self-signed".to_string(),
            request_id: "req-self-signed".to_string(),
            route_pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            caller_identity_hash: "caller-hash".to_string(),
            session_id: None,
            verdict: chio_http_core::Verdict::Allow,
            receipt_kind: chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core_types::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core_types::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core_types::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            response_status: 200,
            timestamp: 1_700_000_000,
            content_hash: chio_core_types::sha256_hex(b"test-content"),
            policy_hash: "policy".to_string(),
            trust_level: chio_core_types::receipt::kinds::TrustLevel::Mediated,
            capability_id: None,
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .test_unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/chio/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&receipt).test_unwrap()))
        .test_unwrap();

    let response = sidecar_verify_handler(State(state), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let verification: VerifyReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(verification.signature_valid);
    assert!(!verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_mint_returns_canonical_capability_tokens() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search", "tool:server-a:fetch:invoke"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let response = sidecar_mint_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let mint: SidecarMintResponse = serde_json::from_slice(&bytes).test_unwrap();

    assert_eq!(mint.capability.issuer, state.signer_keypair.public_key());
    assert_eq!(mint.capability.scope.grants.len(), 2);
    assert_eq!(mint.capability.scope.grants[0].server_id, "*");
    assert_eq!(mint.capability.scope.grants[0].tool_name, "search");
    assert!(mint.capability.verify_signature().test_unwrap());
}

#[tokio::test]
async fn sidecar_mint_reuses_capability_id_for_retry_requests() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request_body = serde_json::to_vec(&serde_json::json!({
        "subject": "job/default/demo",
        "scopes": ["tools:search", "tool:server-a:fetch:invoke"],
        "job_uid": "job-uid-1",
        "ttl_seconds": 300,
    }))
    .test_unwrap();

    let first_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(request_body.clone()))
            .test_unwrap(),
    );
    let second_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(request_body))
            .test_unwrap(),
    );

    let first_response = sidecar_mint_handler(State(Arc::clone(&state)), first_request).await;
    let second_response = sidecar_mint_handler(State(Arc::clone(&state)), second_request).await;
    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(second_response.status(), StatusCode::OK);

    let first_bytes = to_bytes(first_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let second_bytes = to_bytes(second_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let first_mint: SidecarMintResponse = serde_json::from_slice(&first_bytes).test_unwrap();
    let second_mint: SidecarMintResponse = serde_json::from_slice(&second_bytes).test_unwrap();

    assert_eq!(
        first_mint.capability.body().id,
        second_mint.capability.body().id
    );
}

#[tokio::test]
async fn sidecar_mint_changes_capability_id_for_different_scope_requests() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    let search_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );
    let fetch_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tool:server-a:fetch:invoke"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let search_response = sidecar_mint_handler(State(Arc::clone(&state)), search_request).await;
    let fetch_response = sidecar_mint_handler(State(Arc::clone(&state)), fetch_request).await;
    assert_eq!(search_response.status(), StatusCode::OK);
    assert_eq!(fetch_response.status(), StatusCode::OK);

    let search_bytes = to_bytes(search_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let fetch_bytes = to_bytes(fetch_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let search_mint: SidecarMintResponse = serde_json::from_slice(&search_bytes).test_unwrap();
    let fetch_mint: SidecarMintResponse = serde_json::from_slice(&fetch_bytes).test_unwrap();

    assert_ne!(
        search_mint.capability.body().id,
        fetch_mint.capability.body().id
    );
}

#[tokio::test]
async fn sidecar_submit_receipt_accepts_controller_job_receipts() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "job_name": "demo",
                    "namespace": "default",
                    "job_uid": "job-uid-1",
                    "capability_id": "cap-1",
                    "outcome": "succeeded",
                    "started_at": "2026-04-17T10:00:00Z",
                    "completed_at": "2026-04-17T10:05:00Z",
                    "steps": [{
                        "pod_name": "demo-pod",
                        "phase": "Succeeded",
                        "payload": "{\"ok\":true}",
                        "observed_at": "2026-04-17T10:05:00Z"
                    }]
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let response = sidecar_submit_receipt_handler(State(state), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let receipt: SidecarSubmitReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(receipt.accepted);
    assert!(!receipt.receipt_id.is_empty());
}

#[test]
fn ttl_seconds_from_wire_accepts_seconds_and_nanoseconds() {
    assert_eq!(ttl_seconds_from_wire(None, None), 3600);
    assert_eq!(ttl_seconds_from_wire(Some(3600), None), 3600);
    assert_eq!(ttl_seconds_from_wire(None, Some(500_000_000)), 1);
}

#[test]
fn parse_sidecar_operation_shorthand_read_preserves_read_scope() {
    assert_eq!(
        parse_sidecar_operation("read", true).test_unwrap(),
        Operation::Read
    );
}

#[tokio::test]
async fn sidecar_release_persists_revocation_and_blocks_reuse() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );

    let release_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                    "job_uid": "job-uid-1",
                    "reason": "completed",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::OK);

    let reloaded = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header(
            "x-chio-capability",
            signed_capability_token_json(&reloaded.signer_keypair, "cap-revoked"),
        )
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();
    let response = proxy_handler(State(Arc::clone(&reloaded)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["message"], "capability token has been revoked");

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_release_requires_persistent_receipt_store() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
    );

    let release_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                    "job_uid": "job-uid-1",
                    "reason": "completed",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let bytes = to_bytes(release_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(
        json["message"],
        "persistent receipt_db must be configured for capability release"
    );

    assert!(!state
        .revoked_capability_ids
        .lock()
        .await
        .contains("cap-revoked"));
}

#[tokio::test]
async fn sidecar_submit_receipt_persists_submitted_job_receipt() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "job_name": "demo",
                    "namespace": "default",
                    "job_uid": "job-uid-1",
                    "capability_id": "cap-1",
                    "outcome": "succeeded",
                    "started_at": "2026-04-17T10:00:00Z",
                    "completed_at": "2026-04-17T10:05:00Z",
                    "steps": [{
                        "pod_name": "demo-pod",
                        "phase": "Succeeded",
                        "payload": "{\"ok\":true}",
                        "observed_at": "2026-04-17T10:05:00Z"
                    }]
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let response = sidecar_submit_receipt_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let submit_response: SidecarSubmitReceiptResponse =
        serde_json::from_slice(&bytes).test_unwrap();

    let reloaded = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let log = reloaded.receipt_log.lock().await;
    let stored = log
        .receipts
        .iter()
        .find(|receipt| receipt.id == submit_response.receipt_id)
        .test_unwrap();
    assert_eq!(stored.capability_id.as_deref(), Some("cap-1"));
    assert_eq!(
        stored.metadata.as_ref().test_unwrap()["job_uid"],
        "job-uid-1"
    );
    assert_eq!(
        stored.metadata.as_ref().test_unwrap()["steps"][0]["pod_name"],
        "demo-pod"
    );
    assert!(stored.verify_signature().test_unwrap());
    // The returned id must be the content-addressed signed id (64-char
    // SHA-256 hex), not the pre-sign UUID. This guarantees clients can
    // look up the submitted job receipt in the receipt log.
    assert_eq!(submit_response.receipt_id, stored.id);
    assert_eq!(
        submit_response.receipt_id,
        stored.recompute_id().test_unwrap()
    );
    assert_eq!(submit_response.receipt_id.len(), 64);
    assert!(submit_response
        .receipt_id
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_control_endpoints_reject_non_loopback_callers() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

    let release_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::FORBIDDEN);

    let receipt_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "job_name": "demo",
                    "namespace": "default",
                    "job_uid": "job-uid-1",
                    "outcome": "succeeded",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let receipt_response =
        sidecar_submit_receipt_handler(State(Arc::clone(&state)), receipt_request).await;
    assert_eq!(receipt_response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(receipt_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
    assert_eq!(
        json["message"],
        "sidecar control endpoints require a loopback caller"
    );
}

#[tokio::test]
async fn sidecar_control_endpoints_allow_authenticated_non_loopback_callers() {
    let receipt_db = temp_receipt_db_path();
    let mut state = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some("cluster-control-token".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .header("authorization", "Bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::OK);

    let release_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .header("authorization", "Bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "capability_id": "cap-revoked",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let release_response =
        sidecar_release_handler(State(Arc::clone(&state)), release_request).await;
    assert_eq!(release_response.status(), StatusCode::OK);

    let receipt_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .header("authorization", "Bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "job_name": "demo",
                    "namespace": "default",
                    "job_uid": "job-uid-1",
                    "outcome": "succeeded",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );
    let receipt_response =
        sidecar_submit_receipt_handler(State(Arc::clone(&state)), receipt_request).await;
    assert_eq!(receipt_response.status(), StatusCode::OK);

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_control_endpoints_accept_lowercase_bearer_scheme() {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some("cluster-control-token".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .header("authorization", "bearer cluster-control-token")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );

    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn sidecar_control_endpoints_require_bearer_auth_for_loopback_when_configured() {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token =
        Some("cluster-control-token".to_string());

    let mint_request = with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
    );

    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
    assert_eq!(
        json["message"],
        "sidecar control endpoints require a loopback caller or valid bearer token"
    );
}

#[tokio::test]
async fn sidecar_control_endpoints_reject_blank_control_token_configuration() {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token = Some("   ".to_string());
    let remote = SocketAddr::from(([10, 1, 2, 3], 5200));

    let mint_request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("content-type", "application/json")
            .header("authorization", "Bearer ")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "subject": "job/default/demo",
                    "scopes": ["tools:search"],
                    "job_uid": "job-uid-1",
                }))
                .test_unwrap(),
            ))
            .test_unwrap(),
        remote,
    );

    let mint_response = sidecar_mint_handler(State(Arc::clone(&state)), mint_request).await;
    assert_eq!(mint_response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(json["error"], "chio_control_forbidden");
}

#[test]
fn sidecar_control_bearer_token_compare_is_constant_time_safe() {
    // Regression test: bearer-token comparison must use a constant-time
    // primitive so callers cannot recover the configured token through
    // response timing differences. We exercise both equal and prefix-
    // matching tokens to confirm the byte compare path is reached.
    let request = |header: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/mint")
            .header("authorization", header)
            .body(Body::empty())
            .test_unwrap()
    };

    let configured = "cluster-control-token";
    assert!(sidecar_control_bearer_token_matches(
        &request(&format!("Bearer {configured}")),
        configured,
    ));
    assert!(!sidecar_control_bearer_token_matches(
        &request("Bearer cluster-control-toxen"),
        configured,
    ));
    assert!(!sidecar_control_bearer_token_matches(
        &request("Bearer cluster-control"),
        configured,
    ));
    assert!(!sidecar_control_bearer_token_matches(
        &request("Bearer "),
        configured,
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_persists_receipts_when_receipt_db_configured() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let reloaded = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let log = reloaded.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert!(log.receipts[0].verify_signature().test_unwrap());

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persisted_receipts_are_visible_across_proxy_and_sidecar_flows() {
    let receipt_db = temp_receipt_db_path();
    let proxy_state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let denied_request = Request::builder()
        .method("POST")
        .uri("/pets")
        .body(Body::from(r#"{"name":"fido"}"#))
        .test_unwrap();
    let denied_response = proxy_handler(State(Arc::clone(&proxy_state)), denied_request).await;
    assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);

    let sidecar_state = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    {
        let log = sidecar_state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
    }

    let body = ChioHttpRequest::new(
        "req-sidecar-persisted".to_string(),
        HttpMethod::Get,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
        .test_unwrap();

    let response = sidecar_evaluate_handler(State(Arc::clone(&sidecar_state)), request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let reloaded = test_state_with_receipt_db(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let log = reloaded.receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 2);

    let _ = std::fs::remove_file(receipt_db);
}

// -------------------------------------------------------------
// SDK-shape body tests for the proxy routes.
// -------------------------------------------------------------

fn loopback_post(uri: &str, body: serde_json::Value) -> Request<Body> {
    with_loopback_peer(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).test_unwrap()))
            .test_unwrap(),
    )
}

fn parse_advisory_evaluation_body(bytes: &[u8]) -> (serde_json::Value, ChioReceipt) {
    let body: serde_json::Value = serde_json::from_slice(bytes).test_unwrap();
    assert_eq!(
        body["schema"],
        serde_json::json!("chio.sidecar.advisory-evaluation.v1")
    );
    assert_eq!(body["authorization"], serde_json::json!(false));
    assert_eq!(body["authorizationBasis"], "advisory_only");
    let receipt: ChioReceipt = serde_json::from_value(body["receipt"].clone()).test_unwrap();
    (body, receipt)
}

#[tokio::test]
async fn sidecar_capabilities_alias_accepts_sdk_body_shape() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let subject = Keypair::generate();

    let body = serde_json::json!({
        "subject": subject.public_key().to_hex(),
        "scope": {
            "grants": [],
            "resource_grants": [],
            "prompt_grants": [],
        },
        "ttl_seconds": 600,
    });

    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&bytes).test_unwrap();
    assert!(!token.id.is_empty());
    assert!(token.verify_signature().test_unwrap());
}

#[tokio::test]
async fn sidecar_capabilities_alias_accepts_canonical_body_shape() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    let body = serde_json::json!({
        "subject": "agent-via-canonical",
        "scopes": ["filesystem:read"],
        "ttl_seconds": 600,
        "job_uid": "job-canonical-1",
    });

    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&bytes).test_unwrap();
    assert!(token.verify_signature().test_unwrap());
}

#[tokio::test]
async fn sidecar_capabilities_alias_rejects_blank_subject() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let body = serde_json::json!({
        "subject": "   ",
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 60,
    });
    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sidecar_validate_capability_returns_valid_for_freshly_minted_token() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let mint_bytes = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&mint_bytes).test_unwrap();

    let validate_body = serde_json::to_value(&token).test_unwrap();
    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(validate_response.status(), StatusCode::OK);

    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], true);
    assert_eq!(json["capability_id"], token.id);
    assert!(json.get("reason").is_none() || json["reason"].is_null());
}

#[tokio::test]
async fn sidecar_validate_capability_rejects_relaxed_expected_scope_constraints() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": {
            "grants": [{
                "server_id": "files",
                "tool_name": "read",
                "operations": ["invoke"],
                "constraints": [{"type": "path_prefix", "value": "/secret"}]
            }],
            "resource_grants": [],
            "prompt_grants": []
        },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let mint_bytes = to_bytes(mint_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(&mint_bytes).test_unwrap();

    let validate_body = serde_json::json!({
        "id": token.id,
        "issuer": token.issuer.to_hex(),
        "subject": token.subject.to_hex(),
        "scope": token.scope,
        "issued_at": token.issued_at,
        "expires_at": token.expires_at,
        "delegation_chain": token.delegation_chain,
        "signature": token.signature.to_hex(),
        "expected_scope": {
            "grants": [{
                "server_id": "files",
                "tool_name": "read",
                "operations": ["invoke"],
                "constraints": []
            }],
            "resource_grants": [],
            "prompt_grants": []
        }
    });
    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(validate_response.status(), StatusCode::OK);

    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    assert_eq!(
        json["reason"].as_str(),
        Some("expected_scope is not a subset of capability scope")
    );
}

#[tokio::test]
async fn sidecar_validate_capability_reports_revoked_capability() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    // Revoke the capability via the existing release route, then
    // validate.
    let release_body = serde_json::json!({
        "capability_id": token.id,
        "reason": "test",
    });
    let release_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/release", release_body))
        .await
        .test_unwrap();
    assert_eq!(release_response.status(), StatusCode::OK);

    let validate_body = serde_json::to_value(&token).test_unwrap();
    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    assert!(json["reason"].as_str().test_unwrap().contains("revoked"));

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_validate_capability_rejects_untrusted_issuer() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let untrusted_issuer = Keypair::generate();
    let token_json = signed_capability_token_json(&untrusted_issuer, "cap-untrusted");
    let validate_body: serde_json::Value = serde_json::from_str(&token_json).test_unwrap();

    let validate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/validate", validate_body))
        .await
        .test_unwrap();
    assert_eq!(validate_response.status(), StatusCode::OK);

    let bytes = to_bytes(validate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["valid"], false);
    assert!(json["reason"]
        .as_str()
        .test_unwrap()
        .contains("issuer is not trusted"));
}

#[tokio::test]
async fn sidecar_attenuate_capability_fails_closed_without_subject_signer() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let body = serde_json::json!({
        "parent_capability_id": "anything",
        "attenuated_scope": {},
    });

    let response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/attenuate", body))
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(json["error"], "chio_attenuation_requires_subject_signer");
    assert_eq!(json["authorization"], false);
}

#[tokio::test]
async fn sidecar_verify_receipt_round_trips_a_signed_chio_receipt() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    let evaluate_body = serde_json::json!({
        "capability_id": token.id,
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);
    assert!(receipt.verify_signature().test_unwrap());
    assert_eq!(receipt.capability_id, token.id);
    // The sidecar advisory path emits advisory receipts (no decision)
    // so v1 authority gates cannot mistake the result for a kernel-
    // mediated authorization.
    assert!(receipt.decision.is_none());
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.boundary_class, BoundaryClass::AdvisoryOnly);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Evaluated)
    );
    assert!(!receipt.is_allowed());

    // Now feed it back through `/v1/receipts/verify`.
    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
    assert_eq!(verification.receipt_kind, "advisory_evaluation");
    assert_eq!(verification.boundary_class, "advisory_only");
    assert_eq!(verification.trust_level, "advisory");
    assert_eq!(verification.result, "none");
}

#[tokio::test]
async fn sidecar_evaluate_advisory_route_wraps_non_authorization_response() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let evaluate_body = serde_json::json!({
        "capability_id": "cap-advisory-route",
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
    });
    let removed_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate", evaluate_body.clone()))
        .await
        .test_unwrap();
    assert_eq!(removed_response.status(), StatusCode::GONE);

    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();

    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&bytes);
    assert_eq!(receipt.capability_id, "cap-advisory-route");
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.boundary_class, BoundaryClass::AdvisoryOnly);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert!(receipt.decision.is_none());
}

#[tokio::test]
async fn sidecar_advisory_json_fallback_preserves_trust_header() {
    let signer = Keypair::generate();
    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let parameter_hash = chio_core_types::canonical_json_bytes(&parameters)
        .map(|canonical| chio_core_types::sha256_hex(&canonical))
        .test_unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-advisory".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction {
                parameters,
                parameter_hash,
            },
            decision: None,
            receipt_kind: ReceiptKind::AdvisoryEvaluation,
            boundary_class: BoundaryClass::AdvisoryOnly,
            observation_outcome: Some(ObservationOutcome::Evaluated),
            tool_origin: ToolOrigin::HostExecutedUnmediated,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"test"),
            policy_hash: manual_receipt_policy_hash(
                "advisory_json_fallback_preserves_trust_header",
            ),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Advisory,
            tenant_id: None,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        &signer,
    )
    .test_unwrap();

    let receipt_id = receipt.id.clone();
    let response = sidecar_advisory_tool_call_evaluate_json_response(receipt);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, wrapped_receipt) = parse_advisory_evaluation_body(&body);
    assert_eq!(wrapped_receipt.id, receipt_id);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_untrusted_signer() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let attacker = Keypair::generate();
    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let parameter_hash = chio_core_types::canonical_json_bytes(&parameters)
        .map(|canonical| chio_core_types::sha256_hex(&canonical))
        .test_unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-attacker".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction {
                parameters,
                parameter_hash,
            },
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"forged-request-body"),
            policy_hash: manual_receipt_policy_hash("forged_sidecar_receipt_test"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: attacker.public_key(),
            bbs_projection_version: None,
        },
        &attacker,
    )
    .test_unwrap();
    assert!(receipt.verify_signature().test_unwrap());

    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("signer is not trusted"));

    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(!verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_capability_issuer_as_receipt_signer() {
    let attacker = Keypair::generate();
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    Arc::get_mut(&mut state)
        .test_expect("state is not shared yet")
        .trusted_capability_issuers
        .push(attacker.public_key());

    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let action = ToolCallAction::from_parameters(parameters).test_unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-attacker".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"forged-request-body"),
            policy_hash: manual_receipt_policy_hash("forged_capability_issuer_receipt_test"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: attacker.public_key(),
            bbs_projection_version: None,
        },
        &attacker,
    )
    .test_unwrap();

    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("signer is not trusted"));

    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(!verification.signer_trusted);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_action_parameter_hash_mismatch() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let parameters = serde_json::json!({"path": "/etc/hostname"});
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: uuid::Uuid::now_v7().to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            capability_id: "cap-sidecar".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read".to_string(),
            action: ToolCallAction {
                parameters,
                parameter_hash: "0".repeat(64),
            },
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core_types::sha256_hex(b"trusted-request-body"),
            policy_hash: manual_receipt_policy_hash("bad_action_hash_receipt_test"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: state.signer_keypair.public_key(),
            bbs_projection_version: None,
        },
        &state.signer_keypair,
    )
    .test_unwrap();
    assert!(receipt.verify_signature().test_unwrap());

    let verify_body = serde_json::to_value(&receipt).test_unwrap();
    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("parameter_hash"));

    let verification: VerifyReceiptResponse = serde_json::from_value(verify_json).test_unwrap();
    assert!(verification.signature_valid);
    assert!(verification.signer_trusted);
    assert!(verification.receipt_id_valid);
    assert!(!verification.parameter_hash_valid);
    assert!(!verification.authorized);
    assert!(!verification.ok);
}

#[tokio::test]
async fn sidecar_verify_receipt_rejects_expected_decision_mismatch() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    let evaluate_body = serde_json::json!({
        "capability_id": token.id,
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);

    let mut verify_body = serde_json::to_value(&receipt).test_unwrap();
    verify_body
        .as_object_mut()
        .test_unwrap()
        .insert("expected_decision".to_string(), serde_json::json!("deny"));

    let verify_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/receipts/verify", verify_body))
        .await
        .test_unwrap();
    let verify_json: serde_json::Value = serde_json::from_slice(
        &to_bytes(verify_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(verify_json["valid"], false);
    assert!(verify_json["reason"]
        .as_str()
        .test_unwrap()
        .contains("does not match"));
}

#[tokio::test]
async fn sidecar_evaluate_tool_call_denies_revoked_capability() {
    let receipt_db = temp_receipt_db_path();
    let state = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );

    let mint_body = serde_json::json!({
        "subject": Keypair::generate().public_key().to_hex(),
        "scope": { "grants": [], "resource_grants": [], "prompt_grants": [] },
        "ttl_seconds": 600,
    });
    let mint_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities", mint_body))
        .await
        .test_unwrap();
    let token: CapabilityToken = serde_json::from_slice(
        &to_bytes(mint_response.into_body(), 1024 * 1024)
            .await
            .test_unwrap(),
    )
    .test_unwrap();

    let release_body = serde_json::json!({"capability_id": token.id});
    let release_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/capabilities/release", release_body))
        .await
        .test_unwrap();
    assert_eq!(release_response.status(), StatusCode::OK);

    let evaluate_body = serde_json::json!({
        "capability_id": token.id,
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {},
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Dropped)
    );
    let alias_outcome = receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("advisory_check_outcome"))
        .and_then(|v| v.as_str());
    assert_eq!(alias_outcome, Some("capability_revoked"));
    assert!(receipt.verify_signature().test_unwrap());

    let log = state.tool_receipt_log.lock().await;
    assert_eq!(log.receipts.len(), 1);
    assert_eq!(log.receipts[0].id, receipt.id);
    drop(log);

    let reloaded = test_state_with_receipt_db(
        Vec::new(),
        "http://127.0.0.1:1".to_string(),
        Some(&receipt_db),
    );
    let persisted = reloaded.tool_receipt_log.lock().await;
    assert_eq!(persisted.receipts.len(), 1);
    assert_eq!(persisted.receipts[0].id, receipt.id);

    let _ = std::fs::remove_file(receipt_db);
}

#[tokio::test]
async fn sidecar_evaluate_tool_call_denies_parameter_hash_mismatch() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());

    let evaluate_body = serde_json::json!({
        "capability_id": "cap-test",
        "tool_server": "fs",
        "tool_name": "read",
        "parameters": {"path": "/etc/hostname"},
        "parameter_hash": "deadbeef".to_string(),
    });
    let evaluate_response = build_app(Arc::clone(&state))
        .oneshot(loopback_post("/v1/evaluate/advisory", evaluate_body))
        .await
        .test_unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    assert_eq!(
        evaluate_response
            .headers()
            .get(CHIO_TRUST_LEVEL_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("advisory")
    );
    let receipt_bytes = to_bytes(evaluate_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let (_body, receipt) = parse_advisory_evaluation_body(&receipt_bytes);
    assert!(receipt.decision.is_none());
    assert!(!receipt.is_allowed());
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert_eq!(
        receipt.observation_outcome,
        Some(ObservationOutcome::Dropped)
    );
    let alias_outcome = receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("advisory_check_outcome"))
        .and_then(|v| v.as_str());
    assert_eq!(alias_outcome, Some("parameter_hash_mismatch"));
}

#[tokio::test]
async fn live_route_reports_process_healthy_without_consulting_dependencies() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    let request = Request::builder()
        .method("GET")
        .uri("/chio/live")
        .body(Body::empty())
        .test_unwrap();

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(health.status, SidecarStatus::Healthy);
}

#[tokio::test]
async fn health_route_reports_ready_when_the_receipt_store_is_reachable() {
    let db_path = temp_receipt_db_path();
    let state =
        test_state_with_receipt_db(Vec::new(), "http://127.0.0.1:1".to_string(), Some(&db_path));
    let request = Request::builder()
        .method("GET")
        .uri("/chio/health")
        .body(Body::empty())
        .test_unwrap();

    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let health: HealthResponse = serde_json::from_slice(&body).test_unwrap();
    assert_eq!(health.status, SidecarStatus::Healthy);
}

#[tokio::test]
async fn readiness_consults_the_store_reachability_signal() {
    // With no store there is no dependency to fail, so readiness is healthy. The
    // reachability signal it consults is true for a working store; a store whose
    // connection could no longer answer this query drives readiness to unhealthy.
    let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
    assert_eq!(state.readiness_status().await, SidecarStatus::Healthy);

    let db_path = temp_receipt_db_path();
    let store = SqliteReceiptStore::open(&db_path).test_unwrap();
    assert!(
        store.is_reachable(),
        "a freshly opened store must be reachable"
    );
}

#[tokio::test]
async fn reachability_probe_touches_the_write_path_and_persists_nothing() {
    let db_path = temp_receipt_db_path();
    let store = SqliteReceiptStore::open(&db_path).test_unwrap();

    // A healthy store probes reachable, and the probe rolls back: exercising the
    // write path must not leave a durable receipt behind.
    assert!(
        store.is_reachable(),
        "a freshly opened store must be reachable"
    );
    assert!(
        store.load_receipts().test_unwrap().is_empty(),
        "the readiness probe must not persist a receipt"
    );

    // Drop the receipt table out of band, as a bad migration or schema corruption
    // would. A bare connection check would still answer here; the write-path probe
    // must not, so an instance that can no longer persist receipts leaves rotation.
    let side = rusqlite::Connection::open(&db_path).test_unwrap();
    side.execute("DROP TABLE http_receipts", []).test_unwrap();
    drop(side);

    assert!(
        !store.is_reachable(),
        "a store that can no longer persist receipts must fail readiness"
    );
}
