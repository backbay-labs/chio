use super::*;
use axum::body::to_bytes;
use chio_openapi::PolicyDecision;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use chio_test_support::prelude::*;

fn strict_nonce_state(routes: Vec<RouteEntry>) -> Arc<ProxyState> {
    strict_nonce_state_with_upstream(routes, "http://127.0.0.1:1".to_string())
}

fn strict_nonce_state_with_upstream(routes: Vec<RouteEntry>, upstream: String) -> Arc<ProxyState> {
    let keypair = Keypair::generate();
    let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
    let signer_public_key = keypair.public_key();
    let trusted_capability_issuers = vec![signer_public_key.clone()];
    let trusted_receipt_signers = vec![signer_public_key];
    let mut evaluator = RequestEvaluator::new_ephemeral_with_approval_store(
        routes,
        keypair.clone(),
        "test-policy".to_string(),
        Arc::clone(&approval_store),
    );
    evaluator.enable_strict_execution_nonce_for_tests();
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
        receipt_log: Mutex::new(ReceiptLog {
            receipts: Vec::new(),
        }),
        tool_receipt_log: Mutex::new(ToolReceiptLog {
            receipts: Vec::new(),
        }),
        receipt_store: None,
        revocation_store: None,
        revoked_capability_ids: Mutex::new(HashSet::new()),
        trusted_capability_issuers,
        trusted_receipt_signers,
        sidecar_control_token: None,
        receipt_backend: "ephemeral",
        revocation_backend: "ephemeral",
    })
}

struct DeferredUpstream {
    base_url: String,
    listener: TcpListener,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

impl DeferredUpstream {
    fn bind() -> Option<Self> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => match error.kind() {
                std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::Unsupported => {
                    eprintln!(
                        "skipping proxy nonce test because loopback bind is unavailable: {error}"
                    );
                    return None;
                }
                _ => panic!("bind nonce upstream listener: {error}"),
            },
        };
        let address = listener.local_addr().test_unwrap();
        Some(Self {
            base_url: format!("http://{}", address),
            listener,
            requests: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    fn start(self) -> RunningUpstream {
        let requests = Arc::clone(&self.requests);
        let request_log = Arc::clone(&self.requests);
        let handle = thread::spawn(move || {
            let (mut stream, _) = self.listener.accept().test_unwrap();
            let request = read_http_request(&mut stream);
            request_log.lock().test_unwrap().push(request);
            write_http_response(&mut stream, 200, "application/json", "{\"ok\":true}");
        });
        RunningUpstream { requests, handle }
    }
}

struct RunningUpstream {
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    handle: thread::JoinHandle<()>,
}

impl RunningUpstream {
    fn join(self) -> Vec<String> {
        self.handle.join().test_unwrap();
        self.requests.lock().test_unwrap().clone()
    }
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

fn write_http_response<W: Write>(stream: &mut W, status: u16, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).test_unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sidecar_evaluate_returns_strict_execution_nonce_for_retry() {
    let state = strict_nonce_state(vec![RouteEntry {
        pattern: "/pets".to_string(),
        method: HttpMethod::Post,
        operation_id: Some("createPet".to_string()),
        policy: PolicyDecision::SessionAllow,
    }]);
    let mut body = ChioHttpRequest::new(
        "req-sidecar-nonce-preflight".to_string(),
        HttpMethod::Post,
        "/pets".to_string(),
        "/pets".to_string(),
        chio_http_core::CallerIdentity::anonymous(),
    );
    body.body_hash = Some("abc".to_string());
    body.body_length = 3;
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
    let preflight: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(matches!(preflight.verdict, Verdict::Incomplete { .. }));
    assert!(!preflight.receipt.is_allowed());
    let nonce = preflight
        .execution_nonce
        .clone()
        .test_expect("strict sidecar preflight should return retry nonce");

    let mut retry_body = body;
    retry_body.request_id = "req-sidecar-nonce-retry".to_string();
    retry_body.execution_nonce = Some(nonce);
    let retry_request = Request::builder()
        .method("POST")
        .uri("/chio/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&retry_body).test_unwrap()))
        .test_unwrap();

    let retry_response = sidecar_evaluate_handler(State(Arc::clone(&state)), retry_request).await;
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_bytes = to_bytes(retry_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let allowed: EvaluateResponse = serde_json::from_slice(&retry_bytes).test_unwrap();
    assert!(allowed.verdict.is_allowed());
    assert!(allowed.receipt.is_allowed());
    assert!(allowed.execution_nonce.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_handler_returns_strict_execution_nonce_before_upstream_dispatch() {
    let upstream = match DeferredUpstream::bind() {
        Some(upstream) => upstream,
        None => return,
    };
    let state = strict_nonce_state_with_upstream(
        vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::SessionAllow,
        }],
        upstream.base_url(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "text/plain")
        .body(Body::from("abc"))
        .test_unwrap();

    let response = proxy_handler(State(Arc::clone(&state)), request).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let preflight: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(matches!(preflight.verdict, Verdict::Incomplete { .. }));
    assert!(!preflight.receipt.is_allowed());
    let nonce = preflight
        .execution_nonce
        .clone()
        .test_expect("strict proxy preflight should return retry nonce");

    let running_upstream = upstream.start();
    let retry_request = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "text/plain")
        .header(
            CHIO_EXECUTION_NONCE_HEADER,
            serde_json::to_string(&nonce).test_unwrap(),
        )
        .body(Body::from("abc"))
        .test_unwrap();

    let retry_response = proxy_handler(State(Arc::clone(&state)), retry_request).await;
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_body = to_bytes(retry_response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    assert_eq!(retry_body.as_ref(), br#"{"ok":true}"#);
    let requests = running_upstream.join();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /pets HTTP/1.1"));
    assert!(!requests[0]
        .to_ascii_lowercase()
        .contains("x-chio-execution-nonce:"));
}
