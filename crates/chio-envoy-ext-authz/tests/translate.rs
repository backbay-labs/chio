//! End-to-end integration tests: spin up an in-memory tonic server that
//! hosts [`ChioExtAuthzService`] with a mock kernel, then dispatch
//! `CheckRequest`s through a locally connected gRPC client and assert the
//! adapter's allow/deny/fail-closed behaviour.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use async_trait::async_trait;
use chio_envoy_ext_authz::proto::envoy::config::core::v3::HeaderValueOption;
use chio_envoy_ext_authz::proto::envoy::r#type::v3::StatusCode as EnvoyStatusCode;
use chio_envoy_ext_authz::proto::envoy::service::auth::v3::attribute_context::{
    HttpRequest, Peer, Request as AttrRequest,
};
use chio_envoy_ext_authz::proto::envoy::service::auth::v3::authorization_client::AuthorizationClient;
use chio_envoy_ext_authz::proto::envoy::service::auth::v3::authorization_server::AuthorizationServer;
use chio_envoy_ext_authz::proto::envoy::service::auth::v3::check_response::HttpResponse;
use chio_envoy_ext_authz::proto::envoy::service::auth::v3::{AttributeContext, CheckRequest};
use chio_envoy_ext_authz::{
    ChioExtAuthzService, EnvoyKernel, KernelError, ToolCallRequest, Verdict,
};
use prost_types::value::Kind;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::Code;

#[derive(Clone)]
enum MockBehavior {
    Allow,
    Deny {
        reason: String,
        guard: String,
        http_status: u16,
    },
    Error(String),
}

struct MockKernel {
    behavior: MockBehavior,
    calls: Arc<AtomicUsize>,
    last_tool: Arc<std::sync::Mutex<Option<String>>>,
}

#[async_trait]
impl EnvoyKernel for MockKernel {
    async fn evaluate(&self, request: ToolCallRequest) -> Result<Verdict, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut slot) = self.last_tool.lock() {
            *slot = Some(request.tool.clone());
        }
        match &self.behavior {
            MockBehavior::Allow => Ok(Verdict::Allow),
            MockBehavior::Deny {
                reason,
                guard,
                http_status,
            } => Ok(Verdict::Deny {
                reason: reason.clone(),
                guard: guard.clone(),
                http_status: *http_status,
            }),
            MockBehavior::Error(msg) => Err(KernelError::evaluation(msg)),
        }
    }
}

/// Stand up a tonic server on an ephemeral port and return a connected client
/// plus counters so the test can assert that the mock kernel saw the call.
async fn spawn_server(
    behavior: MockBehavior,
) -> (
    AuthorizationClient<Channel>,
    Arc<AtomicUsize>,
    Arc<std::sync::Mutex<Option<String>>>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let last_tool = Arc::new(std::sync::Mutex::new(None));
    let kernel = MockKernel {
        behavior,
        calls: calls.clone(),
        last_tool: last_tool.clone(),
    };
    let svc = ChioExtAuthzService::new(kernel);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AuthorizationServer::new(svc))
            .serve_with_incoming(incoming)
            .await;
    });

    // Wait briefly for the listener to be ready, then dial.
    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(2));
    let channel = endpoint.connect().await.unwrap();
    let client = AuthorizationClient::new(channel);
    (client, calls, last_tool)
}

/// Build a minimal valid `CheckRequest` for `GET <path>`. Extra headers
/// can be provided for identity tests.
fn make_check(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> CheckRequest {
    let mut header_map = std::collections::HashMap::new();
    for (k, v) in headers {
        header_map.insert((*k).to_string(), (*v).to_string());
    }
    CheckRequest {
        attributes: Some(AttributeContext {
            source: Some(Peer {
                address: None,
                service: String::new(),
                labels: Default::default(),
                principal: String::new(),
                certificate: String::new(),
            }),
            destination: None,
            request: Some(AttrRequest {
                time: None,
                http: Some(HttpRequest {
                    id: "test-req".to_string(),
                    method: method.to_string(),
                    headers: header_map,
                    path: path.to_string(),
                    host: "upstream.svc".to_string(),
                    scheme: "http".to_string(),
                    query: String::new(),
                    fragment: String::new(),
                    size: body.len() as i64,
                    protocol: "HTTP/2".to_string(),
                    body: body.to_string(),
                    raw_body: Vec::new(),
                }),
            }),
            context_extensions: Default::default(),
            metadata_context: None,
            route_metadata_context: None,
        }),
    }
}

fn metadata_string(metadata: &prost_types::Struct, key: &str) -> Option<String> {
    metadata.fields.get(key).and_then(|value| {
        value.kind.as_ref().and_then(|kind| match kind {
            Kind::StringValue(value) => Some(value.clone()),
            _ => None,
        })
    })
}

#[tokio::test]
async fn allow_verdict_returns_ok_response() {
    let (mut client, calls, last_tool) = spawn_server(MockBehavior::Allow).await;
    let check = make_check("GET", "/resource", &[], "");
    let response = client.check(check).await.unwrap().into_inner();

    let metadata = response
        .dynamic_metadata
        .as_ref()
        .expect("allow response carries dynamic metadata");
    assert_eq!(
        metadata_string(metadata, "chio.verdict").as_deref(),
        Some("allow")
    );
    let status = response.status.unwrap();
    assert_eq!(status.code, Code::Ok as i32);
    match response.http_response.unwrap() {
        HttpResponse::OkResponse(_) => (),
        other => panic!("expected OkResponse, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        last_tool.lock().unwrap().as_deref(),
        Some("http.get.resource")
    );
}

#[tokio::test]
async fn deny_verdict_returns_forbidden_response() {
    let (mut client, _, _) = spawn_server(MockBehavior::Deny {
        reason: "scope check failed".to_string(),
        guard: "ScopeGuard".to_string(),
        http_status: 403,
    })
    .await;
    let check = make_check("POST", "/execute", &[], "{\"cmd\":\"ls\"}");
    let response = client.check(check).await.unwrap().into_inner();

    let status = response.status.unwrap();
    assert_eq!(status.code, Code::PermissionDenied as i32);
    match response.http_response.unwrap() {
        HttpResponse::DeniedResponse(denied) => {
            assert_eq!(
                denied.status.unwrap().code,
                EnvoyStatusCode::Forbidden as i32
            );
            assert!(denied.body.contains("scope check failed"));
            let reason_header =
                denied
                    .headers
                    .iter()
                    .find_map(|HeaderValueOption { header, .. }| {
                        header.as_ref().and_then(|h| {
                            if h.key == "x-chio-denial-reason" {
                                Some(h.value.clone())
                            } else {
                                None
                            }
                        })
                    });
            assert_eq!(reason_header.as_deref(), Some("scope check failed"));
        }
        other => panic!("expected DeniedResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn deny_verdict_honours_custom_http_status() {
    let (mut client, _, _) = spawn_server(MockBehavior::Deny {
        reason: "rate limited".to_string(),
        guard: "RateGuard".to_string(),
        http_status: 429,
    })
    .await;
    let check = make_check("GET", "/resource", &[], "");
    let response = client.check(check).await.unwrap().into_inner();

    let metadata = response
        .dynamic_metadata
        .as_ref()
        .expect("deny response carries dynamic metadata");
    assert_eq!(
        metadata_string(metadata, "chio.verdict").as_deref(),
        Some("deny")
    );
    assert_eq!(
        metadata_string(metadata, "chio.denial_guard").as_deref(),
        Some("RateGuard")
    );
    assert_eq!(
        metadata_string(metadata, "chio.denial_reason").as_deref(),
        Some("rate limited")
    );
    match response.http_response.unwrap() {
        HttpResponse::DeniedResponse(denied) => {
            assert_eq!(
                denied.status.unwrap().code,
                EnvoyStatusCode::TooManyRequests as i32
            );
        }
        other => panic!("expected DeniedResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn kernel_error_fails_closed_with_500() {
    let (mut client, calls, _) =
        spawn_server(MockBehavior::Error("downstream exploded".to_string())).await;
    let check = make_check("GET", "/resource", &[], "");
    let response = client.check(check).await.unwrap().into_inner();

    let status = response.status.unwrap();
    assert_eq!(status.code, Code::Internal as i32);
    match response.http_response.unwrap() {
        HttpResponse::DeniedResponse(denied) => {
            assert_eq!(
                denied.status.unwrap().code,
                EnvoyStatusCode::InternalServerError as i32
            );
            assert!(denied.body.contains("fail_closed"));
        }
        other => panic!("expected DeniedResponse, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn kernel_error_redacts_internal_message_from_denied_response() {
    let internal_error = "db password=secret-token unavailable";
    let (mut client, _, _) = spawn_server(MockBehavior::Error(internal_error.to_string())).await;
    let check = make_check("GET", "/resource", &[], "");
    let response = client.check(check).await.unwrap().into_inner();

    let metadata = response
        .dynamic_metadata
        .as_ref()
        .expect("fail-closed response carries dynamic metadata");
    assert_eq!(
        metadata_string(metadata, "chio.denial_guard").as_deref(),
        Some("fail_closed")
    );
    assert!(!metadata.fields.values().any(|value| {
        matches!(
            value.kind.as_ref(),
            Some(Kind::StringValue(value)) if value.contains(internal_error)
        )
    }));
    match response.http_response.unwrap() {
        HttpResponse::DeniedResponse(denied) => {
            assert_eq!(
                denied.status.unwrap().code,
                EnvoyStatusCode::InternalServerError as i32
            );
            assert!(denied.body.contains("fail_closed"));
            assert!(!denied.body.contains(internal_error));

            let reason_header =
                denied
                    .headers
                    .iter()
                    .find_map(|HeaderValueOption { header, .. }| {
                        header.as_ref().and_then(|h| {
                            if h.key == "x-chio-denial-reason" {
                                Some(h.value.clone())
                            } else {
                                None
                            }
                        })
                    });
            assert_ne!(reason_header.as_deref(), Some(internal_error));
        }
        other => panic!("expected DeniedResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_attributes_fails_closed_without_kernel_call() {
    let (mut client, calls, _) = spawn_server(MockBehavior::Allow).await;
    let check = CheckRequest { attributes: None };
    let response = client.check(check).await.unwrap().into_inner();

    let status = response.status.unwrap();
    assert_eq!(status.code, Code::Internal as i32);
    match response.http_response.unwrap() {
        HttpResponse::DeniedResponse(denied) => {
            assert_eq!(
                denied.status.unwrap().code,
                EnvoyStatusCode::InternalServerError as i32
            );
        }
        other => panic!("expected DeniedResponse, got {other:?}"),
    }
    // Malformed requests short-circuit before the kernel is invoked.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bearer_token_populates_caller_identity_hint() {
    let (mut client, _, last_tool) = spawn_server(MockBehavior::Allow).await;
    let check = make_check(
        "GET",
        "/ping",
        &[("authorization", "Bearer abc.def.ghi")],
        "",
    );
    let _ = client.check(check).await.unwrap().into_inner();
    assert_eq!(last_tool.lock().unwrap().as_deref(), Some("http.get.ping"));
}
