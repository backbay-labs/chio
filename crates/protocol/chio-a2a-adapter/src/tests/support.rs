use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Once;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use chio_core::capability::{scope::{ChioScope, Operation, ToolGrant}, token::{CapabilityToken, CapabilityTokenBody}};
use chio_core::crypto::Keypair;
use chio_core::receipt::decision::Decision;
use chio_kernel::{
    ChioKernel, KernelConfig, ToolCallRequest, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair as RcgenKeyPair,
};

fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = ureq::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
}

fn bind_fake_a2a_listener(label: &str) -> Option<TcpListener> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::Unsupported
            ) =>
        {
            eprintln!("skipping {label}: loopback TCP bind unavailable: {err}");
            None
        }
        Err(err) => panic!("bind {label}: {err}"),
    }
}

fn test_adapter_config(base_url: &str, public_key: String) -> A2aAdapterConfig {
    A2aAdapterConfig::new(base_url, public_key)
        .with_egress_contract(test_egress_contract(base_url))
}

fn test_egress_contract(base_url: &str) -> HttpEgressContract {
    let url = Url::parse(base_url).expect("test base URL parses");
    let host = url.host_str().expect("test base URL has host");
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    HttpEgressContract::permissive_for_tests(&authority)
}

fn seed_a2a_task(adapter: &A2aAdapter, tool_name: &str, task_id: &str) {
    adapter
        .record_task_activity(
            tool_name,
            &json!({
                "task": {
                    "id": task_id,
                    "status": { "state": "TASK_STATE_WORKING" }
                }
            }),
            "test_seed",
        )
        .expect("seed A2A task registry");
}

fn insert_test_egress_authority(contract: &mut HttpEgressContract, base_url: &str) {
    let url = Url::parse(base_url).expect("test base URL parses");
    let host = url.host_str().expect("test base URL has host");
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    contract.allowed_authority_set.insert(authority);
}

fn local_test_adapter(
    capabilities: A2aAgentCapabilities,
    selected_binding: A2aProtocolBinding,
    tenant: Option<&str>,
) -> A2aAdapter {
    let agent_card = A2aAgentCard {
        name: "Research Agent".to_string(),
        description: "Answers research questions over A2A".to_string(),
        supported_interfaces: vec![],
        version: "1.0.0".to_string(),
        capabilities,
        security_schemes: None,
        security_requirements: None,
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![A2aAgentSkill {
            id: "research".to_string(),
            name: "Research".to_string(),
            description: "Search and synthesize results".to_string(),
            tags: vec!["search".to_string()],
            examples: None,
            input_modes: None,
            output_modes: None,
            security_requirements: None,
        }],
        documentation_url: None,
        icon_url: None,
    };
    let selected_interface = A2aAgentInterface {
        url: match selected_binding {
            A2aProtocolBinding::JsonRpc => "http://localhost:9000/rpc".to_string(),
            A2aProtocolBinding::HttpJson => "http://localhost:9000".to_string(),
        },
        protocol_binding: match selected_binding {
            A2aProtocolBinding::JsonRpc => "JSONRPC".to_string(),
            A2aProtocolBinding::HttpJson => "HTTP+JSON".to_string(),
        },
        protocol_version: "1.0".to_string(),
        tenant: tenant.map(ToString::to_string),
    };
    let manifest = build_manifest(
        "tenant-test",
        "0.1.0",
        &Keypair::generate().public_key().to_hex(),
        &agent_card,
        &selected_binding,
    )
    .expect("build manifest");
    A2aAdapter {
        manifest,
        agent_card,
        agent_card_url: normalize_agent_card_url("http://localhost:9000")
            .expect("normalize agent card URL"),
        selected_interface,
        selected_binding,
        configured_headers: Vec::new(),
        configured_query_params: Vec::new(),
        configured_cookies: Vec::new(),
        oauth_client_credentials: None,
        oauth_scopes: Vec::new(),
        oauth_token_endpoint_override: None,
        transport_config: A2aTransportConfig {
            default_tls_config: None,
            mutual_tls_config: None,
            egress_contract: None,
        },
        token_cache: Mutex::new(Vec::new()),
        timeout: Duration::from_secs(2),
        request_counter: AtomicU64::new(0),
        partner_policy: None,
        task_registry: None,
    }
}

#[derive(Clone, Copy)]
enum TestBinding {
    JsonRpc,
    HttpJson,
}

#[derive(Clone, Copy)]
enum TestScenario {
    BlockingMessage,
    TaskFollowUp,
    CancelTask,
    PushNotificationCrud,
    PushNotificationCapabilityOnly,
    OAuthClientCredentialsRequired,
    OAuthClientCredentialsSingleInvoke,
    OpenIdClientCredentialsRequired,
    MissingSendMessageResult,
    StreamingComplete,
    StreamingIncomplete,
    SubscribeComplete,
    SubscribeIncomplete,
    BearerRequired,
    BasicRequired,
    ApiKeyRequired,
    ApiKeyQueryRequired,
    ApiKeyCookieRequired,
    MutualTlsRequired,
}

enum TestResponse {
    Json(Value),
    EventStream(String),
}

struct FakeA2aServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    handle: thread::JoinHandle<()>,
}

impl FakeA2aServer {
    fn spawn_jsonrpc() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::BlockingMessage)
    }

    fn spawn_jsonrpc_task_follow_up() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::TaskFollowUp)
    }

    fn spawn_jsonrpc_missing_send_message_result() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::MissingSendMessageResult)
    }

    fn spawn_http_json() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::BlockingMessage)
    }

    fn spawn_http_json_task_follow_up() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::TaskFollowUp)
    }

    fn spawn_jsonrpc_cancel_task() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::CancelTask)
    }

    fn spawn_http_json_cancel_task() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::CancelTask)
    }

    fn spawn_jsonrpc_push_notification_crud() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::PushNotificationCrud)
    }

    fn spawn_http_json_push_notification_crud() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::PushNotificationCrud)
    }

    fn spawn_jsonrpc_push_notification_capability_only() -> Option<Self> {
        Self::spawn(
            TestBinding::JsonRpc,
            TestScenario::PushNotificationCapabilityOnly,
        )
    }

    fn spawn_jsonrpc_oauth_client_credentials_required() -> Option<Self> {
        Self::spawn(
            TestBinding::JsonRpc,
            TestScenario::OAuthClientCredentialsRequired,
        )
    }

    fn spawn_jsonrpc_oauth_client_credentials_single_invoke() -> Option<Self> {
        Self::spawn(
            TestBinding::JsonRpc,
            TestScenario::OAuthClientCredentialsSingleInvoke,
        )
    }

    fn spawn_jsonrpc_openid_client_credentials_required() -> Option<Self> {
        Self::spawn(
            TestBinding::JsonRpc,
            TestScenario::OpenIdClientCredentialsRequired,
        )
    }

    fn spawn_jsonrpc_streaming_complete() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::StreamingComplete)
    }

    fn spawn_http_json_streaming_complete() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::StreamingComplete)
    }

    fn spawn_jsonrpc_streaming_incomplete() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::StreamingIncomplete)
    }

    fn spawn_jsonrpc_subscribe_complete() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::SubscribeComplete)
    }

    fn spawn_http_json_subscribe_complete() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::SubscribeComplete)
    }

    fn spawn_jsonrpc_subscribe_incomplete() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::SubscribeIncomplete)
    }

    fn spawn_jsonrpc_bearer_required() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::BearerRequired)
    }

    fn spawn_http_json_basic_required() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::BasicRequired)
    }

    fn spawn_http_json_api_key_required() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyRequired)
    }

    fn spawn_http_json_api_key_query_required() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyQueryRequired)
    }

    fn spawn_http_json_api_key_cookie_required() -> Option<Self> {
        Self::spawn(TestBinding::HttpJson, TestScenario::ApiKeyCookieRequired)
    }

    fn spawn_jsonrpc_mtls_required() -> Option<Self> {
        Self::spawn(TestBinding::JsonRpc, TestScenario::MutualTlsRequired)
    }

    fn spawn(binding: TestBinding, scenario: TestScenario) -> Option<Self> {
        let listener = bind_fake_a2a_listener("fake A2A listener")?;
        let address = listener.local_addr().expect("listener address");
        let base_url = format!("http://{address}");
        let base_url_for_thread = base_url.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let (ready_tx, ready_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            ready_tx.send(()).expect("server ready");
            let expected_requests = match scenario {
                TestScenario::BlockingMessage => 2,
                TestScenario::TaskFollowUp => 3,
                TestScenario::CancelTask => 2,
                TestScenario::PushNotificationCrud => 5,
                TestScenario::PushNotificationCapabilityOnly => 1,
                TestScenario::OAuthClientCredentialsRequired => 4,
                TestScenario::OAuthClientCredentialsSingleInvoke => 3,
                TestScenario::OpenIdClientCredentialsRequired => 4,
                TestScenario::MissingSendMessageResult => 2,
                TestScenario::StreamingComplete
                | TestScenario::StreamingIncomplete
                | TestScenario::SubscribeComplete
                | TestScenario::SubscribeIncomplete
                | TestScenario::BasicRequired
                | TestScenario::ApiKeyRequired
                | TestScenario::ApiKeyQueryRequired
                | TestScenario::ApiKeyCookieRequired => 2,
                TestScenario::BearerRequired | TestScenario::MutualTlsRequired => 1,
            };
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set read timeout");
                let request = read_http_request(&mut stream);
                requests_for_thread
                    .lock()
                    .expect("lock request log")
                    .push(request.clone());
                let first_line = request.lines().next().unwrap_or_default();
                let response_body = if first_line
                    .starts_with("GET /.well-known/agent-card.json")
                {
                    let interface = match binding {
                        TestBinding::JsonRpc => json!([{
                            "url": format!("{base_url_for_thread}/rpc"),
                            "protocolBinding": "JSONRPC",
                            "protocolVersion": "1.0"
                        }]),
                        TestBinding::HttpJson => json!([{
                            "url": base_url_for_thread,
                            "protocolBinding": "HTTP+JSON",
                            "protocolVersion": "1.0"
                        }]),
                    };
                    let (security_schemes, security_requirements) =
                        agent_card_security_metadata(scenario, &base_url_for_thread);
                    json!({
                            "name": "Research Agent",
                            "description": "Answers research questions over A2A",
                            "supportedInterfaces": interface,
                            "version": "1.0.0",
                            "capabilities": {
                                "streaming": matches!(scenario, TestScenario::StreamingComplete | TestScenario::StreamingIncomplete | TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete),
                                "pushNotifications": matches!(scenario, TestScenario::PushNotificationCrud | TestScenario::PushNotificationCapabilityOnly),
                                "stateTransitionHistory": matches!(scenario, TestScenario::BlockingMessage | TestScenario::TaskFollowUp)
                            },
                            "defaultInputModes": ["text/plain", "application/json"],
                            "defaultOutputModes": ["application/json"],
                            "skills": [{
                                "id": "research",
                                "name": "Research",
                                "description": "Search and synthesize results",
                                "tags": ["search", "synthesis"],
                                "examples": ["Summarize recent cardiology evidence"],
                                "inputModes": ["text/plain", "application/json"],
                                "outputModes": ["application/json"]
                            }],
                            "securitySchemes": security_schemes,
                            "securityRequirements": security_requirements
                        })
                        .into()
                } else if first_line.starts_with("POST /rpc") {
                    response_for_jsonrpc(&request, scenario)
                } else if first_line.starts_with("GET /openid/.well-known/openid-configuration")
                {
                    response_for_openid_configuration(&request, scenario, &base_url_for_thread)
                } else if first_line.starts_with("POST /oauth/token") {
                    response_for_oauth_token(&request, scenario)
                } else if first_line.starts_with("POST /tasks/")
                    && first_line.contains(":cancel ")
                {
                    response_for_http_cancel_task(&request, scenario)
                } else if first_line.starts_with("POST /tasks/")
                    && first_line.contains("/pushNotificationConfigs ")
                {
                    response_for_http_create_push_notification_config(&request, scenario)
                } else if first_line.starts_with("POST /message:stream") {
                    response_for_http_stream(&request, scenario)
                } else if first_line.starts_with("GET /tasks/")
                    && first_line.contains(":subscribe ")
                {
                    response_for_http_subscribe(&request, scenario)
                } else if first_line.starts_with("GET /tasks/")
                    && first_line.contains("/pushNotificationConfigs/")
                {
                    response_for_http_get_push_notification_config(&request, scenario)
                } else if first_line.starts_with("GET /tasks/")
                    && first_line.contains("/pushNotificationConfigs")
                {
                    response_for_http_list_push_notification_configs(&request, scenario)
                } else if first_line.starts_with("POST /message:send") {
                    response_for_http_send(&request, scenario)
                } else if first_line.starts_with("DELETE /tasks/")
                    && first_line.contains("/pushNotificationConfigs/")
                {
                    response_for_http_delete_push_notification_config(&request, scenario)
                } else if first_line.starts_with("GET /tasks/") {
                    response_for_http_get_task(&request, scenario)
                } else {
                    json!({
                        "error": format!("unexpected request: {first_line}")
                    })
                    .into()
                };
                match response_body {
                    TestResponse::Json(body) => {
                        write_http_json_response(&mut stream, 200, &body)
                    }
                    TestResponse::EventStream(body) => {
                        write_http_event_stream_response(&mut stream, 200, &body)
                    }
                }
            }
        });

        ready_rx.recv().expect("server should start");
        Some(Self {
            base_url,
            requests,
            handle,
        })
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("lock requests").clone()
    }

    fn join(self) {
        self.handle.join().expect("join fake A2A server");
    }
}

struct MtlsTestMaterials {
    root_ca_pem: String,
    client_cert_chain_pem: String,
    client_private_key_pem: String,
    server_cert_chain_pem: String,
    server_private_key_pem: String,
}

struct FakeMtlsA2aServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    root_ca_pem: String,
    client_cert_chain_pem: String,
    client_private_key_pem: String,
    handle: thread::JoinHandle<()>,
}

impl FakeMtlsA2aServer {
    fn spawn_jsonrpc() -> Option<Self> {
        ensure_rustls_crypto_provider();
        let materials = generate_mtls_test_materials();
        let listener = bind_fake_a2a_listener("fake mTLS A2A listener")?;
        let address = listener.local_addr().expect("listener address");
        let base_url = format!("https://{address}");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let server_tls_config = build_test_server_tls_config(&materials);
        let base_url_for_thread = base_url.clone();
        let (ready_tx, ready_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            ready_tx.send(()).expect("server ready");
            let mut handled_requests = 0_usize;
            let mut accepted_connections = 0_usize;
            while handled_requests < 2 {
                accepted_connections += 1;
                assert!(
                    accepted_connections <= 6,
                    "fake mTLS A2A server exceeded retry budget before receiving expected requests"
                );
                let (tcp_stream, _) = listener.accept().expect("accept request");
                tcp_stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set read timeout");
                let connection =
                    ureq::rustls::ServerConnection::new(Arc::clone(&server_tls_config))
                        .expect("create rustls server connection");
                let mut stream = ureq::rustls::StreamOwned::new(connection, tcp_stream);
                let request = match try_read_http_request(&mut stream) {
                    Ok(request) if !request.is_empty() => request,
                    Ok(_) => continue,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("read mTLS request: {error}"),
                };
                requests_for_thread
                    .lock()
                    .expect("lock request log")
                    .push(request.clone());
                let first_line = request.lines().next().unwrap_or_default();
                let response = if first_line.starts_with("GET /.well-known/agent-card.json") {
                    mtls_agent_card_payload(&base_url_for_thread)
                } else if first_line.starts_with("POST /rpc") {
                    assert!(request.contains("\"method\":\"SendMessage\""));
                    assert!(request.contains("\"targetSkillId\":\"research\""));
                    assert!(!request.contains("Authorization: Bearer"));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "message": {
                                "messageId": "msg-out",
                                "contextId": "ctx-1",
                                "taskId": "task-1",
                                "role": "ROLE_AGENT",
                                "parts": [{
                                    "text": "completed research request",
                                    "mediaType": "text/plain"
                                }]
                            }
                        }
                    })
                } else {
                    json!({
                        "error": format!("unexpected request: {first_line}")
                    })
                };
                write_http_json_response(&mut stream, 200, &response);
                stream.flush().expect("flush response");
                handled_requests += 1;
            }
        });

        ready_rx.recv().expect("server should start");
        Some(Self {
            base_url,
            requests,
            root_ca_pem: materials.root_ca_pem,
            client_cert_chain_pem: materials.client_cert_chain_pem,
            client_private_key_pem: materials.client_private_key_pem,
            handle,
        })
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn root_ca_pem(&self) -> &str {
        &self.root_ca_pem
    }

    fn client_cert_chain_pem(&self) -> &str {
        &self.client_cert_chain_pem
    }

    fn client_private_key_pem(&self) -> &str {
        &self.client_private_key_pem
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("lock requests").clone()
    }

    fn join(self) {
        self.handle.join().expect("join fake mTLS A2A server");
    }
}

fn generate_mtls_test_materials() -> MtlsTestMaterials {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Chio Test Root CA");
    let ca_key_pair = RcgenKeyPair::generate().expect("generate CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .expect("self-sign CA certificate");

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("server params");
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key_pair = RcgenKeyPair::generate().expect("generate server key");
    let server_cert = server_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .expect("sign server certificate");

    let mut client_params =
        CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "Chio Test Client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key_pair = RcgenKeyPair::generate().expect("generate client key");
    let client_cert = client_params
        .signed_by(&client_key_pair, &ca_cert, &ca_key_pair)
        .expect("sign client certificate");

    let root_ca_pem = ca_cert.pem();
    MtlsTestMaterials {
        root_ca_pem: root_ca_pem.clone(),
        client_cert_chain_pem: format!("{}{}", client_cert.pem(), root_ca_pem.clone()),
        client_private_key_pem: client_key_pair.serialize_pem(),
        server_cert_chain_pem: format!("{}{}", server_cert.pem(), root_ca_pem),
        server_private_key_pem: server_key_pair.serialize_pem(),
    }
}

fn build_test_server_tls_config(
    materials: &MtlsTestMaterials,
) -> Arc<ureq::rustls::ServerConfig> {
    let mut client_root_store = ureq::rustls::RootCertStore::empty();
    for certificate in
        parse_pem_certificates(materials.root_ca_pem.as_str(), "mTLS test root CA")
            .expect("parse test root CA")
    {
        client_root_store
            .add(certificate)
            .expect("add test root CA to verifier store");
    }
    let verifier =
        ureq::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_root_store))
            .build()
            .expect("build client cert verifier");
    let server_cert_chain = parse_pem_certificates(
        materials.server_cert_chain_pem.as_str(),
        "mTLS test server certificate chain",
    )
    .expect("parse server certificate chain");
    let server_private_key = parse_pem_private_key(
        materials.server_private_key_pem.as_str(),
        "mTLS test server private key",
    )
    .expect("parse server private key");
    Arc::new(
        ureq::rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_cert_chain, server_private_key)
            .expect("build test mTLS server config"),
    )
}

fn mtls_agent_card_payload(base_url: &str) -> Value {
    json!({
        "name": "Research Agent",
        "description": "Answers research questions over A2A",
        "supportedInterfaces": [{
            "url": format!("{base_url}/rpc"),
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0"
        }],
        "version": "1.0.0",
        "capabilities": {
            "streaming": false,
            "pushNotifications": false
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [{
            "id": "research",
            "name": "Research",
            "description": "Search and synthesize results",
            "tags": ["search", "synthesis"],
            "examples": ["Summarize recent cardiology evidence"],
            "inputModes": ["text/plain", "application/json"],
            "outputModes": ["application/json"]
        }],
        "securitySchemes": {
            "mtlsAuth": {
                "mtlsSecurityScheme": {}
            }
        },
        "securityRequirements": [{
            "schemes": {
                "mtlsAuth": []
            }
        }]
    })
}

fn read_http_request<R: Read>(stream: &mut R) -> String {
    try_read_http_request(stream).expect("read request")
}

fn try_read_http_request<R: Read>(stream: &mut R) -> std::io::Result<String> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0_usize;

    loop {
        let read = stream.read(&mut chunk)?;
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
    Ok(String::from_utf8_lossy(&request).into_owned())
}

fn write_http_json_response<W: Write>(stream: &mut W, status: u16, body: &Value) {
    let body_text = body.to_string();
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_text(status),
        body_text.len(),
        body_text
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response");
}

fn write_http_event_stream_response<W: Write>(stream: &mut W, status: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_text(status),
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response");
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
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

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Error",
    }
}

fn response_for_jsonrpc(request: &str, scenario: TestScenario) -> TestResponse {
    if request.contains("\"method\":\"SendMessage\"") {
        assert!(request.contains("\"targetSkillId\":\"research\""));
        match scenario {
            TestScenario::BlockingMessage | TestScenario::BearerRequired => {
                if matches!(scenario, TestScenario::BearerRequired) {
                    assert!(request.contains("Authorization: Bearer secret-token"));
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "message": {
                            "messageId": "msg-out",
                            "contextId": "ctx-1",
                            "taskId": "task-1",
                            "role": "ROLE_AGENT",
                            "parts": [{
                                "text": "completed research request",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                    })
                .into()
            }
            TestScenario::MissingSendMessageResult => json!({
                "jsonrpc": "2.0",
                "id": 1
            })
            .into(),
            TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke => {
                assert!(request.contains("Authorization: Bearer oauth-access-token"));
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "message": {
                            "messageId": "msg-out",
                            "contextId": "ctx-1",
                            "taskId": "task-1",
                            "role": "ROLE_AGENT",
                            "parts": [{
                                "text": "completed research request",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                })
                .into()
            }
            TestScenario::OpenIdClientCredentialsRequired => {
                assert!(request.contains("Authorization: Bearer oidc-access-token"));
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "message": {
                            "messageId": "msg-out",
                            "contextId": "ctx-1",
                            "taskId": "task-1",
                            "role": "ROLE_AGENT",
                            "parts": [{
                                "text": "completed research request",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                })
                .into()
            }
            TestScenario::TaskFollowUp => {
                assert!(request.contains("\"returnImmediately\":true"));
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "task": task_payload("TASK_STATE_WORKING", false)
                    }
                })
                .into()
            }
            TestScenario::CancelTask
            | TestScenario::PushNotificationCrud
            | TestScenario::PushNotificationCapabilityOnly => {
                panic!("unexpected SendMessage for task-management scenario")
            }
            TestScenario::StreamingComplete
            | TestScenario::StreamingIncomplete
            | TestScenario::SubscribeComplete
            | TestScenario::SubscribeIncomplete
            | TestScenario::BasicRequired
            | TestScenario::MutualTlsRequired
            | TestScenario::ApiKeyRequired
            | TestScenario::ApiKeyQueryRequired
            | TestScenario::ApiKeyCookieRequired => {
                panic!("unexpected SendMessage for streaming scenario")
            }
        }
    } else if request.contains("\"method\":\"SendStreamingMessage\"") {
        assert!(matches!(
            scenario,
            TestScenario::StreamingComplete | TestScenario::StreamingIncomplete
        ));
        TestResponse::EventStream(jsonrpc_stream_body(scenario))
    } else if request.contains("\"method\":\"SubscribeToTask\"") {
        assert!(matches!(
            scenario,
            TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete
        ));
        assert!(request.contains("\"id\":\"task-1\""));
        TestResponse::EventStream(jsonrpc_stream_body(scenario))
    } else if request.contains("\"method\":\"GetTask\"") {
        assert!(matches!(scenario, TestScenario::TaskFollowUp));
        assert!(request.contains("\"id\":\"task-1\""));
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": task_payload("TASK_STATE_COMPLETED", true)
        })
        .into()
    } else if request.contains("\"method\":\"CancelTask\"") {
        assert!(matches!(scenario, TestScenario::CancelTask));
        assert!(request.contains("\"id\":\"task-1\""));
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": task_payload("TASK_STATE_CANCELED", false)
        })
        .into()
    } else if request.contains("\"method\":\"CreateTaskPushNotificationConfig\"") {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.contains("\"taskId\":\"task-1\""));
        assert!(request.contains("\"url\":\"https://callbacks.example.com/chio\""));
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "result": push_notification_config_payload()
        })
        .into()
    } else if request.contains("\"method\":\"GetTaskPushNotificationConfig\"") {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.contains("\"taskId\":\"task-1\""));
        assert!(request.contains("\"id\":\"config-1\""));
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "result": push_notification_config_payload()
        })
        .into()
    } else if request.contains("\"method\":\"ListTaskPushNotificationConfigs\"") {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.contains("\"taskId\":\"task-1\""));
        assert!(request.contains("\"pageSize\":25"));
        assert!(request.contains("\"pageToken\":\"page-2\""));
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "result": {
                "configs": [push_notification_config_payload()],
                "nextPageToken": "next-page"
            }
        })
        .into()
    } else if request.contains("\"method\":\"DeleteTaskPushNotificationConfig\"") {
        assert!(matches!(scenario, TestScenario::PushNotificationCrud));
        assert!(request.contains("\"taskId\":\"task-1\""));
        assert!(request.contains("\"id\":\"config-1\""));
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {}
        })
        .into()
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": 99,
            "error": {
                "code": -32601,
                "message": "unexpected method"
            }
        })
        .into()
    }
}

fn response_for_http_send(request: &str, scenario: TestScenario) -> TestResponse {
    assert!(request.contains("\"targetSkillId\":\"research\""));
    match scenario {
        TestScenario::BlockingMessage => json!({
            "task": task_payload("TASK_STATE_COMPLETED", true)
        }),
        TestScenario::BasicRequired => {
            assert!(request.contains("Authorization: Basic "));
            assert!(!request.contains("Authorization: Bearer"));
            json!({
                "task": task_payload("TASK_STATE_COMPLETED", true)
            })
        }
        TestScenario::ApiKeyRequired => {
            assert!(request.contains("X-A2A-Key: secret-key"));
            assert!(!request.contains("Authorization: Bearer"));
            json!({
                "task": task_payload("TASK_STATE_COMPLETED", true)
            })
        }
        TestScenario::ApiKeyQueryRequired => {
            assert!(request.starts_with("POST /message:send?a2a_key=secret-key "));
            assert!(!request.contains("Authorization: Bearer"));
            json!({
                "task": task_payload("TASK_STATE_COMPLETED", true)
            })
        }
        TestScenario::ApiKeyCookieRequired => {
            assert!(request.contains("Cookie: a2a_session=secret-cookie"));
            assert!(!request.contains("Authorization: Bearer"));
            json!({
                "task": task_payload("TASK_STATE_COMPLETED", true)
            })
        }
        TestScenario::TaskFollowUp => {
            assert!(request.contains("\"returnImmediately\":true"));
            json!({
                "task": task_payload("TASK_STATE_WORKING", false)
            })
        }
        TestScenario::CancelTask
        | TestScenario::PushNotificationCrud
        | TestScenario::PushNotificationCapabilityOnly => {
            panic!("unexpected blocking send for task-management scenario")
        }
        TestScenario::OAuthClientCredentialsRequired
        | TestScenario::OAuthClientCredentialsSingleInvoke
        | TestScenario::OpenIdClientCredentialsRequired => {
            panic!("unexpected blocking send for OAuth/OpenID scenario")
        }
        TestScenario::MissingSendMessageResult => {
            panic!("unexpected HTTP send for JSON-RPC malformed-result scenario")
        }
        TestScenario::StreamingComplete
        | TestScenario::StreamingIncomplete
        | TestScenario::SubscribeComplete
        | TestScenario::SubscribeIncomplete
        | TestScenario::BearerRequired
        | TestScenario::MutualTlsRequired => {
            panic!("unexpected blocking send for streaming scenario")
        }
    }
    .into()
}

fn response_for_http_stream(_request: &str, scenario: TestScenario) -> TestResponse {
    assert!(matches!(
        scenario,
        TestScenario::StreamingComplete | TestScenario::StreamingIncomplete
    ));
    TestResponse::EventStream(http_stream_body(scenario))
}

fn response_for_http_subscribe(request: &str, scenario: TestScenario) -> TestResponse {
    assert!(matches!(
        scenario,
        TestScenario::SubscribeComplete | TestScenario::SubscribeIncomplete
    ));
    assert!(request.starts_with("GET /tasks/task-1:subscribe"));
    TestResponse::EventStream(http_stream_body(scenario))
}

fn response_for_http_get_task(request: &str, scenario: TestScenario) -> TestResponse {
    assert!(matches!(scenario, TestScenario::TaskFollowUp));
    assert!(request.starts_with("GET /tasks/task-1"));
    json!(task_payload("TASK_STATE_COMPLETED", true)).into()
}

fn response_for_http_cancel_task(request: &str, scenario: TestScenario) -> TestResponse {
    assert!(matches!(scenario, TestScenario::CancelTask));
    assert!(request.starts_with("POST /tasks/task-1:cancel"));
    assert!(request.contains("\"reason\":\"user-request\""));
    json!(task_payload("TASK_STATE_CANCELED", false)).into()
}

fn response_for_http_create_push_notification_config(
    request: &str,
    scenario: TestScenario,
) -> TestResponse {
    assert!(matches!(scenario, TestScenario::PushNotificationCrud));
    assert!(request.starts_with("POST /tasks/task-1/pushNotificationConfigs"));
    assert!(request.contains("\"url\":\"https://callbacks.example.com/chio\""));
    json!(push_notification_config_payload()).into()
}

fn response_for_http_get_push_notification_config(
    request: &str,
    scenario: TestScenario,
) -> TestResponse {
    assert!(matches!(scenario, TestScenario::PushNotificationCrud));
    assert!(request.starts_with("GET /tasks/task-1/pushNotificationConfigs/config-1"));
    json!(push_notification_config_payload()).into()
}

fn response_for_http_list_push_notification_configs(
    request: &str,
    scenario: TestScenario,
) -> TestResponse {
    assert!(matches!(scenario, TestScenario::PushNotificationCrud));
    assert!(request
        .starts_with("GET /tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2"));
    json!({
        "configs": [push_notification_config_payload()],
        "nextPageToken": "next-page"
    })
    .into()
}

fn response_for_http_delete_push_notification_config(
    request: &str,
    scenario: TestScenario,
) -> TestResponse {
    assert!(matches!(scenario, TestScenario::PushNotificationCrud));
    assert!(request.starts_with("DELETE /tasks/task-1/pushNotificationConfigs/config-1"));
    json!({}).into()
}

fn response_for_openid_configuration(
    request: &str,
    scenario: TestScenario,
    base_url: &str,
) -> TestResponse {
    assert!(matches!(
        scenario,
        TestScenario::OpenIdClientCredentialsRequired
    ));
    assert!(request.starts_with("GET /openid/.well-known/openid-configuration"));
    json!({
        "token_endpoint": format!("{base_url}/oauth/token")
    })
    .into()
}

fn response_for_oauth_token(request: &str, scenario: TestScenario) -> TestResponse {
    assert!(matches!(
        scenario,
        TestScenario::OAuthClientCredentialsRequired
            | TestScenario::OAuthClientCredentialsSingleInvoke
            | TestScenario::OpenIdClientCredentialsRequired
    ));
    assert!(request.starts_with("POST /oauth/token"));
    assert!(request.contains("grant_type=client_credentials"));
    assert!(
        request.contains("Authorization: Basic")
            || (request.contains("client_id=client-id")
                && request.contains("client_secret=client-secret"))
    );
    match scenario {
        TestScenario::OAuthClientCredentialsRequired
        | TestScenario::OAuthClientCredentialsSingleInvoke => {
            assert!(request.contains("a2a.invoke"));
            json!({
                "access_token": "oauth-access-token",
                "token_type": "  Bearer  ",
                "expires_in": 3600
            })
            .into()
        }
        TestScenario::OpenIdClientCredentialsRequired => {
            assert!(request.contains("openid"));
            assert!(request.contains("profile"));
            json!({
                "access_token": "oidc-access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            })
            .into()
        }
        _ => unreachable!("unexpected token response scenario"),
    }
}

fn agent_card_security_metadata(scenario: TestScenario, base_url: &str) -> (Value, Value) {
    match scenario {
        TestScenario::BearerRequired => (
            json!({
                "bearerAuth": {
                    "httpAuthSecurityScheme": {
                        "scheme": "bearer"
                    }
                }
            }),
            json!([
                {
                    "schemes": {
                        "bearerAuth": []
                    }
                }
            ]),
        ),
        TestScenario::BasicRequired => (
            json!({
                "basicAuth": {
                    "httpAuthSecurityScheme": {
                        "scheme": "basic"
                    }
                }
            }),
            json!([
                {
                    "schemes": {
                        "basicAuth": []
                    }
                }
            ]),
        ),
        TestScenario::ApiKeyRequired => (
            json!({
                "apiKeyAuth": {
                    "apiKeySecurityScheme": {
                        "name": "X-A2A-Key",
                        "location": "header"
                    }
                }
            }),
            json!([
                {
                    "schemes": {
                        "apiKeyAuth": []
                    }
                }
            ]),
        ),
        TestScenario::ApiKeyQueryRequired => (
            json!({
                "apiKeyAuth": {
                    "apiKeySecurityScheme": {
                        "name": "a2a_key",
                        "location": "query"
                    }
                }
            }),
            json!([
                {
                    "schemes": {
                        "apiKeyAuth": []
                    }
                }
            ]),
        ),
        TestScenario::ApiKeyCookieRequired => (
            json!({
                "apiKeyAuth": {
                    "apiKeySecurityScheme": {
                        "name": "a2a_session",
                        "location": "cookie"
                    }
                }
            }),
            json!([
                {
                    "schemes": {
                        "apiKeyAuth": []
                    }
                }
            ]),
        ),
        TestScenario::OAuthClientCredentialsRequired
        | TestScenario::OAuthClientCredentialsSingleInvoke => (
            json!({
                "oauthAuth": {
                    "oauth2SecurityScheme": {
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": format!("{base_url}/oauth/token")
                            }
                        }
                    }
                }
            }),
            json!([
                {
                    "schemes": {
                        "oauthAuth": ["a2a.invoke"]
                    }
                }
            ]),
        ),
        TestScenario::OpenIdClientCredentialsRequired => (
            json!({
                "oidcAuth": {
                    "openIdConnectSecurityScheme": {
                        "openIdConnectUrl": format!("{base_url}/openid/.well-known/openid-configuration")
                    }
                }
            }),
            json!([
                {
                    "schemes": {
                        "oidcAuth": ["openid", "profile"]
                    }
                }
            ]),
        ),
        TestScenario::MutualTlsRequired => (
            json!({
                "mtlsAuth": {
                    "mtlsSecurityScheme": {}
                }
            }),
            json!([
                {
                    "schemes": {
                        "mtlsAuth": []
                    }
                }
            ]),
        ),
        TestScenario::BlockingMessage
        | TestScenario::TaskFollowUp
        | TestScenario::CancelTask
        | TestScenario::PushNotificationCrud
        | TestScenario::PushNotificationCapabilityOnly
        | TestScenario::MissingSendMessageResult
        | TestScenario::StreamingComplete
        | TestScenario::StreamingIncomplete
        | TestScenario::SubscribeComplete
        | TestScenario::SubscribeIncomplete => (Value::Null, Value::Null),
    }
}

fn task_payload(state: &str, include_artifacts: bool) -> Value {
    let mut task = json!({
        "id": "task-1",
        "contextId": "ctx-1",
        "status": {
            "state": state
        },
        "createdAt": "2026-03-24T00:00:00.000Z",
        "lastModified": "2026-03-24T00:00:01.000Z"
    });
    if include_artifacts {
        task["artifacts"] = json!([{
            "artifactId": "artifact-1",
            "parts": [{
                "text": "completed research request",
                "mediaType": "text/plain"
            }]
        }]);
    }
    task
}

fn push_notification_config_payload() -> Value {
    json!({
        "id": "config-1",
        "taskId": "task-1",
        "url": "https://callbacks.example.com/chio",
        "token": "notify-token",
        "authentication": {
            "scheme": "bearer",
            "credentials": "callback-secret"
        }
    })
}

fn jsonrpc_stream_body(scenario: TestScenario) -> String {
    sse_body(match scenario {
        TestScenario::StreamingComplete | TestScenario::SubscribeComplete => vec![
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "task": task_payload("TASK_STATE_WORKING", false) }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "artifactUpdate": {
                        "taskId": "task-1",
                        "artifact": {
                            "artifactId": "artifact-1",
                            "parts": [{
                                "text": "partial research result",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "statusUpdate": {
                        "taskId": "task-1",
                        "status": { "state": "TASK_STATE_COMPLETED" }
                    }
                }
            }),
        ],
        TestScenario::StreamingIncomplete | TestScenario::SubscribeIncomplete => vec![
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "task": task_payload("TASK_STATE_WORKING", false) }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "artifactUpdate": {
                        "taskId": "task-1",
                        "artifact": {
                            "artifactId": "artifact-1",
                            "parts": [{
                                "text": "partial research result",
                                "mediaType": "text/plain"
                            }]
                        }
                    }
                }
            }),
        ],
        _ => panic!("unexpected streaming scenario"),
    })
}

fn http_stream_body(scenario: TestScenario) -> String {
    sse_body(match scenario {
        TestScenario::StreamingComplete | TestScenario::SubscribeComplete => vec![
            json!({ "task": task_payload("TASK_STATE_WORKING", false) }),
            json!({
                "artifactUpdate": {
                    "taskId": "task-1",
                    "artifact": {
                        "artifactId": "artifact-1",
                        "parts": [{
                            "text": "partial research result",
                            "mediaType": "text/plain"
                        }]
                    }
                }
            }),
            json!({
                "statusUpdate": {
                    "taskId": "task-1",
                    "status": { "state": "TASK_STATE_COMPLETED" }
                }
            }),
        ],
        TestScenario::StreamingIncomplete | TestScenario::SubscribeIncomplete => vec![
            json!({ "task": task_payload("TASK_STATE_WORKING", false) }),
            json!({
                "artifactUpdate": {
                    "taskId": "task-1",
                    "artifact": {
                        "artifactId": "artifact-1",
                        "parts": [{
                            "text": "partial research result",
                            "mediaType": "text/plain"
                        }]
                    }
                }
            }),
        ],
        _ => panic!("unexpected streaming scenario"),
    })
}

fn sse_body(events: Vec<Value>) -> String {
    events
        .into_iter()
        .map(|event| format!("data: {}\n\n", event))
        .collect()
}

fn test_capability(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    capability_id: &str,
) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_string(),
                    tool_name: "research".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(5),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 100,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .expect("sign capability")
}

impl From<Value> for TestResponse {
    fn from(value: Value) -> Self {
        Self::Json(value)
    }
}

trait ToolCallOutputExt {
    fn into_value(self) -> Value;
    fn into_stream(self) -> ToolCallStream;
}

impl ToolCallOutputExt for chio_kernel::ToolCallOutput {
    fn into_value(self) -> Value {
        match self {
            chio_kernel::ToolCallOutput::Value(value) => value,
            chio_kernel::ToolCallOutput::Stream(_) => panic!("expected value output"),
        }
    }

    fn into_stream(self) -> ToolCallStream {
        match self {
            chio_kernel::ToolCallOutput::Value(_) => panic!("expected stream output"),
            chio_kernel::ToolCallOutput::Stream(stream) => stream,
        }
    }
}
