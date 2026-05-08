#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chio_a2a_adapter::{A2aAdapter, A2aAdapterConfig};
use chio_core::crypto::Keypair;
use chio_egress_contract::HttpEgressContract;
use chio_kernel::ToolServerConnection;
use serde_json::{json, Value};

fn bind_fake_a2a_listener() -> Option<TcpListener> {
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
            eprintln!("skipping integration smoke test: loopback TCP bind unavailable: {err}");
            None
        }
        Err(err) => panic!("bind fake A2A listener: {err}"),
    }
}

fn test_adapter_config(base_url: &str, public_key: String) -> A2aAdapterConfig {
    A2aAdapterConfig::new(base_url, public_key).with_egress_contract(test_egress_contract(base_url))
}

fn test_egress_contract(base_url: &str) -> HttpEgressContract {
    let url = url::Url::parse(base_url).expect("test base URL parses");
    let host = url.host_str().expect("test base URL has host");
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    HttpEgressContract::permissive_for_tests(&authority)
}

struct FakeA2aJsonRpcServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    handle: thread::JoinHandle<()>,
}

impl FakeA2aJsonRpcServer {
    fn spawn() -> Option<Self> {
        let listener = bind_fake_a2a_listener()?;
        let address = listener.local_addr().expect("listener address");
        let base_url = format!("http://127.0.0.1:{}", address.port());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let base_url_for_thread = base_url.clone();

        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set read timeout");
                let request = read_http_request(&mut stream);
                requests_for_thread
                    .lock()
                    .expect("lock request log")
                    .push(request.clone());

                let response = if request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .starts_with("GET /.well-known/agent-card.json")
                {
                    json!({
                        "name": "Research Agent",
                        "description": "Answers research questions over A2A",
                        "supportedInterfaces": [{
                            "url": format!("{base_url_for_thread}/rpc"),
                            "protocolBinding": "JSONRPC",
                            "protocolVersion": "1.0"
                        }],
                        "version": "1.0.0",
                        "capabilities": {
                            "streaming": false,
                            "pushNotifications": false,
                            "stateTransitionHistory": false
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
                        }]
                    })
                } else {
                    assert!(request.starts_with("POST /rpc HTTP/1.1"));
                    assert!(request.contains("Authorization: Bearer secret-token"));
                    assert!(request.contains("A2A-Version: 1.0"));
                    assert!(request.contains("\"method\":\"SendMessage\""));
                    assert!(request.contains("\"targetSkillId\":\"research\""));
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
                };
                write_http_json_response(&mut stream, 200, &response);
                stream.flush().expect("flush fake A2A response");
            }
        });

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
        self.requests.lock().expect("lock request log").clone()
    }

    fn join(self) {
        self.handle.join().expect("join fake A2A server");
    }
}

fn read_http_request<R: Read>(stream: &mut R) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    let mut content_length = 0_usize;

    loop {
        let read = stream.read(&mut chunk).expect("read request");
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

    String::from_utf8_lossy(&request).into_owned()
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

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Error",
    }
}

#[tokio::test]
async fn adapter_discovers_and_invokes_over_a2a_jsonrpc() {
    let Some(server) = FakeA2aJsonRpcServer::spawn() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_bearer_token("secret-token")
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover A2A adapter");

    assert_eq!(adapter.tool_names(), vec!["research".to_string()]);

    let result = adapter
        .invoke(
            "research",
            json!({
                "message": "Summarize recent cardiology evidence"
            }),
            None,
        )
        .await
        .expect("invoke A2A skill");

    assert_eq!(
        result["message"]["parts"][0]["text"],
        "completed research request"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("GET /.well-known/agent-card.json HTTP/1.1"));
    assert!(requests[1].contains("POST /rpc HTTP/1.1"));
    server.join();
}
