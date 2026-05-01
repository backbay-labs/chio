//! Ollama localhost replay gate.
//!
//! This gate exercises the configured `OLLAMA_HOST` with a lightweight
//! `/api/chat` probe, then runs the captured `ollama_localhost_replay` NDJSON
//! fixture through the adapter's `lift_batch` path so tool-call assertions stay
//! deterministic.
//!
//! `OLLAMA_HOST` is treated purely as an opt-in switch: when unset the
//! lane is skipped so PR jobs do not require a model on every machine. When
//! set, the test first validates that the local daemon accepts `/api/chat`
//! traffic before replaying captured fixture bytes through the adapter.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chio_ollama_tools_adapter::transport::Transport;
use chio_ollama_tools_adapter::{OllamaAdapter, OllamaAdapterConfig};
use chio_tool_call_fabric::{ProviderId, ProviderRequest};
use serde_json::Value;

struct HostTransport {
    endpoint: String,
}

impl HostTransport {
    fn new(endpoint: String) -> Self {
        Self { endpoint }
    }
}

impl Transport for HostTransport {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../chio-provider-conformance/fixtures/ollama/ollama_localhost_replay.ndjson")
}

fn read_response_payload(path: &Path) -> Result<Value, String> {
    let body = fs::read_to_string(path).map_err(|error| format!("read {path:?}: {error}"))?;
    for (idx, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("parse {path:?} line {}: {error}", idx + 1))?;
        if value.get("direction").and_then(Value::as_str) == Some("upstream_response") {
            return value
                .get("payload")
                .cloned()
                .ok_or_else(|| format!("upstream_response payload missing at line {}", idx + 1));
        }
    }
    Err(format!("no upstream_response in {path:?}"))
}

fn parse_http_host(host: &str) -> Result<(String, String), String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err("OLLAMA_HOST was empty".to_string());
    }
    if trimmed.starts_with("https://") {
        return Err("OLLAMA_HOST must use http:// for this localhost replay".to_string());
    }

    let without_scheme = match trimmed.strip_prefix("http://") {
        Some(value) => value,
        None => trimmed,
    };
    let (authority, path) = match without_scheme.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (without_scheme, String::new()),
    };
    if authority.trim().is_empty() {
        return Err(format!("OLLAMA_HOST `{host}` did not include a host"));
    }
    let address = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:11434")
    };
    Ok((address, path))
}

fn join_chat_path(base_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    if base.is_empty() {
        "/api/chat".to_string()
    } else {
        format!("{base}/api/chat")
    }
}

fn decode_body(headers: &str, body: &str) -> Result<String, String> {
    if !headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return Ok(body.to_string());
    }

    let mut rest = body;
    let mut decoded = String::new();
    loop {
        let Some((len_line, after_len)) = rest.split_once("\r\n") else {
            return Err("chunked response ended before a chunk length".to_string());
        };
        let len_hex = match len_line.split_once(';') {
            Some((len_hex, _extensions)) => len_hex.trim(),
            None => len_line.trim(),
        };
        let len = usize::from_str_radix(len_hex, 16)
            .map_err(|error| format!("parse chunk length `{len_hex}`: {error}"))?;
        if len == 0 {
            return Ok(decoded);
        }
        if after_len.len() < len + 2 {
            return Err("chunked response ended before chunk payload".to_string());
        }
        decoded.push_str(&after_len[..len]);
        let suffix = &after_len[len..];
        let Some(next) = suffix.strip_prefix("\r\n") else {
            return Err("chunked response payload missing CRLF terminator".to_string());
        };
        rest = next;
    }
}

fn post_ollama_chat(host: &str, model: &str) -> Result<String, String> {
    let (address, base_path) = parse_http_host(host)?;
    let path = join_chat_path(&base_path);
    let payload = serde_json::json!({
        "model": model,
        "stream": false,
        "messages": [
            {
                "role": "user",
                "content": "Return exactly OK."
            }
        ]
    })
    .to_string();

    let mut stream = TcpStream::connect(&address)
        .map_err(|error| format!("connect to OLLAMA_HOST `{host}` at {address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| format!("set read timeout for OLLAMA_HOST `{host}`: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| format!("set write timeout for OLLAMA_HOST `{host}`: {error}"))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{payload}",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write /api/chat request to OLLAMA_HOST `{host}`: {error}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read /api/chat response from OLLAMA_HOST `{host}`: {error}"))?;
    let Some((headers, raw_body)) = response.split_once("\r\n\r\n") else {
        return Err("Ollama /api/chat response did not include headers and body".to_string());
    };
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| "Ollama /api/chat response did not include a status line".to_string())?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("Ollama /api/chat status line was malformed: {status_line}"))?;
    let code: u16 = code
        .parse()
        .map_err(|error| format!("parse Ollama /api/chat status `{code}`: {error}"))?;
    let body = decode_body(headers, raw_body)?;
    if !(200..300).contains(&code) {
        let preview: String = body.chars().take(200).collect();
        return Err(format!(
            "Ollama /api/chat returned HTTP {code}; body preview: {preview}"
        ));
    }
    if body.trim().is_empty() {
        return Err("Ollama /api/chat returned an empty response body".to_string());
    }
    Ok(body)
}

fn response_has_chat_shape(body: &str) -> bool {
    match serde_json::from_str::<Value>(body) {
        Ok(value) => value
            .as_object()
            .is_some_and(|object| object.get("message").is_some() || object.get("done").is_some()),
        Err(_) => false,
    }
}

#[test]
fn response_has_chat_shape_rejects_unrelated_json() {
    assert!(!response_has_chat_shape(r#"{"status":"ok"}"#));
    assert!(!response_has_chat_shape(
        r#"[{"message":{"role":"assistant"}}]"#
    ));
    assert!(response_has_chat_shape(
        r#"{"message":{"role":"assistant","content":"OK"},"done":true}"#
    ));
}

#[test]
fn localhost_probe_then_deterministic_fixture_replay() {
    let Some(host) = env::var("OLLAMA_HOST").ok() else {
        eprintln!("OLLAMA_HOST not set; skipping localhost integration replay");
        return;
    };
    let model = env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.2:1b".to_string());
    let live_body = match post_ollama_chat(&host, &model) {
        Ok(body) => body,
        Err(error) => panic!("{error}"),
    };
    assert!(
        response_has_chat_shape(&live_body),
        "Ollama /api/chat returned a non-JSON or non-chat response: {live_body}"
    );

    let path = fixture_path();
    let payload = match read_response_payload(&path) {
        Ok(payload) => payload,
        Err(error) => panic!("{error}"),
    };

    let bytes = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(error) => panic!("encode replay payload: {error}"),
    };

    let adapter = OllamaAdapter::new(
        OllamaAdapterConfig::new(
            "ollama-1",
            "Ollama Chat",
            "0.1.0",
            "deadbeef",
            "local_chio_demo",
        ),
        Arc::new(HostTransport::new(host.clone())),
    );
    assert_eq!(
        adapter.transport().endpoint(),
        host,
        "localhost replay must drive the configured OLLAMA_HOST",
    );

    let invocations = match adapter.lift_batch(ProviderRequest(bytes)) {
        Ok(invocations) => invocations,
        Err(error) => panic!("lift_batch failed: {error}"),
    };
    assert_eq!(invocations.len(), 1, "expected one tool invocation");
    let invocation = &invocations[0];
    assert_eq!(invocation.provider, ProviderId::Ollama);
    assert_eq!(invocation.tool_name, "get_weather");
    assert_eq!(invocation.provenance.api_version, "2025-04");
}
