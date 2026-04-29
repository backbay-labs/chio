/// libFuzzer entry-point module for `chio-a2a-adapter`. Gated behind `fuzz` feature.

pub mod fuzz {
    use serde_json::Value;

    use super::{parse_sse_stream, validate_stream_response, A2aJsonRpcResponse, AdapterError};

    // Mirrors the anonymous closure in `invoke_stream_jsonrpc` / `subscribe_task_jsonrpc`;
    // reproduced here because there is no public seam to import from `invoke.rs`.
    fn jsonrpc_decode_event(value: Value) -> Result<Value, AdapterError> {
        let response: A2aJsonRpcResponse<Value> = serde_json::from_value(value).map_err(|error| {
            AdapterError::Protocol(format!(
                "failed to decode A2A JSON-RPC stream event: {error}"
            ))
        })?;
        if response.jsonrpc != "2.0" {
            return Err(AdapterError::Protocol(format!(
                "unexpected JSON-RPC version {}",
                response.jsonrpc
            )));
        }
        if let Some(error) = response.error {
            return Err(AdapterError::Remote(format!(
                "A2A JSON-RPC error {}: {}",
                error.code, error.message
            )));
        }
        response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC stream event omitted `result`".to_string())
        })
    }

    fn http_json_decode_event(value: Value) -> Result<Value, AdapterError> {
        Ok(value)
    }

    pub fn fuzz_a2a_envelope_decode(data: &[u8]) {
        // Fan-out 1: HTTP-JSON binding (identity decode_event).
        let _ = parse_sse_stream(data, http_json_decode_event);

        // Fan-out 2: JSON-RPC binding (envelope-unwrap decode_event).
        let _ = parse_sse_stream(data, jsonrpc_decode_event);

        // Fan-out 3: drive the validator on raw data: lines independently of the SSE
        // framer, so it is reachable even when parse_sse_stream short-circuits early.
        if let Ok(text) = std::str::from_utf8(data) {
            for frame in text.split("\n\n") {
                let mut data_lines: Vec<&str> = Vec::new();
                for line in frame.split('\n') {
                    let trimmed = line.trim_end_matches('\r');
                    if let Some(payload) = trimmed.strip_prefix("data:") {
                        data_lines.push(payload.trim_start());
                    }
                }
                if data_lines.is_empty() {
                    continue;
                }
                let payload = data_lines.join("\n");
                let value: Value = match serde_json::from_str(&payload) {
                    Ok(value) => value,
                    Err(_) => continue,
                };

                // Per-envelope: HTTP-JSON identity decode + validator.
                if let Ok(decoded) = http_json_decode_event(value.clone()) {
                    let _ = validate_stream_response(decoded);
                }

                // Per-envelope: JSON-RPC unwrap + validator on the
                // unwrapped `result` payload.
                if let Ok(decoded) = jsonrpc_decode_event(value) {
                    let _ = validate_stream_response(decoded);
                }
            }
        }
    }
}
