const MAX_SSE_LINE_BYTES: usize = 16 * 1024;
const MAX_SSE_EVENT_BYTES: usize = 256 * 1024;
const MAX_SSE_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_SSE_CHUNKS: usize = 1024;

// HttpEgressContract: this file holds the SSE parser; the typed egress
// contract is applied at the upstream dispatch sites in `auth.rs`
// (`fetch_json`, `delete_empty`, `get_sse`, `post_json`, `post_form_json`,
// `post_sse_json`) before any byte is sent. The `A2aTransportConfig` carrier
// is defined in `config.rs` and includes `HttpEgressContract`.
#[allow(dead_code)]
const _A2A_TRANSPORT_EGRESS_CONTRACT_ANCHOR: &str = "HttpEgressContract";

#[cfg(any(test, feature = "fuzz"))]
fn parse_sse_stream<R: Read, F>(
    reader: R,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    parse_sse_stream_with_limit(reader, MAX_SSE_TOTAL_BYTES as u64, decode_event)
}

fn parse_sse_stream_with_limit<R: Read, F>(
    reader: R,
    max_total_bytes: u64,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut data_lines = Vec::new();
    let mut chunks = Vec::new();
    let mut saw_terminal_or_interrupted = false;
    let mut total_bytes = 0_u64;
    let mut event_bytes = 0usize;
    let max_total_bytes = max_total_bytes.min(MAX_SSE_TOTAL_BYTES as u64);

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).map_err(|error| {
            AdapterError::Remote(format!("failed to read A2A SSE stream: {error}"))
        })?;
        if bytes_read == 0 {
            if !data_lines.is_empty() {
                process_sse_event(
                    &mut chunks,
                    &mut saw_terminal_or_interrupted,
                    &mut data_lines,
                    &mut event_bytes,
                    &decode_event,
                )?;
            }
            break;
        }
        if bytes_read > MAX_SSE_LINE_BYTES {
            return Err(AdapterError::Protocol(format!(
                "A2A SSE line exceeded {MAX_SSE_LINE_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes
            .checked_add(bytes_read as u64)
            .ok_or_else(|| AdapterError::Protocol("A2A SSE stream byte counter overflowed".to_string()))?;
        if total_bytes > max_total_bytes {
            return Err(AdapterError::Protocol(format!(
                "A2A SSE stream exceeded {max_total_bytes} response bytes"
            )));
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            process_sse_event(
                &mut chunks,
                &mut saw_terminal_or_interrupted,
                &mut data_lines,
                &mut event_bytes,
                &decode_event,
            )?;
            if saw_terminal_or_interrupted {
                break;
            }
            continue;
        }
        if trimmed.starts_with(':') {
            continue;
        }
        if let Some(data) = trimmed.strip_prefix("data:") {
            let data = data.trim_start();
            event_bytes = event_bytes.saturating_add(data.len()).saturating_add(1);
            if event_bytes > MAX_SSE_EVENT_BYTES {
                return Err(AdapterError::Protocol(format!(
                    "A2A SSE event exceeded {MAX_SSE_EVENT_BYTES} bytes"
                )));
            }
            data_lines.push(data.to_string());
        }
    }

    let stream = ToolCallStream { chunks };
    if stream.chunks.is_empty() {
        return Ok(ToolServerStreamResult::Incomplete {
            stream,
            reason: "A2A streaming response ended without any stream events".to_string(),
        });
    }

    if saw_terminal_or_interrupted {
        Ok(ToolServerStreamResult::Complete(stream))
    } else {
        Ok(ToolServerStreamResult::Incomplete {
            stream,
            reason: "A2A streaming response ended before a terminal or interrupted task state"
                .to_string(),
        })
    }
}

fn process_sse_event<F>(
    chunks: &mut Vec<ToolCallChunk>,
    saw_terminal_or_interrupted: &mut bool,
    data_lines: &mut Vec<String>,
    event_bytes: &mut usize,
    decode_event: &F,
) -> Result<(), AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    if data_lines.is_empty() {
        return Ok(());
    }

    let payload = data_lines.join("\n");
    data_lines.clear();
    *event_bytes = 0;
    let event = serde_json::from_str::<Value>(&payload).map_err(|error| {
        AdapterError::Protocol(format!("failed to decode A2A SSE event JSON: {error}"))
    })?;
    let stream_response = decode_event(event)?;
    let (stream_response, terminal_or_interrupted) = validate_stream_response(stream_response)?;
    if chunks.len() >= MAX_SSE_CHUNKS {
        return Err(AdapterError::Protocol(format!(
            "A2A SSE stream exceeded {MAX_SSE_CHUNKS} chunks"
        )));
    }
    *saw_terminal_or_interrupted |= terminal_or_interrupted;
    chunks.push(ToolCallChunk {
        data: stream_response,
    });
    Ok(())
}

fn apply_request_headers(
    mut request: ureq::Request,
    request_headers: &[A2aRequestHeader],
    strip_sensitive_headers: bool,
) -> ureq::Request {
    for header in request_headers {
        if strip_sensitive_headers
            && (header.sensitive || is_sensitive_redirect_header(&header.name))
        {
            continue;
        }
        request = request.set(header.name.as_str(), header.value.as_str());
    }
    request
}

fn apply_request_auth(
    mut request: ureq::Request,
    request_auth: &A2aResolvedRequestAuth,
    strip_sensitive_headers: bool,
) -> ureq::Request {
    request = apply_request_headers(request, &request_auth.headers, strip_sensitive_headers);
    if !strip_sensitive_headers && !request_auth.cookies.is_empty() {
        let cookie_value = build_cookie_header(request_auth);
        request = request.set("Cookie", cookie_value.as_str());
    }
    request
}

fn is_sensitive_redirect_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

fn build_cookie_header(request_auth: &A2aResolvedRequestAuth) -> String {
    let mut cookie_fragments = request_auth
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Cookie"))
        .map(|header| header.value.clone())
        .collect::<Vec<_>>();
    cookie_fragments.extend(
        request_auth
            .cookies
            .iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value)),
    );
    cookie_fragments.join("; ")
}

fn apply_request_auth_url(mut url: Url, request_auth: &A2aResolvedRequestAuth) -> Url {
    if request_auth.query_params.is_empty() {
        return url;
    }
    let auth_names = request_auth
        .query_params
        .iter()
        .map(|query_param| query_param.name.as_str())
        .collect::<Vec<_>>();
    let existing_pairs = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .filter(|(name, _)| !auth_names.iter().any(|auth_name| auth_name == name))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query_pairs = url.query_pairs_mut();
        for (name, value) in existing_pairs {
            query_pairs.append_pair(name.as_str(), value.as_str());
        }
        for query_param in &request_auth.query_params {
            query_pairs.append_pair(query_param.name.as_str(), query_param.value.as_str());
        }
    }
    url
}

fn enforce_ureq_content_length(
    contract: &HttpEgressContract,
    response: &ureq::Response,
    context: &str,
) -> Result<(), AdapterError> {
    if let Some(content_length) = response.header("Content-Length") {
        let content_length = content_length.trim().parse::<u64>().map_err(|error| {
            AdapterError::Protocol(format!("invalid A2A Content-Length from {context}: {error}"))
        })?;
        contract.enforce_response_bytes(content_length).map_err(|err| {
            AdapterError::Protocol(format!("HttpEgressContract rejects A2A response: {err}"))
        })?;
    }
    Ok(())
}

fn read_ureq_response_body_with_contract(
    response: ureq::Response,
    contract: &HttpEgressContract,
    context: &str,
) -> Result<Vec<u8>, AdapterError> {
    enforce_ureq_content_length(contract, &response, context)?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(contract.max_response_bytes.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|error| AdapterError::Remote(format!("failed to read A2A response from {context}: {error}")))?;
    contract
        .enforce_response_bytes(body.len() as u64)
        .map_err(|err| AdapterError::Protocol(format!("HttpEgressContract rejects A2A response: {err}")))?;
    Ok(body)
}

fn map_ureq_error_with_contract(
    error: ureq::Error,
    contract: &HttpEgressContract,
) -> AdapterError {
    match error {
        ureq::Error::Status(status, response) => {
            let body = match read_ureq_response_body_with_contract(
                response,
                contract,
                &format!("HTTP {status} error"),
            ) {
                Ok(body) => body,
                Err(error) => return error,
            };
            let body = String::from_utf8_lossy(&body).into_owned();
            AdapterError::Remote(format!("HTTP {status}: {}", body.trim()))
        }
        ureq::Error::Transport(error) => AdapterError::Remote(error.to_string()),
    }
}
