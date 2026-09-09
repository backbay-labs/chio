//! Operator exchange for authority limited to one retained MCP session.
//!
//! Credentials are opaque bearer secrets. Only their hashes and signed authority
//! bindings are persisted in the operator-owned session database. They cannot
//! create sessions, mint capabilities, or invoke administrative APIs.

use super::*;
use rusqlite::{params, OptionalExtension};
use subtle::ConstantTimeEq;

const SCHEMA: &str = "chio.mcp.session-credential.v1";
const PREFIX: &str = "chio_session_v1_";
const TABLE: &str = "remote_session_credentials";
const MAX_TTL_SECONDS: u64 = 3600;
const CALL_TABLE: &str = "remote_session_credential_calls";
const LATCH_TABLE: &str = "remote_session_credential_latches";
const DELIVERY_SCHEMA: &str = "chio.mcp.delivery-ack.v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeliveryAcknowledgement {
    schema: String,
    request_id: String,
    request_hash: String,
    receipt_id: String,
    result_hash: String,
    acknowledgement: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CredentialCall {
    schema: String,
    session_id: String,
    subject_key: String,
    capability_ids: Vec<String>,
    server_id: String,
    request_id: String,
    request_hash: String,
    tool_name: String,
    parameter_hash: String,
    started_at: u64,
    state: String,
    response: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_ack: Option<DeliveryAcknowledgement>,
}

pub(super) enum CallReservation {
    Pending(Box<CredentialCall>),
    Replay(Value),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SessionCredential {
    schema: String,
    token_hash: String,
    session_id: String,
    subject_key: String,
    capability_ids: Vec<String>,
    server_id: String,
    endpoint_path: String,
    auth_mode_fingerprint: String,
    policy_fingerprint: String,
    allowed_tools: Vec<String>,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueRequest {
    ttl_seconds: u64,
    allowed_tools: Vec<String>,
}

pub(super) fn install_routes(router: Router<RemoteAppState>) -> Router<RemoteAppState> {
    router
        .route("/admin/sessions/{session_id}/credential", post(issue))
        .route(
            "/admin/sessions/{session_id}/credential/revoke",
            post(revoke),
        )
        .route(
            "/admin/sessions/{session_id}/credential/status",
            get(status),
        )
}

fn storage_error(error: impl std::fmt::Display) -> Response {
    error!(error = %error, "session credential persistence failed");
    plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "session credential storage unavailable",
    )
}

fn unavailable() -> Response {
    unauthorized_bearer_response("invalid, expired, or revoked session credential", None)
}

fn open_db(path: &FsPath) -> Result<rusqlite::Connection, CliError> {
    let conn = open_session_state_db(path)?;
    conn.execute_batch(&format!(
        "PRAGMA synchronous = FULL;
         CREATE TABLE IF NOT EXISTS {TABLE} (
           session_id TEXT PRIMARY KEY NOT NULL,
           token_hash TEXT UNIQUE NOT NULL,
           record_json TEXT NOT NULL,
           signature TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS {CALL_TABLE} (
           session_id TEXT NOT NULL, request_id TEXT NOT NULL,
           record_json TEXT NOT NULL, signature TEXT NOT NULL,
           PRIMARY KEY (session_id, request_id)
         );
         CREATE TABLE IF NOT EXISTS {LATCH_TABLE} (
           session_id TEXT PRIMARY KEY NOT NULL, request_id TEXT NOT NULL,
           record_json TEXT NOT NULL, signature TEXT NOT NULL
         );"
    ))?;
    Ok(conn)
}

fn operator_runtime(state: &RemoteAppState) -> Result<(&FsPath, Keypair), Response> {
    if !matches!(
        state.auth_mode.as_ref(),
        RemoteAuthMode::StaticBearer { .. }
    ) || state.admin_token.as_deref() == state.factory.config.auth_token.as_deref()
        || !state.factory.config.shared_hosted_owner
    {
        return Err(plain_http_error(StatusCode::CONFLICT,
            "session credentials require static operator auth, a distinct admin token, and a shared hosted owner"));
    }
    let path = state
        .factory
        .config
        .session_db_path
        .as_deref()
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::CONFLICT,
                "session credentials require durable session storage",
            )
        })?;
    let runtime = state.factory.durable_admission.as_ref().ok_or_else(|| {
        plain_http_error(
            StatusCode::CONFLICT,
            "session credentials require durable admission",
        )
    })?;
    Ok((path, runtime.kernel_keypair()))
}

async fn issue(
    State(state): State<RemoteAppState>,
    AxumPath(session_id): AxumPath<String>,
    request: Request,
) -> Response {
    if let Err(response) =
        remote_mcp_admin::validate_admin_request(request.headers(), state.admin_token.as_deref())
    {
        return response;
    }
    let (path, keypair) = match operator_runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let bytes = match axum::body::to_bytes(request.into_body(), 16 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return plain_http_error(StatusCode::BAD_REQUEST, "invalid credential exchange body")
        }
    };
    let input: IssueRequest = match serde_json::from_slice(&bytes) {
        Ok(input) => input,
        Err(_) => {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "expected ttlSeconds and explicit allowedTools",
            )
        }
    };
    if input.ttl_seconds == 0
        || input.ttl_seconds > MAX_TTL_SECONDS
        || input.allowed_tools.is_empty()
        || input.allowed_tools.len() > 128
    {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "invalid credential TTL or tool allowlist",
        );
    }
    let Some(RemoteSessionEntry::Active(session)) =
        resolve_session_entry(&state, &session_id).await
    else {
        return plain_http_error(StatusCode::NOT_FOUND, "retained active session required");
    };
    if let Err(response) = validate_session_lifecycle(&session) {
        return response;
    }
    let _request_lock = session.active_request_stream.lock().await;
    let mut allowed_tools = input.allowed_tools;
    allowed_tools.sort();
    allowed_tools.dedup();
    let inventory = state
        .factory
        .shared_upstream_owner
        .lock()
        .ok()
        .and_then(|owner| {
            owner
                .as_ref()
                .map(|owner| owner.upstream_server.tool_names())
        })
        .unwrap_or_default();
    let now = unix_now();
    for tool in &allowed_tools {
        let covered = session.issued_capabilities.iter().any(|capability| {
            capability.expires_at > now
                && capability.subject.to_hex() == session.agent_id
                && capability.scope.grants.iter().any(|grant| {
                    (grant.server_id == "*" || grant.server_id == state.factory.config.server_id)
                        && (grant.tool_name == "*" || grant.tool_name == *tool)
                        && grant
                            .operations
                            .contains(&chio_core::capability::scope::Operation::Invoke)
                })
        });
        if !covered || !inventory.contains(tool) {
            return plain_http_error(
                StatusCode::BAD_REQUEST,
                "allowedTools must be exact issued tools in the owner inventory",
            );
        }
    }
    let expires_at = session
        .issued_capabilities
        .iter()
        .map(|cap| cap.expires_at)
        .min()
        .unwrap_or(now)
        .min(now.saturating_add(input.ttl_seconds));
    if expires_at <= now {
        return unavailable();
    }
    let token = format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(Keypair::generate().seed_bytes())
    );
    let record = SessionCredential {
        schema: SCHEMA.to_owned(),
        token_hash: sha256_hex(token.as_bytes()),
        session_id,
        subject_key: session.agent_id.clone(),
        capability_ids: session
            .capabilities
            .iter()
            .map(|cap| cap.id.clone())
            .collect(),
        server_id: state.factory.config.server_id.clone(),
        endpoint_path: MCP_ENDPOINT_PATH.to_owned(),
        auth_mode_fingerprint: session.auth_mode_fingerprint.clone(),
        policy_fingerprint: session.policy_fingerprint.clone(),
        allowed_tools,
        issued_at: now,
        expires_at,
    };
    let Some(resume) = session.resume_record() else {
        return unavailable();
    };
    // Do not deliver a usable credential if its retained session was not durable.
    if let Err(error) = persist_active_session_record(path, &resume) {
        return storage_error(error);
    }
    if let Err(error) = persist_record(path, &keypair, &record) {
        return storage_error(error);
    }
    let mut result = record.public_binding();
    result["bearerToken"] = json!(token);
    let mut response = Json(result).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

fn persist_record(
    path: &FsPath,
    keypair: &Keypair,
    record: &SessionCredential,
) -> Result<(), CliError> {
    let (signature, _) = keypair.sign_canonical(record)?;
    open_db(path)?.execute(&format!(
        "INSERT INTO {TABLE} (session_id, token_hash, record_json, signature) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(session_id) DO UPDATE SET token_hash=excluded.token_hash,
         record_json=excluded.record_json, signature=excluded.signature"
    ), params![record.session_id, record.token_hash, serde_json::to_string(record)?, signature.to_hex()])?;
    Ok(())
}

async fn revoke(
    State(state): State<RemoteAppState>,
    AxumPath(session_id): AxumPath<String>,
    request: Request,
) -> Response {
    if let Err(response) =
        remote_mcp_admin::validate_admin_request(request.headers(), state.admin_token.as_deref())
    {
        return response;
    }
    let (path, _) = match operator_runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let session = match resolve_session_entry(&state, &session_id).await {
        Some(RemoteSessionEntry::Active(session)) => Some(session),
        _ => None,
    };
    // Revoke returns only after any admitted request has released its stream.
    // Requests queued behind this lock reauthenticate before dispatch.
    let _request_lock = match session.as_ref() {
        Some(session) => Some(session.active_request_stream.lock().await),
        None => None,
    };
    let conn = match open_db(path) {
        Ok(conn) => conn,
        Err(error) => return storage_error(error),
    };
    match conn.execute(
        &format!("DELETE FROM {TABLE} WHERE session_id=?1"),
        params![session_id],
    ) {
        Ok(_) => Json(json!({"revoked": true, "sessionId": session_id})).into_response(),
        Err(error) => storage_error(error),
    }
}

fn load_record(
    path: &FsPath,
    keypair: &Keypair,
    token_hash: &str,
) -> Result<Option<SessionCredential>, CliError> {
    let stored: Option<(String, String, String)> = open_db(path)?
        .query_row(
            &format!("SELECT session_id, record_json, signature FROM {TABLE} WHERE token_hash=?1"),
            params![token_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((session_id, encoded, signature)) = stored else {
        return Ok(None);
    };
    let record: SessionCredential = serde_json::from_str(&encoded)?;
    let signature = Ed25519Signature::from_hex(&signature)?;
    if record.schema != SCHEMA
        || record.token_hash != token_hash
        || record.session_id != session_id
        || !keypair
            .public_key()
            .verify(&canonical_json_bytes(&record)?, &signature)
    {
        return Ok(None);
    }
    Ok(Some(record))
}

pub(super) async fn authenticate_request(
    state: &RemoteAppState,
    headers: &HeaderMap,
    method: &str,
    target: &str,
) -> Result<(SessionAuthContext, Option<SessionCredential>), Response> {
    let token = extract_bearer_token(headers, state.protected_resource_metadata.as_deref())?;
    if !token.starts_with(PREFIX) {
        return authenticate_session_request(
            headers,
            &state.auth_mode,
            state.protected_resource_metadata.as_deref(),
            method,
            target,
        )
        .await
        .map(|context| (context, None));
    }
    // GET subscriptions could expose unrelated upstream notifications. This
    // credential supports bounded POST responses and explicit session deletion.
    if !matches!(method, "POST" | "DELETE") || target != MCP_ENDPOINT_PATH {
        return Err(unavailable());
    }
    let session_id = match mcp_session_id_header(headers) {
        McpSessionIdHeader::Valid(id) => id,
        _ => return Err(unavailable()),
    };
    let (path, keypair) = operator_runtime(state)?;
    let record = load_record(path, &keypair, &sha256_hex(token.as_bytes()))
        .map_err(storage_error)?
        .ok_or_else(unavailable)?;
    let Some(RemoteSessionEntry::Active(session)) = resolve_session_entry(state, &session_id).await
    else {
        return Err(unavailable());
    };
    let now = unix_now();
    if record.session_id != session_id
        || record.subject_key != session.agent_id
        || record.server_id != state.factory.config.server_id
        || record.endpoint_path != target
        || record.capability_ids
            != session
                .capabilities
                .iter()
                .map(|cap| cap.id.clone())
                .collect::<Vec<_>>()
        || record.auth_mode_fingerprint != session.auth_mode_fingerprint
        || record.policy_fingerprint != session.policy_fingerprint
        || record.issued_at > now
        || record.expires_at <= now
        || headers.get(ORIGIN).and_then(|value| value.to_str().ok())
            != session.auth_context.origin.as_deref()
    {
        return Err(unavailable());
    }
    validate_session_lifecycle(&session)?;
    Ok((session.auth_context.clone(), Some(record)))
}

impl SessionCredential {
    fn public_binding(&self) -> Value {
        json!({"schema": SCHEMA, "sessionId": self.session_id, "subjectKey": self.subject_key,
            "capabilityIds": self.capability_ids, "serverId": self.server_id,
            "endpointPath": self.endpoint_path, "allowedTools": self.allowed_tools,
            "issuedAt": self.issued_at, "expiresAt": self.expires_at})
    }

    pub(super) fn validate_message(&self, message: &Value) -> Result<(), Response> {
        let method = message.get("method").and_then(Value::as_str);
        let request_shape = message.get("jsonrpc") == Some(&json!("2.0"))
            && if method == Some("notifications/cancelled") {
                message.get("id").is_none()
            } else {
                message
                    .get("id")
                    .is_some_and(|id| id.is_string() || id.is_i64() || id.is_u64())
            };
        if !request_shape {
            return Err(plain_http_error(
                StatusCode::BAD_REQUEST,
                "invalid restricted JSON-RPC request",
            ));
        }
        let allowed = match method {
            Some("tools/call") => message
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| self.allowed_tools.iter().any(|tool| tool == name)),
            Some(
                "tools/list"
                | "chio/execution-context"
                | "chio/acknowledge"
                | "ping"
                | "notifications/cancelled",
            ) => true,
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(plain_http_error(
                StatusCode::FORBIDDEN,
                "method or tool outside session credential authority",
            ))
        }
    }

    pub(super) fn restrict_response(&self, method: &str, message: &mut Value) {
        if method == "tools/list" {
            if let Some(tools) = message
                .pointer_mut("/result/tools")
                .and_then(Value::as_array_mut)
            {
                tools.retain(|tool| {
                    tool.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| {
                            self.allowed_tools.iter().any(|allowed| allowed == name)
                        })
                });
            }
        } else if method == "chio/execution-context" {
            if let Some(result) = message.get_mut("result").and_then(Value::as_object_mut) {
                result.insert("serverId".to_owned(), json!(self.server_id));
                result.insert("deliveryAcknowledgementVersion".to_owned(), json!("1"));
                result.insert("sessionCredential".to_owned(), self.public_binding());
            }
        }
    }
}

fn fence_error() -> Response {
    plain_http_error(
        StatusCode::CONFLICT,
        "session credential has a pending or uncertain call; operator reconciliation is required",
    )
}

fn decode_call(
    keypair: &Keypair,
    session_id: &str,
    request_id: &str,
    encoded: &str,
    signature: &str,
) -> Result<CredentialCall, Response> {
    let call: CredentialCall = serde_json::from_str(encoded).map_err(storage_error)?;
    let signature = Ed25519Signature::from_hex(signature).map_err(storage_error)?;
    if call.schema != "chio.mcp.session-credential-call.v1"
        || call.session_id != session_id
        || call.request_id != request_id
        || !keypair.public_key().verify(
            &canonical_json_bytes(&call).map_err(storage_error)?,
            &signature,
        )
    {
        return Err(fence_error());
    }
    Ok(call)
}

fn read_latch(
    conn: &rusqlite::Connection,
    keypair: &Keypair,
    session_id: &str,
) -> Result<Option<CredentialCall>, Response> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            &format!(
                "SELECT request_id,record_json,signature FROM {LATCH_TABLE} WHERE session_id=?1"
            ),
            params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage_error)?;
    row.map(|(request_id, encoded, signature)| {
        decode_call(keypair, session_id, &request_id, &encoded, &signature)
    })
    .transpose()
}

fn write_call(
    conn: &rusqlite::Connection,
    keypair: &Keypair,
    call: &CredentialCall,
) -> Result<(), Response> {
    let (signature, _) = keypair.sign_canonical(call).map_err(storage_error)?;
    let encoded = serde_json::to_string(call).map_err(storage_error)?;
    conn.execute(
        &format!(
            "INSERT INTO {CALL_TABLE} (session_id,request_id,record_json,signature)
        VALUES (?1,?2,?3,?4) ON CONFLICT(session_id,request_id) DO UPDATE SET
        record_json=excluded.record_json,signature=excluded.signature"
        ),
        params![
            call.session_id,
            call.request_id,
            encoded,
            signature.to_hex()
        ],
    )
    .map_err(storage_error)?;
    conn.execute(
        &format!(
            "INSERT INTO {LATCH_TABLE} (session_id,request_id,record_json,signature)
        VALUES (?1,?2,?3,?4) ON CONFLICT(session_id) DO UPDATE SET request_id=excluded.request_id,
        record_json=excluded.record_json,signature=excluded.signature"
        ),
        params![
            call.session_id,
            call.request_id,
            encoded,
            signature.to_hex()
        ],
    )
    .map_err(storage_error)?;
    Ok(())
}

pub(super) fn reserve_call(
    state: &RemoteAppState,
    credential: &SessionCredential,
    message: &Value,
) -> Result<CallReservation, Response> {
    let (path, keypair) = operator_runtime(state)?;
    reserve_at(path, &keypair, credential, message)
}

fn reserve_at(
    path: &FsPath,
    keypair: &Keypair,
    credential: &SessionCredential,
    message: &Value,
) -> Result<CallReservation, Response> {
    let request_id = message
        .pointer("/params/_meta/chioRequestId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 1024)
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::BAD_REQUEST,
                "restricted calls require a stable chioRequestId",
            )
        })?;
    let request_hash = sha256_hex(
        &canonical_json_bytes(&json!({"method":message["method"],"params":message["params"]}))
            .map_err(storage_error)?,
    );
    let mut conn = open_db(path).map_err(storage_error)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let row: Option<(String,String)> = tx.query_row(
        &format!("SELECT record_json,signature FROM {CALL_TABLE} WHERE session_id=?1 AND request_id=?2"),
        params![credential.session_id,request_id], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(storage_error)?;
    if let Some((encoded, signature)) = row {
        let call = decode_call(
            keypair,
            &credential.session_id,
            request_id,
            &encoded,
            &signature,
        )?;
        if !matches!(
            call.state.as_str(),
            "completed_unacknowledged" | "acknowledged" | "fenced"
        ) || call.request_hash != request_hash
            || call.subject_key != credential.subject_key
            || call.capability_ids != credential.capability_ids
            || call.server_id != credential.server_id
        {
            return Err(fence_error());
        }
        let mut response = call.response.ok_or_else(fence_error)?;
        response["id"] = message["id"].clone();
        return Ok(CallReservation::Replay(response));
    }
    // Knowing the kernel completed is distinct from the caller having received
    // its result. Even a new request ID remains fenced until explicit delivery
    // acknowledgement. Legacy completed records have no such proof and stop.
    if read_latch(&tx, keypair, &credential.session_id)?
        .is_some_and(|call| call.state != "acknowledged")
    {
        return Err(fence_error());
    }
    let call = CredentialCall {
        schema: "chio.mcp.session-credential-call.v1".to_owned(),
        session_id: credential.session_id.clone(),
        subject_key: credential.subject_key.clone(),
        capability_ids: credential.capability_ids.clone(),
        server_id: credential.server_id.clone(),
        request_id: request_id.to_owned(),
        request_hash,
        tool_name: message["params"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        parameter_hash: sha256_hex(
            &canonical_json_bytes(
                &message["params"]
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            )
            .map_err(storage_error)?,
        ),
        started_at: unix_now(),
        state: "pending".to_owned(),
        response: None,
        delivery_ack: None,
    };
    write_call(&tx, keypair, &call)?;
    tx.commit().map_err(storage_error)?;
    Ok(CallReservation::Pending(Box::new(call)))
}

fn verified_completed_response(keypair: &Keypair, call: &CredentialCall, message: &Value) -> bool {
    let evidence = &message["result"]["_meta"]["chioEvidence"];
    let Ok(receipt) = serde_json::from_value::<chio_core::receipt::body::ChioReceipt>(
        evidence["receipt"].clone(),
    ) else {
        return false;
    };
    if receipt.kernel_key != keypair.public_key()
        || !matches!(receipt.verify_signature(), Ok(true))
        || receipt.decision != Some(chio_core::receipt::decision::Decision::Allow)
        || receipt.tool_server != call.server_id
        || receipt.tool_name != call.tool_name
        || receipt.action.parameter_hash != call.parameter_hash
        || !call.capability_ids.contains(&receipt.capability_id)
    {
        return false;
    }
    let Some(metadata) = receipt.metadata.as_ref() else {
        return false;
    };
    let admission = &metadata["admission_operation"];
    if metadata["receipt_context"]["request_id"] != call.request_id
        || metadata["attribution"]["subject_key"] != call.subject_key
        || admission["schema"] != "chio.admission-receipt.v1"
        || admission["request_id"] != call.request_id
        || admission["projected_state"] != "completed"
        || admission["projected_dispatch_state"] != "terminal"
        || !admission["tool_outcome_id"].is_string()
        || evidence["outputKind"] != "value"
    {
        return false;
    }
    // A terminal tool result can report failure. Acknowledge its verified delivery
    // without converting isError into success or treating it as an unknown dispatch.
    canonical_json_bytes(&evidence["output"])
        .is_ok_and(|bytes| sha256_hex(&bytes) == receipt.content_hash)
}

pub(super) fn finish_call(
    state: &RemoteAppState,
    pending: &CredentialCall,
    message: &Value,
) -> Result<Value, Response> {
    let (path, keypair) = operator_runtime(state)?;
    finish_at(path, &keypair, pending, message)
}

fn finish_at(
    path: &FsPath,
    keypair: &Keypair,
    pending: &CredentialCall,
    message: &Value,
) -> Result<Value, Response> {
    let mut conn = open_db(path).map_err(storage_error)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let current = read_latch(&tx, keypair, &pending.session_id)?.ok_or_else(fence_error)?;
    if current.request_id != pending.request_id
        || current.request_hash != pending.request_hash
        || current.state != "pending"
    {
        return Err(fence_error());
    }
    let mut terminal = pending.clone();
    let mut response = message.clone();
    if verified_completed_response(keypair, pending, message) {
        let receipt = &message["result"]["_meta"]["chioEvidence"]["receipt"];
        // Bind the acknowledgement to the already verified receipt and raw result.
        let signed: chio_core::receipt::body::ChioReceipt =
            serde_json::from_value(receipt.clone()).map_err(storage_error)?;
        let delivery = DeliveryAcknowledgement {
            schema: DELIVERY_SCHEMA.to_owned(),
            request_id: pending.request_id.clone(),
            request_hash: pending.request_hash.clone(),
            receipt_id: signed.id,
            result_hash: signed.content_hash,
            acknowledgement: URL_SAFE_NO_PAD.encode(Keypair::generate().seed_bytes()),
        };
        response["result"]["_meta"]["chioDelivery"] =
            serde_json::to_value(&delivery).map_err(storage_error)?;
        terminal.delivery_ack = Some(delivery);
        terminal.state = "completed_unacknowledged".to_owned();
    } else {
        terminal.state = "fenced".to_owned();
    }
    terminal.response = Some(response.clone());
    write_call(&tx, keypair, &terminal)?;
    tx.commit().map_err(storage_error)?;
    Ok(response)
}

pub(super) fn acknowledge_call(
    state: &RemoteAppState,
    credential: &SessionCredential,
    message: &Value,
) -> Result<Value, Response> {
    let (path, keypair) = operator_runtime(state)?;
    let acknowledgement: DeliveryAcknowledgement =
        serde_json::from_value(message["params"].clone()).map_err(|_| {
            plain_http_error(StatusCode::BAD_REQUEST, "invalid delivery acknowledgement")
        })?;
    acknowledge_at(path, &keypair, credential, &acknowledgement)?;
    Ok(json!({"jsonrpc":"2.0","id":message["id"],"result":{
        "schema":DELIVERY_SCHEMA,"requestId":acknowledgement.request_id,
        "receiptId":acknowledgement.receipt_id,"acknowledged":true}}))
}

fn acknowledge_at(
    path: &FsPath,
    keypair: &Keypair,
    credential: &SessionCredential,
    acknowledgement: &DeliveryAcknowledgement,
) -> Result<(), Response> {
    let mut conn = open_db(path).map_err(storage_error)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let row: Option<(String,String)> = tx.query_row(
        &format!("SELECT record_json,signature FROM {CALL_TABLE} WHERE session_id=?1 AND request_id=?2"),
        params![credential.session_id,acknowledgement.request_id], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(storage_error)?;
    let (encoded, signature) = row.ok_or_else(fence_error)?;
    let mut call = decode_call(
        keypair,
        &credential.session_id,
        &acknowledgement.request_id,
        &encoded,
        &signature,
    )?;
    let expected = call.delivery_ack.as_ref().ok_or_else(fence_error)?;
    if acknowledgement.schema != DELIVERY_SCHEMA
        || acknowledgement.request_hash != call.request_hash
        || acknowledgement.receipt_id != expected.receipt_id
        || acknowledgement.result_hash != expected.result_hash
        || !bool::from(
            acknowledgement
                .acknowledgement
                .as_bytes()
                .ct_eq(expected.acknowledgement.as_bytes()),
        )
        || call.subject_key != credential.subject_key
        || call.capability_ids != credential.capability_ids
        || call.server_id != credential.server_id
    {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "delivery acknowledgement does not match the original outcome",
        ));
    }
    if call.state == "acknowledged" {
        return Ok(());
    }
    if call.state != "completed_unacknowledged" {
        return Err(fence_error());
    }
    // An acknowledgement for an older request must never clear a newer latch.
    let active = read_latch(&tx, keypair, &credential.session_id)?.ok_or_else(fence_error)?;
    if active.request_id != call.request_id
        || active.request_hash != call.request_hash
        || active.state != "completed_unacknowledged"
    {
        return Err(fence_error());
    }
    call.state = "acknowledged".to_owned();
    write_call(&tx, keypair, &call)?;
    tx.commit().map_err(storage_error)?;
    Ok(())
}

async fn status(
    State(state): State<RemoteAppState>,
    AxumPath(session_id): AxumPath<String>,
    request: Request,
) -> Response {
    if let Err(response) =
        remote_mcp_admin::validate_admin_request(request.headers(), state.admin_token.as_deref())
    {
        return response;
    }
    let (path, keypair) = match operator_runtime(&state) {
        Ok(runtime) => runtime,
        Err(response) => return response,
    };
    let conn = match open_db(path) {
        Ok(conn) => conn,
        Err(error) => return storage_error(error),
    };
    match read_latch(&conn,&keypair,&session_id) {
        Ok(call) => Json(json!({"sessionId":session_id,"call":call,"recovery":"operator-inspect-and-revoke; no automatic unfencing"})).into_response(),
        Err(response)=>response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> SessionCredential {
        SessionCredential {
            schema: SCHEMA.to_owned(),
            token_hash: sha256_hex(b"test bearer"),
            session_id: "retained-session".to_owned(),
            subject_key: "subject".to_owned(),
            capability_ids: vec!["capability".to_owned()],
            server_id: "fs".to_owned(),
            endpoint_path: "/mcp".to_owned(),
            auth_mode_fingerprint: "auth".to_owned(),
            policy_fingerprint: "policy".to_owned(),
            allowed_tools: vec!["write_file".to_owned()],
            issued_at: 100,
            expires_at: 200,
        }
    }

    fn completed_response(
        keypair: &Keypair,
        call: &CredentialCall,
        arguments: Value,
        is_error: bool,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
        use chio_core::receipt::decision::{Decision, ToolCallAction};
        use chio_core::receipt::kinds::{
            BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
        };
        let output = json!({"content":[{"type":"text","text":"original completed result"}],"isError":is_error});
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "delivery-ack-test".to_owned(),
                timestamp: unix_now(),
                capability_id: call.capability_ids[0].clone(),
                tool_server: call.server_id.clone(),
                tool_name: call.tool_name.clone(),
                action: ToolCallAction::from_parameters(arguments)?,
                decision: Some(Decision::Allow),
                receipt_kind: ReceiptKind::MediatedDecision,
                boundary_class: BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: sha256_hex(&canonical_json_bytes(&output)?),
                policy_hash: "policy".to_owned(),
                evidence: Vec::new(),
                metadata: Some(json!({
                    "receipt_context":{"request_id":call.request_id}, "attribution":{"subject_key":call.subject_key},
                    "admission_operation":{"schema":"chio.admission-receipt.v1","request_id":call.request_id,
                        "projected_state":"completed","projected_dispatch_state":"terminal","tool_outcome_id":"outcome-1"}
                })),
                trust_level: TrustLevel::Mediated,
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            keypair,
        )?;
        Ok(
            json!({"jsonrpc":"2.0","id":1,"result":{"_meta":{"chioEvidence":{
            "receipt":receipt,"outputKind":"value","output":output}},"isError":is_error}}),
        )
    }

    #[test]
    fn caller_acknowledgement_is_required_after_verified_kernel_completion(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-delivery-{}.sqlite",
            Keypair::generate().public_key().to_hex()
        ));
        let keypair = Keypair::generate();
        let mut credential = record();
        let message = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"write_file","arguments":{"path":"/workspace/one"},"_meta":{"chioRequestId":"logical-one"}}});
        let Ok(CallReservation::Pending(pending)) =
            reserve_at(&path, &keypair, &credential, &message)
        else {
            return Err("reserve".into());
        };
        let completed = completed_response(
            &keypair,
            &pending,
            message["params"]["arguments"].clone(),
            false,
        )?;
        assert!(verified_completed_response(&keypair, &pending, &completed));
        let delivered = finish_at(&path, &keypair, &pending, &completed).map_err(|_| "complete")?;
        let acknowledgement: DeliveryAcknowledgement =
            serde_json::from_value(delivered["result"]["_meta"]["chioDelivery"].clone())?;
        assert_eq!(acknowledgement.acknowledgement.len(), 43);
        let mut next = message.clone();
        next["params"]["_meta"]["chioRequestId"] = json!("logical-two");
        assert!(reserve_at(&path, &keypair, &credential, &next).is_err());
        credential.token_hash = "rotated".to_owned();
        assert!(reserve_at(&path, &keypair, &credential, &next).is_err());
        let Ok(CallReservation::Replay(replayed)) =
            reserve_at(&path, &keypair, &credential, &message)
        else {
            return Err("replay".into());
        };
        assert_eq!(delivered, replayed);
        for field in [
            "requestId",
            "requestHash",
            "receiptId",
            "resultHash",
            "acknowledgement",
        ] {
            let mut forged = serde_json::to_value(&acknowledgement)?;
            forged[field] = json!("wrong");
            let forged = serde_json::from_value(forged)?;
            assert!(acknowledge_at(&path, &keypair, &credential, &forged).is_err());
            assert!(reserve_at(&path, &keypair, &credential, &next).is_err());
        }
        acknowledge_at(&path, &keypair, &credential, &acknowledgement)
            .map_err(|_| "acknowledge")?;
        acknowledge_at(&path, &keypair, &credential, &acknowledgement)
            .map_err(|_| "idempotent acknowledge")?;
        assert!(matches!(
            reserve_at(&path, &keypair, &credential, &next),
            Ok(CallReservation::Pending(_))
        ));
        acknowledge_at(&path, &keypair, &credential, &acknowledgement)
            .map_err(|_| "old acknowledge")?;
        let mut third = next.clone();
        third["params"]["_meta"]["chioRequestId"] = json!("logical-three");
        assert!(reserve_at(&path, &keypair, &credential, &third).is_err());
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn completed_tool_error_can_be_acknowledged_without_claiming_success(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-tool-error-{}.sqlite",
            Keypair::generate().public_key().to_hex()
        ));
        let keypair = Keypair::generate();
        let credential = record();
        let message = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"write_file","arguments":{"path":"/outside-resource"},"_meta":{"chioRequestId":"tool-error"}}});
        let Ok(CallReservation::Pending(pending)) =
            reserve_at(&path, &keypair, &credential, &message)
        else {
            return Err("reserve tool error".into());
        };
        let response = completed_response(
            &keypair,
            &pending,
            message["params"]["arguments"].clone(),
            true,
        )?;
        assert!(verified_completed_response(&keypair, &pending, &response));
        let mut forged = response.clone();
        forged["result"]["_meta"]["chioEvidence"]["output"]["isError"] = json!(false);
        assert!(!verified_completed_response(&keypair, &pending, &forged));
        assert!(!verified_completed_response(
            &keypair,
            &pending,
            &json!({"error":{"code":-32603}})
        ));
        let delivered = finish_at(&path, &keypair, &pending, &response).map_err(|_| "finish")?;
        assert_eq!(
            delivered["result"]["_meta"]["chioEvidence"]["output"]["isError"],
            true
        );
        let mut next = message.clone();
        next["params"]["_meta"]["chioRequestId"] = json!("after-error");
        assert!(reserve_at(&path, &keypair, &credential, &next).is_err());
        let acknowledgement =
            serde_json::from_value(delivered["result"]["_meta"]["chioDelivery"].clone())?;
        acknowledge_at(&path, &keypair, &credential, &acknowledgement)
            .map_err(|_| "acknowledge")?;
        assert!(
            matches!(reserve_at(&path, &keypair, &credential, &message), Ok(CallReservation::Replay(value)) if value == delivered)
        );
        assert!(matches!(
            reserve_at(&path, &keypair, &credential, &next),
            Ok(CallReservation::Pending(_))
        ));
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn pending_owner_call_survives_reopen_and_token_rotation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-call-{}.sqlite",
            Keypair::generate().public_key().to_hex()
        ));
        let keypair = Keypair::generate();
        let mut credential = record();
        let message = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"write_file","arguments":{"path":"/workspace/one"},"_meta":{"chioRequestId":"logical-one"}}});
        let Ok(CallReservation::Pending(pending)) =
            reserve_at(&path, &keypair, &credential, &message)
        else {
            return Err("first call was not durably reserved".into());
        };
        assert!(reserve_at(&path, &keypair, &credential, &message).is_err());
        credential.token_hash = "rotated-token".to_owned();
        let mut another = message.clone();
        another["params"]["_meta"]["chioRequestId"] = json!("logical-two");
        assert!(reserve_at(&path, &keypair, &credential, &another).is_err());
        let mut forged = pending;
        forged.state = "completed".to_owned();
        open_db(&path)?.execute(
            &format!("UPDATE {LATCH_TABLE} SET record_json=?1"),
            params![serde_json::to_string(&forged)?],
        )?;
        assert!(reserve_at(&path, &keypair, &credential, &another).is_err());
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn completed_cache_replays_exact_request_and_rejects_conflicts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-replay-{}.sqlite",
            Keypair::generate().public_key().to_hex()
        ));
        let keypair = Keypair::generate();
        let credential = record();
        let message = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"write_file","arguments":{"path":"/workspace/one"},"_meta":{"chioRequestId":"logical-one"}}});
        let Ok(CallReservation::Pending(mut pending)) =
            reserve_at(&path, &keypair, &credential, &message)
        else {
            return Err("first call was not reserved".into());
        };
        pending.state = "completed_unacknowledged".to_owned();
        pending.response = Some(json!({"jsonrpc":"2.0","id":1,"result":{"ownerResult":true}}));
        write_call(&open_db(&path)?, &keypair, &pending).map_err(|_| "write completed record")?;
        let mut retry = message.clone();
        retry["id"] = json!(99);
        let Ok(CallReservation::Replay(response)) =
            reserve_at(&path, &keypair, &credential, &retry)
        else {
            return Err("exact completed request was not replayed".into());
        };
        assert_eq!(response["id"], 99);
        assert_eq!(response["result"]["ownerResult"], true);
        retry["params"]["arguments"]["path"] = json!("/workspace/two");
        assert!(reserve_at(&path, &keypair, &credential, &retry).is_err());
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn credential_storage_rejects_substitution_and_survives_reopen(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-credential-{}.sqlite",
            Keypair::generate().public_key().to_hex()
        ));
        let keypair = Keypair::generate();
        let record = record();
        persist_record(&path, &keypair, &record)?;
        assert!(load_record(&path, &keypair, &record.token_hash)?.is_some());
        assert!(load_record(&path, &Keypair::generate(), &record.token_hash)?.is_none());
        assert!(load_record(&path, &keypair, "wrong-token")?.is_none());
        let mut substituted = record.clone();
        substituted.allowed_tools.push("move_file".to_owned());
        open_db(&path)?.execute(
            &format!("UPDATE {TABLE} SET record_json=?1"),
            params![serde_json::to_string(&substituted)?],
        )?;
        assert!(load_record(&path, &keypair, &record.token_hash)?.is_none());
        persist_record(&path, &keypair, &record)?;
        open_db(&path)?.execute(&format!("DELETE FROM {TABLE}"), [])?;
        assert!(load_record(&path, &keypair, &record.token_hash)?.is_none());
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn credential_route_allowlist_excludes_issuance_and_hidden_tools() {
        let credential = record();
        assert!(credential
            .validate_message(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file"}}))
            .is_ok());
        for message in [
            json!({"method":"initialize"}),
            json!({"method":"resources/read"}),
            json!({"method":"prompts/get"}),
            json!({"method":"notifications/roots/list_changed"}),
            json!({"method":"tools/call","params":{"name":"move_file"}}),
            json!({"method":"tools/call","params":{}}),
            json!({"result":{}}),
            json!([]),
        ] {
            assert!(credential.validate_message(&message).is_err());
        }
    }

    #[test]
    fn credential_response_filters_inventory_and_exposes_bound_context() {
        let credential = record();
        let mut result = json!({"result":{"tools":[{"name":"write_file"},{"name":"move_file"}]}});
        credential.restrict_response("tools/list", &mut result);
        assert_eq!(result["result"]["tools"], json!([{"name":"write_file"}]));
        credential.restrict_response("chio/execution-context", &mut result);
        assert_eq!(result["result"]["serverId"], "fs");
        assert_eq!(
            result["result"]["sessionCredential"]["allowedTools"],
            json!(["write_file"])
        );
        assert!(result["result"]["sessionCredential"]
            .get("tokenHash")
            .is_none());
        assert!(result["result"]["sessionCredential"]
            .get("bearerToken")
            .is_none());
    }
}
