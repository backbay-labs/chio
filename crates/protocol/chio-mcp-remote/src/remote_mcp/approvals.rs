//! Operator-owned approval records. This module never dispatches protected work.
//! Returned artifacts are admitted only by the ordinary kernel tools/call path.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, GovernedTransactionIntentBody,
};
use chio_core::Hash;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubmitRequest {
    session_id: String,
    capability_id: String,
    request_id: String,
    tool_name: String,
    arguments: Value,
    purpose: String,
    #[serde(default = "default_ttl")]
    ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionRequest {
    decision: GovernedApprovalDecision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApprovalRecord {
    schema: String,
    id: String,
    session_id: String,
    capability_id: String,
    subject: PublicKey,
    policy_fingerprint: String,
    request_id: String,
    arguments: Value,
    intent: GovernedTransactionIntent,
    created_at: u64,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<GovernedApprovalToken>,
}

#[derive(Serialize, Deserialize)]
struct SignedRecord {
    record: ApprovalRecord,
    signature: Ed25519Signature,
}

fn failure(status: StatusCode, message: impl ToString) -> Response {
    plain_http_error(status, &message.to_string())
}

fn internal(error: impl ToString) -> Response {
    failure(StatusCode::INTERNAL_SERVER_ERROR, error)
}

fn storage(state: &RemoteAppState, headers: &HeaderMap) -> Result<(Connection, Keypair), Response> {
    super::remote_mcp_admin::validate_admin_request(headers, state.admin_token.as_deref())?;
    // The ordinary admin surface historically defaults to the agent credential.
    // Approval issuance must never inherit that compatibility behavior.
    if state.factory.config.auth_token.as_deref() == state.admin_token.as_deref() {
        return Err(failure(
            StatusCode::CONFLICT,
            "approvals require a distinct operator credential",
        ));
    }
    let runtime = state.factory.durable_admission.as_ref().ok_or_else(|| {
        failure(
            StatusCode::CONFLICT,
            "approvals require durable kernel admission",
        )
    })?;
    let path = state
        .factory
        .config
        .session_db_path
        .as_deref()
        .ok_or_else(|| {
            failure(
                StatusCode::CONFLICT,
                "approvals require durable session state",
            )
        })?;
    let connection = open_session_state_db(path).map_err(internal)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(internal)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(internal)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS remote_operator_approvals (
            id TEXT PRIMARY KEY NOT NULL,
            session_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            signed_record TEXT NOT NULL,
            UNIQUE(session_id, request_id)
        );",
        )
        .map_err(internal)?;
    Ok((connection, runtime.kernel_keypair()))
}

fn serialize_record(record: ApprovalRecord, signer: &Keypair) -> Result<String, Response> {
    let (signature, _) = signer.sign_canonical(&record).map_err(internal)?;
    serde_json::to_string(&SignedRecord { record, signature }).map_err(internal)
}

fn load_record(
    connection: &Connection,
    id: &str,
    signer: &Keypair,
) -> Result<ApprovalRecord, Response> {
    let serialized: String = connection
        .query_row(
            "SELECT signed_record FROM remote_operator_approvals WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "unknown approval"))?;
    let signed: SignedRecord = serde_json::from_str(&serialized).map_err(internal)?;
    if signed.record.id != id
        || !signer
            .public_key()
            .verify_canonical_strict(&signed.record, &signed.signature)
            .map_err(internal)?
    {
        return Err(failure(
            StatusCode::CONFLICT,
            "approval record integrity check failed",
        ));
    }
    Ok(signed.record)
}

fn projection(record: &ApprovalRecord) -> Value {
    let status = match record.decision.as_ref().map(|token| token.decision) {
        Some(GovernedApprovalDecision::Approved) => "approved",
        Some(GovernedApprovalDecision::Denied) => "denied",
        None => "pending",
    };
    let mut result =
        json!({"record": record, "status": status, "dispatchPerformedByThisEndpoint": false});
    if let Some(token) = &record.decision {
        // A denied token is useful evidence and still fails kernel admission.
        result["toolCallParams"] = json!({
            "name": record.intent.tool_name,
            "arguments": record.arguments,
            "_meta": {
                "chioRequestId": record.request_id,
                "chioGovernedIntent": record.intent,
                "chioApprovalToken": token,
            },
        });
    }
    result
}

pub(super) async fn submit(
    State(state): State<RemoteAppState>,
    headers: HeaderMap,
    Json(request): Json<SubmitRequest>,
) -> Response {
    if let Err(response) =
        super::remote_mcp_admin::validate_admin_request(&headers, state.admin_token.as_deref())
    {
        return response;
    }
    if request.ttl_seconds == 0
        || request.ttl_seconds > 3600
        || !request.arguments.is_object()
        || request.request_id.is_empty()
        || request.request_id.len() > 256
        || request.tool_name.is_empty()
        || request.tool_name.len() > 256
        || request.purpose.is_empty()
        || request.purpose.len() > 4096
    {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid approval request, arguments, or lifetime",
        );
    }
    let Some(RemoteSessionEntry::Active(session)) =
        resolve_session_entry(&state, &request.session_id).await
    else {
        return failure(StatusCode::NOT_FOUND, "active MCP session required");
    };
    if let Err(response) = validate_session_lifecycle(&session) {
        return response;
    }
    let Some(capability) = session
        .issued_capabilities
        .iter()
        .find(|cap| cap.id == request.capability_id)
    else {
        return failure(
            StatusCode::BAD_REQUEST,
            "capability does not belong to session",
        );
    };
    let now = session_now_millis() / 1000;
    if capability.expires_at <= now {
        return failure(StatusCode::CONFLICT, "capability expired");
    }
    let (connection, signer) = match storage(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let identity = json!([request.session_id, request.request_id]);
    let id = match canonical_json_bytes(&identity) {
        Ok(bytes) => format!("approval-{}", sha256_hex(&bytes)),
        Err(error) => return internal(error),
    };
    let parameters_hash = match canonical_json_bytes(&request.arguments) {
        Ok(bytes) => Hash::from_bytes(Sha256::digest(&bytes).into()),
        Err(error) => return internal(error),
    };
    let intent = GovernedTransactionIntent {
        id: id.clone(),
        server_id: state.factory.config.server_id.clone(),
        tool_name: request.tool_name,
        purpose: request.purpose,
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(
            json!({"mcpSessionId": request.session_id, "capabilityId": request.capability_id,
            "policyFingerprint": session.policy_fingerprint}),
        ),
        body: GovernedTransactionIntentBody::BoundToolInvocation {
            capability_id: capability.id.clone(),
            parameters_hash,
        },
    };
    let record = ApprovalRecord {
        schema: "chio.mcp.operator-approval.v1".into(),
        id: id.clone(),
        session_id: request.session_id,
        capability_id: request.capability_id,
        subject: capability.subject.clone(),
        policy_fingerprint: session.policy_fingerprint.clone(),
        request_id: request.request_id,
        arguments: request.arguments,
        intent,
        created_at: now,
        expires_at: (now + request.ttl_seconds).min(capability.expires_at),
        decision: None,
    };
    let serialized = match serialize_record(record.clone(), &signer) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match connection.execute("INSERT OR IGNORE INTO remote_operator_approvals (id, session_id, request_id, signed_record) VALUES (?1, ?2, ?3, ?4)",
        params![id, record.session_id, record.request_id, serialized]) {
        Ok(1) => (StatusCode::CREATED, Json(projection(&record))).into_response(),
        Ok(_) => failure(StatusCode::CONFLICT, "session request already has an approval record; retrieve it instead"),
        Err(error) => internal(error),
    }
}

pub(super) async fn get_record(
    State(state): State<RemoteAppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let (connection, signer) = match storage(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match load_record(&connection, &id, &signer) {
        Ok(record) => Json(projection(&record)).into_response(),
        Err(response) => response,
    }
}

pub(super) async fn decide(
    State(state): State<RemoteAppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<DecisionRequest>,
) -> Response {
    let (mut connection, signer) = match storage(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(value) => value,
        Err(error) => return internal(error),
    };
    let mut record = match load_record(&transaction, &id, &signer) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(existing) = &record.decision {
        return if existing.decision == request.decision {
            Json(projection(&record)).into_response()
        } else {
            failure(StatusCode::CONFLICT, "approval decision is terminal")
        };
    }
    let now = session_now_millis() / 1000;
    if now >= record.expires_at {
        return failure(StatusCode::CONFLICT, "approval expired; no artifact issued");
    }
    let intent_hash = match record.intent.binding_hash() {
        Ok(value) => value,
        Err(error) => return internal(error),
    };
    let token = match GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("{}-decision", record.id),
            approver: signer.public_key(),
            subject: record.subject.clone(),
            governed_intent_hash: intent_hash,
            request_id: record.request_id.clone(),
            threshold_proposal_hash: None,
            issued_at: now,
            expires_at: record.expires_at,
            decision: request.decision,
        },
        &signer,
    ) {
        Ok(value) => value,
        Err(error) => return internal(error),
    };
    record.decision = Some(token);
    let serialized = match serialize_record(record.clone(), &signer) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(error) = transaction.execute(
        "UPDATE remote_operator_approvals SET signed_record = ?1 WHERE id = ?2",
        params![serialized, id],
    ) {
        return internal(error);
    }
    if let Err(error) = transaction.commit() {
        return internal(error);
    }
    Json(projection(&record)).into_response()
}
