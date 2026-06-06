#[derive(Debug, Default, Deserialize)]
struct AdminToolReceiptQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    tool_server: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}
#[derive(Debug, Default, Deserialize)]
struct AdminChildReceiptQuery {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    parent_request_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    operation_kind: Option<String>,
    #[serde(default)]
    terminal_state: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminRevocationQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminBudgetQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AdminRevokeCapabilityRequest {
    capability_id: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_details: Option<String>,
    #[serde(default)]
    chio_transaction_context: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    chio_sender_dpop_public_key: Option<String>,
    #[serde(default)]
    chio_sender_mtls_thumbprint_sha256: Option<String>,
    #[serde(default)]
    chio_sender_attestation_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationApprovalForm {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_details: Option<String>,
    #[serde(default)]
    chio_transaction_context: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    chio_sender_dpop_public_key: Option<String>,
    #[serde(default)]
    chio_sender_mtls_thumbprint_sha256: Option<String>,
    #[serde(default)]
    chio_sender_attestation_sha256: Option<String>,
    decision: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequestForm {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
}
