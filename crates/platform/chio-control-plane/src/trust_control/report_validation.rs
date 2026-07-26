use super::cluster::cluster_authority_lease_view;
use super::*;

pub(crate) fn budget_visibility_matches(
    allowed: bool,
    invocation_count: Option<u32>,
    max_invocations: Option<u32>,
) -> bool {
    match (allowed, invocation_count, max_invocations) {
        (true, Some(_), _) => true,
        (true, None, _) => false,
        (false, Some(count), Some(max)) => count >= max,
        (false, Some(_), None) => true,
        (false, None, Some(0)) => true,
        (false, None, Some(_)) => false,
        (false, None, None) => false,
    }
}

pub(crate) fn normalize_cluster_url(value: &str) -> Result<String, CliError> {
    let normalized = value.trim().trim_end_matches('/');
    if normalized.is_empty() {
        return Err(CliError::cli_other_error(
            "cluster URL must not be empty".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

pub(crate) fn normalize_cluster_config_url(
    value: &str,
    allow_local: bool,
) -> Result<String, CliError> {
    let normalized = normalize_cluster_url(value)?;
    let parsed = Url::parse(&normalized).map_err(|error| {
        CliError::cli_other_error(format!("cluster URL must be valid: {error}"))
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(CliError::cli_other_error(format!(
                "cluster URL scheme `{scheme}` is not allowed"
            )));
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain username or password material".to_string(),
        ));
    }
    if parsed.query().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain a query string".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(CliError::cli_other_error(
            "cluster URL must not contain a fragment".to_string(),
        ));
    }
    if allow_local {
        return Ok(normalized);
    }
    validate_cluster_url_host(&parsed)?;
    Ok(normalized)
}

fn validate_cluster_url_host(parsed: &Url) -> Result<(), CliError> {
    match parsed.host() {
        Some(Host::Ipv4(address)) => {
            if chio_external_guards::denied_external_guard_ip(IpAddr::V4(address)) {
                return Err(CliError::cli_other_error(format!(
                    "cluster URL must not target disallowed address `{address}` without --allow-local-peer-urls"
                )));
            }
        }
        Some(Host::Ipv6(address)) => {
            if chio_external_guards::denied_external_guard_ip(IpAddr::V6(address)) {
                return Err(CliError::cli_other_error(format!(
                    "cluster URL must not target disallowed address `{address}` without --allow-local-peer-urls"
                )));
            }
        }
        Some(Host::Domain(host)) => {
            let lower = host.to_ascii_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") {
                return Err(CliError::cli_other_error(
                    "cluster URL must not target localhost without --allow-local-peer-urls"
                        .to_string(),
                ));
            }
            let port = parsed.port_or_known_default().ok_or_else(|| {
                CliError::cli_other_error("cluster URL must include a resolvable port".to_string())
            })?;
            let addrs = (host, port).to_socket_addrs().map_err(|error| {
                CliError::cli_other_error(format!(
                    "cluster URL host `{host}` could not be resolved: {error}"
                ))
            })?;
            for addr in addrs {
                if chio_external_guards::denied_external_guard_ip(addr.ip()) {
                    return Err(CliError::cli_other_error(format!(
                        "cluster URL host `{host}` resolved to disallowed address `{}` without --allow-local-peer-urls",
                        addr.ip()
                    )));
                }
            }
        }
        None => {
            return Err(CliError::cli_other_error(
                "cluster URL must include a host".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn bearer_token_from_headers(headers: &HeaderMap) -> Result<String, Response> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let provided = header.strip_prefix("Bearer ").unwrap_or_default();
    if !provided.is_empty() {
        return Ok(provided.to_string());
    }
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid issuance bearer token",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"chio-passport-issuance\""),
    );
    Err(response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClusterPeerAuthContext {
    pub(crate) node_id: String,
    pub(crate) issued_at: i64,
    pub(crate) term: Option<u64>,
}

static CLUSTER_PEER_AUTH_FAILURES: LazyLock<Mutex<HashMap<String, Vec<u64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_cluster_peer_auth_failures(failures: &mut Vec<u64>, now: u64) {
    let cutoff = now.saturating_sub(CLUSTER_AUTH_FAILURE_WINDOW_SECS);
    failures.retain(|recorded_at| *recorded_at >= cutoff);
}

fn cluster_peer_auth_is_rate_limited(node_id: &str, now: u64) -> bool {
    let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() else {
        return false;
    };
    let Some(history) = failures.get_mut(node_id) else {
        return false;
    };
    prune_cluster_peer_auth_failures(history, now);
    if history.is_empty() {
        failures.remove(node_id);
        return false;
    }
    history.len() >= CLUSTER_AUTH_FAILURE_BURST
}

fn record_cluster_peer_auth_failure(node_id: &str) {
    let now = unix_timestamp_now();
    let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() else {
        return;
    };
    let history = failures.entry(node_id.to_string()).or_default();
    prune_cluster_peer_auth_failures(history, now);
    history.push(now);
}

pub(crate) fn clear_cluster_peer_auth_failures(node_id: &str) {
    if let Ok(mut failures) = CLUSTER_PEER_AUTH_FAILURES.lock() {
        failures.remove(node_id);
    }
}

pub(crate) fn cluster_peer_auth_unverified_failure_key(node_id: &str, endpoint: &str) -> String {
    let payload = format!("{node_id}\0{endpoint}");
    format!("unverified:{}", sha256_hex(payload.as_bytes()))
}

pub(crate) fn cluster_peer_auth_signature(
    service_token: &str,
    node_id: &str,
    endpoint: &str,
    issued_at: i64,
    term: Option<u64>,
) -> Result<String, CliError> {
    let payload = canonical_json_bytes(&json!({
        "scheme": CLUSTER_AUTH_SCHEME,
        "serviceToken": service_token,
        "nodeId": node_id,
        "endpoint": endpoint,
        "issuedAt": issued_at,
        "term": term,
    }))
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to encode cluster peer auth payload: {error}"
        ))
    })?;
    Ok(sha256_hex(&payload))
}

pub(crate) fn validate_cluster_peer_auth(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
    endpoint: &str,
) -> Result<ClusterPeerAuthContext, Response> {
    let node_id = headers
        .get(CLUSTER_NODE_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| normalize_cluster_url(value).ok())
        .ok_or_else(cluster_peer_auth_error)?;
    let issued_at = headers
        .get(CLUSTER_AUTH_ISSUED_AT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(cluster_peer_auth_error)?;
    let signature = headers
        .get(CLUSTER_AUTH_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(cluster_peer_auth_error)?;
    let term = headers
        .get(CLUSTER_AUTH_TERM_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                plain_http_error(StatusCode::UNAUTHORIZED, "invalid cluster peer term header")
            })
        })
        .transpose()?;
    let unverified_failure_key = cluster_peer_auth_unverified_failure_key(&node_id, endpoint);
    let allowlisted = config
        .peer_urls
        .iter()
        .filter_map(|peer_url| normalize_cluster_url(peer_url).ok())
        .any(|peer_url| peer_url == node_id);
    if !allowlisted {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "cluster peer is not in the configured allowlist",
        ));
    }
    let now = unix_timestamp_now() as i64;
    let expected =
        cluster_peer_auth_signature(&config.service_token, &node_id, endpoint, issued_at, term)
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
    if !bool::from(signature.as_bytes().ct_eq(expected.as_bytes())) {
        if cluster_peer_auth_is_rate_limited(&unverified_failure_key, now as u64) {
            let mut response = plain_http_error(
                StatusCode::TOO_MANY_REQUESTS,
                "cluster peer authentication temporarily rate limited after repeated invalid signatures",
            );
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("60"),
            );
            return Err(response);
        }
        record_cluster_peer_auth_failure(&unverified_failure_key);
        return Err(cluster_peer_auth_error());
    }
    if cluster_peer_auth_is_rate_limited(&node_id, now as u64) {
        let mut response = plain_http_error(
            StatusCode::TOO_MANY_REQUESTS,
            "cluster peer authentication temporarily rate limited after repeated verified failures",
        );
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_static("60"),
        );
        return Err(response);
    }
    if issued_at > now.saturating_add(CLUSTER_AUTH_MAX_SKEW_SECS) {
        record_cluster_peer_auth_failure(&node_id);
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer auth timestamp is in the future",
        ));
    }
    if issued_at < now.saturating_sub(CLUSTER_AUTH_MAX_SKEW_SECS) {
        record_cluster_peer_auth_failure(&node_id);
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "cluster peer auth timestamp expired outside the allowed skew window",
        ));
    }
    clear_cluster_peer_auth_failures(&node_id);
    Ok(ClusterPeerAuthContext {
        node_id,
        issued_at,
        term,
    })
}

fn cluster_peer_auth_error() -> Response {
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid cluster peer authentication",
    );
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(CLUSTER_AUTH_SCHEME),
    );
    response
}

pub(crate) fn validate_authority_mutation_auth(
    headers: &HeaderMap,
    state: &TrustServiceState,
    endpoint: &str,
) -> Result<Option<ClusterPeerAuthContext>, Response> {
    let has_cluster_peer_headers = headers.contains_key(CLUSTER_NODE_ID_HEADER)
        || headers.contains_key(CLUSTER_AUTH_ISSUED_AT_HEADER)
        || headers.contains_key(CLUSTER_AUTH_SIGNATURE_HEADER)
        || headers.contains_key(CLUSTER_AUTH_TERM_HEADER);
    if has_cluster_peer_headers {
        let peer = validate_cluster_peer_auth(headers, &state.config, endpoint)?;
        let Some(term) = peer.term else {
            return Err(plain_http_error(
                StatusCode::UNAUTHORIZED,
                "cluster authority mutation is missing the forwarded term",
            ));
        };
        let Some(authority_lease) = cluster_authority_lease_view(state) else {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster authority lease is unavailable for authority mutation",
            ));
        };
        if !authority_lease.lease_valid {
            return Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "cluster authority lease expired before authority mutation",
            ));
        }
        if term != authority_lease.term {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "cluster authority mutation term does not match the current lease",
            ));
        }
        return Ok(Some(peer));
    }
    validate_service_auth(headers, &state.config.service_token)?;
    Ok(None)
}

pub(crate) fn enforce_authority_mutation_fence(
    state: &TrustServiceState,
) -> Result<Option<ClusterAuthorityLeaseView>, Response> {
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Ok(None);
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority mutation",
        ));
    }
    if let Some(path) = state.config.authority_db_path.as_deref() {
        SqliteCapabilityAuthority::open(path)
            .and_then(|authority| {
                authority.enforce_cluster_fence(&authority_lease.leader_url, authority_lease.term)
            })
            .map_err(|error| plain_http_error(StatusCode::CONFLICT, &error.to_string()))?;
    }
    Ok(Some(authority_lease))
}

pub(crate) fn refresh_authority_mutation_fence(state: &TrustServiceState) -> Result<(), Response> {
    let Some(authority_lease) = cluster_authority_lease_view(state) else {
        return Ok(());
    };
    if !authority_lease.lease_valid {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster authority lease expired before authority fence refresh",
        ));
    }
    let Some(path) = state.config.authority_db_path.as_deref() else {
        return Ok(());
    };
    SqliteCapabilityAuthority::open(path)
        .and_then(|authority| {
            authority.seed_cluster_fence(Some(&authority_lease.leader_url), authority_lease.term)
        })
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    Ok(())
}

pub(crate) fn validate_service_auth(
    headers: &HeaderMap,
    service_token: &str,
) -> Result<(), Response> {
    if service_token.is_empty() {
        return Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "control service token must be non-empty",
        ));
    }
    let Some(provided) = control_bearer_token(headers) else {
        return Err(missing_or_invalid_control_token());
    };
    if bool::from(provided.as_bytes().ct_eq(service_token.as_bytes())) {
        return Ok(());
    }
    Err(missing_or_invalid_control_token())
}

fn control_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let provided = header.strip_prefix("Bearer ")?;
    (!provided.is_empty()).then_some(provided)
}

fn missing_or_invalid_control_token() -> Response {
    let mut response = plain_http_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid control bearer token",
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedControlReadPrincipal {
    AdminService,
    TenantRead { tenant_id: String },
}

impl ResolvedControlReadPrincipal {
    pub(crate) fn receipt_read_context(&self) -> ReceiptReadContext {
        match self {
            Self::AdminService => ReceiptReadContext::admin_service(),
            Self::TenantRead { tenant_id } => {
                ReceiptReadContext::authenticated_tenant(tenant_id.clone())
            }
        }
    }

    pub(crate) fn authorize_evidence_export_query(
        &self,
        mut query: EvidenceExportQuery,
    ) -> Result<EvidenceExportQuery, Response> {
        match self {
            Self::AdminService => Ok(query),
            Self::TenantRead { tenant_id } => {
                match &query.read_boundary {
                    Some(ReceiptReadBoundary::AdminAll) => {
                        return Err(plain_http_error(
                            StatusCode::FORBIDDEN,
                            "tenant read token cannot request admin-all evidence export",
                        ));
                    }
                    Some(ReceiptReadBoundary::TenantScoped { tenant }) if tenant != tenant_id => {
                        return Err(plain_http_error(
                            StatusCode::FORBIDDEN,
                            "tenant read token cannot export evidence for another tenant",
                        ));
                    }
                    Some(ReceiptReadBoundary::TenantScoped { .. }) => {}
                    None => {
                        query.read_boundary = Some(ReceiptReadBoundary::TenantScoped {
                            tenant: tenant_id.clone(),
                        });
                    }
                }
                if query
                    .tenant
                    .as_deref()
                    .is_some_and(|tenant| tenant != tenant_id)
                {
                    return Err(plain_http_error(
                        StatusCode::FORBIDDEN,
                        "tenant read token cannot narrow evidence export to another tenant",
                    ));
                }
                query.tenant = Some(tenant_id.clone());
                Ok(query)
            }
        }
    }
}

pub(crate) fn resolve_control_read_principal(
    headers: &HeaderMap,
    config: &TrustServiceConfig,
) -> Result<ResolvedControlReadPrincipal, Response> {
    config
        .validate()
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let Some(provided) = control_bearer_token(headers) else {
        return Err(missing_or_invalid_control_token());
    };
    if bool::from(provided.as_bytes().ct_eq(config.service_token.as_bytes())) {
        return Ok(ResolvedControlReadPrincipal::AdminService);
    }
    for (tenant_id, token) in &config.tenant_read_tokens {
        if bool::from(provided.as_bytes().ct_eq(token.as_bytes())) {
            return Ok(ResolvedControlReadPrincipal::TenantRead {
                tenant_id: tenant_id.clone(),
            });
        }
    }
    Err(missing_or_invalid_control_token())
}

pub(crate) fn validate_metered_billing_reconciliation_request(
    request: &MeteredBillingReconciliationUpdateRequest,
) -> Result<(), String> {
    if request.receipt_id.trim().is_empty() {
        return Err("receiptId must not be empty".to_string());
    }
    if request.adapter_kind.trim().is_empty() {
        return Err("adapterKind must not be empty".to_string());
    }
    if request.evidence_id.trim().is_empty() {
        return Err("evidenceId must not be empty".to_string());
    }
    if request.observed_units == 0 {
        return Err("observedUnits must be greater than zero".to_string());
    }
    if request.billed_cost.units == 0 {
        return Err("billedCost.units must be greater than zero".to_string());
    }
    if request.billed_cost.currency.trim().is_empty() {
        return Err("billedCost.currency must not be empty".to_string());
    }
    if request.recorded_at == 0 {
        return Err("recordedAt must be greater than zero".to_string());
    }
    if request
        .evidence_sha256
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("evidenceSha256 must not be empty when provided".to_string());
    }
    Ok(())
}

pub(crate) fn load_capability_authority(
    config: &TrustServiceConfig,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    load_capability_authority_with_lineage_mode(config, true)
}

pub(crate) fn load_capability_authority_with_deferred_lineage(
    config: &TrustServiceConfig,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    load_capability_authority_with_lineage_mode(config, false)
}

fn load_capability_authority_with_lineage_mode(
    config: &TrustServiceConfig,
    persist_lineage_immediately: bool,
) -> Result<Box<dyn CapabilityAuthority>, Response> {
    let wrap = |inner: Box<dyn CapabilityAuthority>| {
        if persist_lineage_immediately {
            issuance::wrap_capability_authority(
                inner,
                config.issuance_policy.clone(),
                config.runtime_assurance_policy.clone(),
                config.receipt_db_path.as_deref(),
                config.budget_db_path.as_deref(),
            )
        } else {
            issuance::wrap_capability_authority_with_deferred_lineage(
                inner,
                config.issuance_policy.clone(),
                config.runtime_assurance_policy.clone(),
                config.receipt_db_path.as_deref(),
                config.budget_db_path.as_deref(),
            )
        }
    };
    match (
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    ) {
        (Some(_), Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires either --authority-seed-file or --authority-db, not both",
        )),
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path).map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
            Ok(wrap(Box::new(LocalCapabilityAuthority::new(keypair))))
        }
        (None, Some(path)) => SqliteCapabilityAuthority::open(path)
            .map(|authority| wrap(Box::new(authority)))
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }),
        (None, None) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        )),
    }
}

pub(crate) fn load_authority_status(
    config: &TrustServiceConfig,
) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.status())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Ok(TrustAuthorityStatus {
            configured: false,
            backend: None,
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        });
    };
    match authority_public_key_from_seed_file(path) {
        Ok(Some(public_key)) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Ok(None) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: None,
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: Vec::new(),
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

pub(crate) fn rotate_authority(
    config: &TrustServiceConfig,
) -> Result<TrustAuthorityStatus, Response> {
    if let Some(path) = config.authority_db_path.as_deref() {
        let status = SqliteCapabilityAuthority::open(path)
            .and_then(|authority| authority.rotate())
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?;
        return Ok(authority_status_response("sqlite".to_string(), status));
    }

    let Some(path) = config.authority_seed_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --authority-seed-file or --authority-db",
        ));
    };
    match rotate_authority_keypair(path) {
        Ok(public_key) => Ok(TrustAuthorityStatus {
            configured: true,
            backend: Some("seed_file".to_string()),
            public_key: Some(public_key.to_hex()),
            generation: None,
            rotated_at: None,
            applies_to_future_sessions_only: true,
            trusted_public_keys: vec![public_key.to_hex()],
        }),
        Err(error) => Err(plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &error.to_string(),
        )),
    }
}

pub(crate) fn authority_status_response(
    backend: String,
    status: AuthorityStatus,
) -> TrustAuthorityStatus {
    TrustAuthorityStatus {
        configured: true,
        backend: Some(backend),
        public_key: Some(status.public_key.to_hex()),
        generation: Some(status.generation),
        rotated_at: Some(status.rotated_at),
        applies_to_future_sessions_only: true,
        trusted_public_keys: status
            .trusted_public_keys
            .into_iter()
            .map(|public_key| public_key.to_hex())
            .collect(),
    }
}
