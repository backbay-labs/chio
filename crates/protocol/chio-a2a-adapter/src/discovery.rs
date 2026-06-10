fn parse_security_requirements(
    raw: &Value,
) -> Result<Vec<Vec<A2aSecurityRequirementEntry>>, AdapterError> {
    let requirements = raw.as_array().ok_or_else(|| {
        AdapterError::Protocol("A2A securityRequirements must be an array".to_string())
    })?;
    requirements
        .iter()
        .map(|requirement| {
            let schemes = requirement
                .get("schemes")
                .and_then(Value::as_object)
                .or_else(|| requirement.as_object())
                .ok_or_else(|| {
                    AdapterError::Protocol(
                        "A2A security requirement entry must be an object".to_string(),
                    )
                })?;
            schemes
                .iter()
                .map(|(name, scopes)| {
                    Ok(A2aSecurityRequirementEntry {
                        scheme_name: name.clone(),
                        scopes: parse_required_scopes(scopes)?,
                    })
                })
                .collect()
        })
        .collect()
}

fn parse_security_schemes(raw: &Value) -> Result<Vec<A2aParsedSecurityScheme>, AdapterError> {
    let schemes = raw.as_object().ok_or_else(|| {
        AdapterError::Protocol("A2A securitySchemes must be an object".to_string())
    })?;
    schemes
        .iter()
        .map(|(name, value)| {
            Ok(A2aParsedSecurityScheme {
                name: name.clone(),
                kind: parse_security_scheme_kind(value),
            })
        })
        .collect()
}

fn parse_security_scheme_kind(raw: &Value) -> A2aSecuritySchemeKind {
    let Some(object) = raw.as_object() else {
        return A2aSecuritySchemeKind::Unsupported(
            "scheme definition is not an object".to_string(),
        );
    };

    if let Some(http_auth) = object
        .get("httpAuthSecurityScheme")
        .or_else(|| object.get("http_auth_security_scheme"))
    {
        let scheme = http_auth
            .get("scheme")
            .or_else(|| http_auth.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        return if scheme.eq_ignore_ascii_case("bearer") {
            A2aSecuritySchemeKind::BearerToken
        } else if scheme.eq_ignore_ascii_case("basic") {
            A2aSecuritySchemeKind::BasicAuth
        } else {
            A2aSecuritySchemeKind::Unsupported(format!(
                "HTTP auth scheme `{scheme}` is not supported"
            ))
        };
    }

    if let Some(api_key) = object
        .get("apiKeySecurityScheme")
        .or_else(|| object.get("api_key_security_scheme"))
    {
        let location = api_key
            .get("location")
            .or_else(|| api_key.get("in"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let header_name = api_key
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        return match location.to_ascii_lowercase().as_str() {
            "header" if !header_name.trim().is_empty() => {
                A2aSecuritySchemeKind::ApiKeyHeader { header_name }
            }
            "query" if !header_name.trim().is_empty() => A2aSecuritySchemeKind::ApiKeyQuery {
                param_name: header_name,
            },
            "cookie" if !header_name.trim().is_empty() => A2aSecuritySchemeKind::ApiKeyCookie {
                cookie_name: header_name,
            },
            "header" => A2aSecuritySchemeKind::Unsupported(
                "API key header scheme omitted header name".to_string(),
            ),
            "query" => A2aSecuritySchemeKind::Unsupported(
                "API key query scheme omitted parameter name".to_string(),
            ),
            "cookie" => A2aSecuritySchemeKind::Unsupported(
                "API key cookie scheme omitted cookie name".to_string(),
            ),
            _ => A2aSecuritySchemeKind::Unsupported(format!(
                "API key location `{location}` is not supported"
            )),
        };
    }

    if let Some(oauth2) = object
        .get("oauth2SecurityScheme")
        .or_else(|| object.get("oauth2_security_scheme"))
    {
        return A2aSecuritySchemeKind::OAuthBearerToken {
            token_endpoint: extract_oauth_token_endpoint(oauth2),
        };
    }

    if let Some(openid) = object
        .get("openIdConnectSecurityScheme")
        .or_else(|| object.get("open_id_connect_security_scheme"))
    {
        let discovery_url =
            extract_string_field(openid, &["openIdConnectUrl", "open_id_connect_url"]);
        return match discovery_url {
            Some(discovery_url) if !discovery_url.trim().is_empty() => {
                A2aSecuritySchemeKind::OpenIdBearerToken { discovery_url }
            }
            _ => A2aSecuritySchemeKind::Unsupported(
                "OpenID Connect scheme omitted discovery URL".to_string(),
            ),
        };
    }

    if object.contains_key("mtlsSecurityScheme") || object.contains_key("mtls_security_scheme") {
        return A2aSecuritySchemeKind::MutualTls;
    }

    A2aSecuritySchemeKind::Unsupported("unknown security scheme shape".to_string())
}

fn parse_required_scopes(raw: &Value) -> Result<Vec<String>, AdapterError> {
    match raw {
        Value::Null => Ok(Vec::new()),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(ToString::to_string).ok_or_else(|| {
                    AdapterError::Protocol(
                        "A2A security requirement scopes must be strings".to_string(),
                    )
                })
            })
            .collect(),
        _ => Err(AdapterError::Protocol(
            "A2A security requirement scopes must be an array".to_string(),
        )),
    }
}

fn extract_string_field(raw: &Value, field_names: &[&str]) -> Option<String> {
    let object = raw.as_object()?;
    field_names.iter().find_map(|field_name| {
        object
            .get(*field_name)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    })
}

fn extract_oauth_token_endpoint(raw: &Value) -> Option<String> {
    extract_string_field(raw, &["tokenUrl", "token_url"]).or_else(|| {
        raw.get("flows")
            .and_then(|flows| {
                flows
                    .get("clientCredentials")
                    .or_else(|| flows.get("client_credentials"))
            })
            .and_then(|client_credentials| {
                extract_string_field(client_credentials, &["tokenUrl", "token_url"])
            })
    })
}

fn configured_bearer_header(headers: &[A2aRequestHeader]) -> Option<A2aRequestHeader> {
    headers
        .iter()
        .find(|header| {
            header.name.eq_ignore_ascii_case("Authorization")
                && header.value.to_ascii_lowercase().starts_with("bearer ")
        })
        .cloned()
}

fn configured_basic_auth_header(headers: &[A2aRequestHeader]) -> Option<A2aRequestHeader> {
    headers
        .iter()
        .find(|header| {
            header.name.eq_ignore_ascii_case("Authorization")
                && header.value.to_ascii_lowercase().starts_with("basic ")
        })
        .cloned()
}

fn configured_named_header(
    headers: &[A2aRequestHeader],
    header_name: &str,
) -> Option<A2aRequestHeader> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(header_name))
        .cloned()
}

fn configured_named_query_param(
    query_params: &[A2aRequestQueryParam],
    param_name: &str,
) -> Option<A2aRequestQueryParam> {
    query_params
        .iter()
        .find(|query_param| query_param.name == param_name)
        .cloned()
}

fn configured_named_cookie(
    cookies: &[A2aRequestCookie],
    cookie_name: &str,
) -> Option<A2aRequestCookie> {
    cookies
        .iter()
        .find(|cookie| cookie.name == cookie_name)
        .cloned()
}

fn dedupe_request_headers(headers: &mut Vec<A2aRequestHeader>) {
    let mut deduped: Vec<A2aRequestHeader> = Vec::new();
    for header in headers.drain(..) {
        let mut merged = false;
        for existing in &mut deduped {
            if existing.name.eq_ignore_ascii_case(&header.name) && existing.value == header.value {
                existing.sensitive |= header.sensitive;
                merged = true;
                break;
            }
        }
        if !merged {
            deduped.push(header);
        }
    }
    *headers = deduped;
}

fn dedupe_request_query_params(query_params: &mut Vec<A2aRequestQueryParam>) {
    let mut deduped = Vec::new();
    for query_param in query_params.drain(..) {
        if !deduped
            .iter()
            .any(|existing: &A2aRequestQueryParam| existing == &query_param)
        {
            deduped.push(query_param);
        }
    }
    *query_params = deduped;
}

fn dedupe_request_cookies(cookies: &mut Vec<A2aRequestCookie>) {
    let mut deduped = Vec::new();
    for cookie in cookies.drain(..) {
        if !deduped
            .iter()
            .any(|existing: &A2aRequestCookie| existing == &cookie)
        {
            deduped.push(cookie);
        }
    }
    *cookies = deduped;
}

fn upsert_request_header(
    headers: &mut Vec<A2aRequestHeader>,
    name: String,
    value: String,
    sensitive: bool,
) {
    if let Some(existing) = headers
        .iter_mut()
        .find(|header| header.name.eq_ignore_ascii_case(&name))
    {
        existing.value = value;
        existing.sensitive |= sensitive;
    } else {
        headers.push(A2aRequestHeader {
            name,
            value,
            sensitive,
        });
    }
}

fn upsert_request_query_param(
    query_params: &mut Vec<A2aRequestQueryParam>,
    name: String,
    value: String,
    sensitive: bool,
) {
    if let Some(existing) = query_params
        .iter_mut()
        .find(|query_param| query_param.name == name)
    {
        existing.value = value;
        existing.sensitive |= sensitive;
    } else {
        query_params.push(A2aRequestQueryParam {
            name,
            value,
            sensitive,
        });
    }
}

fn upsert_request_cookie(cookies: &mut Vec<A2aRequestCookie>, name: String, value: String) {
    if let Some(existing) = cookies.iter_mut().find(|cookie| cookie.name == name) {
        existing.value = value;
    } else {
        cookies.push(A2aRequestCookie { name, value });
    }
}

fn merge_skill_routing_metadata(
    metadata: Option<Value>,
    skill: &A2aAgentSkill,
) -> Result<Value, AdapterError> {
    let mut object = match metadata {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(object)) => object,
        Some(other) => {
            return Err(AdapterError::InvalidToolInput(format!(
                "`metadata` must be an object, got {other}"
            )))
        }
    };

    let mut chio_namespace = match object.remove("chio") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(object)) => object,
        Some(_) => {
            return Err(AdapterError::InvalidToolInput(
                "`metadata.chio` must be an object when provided".to_string(),
            ))
        }
    };
    chio_namespace.insert("targetSkillId".to_string(), Value::String(skill.id.clone()));
    chio_namespace.insert(
        "targetSkillName".to_string(),
        Value::String(skill.name.clone()),
    );
    object.insert("chio".to_string(), Value::Object(chio_namespace));
    Ok(Value::Object(object))
}

fn validate_object_metadata(
    field_name: &str,
    metadata: Option<Value>,
) -> Result<Option<Value>, AdapterError> {
    match metadata {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(Value::Object(object))),
        Some(_) => Err(AdapterError::InvalidToolInput(format!(
            "`{field_name}` must be an object when provided"
        ))),
    }
}

fn validate_send_message_response(
    mut response: A2aSendMessageResponse,
) -> Result<A2aSendMessageResponse, AdapterError> {
    let has_task = response.task.is_some();
    let has_message = response.message.is_some();
    if has_task == has_message {
        return Err(AdapterError::Protocol(
            "A2A SendMessage response must contain exactly one of `task` or `message`".to_string(),
        ));
    }
    if let Some(task) = response.task.take() {
        response.task = Some(validate_task_response(task)?);
    }
    Ok(response)
}

fn validate_task_response(task: Value) -> Result<Value, AdapterError> {
    let Some(id) = task.get("id").and_then(Value::as_str) else {
        return Err(AdapterError::Protocol(
            "A2A task response must contain string `id`".to_string(),
        ));
    };
    if id.trim().is_empty() {
        return Err(AdapterError::Protocol(
            "A2A task response `id` must not be empty".to_string(),
        ));
    }
    validate_non_empty_string(
        task.get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str),
        "A2A task response must contain string `status.state`",
        "A2A task response `status.state` must not be empty",
    )?;
    Ok(task)
}

fn validate_stream_response(response: Value) -> Result<(Value, bool), AdapterError> {
    let has_task = response.get("task").is_some();
    let has_message = response.get("message").is_some();
    let has_status_update = response.get("statusUpdate").is_some();
    let has_artifact_update = response.get("artifactUpdate").is_some();
    let present_count = [
        has_task,
        has_message,
        has_status_update,
        has_artifact_update,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if present_count != 1 {
        return Err(AdapterError::Protocol(
            "A2A stream event must contain exactly one of `task`, `message`, `statusUpdate`, or `artifactUpdate`".to_string(),
        ));
    }

    let terminal_or_interrupted = if let Some(task) = response.get("task") {
        validate_task_value(task)?;
        task_state_is_terminal_or_interrupted(
            task.get("status")
                .and_then(|status| status.get("state"))
                .and_then(Value::as_str),
        )
    } else if has_message {
        true
    } else if let Some(update) = response.get("statusUpdate") {
        validate_status_update(update)?;
        task_state_is_terminal_or_interrupted(
            update
                .get("status")
                .and_then(|status| status.get("state"))
                .and_then(Value::as_str),
        )
    } else {
        if let Some(update) = response.get("artifactUpdate") {
            validate_artifact_update(update)?;
        }
        false
    };

    Ok((response, terminal_or_interrupted))
}

fn validate_task_value(task: &Value) -> Result<(), AdapterError> {
    validate_non_empty_string(
        task.get("id").and_then(Value::as_str),
        "A2A task response must contain string `id`",
        "A2A task response `id` must not be empty",
    )?;
    validate_non_empty_string(
        task.get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str),
        "A2A task response must contain string `status.state`",
        "A2A task response `status.state` must not be empty",
    )
}

fn validate_status_update(update: &Value) -> Result<(), AdapterError> {
    validate_non_empty_string(
        update.get("taskId").and_then(Value::as_str),
        "A2A status update must contain string `taskId`",
        "A2A status update `taskId` must not be empty",
    )?;
    validate_non_empty_string(
        update
            .get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str),
        "A2A status update must contain string `status.state`",
        "A2A status update `status.state` must not be empty",
    )
}

fn validate_artifact_update(update: &Value) -> Result<(), AdapterError> {
    validate_non_empty_string(
        update.get("taskId").and_then(Value::as_str),
        "A2A artifact update must contain string `taskId`",
        "A2A artifact update `taskId` must not be empty",
    )?;
    if update.get("artifact").and_then(Value::as_object).is_none() {
        return Err(AdapterError::Protocol(
            "A2A artifact update must contain object `artifact`".to_string(),
        ));
    }
    Ok(())
}

fn validate_non_empty_string(
    value: Option<&str>,
    missing_message: &str,
    empty_message: &str,
) -> Result<(), AdapterError> {
    let Some(value) = value else {
        return Err(AdapterError::Protocol(missing_message.to_string()));
    };
    if value.trim().is_empty() {
        return Err(AdapterError::Protocol(empty_message.to_string()));
    }
    Ok(())
}

fn task_state_is_terminal_or_interrupted(state: Option<&str>) -> bool {
    matches!(
        state,
        Some(
            "TASK_STATE_COMPLETED"
                | "TASK_STATE_FAILED"
                | "TASK_STATE_CANCELED"
                | "TASK_STATE_REJECTED"
                | "TASK_STATE_INPUT_REQUIRED"
                | "TASK_STATE_AUTH_REQUIRED"
        )
    )
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn binding_label(binding: &A2aProtocolBinding) -> &'static str {
    match binding {
        A2aProtocolBinding::JsonRpc => "JSONRPC",
        A2aProtocolBinding::HttpJson => "HTTP+JSON",
    }
}

fn next_message_id(counter: &AtomicU64, server_id: &str, skill_id: &str) -> String {
    let seq = counter.fetch_add(1, Ordering::Relaxed) + 1;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("chio-a2a-{server_id}-{skill_id}-{nanos}-{seq}")
}

fn derive_chio_server_id(agent_card_url: &Url) -> String {
    let host = agent_card_url
        .host_str()
        .unwrap_or("a2a")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let hash = sha256_hex(agent_card_url.as_str().as_bytes());
    format!("a2a-{host}-{}", &hash[..12])
}

fn normalize_agent_card_url(value: &str) -> Result<Url, AdapterError> {
    let mut url = Url::parse(value).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
    validate_remote_url(&url)?;
    if url.path().ends_with(".json") {
        return Ok(url);
    }
    let new_path = if url.path().is_empty() || url.path() == "/" {
        DEFAULT_AGENT_CARD_PATH.to_string()
    } else {
        format!(
            "{}/.well-known/agent-card.json",
            url.path().trim_end_matches('/')
        )
    };
    url.set_path(&new_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn build_get_task_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
    history_length: Option<u32>,
) -> Result<Url, AdapterError> {
    let encoded_id: String = byte_serialize(task_id.as_bytes()).collect();
    let mut url = join_tenant_url_path(base, tenant, &format!("/tasks/{encoded_id}"))?;
    if let Some(history_length) = history_length {
        url.query_pairs_mut()
            .append_pair("historyLength", &history_length.to_string());
    }
    Ok(url)
}

fn build_subscribe_task_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_id: String = byte_serialize(task_id.as_bytes()).collect();
    join_tenant_url_path(base, tenant, &format!("/tasks/{encoded_id}:subscribe"))
}

fn build_send_message_url(
    base: &str,
    tenant: Option<&str>,
    streaming: bool,
) -> Result<Url, AdapterError> {
    join_tenant_url_path(
        base,
        tenant,
        if streaming {
            "/message:stream"
        } else {
            "/message:send"
        },
    )
}

fn build_cancel_task_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_id: String = byte_serialize(task_id.as_bytes()).collect();
    join_tenant_url_path(base, tenant, &format!("/tasks/{encoded_id}:cancel"))
}

fn build_push_notification_configs_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_task_id: String = byte_serialize(task_id.as_bytes()).collect();
    join_tenant_url_path(
        base,
        tenant,
        &format!("/tasks/{encoded_task_id}/pushNotificationConfigs"),
    )
}

fn build_push_notification_config_url(
    base: &str,
    task_id: &str,
    config_id: &str,
    tenant: Option<&str>,
) -> Result<Url, AdapterError> {
    let encoded_task_id: String = byte_serialize(task_id.as_bytes()).collect();
    let encoded_config_id: String = byte_serialize(config_id.as_bytes()).collect();
    join_tenant_url_path(
        base,
        tenant,
        &format!("/tasks/{encoded_task_id}/pushNotificationConfigs/{encoded_config_id}"),
    )
}

fn build_list_push_notification_configs_url(
    base: &str,
    task_id: &str,
    tenant: Option<&str>,
    page_size: Option<u32>,
    page_token: Option<&str>,
) -> Result<Url, AdapterError> {
    let mut url = build_push_notification_configs_url(base, task_id, tenant)?;
    if let Some(page_size) = page_size {
        url.query_pairs_mut()
            .append_pair("pageSize", &page_size.to_string());
    }
    if let Some(page_token) = page_token {
        url.query_pairs_mut().append_pair("pageToken", page_token);
    }
    Ok(url)
}

fn join_tenant_url_path(
    base: &str,
    tenant: Option<&str>,
    suffix: &str,
) -> Result<Url, AdapterError> {
    let mut url = Url::parse(base).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
    validate_remote_url(&url)?;
    let mut joined = url.path().trim_end_matches('/').to_string();
    if let Some(tenant) = tenant {
        let encoded_tenant: String = byte_serialize(tenant.as_bytes()).collect();
        joined.push('/');
        joined.push_str(&encoded_tenant);
    }
    joined.push_str(suffix);
    url.set_path(&joined);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn validate_remote_url(url: &Url) -> Result<(), AdapterError> {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or_default();
    let localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if scheme == "https" || (scheme == "http" && localhost) {
        Ok(())
    } else {
        Err(AdapterError::InvalidUrl(format!(
            "A2A URLs must use https, or http on localhost during local testing: {}",
            url
        )))
    }
}

fn parse_remote_url(value: &str, field_name: &str) -> Result<Url, AdapterError> {
    let url = Url::parse(value).map_err(|error| {
        AdapterError::AuthNegotiation(format!("{field_name} is not a valid URL: {error}"))
    })?;
    validate_remote_url(&url).map_err(|error| {
        AdapterError::AuthNegotiation(format!(
            "{field_name} must use https, or localhost http: {error}"
        ))
    })?;
    Ok(url)
}

fn validate_notification_target_url(value: &str) -> Result<String, AdapterError> {
    let url = Url::parse(value).map_err(|error| {
        AdapterError::InvalidToolInput(format!("invalid push notification URL: {error}"))
    })?;
    validate_remote_url(&url).map_err(|error| {
        AdapterError::InvalidToolInput(format!(
            "push notification URL must use https, or http on localhost during local testing: {error}"
        ))
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AdapterError::InvalidToolInput(
            "push notification URL must not include userinfo".to_string(),
        ));
    }
    if url.fragment().is_some() {
        return Err(AdapterError::InvalidToolInput(
            "push notification URL must not include a fragment".to_string(),
        ));
    }
    Ok(url.to_string())
}

fn validate_identifier(field_name: &str, value: String) -> Result<String, AdapterError> {
    if value.trim().is_empty() {
        Err(AdapterError::InvalidToolInput(format!(
            "`{field_name}` must not be empty"
        )))
    } else {
        Ok(value)
    }
}

fn validate_authentication_info(
    input: Option<A2aAuthenticationInfoToolInput>,
) -> Result<Option<A2aAuthenticationInfo>, AdapterError> {
    match input {
        None => Ok(None),
        Some(input) => Ok(Some(A2aAuthenticationInfo {
            scheme: validate_push_auth_scheme("authentication.scheme", input.scheme)?,
            credentials: validate_optional_push_auth_material(
                "authentication.credentials",
                input.credentials,
            )?,
        })),
    }
}

fn validate_push_auth_scheme(field_name: &str, value: String) -> Result<String, AdapterError> {
    if value.is_empty() || value.trim() != value || !value.bytes().all(is_http_token_byte) {
        return Err(AdapterError::InvalidToolInput(format!(
            "`{field_name}` must be a non-empty HTTP token"
        )));
    }
    Ok(value)
}

fn validate_optional_push_auth_material(
    field_name: &str,
    value: Option<String>,
) -> Result<Option<String>, AdapterError> {
    match value {
        None => Ok(None),
        Some(value) => {
            if value.is_empty()
                || value.trim() != value
                || value.chars().any(|character| character.is_control())
            {
                return Err(AdapterError::InvalidToolInput(format!(
                    "`{field_name}` must be a non-empty unpadded string without control characters"
                )));
            }
            Ok(Some(value))
        }
    }
}
