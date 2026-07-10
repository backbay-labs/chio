use super::*;

pub(super) fn validate_authorization_request(
    request: &AuthorizationRequest,
    supported_scopes: &[String],
    expected_resource: &str,
) -> Result<String, Response> {
    if request.response_type != "code" {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be code",
        ));
    }
    if request.client_id.trim().is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id must not be empty",
        ));
    }
    validate_redirect_uri(&request.redirect_uri)?;
    let resource = request.resource.clone().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "missing resource parameter",
        )
    })?;
    if resource != expected_resource {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource parameter must match the advertised protected resource",
        ));
    }
    let code_challenge = request.code_challenge.as_deref().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "missing code_challenge",
        )
    })?;
    if code_challenge.is_empty() {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "empty code_challenge",
        ));
    }
    if request.code_challenge_method.as_deref() != Some("S256") {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    let _ = parse_request_time_authorization_details(request.authorization_details.as_deref())?;
    let _ = parse_request_time_transaction_context(request.chio_transaction_context.as_deref())?;
    let _ = resolve_requested_scopes(request.scope.as_deref(), supported_scopes)?;
    Ok(resource)
}

pub(super) fn validate_redirect_uri(redirect_uri: &str) -> Result<(), Response> {
    let redirect = Url::parse(redirect_uri).map_err(|_| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        )
    })?;
    let Some(host) = redirect.host_str() else {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid redirect_uri",
        ));
    };
    let is_localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if redirect.scheme() == "https" || (redirect.scheme() == "http" && is_localhost) {
        Ok(())
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri must use https or localhost",
        ))
    }
}

pub(super) fn resolve_requested_scopes(
    requested_scope: Option<&str>,
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = requested_scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if supported_scopes.is_empty() {
        return Ok(requested);
    }
    let scopes = if requested.is_empty() {
        supported_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| supported_scopes.iter().any(|supported| supported == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "requested scope is not supported",
        ))
    }
}

pub(super) fn resolve_exchange_scopes(
    requested_scope: Option<&str>,
    subject_scopes: &[String],
    supported_scopes: &[String],
) -> Result<Vec<String>, Response> {
    let requested = resolve_requested_scopes(requested_scope, supported_scopes)?;
    let scopes = if requested.is_empty() {
        subject_scopes.to_vec()
    } else {
        requested
    };
    if scopes
        .iter()
        .all(|scope| subject_scopes.iter().any(|granted| granted == scope))
    {
        Ok(scopes)
    } else {
        Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "requested exchange scope exceeds subject token scope",
        ))
    }
}
