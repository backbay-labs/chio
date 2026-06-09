fn bearer_request_header(access_token: String) -> A2aRequestHeader {
    A2aRequestHeader {
        name: "Authorization".to_string(),
        value: format!("Bearer {access_token}"),
        sensitive: true,
    }
}

fn basic_request_header_value(username: String, password: String) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{username}:{password}"))
    )
}

fn merged_oauth_scopes(required_scopes: &[String], configured_scopes: &[String]) -> Vec<String> {
    let mut scopes = Vec::new();
    for scope in required_scopes.iter().chain(configured_scopes.iter()) {
        if !scope.trim().is_empty() && !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.clone());
        }
    }
    scopes
}

fn oauth_cache_key(scheme_name: &str, token_endpoint: &Url, scopes: &[String]) -> String {
    let mut normalized_scopes = scopes.to_vec();
    normalized_scopes.sort();
    normalized_scopes.dedup();
    format!(
        "{scheme_name}|{}|{}",
        token_endpoint,
        normalized_scopes.join(" ")
    )
}

fn request_client_credentials_token(
    token_endpoint: &Url,
    credentials: &A2aOAuthClientCredentials,
    scopes: &[String],
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<A2aOAuthTokenResponse, AdapterError> {
    let basic_header = A2aRequestHeader {
        name: "Authorization".to_string(),
        value: format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!(
                "{}:{}",
                credentials.client_id, credentials.client_secret
            ))
        ),
        sensitive: true,
    };
    let basic_body = build_client_credentials_form(scopes, None);
    let response = match post_form_json::<A2aOAuthTokenResponse>(
        token_endpoint,
        basic_body.as_str(),
        &[basic_header],
        timeout,
        transport_config,
        A2aTlsMode::Default,
    ) {
        Ok(response) => response,
        Err(AdapterError::Remote(message))
            if message.starts_with("HTTP 400:") || message.starts_with("HTTP 401:") =>
        {
            let fallback_body = build_client_credentials_form(
                scopes,
                Some((&credentials.client_id, &credentials.client_secret)),
            );
            post_form_json::<A2aOAuthTokenResponse>(
                token_endpoint,
                fallback_body.as_str(),
                &[],
                timeout,
                transport_config,
                A2aTlsMode::Default,
            )?
        }
        Err(error) => return Err(error),
    };
    validate_oauth_token_response(response)
}

fn validate_oauth_token_response(
    response: A2aOAuthTokenResponse,
) -> Result<A2aOAuthTokenResponse, AdapterError> {
    if response.access_token.trim().is_empty() {
        return Err(AdapterError::AuthNegotiation(
            "OAuth token endpoint returned empty access_token".to_string(),
        ));
    }
    if response.access_token.trim() != response.access_token {
        return Err(AdapterError::AuthNegotiation(
            "OAuth token endpoint returned access_token with surrounding whitespace".to_string(),
        ));
    }
    if bearer_token_contains_forbidden_character(&response.access_token) {
        return Err(AdapterError::AuthNegotiation(
            "OAuth token endpoint returned access_token with whitespace or control characters"
                .to_string(),
        ));
    }
    let token_type = response.token_type.as_deref().ok_or_else(|| {
        AdapterError::AuthNegotiation("OAuth token endpoint omitted token_type".to_string())
    })?;
    if !token_type.trim().eq_ignore_ascii_case("bearer") {
        return Err(AdapterError::AuthNegotiation(format!(
            "OAuth token endpoint returned unsupported token_type `{token_type}`"
        )));
    }
    Ok(response)
}

fn build_client_credentials_form(scopes: &[String], credentials: Option<(&str, &str)>) -> String {
    let mut serializer = UrlFormSerializer::new(String::new());
    serializer.append_pair("grant_type", "client_credentials");
    if !scopes.is_empty() {
        serializer.append_pair("scope", &scopes.join(" "));
    }
    if let Some((client_id, client_secret)) = credentials {
        serializer.append_pair("client_id", client_id);
        serializer.append_pair("client_secret", client_secret);
    }
    serializer.finish()
}

// HttpEgressContract: every outbound A2A dispatch (agent-card discovery,
// SendMessage, OAuth token exchange) runs through the typed egress contract
// before bytes leave the substrate. The contract is threaded via
// `A2aTransportConfig.egress_contract` and populated via
// [`A2aAdapterConfig::with_egress_contract`]. Production callers must supply
// a tenant-scoped contract; if unset, dispatch fails closed.
fn enforce_egress_contract(
    transport_config: &A2aTransportConfig,
    target_url: &str,
) -> Result<(), AdapterError> {
    let Some(contract) = transport_config.egress_contract.as_ref() else {
        return Err(AdapterError::InvalidUrl(
            "A2A outbound HTTP requires an HttpEgressContract".to_string(),
        ));
    };
    contract.enforce_url_with_dns(target_url, 0).map_err(|err| {
        AdapterError::InvalidUrl(format!("HttpEgressContract rejects A2A URL: {err}"))
    })?;
    Ok(())
}

#[derive(Clone)]
struct A2aContractResolver {
    contract: HttpEgressContract,
}

impl ureq::Resolver for A2aContractResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let host = resolver_host_label(netloc);
        let addrs = netloc
            .to_socket_addrs()?
            .map(|addr| {
                self.contract
                    .enforce_resolved_ip(host, addr.ip())
                    .map(|()| addr)
                    .map_err(|err| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
                    })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{netloc} resolved to no addresses"),
            ));
        }
        Ok(addrs)
    }
}

fn resolver_host_label(netloc: &str) -> &str {
    if let Some(rest) = netloc.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
    }
    netloc.rsplit_once(':').map_or(netloc, |(host, _)| host)
}

/// Manually drive a ureq request and validate every redirect target via
/// the typed `HttpEgressContract`. The closure returns a fresh ureq
/// `Response` for each URL hop; when the response is a 3xx, we extract
/// the `Location` header, run it through the contract, and re-issue the
/// request against the redirect target. This stops an attacker who
/// controls an A2A endpoint from redirecting our dispatch into an
/// internal address that the initial pre-flight check did not see.
///
/// `redirects(0)` on the agent means ureq returns 3xx responses directly
/// rather than following them. Missing contracts fail closed before dispatch.
fn dispatch_with_redirect_validation<F>(
    initial_url: &str,
    transport_config: &A2aTransportConfig,
    allow_cross_origin_redirects: bool,
    mut send: F,
) -> Result<ureq::Response, AdapterError>
where
    F: FnMut(&str, bool) -> Result<ureq::Response, ureq::Error>,
{
    let Some(contract) = transport_config.egress_contract.as_ref() else {
        return Err(AdapterError::InvalidUrl(
            "A2A outbound HTTP requires an HttpEgressContract".to_string(),
        ));
    };
    let max_chain = contract.max_redirect_chain;
    let mut current_url = initial_url.to_string();
    let mut chain_len: u8 = 0;
    let mut strip_sensitive_headers = false;
    loop {
        let response =
            send(&current_url, strip_sensitive_headers).map_err(|error| map_ureq_error_with_contract(error, contract))?;
        let status = response.status();
        if !(300..400).contains(&status) {
            return Ok(response);
        }
        let Some(location) = response.header("Location") else {
            return Ok(response);
        };
        if chain_len >= max_chain {
            return Err(AdapterError::InvalidUrl(format!(
                "HttpEgressContract redirect limit exceeded ({max_chain}) following A2A redirect from {current_url}"
            )));
        }
        chain_len = chain_len.saturating_add(1);
        let next_url = match Url::parse(location) {
            Ok(absolute) => absolute,
            Err(_) => Url::parse(&current_url)
                .and_then(|base| base.join(location))
                .map_err(|error| {
                    AdapterError::InvalidUrl(format!(
                        "invalid A2A redirect target `{location}`: {error}"
                    ))
                })?,
        };
        contract
            .enforce_url_with_dns(next_url.as_str(), chain_len)
            .map_err(|err| {
                AdapterError::InvalidUrl(format!(
                    "HttpEgressContract rejects A2A redirect target: {err}"
                ))
            })?;
        let previous_url = Url::parse(&current_url).map_err(|error| {
            AdapterError::InvalidUrl(format!("invalid A2A redirect source `{current_url}`: {error}"))
        })?;
        let cross_origin = !same_origin(&previous_url, &next_url);
        if cross_origin && !allow_cross_origin_redirects {
            return Err(AdapterError::InvalidUrl(format!(
                "A2A body-bearing request rejected cross-origin redirect from {previous_url} to {next_url}"
            )));
        }
        strip_sensitive_headers = strip_sensitive_headers || cross_origin;
        current_url = next_url.into();
    }
}

fn read_json_response_with_contract<T: for<'de> Deserialize<'de>>(
    response: ureq::Response,
    context: &str,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let contract = transport_config.egress_contract.as_ref().ok_or_else(|| {
        AdapterError::InvalidUrl("A2A response reads require an HttpEgressContract".to_string())
    })?;
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
    serde_json::from_slice::<T>(&body).map_err(|error| {
        AdapterError::Protocol(format!("failed to decode A2A JSON from {context}: {error}"))
    })
}

fn read_sse_response_with_contract<F>(
    response: ureq::Response,
    context: &str,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let contract = transport_config.egress_contract.as_ref().ok_or_else(|| {
        AdapterError::InvalidUrl("A2A streaming response reads require an HttpEgressContract".to_string())
    })?;
    enforce_ureq_content_length(contract, &response, context)?;
    parse_sse_stream_with_limit(
        response.into_reader(),
        contract.max_response_bytes,
        decode_event,
    )
}

fn fetch_json<T: for<'de> Deserialize<'de>>(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    enforce_egress_contract(transport_config, request_url.as_str())?;
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        true,
        |target, strip_sensitive_headers| {
            let request = agent
                .get(target)
                .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.call()
        },
    )?;
    read_json_response_with_contract(response, request_url.as_str(), transport_config)
}

fn delete_empty(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<(), AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    enforce_egress_contract(transport_config, request_url.as_str())?;
    dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        true,
        |target, strip_sensitive_headers| {
            let request = agent
                .delete(target)
                .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.call()
        },
    )?;
    Ok(())
}

fn get_sse<F>(
    url: &Url,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(url.clone(), request_auth);
    enforce_egress_contract(transport_config, request_url.as_str())?;
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        true,
        |target, strip_sensitive_headers| {
            let request = agent
                .get(target)
                .set("Accept", SSE_CONTENT_TYPE)
                .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.call()
        },
    )?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    read_sse_response_with_contract(response, request_url.as_str(), transport_config, decode_event)
}

fn post_json<T: for<'de> Deserialize<'de>, B: Serialize>(
    url: &str,
    body: &B,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(
        Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?,
        request_auth,
    );
    enforce_egress_contract(transport_config, request_url.as_str())?;
    let body_value = serde_json::to_value(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?;
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        false,
        |target, strip_sensitive_headers| {
            let request = agent
                .post(target)
                .set("Content-Type", "application/json")
                .set("Accept", "application/json")
                .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.send_json(body_value.clone())
        },
    )?;
    read_json_response_with_contract(response, request_url.as_str(), transport_config)
}

fn post_form_json<T: for<'de> Deserialize<'de>>(
    url: &Url,
    body: &str,
    request_headers: &[A2aRequestHeader],
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    tls_mode: A2aTlsMode,
) -> Result<T, AdapterError> {
    let agent = build_agent(timeout, transport_config, tls_mode)?;
    enforce_egress_contract(transport_config, url.as_str())?;
    let response = dispatch_with_redirect_validation(
        url.as_str(),
        transport_config,
        false,
        |target, strip_sensitive_headers| {
            let request = agent
                .post(target)
                .set("Content-Type", "application/x-www-form-urlencoded")
                .set("Accept", "application/json");
            let request =
                apply_request_headers(request, request_headers, strip_sensitive_headers);
            request.send_string(body)
        },
    )?;
    read_json_response_with_contract(response, url.as_str(), transport_config)
}

fn post_sse_json<T: Serialize, F>(
    url: &str,
    body: &T,
    request_auth: &A2aResolvedRequestAuth,
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    decode_event: F,
) -> Result<ToolServerStreamResult, AdapterError>
where
    F: Fn(Value) -> Result<Value, AdapterError>,
{
    let agent = build_agent(timeout, transport_config, request_auth.tls_mode)?;
    let request_url = apply_request_auth_url(
        Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?,
        request_auth,
    );
    enforce_egress_contract(transport_config, request_url.as_str())?;
    let body_value = serde_json::to_value(body).map_err(|error| {
        AdapterError::Protocol(format!("failed to serialize A2A request: {error}"))
    })?;
    let response = dispatch_with_redirect_validation(
        request_url.as_str(),
        transport_config,
        false,
        |target, strip_sensitive_headers| {
            let request = agent
                .post(target)
                .set("Content-Type", "application/json")
                .set("Accept", SSE_CONTENT_TYPE)
                .set(A2A_VERSION_HEADER, A2A_PROTOCOL_VERSION_HEADER_VALUE);
            let request = apply_request_auth(request, request_auth, strip_sensitive_headers);
            request.send_json(body_value.clone())
        },
    )?;
    let content_type = response.header("Content-Type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains(SSE_CONTENT_TYPE) {
        return Err(AdapterError::Protocol(format!(
            "expected {SSE_CONTENT_TYPE} response, got {content_type}"
        )));
    }
    read_sse_response_with_contract(response, request_url.as_str(), transport_config, decode_event)
}

fn build_optional_default_tls_config(
    root_ca_pems: &[String],
) -> Result<Option<Arc<ureq::rustls::ClientConfig>>, AdapterError> {
    if root_ca_pems.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(build_client_tls_config(root_ca_pems, None)?)))
}

fn build_optional_mutual_tls_config(
    root_ca_pems: &[String],
    mutual_tls_identity: Option<&A2aMutualTlsIdentity>,
) -> Result<Option<Arc<ureq::rustls::ClientConfig>>, AdapterError> {
    let Some(mutual_tls_identity) = mutual_tls_identity else {
        return Ok(None);
    };
    Ok(Some(Arc::new(build_client_tls_config(
        root_ca_pems,
        Some(mutual_tls_identity),
    )?)))
}

fn build_client_tls_config(
    root_ca_pems: &[String],
    mutual_tls_identity: Option<&A2aMutualTlsIdentity>,
) -> Result<ureq::rustls::ClientConfig, AdapterError> {
    let root_store = build_root_cert_store(root_ca_pems)?;
    let builder = ureq::rustls::ClientConfig::builder().with_root_certificates(root_store);
    if let Some(mutual_tls_identity) = mutual_tls_identity {
        let cert_chain = parse_pem_certificates(
            mutual_tls_identity.cert_chain_pem.as_str(),
            "mutual TLS client certificate chain",
        )?;
        let private_key = parse_pem_private_key(
            mutual_tls_identity.private_key_pem.as_str(),
            "mutual TLS client private key",
        )?;
        builder
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|error| {
                AdapterError::AuthNegotiation(format!(
                    "failed to build mutual TLS client identity: {error}"
                ))
            })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

fn build_root_cert_store(
    root_ca_pems: &[String],
) -> Result<ureq::rustls::RootCertStore, AdapterError> {
    let mut root_store = ureq::rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for root_ca_pem in root_ca_pems {
        for certificate in parse_pem_certificates(root_ca_pem, "custom TLS root CA")? {
            root_store.add(certificate).map_err(|error| {
                AdapterError::AuthNegotiation(format!(
                    "failed to add custom TLS root CA certificate: {error}"
                ))
            })?;
        }
    }
    Ok(root_store)
}

fn parse_pem_certificates(
    pem: &str,
    field_name: &str,
) -> Result<Vec<ureq::rustls::pki_types::CertificateDer<'static>>, AdapterError> {
    let mut reader = pem.as_bytes();
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            AdapterError::AuthNegotiation(format!("failed to parse {field_name}: {error}"))
        })?;
    if certificates.is_empty() {
        return Err(AdapterError::AuthNegotiation(format!(
            "{field_name} did not contain any PEM certificates"
        )));
    }
    Ok(certificates)
}

fn parse_pem_private_key(
    pem: &str,
    field_name: &str,
) -> Result<ureq::rustls::pki_types::PrivateKeyDer<'static>, AdapterError> {
    let mut reader = pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut reader)
        .map_err(|error| {
            AdapterError::AuthNegotiation(format!("failed to parse {field_name}: {error}"))
        })?
        .ok_or_else(|| {
            AdapterError::AuthNegotiation(format!(
                "{field_name} did not contain a supported PEM private key"
            ))
        })?;
    Ok(private_key)
}

fn build_agent(
    timeout: Duration,
    transport_config: &A2aTransportConfig,
    tls_mode: A2aTlsMode,
) -> Result<ureq::Agent, AdapterError> {
    let mut builder = ureq::AgentBuilder::new().timeout(timeout);
    // HttpEgressContract: suppress ureq's built-in redirect follow so
    // `dispatch_with_redirect_validation` can validate every hop before
    // re-issuing.
    builder = builder.redirects(0);
    if let Some(contract) = transport_config.egress_contract.clone() {
        builder = builder.resolver(A2aContractResolver { contract });
    }
    let builder = match tls_mode {
        A2aTlsMode::Default => match transport_config.default_tls_config.as_ref() {
            Some(tls_config) => builder.tls_config(Arc::clone(tls_config)),
            None => builder,
        },
        A2aTlsMode::MutualTls => {
            let tls_config = transport_config.mutual_tls_config.as_ref().ok_or_else(|| {
                AdapterError::AuthNegotiation(
                    "mutual TLS transport was selected without a client identity".to_string(),
                )
            })?;
            builder.tls_config(Arc::clone(tls_config))
        }
    };
    Ok(builder.build())
}
