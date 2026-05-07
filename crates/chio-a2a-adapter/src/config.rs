#[derive(Debug, Clone, PartialEq, Eq)]
struct A2aRequestHeader {
    name: String,
    value: String,
    sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct A2aRequestQueryParam {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct A2aRequestCookie {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct A2aOAuthClientCredentials {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Clone)]
struct A2aCachedBearerToken {
    cache_key: String,
    access_token: String,
    expires_at: Option<SystemTime>,
}

#[derive(Debug, Clone)]
struct A2aMutualTlsIdentity {
    cert_chain_pem: String,
    private_key_pem: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum A2aTlsMode {
    Default,
    MutualTls,
}

#[derive(Debug, Clone)]
struct A2aResolvedRequestAuth {
    headers: Vec<A2aRequestHeader>,
    query_params: Vec<A2aRequestQueryParam>,
    cookies: Vec<A2aRequestCookie>,
    tls_mode: A2aTlsMode,
}

#[derive(Debug, Clone)]
struct A2aTransportConfig {
    default_tls_config: Option<Arc<ureq::rustls::ClientConfig>>,
    mutual_tls_config: Option<Arc<ureq::rustls::ClientConfig>>,
    /// Typed HTTP egress contract that gates every outbound A2A dispatch.
    /// `None` fails closed before dispatch; production callers must thread a
    /// tenant-scoped contract via [`A2aAdapterConfig::with_egress_contract`].
    egress_contract: Option<HttpEgressContract>,
}


#[derive(Debug, Clone)]
pub struct A2aAdapterConfig {
    agent_card_url: String,
    public_key: String,
    request_headers: Vec<A2aRequestHeader>,
    request_query_params: Vec<A2aRequestQueryParam>,
    request_cookies: Vec<A2aRequestCookie>,
    oauth_client_credentials: Option<A2aOAuthClientCredentials>,
    oauth_scopes: Vec<String>,
    oauth_token_endpoint_override: Option<String>,
    tls_root_ca_pems: Vec<String>,
    mutual_tls_identity: Option<A2aMutualTlsIdentity>,
    timeout: Duration,
    server_id: Option<String>,
    server_version: String,
    partner_policy: Option<A2aPartnerPolicy>,
    task_registry_path: Option<PathBuf>,
    /// Typed HTTP egress contract that gates every outbound A2A dispatch.
    egress_contract: Option<HttpEgressContract>,
}

impl A2aAdapterConfig {
    #[must_use]
    pub fn new(agent_card_url: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            agent_card_url: agent_card_url.into(),
            public_key: public_key.into(),
            request_headers: Vec::new(),
            request_query_params: Vec::new(),
            request_cookies: Vec::new(),
            oauth_client_credentials: None,
            oauth_scopes: Vec::new(),
            oauth_token_endpoint_override: None,
            tls_root_ca_pems: Vec::new(),
            mutual_tls_identity: None,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            server_id: None,
            server_version: "0.1.0".to_string(),
            partner_policy: None,
            task_registry_path: None,
            egress_contract: None,
        }
    }

    /// Set the typed [`HttpEgressContract`] that gates every outbound A2A
    /// dispatch (agent-card discovery, SendMessage, OAuth token exchange).
    /// Production callers must thread a tenant-scoped contract through here.
    #[must_use]
    pub fn with_egress_contract(mut self, contract: HttpEgressContract) -> Self {
        self.egress_contract = Some(contract);
        self
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        upsert_request_header(
            &mut self.request_headers,
            "Authorization".to_string(),
            format!("Bearer {}", token.into()),
            true,
        );
        self
    }

    #[must_use]
    pub fn with_http_basic_auth(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        upsert_request_header(
            &mut self.request_headers,
            "Authorization".to_string(),
            basic_request_header_value(username.into(), password.into()),
            true,
        );
        self
    }

    #[must_use]
    pub fn with_request_header(
        mut self,
        header_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        let header_name = header_name.into();
        let sensitive = is_sensitive_redirect_header(header_name.as_str());
        upsert_request_header(&mut self.request_headers, header_name, value.into(), sensitive);
        self
    }

    #[must_use]
    pub fn with_api_key_header(
        mut self,
        header_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_header(&mut self.request_headers, header_name.into(), value.into(), true);
        self
    }

    #[must_use]
    pub fn with_request_query_param(
        mut self,
        param_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_query_param(
            &mut self.request_query_params,
            param_name.into(),
            value.into(),
        );
        self
    }

    #[must_use]
    pub fn with_api_key_query_param(
        mut self,
        param_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_query_param(
            &mut self.request_query_params,
            param_name.into(),
            value.into(),
        );
        self
    }

    #[must_use]
    pub fn with_request_cookie(
        mut self,
        cookie_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_cookie(&mut self.request_cookies, cookie_name.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_api_key_cookie(
        mut self,
        cookie_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        upsert_request_cookie(&mut self.request_cookies, cookie_name.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_oauth_client_credentials(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.oauth_client_credentials = Some(A2aOAuthClientCredentials {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        });
        self
    }

    #[must_use]
    pub fn with_oauth_scope(mut self, scope: impl Into<String>) -> Self {
        let scope = scope.into();
        if !scope.trim().is_empty() && !self.oauth_scopes.iter().any(|existing| existing == &scope)
        {
            self.oauth_scopes.push(scope);
        }
        self
    }

    #[must_use]
    pub fn with_oauth_token_endpoint(mut self, token_endpoint: impl Into<String>) -> Self {
        self.oauth_token_endpoint_override = Some(token_endpoint.into());
        self
    }

    #[must_use]
    pub fn with_tls_root_ca_pem(mut self, root_ca_pem: impl Into<String>) -> Self {
        let root_ca_pem = root_ca_pem.into();
        if !root_ca_pem.trim().is_empty() {
            self.tls_root_ca_pems.push(root_ca_pem);
        }
        self
    }

    #[must_use]
    pub fn with_mtls_client_auth_pem(
        mut self,
        cert_chain_pem: impl Into<String>,
        private_key_pem: impl Into<String>,
    ) -> Self {
        self.mutual_tls_identity = Some(A2aMutualTlsIdentity {
            cert_chain_pem: cert_chain_pem.into(),
            private_key_pem: private_key_pem.into(),
        });
        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_server_id(mut self, server_id: impl Into<String>) -> Self {
        self.server_id = Some(server_id.into());
        self
    }

    #[must_use]
    pub fn with_server_version(mut self, server_version: impl Into<String>) -> Self {
        self.server_version = server_version.into();
        self
    }

    #[must_use]
    pub fn with_partner_policy(mut self, policy: A2aPartnerPolicy) -> Self {
        self.partner_policy = Some(policy);
        self
    }

    #[must_use]
    pub fn with_task_registry_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.task_registry_path = Some(path.into());
        self
    }
}
