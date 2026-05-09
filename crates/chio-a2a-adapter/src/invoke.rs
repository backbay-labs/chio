#[derive(Debug)]
pub struct A2aAdapter {
    manifest: ToolManifest,
    agent_card: A2aAgentCard,
    agent_card_url: Url,
    selected_interface: A2aAgentInterface,
    selected_binding: A2aProtocolBinding,
    configured_headers: Vec<A2aRequestHeader>,
    configured_query_params: Vec<A2aRequestQueryParam>,
    configured_cookies: Vec<A2aRequestCookie>,
    oauth_client_credentials: Option<A2aOAuthClientCredentials>,
    oauth_scopes: Vec<String>,
    oauth_token_endpoint_override: Option<String>,
    transport_config: A2aTransportConfig,
    token_cache: Mutex<Vec<A2aCachedBearerToken>>,
    timeout: Duration,
    request_counter: AtomicU64,
    partner_policy: Option<A2aPartnerPolicy>,
    task_registry: Option<A2aTaskRegistry>,
}

impl A2aAdapter {
    pub fn discover(config: A2aAdapterConfig) -> Result<Self, AdapterError> {
        let agent_card_url = normalize_agent_card_url(&config.agent_card_url)?;
        let transport_config = A2aTransportConfig {
            default_tls_config: build_optional_default_tls_config(&config.tls_root_ca_pems)?,
            mutual_tls_config: build_optional_mutual_tls_config(
                &config.tls_root_ca_pems,
                config.mutual_tls_identity.as_ref(),
            )?,
            egress_contract: config.egress_contract.clone(),
        };
        let discovery_tls_mode = if transport_config.mutual_tls_config.is_some() {
            A2aTlsMode::MutualTls
        } else {
            A2aTlsMode::Default
        };
        let discovery_request_auth = A2aResolvedRequestAuth {
            headers: config.request_headers.clone(),
            query_params: config.request_query_params.clone(),
            cookies: config.request_cookies.clone(),
            tls_mode: discovery_tls_mode,
        };
        let agent_card = fetch_json::<A2aAgentCard>(
            &agent_card_url,
            &discovery_request_auth,
            config.timeout,
            &transport_config,
        )?;
        if agent_card.skills.is_empty() {
            return Err(AdapterError::NoSkillsAdvertised);
        }

        let (selected_interface, selected_binding) = select_supported_interface(
            &agent_card.supported_interfaces,
            config.partner_policy.as_ref(),
        )?;
        if let Some(policy) = config.partner_policy.as_ref() {
            validate_partner_policy(policy, &agent_card, &selected_interface)?;
        }
        let server_id = config
            .server_id
            .unwrap_or_else(|| derive_chio_server_id(&agent_card_url));
        let manifest = build_manifest(
            &server_id,
            &config.server_version,
            &config.public_key,
            &agent_card,
            &selected_binding,
        )?;

        Ok(Self {
            manifest,
            agent_card,
            agent_card_url,
            selected_interface,
            selected_binding,
            configured_headers: config.request_headers,
            configured_query_params: config.request_query_params,
            configured_cookies: config.request_cookies,
            oauth_client_credentials: config.oauth_client_credentials,
            oauth_scopes: config.oauth_scopes,
            oauth_token_endpoint_override: config.oauth_token_endpoint_override,
            transport_config,
            token_cache: Mutex::new(Vec::new()),
            timeout: config.timeout,
            request_counter: AtomicU64::new(0),
            partner_policy: config.partner_policy,
            task_registry: config
                .task_registry_path
                .as_ref()
                .map(|path| A2aTaskRegistry::open(path.as_path()))
                .transpose()?,
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    #[must_use]
    pub fn agent_card(&self) -> &A2aAgentCard {
        &self.agent_card
    }

    #[must_use]
    pub fn agent_card_url(&self) -> &Url {
        &self.agent_card_url
    }

    #[must_use]
    pub fn selected_interface(&self) -> &A2aAgentInterface {
        &self.selected_interface
    }

    fn partner_label(&self) -> String {
        self.partner_policy
            .as_ref()
            .map(|policy| policy.partner_id.clone())
            .filter(|value| !value.trim().is_empty())
            .or_else(|| self.agent_card_url.host_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "a2a-partner".to_string())
    }

    fn auth_context(&self, skill: &A2aAgentSkill) -> String {
        let tenant = self.selected_interface.tenant.as_deref().unwrap_or("none");
        format!(
            "partner `{}` skill `{}` interface `{}` tenant `{tenant}`",
            self.partner_label(),
            skill.id,
            self.selected_interface.url
        )
    }

    fn validate_task_binding(
        &self,
        tool_name: &str,
        task_id: &str,
        operation: &str,
    ) -> Result<(), AdapterError> {
        let Some(registry) = self.task_registry.as_ref() else {
            return Ok(());
        };
        registry.validate_follow_up(
            task_id,
            tool_name,
            self.server_id(),
            &self.selected_interface,
            &self.selected_binding,
            operation,
        )
    }

    fn record_task_activity(
        &self,
        tool_name: &str,
        response: &Value,
        source: &str,
    ) -> Result<(), AdapterError> {
        let Some(registry) = self.task_registry.as_ref() else {
            return Ok(());
        };
        let partner = self.partner_label();
        let context = A2aTaskRecordContext {
            source,
            tool_name,
            server_id: self.server_id(),
            selected_interface: &self.selected_interface,
            selected_binding: &self.selected_binding,
            partner: partner.as_str(),
        };
        registry.record_from_value(response, &context)
    }

    fn resolve_request_auth(
        &self,
        skill: &A2aAgentSkill,
    ) -> Result<A2aResolvedRequestAuth, AdapterError> {
        let Some(raw_requirements) = skill
            .security_requirements
            .as_ref()
            .or(self.agent_card.security_requirements.as_ref())
        else {
            return Ok(A2aResolvedRequestAuth {
                headers: self.configured_headers.clone(),
                query_params: self.configured_query_params.clone(),
                cookies: self.configured_cookies.clone(),
                tls_mode: A2aTlsMode::Default,
            });
        };
        let requirements = parse_security_requirements(raw_requirements)?;
        if requirements.is_empty() {
            return Ok(A2aResolvedRequestAuth {
                headers: Vec::new(),
                query_params: Vec::new(),
                cookies: Vec::new(),
                tls_mode: A2aTlsMode::Default,
            });
        }
        let Some(raw_schemes) = self.agent_card.security_schemes.as_ref() else {
            return Err(AdapterError::AuthNegotiation(format!(
                "{} declares security requirements but omits securitySchemes",
                self.auth_context(skill)
            )));
        };
        let schemes = parse_security_schemes(raw_schemes)?;
        let static_bearer = configured_bearer_header(&self.configured_headers);
        let static_basic = configured_basic_auth_header(&self.configured_headers);
        let mut errors = Vec::new();

        for requirement in requirements {
            if requirement.is_empty() {
                return Ok(A2aResolvedRequestAuth {
                    headers: Vec::new(),
                    query_params: Vec::new(),
                    cookies: Vec::new(),
                    tls_mode: A2aTlsMode::Default,
                });
            }
            let mut headers = Vec::new();
            let mut query_params = Vec::new();
            let mut cookies = Vec::new();
            let mut tls_mode = A2aTlsMode::Default;
            let mut supported = true;
            for entry in requirement {
                let Some(scheme) = schemes
                    .iter()
                    .find(|scheme| scheme.name == entry.scheme_name)
                else {
                    return Err(AdapterError::AuthNegotiation(format!(
                        "{} references unknown security scheme `{}`",
                        self.auth_context(skill),
                        entry.scheme_name
                    )));
                };
                let header = match &scheme.kind {
                    A2aSecuritySchemeKind::BearerToken => {
                        static_bearer.clone().map(Some).ok_or_else(|| {
                            AdapterError::AuthNegotiation(format!(
                                "missing bearer token for `{}`",
                                entry.scheme_name
                            ))
                        })
                    }
                    A2aSecuritySchemeKind::BasicAuth => {
                        static_basic.clone().map(Some).ok_or_else(|| {
                            AdapterError::AuthNegotiation(format!(
                                "missing HTTP Basic credentials for `{}`",
                                entry.scheme_name
                            ))
                        })
                    }
                    A2aSecuritySchemeKind::OAuthBearerToken { token_endpoint } => {
                        if let Some(header) = static_bearer.clone() {
                            Ok(Some(header))
                        } else {
                            self.acquire_oauth_bearer_header(
                                &entry.scheme_name,
                                token_endpoint.as_deref(),
                                &entry.scopes,
                            )
                            .map(Some)
                        }
                    }
                    A2aSecuritySchemeKind::OpenIdBearerToken { discovery_url } => {
                        if let Some(header) = static_bearer.clone() {
                            Ok(Some(header))
                        } else {
                            self.acquire_openid_bearer_header(
                                &entry.scheme_name,
                                discovery_url.as_str(),
                                &entry.scopes,
                            )
                            .map(Some)
                        }
                    }
                    A2aSecuritySchemeKind::ApiKeyHeader { header_name } => {
                        let Some(header) =
                            configured_named_header(&self.configured_headers, header_name)
                        else {
                            errors.push(format!(
                                "missing API key header `{header_name}` for `{}`",
                                entry.scheme_name
                            ));
                            supported = false;
                            break;
                        };
                        Ok(Some(header))
                    }
                    A2aSecuritySchemeKind::ApiKeyQuery { param_name } => {
                        let Some(query_param) =
                            configured_named_query_param(&self.configured_query_params, param_name)
                        else {
                            errors.push(format!(
                                "missing API key query parameter `{param_name}` for `{}`",
                                entry.scheme_name
                            ));
                            supported = false;
                            break;
                        };
                        query_params.push(query_param);
                        Ok(None)
                    }
                    A2aSecuritySchemeKind::ApiKeyCookie { cookie_name } => {
                        let Some(cookie) =
                            configured_named_cookie(&self.configured_cookies, cookie_name)
                        else {
                            errors.push(format!(
                                "missing API key cookie `{cookie_name}` for `{}`",
                                entry.scheme_name
                            ));
                            supported = false;
                            break;
                        };
                        cookies.push(cookie);
                        Ok(None)
                    }
                    A2aSecuritySchemeKind::MutualTls => {
                        if self.transport_config.mutual_tls_config.is_none() {
                            Err(AdapterError::AuthNegotiation(format!(
                                "missing mutual TLS client identity for `{}`",
                                entry.scheme_name
                            )))
                        } else {
                            tls_mode = A2aTlsMode::MutualTls;
                            Ok(None)
                        }
                    }
                    A2aSecuritySchemeKind::Unsupported(reason) => {
                        Err(AdapterError::AuthNegotiation(format!(
                            "unsupported A2A security scheme `{}`: {reason}",
                            entry.scheme_name
                        )))
                    }
                };
                match header {
                    Ok(header) => {
                        if let Some(header) = header {
                            headers.push(header);
                        }
                    }
                    Err(error) => {
                        errors.push(error.to_string());
                        supported = false;
                        break;
                    }
                }
            }
            if supported {
                dedupe_request_headers(&mut headers);
                dedupe_request_query_params(&mut query_params);
                dedupe_request_cookies(&mut cookies);
                return Ok(A2aResolvedRequestAuth {
                    headers,
                    query_params,
                    cookies,
                    tls_mode,
                });
            }
        }

        Err(AdapterError::AuthNegotiation(format!(
            "failed to negotiate A2A auth requirements for {}: {}",
            self.auth_context(skill),
            errors.join("; ")
        )))
    }

    fn acquire_oauth_bearer_header(
        &self,
        scheme_name: &str,
        token_endpoint: Option<&str>,
        required_scopes: &[String],
    ) -> Result<A2aRequestHeader, AdapterError> {
        let Some(credentials) = self.oauth_client_credentials.as_ref() else {
            return Err(AdapterError::AuthNegotiation(format!(
                "missing bearer token or OAuth client credentials for `{scheme_name}`"
            )));
        };
        let token_endpoint = token_endpoint
            .or(self.oauth_token_endpoint_override.as_deref())
            .ok_or_else(|| {
                AdapterError::AuthNegotiation(format!(
                    "A2A OAuth scheme `{scheme_name}` does not declare a token endpoint and no override was configured"
                ))
            })?;
        let token_endpoint = parse_remote_url(
            token_endpoint,
            &format!("OAuth token endpoint for `{scheme_name}`"),
        )?;
        let scopes = merged_oauth_scopes(required_scopes, &self.oauth_scopes);
        let cache_key = oauth_cache_key(scheme_name, &token_endpoint, &scopes);
        if let Some(access_token) = self.lookup_cached_bearer_token(&cache_key)? {
            return Ok(bearer_request_header(access_token));
        }

        let response = request_client_credentials_token(
            &token_endpoint,
            credentials,
            &scopes,
            self.timeout,
            &self.transport_config,
        )?;
        if let Some(token_type) = response.token_type.as_deref() {
            if !token_type.eq_ignore_ascii_case("bearer") {
                return Err(AdapterError::AuthNegotiation(format!(
                    "token endpoint for `{scheme_name}` returned unsupported token type `{token_type}`"
                )));
            }
        }
        self.store_cached_bearer_token(
            cache_key,
            response.access_token.clone(),
            response.expires_in,
        )?;
        Ok(bearer_request_header(response.access_token))
    }

    fn acquire_openid_bearer_header(
        &self,
        scheme_name: &str,
        discovery_url: &str,
        required_scopes: &[String],
    ) -> Result<A2aRequestHeader, AdapterError> {
        let discovery_url = parse_remote_url(
            discovery_url,
            &format!("OpenID discovery URL for `{scheme_name}`"),
        )?;
        let metadata = fetch_json::<A2aOpenIdConfiguration>(
            &discovery_url,
            &A2aResolvedRequestAuth {
                headers: Vec::new(),
                query_params: Vec::new(),
                cookies: Vec::new(),
                tls_mode: A2aTlsMode::Default,
            },
            self.timeout,
            &self.transport_config,
        )?;
        self.acquire_oauth_bearer_header(
            scheme_name,
            Some(metadata.token_endpoint.as_str()),
            required_scopes,
        )
    }

    fn lookup_cached_bearer_token(&self, cache_key: &str) -> Result<Option<String>, AdapterError> {
        let now = SystemTime::now();
        let mut cache = self.token_cache.lock().map_err(|_| {
            AdapterError::AuthNegotiation("OAuth token cache lock poisoned".to_string())
        })?;
        cache.retain(|entry| {
            entry
                .expires_at
                .map(|expires_at| expires_at > now)
                .unwrap_or(true)
        });
        Ok(cache
            .iter()
            .find(|entry| entry.cache_key == cache_key)
            .map(|entry| entry.access_token.clone()))
    }

    fn store_cached_bearer_token(
        &self,
        cache_key: String,
        access_token: String,
        expires_in: Option<u64>,
    ) -> Result<(), AdapterError> {
        let expires_at = expires_in.and_then(|expires_in| {
            let effective_ttl = expires_in.saturating_sub(OAUTH_CACHE_SKEW_SECS);
            if effective_ttl == 0 {
                None
            } else {
                Some(SystemTime::now() + Duration::from_secs(effective_ttl))
            }
        });
        let mut cache = self.token_cache.lock().map_err(|_| {
            AdapterError::AuthNegotiation("OAuth token cache lock poisoned".to_string())
        })?;
        if let Some(existing) = cache.iter_mut().find(|entry| entry.cache_key == cache_key) {
            existing.access_token = access_token;
            existing.expires_at = expires_at;
        } else {
            cache.push(A2aCachedBearerToken {
                cache_key,
                access_token,
                expires_at,
            });
        }
        Ok(())
    }

    fn invoke_skill(
        &self,
        tool_name: &str,
        skill: &A2aAgentSkill,
        arguments: Value,
    ) -> Result<Value, AdapterError> {
        let request_auth = self.resolve_request_auth(skill)?;
        match parse_tool_input(arguments)? {
            A2aToolInvocation::SendMessage(input) => {
                if let Some(task_id) = input.task_id.as_deref() {
                    self.validate_task_binding(tool_name, task_id, "send_message.task_id")?;
                }
                let request = self.build_send_message_request(skill, input)?;
                let response = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => self.invoke_jsonrpc(request, &request_auth),
                    A2aProtocolBinding::HttpJson => self.invoke_http_json(request, &request_auth),
                }?;
                let value = serde_json::to_value(response).map_err(|error| {
                    AdapterError::Protocol(format!("failed to encode A2A response: {error}"))
                })?;
                self.record_task_activity(tool_name, &value, "send_message")?;
                Ok(value)
            }
            A2aToolInvocation::GetTask(input) => {
                self.validate_task_binding(tool_name, &input.id, "get_task")?;
                let task = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => self.get_task_jsonrpc(input, &request_auth)?,
                    A2aProtocolBinding::HttpJson => {
                        self.get_task_http_json(input, &request_auth)?
                    }
                };
                let value = json!({ "task": task });
                self.record_task_activity(tool_name, &value, "get_task")?;
                Ok(value)
            }
            A2aToolInvocation::SubscribeTask(_) => Err(AdapterError::InvalidToolInput(
                "`subscribe_task` requires a streaming tool invocation".to_string(),
            )),
            A2aToolInvocation::CancelTask(input) => {
                self.validate_task_binding(tool_name, &input.id, "cancel_task")?;
                let task = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.cancel_task_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.cancel_task_http_json(input, &request_auth)?
                    }
                };
                let value = json!({ "task": task });
                self.record_task_activity(tool_name, &value, "cancel_task")?;
                Ok(value)
            }
            A2aToolInvocation::CreatePushNotificationConfig(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "create_push_notification_config",
                )?;
                let config = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.create_push_notification_config_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.create_push_notification_config_http_json(input, &request_auth)?
                    }
                };
                Ok(json!({ "push_notification_config": config }))
            }
            A2aToolInvocation::GetPushNotificationConfig(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "get_push_notification_config",
                )?;
                let config = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.get_push_notification_config_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.get_push_notification_config_http_json(input, &request_auth)?
                    }
                };
                Ok(json!({ "push_notification_config": config }))
            }
            A2aToolInvocation::ListPushNotificationConfigs(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "list_push_notification_configs",
                )?;
                let response = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.list_push_notification_configs_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.list_push_notification_configs_http_json(input, &request_auth)?
                    }
                };
                Ok(json!({
                    "push_notification_configs": response.configs,
                    "next_page_token": response.next_page_token
                }))
            }
            A2aToolInvocation::DeletePushNotificationConfig(input) => {
                self.ensure_push_notifications_supported()?;
                self.validate_task_binding(
                    tool_name,
                    &input.task_id,
                    "delete_push_notification_config",
                )?;
                match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.delete_push_notification_config_jsonrpc(input, &request_auth)?
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.delete_push_notification_config_http_json(input, &request_auth)?
                    }
                }
                Ok(json!({ "deleted": true }))
            }
        }
    }

    fn ensure_push_notifications_supported(&self) -> Result<(), AdapterError> {
        if self.agent_card.capabilities.push_notifications {
            Ok(())
        } else {
            Err(AdapterError::Protocol(
                "A2A agent card does not advertise push notification support".to_string(),
            ))
        }
    }

    fn ensure_state_transition_history_supported(&self) -> Result<(), AdapterError> {
        if self.agent_card.capabilities.state_transition_history {
            Ok(())
        } else {
            Err(AdapterError::Protocol(
                "A2A agent card does not advertise state transition history support".to_string(),
            ))
        }
    }

    fn build_send_message_request(
        &self,
        skill: &A2aAgentSkill,
        input: A2aSendToolInput,
    ) -> Result<A2aSendMessageRequest, AdapterError> {
        if input.history_length.is_some() {
            self.ensure_state_transition_history_supported()?;
        }
        let mut parts = Vec::new();
        if let Some(message) = input.message {
            parts.push(A2aPart {
                text: Some(message),
                raw: None,
                url: None,
                data: None,
                metadata: None,
                filename: None,
                media_type: Some("text/plain".to_string()),
            });
        }
        if let Some(data) = input.data {
            parts.push(A2aPart {
                text: None,
                raw: None,
                url: None,
                data: Some(data),
                metadata: None,
                filename: None,
                media_type: Some("application/json".to_string()),
            });
        }
        if parts.is_empty() {
            return Err(AdapterError::InvalidToolInput(
                "A2A tools require at least one of `message` or `data`".to_string(),
            ));
        }

        let accepted_output_modes = skill
            .output_modes
            .clone()
            .filter(|modes| !modes.is_empty())
            .unwrap_or_else(|| self.agent_card.default_output_modes.clone());
        let configuration = if accepted_output_modes.is_empty()
            && input.history_length.is_none()
            && input.return_immediately.is_none()
        {
            None
        } else {
            Some(A2aSendMessageConfiguration {
                accepted_output_modes: if accepted_output_modes.is_empty() {
                    None
                } else {
                    Some(accepted_output_modes)
                },
                history_length: input.history_length,
                return_immediately: input.return_immediately,
            })
        };

        Ok(A2aSendMessageRequest {
            tenant: self.selected_interface.tenant.clone(),
            message: A2aMessage {
                message_id: next_message_id(
                    &self.request_counter,
                    self.manifest.server_id.as_str(),
                    skill.id.as_str(),
                ),
                context_id: input.context_id,
                task_id: input.task_id,
                role: "ROLE_USER".to_string(),
                parts,
                metadata: validate_object_metadata("message_metadata", input.message_metadata)?,
                extensions: None,
                reference_task_ids: input.reference_task_ids,
            },
            configuration,
            metadata: Some(merge_skill_routing_metadata(input.metadata, skill)?),
        })
    }

    fn get_task_jsonrpc(
        &self,
        input: A2aGetTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        if input.history_length.is_some() {
            self.ensure_state_transition_history_supported()?;
        }
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "GetTask",
            params: A2aGetTaskRequest {
                id: input.id,
                tenant: self.selected_interface.tenant.clone(),
                history_length: input.history_length,
            },
        };
        let response: A2aJsonRpcResponse<Value> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
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
        let task = response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC GetTask response omitted `result`".to_string())
        })?;
        validate_task_response(task)
    }

    fn get_task_http_json(
        &self,
        input: A2aGetTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        if input.history_length.is_some() {
            self.ensure_state_transition_history_supported()?;
        }
        let endpoint = build_get_task_url(
            self.selected_interface.url.as_str(),
            input.id.as_str(),
            self.selected_interface.tenant.as_deref(),
            input.history_length,
        )?;
        let task = fetch_json(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        validate_task_response(task)
    }

    fn cancel_task_jsonrpc(
        &self,
        input: A2aCancelTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "CancelTask",
            params: A2aCancelTaskRequest {
                tenant: self.selected_interface.tenant.clone(),
                id: validate_identifier("cancel_task.id", input.id)?,
                metadata: validate_object_metadata("cancel_task.metadata", input.metadata)?,
            },
        };
        let response: A2aJsonRpcResponse<Value> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
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
        let task = response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC CancelTask response omitted `result`".to_string())
        })?;
        validate_task_response(task)
    }

    fn cancel_task_http_json(
        &self,
        input: A2aCancelTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<Value, AdapterError> {
        let task_id = validate_identifier("cancel_task.id", input.id)?;
        let endpoint = build_cancel_task_url(
            self.selected_interface.url.as_str(),
            task_id.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        let body = A2aCancelTaskRequest {
            tenant: None,
            id: task_id,
            metadata: validate_object_metadata("cancel_task.metadata", input.metadata)?,
        };
        let task = post_json(
            endpoint.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        validate_task_response(task)
    }

    fn create_push_notification_config_jsonrpc(
        &self,
        input: A2aCreatePushNotificationConfigToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let config = self.build_push_notification_config(input)?;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "CreateTaskPushNotificationConfig",
            params: config,
        };
        let response: A2aJsonRpcResponse<A2aTaskPushNotificationConfig> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
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
            AdapterError::Protocol(
                "A2A JSON-RPC CreateTaskPushNotificationConfig response omitted `result`"
                    .to_string(),
            )
        })
    }

    fn create_push_notification_config_http_json(
        &self,
        input: A2aCreatePushNotificationConfigToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let config = self.build_push_notification_config(input)?;
        let endpoint = build_push_notification_configs_url(
            self.selected_interface.url.as_str(),
            config.task_id.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        post_json(
            endpoint.as_str(),
            &config,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn get_push_notification_config_jsonrpc(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "GetTaskPushNotificationConfig",
            params: A2aGetTaskPushNotificationConfigRequest {
                tenant: self.selected_interface.tenant.clone(),
                task_id: validate_identifier(
                    "get_push_notification_config.task_id",
                    input.task_id,
                )?,
                id: validate_identifier("get_push_notification_config.id", input.id)?,
            },
        };
        let response: A2aJsonRpcResponse<A2aTaskPushNotificationConfig> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
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
            AdapterError::Protocol(
                "A2A JSON-RPC GetTaskPushNotificationConfig response omitted `result`".to_string(),
            )
        })
    }

    fn get_push_notification_config_http_json(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        let endpoint = build_push_notification_config_url(
            self.selected_interface.url.as_str(),
            validate_identifier("get_push_notification_config.task_id", input.task_id)?.as_str(),
            validate_identifier("get_push_notification_config.id", input.id)?.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        fetch_json(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn list_push_notification_configs_jsonrpc(
        &self,
        input: A2aListPushNotificationConfigsToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aListTaskPushNotificationConfigsResponse, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "ListTaskPushNotificationConfigs",
            params: A2aListTaskPushNotificationConfigsRequest {
                tenant: self.selected_interface.tenant.clone(),
                task_id: validate_identifier(
                    "list_push_notification_configs.task_id",
                    input.task_id,
                )?,
                page_size: input.page_size,
                page_token: input.page_token,
            },
        };
        let response: A2aJsonRpcResponse<A2aListTaskPushNotificationConfigsResponse> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
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
            AdapterError::Protocol(
                "A2A JSON-RPC ListTaskPushNotificationConfigs response omitted `result`"
                    .to_string(),
            )
        })
    }

    fn list_push_notification_configs_http_json(
        &self,
        input: A2aListPushNotificationConfigsToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aListTaskPushNotificationConfigsResponse, AdapterError> {
        let endpoint = build_list_push_notification_configs_url(
            self.selected_interface.url.as_str(),
            validate_identifier("list_push_notification_configs.task_id", input.task_id)?.as_str(),
            self.selected_interface.tenant.as_deref(),
            input.page_size,
            input.page_token.as_deref(),
        )?;
        fetch_json(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn delete_push_notification_config_jsonrpc(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<(), AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "DeleteTaskPushNotificationConfig",
            params: A2aDeleteTaskPushNotificationConfigRequest {
                tenant: self.selected_interface.tenant.clone(),
                task_id: validate_identifier(
                    "delete_push_notification_config.task_id",
                    input.task_id,
                )?,
                id: validate_identifier("delete_push_notification_config.id", input.id)?,
            },
        };
        let response: A2aJsonRpcResponse<Value> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
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
        Ok(())
    }

    fn delete_push_notification_config_http_json(
        &self,
        input: A2aPushNotificationConfigRefToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<(), AdapterError> {
        let endpoint = build_push_notification_config_url(
            self.selected_interface.url.as_str(),
            validate_identifier("delete_push_notification_config.task_id", input.task_id)?.as_str(),
            validate_identifier("delete_push_notification_config.id", input.id)?.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        delete_empty(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
        )
    }

    fn build_push_notification_config(
        &self,
        input: A2aCreatePushNotificationConfigToolInput,
    ) -> Result<A2aTaskPushNotificationConfig, AdapterError> {
        Ok(A2aTaskPushNotificationConfig {
            tenant: self.selected_interface.tenant.clone(),
            id: match input.id {
                Some(id) => Some(validate_identifier(
                    "create_push_notification_config.id",
                    id,
                )?),
                None => None,
            },
            task_id: validate_identifier("create_push_notification_config.task_id", input.task_id)?,
            url: validate_notification_target_url(input.url.as_str())?,
            token: input.token.filter(|value| !value.trim().is_empty()),
            authentication: validate_authentication_info(input.authentication)?,
        })
    }

    fn invoke_stream_jsonrpc(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "SendStreamingMessage",
            params: request,
        };
        post_sse_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
            |value| {
                let response: A2aJsonRpcResponse<Value> =
                    serde_json::from_value(value).map_err(|error| {
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
            },
        )
    }

    fn invoke_stream_http_json(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let endpoint = build_send_message_url(
            self.selected_interface.url.as_str(),
            self.selected_interface.tenant.as_deref(),
            true,
        )?;
        post_sse_json(
            endpoint.as_str(),
            &request,
            request_auth,
            self.timeout,
            &self.transport_config,
            Ok,
        )
    }

    fn invoke_jsonrpc(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aSendMessageResponse, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "SendMessage",
            params: request,
        };
        let response: A2aJsonRpcResponse<A2aSendMessageResponse> = post_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
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
        let response = response.result.ok_or_else(|| {
            AdapterError::Protocol("A2A JSON-RPC response omitted `result`".to_string())
        })?;
        validate_send_message_response(response)
    }

    fn invoke_http_json(
        &self,
        request: A2aSendMessageRequest,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<A2aSendMessageResponse, AdapterError> {
        let endpoint = build_send_message_url(
            self.selected_interface.url.as_str(),
            self.selected_interface.tenant.as_deref(),
            false,
        )?;
        let response = post_json(
            endpoint.as_str(),
            &request,
            request_auth,
            self.timeout,
            &self.transport_config,
        )?;
        validate_send_message_response(response)
    }

    fn subscribe_task_jsonrpc(
        &self,
        input: A2aSubscribeTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let request_id = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let body = A2aJsonRpcRequest {
            jsonrpc: "2.0",
            id: request_id,
            method: "SubscribeToTask",
            params: A2aSubscribeToTaskRequest {
                tenant: self.selected_interface.tenant.clone(),
                id: input.id,
            },
        };
        post_sse_json(
            self.selected_interface.url.as_str(),
            &body,
            request_auth,
            self.timeout,
            &self.transport_config,
            |value| {
                let response: A2aJsonRpcResponse<Value> =
                    serde_json::from_value(value).map_err(|error| {
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
            },
        )
    }

    fn subscribe_task_http_json(
        &self,
        input: A2aSubscribeTaskToolInput,
        request_auth: &A2aResolvedRequestAuth,
    ) -> Result<ToolServerStreamResult, AdapterError> {
        let endpoint = build_subscribe_task_url(
            self.selected_interface.url.as_str(),
            input.id.as_str(),
            self.selected_interface.tenant.as_deref(),
        )?;
        get_sse(
            &endpoint,
            request_auth,
            self.timeout,
            &self.transport_config,
            Ok,
        )
    }
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for A2aAdapter {
    fn server_id(&self) -> &str {
        &self.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let Some(skill) = self
            .agent_card
            .skills
            .iter()
            .find(|skill| skill.id == tool_name)
        else {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        };
        let response = self
            .invoke_skill(tool_name, skill, arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        Ok(response)
    }

    async fn invoke_stream(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let Some(skill) = self
            .agent_card
            .skills
            .iter()
            .find(|skill| skill.id == tool_name)
        else {
            return Err(KernelError::ToolNotRegistered(tool_name.to_string()));
        };
        let invocation = parse_tool_input(arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        let request_auth = self
            .resolve_request_auth(skill)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        match invocation {
            A2aToolInvocation::SendMessage(input) => {
                if !input.stream {
                    return Ok(None);
                }
                if !self.agent_card.capabilities.streaming {
                    return Err(KernelError::ToolServerError(
                        "A2A server does not advertise streaming support".to_string(),
                    ));
                }
                if let Some(task_id) = input.task_id.as_deref() {
                    self.validate_task_binding(tool_name, task_id, "send_streaming_message.task_id")
                        .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                }

                let request = self
                    .build_send_message_request(skill, input)
                    .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                let result = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.invoke_stream_jsonrpc(request, &request_auth)
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.invoke_stream_http_json(request, &request_auth)
                    }
                }
                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                match &result {
                    ToolServerStreamResult::Complete(stream)
                    | ToolServerStreamResult::Incomplete { stream, .. } => {
                        for chunk in &stream.chunks {
                            self.record_task_activity(tool_name, &chunk.data, "stream_event")
                                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                        }
                    }
                }
                Ok(Some(result))
            }
            A2aToolInvocation::SubscribeTask(input) => {
                if !self.agent_card.capabilities.streaming {
                    return Err(KernelError::ToolServerError(
                        "A2A server does not advertise streaming support".to_string(),
                    ));
                }
                self.validate_task_binding(tool_name, &input.id, "subscribe_task")
                    .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                let result = match self.selected_binding {
                    A2aProtocolBinding::JsonRpc => {
                        self.subscribe_task_jsonrpc(input, &request_auth)
                    }
                    A2aProtocolBinding::HttpJson => {
                        self.subscribe_task_http_json(input, &request_auth)
                    }
                }
                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                match &result {
                    ToolServerStreamResult::Complete(stream)
                    | ToolServerStreamResult::Incomplete { stream, .. } => {
                        for chunk in &stream.chunks {
                            self.record_task_activity(tool_name, &chunk.data, "subscribe_event")
                                .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                        }
                    }
                }
                Ok(Some(result))
            }
            A2aToolInvocation::GetTask(_)
            | A2aToolInvocation::CancelTask(_)
            | A2aToolInvocation::CreatePushNotificationConfig(_)
            | A2aToolInvocation::GetPushNotificationConfig(_)
            | A2aToolInvocation::ListPushNotificationConfigs(_)
            | A2aToolInvocation::DeletePushNotificationConfig(_) => Ok(None),
        }
    }
}
