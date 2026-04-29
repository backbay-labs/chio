#[derive(Debug, Clone, Deserialize)]
struct A2aToolInput {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default, alias = "contextId")]
    context_id: Option<String>,
    #[serde(default, alias = "taskId")]
    task_id: Option<String>,
    #[serde(default, alias = "referenceTaskIds")]
    reference_task_ids: Option<Vec<String>>,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default, alias = "messageMetadata")]
    message_metadata: Option<Value>,
    #[serde(default, alias = "historyLength")]
    history_length: Option<u32>,
    #[serde(default, alias = "returnImmediately")]
    return_immediately: Option<bool>,
    #[serde(default)]
    stream: Option<bool>,
    #[serde(default, alias = "getTask")]
    get_task: Option<A2aGetTaskToolInput>,
    #[serde(default, alias = "subscribeTask")]
    subscribe_task: Option<A2aSubscribeTaskToolInput>,
    #[serde(default, alias = "cancelTask")]
    cancel_task: Option<A2aCancelTaskToolInput>,
    #[serde(default, alias = "createPushNotificationConfig")]
    create_push_notification_config: Option<A2aCreatePushNotificationConfigToolInput>,
    #[serde(default, alias = "getPushNotificationConfig")]
    get_push_notification_config: Option<A2aPushNotificationConfigRefToolInput>,
    #[serde(default, alias = "listPushNotificationConfigs")]
    list_push_notification_configs: Option<A2aListPushNotificationConfigsToolInput>,
    #[serde(default, alias = "deletePushNotificationConfig")]
    delete_push_notification_config: Option<A2aPushNotificationConfigRefToolInput>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aGetTaskToolInput {
    id: String,
    #[serde(default, alias = "historyLength")]
    history_length: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aSubscribeTaskToolInput {
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aCancelTaskToolInput {
    id: String,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aAuthenticationInfoToolInput {
    scheme: String,
    #[serde(default)]
    credentials: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aCreatePushNotificationConfigToolInput {
    task_id: String,
    #[serde(default)]
    id: Option<String>,
    url: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    authentication: Option<A2aAuthenticationInfoToolInput>,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aPushNotificationConfigRefToolInput {
    task_id: String,
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct A2aListPushNotificationConfigsToolInput {
    task_id: String,
    #[serde(default, alias = "pageSize")]
    page_size: Option<u32>,
    #[serde(default, alias = "pageToken")]
    page_token: Option<String>,
}

#[derive(Debug, Clone)]
struct A2aSendToolInput {
    message: Option<String>,
    data: Option<Value>,
    context_id: Option<String>,
    task_id: Option<String>,
    reference_task_ids: Option<Vec<String>>,
    metadata: Option<Value>,
    message_metadata: Option<Value>,
    history_length: Option<u32>,
    return_immediately: Option<bool>,
    stream: bool,
}

#[derive(Debug, Clone)]
enum A2aToolInvocation {
    SendMessage(A2aSendToolInput),
    GetTask(A2aGetTaskToolInput),
    SubscribeTask(A2aSubscribeTaskToolInput),
    CancelTask(A2aCancelTaskToolInput),
    CreatePushNotificationConfig(A2aCreatePushNotificationConfigToolInput),
    GetPushNotificationConfig(A2aPushNotificationConfigRefToolInput),
    ListPushNotificationConfigs(A2aListPushNotificationConfigsToolInput),
    DeletePushNotificationConfig(A2aPushNotificationConfigRefToolInput),
}

#[derive(Debug, Clone)]
struct A2aParsedSecurityScheme {
    name: String,
    kind: A2aSecuritySchemeKind,
}

#[derive(Debug, Clone)]
struct A2aSecurityRequirementEntry {
    scheme_name: String,
    scopes: Vec<String>,
}

#[derive(Debug, Clone)]
enum A2aSecuritySchemeKind {
    BearerToken,
    BasicAuth,
    OAuthBearerToken { token_endpoint: Option<String> },
    OpenIdBearerToken { discovery_url: String },
    ApiKeyHeader { header_name: String },
    ApiKeyQuery { param_name: String },
    ApiKeyCookie { cookie_name: String },
    MutualTls,
    Unsupported(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("invalid A2A URL: {0}")]
    InvalidUrl(String),

    #[error("A2A protocol binding is not supported: {0}")]
    UnsupportedBinding(String),

    #[error("A2A protocol version is not supported: {0}")]
    UnsupportedVersion(String),

    #[error("no supported A2A interfaces were advertised")]
    NoSupportedInterfaces,

    #[error("A2A agent card advertised no skills")]
    NoSkillsAdvertised,

    #[error("invalid A2A tool input: {0}")]
    InvalidToolInput(String),

    #[error("A2A remote request failed: {0}")]
    Remote(String),

    #[error("A2A protocol error: {0}")]
    Protocol(String),

    #[error("A2A auth negotiation failed: {0}")]
    AuthNegotiation(String),

    #[error("A2A partner admission failed: {0}")]
    PartnerAdmission(String),

    #[error("A2A lifecycle correlation failed: {0}")]
    Lifecycle(String),
}

fn build_manifest(
    server_id: &str,
    server_version: &str,
    public_key: &str,
    agent_card: &A2aAgentCard,
    binding: &A2aProtocolBinding,
) -> Result<ToolManifest, AdapterError> {
    let binding_name = match binding {
        A2aProtocolBinding::JsonRpc => "JSONRPC",
        A2aProtocolBinding::HttpJson => "HTTP+JSON",
    };
    let manifest = ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: server_id.to_string(),
        name: format!("{} (A2A)", agent_card.name),
        description: Some(format!(
            "{}\n\nDiscovered from A2A Agent Card. Skill routing uses metadata.chio.targetSkillId on top of the core A2A SendMessage request. Preferred binding: {binding_name}.",
            agent_card.description
        )),
        version: server_version.to_string(),
        tools: agent_card.skills.iter().map(build_tool_definition).collect(),
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: public_key.to_string(),
    };
    validate_manifest(&manifest)
        .map_err(|error| AdapterError::Protocol(format!("invalid generated manifest: {error}")))?;
    Ok(manifest)
}

fn build_tool_definition(skill: &A2aAgentSkill) -> ToolDefinition {
    let mut description = skill.description.clone();
    if !skill.tags.is_empty() {
        description.push_str(&format!("\n\nTags: {}", skill.tags.join(", ")));
    }
    if let Some(examples) = skill.examples.as_ref().filter(|examples| !examples.is_empty()) {
        description.push_str(&format!("\n\nExamples: {}", examples.join(" | ")));
    }

    ToolDefinition {
        name: skill.id.clone(),
        description,
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Plain-text user content to send as an A2A text Part."
                },
                "data": {
                    "description": "Structured JSON payload to send as an A2A data Part."
                },
                "context_id": { "type": "string" },
                "task_id": { "type": "string" },
                "reference_task_ids": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "metadata": {
                    "type": "object",
                    "description": "Top-level A2A SendMessageRequest metadata. The adapter will merge metadata.chio.targetSkillId."
                },
                "message_metadata": {
                    "type": "object",
                    "description": "Metadata attached directly to the A2A Message."
                },
                "history_length": {
                    "type": "integer",
                    "minimum": 0
                },
                "return_immediately": { "type": "boolean" },
                "stream": {
                    "type": "boolean",
                    "description": "When true, use A2A SendStreamingMessage and surface each A2A StreamResponse as one Chio stream chunk."
                },
                "get_task": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string" },
                        "history_length": {
                            "type": "integer",
                            "minimum": 0
                        }
                    },
                    "required": ["id"],
                    "description": "Adapter-local follow-up mode that issues A2A GetTask instead of SendMessage."
                },
                "subscribe_task": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string" }
                    },
                    "required": ["id"],
                    "description": "Adapter-local streaming follow-up mode that issues A2A SubscribeToTask instead of SendMessage."
                },
                "cancel_task": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "id": { "type": "string" },
                        "metadata": { "type": "object" }
                    },
                    "required": ["id"],
                    "description": "Adapter-local follow-up mode that issues A2A CancelTask."
                },
                "create_push_notification_config": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "id": { "type": "string" },
                        "url": { "type": "string" },
                        "token": { "type": "string" },
                        "authentication": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "scheme": { "type": "string" },
                                "credentials": { "type": "string" }
                            },
                            "required": ["scheme"]
                        }
                    },
                    "required": ["task_id", "url"],
                    "description": "Adapter-local follow-up mode that issues A2A CreateTaskPushNotificationConfig."
                },
                "get_push_notification_config": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "id": { "type": "string" }
                    },
                    "required": ["task_id", "id"],
                    "description": "Adapter-local follow-up mode that issues A2A GetTaskPushNotificationConfig."
                },
                "list_push_notification_configs": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "page_size": { "type": "integer", "minimum": 0 },
                        "page_token": { "type": "string" }
                    },
                    "required": ["task_id"],
                    "description": "Adapter-local follow-up mode that issues A2A ListTaskPushNotificationConfigs."
                },
                "delete_push_notification_config": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "task_id": { "type": "string" },
                        "id": { "type": "string" }
                    },
                    "required": ["task_id", "id"],
                    "description": "Adapter-local follow-up mode that issues A2A DeleteTaskPushNotificationConfig."
                }
            },
            "oneOf": [
                { "required": ["delete_push_notification_config"] },
                { "required": ["list_push_notification_configs"] },
                { "required": ["get_push_notification_config"] },
                { "required": ["create_push_notification_config"] },
                { "required": ["cancel_task"] },
                { "required": ["subscribe_task"] },
                { "required": ["get_task"] },
                {
                    "anyOf": [
                        { "required": ["message"] },
                        { "required": ["data"] }
                    ]
                }
            ]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "task": { "type": "object" },
                "message": { "type": "object" },
                "push_notification_config": { "type": "object" },
                "push_notification_configs": {
                    "type": "array",
                    "items": { "type": "object" }
                },
                "next_page_token": { "type": "string" },
                "deleted": { "type": "boolean" }
            }
        })),
        pricing: None,
        has_side_effects: true,
        latency_hint: Some(LatencyHint::Moderate),
    }
}

fn interface_origin(url: &str) -> Result<String, AdapterError> {
    let url = Url::parse(url).map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
    let host = url.host_str().ok_or_else(|| {
        AdapterError::InvalidUrl(format!("A2A interface URL is missing a host: {url}"))
    })?;
    let mut origin = format!("{}://{host}", url.scheme());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn partner_policy_allows_interface(
    policy: Option<&A2aPartnerPolicy>,
    interface: &A2aAgentInterface,
) -> Result<bool, AdapterError> {
    let Some(policy) = policy else {
        return Ok(true);
    };
    if policy.allowed_interface_origins.is_empty() {
        return Ok(true);
    }
    let origin = interface_origin(&interface.url)?;
    Ok(policy
        .allowed_interface_origins
        .iter()
        .any(|allowed| allowed == &origin))
}

fn validate_partner_policy(
    policy: &A2aPartnerPolicy,
    agent_card: &A2aAgentCard,
    selected_interface: &A2aAgentInterface,
) -> Result<(), AdapterError> {
    if let Some(required_tenant) = policy.required_tenant.as_deref() {
        if selected_interface.tenant.as_deref() != Some(required_tenant) {
            return Err(AdapterError::PartnerAdmission(format!(
                "partner `{}` requires tenant `{required_tenant}`, but the selected interface advertises `{}`",
                policy.partner_id,
                selected_interface.tenant.as_deref().unwrap_or("none")
            )));
        }
    }
    for skill_id in &policy.required_skills {
        if !agent_card.skills.iter().any(|skill| &skill.id == skill_id) {
            return Err(AdapterError::PartnerAdmission(format!(
                "partner `{}` requires advertised skill `{skill_id}`, but it was missing from the Agent Card",
                policy.partner_id
            )));
        }
    }
    if !policy.required_security_scheme_names.is_empty() {
        let raw_schemes = agent_card.security_schemes.as_ref().ok_or_else(|| {
            AdapterError::PartnerAdmission(format!(
                "partner `{}` requires explicit security schemes, but the Agent Card omits securitySchemes",
                policy.partner_id
            ))
        })?;
        let schemes = parse_security_schemes(raw_schemes)?;
        let requirements = agent_card
            .security_requirements
            .as_ref()
            .map(parse_security_requirements)
            .transpose()?;
        for scheme_name in &policy.required_security_scheme_names {
            if !schemes.iter().any(|scheme| &scheme.name == scheme_name) {
                return Err(AdapterError::PartnerAdmission(format!(
                    "partner `{}` requires security scheme `{scheme_name}`, but it was not declared",
                    policy.partner_id
                )));
            }
            if let Some(requirements) = requirements.as_ref() {
                let referenced = requirements.iter().any(|requirement| {
                    requirement
                        .iter()
                        .any(|entry| &entry.scheme_name == scheme_name)
                });
                if !referenced {
                    return Err(AdapterError::PartnerAdmission(format!(
                        "partner `{}` requires security scheme `{scheme_name}`, but no A2A security requirement references it",
                        policy.partner_id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn select_supported_interface(
    interfaces: &[A2aAgentInterface],
    partner_policy: Option<&A2aPartnerPolicy>,
) -> Result<(A2aAgentInterface, A2aProtocolBinding), AdapterError> {
    for interface in interfaces {
        if !interface.protocol_version.starts_with(A2A_PROTOCOL_MAJOR) {
            continue;
        }
        let binding = match interface.protocol_binding.to_ascii_uppercase().as_str() {
            "JSONRPC" => A2aProtocolBinding::JsonRpc,
            "HTTP+JSON" => A2aProtocolBinding::HttpJson,
            _ => continue,
        };
        let url = Url::parse(&interface.url)
            .map_err(|error| AdapterError::InvalidUrl(error.to_string()))?;
        validate_remote_url(&url)?;
        if !partner_policy_allows_interface(partner_policy, interface)? {
            continue;
        }
        return Ok((interface.clone(), binding));
    }

    if let Some(interface) = interfaces.first() {
        if !interface.protocol_version.starts_with(A2A_PROTOCOL_MAJOR) {
            return Err(AdapterError::UnsupportedVersion(
                interface.protocol_version.clone(),
            ));
        }
        if let Some(policy) = partner_policy {
            if !policy.allowed_interface_origins.is_empty() {
                return Err(AdapterError::PartnerAdmission(format!(
                    "partner `{}` did not advertise any supported interface under {}",
                    policy.partner_id,
                    policy.allowed_interface_origins.join(", ")
                )));
            }
        }
        return Err(AdapterError::UnsupportedBinding(
            interface.protocol_binding.clone(),
        ));
    }
    Err(AdapterError::NoSupportedInterfaces)
}

fn parse_tool_input(arguments: Value) -> Result<A2aToolInvocation, AdapterError> {
    let input: A2aToolInput = serde_json::from_value(arguments)
        .map_err(|error| AdapterError::InvalidToolInput(error.to_string()))?;
    let mixed_send_fields = send_message_fields_present(&input);
    let active_management_modes = [
        input.get_task.is_some(),
        input.subscribe_task.is_some(),
        input.cancel_task.is_some(),
        input.create_push_notification_config.is_some(),
        input.get_push_notification_config.is_some(),
        input.list_push_notification_configs.is_some(),
        input.delete_push_notification_config.is_some(),
    ]
    .into_iter()
    .filter(|active| *active)
    .count();

    if active_management_modes > 1 {
        return Err(AdapterError::InvalidToolInput(
            "A2A follow-up and task-management modes are mutually exclusive".to_string(),
        ));
    }

    if let Some(subscribe_task) = input.subscribe_task {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`subscribe_task` is mutually exclusive with SendMessage and `get_task` fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::SubscribeTask(subscribe_task));
    }

    if let Some(get_task) = input.get_task {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`get_task` is mutually exclusive with SendMessage fields".to_string(),
            ));
        }
        return Ok(A2aToolInvocation::GetTask(get_task));
    }

    if let Some(cancel_task) = input.cancel_task {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`cancel_task` is mutually exclusive with SendMessage fields".to_string(),
            ));
        }
        return Ok(A2aToolInvocation::CancelTask(cancel_task));
    }

    if let Some(create_push_notification_config) = input.create_push_notification_config {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`create_push_notification_config` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::CreatePushNotificationConfig(
            create_push_notification_config,
        ));
    }

    if let Some(get_push_notification_config) = input.get_push_notification_config {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`get_push_notification_config` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::GetPushNotificationConfig(
            get_push_notification_config,
        ));
    }

    if let Some(list_push_notification_configs) = input.list_push_notification_configs {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`list_push_notification_configs` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::ListPushNotificationConfigs(
            list_push_notification_configs,
        ));
    }

    if let Some(delete_push_notification_config) = input.delete_push_notification_config {
        if mixed_send_fields {
            return Err(AdapterError::InvalidToolInput(
                "`delete_push_notification_config` is mutually exclusive with SendMessage fields"
                    .to_string(),
            ));
        }
        return Ok(A2aToolInvocation::DeletePushNotificationConfig(
            delete_push_notification_config,
        ));
    }

    Ok(A2aToolInvocation::SendMessage(A2aSendToolInput {
        message: input.message,
        data: input.data,
        context_id: input.context_id,
        task_id: input.task_id,
        reference_task_ids: input.reference_task_ids,
        metadata: input.metadata,
        message_metadata: input.message_metadata,
        history_length: input.history_length,
        return_immediately: input.return_immediately,
        stream: input.stream.unwrap_or(false),
    }))
}

fn send_message_fields_present(input: &A2aToolInput) -> bool {
    input.message.is_some()
        || input.data.is_some()
        || input.context_id.is_some()
        || input.task_id.is_some()
        || input.reference_task_ids.is_some()
        || input.metadata.is_some()
        || input.message_metadata.is_some()
        || input.history_length.is_some()
        || input.return_immediately.is_some()
        || input.stream.unwrap_or(false)
}
