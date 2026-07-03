//! Bedrock Runtime transport: AWS SDK Converse calls plus a hermetic mock.
//!
//! The live transport ([`AwsSdkTransport`]) drives the AWS SDK for Rust
//! (`aws-sdk-bedrockruntime`), which signs every request with SigV4 and reads
//! credentials and region from an [`aws_types::sdk_config::SdkConfig`] (the
//! shape produced by the AWS default credential/region chain) or from
//! caller-supplied static credentials. The mock transport
//! ([`MockTransport`]) records intended calls and replays scripted Converse
//! responses so the adapter can be exercised without contacting AWS.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use aws_sdk_bedrockruntime::config::{
    BehaviorVersion, Credentials, Region, SharedCredentialsProvider,
};
use aws_sdk_bedrockruntime::types::{
    ContentBlock, ConversationRole, ConverseOutput, Message, Tool, ToolConfiguration,
    ToolInputSchema, ToolResultBlock, ToolResultContentBlock, ToolResultStatus, ToolSpecification,
    ToolUseBlock,
};
use aws_sdk_bedrockruntime::Client;
use aws_smithy_types::{Document, Number};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::native::ToolConfig;

/// Pinned Bedrock Converse API marker used in Chio provenance.
pub const BEDROCK_CONVERSE_API_VERSION: &str = "bedrock.converse.v1";

/// Only AWS region supported by the v1 Bedrock adapter.
pub const BEDROCK_REGION: &str = "us-east-1";

/// Provider name stamped on caller-supplied static credentials.
const STATIC_CREDENTIALS_PROVIDER: &str = "chio-bedrock-static";

/// Default request timeout applied to live Converse calls.
const DEFAULT_CONVERSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Boxed future returned by the async [`Transport`] surface so the trait stays
/// object-safe behind `Arc<dyn Transport>`.
pub type TransportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

/// Bedrock Runtime operations this adapter is allowed to target.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BedrockOperation {
    /// Batch Bedrock Runtime Converse call.
    Converse,
    /// Streaming Bedrock Runtime Converse call over HTTP/2.
    ConverseStream,
}

impl BedrockOperation {
    /// AWS SDK operation name.
    pub fn sdk_name(&self) -> &'static str {
        match self {
            BedrockOperation::Converse => "Converse",
            BedrockOperation::ConverseStream => "ConverseStream",
        }
    }
}

/// One Converse turn supplied to the transport.
///
/// The adapter lifts the model's tool-call response, so a turn carries the
/// model id, the conversation `messages`, and an optional `toolConfig`. Each
/// message is `{ "role": "user" | "assistant", "content": [ ... ] }` using the
/// Bedrock content-block shapes the adapter understands (`text`, `toolUse`,
/// `toolResult`).
#[derive(Debug, Clone)]
pub struct ConverseRequest {
    /// Bedrock model id or inference-profile ARN.
    pub model_id: String,
    /// Conversation messages in Bedrock wire shape.
    pub messages: Vec<Value>,
    /// Optional tool configuration offered to the model.
    pub tool_config: Option<ToolConfig>,
}

impl ConverseRequest {
    /// Build a request from a model id and conversation messages.
    pub fn new(model_id: impl Into<String>, messages: Vec<Value>) -> Self {
        Self {
            model_id: model_id.into(),
            messages,
            tool_config: None,
        }
    }

    /// Attach a tool configuration to the request.
    pub fn with_tool_config(mut self, tool_config: ToolConfig) -> Self {
        self.tool_config = Some(tool_config);
        self
    }

    /// Parse a Converse request from a JSON envelope of the form
    /// `{ "modelId": "...", "messages": [...], "toolConfig": { ... } }`.
    pub fn from_json_bytes(raw: &[u8]) -> Result<Self, TransportError> {
        let value: Value = serde_json::from_slice(raw)
            .map_err(|error| TransportError::MalformedRequest(format!("not JSON: {error}")))?;
        let object = value.as_object().ok_or_else(|| {
            TransportError::MalformedRequest("request must be a JSON object".to_string())
        })?;

        let model_id = object
            .get("modelId")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                TransportError::MalformedRequest("request is missing string modelId".to_string())
            })?;
        let model_id = required_identifier(model_id, "request modelId")?.to_string();

        let messages = object
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                TransportError::MalformedRequest("request is missing messages array".to_string())
            })?
            .clone();

        let tool_config = match object.get("toolConfig") {
            Some(value) => Some(serde_json::from_value(value.clone()).map_err(|error| {
                TransportError::MalformedRequest(format!("toolConfig was malformed: {error}"))
            })?),
            None => None,
        };

        Ok(Self {
            model_id,
            messages,
            tool_config,
        })
    }
}

/// Wire-level transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("mock bedrock transport has no scripted response for {operation}")]
    MockExhausted { operation: &'static str },
    #[error("unsupported bedrock runtime operation: {operation}")]
    UnsupportedOperation { operation: String },
    #[error("unsupported bedrock region: {region}; expected us-east-1")]
    UnsupportedRegion { region: String },
    #[error("bedrock Converse request was malformed: {0}")]
    MalformedRequest(String),
    #[error("bedrock Converse upstream rate limited; retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("bedrock Converse upstream {status} error: {message}")]
    Upstream { status: u16, message: String },
    #[error("bedrock Converse call timed out after {ms}ms")]
    Timeout { ms: u64 },
    #[error("bedrock Converse upstream rejected the request: {0}")]
    Rejected(String),
    #[error("bedrock Converse response could not be decoded: {0}")]
    DecodeResponse(String),
}

/// Wire-level transport contract.
pub trait Transport: Send + Sync {
    /// AWS region targeted by this transport.
    fn region(&self) -> &str {
        BEDROCK_REGION
    }

    /// Whether this transport supports a Bedrock Runtime operation.
    fn supports_operation(&self, operation: BedrockOperation) -> bool {
        matches!(
            operation,
            BedrockOperation::Converse | BedrockOperation::ConverseStream
        )
    }

    /// Validate that the transport is pinned to the allowed region and that
    /// the requested operation is supported.
    fn validate_operation(&self, operation: BedrockOperation) -> Result<(), TransportError> {
        if self.region() != BEDROCK_REGION {
            return Err(TransportError::UnsupportedRegion {
                region: self.region().to_string(),
            });
        }
        if !self.supports_operation(operation) {
            return Err(TransportError::UnsupportedOperation {
                operation: operation.sdk_name().to_string(),
            });
        }
        Ok(())
    }

    /// Perform a batch Bedrock Runtime Converse call and return the response
    /// as Bedrock Converse JSON bytes (`{ "output": { "message": { ... } } }`)
    /// that the adapter lifts into [`crate::native::ToolUseBlock`] invocations.
    fn converse<'a>(&'a self, request: &'a ConverseRequest) -> TransportFuture<'a, Vec<u8>>;
}

/// AWS-SDK-backed Bedrock Runtime transport.
///
/// Wraps an `aws-sdk-bedrockruntime` [`Client`]. Construction is region-pinned
/// to [`BEDROCK_REGION`]. SigV4 signing, retries, and TLS come from the SDK.
#[derive(Clone)]
pub struct AwsSdkTransport {
    client: Client,
    timeout: Duration,
}

impl AwsSdkTransport {
    /// Build a transport from an [`SdkConfig`](aws_types::sdk_config::SdkConfig),
    /// the shape returned by the AWS default credential/region chain
    /// (`aws_config::defaults(..).region("us-east-1").load().await`). The
    /// config must carry credentials, a `us-east-1` region, an HTTP connector,
    /// and a behavior version.
    pub fn from_sdk_config(
        sdk_config: &aws_types::sdk_config::SdkConfig,
    ) -> Result<Self, TransportError> {
        if let Some(region) = sdk_config.region() {
            if region.as_ref() != BEDROCK_REGION {
                return Err(TransportError::UnsupportedRegion {
                    region: region.as_ref().to_string(),
                });
            }
        }
        Ok(Self::from_client(Client::new(sdk_config)))
    }

    /// Build a transport from caller-supplied static credentials, pinned to
    /// `us-east-1`. Useful for short-lived STS session credentials handed to
    /// the adapter directly rather than resolved from the ambient environment.
    pub fn from_static_credentials(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        let credentials = Credentials::new(
            access_key_id,
            secret_access_key,
            session_token,
            None,
            STATIC_CREDENTIALS_PROVIDER,
        );
        let config = aws_sdk_bedrockruntime::Config::builder()
            .behavior_version(BehaviorVersion::v2026_01_12())
            .region(Region::new(BEDROCK_REGION))
            .credentials_provider(SharedCredentialsProvider::new(credentials))
            .build();
        Self::from_client(Client::from_conf(config))
    }

    /// Wrap an already-built Bedrock Runtime [`Client`]. The caller is
    /// responsible for pinning the client to `us-east-1`; this is the seam
    /// hermetic tests use to inject a replay HTTP client.
    pub fn from_client(client: Client) -> Self {
        Self {
            client,
            timeout: DEFAULT_CONVERSE_TIMEOUT,
        }
    }

    /// Override the per-call timeout applied around the SDK Converse future.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn converse_inner(&self, request: &ConverseRequest) -> Result<Vec<u8>, TransportError> {
        let model_id = required_identifier(&request.model_id, "request modelId")?;
        let messages = build_messages(&request.messages)?;
        let tool_config = match &request.tool_config {
            Some(config) => Some(build_tool_configuration(config)?),
            None => None,
        };

        let mut call = self
            .client
            .converse()
            .model_id(model_id)
            .set_messages(Some(messages));
        if let Some(tool_config) = tool_config {
            call = call.tool_config(tool_config);
        }

        let send = call.send();
        let output = match tokio::time::timeout(self.timeout, send).await {
            Ok(result) => result.map_err(map_sdk_error)?,
            Err(_) => {
                return Err(TransportError::Timeout {
                    ms: self.timeout.as_millis() as u64,
                })
            }
        };

        let body = converse_output_to_json(&output)?;
        serde_json::to_vec(&body)
            .map_err(|error| TransportError::DecodeResponse(format!("re-encode failed: {error}")))
    }
}

impl Transport for AwsSdkTransport {
    fn converse<'a>(&'a self, request: &'a ConverseRequest) -> TransportFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.validate_operation(BedrockOperation::Converse)?;
            self.converse_inner(request).await
        })
    }
}

/// In-memory transport that records intended Bedrock calls and replays scripted
/// Converse responses without contacting AWS.
#[derive(Default)]
pub struct MockTransport {
    calls: Mutex<Vec<(BedrockOperation, Vec<u8>)>>,
    converse_responses: Mutex<Vec<Vec<u8>>>,
}

impl MockTransport {
    /// Construct an empty mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a mock transport pre-loaded with scripted Converse response
    /// bodies, served in order by [`Transport::converse`].
    pub fn with_converse_responses(responses: Vec<Vec<u8>>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            converse_responses: Mutex::new(responses.into_iter().rev().collect()),
        }
    }

    /// Queue one scripted Converse response body.
    pub fn push_converse_response(&self, body: Vec<u8>) {
        if let Ok(mut guard) = self.converse_responses.lock() {
            guard.insert(0, body);
        }
    }

    /// Record a call intent after validating the operation and region gates.
    pub fn record(&self, operation: BedrockOperation, body: &[u8]) -> Result<(), TransportError> {
        self.validate_operation(operation)?;
        if let Ok(mut guard) = self.calls.lock() {
            guard.push((operation, body.to_vec()));
        }
        Ok(())
    }

    /// Snapshot recorded calls for assertions.
    pub fn calls(&self) -> Vec<(BedrockOperation, Vec<u8>)> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl Transport for MockTransport {
    fn converse<'a>(&'a self, request: &'a ConverseRequest) -> TransportFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.validate_operation(BedrockOperation::Converse)?;
            let body = serde_json::to_vec(&json!({
                "modelId": request.model_id,
                "messages": request.messages,
            }))
            .unwrap_or_default();
            self.record(BedrockOperation::Converse, &body)?;

            let scripted = self
                .converse_responses
                .lock()
                .ok()
                .and_then(|mut guard| guard.pop());
            scripted.ok_or(TransportError::MockExhausted {
                operation: "Converse",
            })
        })
    }
}

fn build_messages(messages: &[Value]) -> Result<Vec<Message>, TransportError> {
    messages.iter().map(build_message).collect()
}

fn build_message(message: &Value) -> Result<Message, TransportError> {
    let object = message.as_object().ok_or_else(|| {
        TransportError::MalformedRequest("message must be a JSON object".to_string())
    })?;
    let role = match object.get("role").and_then(Value::as_str) {
        Some("user") => ConversationRole::User,
        Some("assistant") => ConversationRole::Assistant,
        Some(other) => {
            return Err(TransportError::MalformedRequest(format!(
                "message role `{other}` is not user or assistant"
            )))
        }
        None => {
            return Err(TransportError::MalformedRequest(
                "message is missing a role".to_string(),
            ))
        }
    };
    let content = object
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TransportError::MalformedRequest("message is missing a content array".to_string())
        })?
        .iter()
        .map(build_content_block)
        .collect::<Result<Vec<_>, _>>()?;

    Message::builder()
        .role(role)
        .set_content(Some(content))
        .build()
        .map_err(|error| {
            TransportError::MalformedRequest(format!("message could not be built: {error}"))
        })
}

fn build_content_block(block: &Value) -> Result<ContentBlock, TransportError> {
    let object = block.as_object().ok_or_else(|| {
        TransportError::MalformedRequest("content block must be a JSON object".to_string())
    })?;

    if let Some(text) = object.get("text") {
        let text = text.as_str().ok_or_else(|| {
            TransportError::MalformedRequest("content block text must be a string".to_string())
        })?;
        return Ok(ContentBlock::Text(text.to_string()));
    }

    if let Some(tool_use) = object.get("toolUse") {
        return Ok(ContentBlock::ToolUse(build_tool_use_block(tool_use)?));
    }

    if let Some(tool_result) = object.get("toolResult") {
        return Ok(ContentBlock::ToolResult(build_tool_result_block(
            tool_result,
        )?));
    }

    Err(TransportError::MalformedRequest(
        "content block must be one of text, toolUse, or toolResult".to_string(),
    ))
}

fn build_tool_use_block(value: &Value) -> Result<ToolUseBlock, TransportError> {
    let object = value.as_object().ok_or_else(|| {
        TransportError::MalformedRequest("toolUse must be a JSON object".to_string())
    })?;
    let tool_use_id = required_str(object, "toolUseId", "toolUse.toolUseId")?;
    let name = required_str(object, "name", "toolUse.name")?;
    let input = object.get("input").cloned().unwrap_or_else(|| json!({}));

    ToolUseBlock::builder()
        .tool_use_id(tool_use_id)
        .name(name)
        .input(json_to_document(&input))
        .build()
        .map_err(|error| {
            TransportError::MalformedRequest(format!("toolUse could not be built: {error}"))
        })
}

fn build_tool_result_block(value: &Value) -> Result<ToolResultBlock, TransportError> {
    let object = value.as_object().ok_or_else(|| {
        TransportError::MalformedRequest("toolResult must be a JSON object".to_string())
    })?;
    let tool_use_id = required_str(object, "toolUseId", "toolResult.toolUseId")?;

    let content = object
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TransportError::MalformedRequest("toolResult is missing a content array".to_string())
        })?
        .iter()
        .map(build_tool_result_content_block)
        .collect::<Result<Vec<_>, _>>()?;

    let mut builder = ToolResultBlock::builder()
        .tool_use_id(tool_use_id)
        .set_content(Some(content));
    match object.get("status").and_then(Value::as_str) {
        Some("success") => builder = builder.status(ToolResultStatus::Success),
        Some("error") => builder = builder.status(ToolResultStatus::Error),
        Some(other) => {
            return Err(TransportError::MalformedRequest(format!(
                "toolResult status `{other}` is not success or error"
            )))
        }
        None => {}
    }

    builder.build().map_err(|error| {
        TransportError::MalformedRequest(format!("toolResult could not be built: {error}"))
    })
}

fn build_tool_result_content_block(
    block: &Value,
) -> Result<ToolResultContentBlock, TransportError> {
    let object = block.as_object().ok_or_else(|| {
        TransportError::MalformedRequest(
            "toolResult content block must be a JSON object".to_string(),
        )
    })?;
    if let Some(json_value) = object.get("json") {
        return Ok(ToolResultContentBlock::Json(json_to_document(json_value)));
    }
    if let Some(text) = object.get("text") {
        let text = text.as_str().ok_or_else(|| {
            TransportError::MalformedRequest("toolResult content text must be a string".to_string())
        })?;
        return Ok(ToolResultContentBlock::Text(text.to_string()));
    }
    Err(TransportError::MalformedRequest(
        "toolResult content block must be json or text".to_string(),
    ))
}

fn build_tool_configuration(config: &ToolConfig) -> Result<ToolConfiguration, TransportError> {
    let tools = config
        .tools
        .iter()
        .map(|spec| {
            let tool_spec = ToolSpecification::builder()
                .name(spec.name.clone())
                .set_description(spec.description.clone())
                .input_schema(ToolInputSchema::Json(json_to_document(&spec.input_schema)))
                .build()
                .map_err(|error| {
                    TransportError::MalformedRequest(format!(
                        "toolSpec `{}` could not be built: {error}",
                        spec.name
                    ))
                })?;
            Ok(Tool::ToolSpec(tool_spec))
        })
        .collect::<Result<Vec<_>, TransportError>>()?;

    ToolConfiguration::builder()
        .set_tools(Some(tools))
        .build()
        .map_err(|error| {
            TransportError::MalformedRequest(format!("toolConfig could not be built: {error}"))
        })
}

fn converse_output_to_json(
    output: &aws_sdk_bedrockruntime::operation::converse::ConverseOutput,
) -> Result<Value, TransportError> {
    let ConverseOutput::Message(message) = output.output().ok_or_else(|| {
        TransportError::DecodeResponse("Converse response omitted output.message".to_string())
    })?
    else {
        return Err(TransportError::DecodeResponse(
            "Converse response output was not a message".to_string(),
        ));
    };

    let role = match message.role() {
        ConversationRole::Assistant => "assistant",
        ConversationRole::User => "user",
        other => other.as_str(),
    };

    let content = message
        .content()
        .iter()
        .map(content_block_to_json)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(json!({
        "output": {
            "message": {
                "role": role,
                "content": content,
            }
        },
        "stopReason": output.stop_reason().as_str(),
    }))
}

fn content_block_to_json(block: &ContentBlock) -> Result<Value, TransportError> {
    match block {
        ContentBlock::Text(text) => Ok(json!({ "text": text })),
        ContentBlock::ToolUse(tool_use) => Ok(json!({
            "toolUse": {
                "toolUseId": tool_use.tool_use_id(),
                "name": tool_use.name(),
                "input": document_to_json(tool_use.input()),
            }
        })),
        ContentBlock::ToolResult(tool_result) => {
            let content = tool_result
                .content()
                .iter()
                .map(tool_result_content_to_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({
                "toolResult": {
                    "toolUseId": tool_result.tool_use_id(),
                    "content": content,
                }
            }))
        }
        other => Err(TransportError::DecodeResponse(format!(
            "Converse response content block `{other:?}` is not supported"
        ))),
    }
}

fn tool_result_content_to_json(block: &ToolResultContentBlock) -> Result<Value, TransportError> {
    match block {
        ToolResultContentBlock::Json(document) => Ok(json!({ "json": document_to_json(document) })),
        ToolResultContentBlock::Text(text) => Ok(json!({ "text": text })),
        other => Err(TransportError::DecodeResponse(format!(
            "Converse toolResult content block `{other:?}` is not supported"
        ))),
    }
}

fn required_str(
    object: &Map<String, Value>,
    field: &str,
    display: &str,
) -> Result<String, TransportError> {
    let raw = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| TransportError::MalformedRequest(format!("{display} is missing")))?;
    Ok(required_identifier(raw, display)?.to_string())
}

fn required_identifier<'a>(raw: &'a str, display: &str) -> Result<&'a str, TransportError> {
    if raw.trim().is_empty() {
        return Err(TransportError::MalformedRequest(format!(
            "{display} must not be empty"
        )));
    }
    if raw.trim() != raw {
        return Err(TransportError::MalformedRequest(format!(
            "{display} must not contain surrounding whitespace"
        )));
    }
    Ok(raw)
}

fn json_to_document(value: &Value) -> Document {
    match value {
        Value::Null => Document::Null,
        Value::Bool(boolean) => Document::Bool(*boolean),
        Value::Number(number) => Document::Number(json_number_to_document(number)),
        Value::String(string) => Document::String(string.clone()),
        Value::Array(items) => Document::Array(items.iter().map(json_to_document).collect()),
        Value::Object(map) => Document::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), json_to_document(value)))
                .collect(),
        ),
    }
}

fn json_number_to_document(number: &serde_json::Number) -> Number {
    if let Some(unsigned) = number.as_u64() {
        Number::PosInt(unsigned)
    } else if let Some(signed) = number.as_i64() {
        Number::NegInt(signed)
    } else {
        Number::Float(number.as_f64().unwrap_or(0.0))
    }
}

fn document_to_json(document: &Document) -> Value {
    match document {
        Document::Null => Value::Null,
        Document::Bool(boolean) => Value::Bool(*boolean),
        Document::Number(number) => document_number_to_json(number),
        Document::String(string) => Value::String(string.clone()),
        Document::Array(items) => Value::Array(items.iter().map(document_to_json).collect()),
        Document::Object(map) => {
            let mut object = Map::with_capacity(map.len());
            for (key, value) in map {
                object.insert(key.clone(), document_to_json(value));
            }
            Value::Object(object)
        }
    }
}

fn document_number_to_json(number: &Number) -> Value {
    match number {
        Number::PosInt(value) => Value::Number((*value).into()),
        Number::NegInt(value) => Value::Number((*value).into()),
        Number::Float(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
    }
}

fn map_sdk_error(
    error: aws_smithy_runtime_api::client::result::SdkError<
        aws_sdk_bedrockruntime::operation::converse::ConverseError,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
) -> TransportError {
    use aws_sdk_bedrockruntime::operation::converse::ConverseError;
    use aws_smithy_runtime_api::client::result::SdkError;

    if error.as_service_error().is_none() {
        return match &error {
            SdkError::TimeoutError(_) => TransportError::Timeout { ms: 0 },
            SdkError::DispatchFailure(_) => TransportError::Upstream {
                status: 503,
                message: error.to_string(),
            },
            SdkError::ResponseError(_) => TransportError::DecodeResponse(error.to_string()),
            other => TransportError::Rejected(other.to_string()),
        };
    }

    match error.into_service_error() {
        ConverseError::ThrottlingException(_) => TransportError::RateLimited {
            retry_after_ms: 1_000,
        },
        ConverseError::ModelTimeoutException(inner) => TransportError::Upstream {
            status: 408,
            message: error_message(inner.message(), "model timeout"),
        },
        ConverseError::InternalServerException(inner) => TransportError::Upstream {
            status: 500,
            message: error_message(inner.message(), "internal server error"),
        },
        ConverseError::ServiceUnavailableException(inner) => TransportError::Upstream {
            status: 503,
            message: error_message(inner.message(), "service unavailable"),
        },
        ConverseError::ValidationException(inner) => {
            TransportError::Rejected(error_message(inner.message(), "validation error"))
        }
        ConverseError::AccessDeniedException(inner) => {
            TransportError::Rejected(error_message(inner.message(), "access denied"))
        }
        ConverseError::ResourceNotFoundException(inner) => {
            TransportError::Rejected(error_message(inner.message(), "resource not found"))
        }
        ConverseError::ModelErrorException(inner) => {
            TransportError::Rejected(error_message(inner.message(), "model error"))
        }
        ConverseError::ModelNotReadyException(inner) => {
            TransportError::Rejected(error_message(inner.message(), "model not ready"))
        }
        other => TransportError::Rejected(other.to_string()),
    }
}

fn error_message(message: Option<&str>, fallback: &str) -> String {
    match message {
        Some(message) if !message.trim().is_empty() => message.to_string(),
        _ => fallback.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(BEDROCK_CONVERSE_API_VERSION, "bedrock.converse.v1");
        assert_eq!(BEDROCK_REGION, "us-east-1");
    }

    #[test]
    fn operation_names_match_sdk_surface() {
        assert_eq!(BedrockOperation::Converse.sdk_name(), "Converse");
        assert_eq!(
            BedrockOperation::ConverseStream.sdk_name(),
            "ConverseStream"
        );
    }

    #[test]
    fn mock_transport_records_supported_operations() {
        let mock = MockTransport::new();
        mock.record(BedrockOperation::Converse, b"{\"input\":1}")
            .unwrap();
        mock.record(BedrockOperation::ConverseStream, b"{\"input\":2}")
            .unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, BedrockOperation::Converse);
        assert_eq!(calls[1].1, b"{\"input\":2}");
    }

    #[test]
    fn converse_request_parses_json_envelope() {
        let request = ConverseRequest::from_json_bytes(
            br#"{
                "modelId": "anthropic.claude-3-sonnet",
                "messages": [{"role": "user", "content": [{"text": "hi"}]}],
                "toolConfig": {
                    "tools": [
                        {"name": "get_weather", "inputSchema": {"json": {"type": "object"}}}
                    ]
                }
            }"#,
        )
        .unwrap();
        assert_eq!(request.model_id, "anthropic.claude-3-sonnet");
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.tool_config.as_ref().unwrap().tools.len(), 1);
    }

    #[test]
    fn converse_request_rejects_missing_model_id() {
        let err = ConverseRequest::from_json_bytes(br#"{"messages": []}"#).unwrap_err();
        assert!(matches!(err, TransportError::MalformedRequest(_)));
    }

    #[test]
    fn converse_request_rejects_padded_model_id_from_json_envelope() {
        let err = ConverseRequest::from_json_bytes(
            br#"{
                "modelId": " anthropic.claude-3-sonnet ",
                "messages": [{"role": "user", "content": [{"text": "hi"}]}]
            }"#,
        )
        .expect_err("padded modelId must fail during request parsing");

        assert!(matches!(err, TransportError::MalformedRequest(_)));
        assert!(err
            .to_string()
            .contains("request modelId must not contain surrounding whitespace"));
    }

    #[test]
    fn build_message_rejects_tool_use_identifier_padding_before_sdk_request() {
        let err = build_message(&json!({
            "role": "assistant",
            "content": [
                {
                    "toolUse": {
                        "toolUseId": " tooluse_padded_1 ",
                        "name": "get_weather",
                        "input": {}
                    }
                }
            ]
        }))
        .expect_err("padded toolUseId must fail before SDK serialization");

        assert!(matches!(err, TransportError::MalformedRequest(_)));
        assert!(err
            .to_string()
            .contains("toolUse.toolUseId must not contain surrounding whitespace"));
    }

    #[test]
    fn build_message_rejects_tool_result_identifier_padding_before_sdk_request() {
        let err = build_message(&json!({
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": " tooluse_padded_1 ",
                        "content": [{"json": {"ok": true}}],
                        "status": "success"
                    }
                }
            ]
        }))
        .expect_err("padded toolResult toolUseId must fail before SDK serialization");

        assert!(matches!(err, TransportError::MalformedRequest(_)));
        assert!(err
            .to_string()
            .contains("toolResult.toolUseId must not contain surrounding whitespace"));
    }

    #[test]
    fn document_round_trips_through_json() {
        let value = json!({
            "location": "Boston",
            "count": 3,
            "ratio": 1.5,
            "nested": {"flag": true, "items": [1, 2, null]}
        });
        let document = json_to_document(&value);
        assert_eq!(document_to_json(&document), value);
    }

    #[test]
    fn mock_converse_replays_scripted_response() {
        let response = serde_json::to_vec(&json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}},
            "stopReason": "end_turn"
        }))
        .unwrap();
        let mock = MockTransport::with_converse_responses(vec![response.clone()]);
        let request = ConverseRequest::new(
            "anthropic.claude-3-sonnet",
            vec![json!({"role": "user", "content": [{"text": "hi"}]})],
        );

        let body = futures_block_on(mock.converse(&request)).unwrap();
        assert_eq!(body, response);
        assert_eq!(mock.calls().len(), 1);

        let exhausted = futures_block_on(mock.converse(&request)).unwrap_err();
        assert!(matches!(exhausted, TransportError::MockExhausted { .. }));
    }
    fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWaker;
        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
