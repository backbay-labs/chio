//! AWS Bedrock `ApplyGuardrail` adapter (phase 13.2).
//!
//! This module wraps the AWS Bedrock `ApplyGuardrail` API as an
//! [`ExternalGuard`]. The guard evaluates the tool call's arguments
//! (serialized JSON text) against a configured guardrail and maps the
//! `GUARDRAIL_INTERVENED` action to [`Verdict::Deny`].
//!
//! See: <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ApplyGuardrail.html>
//!
//! All HTTP traffic is expected to go through the [`AsyncGuardAdapter`] -
//! this module exposes the single-attempt [`ExternalGuard::eval`] surface
//! and does not embed retry/caching/rate-limiting of its own. The adapter
//! composes a [`reqwest::Client`] internally so that the underlying
//! transport is re-used across calls, but every network request is issued
//! from inside [`ExternalGuard::eval`] which the adapter drives.
//!
//! # Authentication
//!
//! AWS SigV4 is non-trivial to implement in-tree. For phase 13.2 we accept
//! a pre-computed bearer token (`Authorization: Bearer <token>`) issued by
//! an ambient AWS identity layer (e.g. `AWS_BEARER_TOKEN_BEDROCK` env
//! provisioning, or a sidecar that exchanges instance credentials for a
//! short-lived bearer token). This keeps the adapter free of an AWS SDK
//! dependency while still letting production deployments plug in real
//! credentials.
//!
//! # Fail-closed
//!
//! Any non-2xx HTTP response or transport error surfaces as an
//! [`ExternalGuardError`]. The adapter then returns [`Verdict::Deny`]
//! (fail-closed, per the phase-13.2 acceptance criteria).
//!
//! [`AsyncGuardAdapter`]: super::AsyncGuardAdapter

use std::time::Duration;

use async_trait::async_trait;
use chio_core_types::GuardEvidence;
use chio_kernel::Verdict;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{http_egress, ExternalGuard, ExternalGuardError, GuardCallContext};

/// Guard name reported by [`BedrockGuardrailGuard::name`].
pub const GUARD_NAME: &str = "bedrock-guardrail";

/// Default request timeout. Applies to the inner HTTP call only; the
/// adapter layers its own retries + circuit breaker on top.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Input source type used by `ApplyGuardrail`. Bedrock differentiates
/// between user-supplied text (`INPUT`) and model-generated text
/// (`OUTPUT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BedrockSource {
    /// Evaluate tool arguments as model input.
    #[default]
    Input,
    /// Evaluate tool arguments as model output.
    Output,
}

impl BedrockSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Input => "INPUT",
            Self::Output => "OUTPUT",
        }
    }
}

/// Configuration for [`BedrockGuardrailGuard`].
///
/// `api_key` is wrapped in [`Zeroizing`] so its bytes are scrubbed from
/// memory on drop.
#[derive(Clone)]
pub struct BedrockGuardrailConfig {
    /// Bearer token for the Bedrock runtime endpoint.
    pub api_key: Zeroizing<String>,
    /// Bedrock region (used to construct the default endpoint).
    pub region: String,
    /// Guardrail identifier (the `guardrailId` path parameter).
    pub guardrail_id: String,
    /// Guardrail version (the `guardrailVersion` path parameter, usually
    /// a number or `"DRAFT"`).
    pub guardrail_version: String,
    /// Override the computed endpoint. When `None` we use
    /// `https://bedrock-runtime.{region}.amazonaws.com`.
    pub endpoint: Option<String>,
    /// `source` field submitted to the API.
    pub source: BedrockSource,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
}

impl std::fmt::Debug for BedrockGuardrailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BedrockGuardrailConfig")
            .field("api_key", &"***redacted***")
            .field("region", &self.region)
            .field("guardrail_id", &self.guardrail_id)
            .field("guardrail_version", &self.guardrail_version)
            .field("endpoint", &self.endpoint)
            .field("source", &self.source)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl BedrockGuardrailConfig {
    /// Construct a minimal config with the required identifiers.
    pub fn new(
        api_key: impl Into<String>,
        region: impl Into<String>,
        guardrail_id: impl Into<String>,
        guardrail_version: impl Into<String>,
    ) -> Self {
        Self {
            api_key: Zeroizing::new(api_key.into()),
            region: region.into(),
            guardrail_id: guardrail_id.into(),
            guardrail_version: guardrail_version.into(),
            endpoint: None,
            source: BedrockSource::Input,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the endpoint (primarily for tests).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    fn resolved_endpoint(&self) -> String {
        match self.endpoint.as_deref() {
            Some(ep) => ep.trim_end_matches('/').to_string(),
            None => format!("https://bedrock-runtime.{}.amazonaws.com", self.region),
        }
    }

    fn apply_url(&self) -> String {
        format!(
            "{}/guardrail/{}/version/{}/apply",
            self.resolved_endpoint(),
            self.guardrail_id,
            self.guardrail_version
        )
    }
}

/// Response structure returned by `ApplyGuardrail`. We only deserialize
/// the fields we need (action + any assessments that justify the verdict).
#[derive(Debug, Clone, Deserialize)]
struct ApplyGuardrailResponse {
    /// `NONE` or `GUARDRAIL_INTERVENED`.
    #[serde(default)]
    action: String,
    /// Opaque assessment records - captured verbatim for evidence.
    #[serde(default)]
    assessments: Vec<serde_json::Value>,
}

/// Request body submitted to `ApplyGuardrail`.
#[derive(Debug, Serialize)]
struct ApplyGuardrailRequest<'a> {
    source: &'a str,
    content: Vec<GuardrailContentBlock<'a>>,
}

#[derive(Debug, Serialize)]
struct GuardrailContentBlock<'a> {
    text: GuardrailText<'a>,
}

#[derive(Debug, Serialize)]
struct GuardrailText<'a> {
    text: &'a str,
}

/// [`ExternalGuard`] that calls Bedrock `ApplyGuardrail`.
pub struct BedrockGuardrailGuard {
    cfg: BedrockGuardrailConfig,
    http: Client,
    egress_contract: chio_egress_contract::HttpEgressContract,
}

impl BedrockGuardrailGuard {
    /// Construct a guard with an internally-owned [`reqwest::Client`].
    pub fn new(cfg: BedrockGuardrailConfig) -> Result<Self, ExternalGuardError> {
        let egress_contract = http_egress::contract_for_url(GUARD_NAME, &cfg.apply_url())?;
        let http = http_egress::client_for_contract(&egress_contract, cfg.timeout)?;
        Ok(Self {
            cfg,
            http,
            egress_contract,
        })
    }

    /// Construct a guard from a caller-supplied client handle.
    ///
    /// The supplied client is not reused. The guard rebuilds an internal client
    /// from its egress contract so automatic redirect following cannot bypass
    /// per-hop contract validation.
    pub fn with_client(
        cfg: BedrockGuardrailConfig,
        _http: Client,
    ) -> Result<Self, ExternalGuardError> {
        Self::new(cfg)
    }

    /// Build a [`GuardEvidence`] record for the verdict that
    /// [`ExternalGuard::eval`] most recently returned for `ctx`. The
    /// returned structure is suitable for attaching to receipts as part
    /// of [`chio_core_types::ChioReceiptBody::evidence`].
    pub fn evidence_from_decision(
        &self,
        verdict: Verdict,
        details: Option<&BedrockDecisionDetails>,
    ) -> GuardEvidence {
        GuardEvidence {
            guard_name: self.name().to_string(),
            verdict: matches!(verdict, Verdict::Allow),
            details: details.and_then(|d| d.as_details_string()),
        }
    }
}

/// Structured details extracted from a Bedrock `ApplyGuardrail` response.
/// Useful for receipt evidence and structured logging.
#[derive(Debug, Clone, Serialize)]
pub struct BedrockDecisionDetails {
    /// Raw `action` field from the API response.
    pub action: String,
    /// `true` if `action == "GUARDRAIL_INTERVENED"`.
    pub intervened: bool,
    /// Assessment records returned by Bedrock.
    pub assessments: Vec<serde_json::Value>,
}

impl BedrockDecisionDetails {
    fn as_details_string(&self) -> Option<String> {
        serde_json::to_string(self).ok()
    }
}

#[async_trait]
impl ExternalGuard for BedrockGuardrailGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.cfg.guardrail_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.cfg.guardrail_version.as_bytes());
        hasher.update(b":");
        hasher.update(ctx.tool_name.as_bytes());
        hasher.update(b":");
        hasher.update(ctx.arguments_json.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        Some(format!("bedrock:{hex}"))
    }

    async fn eval(&self, ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
        let url = self.cfg.apply_url();
        super::endpoint_security::validate_external_guard_url("bedrock endpoint", &url)?;
        let body = ApplyGuardrailRequest {
            source: self.cfg.source.as_str(),
            content: vec![GuardrailContentBlock {
                text: GuardrailText {
                    text: &ctx.arguments_json,
                },
            }],
        };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth_value = format!("Bearer {}", self.cfg.api_key.as_str());
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value)
                .map_err(|e| ExternalGuardError::Permanent(format!("invalid api key: {e}")))?,
        );

        let resp = http_egress::send_request_with_contract(
            &self.egress_contract,
            &self.http,
            self.http.post(&url).headers(headers).json(&body),
        )
        .await?;

        let status = resp.status();
        let text = http_egress::response_text(resp).await?;

        if !status.is_success() {
            return Err(classify_status_error("bedrock", status, &text));
        }

        let parsed: ApplyGuardrailResponse = serde_json::from_str(&text)
            .map_err(|e| ExternalGuardError::Transient(format!("parse bedrock response: {e}")))?;

        let intervened = parsed.action.eq_ignore_ascii_case("GUARDRAIL_INTERVENED");
        tracing::info!(
            guard = GUARD_NAME,
            action = %parsed.action,
            intervened,
            assessments = parsed.assessments.len(),
            "bedrock ApplyGuardrail response"
        );
        Ok(if intervened {
            Verdict::Deny
        } else {
            Verdict::Allow
        })
    }
}

/// Helper shared with the other cloud guardrail adapters. Maps
/// non-2xx responses to a retryable vs permanent error.
pub(crate) fn classify_status_error(
    provider: &'static str,
    status: StatusCode,
    body: &str,
) -> ExternalGuardError {
    let snippet = body.chars().take(256).collect::<String>();
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        ExternalGuardError::Transient(format!("{provider} HTTP {}: {}", status.as_u16(), snippet))
    } else {
        ExternalGuardError::Permanent(format!("{provider} HTTP {}: {}", status.as_u16(), snippet))
    }
}
