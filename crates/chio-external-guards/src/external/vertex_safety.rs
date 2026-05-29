//! Google Vertex AI safety-classifier adapter.
//!
//! Vertex AI exposes multiple safety surfaces. This adapter uses the
//! generative-language `generateContent` safety-classification response:
//! when a request is submitted, the response carries `safetyRatings[]`
//! per category, each with a `probability` enum
//! (`NEGLIGIBLE|LOW|MEDIUM|HIGH`). We deny when any rating meets or
//! exceeds the configured probability threshold *or* when Vertex reports
//! a top-level `promptFeedback.blockReason`.
//!
//! See: <https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/safety-filters>
//!
//! Authentication uses a bearer token (typically an OAuth access token
//! minted from a service account). Like the Bedrock adapter, we accept
//! the token as a [`Zeroizing<String>`] so tokens don't linger in memory.

use std::time::Duration;

use async_trait::async_trait;
use chio_core_types::GuardEvidence;
use chio_kernel::Verdict;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::bedrock::classify_status_error;
use super::http_egress;
use super::{ExternalGuard, ExternalGuardError, GuardCallContext};

/// Guard name reported by [`VertexSafetyGuard::name`].
pub const GUARD_NAME: &str = "vertex-safety";

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Vertex safety probability levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum VertexProbability {
    Negligible,
    Low,
    #[default]
    Medium,
    High,
    /// Anything not recognized (e.g. `PROBABILITY_UNSPECIFIED`) is
    /// treated as [`VertexProbability::Low`] for threshold purposes.
    #[serde(other)]
    Unknown,
}

impl VertexProbability {
    fn rank(self) -> u8 {
        match self {
            Self::Negligible => 0,
            Self::Unknown | Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
}

/// Configuration for [`VertexSafetyGuard`].
#[derive(Clone)]
pub struct VertexSafetyConfig {
    /// Bearer token (OAuth access token).
    pub api_key: Zeroizing<String>,
    /// GCP project ID.
    pub project: String,
    /// Region, e.g. `us-central1`.
    pub location: String,
    /// Publisher model, e.g. `gemini-1.5-pro`.
    pub model: String,
    /// Endpoint override. When `None` we use
    /// `https://{location}-aiplatform.googleapis.com`.
    pub endpoint: Option<String>,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
    /// Threshold at or above which the guard denies.
    pub probability_threshold: VertexProbability,
}

impl std::fmt::Debug for VertexSafetyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VertexSafetyConfig")
            .field("api_key", &"***redacted***")
            .field("project", &self.project)
            .field("location", &self.location)
            .field("model", &self.model)
            .field("endpoint", &self.endpoint)
            .field("timeout", &self.timeout)
            .field("probability_threshold", &self.probability_threshold)
            .finish()
    }
}

impl VertexSafetyConfig {
    /// Construct a config with defaults.
    pub fn new(
        api_key: impl Into<String>,
        project: impl Into<String>,
        location: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            api_key: Zeroizing::new(api_key.into()),
            project: project.into(),
            location: location.into(),
            model: model.into(),
            endpoint: None,
            timeout: DEFAULT_TIMEOUT,
            probability_threshold: VertexProbability::Medium,
        }
    }

    /// Override the endpoint (primarily for tests).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Override the probability threshold.
    pub fn with_threshold(mut self, threshold: VertexProbability) -> Self {
        self.probability_threshold = threshold;
        self
    }

    fn resolved_endpoint(&self) -> String {
        match self.endpoint.as_deref() {
            Some(ep) => ep.trim_end_matches('/').to_string(),
            None => format!("https://{}-aiplatform.googleapis.com", self.location),
        }
    }

    fn generate_url(&self) -> String {
        format!(
            "{}/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
            self.resolved_endpoint(),
            self.project,
            self.location,
            self.model
        )
    }
}

#[derive(Debug, Serialize)]
struct GenerateRequest<'a> {
    contents: Vec<GenerateContent<'a>>,
}

#[derive(Debug, Serialize)]
struct GenerateContent<'a> {
    role: &'a str,
    parts: Vec<GeneratePart<'a>>,
}

#[derive(Debug, Serialize)]
struct GeneratePart<'a> {
    text: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
struct GenerateResponse {
    #[serde(default)]
    candidates: Vec<Candidate>,
    #[serde(default, rename = "promptFeedback")]
    prompt_feedback: Option<PromptFeedback>,
}

#[derive(Debug, Clone, Deserialize)]
struct Candidate {
    #[serde(default, rename = "safetyRatings")]
    safety_ratings: Vec<SafetyRating>,
    #[serde(default, rename = "finishReason")]
    #[allow(dead_code)]
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SafetyRating {
    #[serde(default)]
    category: String,
    #[serde(default)]
    probability: VertexProbabilityDefault,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(transparent)]
struct VertexProbabilityDefault(VertexProbability);

impl serde::Serialize for VertexProbability {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let s = match self {
            VertexProbability::Negligible => "NEGLIGIBLE",
            VertexProbability::Low => "LOW",
            VertexProbability::Medium => "MEDIUM",
            VertexProbability::High => "HIGH",
            VertexProbability::Unknown => "UNKNOWN",
        };
        ser.serialize_str(s)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct PromptFeedback {
    #[serde(default, rename = "blockReason")]
    block_reason: Option<String>,
    #[serde(default, rename = "safetyRatings")]
    safety_ratings: Vec<SafetyRating>,
}

/// Guard wrapping Vertex AI safety ratings.
pub struct VertexSafetyGuard {
    cfg: VertexSafetyConfig,
    http: Client,
    egress_contract: chio_egress_contract::HttpEgressContract,
}

impl VertexSafetyGuard {
    /// Build a guard with an internally-owned [`reqwest::Client`].
    pub fn new(cfg: VertexSafetyConfig) -> Result<Self, ExternalGuardError> {
        let egress_contract = http_egress::contract_for_url(GUARD_NAME, &cfg.generate_url())?;
        let http = http_egress::client_for_contract(&egress_contract, cfg.timeout)?;
        Ok(Self {
            cfg,
            http,
            egress_contract,
        })
    }

    /// Build a guard from a caller-supplied client handle.
    ///
    /// The supplied client is not reused. The guard rebuilds an internal client
    /// from its egress contract so automatic redirect following cannot bypass
    /// per-hop contract validation.
    pub fn with_client(cfg: VertexSafetyConfig, _http: Client) -> Result<Self, ExternalGuardError> {
        Self::new(cfg)
    }

    /// Build a [`GuardEvidence`] record for a prior decision.
    pub fn evidence_from_decision(
        &self,
        verdict: Verdict,
        details: Option<&VertexDecisionDetails>,
    ) -> GuardEvidence {
        GuardEvidence {
            guard_name: self.name().to_string(),
            verdict: matches!(verdict, Verdict::Allow),
            details: details.and_then(|d| d.as_details_string()),
        }
    }
}

/// Structured details for receipt evidence.
#[derive(Debug, Clone, Serialize)]
pub struct VertexDecisionDetails {
    /// The model's `promptFeedback.blockReason` if any.
    pub block_reason: Option<String>,
    /// Threshold used for the decision.
    pub threshold: String,
    /// Safety ratings observed.
    pub safety_ratings: Vec<VertexRatingBreakdown>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VertexRatingBreakdown {
    pub category: String,
    pub probability: String,
}

impl VertexDecisionDetails {
    fn as_details_string(&self) -> Option<String> {
        serde_json::to_string(self).ok()
    }
}

#[async_trait]
impl ExternalGuard for VertexSafetyGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.cfg.project.as_bytes());
        hasher.update(b":");
        hasher.update(self.cfg.model.as_bytes());
        hasher.update(b":");
        hasher.update(ctx.tool_name.as_bytes());
        hasher.update(b":");
        hasher.update(ctx.arguments_json.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        Some(format!("vertex:{hex}"))
    }

    async fn eval(&self, ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
        let url = self.cfg.generate_url();
        super::endpoint_security::validate_external_guard_url("vertex-safety endpoint", &url)?;

        let body = GenerateRequest {
            contents: vec![GenerateContent {
                role: "user",
                parts: vec![GeneratePart {
                    text: &ctx.arguments_json,
                }],
            }],
        };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth = format!("Bearer {}", self.cfg.api_key.as_str());
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth)
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
            return Err(classify_status_error("vertex-safety", status, &text));
        }

        let parsed: GenerateResponse = serde_json::from_str(&text)
            .map_err(|e| ExternalGuardError::Transient(format!("parse vertex response: {e}")))?;

        if let Some(pf) = parsed.prompt_feedback.as_ref() {
            if pf.block_reason.is_some() {
                tracing::info!(
                    guard = GUARD_NAME,
                    block_reason = ?pf.block_reason,
                    "vertex safety promptFeedback blocked"
                );
                return Ok(Verdict::Deny);
            }
        }

        let threshold_rank = self.cfg.probability_threshold.rank();
        let mut max_rank = 0_u8;
        let candidate_ratings = parsed
            .candidates
            .iter()
            .flat_map(|c| c.safety_ratings.iter());
        let pf_ratings = parsed
            .prompt_feedback
            .as_ref()
            .map(|p| p.safety_ratings.as_slice())
            .unwrap_or(&[])
            .iter();
        for rating in candidate_ratings.chain(pf_ratings) {
            let rank = rating.probability.0.rank();
            if rank > max_rank {
                max_rank = rank;
            }
        }

        tracing::info!(
            guard = GUARD_NAME,
            max_rank,
            threshold_rank,
            "vertex safety response"
        );

        Ok(if max_rank >= threshold_rank {
            Verdict::Deny
        } else {
            Verdict::Allow
        })
    }
}
