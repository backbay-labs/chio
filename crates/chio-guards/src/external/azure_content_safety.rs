//! Azure Content Safety `text:analyze` adapter (phase 13.2).
//!
//! Wraps the Azure Content Safety `text:analyze` endpoint as an
//! [`ExternalGuard`]. Each category returned by the API carries a
//! `severity` value; the guard denies the call when any configured
//! category exceeds the configured severity threshold.
//!
//! See: <https://learn.microsoft.com/azure/ai-services/content-safety/reference/rest-api-reference-text>
//!
//! # Fail-closed
//!
//! HTTP/transport errors propagate as [`ExternalGuardError`]; the
//! [`AsyncGuardAdapter`] maps those into [`Verdict::Deny`].
//!
//! [`AsyncGuardAdapter`]: super::AsyncGuardAdapter

use std::time::Duration;

use async_trait::async_trait;
use chio_core_types::GuardEvidence;
use chio_kernel::Verdict;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::bedrock::classify_status_error;
use super::http_egress;
use super::{ExternalGuard, ExternalGuardError, GuardCallContext};

/// Guard name reported by [`AzureContentSafetyGuard::name`].
pub const GUARD_NAME: &str = "azure-content-safety";

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default `api-version` query parameter.
pub const DEFAULT_API_VERSION: &str = "2023-10-01";

/// Default severity threshold. Azure Content Safety returns values in
/// `{0, 2, 4, 6}` (or the 8-level scale). `4` corresponds to "Medium",
/// which is the typical blocking threshold.
pub const DEFAULT_SEVERITY_THRESHOLD: u32 = 4;

/// A content category as reported by Azure Content Safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureCategory {
    Hate,
    SelfHarm,
    Sexual,
    Violence,
}

impl AzureCategory {
    /// Returns the canonical API name for the category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hate => "Hate",
            Self::SelfHarm => "SelfHarm",
            Self::Sexual => "Sexual",
            Self::Violence => "Violence",
        }
    }

    /// All known categories.
    pub const fn all() -> [Self; 4] {
        [Self::Hate, Self::SelfHarm, Self::Sexual, Self::Violence]
    }
}

/// Configuration for [`AzureContentSafetyGuard`].
#[derive(Clone)]
pub struct AzureContentSafetyConfig {
    /// Content Safety API key (`Ocp-Apim-Subscription-Key` header).
    pub api_key: Zeroizing<String>,
    /// Content Safety endpoint (e.g.
    /// `https://<region>.api.cognitive.microsoft.com`).
    pub endpoint: String,
    /// `api-version` query parameter.
    pub api_version: String,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
    /// Severity threshold; any category at or above this value triggers a
    /// [`Verdict::Deny`]. Azure uses severity `0..=7` on the 8-level
    /// scale (`0, 2, 4, 6` on the 4-level scale).
    pub severity_threshold: u32,
    /// Categories to submit. An empty vector means "all known
    /// categories".
    pub categories: Vec<AzureCategory>,
}

impl std::fmt::Debug for AzureContentSafetyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureContentSafetyConfig")
            .field("api_key", &"***redacted***")
            .field("endpoint", &self.endpoint)
            .field("api_version", &self.api_version)
            .field("timeout", &self.timeout)
            .field("severity_threshold", &self.severity_threshold)
            .field("categories", &self.categories)
            .finish()
    }
}

impl AzureContentSafetyConfig {
    /// Construct a minimal config with defaults.
    pub fn new(api_key: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            api_key: Zeroizing::new(api_key.into()),
            endpoint: endpoint.into(),
            api_version: DEFAULT_API_VERSION.to_string(),
            timeout: DEFAULT_TIMEOUT,
            severity_threshold: DEFAULT_SEVERITY_THRESHOLD,
            categories: AzureCategory::all().to_vec(),
        }
    }

    /// Override the severity threshold.
    pub fn with_severity_threshold(mut self, threshold: u32) -> Self {
        self.severity_threshold = threshold;
        self
    }

    /// Override the category list.
    pub fn with_categories(mut self, categories: Vec<AzureCategory>) -> Self {
        self.categories = categories;
        self
    }

    fn analyze_url(&self) -> String {
        let base = self.endpoint.trim_end_matches('/');
        format!(
            "{base}/contentsafety/text:analyze?api-version={}",
            self.api_version
        )
    }
}

#[derive(Debug, Serialize)]
struct AnalyzeRequest<'a> {
    text: &'a str,
    categories: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "outputType")]
    output_type: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
struct AnalyzeResponse {
    #[serde(default, rename = "categoriesAnalysis")]
    categories_analysis: Vec<CategoryResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CategoryResult {
    #[serde(default)]
    category: String,
    #[serde(default)]
    severity: u32,
}

/// Guard wrapping Azure Content Safety's `text:analyze` endpoint.
pub struct AzureContentSafetyGuard {
    cfg: AzureContentSafetyConfig,
    http: Client,
    egress_contract: chio_egress_contract::HttpEgressContract,
}

impl AzureContentSafetyGuard {
    /// Build a guard with an internally-owned [`reqwest::Client`].
    pub fn new(cfg: AzureContentSafetyConfig) -> Result<Self, ExternalGuardError> {
        let egress_contract = http_egress::contract_for_url(GUARD_NAME, &cfg.analyze_url())?;
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
    pub fn with_client(
        cfg: AzureContentSafetyConfig,
        _http: Client,
    ) -> Result<Self, ExternalGuardError> {
        Self::new(cfg)
    }

    /// Build a [`GuardEvidence`] record for a prior decision.
    pub fn evidence_from_decision(
        &self,
        verdict: Verdict,
        details: Option<&AzureDecisionDetails>,
    ) -> GuardEvidence {
        GuardEvidence {
            guard_name: self.name().to_string(),
            verdict: matches!(verdict, Verdict::Allow),
            details: details.and_then(|d| d.as_details_string()),
        }
    }
}

/// Structured details extracted from a Content Safety response.
#[derive(Debug, Clone, Serialize)]
pub struct AzureDecisionDetails {
    /// Maximum severity observed across any category.
    pub max_severity: u32,
    /// Threshold used to make the decision.
    pub severity_threshold: u32,
    /// Category-level severity breakdown.
    pub categories: Vec<AzureCategoryBreakdown>,
}

impl AzureDecisionDetails {
    fn as_details_string(&self) -> Option<String> {
        serde_json::to_string(self).ok()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AzureCategoryBreakdown {
    pub category: String,
    pub severity: u32,
}

#[async_trait]
impl ExternalGuard for AzureContentSafetyGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.cfg.endpoint.as_bytes());
        hasher.update(b":");
        hasher.update(ctx.tool_name.as_bytes());
        hasher.update(b":");
        hasher.update(ctx.arguments_json.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        Some(format!("azure-cs:{hex}"))
    }

    async fn eval(&self, ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
        super::endpoint_security::validate_external_guard_url(
            "azure-content-safety endpoint",
            &self.cfg.endpoint,
        )?;
        let url = self.cfg.analyze_url();

        let cats_ref: Vec<&str> = if self.cfg.categories.is_empty() {
            AzureCategory::all().iter().map(|c| c.as_str()).collect()
        } else {
            self.cfg.categories.iter().map(|c| c.as_str()).collect()
        };

        let body = AnalyzeRequest {
            text: &ctx.arguments_json,
            categories: cats_ref,
            output_type: Some("FourSeverityLevels"),
        };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            "Ocp-Apim-Subscription-Key",
            HeaderValue::from_str(self.cfg.api_key.as_str())
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
            return Err(classify_status_error("azure-content-safety", status, &text));
        }

        let parsed: AnalyzeResponse = serde_json::from_str(&text).map_err(|e| {
            ExternalGuardError::Transient(format!("parse azure content safety response: {e}"))
        })?;

        let mut max_severity = 0_u32;
        for entry in &parsed.categories_analysis {
            if entry.severity > max_severity {
                max_severity = entry.severity;
            }
        }

        tracing::info!(
            guard = GUARD_NAME,
            max_severity,
            threshold = self.cfg.severity_threshold,
            categories = parsed.categories_analysis.len(),
            "azure content safety response"
        );

        Ok(if max_severity >= self.cfg.severity_threshold {
            Verdict::Deny
        } else {
            Verdict::Allow
        })
    }
}
