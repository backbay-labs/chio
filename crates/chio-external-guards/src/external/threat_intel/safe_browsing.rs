//! Google Safe Browsing v4 adapter.
//!
//! Accepts `{"url": "<absolute-url>"}` in
//! [`GuardCallContext::arguments_json`] and denies when Safe Browsing
//! returns at least one match.

use std::time::Duration;

use async_trait::async_trait;
use chio_core_types::GuardEvidence;
use chio_kernel::Verdict;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::external::bedrock::classify_status_error;
use crate::external::{http_egress, ExternalGuard, ExternalGuardError, GuardCallContext};

/// Guard name reported by [`SafeBrowsingGuard::name`].
pub const GUARD_NAME: &str = "safe-browsing";

/// Default base URL.
pub const DEFAULT_BASE_URL: &str = "https://safebrowsing.googleapis.com/v4";

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default client id reported to the Safe Browsing API.
pub const DEFAULT_CLIENT_ID: &str = "chio-guards";

/// Default client version.
pub const DEFAULT_CLIENT_VERSION: &str = "0.1.0";

/// Configuration for [`SafeBrowsingGuard`].
#[derive(Clone)]
pub struct SafeBrowsingConfig {
    /// API key (query parameter `key`).
    pub api_key: Zeroizing<String>,
    /// Client identifier submitted in the request body.
    pub client_id: String,
    /// Client version submitted in the request body.
    pub client_version: String,
    /// Override the base URL (test hook).
    pub base_url: Option<String>,
    /// Threat types to query.
    pub threat_types: Vec<String>,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
}

impl std::fmt::Debug for SafeBrowsingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeBrowsingConfig")
            .field("api_key", &"***redacted***")
            .field("client_id", &self.client_id)
            .field("client_version", &self.client_version)
            .field("base_url", &self.base_url)
            .field("threat_types", &self.threat_types)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl SafeBrowsingConfig {
    /// Construct a config with defaults.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: Zeroizing::new(api_key.into()),
            client_id: DEFAULT_CLIENT_ID.to_string(),
            client_version: DEFAULT_CLIENT_VERSION.to_string(),
            base_url: None,
            threat_types: vec![
                "MALWARE".to_string(),
                "SOCIAL_ENGINEERING".to_string(),
                "UNWANTED_SOFTWARE".to_string(),
                "POTENTIALLY_HARMFUL_APPLICATION".to_string(),
            ],
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the base URL (used in tests).
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = Some(base.into());
        self
    }

    fn resolved_base_url(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SafeBrowsingArgs {
    url: String,
}

#[derive(Debug, Serialize)]
struct FindRequest<'a> {
    client: ClientInfo<'a>,
    #[serde(rename = "threatInfo")]
    threat_info: ThreatInfo<'a>,
}

#[derive(Debug, Serialize)]
struct ClientInfo<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientVersion")]
    client_version: &'a str,
}

#[derive(Debug, Serialize)]
struct ThreatInfo<'a> {
    #[serde(rename = "threatTypes")]
    threat_types: &'a [String],
    #[serde(rename = "platformTypes")]
    platform_types: Vec<&'a str>,
    #[serde(rename = "threatEntryTypes")]
    threat_entry_types: Vec<&'a str>,
    #[serde(rename = "threatEntries")]
    threat_entries: Vec<ThreatEntry<'a>>,
}

#[derive(Debug, Serialize)]
struct ThreatEntry<'a> {
    url: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
struct FindResponse {
    #[serde(default)]
    matches: Vec<MatchEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct MatchEntry {
    #[serde(default, rename = "threatType")]
    threat_type: Option<String>,
    #[serde(default, rename = "platformType")]
    platform_type: Option<String>,
}

/// Structured receipt evidence.
#[derive(Debug, Clone, Serialize)]
pub struct SafeBrowsingEvidence {
    pub url: String,
    pub matches: Vec<String>,
}

/// Guard wrapping Safe Browsing `threatMatches:find`.
pub struct SafeBrowsingGuard {
    cfg: SafeBrowsingConfig,
    base_url: String,
    http: Client,
    egress_contract: chio_egress_contract::HttpEgressContract,
}

impl SafeBrowsingGuard {
    /// Build a guard with an internally-owned [`reqwest::Client`].
    pub fn new(cfg: SafeBrowsingConfig) -> Result<Self, ExternalGuardError> {
        let base_url = cfg.resolved_base_url();
        let egress_contract = http_egress::contract_for_url(GUARD_NAME, &base_url)?;
        let http = http_egress::client_for_contract(&egress_contract, cfg.timeout)?;
        Ok(Self {
            cfg,
            base_url,
            http,
            egress_contract,
        })
    }

    /// Build from a caller-supplied client handle.
    ///
    /// The supplied client is not reused. The guard rebuilds an internal client
    /// from its egress contract so automatic redirect following cannot bypass
    /// per-hop contract validation.
    pub fn with_client(cfg: SafeBrowsingConfig, _http: Client) -> Result<Self, ExternalGuardError> {
        Self::new(cfg)
    }

    /// Build a [`GuardEvidence`] record for a prior decision.
    pub fn evidence_from_decision(
        &self,
        verdict: Verdict,
        details: Option<&SafeBrowsingEvidence>,
    ) -> GuardEvidence {
        GuardEvidence {
            guard_name: self.name().to_string(),
            verdict: matches!(verdict, Verdict::Allow),
            details: details.and_then(|d| serde_json::to_string(d).ok()),
        }
    }
}

#[async_trait]
impl ExternalGuard for SafeBrowsingGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
        let args: SafeBrowsingArgs = serde_json::from_str(&ctx.arguments_json).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(args.url.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        Some(format!("sb:{hex}"))
    }

    async fn eval(&self, ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
        super::super::endpoint_security::validate_external_guard_url(
            "safe-browsing base_url",
            &self.base_url,
        )?;
        let args: SafeBrowsingArgs = serde_json::from_str(&ctx.arguments_json).map_err(|e| {
            ExternalGuardError::Permanent(format!("invalid safe-browsing arguments: {e}"))
        })?;

        let endpoint = format!(
            "{}/threatMatches:find?key={}",
            self.base_url,
            self.cfg.api_key.as_str()
        );

        let body = FindRequest {
            client: ClientInfo {
                client_id: &self.cfg.client_id,
                client_version: &self.cfg.client_version,
            },
            threat_info: ThreatInfo {
                threat_types: &self.cfg.threat_types,
                platform_types: vec!["ANY_PLATFORM"],
                threat_entry_types: vec!["URL"],
                threat_entries: vec![ThreatEntry { url: &args.url }],
            },
        };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let resp = http_egress::send_request_with_contract(
            &self.egress_contract,
            &self.http,
            self.http.post(&endpoint).headers(headers).json(&body),
        )
        .await?;

        let status = resp.status();
        let text = http_egress::response_text(resp).await?;

        if !status.is_success() {
            return Err(classify_status_error("safe-browsing", status, &text));
        }

        let parsed: FindResponse = serde_json::from_str(&text).map_err(|e| {
            ExternalGuardError::Transient(format!("parse safe browsing response: {e}"))
        })?;

        let matched = !parsed.matches.is_empty();
        tracing::info!(
            guard = GUARD_NAME,
            match_count = parsed.matches.len(),
            "safe browsing response"
        );

        Ok(if matched {
            Verdict::Deny
        } else {
            Verdict::Allow
        })
    }
}
