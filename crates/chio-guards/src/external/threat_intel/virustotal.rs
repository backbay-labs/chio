//! VirusTotal v3 adapter (phase 13.3).
//!
//! Adapted from
//! `../clawdstrike/crates/libs/clawdstrike/src/async_guards/threat_intel/virustotal.rs`
//! with the following deviations:
//!
//! * The Chio `ExternalGuard` surface is synchronous-in-decision - we
//!   return [`Verdict`] directly rather than the ClawdStrike `warn/block`
//!   tri-state. Below-threshold detections surface as `Allow`; the
//!   existing adapter `tracing::warn!`s the suspicious-but-not-blocked
//!   signal.
//! * Arguments are passed via a small JSON envelope in
//!   [`GuardCallContext::arguments_json`] (`{"hash": ...}` or
//!   `{"url": ...}`) instead of ClawdStrike's `GuardAction` enum.

use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::GuardEvidence;
use chio_kernel::Verdict;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::external::bedrock::classify_status_error;
use crate::external::{http_egress, ExternalGuard, ExternalGuardError, GuardCallContext};

/// Guard name reported by [`VirusTotalGuard::name`].
pub const GUARD_NAME: &str = "virustotal";

/// Default base URL.
pub const DEFAULT_BASE_URL: &str = "https://www.virustotal.com/api/v3";

/// Default detection threshold.
pub const DEFAULT_MIN_DETECTIONS: u64 = 5;

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for [`VirusTotalGuard`].
#[derive(Clone)]
pub struct VirusTotalConfig {
    /// `x-apikey` header.
    pub api_key: Zeroizing<String>,
    /// Override the base URL (test hook).
    pub base_url: Option<String>,
    /// Detection threshold. Calls are denied when
    /// `malicious + suspicious >= min_detections`.
    pub min_detections: u64,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
}

impl std::fmt::Debug for VirusTotalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirusTotalConfig")
            .field("api_key", &"***redacted***")
            .field("base_url", &self.base_url)
            .field("min_detections", &self.min_detections)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl VirusTotalConfig {
    /// Construct a config with defaults.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: Zeroizing::new(api_key.into()),
            base_url: None,
            min_detections: DEFAULT_MIN_DETECTIONS,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the base URL (used in tests).
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = Some(base.into());
        self
    }

    /// Override the detection threshold.
    pub fn with_min_detections(mut self, threshold: u64) -> Self {
        self.min_detections = threshold.max(1);
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

/// Shape of the JSON we accept in
/// [`GuardCallContext::arguments_json`].
#[derive(Debug, Clone, Deserialize)]
struct VirusTotalArgs {
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct VirusTotalResponse {
    #[serde(default)]
    data: Option<VirusTotalData>,
}

#[derive(Debug, Clone, Deserialize)]
struct VirusTotalData {
    #[serde(default)]
    attributes: Option<VirusTotalAttributes>,
}

#[derive(Debug, Clone, Deserialize)]
struct VirusTotalAttributes {
    #[serde(default, rename = "last_analysis_stats")]
    last_analysis_stats: Option<VirusTotalStats>,
}

#[derive(Debug, Clone, Deserialize)]
struct VirusTotalStats {
    #[serde(default)]
    malicious: u64,
    #[serde(default)]
    suspicious: u64,
}

/// Structured receipt evidence.
#[derive(Debug, Clone, Serialize)]
pub struct VirusTotalEvidence {
    pub target: String,
    pub malicious: u64,
    pub suspicious: u64,
    pub min_detections: u64,
}

/// Guard that queries VirusTotal for file-hash or URL reputation.
pub struct VirusTotalGuard {
    cfg: VirusTotalConfig,
    base_url: String,
    http: Client,
    egress_contract: chio_egress_contract::HttpEgressContract,
}

impl VirusTotalGuard {
    /// Build a guard with an internally-owned [`reqwest::Client`].
    pub fn new(cfg: VirusTotalConfig) -> Result<Self, ExternalGuardError> {
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
    pub fn with_client(cfg: VirusTotalConfig, _http: Client) -> Result<Self, ExternalGuardError> {
        Self::new(cfg)
    }

    /// Build a [`GuardEvidence`] record for a prior decision.
    pub fn evidence_from_decision(
        &self,
        verdict: Verdict,
        details: Option<&VirusTotalEvidence>,
    ) -> GuardEvidence {
        GuardEvidence {
            guard_name: self.name().to_string(),
            verdict: matches!(verdict, Verdict::Allow),
            details: details.and_then(|d| serde_json::to_string(d).ok()),
        }
    }
}

fn normalize_sha256_hex(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let without_prefix = if let Some(rest) = trimmed.strip_prefix("sha256:") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("0x") {
        rest
    } else {
        trimmed
    };
    let hex = without_prefix.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

#[async_trait]
impl ExternalGuard for VirusTotalGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
        let args: VirusTotalArgs = serde_json::from_str(&ctx.arguments_json).ok()?;
        if let Some(h) = args.hash.as_deref().and_then(normalize_sha256_hex) {
            return Some(format!("vt:file:{h}"));
        }
        if let Some(u) = args.url.as_deref() {
            let mut hasher = Sha256::new();
            hasher.update(u.as_bytes());
            let digest = hasher.finalize();
            let mut hex = String::with_capacity(digest.len() * 2);
            for b in digest {
                hex.push_str(&format!("{b:02x}"));
            }
            return Some(format!("vt:url:{hex}"));
        }
        None
    }

    async fn eval(&self, ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
        let args: VirusTotalArgs = serde_json::from_str(&ctx.arguments_json).map_err(|e| {
            ExternalGuardError::Permanent(format!("invalid virustotal arguments: {e}"))
        })?;

        let endpoint = if let Some(raw_hash) = args.hash.as_deref() {
            let Some(hash) = normalize_sha256_hex(raw_hash) else {
                return Err(ExternalGuardError::Permanent(
                    "virustotal: hash is not a sha256 hex string".to_string(),
                ));
            };
            format!("{}/files/{hash}", self.base_url)
        } else if let Some(target_url) = args.url.as_deref() {
            let id = URL_SAFE_NO_PAD.encode(target_url.as_bytes());
            format!("{}/urls/{id}", self.base_url)
        } else {
            return Err(ExternalGuardError::Permanent(
                "virustotal: arguments must include `hash` or `url`".to_string(),
            ));
        };
        super::super::endpoint_security::validate_external_guard_url(
            "virustotal base_url",
            &endpoint,
        )?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-apikey",
            HeaderValue::from_str(self.cfg.api_key.as_str())
                .map_err(|e| ExternalGuardError::Permanent(format!("invalid api key: {e}")))?,
        );

        let resp = http_egress::send_request_with_contract(
            &self.egress_contract,
            &self.http,
            self.http.get(&endpoint).headers(headers),
        )
        .await?;

        let status = resp.status();
        let text = http_egress::response_text(resp).await?;

        // 404 -> not found in VT database. We allow-by-default so that a
        // previously-unseen hash/URL doesn't block benign traffic. Upstream
        // callers can layer additional controls.
        if status.as_u16() == 404 {
            tracing::info!(guard = GUARD_NAME, "virustotal: target not found");
            return Ok(Verdict::Allow);
        }

        if !status.is_success() {
            return Err(classify_status_error("virustotal", status, &text));
        }

        let parsed: VirusTotalResponse = serde_json::from_str(&text)
            .map_err(|e| ExternalGuardError::Transient(format!("parse vt response: {e}")))?;

        let (malicious, suspicious) = parsed
            .data
            .and_then(|d| d.attributes)
            .and_then(|a| a.last_analysis_stats)
            .map(|s| (s.malicious, s.suspicious))
            .unwrap_or((0, 0));

        let detections = malicious.saturating_add(suspicious);
        tracing::info!(
            guard = GUARD_NAME,
            malicious,
            suspicious,
            min_detections = self.cfg.min_detections,
            "virustotal response"
        );

        if detections >= self.cfg.min_detections {
            return Ok(Verdict::Deny);
        }
        if malicious > 0 {
            tracing::warn!(
                guard = GUARD_NAME,
                malicious,
                suspicious,
                "virustotal: malicious detections below threshold"
            );
        }

        Ok(Verdict::Allow)
    }
}
