//! Snyk vulnerability-lookup adapter (phase 13.3).
//!
//! Adapted from
//! `../clawdstrike/crates/libs/clawdstrike/src/async_guards/threat_intel/snyk.rs`,
//! but reshaped to query a specific package + version rather than a
//! manifest-level bulk test. The argument envelope is:
//!
//! ```json
//! {"package": "lodash", "version": "4.17.20", "ecosystem": "npm"}
//! ```
//!
//! Calls go to `{base_url}/test/{ecosystem}/{package}/{version}` (the
//! Snyk v1 path for per-package lookups). The guard denies when any
//! returned vulnerability has a severity at or above the configured
//! threshold (and, optionally, is flagged upgradable).

use std::time::Duration;

use async_trait::async_trait;
use chio_core_types::GuardEvidence;
use chio_kernel::Verdict;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::external::bedrock::classify_status_error;
use crate::external::{http_egress, ExternalGuard, ExternalGuardError, GuardCallContext};

/// Guard name reported by [`SnykGuard::name`].
pub const GUARD_NAME: &str = "snyk";

/// Default base URL.
pub const DEFAULT_BASE_URL: &str = "https://snyk.io/api/v1";

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Snyk severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SnykSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl SnykSeverity {
    fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

/// Configuration for [`SnykGuard`].
#[derive(Clone)]
pub struct SnykConfig {
    /// `Authorization: token <api_token>` credential.
    pub api_token: Zeroizing<String>,
    /// Snyk organization id.
    pub org_id: String,
    /// Override the base URL (test hook).
    pub base_url: Option<String>,
    /// Severity at or above which vulnerabilities trigger a deny.
    pub severity_threshold: SnykSeverity,
    /// When `true`, only deny if the Snyk record marks the vuln as
    /// upgradable.
    pub fail_on_upgradable_only: bool,
    /// Per-request HTTP timeout.
    pub timeout: Duration,
}

impl std::fmt::Debug for SnykConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnykConfig")
            .field("api_token", &"***redacted***")
            .field("org_id", &self.org_id)
            .field("base_url", &self.base_url)
            .field("severity_threshold", &self.severity_threshold)
            .field("fail_on_upgradable_only", &self.fail_on_upgradable_only)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl SnykConfig {
    /// Build a config with defaults.
    pub fn new(api_token: impl Into<String>, org_id: impl Into<String>) -> Self {
        Self {
            api_token: Zeroizing::new(api_token.into()),
            org_id: org_id.into(),
            base_url: None,
            severity_threshold: SnykSeverity::High,
            fail_on_upgradable_only: false,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the base URL (tests).
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = Some(base.into());
        self
    }

    /// Override the severity threshold.
    pub fn with_severity_threshold(mut self, threshold: SnykSeverity) -> Self {
        self.severity_threshold = threshold;
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
struct SnykArgs {
    package: String,
    version: String,
    ecosystem: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SnykResponse {
    #[serde(default)]
    issues: Option<SnykIssues>,
    #[serde(default)]
    vulnerabilities: Vec<SnykVuln>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnykIssues {
    #[serde(default)]
    vulnerabilities: Vec<SnykVuln>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnykVuln {
    #[serde(default)]
    severity: Option<SnykSeverity>,
    #[serde(default, rename = "isUpgradable")]
    is_upgradable: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    title: Option<String>,
}

/// Structured receipt evidence.
#[derive(Debug, Clone, Serialize)]
pub struct SnykEvidence {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub threshold: SnykSeverity,
    pub vulns_at_or_above: Vec<SnykVulnSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnykVulnSummary {
    pub id: Option<String>,
    pub title: Option<String>,
    pub severity: SnykSeverity,
    pub upgradable: bool,
}

/// Guard wrapping Snyk per-package lookups.
pub struct SnykGuard {
    cfg: SnykConfig,
    base_url: String,
    http: Client,
    egress_contract: chio_egress_contract::HttpEgressContract,
}

impl SnykGuard {
    /// Build a guard with an internally-owned [`reqwest::Client`].
    pub fn new(cfg: SnykConfig) -> Result<Self, ExternalGuardError> {
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
    pub fn with_client(cfg: SnykConfig, _http: Client) -> Result<Self, ExternalGuardError> {
        Self::new(cfg)
    }

    /// Build a [`GuardEvidence`] record for a prior decision.
    pub fn evidence_from_decision(
        &self,
        verdict: Verdict,
        details: Option<&SnykEvidence>,
    ) -> GuardEvidence {
        GuardEvidence {
            guard_name: self.name().to_string(),
            verdict: matches!(verdict, Verdict::Allow),
            details: details.and_then(|d| serde_json::to_string(d).ok()),
        }
    }
}

#[async_trait]
impl ExternalGuard for SnykGuard {
    fn name(&self) -> &str {
        GUARD_NAME
    }

    fn cache_key(&self, ctx: &GuardCallContext) -> Option<String> {
        let args: SnykArgs = serde_json::from_str(&ctx.arguments_json).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(args.ecosystem.as_bytes());
        hasher.update(b":");
        hasher.update(args.package.as_bytes());
        hasher.update(b":");
        hasher.update(args.version.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(digest.len() * 2);
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        Some(format!("snyk:{hex}"))
    }

    async fn eval(&self, ctx: &GuardCallContext) -> Result<Verdict, ExternalGuardError> {
        let args: SnykArgs = serde_json::from_str(&ctx.arguments_json)
            .map_err(|e| ExternalGuardError::Permanent(format!("invalid snyk arguments: {e}")))?;

        let endpoint = format!(
            "{}/test/{}/{}/{}?orgId={}",
            self.base_url,
            url_encode(&args.ecosystem),
            url_encode(&args.package),
            url_encode(&args.version),
            url_encode(&self.cfg.org_id),
        );
        super::super::endpoint_security::validate_external_guard_url("snyk base_url", &endpoint)?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let auth_value = format!("token {}", self.cfg.api_token.as_str());
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value)
                .map_err(|e| ExternalGuardError::Permanent(format!("invalid api token: {e}")))?,
        );

        let resp = http_egress::send_request_with_contract(
            &self.egress_contract,
            &self.http,
            self.http.get(&endpoint).headers(headers),
        )
        .await?;

        let status = resp.status();
        let text = http_egress::response_text(resp).await?;

        if !status.is_success() {
            return Err(classify_status_error("snyk", status, &text));
        }

        let parsed: SnykResponse = serde_json::from_str(&text)
            .map_err(|e| ExternalGuardError::Transient(format!("parse snyk response: {e}")))?;

        let mut vulns: Vec<&SnykVuln> = parsed.vulnerabilities.iter().collect();
        if let Some(issues) = parsed.issues.as_ref() {
            vulns.extend(issues.vulnerabilities.iter());
        }

        let threshold = self.cfg.severity_threshold.rank();
        let mut denied = false;
        let mut count_at_or_above = 0_usize;
        for v in vulns {
            let Some(sev) = v.severity else {
                continue;
            };
            if sev.rank() < threshold {
                continue;
            }
            count_at_or_above += 1;
            let upgradable = v.is_upgradable.unwrap_or(false);
            if self.cfg.fail_on_upgradable_only {
                if upgradable {
                    denied = true;
                }
            } else {
                denied = true;
            }
        }

        tracing::info!(
            guard = GUARD_NAME,
            count_at_or_above,
            upgradable_only = self.cfg.fail_on_upgradable_only,
            denied,
            "snyk response"
        );

        Ok(if denied {
            Verdict::Deny
        } else {
            Verdict::Allow
        })
    }
}

fn url_encode(input: &str) -> String {
    // Small hand-rolled URL component encoder for the narrow set of chars
    // we expect in ecosystem / package / version / org-id fields. Avoids
    // a direct dep on the `urlencoding` crate.
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
