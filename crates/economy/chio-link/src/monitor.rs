use serde::{Deserialize, Serialize};

pub const CHIO_LINK_RUNTIME_REPORT_SCHEMA: &str = "chio.link.runtime-report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainHealthStatus {
    Healthy,
    Disabled,
    Down,
    Recovering,
    Unavailable,
    Unmonitored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairHealthStatus {
    Healthy,
    FallbackActive,
    DegradedGrace,
    Paused,
    Tripped,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleAlert {
    pub code: String,
    pub severity: AlertSeverity,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    pub observed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainHealthReport {
    pub chain_id: u64,
    pub label: String,
    pub caip2: String,
    pub enabled: bool,
    pub status: ChainHealthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequencer_uptime_feed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_started_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairHealthReport {
    pub pair: String,
    pub chain_id: u64,
    pub status: PairHealthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversion_margin_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OracleRuntimeReport {
    pub schema: String,
    pub generated_at: u64,
    pub global_pause: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    pub chains: Vec<ChainHealthReport>,
    pub pairs: Vec<PairHealthReport>,
    pub alerts: Vec<OracleAlert>,
}

impl OracleRuntimeReport {
    #[must_use]
    pub fn new(generated_at: u64) -> Self {
        Self {
            schema: CHIO_LINK_RUNTIME_REPORT_SCHEMA.to_string(),
            generated_at,
            global_pause: false,
            pause_reason: None,
            chains: Vec::new(),
            pairs: Vec::new(),
            alerts: Vec::new(),
        }
    }
}
