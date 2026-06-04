use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("rate limited by upstream: retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("upstream content policy denied request: {0}")]
    ContentPolicy(String),
    #[error("tool arguments failed schema validation: {0}")]
    BadToolArgs(String),
    #[error("upstream 5xx ({status}): {body}")]
    Upstream5xx { status: u16, body: String },
    #[error("transport timeout after {ms}ms")]
    TransportTimeout { ms: u64 },
    #[error("verdict latency budget exceeded ({observed_ms}ms > {budget_ms}ms); fail-closed")]
    VerdictBudgetExceeded { observed_ms: u64, budget_ms: u64 },
    #[error("malformed upstream payload: {0}")]
    Malformed(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
