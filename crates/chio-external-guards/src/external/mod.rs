pub use chio_guards::external::{
    retry_with_jitter, retry_with_jitter_rng, AsyncGuardAdapter, AsyncGuardAdapterBuilder,
    AsyncGuardAdapterConfig, BackoffStrategy, CircuitBreaker, CircuitBreakerConfig,
    CircuitOpenVerdict, CircuitState, Clock, ExternalGuard, ExternalGuardError, GuardCallContext,
    RateLimitedVerdict, RetryConfig, TokenBucket, TokioClock, TtlCache,
};

mod endpoint_security;
pub use endpoint_security::{
    denied_external_guard_ip, validate_external_guard_url,
    validate_external_guard_url_with_resolver, validate_external_guard_url_without_dns,
};

#[path = "../../../chio-guards/src/external/azure_content_safety.rs"]
pub mod azure_content_safety;
#[path = "../../../chio-guards/src/external/bedrock.rs"]
pub mod bedrock;
#[path = "../../../chio-guards/src/external/http_egress.rs"]
pub(crate) mod http_egress;
#[path = "../../../chio-guards/src/external/threat_intel/mod.rs"]
pub mod threat_intel;
#[path = "../../../chio-guards/src/external/vertex_safety.rs"]
pub mod vertex_safety;

pub use azure_content_safety::{
    AzureCategory, AzureCategoryBreakdown, AzureContentSafetyConfig, AzureContentSafetyGuard,
    AzureDecisionDetails,
};
pub use bedrock::{
    BedrockDecisionDetails, BedrockGuardrailConfig, BedrockGuardrailGuard, BedrockSource,
};
pub use threat_intel::{
    SafeBrowsingConfig, SafeBrowsingGuard, SnykConfig, SnykGuard, SnykSeverity, VirusTotalConfig,
    VirusTotalGuard,
};
pub use vertex_safety::{
    VertexDecisionDetails, VertexProbability, VertexRatingBreakdown, VertexSafetyConfig,
    VertexSafetyGuard,
};
