//! Fail-closed hosted cognition-market edge primitives.
//!
//! The crate authenticates exactly one explicitly selected credential mode
//! before a request body reaches market handlers. Capability credentials bind
//! a short-lived Chio capability and DPoP proof to the deployment, tenant,
//! action, external target, and body digest. API keys retain only an HMAC
//! verifier protected by a deployment pepper.

#![forbid(unsafe_code)]

mod auth;
mod error;
mod lifecycle;
mod operations;
mod proxy;
mod tls;

pub use auth::{
    ApiKeyPepper, HostedAuthCredential, HostedAuthMethod, HostedAuthRepository, HostedAuthRequest,
    HostedAuthenticatedPrincipal, HostedAuthenticator, HostedAuthenticatorConfig,
    HostedTenantAuthPolicy, StaticApiKeyPepper,
};
pub use error::{HostedEdgeError, HostedErrorBody};
pub use lifecycle::{
    verify_signed_hosted_api_key_lifecycle_event, HostedApiKeyIssueRequest,
    HostedApiKeyLifecycleEvent, HostedApiKeyLifecycleOperation, HostedApiKeyLifecycleRepository,
    HostedApiKeyManager, HostedApiKeySecret, HostedIssuedApiKey, SignedHostedApiKeyLifecycleEvent,
    HOSTED_API_KEY_LIFECYCLE_SCHEMA,
};
pub use operations::{
    HostedCircuitBreaker, HostedCircuitBreakerConfig, HostedDependency, HostedEdgeMetrics,
    HostedMetricEvent, HostedMetricSnapshot, HostedRateLimitConfig, HostedRateLimiter,
    HostedReadiness, HostedReadinessSnapshot,
};
pub use proxy::{
    HostedForwardingHeaders, HostedRequestContext, HostedTrustedProxy, HostedTrustedProxyConfig,
};
pub use tls::{HostedTlsConfig, HostedTlsReload, HostedTlsState};
