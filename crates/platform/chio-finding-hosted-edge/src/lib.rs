//! Fail-closed hosted cognition-market edge primitives.
//!
//! The crate authenticates exactly one explicitly selected credential mode
//! before a request body reaches market handlers. Capability credentials bind
//! a short-lived Chio capability and DPoP proof to the deployment, tenant,
//! action, external target, and body digest. API keys retain only an HMAC
//! verifier protected by a deployment pepper.

#![forbid(unsafe_code)]

pub use chio_finding_market_port::{
    HostedApiKeyLifecyclePort, HostedApiKeyRecord, HostedAuthPort, HostedMarketPortError,
    HostedPortWriteOutcome, HostedPrincipal, HostedPrincipalRole, HostedTenantId,
};

mod auth;
mod contracts;
mod error;
mod lifecycle;
mod operations;
mod proxy;
mod server;
mod tls;

pub use auth::{
    ApiKeyPepper, HostedAuthCredential, HostedAuthMethod, HostedAuthRepository, HostedAuthRequest,
    HostedAuthenticatedPrincipal, HostedAuthenticator, HostedAuthenticatorConfig,
    HostedTenantAuthPolicy, StaticApiKeyPepper,
};
pub use chio_finding_market_port::{
    HostedAuthenticatedFindingDelivery, HostedDomainMutation, HostedHttpPage, HostedHttpProjection,
    HostedMarketBackend, HostedMarketBackendError, HostedMarketBackendOutcome,
    HOSTED_AUTHENTICATED_DELIVERY_SCHEMA,
};
pub use contracts::{
    HostedDomainEventEnvelope, HostedHttpMethod, HostedMutationOutcome, HostedMutationResponse,
    HostedRequestContract, HostedTenantBinding, HOSTED_DOMAIN_EVENT_SCHEMA,
    HOSTED_MUTATION_RESPONSE_SCHEMA, HOSTED_REQUEST_CONTRACT_SCHEMA, HOSTED_TENANT_BINDING_SCHEMA,
    HOSTED_TENANT_HEADER,
};
pub use error::{HostedEdgeError, HostedErrorBody, HOSTED_ERROR_SCHEMA};
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
pub use server::{
    hosted_market_router, serve_hosted_market_loopback, serve_hosted_market_loopback_with_shutdown,
    HostedHttpServerConfig, HostedHttpServerState, HostedReleaseIdentity,
    HOSTED_RELEASE_IDENTITY_SCHEMA,
};
pub use tls::{HostedTlsConfig, HostedTlsReload, HostedTlsState};
