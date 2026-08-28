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

pub use auth::{
    ApiKeyPepper, HostedAuthCredential, HostedAuthMethod, HostedAuthRepository, HostedAuthRequest,
    HostedAuthenticatedPrincipal, HostedAuthenticator, HostedAuthenticatorConfig,
    HostedTenantAuthPolicy, StaticApiKeyPepper,
};
pub use error::{HostedEdgeError, HostedErrorBody};
