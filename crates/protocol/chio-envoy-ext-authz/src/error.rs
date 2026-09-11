//! Error types for the Chio ext_authz adapter.

use thiserror::Error;

/// Errors produced while translating an Envoy `CheckRequest` into a Chio
/// [`crate::translate::ToolCallRequest`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TranslateError {
    /// Envoy did not provide the entire body needed to bind authorization.
    #[error("complete request body is required; disable partial messages in Envoy ext_authz")]
    IncompleteBody,
    /// The `CheckRequest` did not carry an `AttributeContext`.
    #[error("check request is missing the attributes field")]
    MissingAttributes,

    /// The attributes did not include a nested `Request`.
    #[error("check request attributes are missing the request field")]
    MissingRequest,

    /// The request did not include an `HttpRequest` payload.
    #[error("check request is missing the HTTP request field")]
    MissingHttpRequest,

    /// The HTTP method string was empty or unrecognised.
    #[error("check request HTTP method is empty or invalid: {0:?}")]
    InvalidHttpMethod(String),
}

/// Errors returned by the [`crate::EnvoyKernel`] abstraction. The adapter
/// translates any error into a fail-closed `DeniedHttpResponse` with status
/// `500 Internal Server Error`, or `503 Service Unavailable` for a missing authority.
#[derive(Debug, Error)]
pub enum KernelError {
    /// The selected authority could not be reached or completed no response.
    #[error("authority unavailable: {0}")]
    Unavailable(String),
    /// The kernel rejected the request with a terminal internal error.
    #[error("kernel evaluation failed: {0}")]
    Evaluation(String),
}

impl KernelError {
    /// Construct a dependency availability error, without treating it as a policy denial.
    pub fn unavailable(reason: impl std::fmt::Display) -> Self {
        Self::Unavailable(reason.to_string())
    }

    /// Construct an evaluation error from any displayable value.
    pub fn evaluation(reason: impl std::fmt::Display) -> Self {
        Self::Evaluation(reason.to_string())
    }
}
