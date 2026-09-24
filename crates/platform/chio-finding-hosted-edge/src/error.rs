use serde::Serialize;

/// Schema identifier pinned by every hosted error body.
pub const HOSTED_ERROR_SCHEMA: &str = "chio.finding.hosted-error.v1";
const MAX_REQUEST_ID_BYTES: usize = 128;
const FALLBACK_REQUEST_ID: &str = "invalid-request-id";

/// The uniform wire error body: stable code, fixed message, request id,
/// and whether retrying can help.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedErrorBody {
    pub schema: &'static str,
    pub code: &'static str,
    pub message: &'static str,
    pub request_id: String,
    pub retryable: bool,
}

/// Closed edge failure vocabulary; every variant maps to one stable
/// wire code and HTTP status.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostedEdgeError {
    #[error("hosted request is invalid")]
    InvalidRequest,
    #[error("hosted authentication failed")]
    AuthenticationFailed,
    #[error("hosted authorization failed")]
    AuthorizationFailed,
    #[error("hosted replay was rejected")]
    ReplayRejected,
    #[error("hosted request rate limit was exceeded")]
    RateLimited,
    #[error("hosted resource was not found")]
    NotFound,
    #[error("hosted mutation conflicts with durable state")]
    Conflict,
    #[error("hosted durable state failed validation")]
    IntegrityFailure,
    #[error("hosted authentication capacity is unavailable")]
    CapacityUnavailable,
    #[error("hosted edge request capacity is unavailable")]
    RequestCapacityUnavailable,
    #[error("hosted authentication dependency is unavailable")]
    DependencyUnavailable,
    #[error("hosted edge configuration is invalid")]
    Configuration,
}

impl HostedEdgeError {
    /// Stable machine-readable wire code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthorizationFailed => "authorization_failed",
            Self::ReplayRejected => "replay_rejected",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::IntegrityFailure => "integrity_failure",
            Self::CapacityUnavailable => "authentication_capacity_unavailable",
            Self::RequestCapacityUnavailable => "request_capacity_unavailable",
            Self::DependencyUnavailable => "authentication_dependency_unavailable",
            Self::Configuration => "edge_configuration_invalid",
        }
    }

    /// Whether a retry can succeed without operator action.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited
                | Self::CapacityUnavailable
                | Self::RequestCapacityUnavailable
                | Self::DependencyUnavailable
        )
    }

    /// The wire body for this error, with an invalid request id replaced
    /// by a fixed fallback so the response never echoes hostile bytes.
    #[must_use]
    pub fn body(self, request_id: impl Into<String>) -> HostedErrorBody {
        let request_id = request_id.into();
        let request_id = if valid_request_id(&request_id) {
            request_id
        } else {
            FALLBACK_REQUEST_ID.to_owned()
        };
        HostedErrorBody {
            schema: HOSTED_ERROR_SCHEMA,
            code: self.code(),
            message: match self {
                Self::InvalidRequest => "The request is invalid.",
                Self::AuthenticationFailed => "Authentication failed.",
                Self::AuthorizationFailed => "The credential does not authorize this action.",
                Self::ReplayRejected => "The proof was already used.",
                Self::RateLimited => "The request rate limit was exceeded.",
                Self::NotFound => "The requested resource was not found.",
                Self::Conflict => "The request conflicts with durable state.",
                Self::IntegrityFailure => "Durable state failed validation.",
                Self::CapacityUnavailable => {
                    "The service is temporarily unable to accept this request."
                }
                Self::RequestCapacityUnavailable => {
                    "The edge is temporarily unable to accept this request."
                }
                Self::DependencyUnavailable => "Authentication is temporarily unavailable.",
                Self::Configuration => "The hosted edge is not ready.",
            },
            request_id,
            retryable: self.retryable(),
        }
    }

    /// The HTTP status this error maps to.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::AuthenticationFailed => 401,
            Self::AuthorizationFailed => 403,
            Self::ReplayRejected | Self::RateLimited => 429,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::IntegrityFailure => 503,
            Self::CapacityUnavailable
            | Self::RequestCapacityUnavailable
            | Self::DependencyUnavailable => 503,
            Self::Configuration => 500,
        }
    }
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_errors_are_stable_and_non_reflective() {
        let body = HostedEdgeError::DependencyUnavailable.body("request-1");
        assert_eq!(body.code, "authentication_dependency_unavailable");
        assert!(body.retryable);
        assert!(!body.message.contains("SQL"));
        let sanitized = HostedEdgeError::InvalidRequest.body("\r\nsecret: leaked");
        assert_eq!(sanitized.request_id, FALLBACK_REQUEST_ID);
    }
}
