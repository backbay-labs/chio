use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedErrorBody {
    pub code: &'static str,
    pub message: &'static str,
    pub request_id: String,
    pub retryable: bool,
}

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
    #[error("hosted authentication capacity is unavailable")]
    CapacityUnavailable,
    #[error("hosted authentication dependency is unavailable")]
    DependencyUnavailable,
    #[error("hosted edge configuration is invalid")]
    Configuration,
}

impl HostedEdgeError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthorizationFailed => "authorization_failed",
            Self::ReplayRejected => "replay_rejected",
            Self::CapacityUnavailable => "authentication_capacity_unavailable",
            Self::DependencyUnavailable => "authentication_dependency_unavailable",
            Self::Configuration => "edge_configuration_invalid",
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::CapacityUnavailable | Self::DependencyUnavailable
        )
    }

    #[must_use]
    pub fn body(self, request_id: impl Into<String>) -> HostedErrorBody {
        HostedErrorBody {
            code: self.code(),
            message: match self {
                Self::InvalidRequest => "The request is invalid.",
                Self::AuthenticationFailed => "Authentication failed.",
                Self::AuthorizationFailed => "The credential does not authorize this action.",
                Self::ReplayRejected => "The proof was already used.",
                Self::CapacityUnavailable | Self::DependencyUnavailable => {
                    "Authentication is temporarily unavailable."
                }
                Self::Configuration => "The hosted edge is not ready.",
            },
            request_id: request_id.into(),
            retryable: self.retryable(),
        }
    }
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
    }
}
