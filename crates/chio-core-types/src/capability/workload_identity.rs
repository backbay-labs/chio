use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};
use url::Url;

/// Normalized workload-identity scheme accepted by Chio runtime attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadIdentityScheme {
    Spiffe,
}

/// Upstream credential family that bound the workload identity to attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadCredentialKind {
    #[default]
    Uri,
    X509Svid,
    JwtSvid,
}

/// Normalized workload identity derived from runtime attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadIdentity {
    /// Identity scheme Chio recognized from the upstream evidence.
    pub scheme: WorkloadIdentityScheme,
    /// Credential family that authenticated the workload.
    pub credential_kind: WorkloadCredentialKind,
    /// Canonical workload identifier URI.
    pub uri: String,
    /// Stable trust domain resolved from the identifier.
    pub trust_domain: String,
    /// Canonical workload path within the trust domain.
    pub path: String,
}

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadIdentityError {
    #[cfg_attr(
        feature = "std",
        error("runtime_identity must not be empty when provided")
    )]
    EmptyRuntimeIdentity,

    #[cfg_attr(feature = "std", error("workload identity URI must not be empty"))]
    EmptyUri,

    #[cfg_attr(feature = "std", error("unsupported workload identity scheme '{0}'"))]
    UnsupportedScheme(String),

    #[cfg_attr(feature = "std", error("workload identity URI is malformed: {0}"))]
    MalformedUri(String),

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity must include a trust domain")
    )]
    MissingTrustDomain,

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity must not include userinfo or a port")
    )]
    InvalidAuthority,

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity must not include query or fragment")
    )]
    InvalidSuffix,

    #[cfg_attr(
        feature = "std",
        error("SPIFFE workload identity path '{0}' is invalid")
    )]
    InvalidPath(String),

    #[cfg_attr(
        feature = "std",
        error(
            "explicit workload identity conflicts with runtime_identity for {field}: expected '{expected}', got '{actual}'"
        )
    )]
    Conflict {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[cfg_attr(
        feature = "std",
        error(
            "runtime_identity '{0}' is opaque and cannot be reconciled with explicit workload_identity"
        )
    )]
    OpaqueRuntimeIdentityConflict(String),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for WorkloadIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyRuntimeIdentity => {
                write!(f, "runtime_identity must not be empty when provided")
            }
            Self::EmptyUri => write!(f, "workload identity URI must not be empty"),
            Self::UnsupportedScheme(v) => {
                write!(f, "unsupported workload identity scheme '{v}'")
            }
            Self::MalformedUri(v) => write!(f, "workload identity URI is malformed: {v}"),
            Self::MissingTrustDomain => {
                write!(f, "SPIFFE workload identity must include a trust domain")
            }
            Self::InvalidAuthority => write!(
                f,
                "SPIFFE workload identity must not include userinfo or a port"
            ),
            Self::InvalidSuffix => write!(
                f,
                "SPIFFE workload identity must not include query or fragment"
            ),
            Self::InvalidPath(v) => write!(f, "SPIFFE workload identity path '{v}' is invalid"),
            Self::Conflict {
                field,
                expected,
                actual,
            } => write!(
                f,
                "explicit workload identity conflicts with runtime_identity for {field}: expected '{expected}', got '{actual}'"
            ),
            Self::OpaqueRuntimeIdentityConflict(v) => write!(
                f,
                "runtime_identity '{v}' is opaque and cannot be reconciled with explicit workload_identity"
            ),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for WorkloadIdentityError {}

impl WorkloadIdentity {
    pub fn parse_spiffe_uri(uri: &str) -> core::result::Result<Self, WorkloadIdentityError> {
        Self::parse_spiffe_uri_with_kind(uri, WorkloadCredentialKind::Uri)
    }

    pub fn parse_spiffe_uri_with_kind(
        uri: &str,
        credential_kind: WorkloadCredentialKind,
    ) -> core::result::Result<Self, WorkloadIdentityError> {
        let trimmed = uri.trim();
        if trimmed.is_empty() {
            return Err(WorkloadIdentityError::EmptyUri);
        }

        let parsed = Url::parse(trimmed)
            .map_err(|_| WorkloadIdentityError::MalformedUri(trimmed.to_string()))?;
        if parsed.scheme() != "spiffe" {
            return Err(WorkloadIdentityError::UnsupportedScheme(
                parsed.scheme().to_string(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() || parsed.port().is_some() {
            return Err(WorkloadIdentityError::InvalidAuthority);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(WorkloadIdentityError::InvalidSuffix);
        }

        let Some(trust_domain) = parsed.host_str() else {
            return Err(WorkloadIdentityError::MissingTrustDomain);
        };
        let path = parsed.path();
        if path.is_empty() || !path.starts_with('/') || path.contains("//") {
            return Err(WorkloadIdentityError::InvalidPath(path.to_string()));
        }

        Ok(Self {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind,
            uri: trimmed.to_string(),
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
        })
    }

    pub fn validate(&self) -> core::result::Result<(), WorkloadIdentityError> {
        let parsed = match self.scheme {
            WorkloadIdentityScheme::Spiffe => {
                Self::parse_spiffe_uri_with_kind(&self.uri, self.credential_kind)?
            }
        };

        if self.trust_domain != parsed.trust_domain {
            return Err(WorkloadIdentityError::Conflict {
                field: "trust_domain",
                expected: parsed.trust_domain,
                actual: self.trust_domain.clone(),
            });
        }
        if self.path != parsed.path {
            return Err(WorkloadIdentityError::Conflict {
                field: "path",
                expected: parsed.path,
                actual: self.path.clone(),
            });
        }

        Ok(())
    }
}
