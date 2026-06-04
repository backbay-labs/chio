use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidPublicKey,
    InvalidHex,
    InvalidSignature,
    Json,
    CanonicalJson,
    CapabilityExpired,
    CapabilityNotYetValid,
    CapabilityRevoked,
    DelegationChainBroken,
    AttenuationViolation,
    ScopeMismatch,
    SignatureVerificationFailed,
    DelegationDepthExceeded,
    InvalidHashLength,
    MerkleProofFailed,
    EmptyTree,
    InvalidProofIndex,
    EmptyManifest,
    DuplicateToolName,
    InvalidToolName,
    InvalidInputSchema,
    InvalidOutputSchema,
    DuplicateServerTool,
    InvalidManifestField,
    InvalidRequiredPermission,
    DuplicateRequiredPermission,
    UnsupportedSchema,
    ManifestVerificationFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] chio_core::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Manifest(#[from] chio_manifest::ManifestError),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Core(error) => core_error_code(error),
            Self::Json(_) => ErrorCode::Json,
            Self::Manifest(error) => match error {
                chio_manifest::ManifestError::Signing(source) => core_error_code(source),
                chio_manifest::ManifestError::EmptyManifest => ErrorCode::EmptyManifest,
                chio_manifest::ManifestError::DuplicateToolName(_) => ErrorCode::DuplicateToolName,
                chio_manifest::ManifestError::InvalidToolName(_) => ErrorCode::InvalidToolName,
                chio_manifest::ManifestError::InvalidManifestField(_) => {
                    ErrorCode::InvalidManifestField
                }
                chio_manifest::ManifestError::InvalidInputSchema(_) => {
                    ErrorCode::InvalidInputSchema
                }
                chio_manifest::ManifestError::InvalidOutputSchema(_) => {
                    ErrorCode::InvalidOutputSchema
                }
                chio_manifest::ManifestError::DuplicateServerTool(_) => {
                    ErrorCode::DuplicateServerTool
                }
                chio_manifest::ManifestError::InvalidRequiredPermission { .. } => {
                    ErrorCode::InvalidRequiredPermission
                }
                chio_manifest::ManifestError::DuplicateRequiredPermission { .. } => {
                    ErrorCode::DuplicateRequiredPermission
                }
                chio_manifest::ManifestError::UnsupportedSchema(_) => ErrorCode::UnsupportedSchema,
                chio_manifest::ManifestError::VerificationFailed => {
                    ErrorCode::ManifestVerificationFailed
                }
            },
        }
    }
}

fn core_error_code(error: &chio_core::Error) -> ErrorCode {
    match error {
        chio_core::Error::InvalidPublicKey(_) => ErrorCode::InvalidPublicKey,
        chio_core::Error::InvalidHex(_) => ErrorCode::InvalidHex,
        chio_core::Error::InvalidSignature(_) => ErrorCode::InvalidSignature,
        chio_core::Error::Json(_) => ErrorCode::Json,
        chio_core::Error::CanonicalJson(_) => ErrorCode::CanonicalJson,
        chio_core::Error::CapabilityExpired { .. } => ErrorCode::CapabilityExpired,
        chio_core::Error::CapabilityNotYetValid { .. } => ErrorCode::CapabilityNotYetValid,
        chio_core::Error::CapabilityRevoked { .. } => ErrorCode::CapabilityRevoked,
        chio_core::Error::DelegationChainBroken { .. } => ErrorCode::DelegationChainBroken,
        chio_core::Error::AttenuationViolation { .. } => ErrorCode::AttenuationViolation,
        chio_core::Error::ScopeMismatch { .. } => ErrorCode::ScopeMismatch,
        chio_core::Error::SignatureVerificationFailed => ErrorCode::SignatureVerificationFailed,
        chio_core::Error::DelegationDepthExceeded { .. } => ErrorCode::DelegationDepthExceeded,
        chio_core::Error::InvalidHashLength { .. } => ErrorCode::InvalidHashLength,
        chio_core::Error::MerkleProofFailed => ErrorCode::MerkleProofFailed,
        chio_core::Error::EmptyTree => ErrorCode::EmptyTree,
        chio_core::Error::InvalidProofIndex { .. } => ErrorCode::InvalidProofIndex,
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::{Error, ErrorCode};

    #[test]
    fn codes_map_core_errors() {
        let error = Error::from(chio_core::Error::CapabilityExpired { expires_at: 42 });
        assert_eq!(error.code(), ErrorCode::CapabilityExpired);
    }

    #[test]
    fn codes_map_manifest_errors() {
        let error = Error::from(chio_manifest::ManifestError::DuplicateToolName(
            "echo".to_string(),
        ));
        assert_eq!(error.code(), ErrorCode::DuplicateToolName);
    }

    #[test]
    fn codes_map_invalid_tool_name_manifest_errors() {
        let error = Error::from(chio_manifest::ManifestError::InvalidToolName(
            " echo ".to_string(),
        ));
        assert_eq!(error.code(), ErrorCode::InvalidToolName);
    }

    #[test]
    fn codes_map_invalid_schema_manifest_errors() {
        let input = Error::from(chio_manifest::ManifestError::InvalidInputSchema(
            "echo".to_string(),
        ));
        assert_eq!(input.code(), ErrorCode::InvalidInputSchema);

        let output = Error::from(chio_manifest::ManifestError::InvalidOutputSchema(
            "echo".to_string(),
        ));
        assert_eq!(output.code(), ErrorCode::InvalidOutputSchema);
    }

    #[test]
    fn codes_map_manifest_identity_and_permission_errors() {
        let identity = Error::from(chio_manifest::ManifestError::InvalidManifestField(
            "server_id",
        ));
        assert_eq!(identity.code(), ErrorCode::InvalidManifestField);

        let invalid_permission =
            Error::from(chio_manifest::ManifestError::InvalidRequiredPermission {
                field: "required_permissions.read_paths",
                value: String::new(),
            });
        assert_eq!(
            invalid_permission.code(),
            ErrorCode::InvalidRequiredPermission
        );

        let duplicate_permission =
            Error::from(chio_manifest::ManifestError::DuplicateRequiredPermission {
                field: "required_permissions.network_hosts",
                value: "api.example.com".to_string(),
            });
        assert_eq!(
            duplicate_permission.code(),
            ErrorCode::DuplicateRequiredPermission
        );
    }
}
