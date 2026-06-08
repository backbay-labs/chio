use alloc::format;
use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Declared verifier material required to treat a checkpoint publication as
/// trust-anchored rather than local-preview only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointPublicationTrustAnchorBinding {
    /// Typed publication surface identity declared for this publication path.
    pub publication_identity: CheckpointPublicationIdentity,
    /// Typed trust-anchor identity declared for this publication path.
    pub trust_anchor_identity: CheckpointTrustAnchorIdentity,
    /// Stable identifier for the trust anchor that vouches for the publication path.
    pub trust_anchor_ref: String,
    /// Stable identifier for the signer certificate or chain entry used by the publisher.
    pub signer_cert_ref: String,
    /// Versioned publication profile that defines the verifier policy for this path.
    pub publication_profile_version: String,
}

impl CheckpointPublicationTrustAnchorBinding {
    pub fn validate(&self) -> Result<()> {
        fn require_non_empty(value: &str, field: &str) -> Result<()> {
            if value.trim().is_empty() {
                return Err(Error::CanonicalJson(format!(
                    "{field} must not be empty for trust-anchored checkpoint publication"
                )));
            }
            Ok(())
        }

        if !self.publication_identity.has_identity() {
            return Err(Error::CanonicalJson(
                "publication_identity.identity must not be empty for trust-anchored checkpoint publication"
                    .to_string(),
            ));
        }
        if !self.trust_anchor_identity.has_identity() {
            return Err(Error::CanonicalJson(
                "trust_anchor_identity.identity must not be empty for trust-anchored checkpoint publication"
                    .to_string(),
            ));
        }
        require_non_empty(&self.trust_anchor_ref, "trust_anchor_ref")?;
        require_non_empty(&self.signer_cert_ref, "signer_cert_ref")?;
        require_non_empty(
            &self.publication_profile_version,
            "publication_profile_version",
        )?;
        Ok(())
    }
}

/// Declared publication surface family for a checkpoint publication record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointPublicationIdentityKind {
    LocalLog,
    TransparencyService,
    ImmutableRecord,
    ChainAnchor,
}

/// Optional typed publication identity carried alongside a checkpoint record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPublicationIdentity {
    pub kind: CheckpointPublicationIdentityKind,
    pub identity: String,
}

impl CheckpointPublicationIdentity {
    #[must_use]
    pub fn new(kind: CheckpointPublicationIdentityKind, identity: impl Into<String>) -> Self {
        Self {
            kind,
            identity: identity.into(),
        }
    }

    #[must_use]
    pub fn has_identity(&self) -> bool {
        !self.identity.trim().is_empty()
    }
}

/// Declared trust-anchor family for a checkpoint publication record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointTrustAnchorIdentityKind {
    OperatorRoot,
    Did,
    X509Root,
    TransparencyRoot,
    ChainRoot,
}

/// Optional typed trust-anchor identity carried alongside a checkpoint record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointTrustAnchorIdentity {
    pub kind: CheckpointTrustAnchorIdentityKind,
    pub identity: String,
}

impl CheckpointTrustAnchorIdentity {
    #[must_use]
    pub fn new(kind: CheckpointTrustAnchorIdentityKind, identity: impl Into<String>) -> Self {
        Self {
            kind,
            identity: identity.into(),
        }
    }

    #[must_use]
    pub fn has_identity(&self) -> bool {
        !self.identity.trim().is_empty()
    }
}
