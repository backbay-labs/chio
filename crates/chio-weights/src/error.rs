//! Typed model-card surface errors.
//!
//! Each variant is bound to a stable `urn:chio:error:weights:*` URN from the
//! workspace error-code registry. Every `Err(_)` returned from this crate carries one of these
//! variants; there is no untyped `String` error path. Variants are
//! non-exhaustive so callers cannot pattern-match past a future variant and
//! silently accept.

/// Error variants emitted by the model-card surface.
///
/// Variants align with `urn:chio:error:weights:*` codes registered in
/// `spec/errors/registry.yaml`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WeightsError {
    /// Canonical-JSON encoding or decoding failed. Fatal: do not retry until
    /// the encoding bug is resolved.
    #[error("model card canonical-json encode/decode failed: {0}")]
    Encoding(String),

    /// Required field is missing from the model card structure.
    #[error("model card missing required field: {0}")]
    MissingField(&'static str),

    /// Schema-level invariant rejected (e.g. weights_hash not 64 hex chars).
    #[error("model card schema rejected: {0}")]
    SchemaRejected(String),

    /// Card expired before the verifier evaluated it.
    #[error("model card expired at {expires_at}, now is {now}")]
    Expired {
        /// Card's `expires_at` field.
        expires_at: chrono::DateTime<chrono::Utc>,
        /// Verifier-side now.
        now: chrono::DateTime<chrono::Utc>,
    },

    /// Cosign bundle verify path rejected the bundle. Wraps the upstream
    /// `chio-attest-verify` error so receipt consumers can correlate.
    #[error("model card cosign bundle rejected: {0}")]
    BundleRejected(String),

    /// Loaded `weights_hash` does not match the card's `weights_hash`.
    /// Maps to `urn:chio:error:weights:card-mismatch`.
    #[error("weights_hash mismatch: card declares {expected}, runtime loaded {found}")]
    CardMismatch {
        /// Card's declared `weights_hash` (lowercase hex sha-256).
        expected: String,
        /// Runtime-loaded hash (lowercase hex sha-256).
        found: String,
    },

    /// Requested capability scope is not in the card's
    /// `allowed_capability_set`. Maps to
    /// `urn:chio:error:weights:scope-not-subset`.
    #[error("requested capability scope {scope:?} is not in card's allowed_capability_set")]
    ScopeNotSubset {
        /// First scope that violated subset containment.
        scope: String,
    },

    /// Requested tool is in the card's `banned_tools`. Maps to
    /// `urn:chio:error:weights:tool-banned`.
    #[error("requested tool {tool:?} is in card's banned_tools")]
    ToolBanned {
        /// Tool identifier that intersected `banned_tools`.
        tool: String,
    },
}

impl WeightsError {
    /// Stable URN for this error. Consumed by the LSP-driven typed-enum
    /// codegen and audit log surfaces.
    #[must_use]
    pub fn urn(&self) -> &'static str {
        match self {
            Self::Encoding(_) => "urn:chio:error:weights:internal-encoding",
            Self::MissingField(_) | Self::SchemaRejected(_) => {
                "urn:chio:error:weights:schema-rejected"
            }
            Self::Expired { .. } => "urn:chio:error:weights:card-expired",
            Self::BundleRejected(_) => "urn:chio:error:weights:bundle-rejected",
            Self::CardMismatch { .. } => "urn:chio:error:weights:card-mismatch",
            Self::ScopeNotSubset { .. } => "urn:chio:error:weights:scope-not-subset",
            Self::ToolBanned { .. } => "urn:chio:error:weights:tool-banned",
        }
    }
}
