use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::crypto::{canonical_json_bytes, sha256_hex};
use crate::error::Result;

/// The Kernel's verdict on a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Decision {
    /// The tool call was allowed and executed.
    Allow,
    /// The tool call was denied.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
        /// The guard or validation step that triggered the denial.
        guard: String,
    },
    /// The tool call was interrupted by explicit cancellation.
    Cancelled {
        /// Human-readable reason for the cancellation.
        reason: String,
    },
    /// The tool call did not reach a complete terminal result.
    Incomplete {
        /// Human-readable reason for the incomplete terminal state.
        reason: String,
    },
}

/// Describes the tool call that was evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallAction {
    /// The parameters that were passed to the tool (or attempted).
    pub parameters: serde_json::Value,
    /// SHA-256 hash of the canonical JSON of `parameters`.
    pub parameter_hash: String,
}

impl ToolCallAction {
    /// Construct from raw parameters, computing the hash automatically.
    pub fn from_parameters(parameters: serde_json::Value) -> Result<Self> {
        let canonical = canonical_json_bytes(&parameters)?;
        let hash = sha256_hex(&canonical);
        Ok(Self {
            parameters,
            parameter_hash: hash,
        })
    }

    /// Verify that `parameter_hash` matches the canonical hash of `parameters`.
    pub fn verify_hash(&self) -> Result<bool> {
        let canonical = canonical_json_bytes(&self.parameters)?;
        let expected = sha256_hex(&canonical);
        Ok(self.parameter_hash == expected)
    }
}
