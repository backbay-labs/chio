use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Opaque authenticated extension carried to the kernel verifier boundary.
///
/// Adapters may transport the base64 text but must never interpret it as a
/// caller-supplied quota key, maximum, or verified claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueSupplementalAuthorization {
    pub signed_extension: String,
}
