use base64::Engine as _;
use chio_core_types::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

use crate::FindingError;

/// Exact two-field plaintext envelope returned by `read_finding`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingRevealEnvelope {
    pub media_type: String,
    pub payload_b64: String,
}

/// Construct the canonical reveal envelope committed by `Finding.payload_sha256`.
#[must_use]
pub fn finding_reveal_envelope(media_type: &str, payload: &[u8]) -> FindingRevealEnvelope {
    FindingRevealEnvelope {
        media_type: media_type.to_owned(),
        payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
    }
}

/// Compute the digest committed by `Finding.payload_sha256`.
pub fn finding_payload_sha256(media_type: &str, payload: &[u8]) -> Result<String, FindingError> {
    let envelope = finding_reveal_envelope(media_type, payload);
    let canonical = chio_core_types::canonical_json_bytes(&envelope)
        .map_err(|_| FindingError::Canonicalization)?;
    Ok(sha256_hex(&canonical))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn payload_commitment_binds_media_type_and_canonical_base64() {
        let payload = b"patch";
        let envelope = finding_reveal_envelope("text/x-diff", payload);
        assert_eq!(envelope.payload_b64, "cGF0Y2g=");
        assert_eq!(
            finding_payload_sha256("text/x-diff", payload).unwrap(),
            sha256_hex(&chio_core_types::canonical_json_bytes(&envelope).unwrap())
        );
        assert_ne!(
            finding_payload_sha256("text/x-diff", payload).unwrap(),
            finding_payload_sha256("application/octet-stream", payload).unwrap()
        );
    }
}
