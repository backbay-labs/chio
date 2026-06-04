use crate::{PeerDirectoryDocument, PheromoneRelayError, RelayProfile, RelayProfileLimits};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use serde::Serialize;
use url::Url;

pub(crate) fn validate_endpoint(endpoint: &str) -> Result<(), PheromoneRelayError> {
    let url = Url::parse(endpoint)
        .map_err(|error| PheromoneRelayError::EndpointDenied(error.to_string()))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(PheromoneRelayError::EndpointDenied(format!(
                "endpoint scheme {scheme} is unsupported"
            )))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PheromoneRelayError::EndpointDenied(
            "endpoint credentials are not allowed".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(PheromoneRelayError::EndpointDenied(
            "endpoint query and fragment are not allowed".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_peer_directory_profile(
    document: &PeerDirectoryDocument,
    profile: RelayProfile,
    limits: &RelayProfileLimits,
) -> Result<(), PheromoneRelayError> {
    if limits.freshness_window_ms == 0 || limits.max_body_bytes == 0 {
        return Err(PheromoneRelayError::RelayProfileDenied(
            "relay profile limits must be positive".to_string(),
        ));
    }
    for peer in &document.peers {
        let url = Url::parse(&peer.endpoint)
            .map_err(|error| PheromoneRelayError::EndpointDenied(error.to_string()))?;
        match profile {
            RelayProfile::LocalDev => {
                if url.scheme() == "http" && !is_loopback_host(&url) {
                    return Err(PheromoneRelayError::EndpointDenied(format!(
                        "local-dev HTTP endpoint {} is not loopback",
                        peer.endpoint
                    )));
                }
            }
            RelayProfile::Production => {
                if url.scheme() != "https" {
                    return Err(PheromoneRelayError::EndpointDenied(format!(
                        "production endpoint {} must use HTTPS",
                        peer.endpoint
                    )));
                }
            }
        }
        if peer.max_batch_frames == 0 || peer.max_batch_frames > limits.max_batch_frames {
            return Err(PheromoneRelayError::RelayProfileDenied(format!(
                "peer {} max batch frames {} exceeds profile bound {}",
                peer.kernel_id, peer.max_batch_frames, limits.max_batch_frames
            )));
        }
        if peer.max_catchup_frames == 0 || peer.max_catchup_frames > limits.max_catchup_frames {
            return Err(PheromoneRelayError::RelayProfileDenied(format!(
                "peer {} max catch-up frames {} exceeds profile bound {}",
                peer.kernel_id, peer.max_catchup_frames, limits.max_catchup_frames
            )));
        }
        if peer.max_batch_frames > peer.max_catchup_frames {
            return Err(PheromoneRelayError::RelayProfileDenied(format!(
                "peer {} max batch frames {} exceeds max catch-up frames {}",
                peer.kernel_id, peer.max_batch_frames, peer.max_catchup_frames
            )));
        }
        if peer.max_catchup_bytes == 0 || peer.max_catchup_bytes > limits.max_catchup_bytes {
            return Err(PheromoneRelayError::RelayProfileDenied(format!(
                "peer {} max catch-up bytes {} exceeds profile bound {}",
                peer.kernel_id, peer.max_catchup_bytes, limits.max_catchup_bytes
            )));
        }
    }
    Ok(())
}

pub(crate) fn is_loopback_host(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

pub(crate) fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, PheromoneRelayError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn u64_from_i64(value: i64, field: &str) -> Result<u64, PheromoneRelayError> {
    u64::try_from(value).map_err(|_| PheromoneRelayError::Sqlite(format!("{field} is negative")))
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(|byte| is_lower_hex_byte(*byte))
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

#[cfg(test)]
mod tests {
    #[test]
    fn lower_hex_byte_helper_accepts_digest_alphabet_only() {
        for byte in b"0123456789abcdef" {
            assert!(super::is_lower_hex_byte(*byte), "{byte}");
        }

        for byte in b"ABCDEFg:-" {
            assert!(!super::is_lower_hex_byte(*byte), "{byte}");
        }
    }
}
