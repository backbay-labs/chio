use std::sync::PoisonError;

#[derive(Debug, thiserror::Error)]
pub enum PheromoneRelayError {
    #[error("unsupported_schema: {0}")]
    UnsupportedSchema(String),
    #[error("duplicate_peer: {0}")]
    DuplicatePeer(String),
    #[error("duplicate_endpoint: {0}")]
    DuplicateEndpoint(String),
    #[error("peer_directory_unsigned: {0}")]
    PeerDirectoryUnsigned(String),
    #[error("unknown_peer_directory_issuer: {0}")]
    UnknownPeerDirectoryIssuer(String),
    #[error("peer_directory_rollback: {0}")]
    PeerDirectoryRollback(String),
    #[error("peer_directory_state_invalid: {0}")]
    PeerDirectoryStateInvalid(String),
    #[error("peer_removed: {0}")]
    PeerRemoved(String),
    #[error("unknown_peer: {0}")]
    UnknownPeer(String),
    #[error("peer_directory_stale: {0}")]
    PeerDirectoryStale(String),
    #[error("endpoint_denied: {0}")]
    EndpointDenied(String),
    #[error("relay_profile_denied: {0}")]
    RelayProfileDenied(String),
    #[error("supervisor_profile_invalid: {0}")]
    SupervisorProfileInvalid(String),
    #[error("catchup_denied: {0}")]
    CatchupDenied(String),
    #[error("body_hash_mismatch: {0}")]
    BodyHashMismatch(String),
    #[error("signature_invalid: relay request signature does not verify")]
    SignatureInvalid,
    #[error("relay_nonce_replay: {0}")]
    RelayNonceReplay(String),
    #[error("relay_request_stale: {0}")]
    RelayRequestStale(String),
    #[error("operator_auth_required: {0}")]
    OperatorAuthRequired(String),
    #[error("alert_routing_invalid: {0}")]
    AlertRoutingInvalid(String),
    #[error("alert_source_invalid: {0}")]
    AlertSourceInvalid(String),
    #[error("alert_handoff_invalid: {0}")]
    AlertHandoffInvalid(String),
    #[error("alert_delivery_invalid: {0}")]
    AlertDeliveryInvalid(String),
    #[error("alert_assurance_invalid: {0}")]
    AlertAssuranceInvalid(String),
    #[error("archive_package_invalid: {0}")]
    ArchivePackageInvalid(String),
    #[error("sender_mismatch: {0}")]
    SenderMismatch(String),
    #[error("recipient_mismatch: {0}")]
    RecipientMismatch(String),
    #[error("method_mismatch: {0}")]
    MethodMismatch(String),
    #[error("path_mismatch: {0}")]
    PathMismatch(String),
    #[error("json: {0}")]
    Json(String),
    #[error("canonical_json: {0}")]
    CanonicalJson(String),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("http: {0}")]
    Http(String),
    #[error("transport_error: {0}")]
    TransportError(String),
    #[error("store_poisoned: pheromone relay store lock is poisoned")]
    StorePoisoned,
}

impl PheromoneRelayError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "unsupported_schema",
            Self::DuplicatePeer(_) => "duplicate_peer",
            Self::DuplicateEndpoint(_) => "duplicate_endpoint",
            Self::PeerDirectoryUnsigned(_) => "peer_directory_unsigned",
            Self::UnknownPeerDirectoryIssuer(_) => "unknown_peer_directory_issuer",
            Self::PeerDirectoryRollback(_) => "peer_directory_rollback",
            Self::PeerDirectoryStateInvalid(_) => "peer_directory_state_invalid",
            Self::PeerRemoved(_) => "peer_removed",
            Self::UnknownPeer(_) => "unknown_peer",
            Self::PeerDirectoryStale(_) => "peer_directory_stale",
            Self::EndpointDenied(_) => "endpoint_denied",
            Self::RelayProfileDenied(_) => "relay_profile_denied",
            Self::SupervisorProfileInvalid(_) => "supervisor_profile_invalid",
            Self::CatchupDenied(_) => "catchup_denied",
            Self::BodyHashMismatch(_) => "body_hash_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::RelayNonceReplay(_) => "relay_nonce_replay",
            Self::RelayRequestStale(_) => "relay_request_stale",
            Self::OperatorAuthRequired(_) => "operator_auth_required",
            Self::AlertRoutingInvalid(_) => "alert_routing_invalid",
            Self::AlertSourceInvalid(_) => "alert_source_invalid",
            Self::AlertHandoffInvalid(_) => "alert_handoff_invalid",
            Self::AlertDeliveryInvalid(_) => "alert_delivery_invalid",
            Self::AlertAssuranceInvalid(_) => "alert_assurance_invalid",
            Self::ArchivePackageInvalid(_) => "archive_package_invalid",
            Self::SenderMismatch(_) => "sender_mismatch",
            Self::RecipientMismatch(_) => "recipient_mismatch",
            Self::MethodMismatch(_) => "method_mismatch",
            Self::PathMismatch(_) => "path_mismatch",
            Self::Json(_) => "json",
            Self::CanonicalJson(_) => "canonical_json",
            Self::Sqlite(_) => "sqlite",
            Self::Http(_) => "http",
            Self::TransportError(_) => "transport_error",
            Self::StorePoisoned => "store_poisoned",
        }
    }
}

impl From<rusqlite::Error> for PheromoneRelayError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error.to_string())
    }
}

impl From<serde_json::Error> for PheromoneRelayError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<std::io::Error> for PheromoneRelayError {
    fn from(error: std::io::Error) -> Self {
        Self::Http(error.to_string())
    }
}

impl<T> From<PoisonError<T>> for PheromoneRelayError {
    fn from(_: PoisonError<T>) -> Self {
        Self::StorePoisoned
    }
}
