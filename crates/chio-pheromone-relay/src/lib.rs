//! Live Chiodos pheromone relay service and durable relay state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::{Keypair, PublicKey, Signature};
use chio_federation::PheromoneGossipBatch;
use chio_pheromone_runtime::PheromoneReceiveReport;
use rusqlite::{params, Connection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const PHEROMONE_PEER_DIRECTORY_SCHEMA: &str = "chio.pheromone.peer-directory.v1";
pub const PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA: &str = "chio.pheromone.peer-directory-bundle.v1";
pub const PHEROMONE_PEER_DIRECTORY_STATE_SCHEMA: &str = "chio.pheromone.peer-directory-state.v1";
pub const PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA: &str =
    "chio.pheromone.peer-directory-rotation-report.v1";
pub const PHEROMONE_RELAY_CONFIG_SCHEMA: &str = "chio.pheromone.relay-config.v1";
pub const PHEROMONE_RELAY_HTTP_REQUEST_SCHEMA: &str = "chio.pheromone.relay-http-request.v1";
pub const PHEROMONE_RELAY_TICK_REPORT_SCHEMA: &str = "chio.pheromone.relay-tick-report.v1";
pub const PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA: &str = "chio.pheromone.relay-operator-report.v1";
pub const PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA: &str = "chio.pheromone.relay-health-report.v1";
pub const PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA: &str =
    "chio.pheromone.relay-observability-report.v1";
pub const PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA: &str =
    "chio.pheromone.relay-metrics-snapshot.v1";
pub const PHEROMONE_RELAY_EVENT_REPORT_SCHEMA: &str = "chio.pheromone.relay-event-report.v1";
pub const PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA: &str =
    "chio.pheromone.relay-alert-routing-profile.v1";
pub const PHEROMONE_RELAY_ALERT_REPORT_SCHEMA: &str = "chio.pheromone.relay-alert-report.v1";
pub const PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA: &str =
    "chio.pheromone.relay-alert-suppression-state.v1";
pub const PHEROMONE_RELAY_TREND_REPORT_SCHEMA: &str = "chio.pheromone.relay-trend-report.v1";
pub const PHEROMONE_RELAY_ALERT_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.pheromone.relay-alert-negative-fixture-corpus.v1";
pub const PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA: &str =
    "chio.pheromone.relay-alert-handoff-profile.v1";
pub const PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA: &str =
    "chio.pheromone.relay-alert-handoff-report.v1";
pub const PHEROMONE_RELAY_ALERT_DRILL_REPORT_SCHEMA: &str =
    "chio.pheromone.relay-alert-drill-report.v1";
pub const PHEROMONE_RELAY_ALERT_HANDOFF_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.pheromone.relay-alert-handoff-negative-fixture-corpus.v1";
pub const PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA: &str =
    "chio.pheromone.relay-alert-delivery-profile.v1";
pub const PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA: &str =
    "chio.pheromone.relay-alert-delivery-evidence.v1";
pub const PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA: &str =
    "chio.pheromone.relay-alert-delivery-report.v1";
pub const PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA: &str =
    "chio.pheromone.relay-alert-acknowledgement-report.v1";
pub const PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA: &str =
    "chio.pheromone.relay-alert-handoff-drift-report.v1";
pub const PHEROMONE_RELAY_ALERT_DELIVERY_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.pheromone.relay-alert-delivery-negative-fixture-corpus.v1";
pub const PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA: &str =
    "chio.pheromone.relay-alert-normalization-profile.v1";
pub const PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA: &str =
    "chio.pheromone.relay-alert-normalization-report.v1";
pub const PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_V2_SCHEMA: &str =
    "chio.pheromone.relay-alert-delivery-drift-report.v2";
pub const PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA: &str =
    "chio.pheromone.relay-alert-route-owner-profile.v1";
pub const PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA: &str =
    "chio.pheromone.relay-alert-route-review-packet.v1";
pub const PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA: &str =
    "chio.pheromone.relay-alert-assurance-package.v1";
pub const PHEROMONE_RELAY_ALERT_ASSURANCE_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.pheromone.relay-alert-assurance-negative-fixture-corpus.v1";
pub const PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA: &str =
    "chio.pheromone.relay-supervisor-profile.v1";
pub const PHEROMONE_RELAY_DRILL_REPORT_SCHEMA: &str = "chio.pheromone.relay-drill-report.v1";
pub const PHEROMONE_CATCHUP_REQUEST_SCHEMA: &str = "chio.pheromone.catchup-request.v1";
pub const PHEROMONE_CATCHUP_RESPONSE_SCHEMA: &str = "chio.pheromone.catchup-response.v1";
pub const PHEROMONE_RELAY_NEGATIVE_CORPUS_SCHEMA: &str =
    "chio.pheromone.relay-negative-fixture-corpus.v1";

pub const PHEROMONE_BATCH_RELAY_PATH: &str = "/v1/chiodos/pheromone/batches";
pub const PHEROMONE_CATCHUP_RELAY_PATH: &str = "/v1/chiodos/pheromone/catchup";
pub const PHEROMONE_HEALTH_PATH: &str = "/v1/chiodos/pheromone/health";
pub const PHEROMONE_READY_PATH: &str = "/v1/chiodos/pheromone/ready";
pub const PHEROMONE_RELAY_OBSERVABILITY_PATH: &str = "/v1/chiodos/pheromone/observability";
pub const PHEROMONE_RELAY_METRICS_PATH: &str = "/v1/chiodos/pheromone/metrics";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRole {
    Origin,
    Hub,
    Receiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayProfile {
    LocalDev,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayProfileLimits {
    pub freshness_window_ms: u64,
    pub max_body_bytes: usize,
    pub max_batch_frames: usize,
    pub max_catchup_frames: usize,
    pub max_catchup_bytes: usize,
}

impl RelayProfileLimits {
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            max_batch_frames: 128,
            max_catchup_frames: 256,
            max_catchup_bytes: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayLadderRef {
    pub ladder_manifest_id: String,
    pub ladder_manifest_sha256: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryEntry {
    pub kernel_id: String,
    pub public_key: PublicKey,
    pub endpoint: String,
    pub treaty_subscriptions: Vec<String>,
    pub relay_role: RelayRole,
    pub allowed_subject_class_namespaces: Vec<String>,
    pub accepted_ladder_refs: Vec<RelayLadderRef>,
    pub max_batch_frames: usize,
    pub max_catchup_frames: usize,
    pub max_catchup_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub peers: Vec<PeerDirectoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryBundleBody {
    pub schema: String,
    pub issuer: String,
    pub key_id: String,
    pub directory_sha256: String,
    pub version: u64,
    pub previous_version_sha256: Option<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryBundleDocument {
    pub schema: String,
    pub body: PeerDirectoryBundleBody,
    pub directory: PeerDirectoryDocument,
    pub signature: Signature,
}

#[derive(Debug, Clone)]
pub struct TrustedPeerDirectoryIssuer {
    pub issuer: String,
    pub key_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct PeerDirectoryBundleTrust {
    pub issuers: Vec<TrustedPeerDirectoryIssuer>,
    pub min_version: u64,
    pub now_unix_ms: u64,
    pub profile: RelayProfile,
    pub limits: RelayProfileLimits,
}

pub struct PeerDirectoryBundleSigningInput<'a> {
    pub issuer: &'a str,
    pub key_id: &'a str,
    pub version: u64,
    pub previous_version_sha256: Option<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub directory: &'a PeerDirectoryDocument,
    pub keypair: &'a Keypair,
}

#[derive(Debug, Clone)]
pub struct PeerDirectory {
    document: PeerDirectoryDocument,
    peers: BTreeMap<String, PeerDirectoryEntry>,
    version: Option<u64>,
    removed_peer_ids: BTreeSet<String>,
}

impl PeerDirectory {
    pub fn from_document(
        document: PeerDirectoryDocument,
        now_unix_ms: u64,
    ) -> Result<Self, PheromoneRelayError> {
        Self::from_document_internal(document, now_unix_ms, None, BTreeSet::new())
    }

    pub fn from_document_with_profile(
        document: PeerDirectoryDocument,
        now_unix_ms: u64,
        profile: RelayProfile,
        limits: &RelayProfileLimits,
    ) -> Result<Self, PheromoneRelayError> {
        validate_peer_directory_profile(&document, profile, limits)?;
        Self::from_document_internal(document, now_unix_ms, None, BTreeSet::new())
    }

    fn from_document_internal(
        document: PeerDirectoryDocument,
        now_unix_ms: u64,
        version: Option<u64>,
        removed_peer_ids: BTreeSet<String>,
    ) -> Result<Self, PheromoneRelayError> {
        if document.schema != PHEROMONE_PEER_DIRECTORY_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(document.schema));
        }
        if document.local_kernel_id.trim().is_empty() {
            return Err(PheromoneRelayError::PeerDirectoryStale(
                "local kernel id is empty".to_string(),
            ));
        }
        if now_unix_ms < document.issued_at_unix_ms || now_unix_ms >= document.expires_at_unix_ms {
            return Err(PheromoneRelayError::PeerDirectoryStale(
                "peer directory is outside its validity window".to_string(),
            ));
        }
        let mut peers = BTreeMap::new();
        let mut endpoints = BTreeSet::new();
        for peer in &document.peers {
            if peer.kernel_id.trim().is_empty() {
                return Err(PheromoneRelayError::UnknownPeer(
                    "peer kernel id is empty".to_string(),
                ));
            }
            if peers.contains_key(&peer.kernel_id) {
                return Err(PheromoneRelayError::DuplicatePeer(peer.kernel_id.clone()));
            }
            validate_endpoint(&peer.endpoint)?;
            if !endpoints.insert(peer.endpoint.clone()) {
                return Err(PheromoneRelayError::DuplicateEndpoint(
                    peer.endpoint.clone(),
                ));
            }
            peers.insert(peer.kernel_id.clone(), peer.clone());
        }
        if peers.is_empty() {
            return Err(PheromoneRelayError::UnknownPeer(
                "peer directory contains no peers".to_string(),
            ));
        }
        Ok(Self {
            document,
            peers,
            version,
            removed_peer_ids,
        })
    }

    #[must_use]
    pub fn local_kernel_id(&self) -> &str {
        &self.document.local_kernel_id
    }

    #[must_use]
    pub fn version(&self) -> Option<u64> {
        self.version
    }

    #[must_use]
    pub fn document(&self) -> &PeerDirectoryDocument {
        &self.document
    }

    pub fn peer(&self, kernel_id: &str) -> Result<&PeerDirectoryEntry, PheromoneRelayError> {
        if self.removed_peer_ids.contains(kernel_id) {
            return Err(PheromoneRelayError::PeerRemoved(kernel_id.to_string()));
        }
        self.peers
            .get(kernel_id)
            .ok_or_else(|| PheromoneRelayError::UnknownPeer(kernel_id.to_string()))
    }

    pub fn endpoint_for(&self, kernel_id: &str, path: &str) -> Result<String, PheromoneRelayError> {
        let peer = self.peer(kernel_id)?;
        let mut endpoint = peer.endpoint.trim_end_matches('/').to_string();
        endpoint.push_str(path);
        Ok(endpoint)
    }
}

pub fn peer_directory_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<PeerDirectory, PheromoneRelayError> {
    let document: PeerDirectoryDocument = serde_json::from_str(json)?;
    PeerDirectory::from_document(document, now_unix_ms)
}

pub fn peer_directory_from_json_with_profile(
    json: &str,
    now_unix_ms: u64,
    profile: RelayProfile,
    limits: &RelayProfileLimits,
) -> Result<PeerDirectory, PheromoneRelayError> {
    let document: PeerDirectoryDocument = serde_json::from_str(json)?;
    PeerDirectory::from_document_with_profile(document, now_unix_ms, profile, limits)
}

pub fn sign_peer_directory_bundle(
    input: PeerDirectoryBundleSigningInput<'_>,
) -> Result<PeerDirectoryBundleDocument, PheromoneRelayError> {
    let directory_sha256 = canonical_sha256(input.directory)?;
    let body = PeerDirectoryBundleBody {
        schema: PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        issuer: input.issuer.to_string(),
        key_id: input.key_id.to_string(),
        directory_sha256,
        version: input.version,
        previous_version_sha256: input.previous_version_sha256,
        issued_at_unix_ms: input.issued_at_unix_ms,
        expires_at_unix_ms: input.expires_at_unix_ms,
    };
    let (signature, _) = input
        .keypair
        .sign_canonical(&body)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    Ok(PeerDirectoryBundleDocument {
        schema: PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        body,
        directory: input.directory.clone(),
        signature,
    })
}

impl PeerDirectoryBundleDocument {
    pub fn verify(
        &self,
        trust: &PeerDirectoryBundleTrust,
    ) -> Result<PeerDirectory, PheromoneRelayError> {
        if self.schema != PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(self.schema.clone()));
        }
        if self.body.schema != PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(
                self.body.schema.clone(),
            ));
        }
        if self.body.version < trust.min_version {
            return Err(PheromoneRelayError::PeerDirectoryRollback(format!(
                "bundle version {} is below trusted floor {}",
                self.body.version, trust.min_version
            )));
        }
        if trust.now_unix_ms < self.body.issued_at_unix_ms
            || trust.now_unix_ms >= self.body.expires_at_unix_ms
        {
            return Err(PheromoneRelayError::PeerDirectoryStale(
                "peer directory bundle is outside its validity window".to_string(),
            ));
        }
        let actual_directory_sha256 = canonical_sha256(&self.directory)?;
        if actual_directory_sha256 != self.body.directory_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "directory hash {actual_directory_sha256} does not match signed hash {}",
                self.body.directory_sha256
            )));
        }
        let issuer = trust
            .issuers
            .iter()
            .find(|issuer| issuer.issuer == self.body.issuer && issuer.key_id == self.body.key_id)
            .ok_or_else(|| {
                PheromoneRelayError::UnknownPeerDirectoryIssuer(format!(
                    "{}#{}",
                    self.body.issuer, self.body.key_id
                ))
            })?;
        if !issuer
            .public_key
            .verify_canonical(&self.body, &self.signature)
            .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?
        {
            return Err(PheromoneRelayError::SignatureInvalid);
        }
        validate_peer_directory_profile(&self.directory, trust.profile, &trust.limits)?;
        PeerDirectory::from_document_internal(
            self.directory.clone(),
            trust.now_unix_ms,
            Some(self.body.version),
            BTreeSet::new(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryStateEntry {
    pub bundle: PeerDirectoryBundleDocument,
    pub bundle_sha256: String,
    pub directory_sha256: String,
    pub version: u64,
    pub promoted_at_unix_ms: u64,
    pub removed_peer_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryRejectedEntry {
    pub bundle_sha256: Option<String>,
    pub version: Option<u64>,
    pub rejected_at_unix_ms: u64,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryStateDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub version_floor: u64,
    pub active: Option<PeerDirectoryStateEntry>,
    pub candidate: Option<PeerDirectoryStateEntry>,
    pub rejected: Vec<PeerDirectoryRejectedEntry>,
}

impl PeerDirectoryStateDocument {
    #[must_use]
    pub fn new(local_kernel_id: &str, generated_at_unix_ms: u64) -> Self {
        Self {
            schema: PHEROMONE_PEER_DIRECTORY_STATE_SCHEMA.to_string(),
            local_kernel_id: local_kernel_id.to_string(),
            generated_at_unix_ms,
            version_floor: 0,
            active: None,
            candidate: None,
            rejected: Vec::new(),
        }
    }

    pub fn active_directory(
        &self,
        trust: &PeerDirectoryBundleTrust,
    ) -> Result<PeerDirectory, PheromoneRelayError> {
        if self.schema != PHEROMONE_PEER_DIRECTORY_STATE_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(self.schema.clone()));
        }
        let active = self.active.as_ref().ok_or_else(|| {
            PheromoneRelayError::PeerDirectoryStateInvalid(
                "peer directory state has no active bundle".to_string(),
            )
        })?;
        let actual_bundle_sha256 = canonical_sha256(&active.bundle)?;
        if actual_bundle_sha256 != active.bundle_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "active bundle hash {actual_bundle_sha256} does not match state hash {}",
                active.bundle_sha256
            )));
        }
        let actual_directory_sha256 = canonical_sha256(&active.bundle.directory)?;
        if actual_directory_sha256 != active.directory_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "active directory hash {actual_directory_sha256} does not match state hash {}",
                active.directory_sha256
            )));
        }
        if active.bundle.directory.local_kernel_id != self.local_kernel_id {
            return Err(PheromoneRelayError::PeerDirectoryStateInvalid(format!(
                "active directory local kernel {} does not match state {}",
                active.bundle.directory.local_kernel_id, self.local_kernel_id
            )));
        }
        let mut effective_trust = trust.clone();
        effective_trust.min_version = effective_trust.min_version.max(self.version_floor);
        let mut directory = active.bundle.verify(&effective_trust)?;
        directory.removed_peer_ids = active.removed_peer_ids.iter().cloned().collect();
        Ok(directory)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerDirectoryRotationReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub previous_version: Option<u64>,
    pub promoted_version: Option<u64>,
    pub active_bundle_sha256: Option<String>,
    pub candidate_bundle_sha256: Option<String>,
    pub removed_peer_ids: Vec<String>,
}

pub fn promote_peer_directory_candidate(
    state: &mut PeerDirectoryStateDocument,
    candidate: PeerDirectoryBundleDocument,
    trust: &PeerDirectoryBundleTrust,
    now_unix_ms: u64,
) -> Result<PeerDirectoryRotationReport, PheromoneRelayError> {
    if state.schema != PHEROMONE_PEER_DIRECTORY_STATE_SCHEMA {
        let error = PheromoneRelayError::UnsupportedSchema(state.schema.clone());
        record_rejected_candidate(state, Some(&candidate), now_unix_ms, &error);
        return Err(error);
    }
    if state.local_kernel_id != candidate.directory.local_kernel_id {
        let error = PheromoneRelayError::PeerDirectoryStateInvalid(format!(
            "candidate local kernel {} does not match state {}",
            candidate.directory.local_kernel_id, state.local_kernel_id
        ));
        record_rejected_candidate(state, Some(&candidate), now_unix_ms, &error);
        return Err(error);
    }
    let previous = state.active.clone();
    if let Some(active) = &previous {
        if candidate.body.version <= active.version {
            let error = PheromoneRelayError::PeerDirectoryRollback(format!(
                "candidate version {} is not higher than active version {}",
                candidate.body.version, active.version
            ));
            record_rejected_candidate(state, Some(&candidate), now_unix_ms, &error);
            return Err(error);
        }
        if candidate.body.previous_version_sha256.as_deref() != Some(active.bundle_sha256.as_str())
        {
            let error = PheromoneRelayError::PeerDirectoryRollback(
                "candidate previous version hash does not match active bundle".to_string(),
            );
            record_rejected_candidate(state, Some(&candidate), now_unix_ms, &error);
            return Err(error);
        }
    } else if candidate.body.previous_version_sha256.is_some() {
        let error = PheromoneRelayError::PeerDirectoryRollback(
            "initial candidate must not point at a previous bundle".to_string(),
        );
        record_rejected_candidate(state, Some(&candidate), now_unix_ms, &error);
        return Err(error);
    }

    let mut effective_trust = trust.clone();
    effective_trust.min_version = effective_trust.min_version.max(state.version_floor);
    if let Err(error) = candidate.verify(&effective_trust) {
        record_rejected_candidate(state, Some(&candidate), now_unix_ms, &error);
        return Err(error);
    }

    let bundle_sha256 = canonical_sha256(&candidate)?;
    let directory_sha256 = canonical_sha256(&candidate.directory)?;
    let removed_peer_ids = removed_peer_ids(previous.as_ref(), &candidate);
    let promoted_version = candidate.body.version;
    let entry = PeerDirectoryStateEntry {
        bundle: candidate,
        bundle_sha256: bundle_sha256.clone(),
        directory_sha256,
        version: promoted_version,
        promoted_at_unix_ms: now_unix_ms,
        removed_peer_ids: removed_peer_ids.clone(),
    };
    state.version_floor = state.version_floor.max(promoted_version);
    state.generated_at_unix_ms = now_unix_ms;
    state.active = Some(entry);
    state.candidate = None;

    Ok(PeerDirectoryRotationReport {
        schema: PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        detail: "peer directory candidate promoted".to_string(),
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        previous_version: previous.as_ref().map(|active| active.version),
        promoted_version: Some(promoted_version),
        active_bundle_sha256: Some(bundle_sha256.clone()),
        candidate_bundle_sha256: Some(bundle_sha256),
        removed_peer_ids,
    })
}

pub fn reject_peer_directory_candidate(
    state: &mut PeerDirectoryStateDocument,
    candidate: PeerDirectoryBundleDocument,
    reason: &str,
    now_unix_ms: u64,
) -> Result<PeerDirectoryRotationReport, PheromoneRelayError> {
    let bundle_sha256 = canonical_sha256(&candidate)?;
    let version = candidate.body.version;
    let error = PheromoneRelayError::PeerDirectoryStateInvalid(reason.to_string());
    state.rejected.push(PeerDirectoryRejectedEntry {
        bundle_sha256: Some(bundle_sha256.clone()),
        version: Some(version),
        rejected_at_unix_ms: now_unix_ms,
        code: error.code().to_string(),
        detail: reason.to_string(),
    });
    state.candidate = None;
    state.generated_at_unix_ms = now_unix_ms;
    Ok(PeerDirectoryRotationReport {
        schema: PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: error.code().to_string(),
        detail: reason.to_string(),
        local_kernel_id: state.local_kernel_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        previous_version: state.active.as_ref().map(|active| active.version),
        promoted_version: None,
        active_bundle_sha256: state
            .active
            .as_ref()
            .map(|active| active.bundle_sha256.clone()),
        candidate_bundle_sha256: Some(bundle_sha256),
        removed_peer_ids: Vec::new(),
    })
}

pub fn peer_directory_state_from_json(
    json: &str,
) -> Result<PeerDirectoryStateDocument, PheromoneRelayError> {
    let state: PeerDirectoryStateDocument = serde_json::from_str(json)?;
    if state.schema != PHEROMONE_PEER_DIRECTORY_STATE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(state.schema));
    }
    Ok(state)
}

fn record_rejected_candidate(
    state: &mut PeerDirectoryStateDocument,
    candidate: Option<&PeerDirectoryBundleDocument>,
    rejected_at_unix_ms: u64,
    error: &PheromoneRelayError,
) {
    let (bundle_sha256, version) = candidate
        .and_then(|candidate| {
            canonical_sha256(candidate)
                .ok()
                .map(|sha| (Some(sha), Some(candidate.body.version)))
        })
        .unwrap_or((None, None));
    state.rejected.push(PeerDirectoryRejectedEntry {
        bundle_sha256,
        version,
        rejected_at_unix_ms,
        code: error.code().to_string(),
        detail: error.to_string(),
    });
    state.generated_at_unix_ms = rejected_at_unix_ms;
}

fn removed_peer_ids(
    previous: Option<&PeerDirectoryStateEntry>,
    candidate: &PeerDirectoryBundleDocument,
) -> Vec<String> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let next_ids = candidate
        .directory
        .peers
        .iter()
        .map(|peer| peer.kernel_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut removed = previous
        .removed_peer_ids
        .iter()
        .filter(|peer_id| !next_ids.contains(peer_id.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    removed.extend(
        previous
            .bundle
            .directory
            .peers
            .iter()
            .filter(|peer| !next_ids.contains(peer.kernel_id.as_str()))
            .map(|peer| peer.kernel_id.clone()),
    );
    removed.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PheromoneRelayHttpRequest {
    pub schema: String,
    pub sender_kernel_id: String,
    pub recipient_kernel_id: String,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
    pub nonce: String,
    pub sent_at_unix_ms: u64,
    pub payload: Value,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PheromoneRelayHttpRequestSigningBody {
    schema: String,
    sender_kernel_id: String,
    recipient_kernel_id: String,
    method: String,
    path: String,
    body_sha256: String,
    nonce: String,
    sent_at_unix_ms: u64,
}

impl PheromoneRelayHttpRequest {
    pub fn verify_payload<T: DeserializeOwned>(
        &self,
        directory: &PeerDirectory,
        context: &RelayHttpVerificationContext,
        nonce_store: &(impl RelayNonceRecorder + ?Sized),
    ) -> Result<T, PheromoneRelayError> {
        self.verify_envelope(directory, context, nonce_store)?;
        serde_json::from_value(self.payload.clone()).map_err(PheromoneRelayError::from)
    }

    fn verify_envelope(
        &self,
        directory: &PeerDirectory,
        context: &RelayHttpVerificationContext,
        nonce_store: &(impl RelayNonceRecorder + ?Sized),
    ) -> Result<(), PheromoneRelayError> {
        if self.schema != PHEROMONE_RELAY_HTTP_REQUEST_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(self.schema.clone()));
        }
        if self.recipient_kernel_id != context.local_kernel_id {
            return Err(PheromoneRelayError::RecipientMismatch(format!(
                "request recipient {} does not match local receiver {}",
                self.recipient_kernel_id, context.local_kernel_id
            )));
        }
        if self.method != context.method {
            return Err(PheromoneRelayError::MethodMismatch(format!(
                "request method {} does not match {}",
                self.method, context.method
            )));
        }
        if self.path != context.path {
            return Err(PheromoneRelayError::PathMismatch(format!(
                "request path {} does not match {}",
                self.path, context.path
            )));
        }
        let peer = directory.peer(&self.sender_kernel_id)?;
        let signing_body = self.signing_body();
        if !peer
            .public_key
            .verify_canonical(&signing_body, &self.signature)
            .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?
        {
            return Err(PheromoneRelayError::SignatureInvalid);
        }
        let actual_hash = canonical_sha256(&self.payload)?;
        if actual_hash != self.body_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "payload hash {} does not match signed hash {}",
                actual_hash, self.body_sha256
            )));
        }
        let skew = self.sent_at_unix_ms.abs_diff(context.now_unix_ms);
        if skew > context.freshness_window_ms {
            return Err(PheromoneRelayError::RelayRequestStale(format!(
                "request skew {skew}ms exceeds {}ms",
                context.freshness_window_ms
            )));
        }
        nonce_store.record_relay_nonce(
            &self.sender_kernel_id,
            &self.nonce,
            context
                .now_unix_ms
                .saturating_add(context.freshness_window_ms),
        )
    }

    fn signing_body(&self) -> PheromoneRelayHttpRequestSigningBody {
        PheromoneRelayHttpRequestSigningBody {
            schema: self.schema.clone(),
            sender_kernel_id: self.sender_kernel_id.clone(),
            recipient_kernel_id: self.recipient_kernel_id.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            body_sha256: self.body_sha256.clone(),
            nonce: self.nonce.clone(),
            sent_at_unix_ms: self.sent_at_unix_ms,
        }
    }
}

pub struct RelayHttpSigningInput<'a, T: Serialize + ?Sized> {
    pub sender_kernel_id: &'a str,
    pub recipient_kernel_id: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub nonce: &'a str,
    pub sent_at_unix_ms: u64,
    pub payload: &'a T,
    pub keypair: &'a Keypair,
}

pub fn sign_relay_http_request<T: Serialize + ?Sized>(
    input: RelayHttpSigningInput<'_, T>,
) -> Result<PheromoneRelayHttpRequest, PheromoneRelayError> {
    let payload = serde_json::to_value(input.payload)?;
    let body_sha256 = canonical_sha256(&payload)?;
    let signing_body = PheromoneRelayHttpRequestSigningBody {
        schema: PHEROMONE_RELAY_HTTP_REQUEST_SCHEMA.to_string(),
        sender_kernel_id: input.sender_kernel_id.to_string(),
        recipient_kernel_id: input.recipient_kernel_id.to_string(),
        method: input.method.to_string(),
        path: input.path.to_string(),
        body_sha256,
        nonce: input.nonce.to_string(),
        sent_at_unix_ms: input.sent_at_unix_ms,
    };
    let (signature, _) = input
        .keypair
        .sign_canonical(&signing_body)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    Ok(PheromoneRelayHttpRequest {
        schema: signing_body.schema,
        sender_kernel_id: signing_body.sender_kernel_id,
        recipient_kernel_id: signing_body.recipient_kernel_id,
        method: signing_body.method,
        path: signing_body.path,
        body_sha256: signing_body.body_sha256,
        nonce: signing_body.nonce,
        sent_at_unix_ms: signing_body.sent_at_unix_ms,
        payload,
        signature,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHttpVerificationContext {
    pub local_kernel_id: String,
    pub method: String,
    pub path: String,
    pub now_unix_ms: u64,
    pub freshness_window_ms: u64,
}

pub trait RelayNonceRecorder: Send + Sync {
    fn record_relay_nonce(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError>;
}

pub trait PheromoneRelayStore: RelayNonceRecorder {
    fn enqueue_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        treaty_id: &str,
        batch: &PheromoneGossipBatch,
        queued_at_unix_ms: u64,
    ) -> Result<String, PheromoneRelayError>;

    fn lease_due_batches(
        &self,
        now_unix_ms: u64,
        max_batches: usize,
    ) -> Result<Vec<RelayOutboxBatch>, PheromoneRelayError>;

    fn mark_delivered(&self, outbox_id: &str) -> Result<(), PheromoneRelayError>;

    fn mark_retry(
        &self,
        outbox_id: &str,
        code: &str,
        next_attempt_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError>;

    fn mark_dead_letter(&self, outbox_id: &str, code: &str) -> Result<(), PheromoneRelayError>;
}

#[derive(Debug, Default)]
pub struct RelayNonceSet {
    inner: Mutex<BTreeSet<(String, String)>>,
}

impl RelayNonceRecorder for RelayNonceSet {
    fn record_relay_nonce(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        _expires_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let mut guard = self.inner.lock()?;
        if !guard.insert((sender_kernel_id.to_string(), nonce.to_string())) {
            return Err(PheromoneRelayError::RelayNonceReplay(nonce.to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatchupRequest {
    pub schema: String,
    pub requester_kernel_id: String,
    pub responder_kernel_id: String,
    pub treaty_id: String,
    pub after_cursor: String,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatchupResponse {
    pub schema: String,
    pub accepted: bool,
    pub responder_kernel_id: String,
    pub requester_kernel_id: String,
    pub treaty_id: String,
    pub frames: Vec<PheromoneGossipBatch>,
    pub next_cursor: String,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOutboxBatch {
    pub outbox_id: String,
    pub sender_kernel_id: String,
    pub recipient_kernel_id: String,
    pub treaty_id: String,
    pub batch: PheromoneGossipBatch,
    pub attempts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxRecordResult {
    pub inserted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTickReport {
    pub schema: String,
    pub accepted: bool,
    pub delivered: u64,
    pub retried: u64,
    pub dead_lettered: u64,
    pub duplicate_idempotent: u64,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOperatorReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayHealthCheck {
    pub code: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayHealthReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub peer_directory_version: Option<u64>,
    pub queue_depth: u64,
    pub oldest_pending_age_ms: Option<u64>,
    pub retry_count: u64,
    pub dead_letter_count: u64,
    pub inbox_count: u64,
    pub cursor_count: u64,
    pub stale_lease_count: u64,
    pub checks: Vec<RelayHealthCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMetricsFormat {
    Json,
    Prometheus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayQueueSummary {
    pub pending: u64,
    pub retry: u64,
    pub leased: u64,
    pub delivered: u64,
    pub dead_letter: u64,
    pub oldest_pending_age_ms: Option<u64>,
    pub stale_lease_count: u64,
    pub inbox_count: u64,
    pub cursor_count: u64,
    pub catchup_event_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDirectorySummary {
    pub active_version: Option<u64>,
    pub active_bundle_sha256: Option<String>,
    pub directory_sha256: Option<String>,
    pub issuer: Option<String>,
    pub expires_at_unix_ms: Option<u64>,
    pub removed_peer_count: u64,
    pub removed_peer_ids: Vec<String>,
    pub rejected_candidate_count: u64,
    pub last_rejection_code: Option<String>,
    pub profile: RelayProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayFailureSummary {
    pub code: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOperatorRecommendation {
    pub code: String,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayObservabilityReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub directory: RelayDirectorySummary,
    pub queue: RelayQueueSummary,
    pub recent_failures: Vec<RelayFailureSummary>,
    pub recommendations: Vec<RelayOperatorRecommendation>,
}

pub struct RelayObservabilityInput<'a> {
    pub local_kernel_id: &'a str,
    pub generated_at_unix_ms: u64,
    pub peer_directory: Option<&'a PeerDirectory>,
    pub peer_directory_state: Option<&'a PeerDirectoryStateDocument>,
    pub profile: RelayProfile,
    pub recent_failure_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayMetricSample {
    pub name: String,
    pub value: f64,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayMetricsSnapshot {
    pub schema: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub samples: Vec<RelayMetricSample>,
}

impl RelayMetricsSnapshot {
    #[must_use]
    pub fn render(&self, format: RelayMetricsFormat) -> String {
        match format {
            RelayMetricsFormat::Json => match serde_json::to_string_pretty(self) {
                Ok(json) => format!("{json}\n"),
                Err(error) => format!("{{\"schema\":\"{PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA}\",\"error\":\"{error}\"}}\n"),
            },
            RelayMetricsFormat::Prometheus => self.render_prometheus(),
        }
    }

    fn render_prometheus(&self) -> String {
        let mut output = String::new();
        let mut described = BTreeSet::new();
        for sample in &self.samples {
            if described.insert(sample.name.clone()) {
                let help = prometheus_help(&sample.name);
                let kind = prometheus_kind(&sample.name);
                output.push_str(&format!("# HELP {} {help}\n", sample.name));
                output.push_str(&format!("# TYPE {} {kind}\n", sample.name));
            }
            output.push_str(&sample.name);
            if !sample.labels.is_empty() {
                output.push('{');
                for (index, (name, value)) in sample.labels.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(name);
                    output.push_str("=\"");
                    output.push_str(&prometheus_label_value(value));
                    output.push('"');
                }
                output.push('}');
            }
            output.push(' ');
            output.push_str(&format_float(sample.value));
            output.push('\n');
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayEventReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub event_kind: String,
    pub stable_failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayAlertRouteKind {
    PagerDuty,
    OpsGenie,
    Slack,
    Email,
    Webhook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayAlertSeverity {
    Info,
    Warning,
    Critical,
}

impl RelayAlertSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRoute {
    pub route_id: String,
    pub kind: RelayAlertRouteKind,
    pub notification_route: String,
    pub opsgenie: String,
    pub target_ref: String,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRule {
    pub alert_code: String,
    pub route_id: String,
    pub severity: RelayAlertSeverity,
    pub min_window_ms: u64,
    pub unsuppressible: bool,
    pub require_event_evidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRoutingProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_source_age_ms: u64,
    pub max_suppression_ms: u64,
    pub allowed_label_names: Vec<String>,
    pub routes: Vec<RelayAlertRoute>,
    pub rules: Vec<RelayAlertRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertSuppressionEntry {
    pub alert_code: String,
    pub route_id: String,
    pub reason: String,
    pub starts_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertSuppressionStateDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub entries: Vec<RelayAlertSuppressionEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertCheck {
    pub code: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlert {
    pub code: String,
    pub state: String,
    pub severity: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub dedupe_key: String,
    pub runbook: String,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub window_ms: u64,
    pub suppressed_until_unix_ms: Option<u64>,
    pub source_report_sha256: String,
    pub event_evidence_sha256: Vec<String>,
    pub recommendation_codes: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_report_sha256: String,
    pub alerts: Vec<RelayAlert>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertEvaluationInput<'a> {
    pub observability: &'a RelayObservabilityReport,
    pub routing_profile: &'a RelayAlertRoutingProfileDocument,
    pub suppression_state: Option<&'a RelayAlertSuppressionStateDocument>,
    pub event_reports: &'a [RelayEventReport],
    pub now_unix_ms: u64,
    pub expected_source_report_sha256: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrendPoint {
    pub code: String,
    pub count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrendReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub source_report_count: u64,
    pub event_report_count: u64,
    pub points: Vec<RelayTrendPoint>,
}

pub struct RelayTrendInput<'a> {
    pub local_kernel_id: &'a str,
    pub observability_reports: &'a [RelayObservabilityReport],
    pub event_reports: &'a [RelayEventReport],
    pub routing_profile: &'a RelayAlertRoutingProfileDocument,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayAlertHandoffSinkKind {
    #[serde(rename = "alertmanager")]
    Alertmanager,
    #[serde(rename = "pagerduty")]
    PagerDuty,
    #[serde(rename = "opsgenie")]
    OpsGenie,
    #[serde(rename = "slack")]
    Slack,
    #[serde(rename = "email")]
    Email,
    #[serde(rename = "webhook")]
    Webhook,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffReceiver {
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub severity_floor: RelayAlertSeverity,
    pub escalation_ref: String,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffEscalation {
    pub escalation_ref: String,
    pub severity: RelayAlertSeverity,
    pub max_delay_ms: u64,
    pub recommendation_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_alert_report_age_ms: u64,
    pub max_trend_report_age_ms: u64,
    pub receivers: Vec<RelayAlertHandoffReceiver>,
    pub escalations: Vec<RelayAlertHandoffEscalation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffRouteReadiness {
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub highest_severity: RelayAlertSeverity,
    pub alert_codes: Vec<String>,
    pub escalation_ref: String,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_alert_report_sha256: String,
    pub source_trend_report_sha256: String,
    pub firing_alert_count: u64,
    pub suppressed_alert_count: u64,
    pub critical_firing_count: u64,
    pub routes: Vec<RelayAlertHandoffRouteReadiness>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDrill {
    pub drill_id: String,
    pub scenario: String,
    pub expected_code: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub drills: Vec<RelayAlertDrill>,
}

pub struct RelayAlertHandoffInput<'a> {
    pub alert_report: &'a RelayAlertReport,
    pub trend_report: &'a RelayTrendReport,
    pub routing_profile: &'a RelayAlertRoutingProfileDocument,
    pub handoff_profile: &'a RelayAlertHandoffProfileDocument,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAlertDeliveryStatus {
    Delivered,
    Accepted,
    Failed,
    Delayed,
    Duplicate,
    Unknown,
    OperatorAcknowledged,
}

impl RelayAlertDeliveryStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Accepted => "accepted",
            Self::Failed => "failed",
            Self::Delayed => "delayed",
            Self::Duplicate => "duplicate",
            Self::Unknown => "unknown",
            Self::OperatorAcknowledged => "operator_acknowledged",
        }
    }

    #[must_use]
    pub const fn requires_attention(self) -> bool {
        matches!(self, Self::Failed | Self::Delayed | Self::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryReceiver {
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub severity_floor: RelayAlertSeverity,
    pub max_delay_ms: u64,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_handoff_report_age_ms: u64,
    pub max_evidence_age_ms: u64,
    pub max_acknowledgement_age_ms: u64,
    pub receivers: Vec<RelayAlertDeliveryReceiver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryEvidence {
    pub schema: String,
    pub local_kernel_id: String,
    pub observed_at_unix_ms: u64,
    pub result_id: String,
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub alert_code: String,
    pub dedupe_key: String,
    pub severity: RelayAlertSeverity,
    pub runbook: String,
    pub status: RelayAlertDeliveryStatus,
    pub source_handoff_report_sha256: String,
    pub downstream_evidence_sha256: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryResult {
    pub result_id: String,
    pub receiver_id: String,
    pub kind: RelayAlertHandoffSinkKind,
    pub target_ref: String,
    pub notification_route: String,
    pub opsgenie: String,
    pub alert_code: String,
    pub dedupe_key: String,
    pub severity: RelayAlertSeverity,
    pub runbook: String,
    pub status: RelayAlertDeliveryStatus,
    pub observed_at_unix_ms: u64,
    pub downstream_evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_handoff_report_sha256: String,
    pub source_alert_report_sha256: String,
    pub source_trend_report_sha256: String,
    pub critical_firing_count: u64,
    pub delivered_count: u64,
    pub delayed_count: u64,
    pub failed_count: u64,
    pub unknown_count: u64,
    pub results: Vec<RelayAlertDeliveryResult>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAcknowledgement {
    pub result_id: String,
    pub receiver_id: String,
    pub alert_code: String,
    pub dedupe_key: String,
    pub status: RelayAlertDeliveryStatus,
    pub acknowledged_at_unix_ms: u64,
    pub downstream_evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAcknowledgementReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_handoff_report_sha256: String,
    pub source_delivery_report_sha256: String,
    pub acknowledged_count: u64,
    pub pending_count: u64,
    pub failed_count: u64,
    pub acknowledgements: Vec<RelayAlertAcknowledgement>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffDrift {
    pub code: String,
    pub receiver_id: String,
    pub alert_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertHandoffDriftReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub handoff_report_count: u64,
    pub delivery_report_count: u64,
    pub drift_count: u64,
    pub drifts: Vec<RelayAlertHandoffDrift>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertNormalizationProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_source_age_ms: u64,
    pub receivers: Vec<RelayAlertDeliveryReceiver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertNormalizationReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_count: u64,
    pub normalized_count: u64,
    pub evidence_hashes: Vec<String>,
    pub evidence: Vec<RelayAlertDeliveryEvidence>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryDriftV2 {
    pub code: String,
    pub source_handoff_report_sha256: String,
    pub matched_delivery_report_sha256: Option<String>,
    pub receiver_id: String,
    pub alert_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertDeliveryDriftReportV2 {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
    pub handoff_report_count: u64,
    pub delivery_report_count: u64,
    pub drift_count: u64,
    pub drifts: Vec<RelayAlertDeliveryDriftV2>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteOwner {
    pub owner_alias: String,
    pub receiver_ids: Vec<String>,
    pub notification_routes: Vec<String>,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteOwnerProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_report_age_ms: u64,
    pub owners: Vec<RelayAlertRouteOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteReview {
    pub owner_alias: String,
    pub receiver_id: String,
    pub notification_route: String,
    pub alert_codes: Vec<String>,
    pub status: String,
    pub runbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertRouteReviewPacket {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_handoff_report_sha256: String,
    pub source_delivery_report_sha256: String,
    pub source_acknowledgement_report_sha256: String,
    pub source_drift_report_sha256: String,
    pub ready_route_count: u64,
    pub owner_review_count: u64,
    pub reviews: Vec<RelayAlertRouteReview>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssurancePackage {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_alert_report_sha256: String,
    pub source_trend_report_sha256: String,
    pub source_handoff_report_sha256: String,
    pub source_normalization_report_sha256: String,
    pub source_delivery_report_sha256: String,
    pub source_acknowledgement_report_sha256: String,
    pub source_drift_report_sha256: String,
    pub source_review_packet_sha256: String,
    pub firing_alert_count: u64,
    pub critical_firing_alert_count: u64,
    pub normalized_count: u64,
    pub ready_route_count: u64,
    pub delivery_attention_count: u64,
    pub acknowledgement_pending_count: u64,
    pub drift_count: u64,
    pub operator_action_codes: Vec<String>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertDeliveryInput<'a> {
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub evidence: &'a [RelayAlertDeliveryEvidence],
    pub now_unix_ms: u64,
}

pub struct RelayAlertAcknowledgementInput<'a> {
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertHandoffDriftInput<'a> {
    pub handoff_reports: &'a [RelayAlertHandoffReport],
    pub delivery_reports: &'a [RelayAlertDeliveryReport],
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
}

pub struct RelayAlertNormalizationInput<'a> {
    pub profile: &'a RelayAlertNormalizationProfileDocument,
    pub sources: &'a [Value],
    pub now_unix_ms: u64,
}

pub struct RelayAlertDeliveryDriftInputV2<'a> {
    pub handoff_reports: &'a [RelayAlertHandoffReport],
    pub delivery_reports: &'a [RelayAlertDeliveryReport],
    pub delivery_profile: &'a RelayAlertDeliveryProfileDocument,
    pub since_unix_ms: u64,
    pub until_unix_ms: u64,
}

pub struct RelayAlertRouteReviewInput<'a> {
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub acknowledgement_report: &'a RelayAlertAcknowledgementReport,
    pub drift_report: &'a RelayAlertDeliveryDriftReportV2,
    pub route_owner_profile: &'a RelayAlertRouteOwnerProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceInput<'a> {
    pub alert_report: &'a RelayAlertReport,
    pub trend_report: &'a RelayTrendReport,
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub normalization_report: &'a RelayAlertNormalizationReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub acknowledgement_report: &'a RelayAlertAcknowledgementReport,
    pub drift_report: &'a RelayAlertDeliveryDriftReportV2,
    pub review_packet: &'a RelayAlertRouteReviewPacket,
    pub now_unix_ms: u64,
}

pub fn relay_alert_routing_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertRoutingProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertRoutingProfileDocument = serde_json::from_str(json)?;
    validate_alert_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_suppression_state_from_json(
    json: &str,
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<RelayAlertSuppressionStateDocument, PheromoneRelayError> {
    let state: RelayAlertSuppressionStateDocument = serde_json::from_str(json)?;
    validate_suppression_state(&state, profile)?;
    Ok(state)
}

pub fn relay_alert_handoff_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertHandoffProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertHandoffProfileDocument = serde_json::from_str(json)?;
    validate_handoff_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_delivery_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertDeliveryProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertDeliveryProfileDocument = serde_json::from_str(json)?;
    validate_delivery_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_delivery_evidence_from_json(
    json: &str,
) -> Result<RelayAlertDeliveryEvidence, PheromoneRelayError> {
    let evidence: RelayAlertDeliveryEvidence = serde_json::from_str(json)?;
    validate_delivery_evidence_shape(&evidence)?;
    Ok(evidence)
}

pub fn evaluate_relay_alerts(
    input: RelayAlertEvaluationInput<'_>,
) -> Result<RelayAlertReport, PheromoneRelayError> {
    validate_alert_profile(input.routing_profile, input.now_unix_ms)?;
    if let Some(state) = input.suppression_state {
        validate_suppression_state(state, input.routing_profile)?;
    }
    validate_observability_source(
        input.observability,
        input.routing_profile,
        input.now_unix_ms,
    )?;
    let source_report_sha256 = canonical_sha256(input.observability)?;
    if let Some(expected) = input.expected_source_report_sha256 {
        if expected != source_report_sha256 {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "observability report hash does not match caller expectation".to_string(),
            ));
        }
    }

    let routes = alert_route_map(input.routing_profile)?;
    let rules = alert_rule_map(input.routing_profile)?;
    let mut checks = vec![RelayAlertCheck {
        code: "source_report".to_string(),
        accepted: true,
        detail: "observability report is current and hash-bound".to_string(),
    }];
    let mut alerts = Vec::new();
    let recommendation_codes = input
        .observability
        .recommendations
        .iter()
        .map(|recommendation| recommendation.code.clone())
        .collect::<Vec<_>>();

    for recommendation in &input.observability.recommendations {
        let rule = rules.get(&recommendation.code).ok_or_else(|| {
            PheromoneRelayError::AlertRoutingInvalid(format!(
                "recommendation code {} has no alert rule",
                recommendation.code
            ))
        })?;
        let route = routes.get(&rule.route_id).ok_or_else(|| {
            PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert route {} is not defined",
                rule.route_id
            ))
        })?;
        let event_evidence_sha256 = matching_event_evidence(&recommendation.code, &input)?;
        if rule.require_event_evidence && event_evidence_sha256.is_empty() {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} requires bounded event evidence",
                recommendation.code
            )));
        }
        let suppressed_until_unix_ms = if rule.unsuppressible {
            None
        } else {
            active_suppression_until(
                input.suppression_state,
                &rule.alert_code,
                &rule.route_id,
                input.now_unix_ms,
            )
        };
        let state = if suppressed_until_unix_ms.is_some() {
            "suppressed"
        } else {
            "firing"
        };
        let labels = alert_labels(route, rule)?;
        alerts.push(RelayAlert {
            code: rule.alert_code.clone(),
            state: state.to_string(),
            severity: rule.severity.as_str().to_string(),
            notification_route: route.notification_route.clone(),
            opsgenie: route.opsgenie.clone(),
            dedupe_key: format!(
                "chiodos-relay:{}:{}:{}",
                input.observability.local_kernel_id, rule.alert_code, route.route_id
            ),
            runbook: route.runbook.clone(),
            first_seen_unix_ms: input.observability.generated_at_unix_ms,
            last_seen_unix_ms: input.now_unix_ms,
            window_ms: rule.min_window_ms,
            suppressed_until_unix_ms,
            source_report_sha256: source_report_sha256.clone(),
            event_evidence_sha256,
            recommendation_codes: recommendation_codes.clone(),
            labels,
        });
    }
    let accepted = alerts.iter().all(|alert| alert.state == "suppressed");
    checks.push(RelayAlertCheck {
        code: "routing_profile".to_string(),
        accepted: true,
        detail: "alert routing profile uses bounded routes and labels".to_string(),
    });
    Ok(RelayAlertReport {
        schema: PHEROMONE_RELAY_ALERT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "alerts_firing"
        }
        .to_string(),
        local_kernel_id: input.observability.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_report_sha256,
        alerts,
        checks,
    })
}

pub fn evaluate_relay_alert_handoff(
    input: RelayAlertHandoffInput<'_>,
) -> Result<RelayAlertHandoffReport, PheromoneRelayError> {
    validate_alert_profile(input.routing_profile, input.now_unix_ms)?;
    validate_handoff_profile(input.handoff_profile, input.now_unix_ms)?;
    validate_handoff_sources(&input)?;
    let source_alert_report_sha256 = canonical_sha256(input.alert_report)?;
    let source_trend_report_sha256 = canonical_sha256(input.trend_report)?;
    let route_map = alert_route_map(input.routing_profile)?;
    let rule_map = alert_rule_map(input.routing_profile)?;
    let receiver_by_route = handoff_receiver_route_map(input.handoff_profile)?;
    let escalation_by_ref = handoff_escalation_map(input.handoff_profile)?;
    for route in route_map.values() {
        let receiver = receiver_by_route
            .get(&(route.notification_route.clone(), route.opsgenie.clone()))
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "route {} has no downstream handoff receiver",
                    route.route_id
                ))
            })?;
        if receiver.target_ref != route.target_ref || receiver.runbook != route.runbook {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "route {} handoff target does not match routing profile",
                route.route_id
            )));
        }
    }

    let mut checks = vec![
        RelayAlertCheck {
            code: "alert_report".to_string(),
            accepted: true,
            detail: "alert report is fresh and schema-bound".to_string(),
        },
        RelayAlertCheck {
            code: "trend_report".to_string(),
            accepted: true,
            detail: "trend report is fresh and schema-bound".to_string(),
        },
        RelayAlertCheck {
            code: "route_coverage".to_string(),
            accepted: true,
            detail: "every routing profile route has a downstream handoff receiver".to_string(),
        },
    ];
    let mut route_readiness = BTreeMap::<String, RelayAlertHandoffRouteReadiness>::new();
    let mut firing_alert_count = 0u64;
    let mut suppressed_alert_count = 0u64;
    let mut critical_firing_count = 0u64;

    for alert in &input.alert_report.alerts {
        if alert.state == "suppressed" {
            suppressed_alert_count = suppressed_alert_count.saturating_add(1);
            continue;
        }
        if alert.state != "firing" {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has unsupported state {}",
                alert.code, alert.state
            )));
        }
        firing_alert_count = firing_alert_count.saturating_add(1);
        let severity = relay_alert_severity_from_str(&alert.severity)?;
        if severity == RelayAlertSeverity::Critical {
            critical_firing_count = critical_firing_count.saturating_add(1);
        }
        let rule = rule_map.get(&alert.code).ok_or_else(|| {
            PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has no routing profile rule",
                alert.code
            ))
        })?;
        let route = route_map.get(&rule.route_id).ok_or_else(|| {
            PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} does not resolve to a routing profile route",
                alert.code
            ))
        })?;
        let receiver = receiver_by_route
            .get(&(route.notification_route.clone(), route.opsgenie.clone()))
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "alert {} has no downstream handoff receiver",
                    alert.code
                ))
            })?;
        if severity < receiver.severity_floor {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} severity is below receiver floor",
                alert.code
            )));
        }
        let escalation = escalation_by_ref
            .get(receiver.escalation_ref.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "alert {} has no downstream escalation mapping",
                    alert.code
                ))
            })?;
        if severity > escalation.severity {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} severity exceeds downstream escalation mapping",
                alert.code
            )));
        }
        let readiness = route_readiness
            .entry(receiver.target_ref.clone())
            .or_insert_with(|| RelayAlertHandoffRouteReadiness {
                receiver_id: receiver.receiver_id.clone(),
                kind: receiver.kind,
                target_ref: receiver.target_ref.clone(),
                notification_route: receiver.notification_route.clone(),
                opsgenie: receiver.opsgenie.clone(),
                highest_severity: severity,
                alert_codes: Vec::new(),
                escalation_ref: receiver.escalation_ref.clone(),
                ready: true,
            });
        if severity > readiness.highest_severity {
            readiness.highest_severity = severity;
        }
        if !readiness.alert_codes.contains(&alert.code) {
            readiness.alert_codes.push(alert.code.clone());
        }
    }

    checks.push(RelayAlertCheck {
        code: "handoff_dry_run".to_string(),
        accepted: true,
        detail: "all firing alerts are routeable without sending notifications".to_string(),
    });
    Ok(RelayAlertHandoffReport {
        schema: PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.alert_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_alert_report_sha256,
        source_trend_report_sha256,
        firing_alert_count,
        suppressed_alert_count,
        critical_firing_count,
        routes: route_readiness.into_values().collect(),
        checks,
    })
}

pub fn evaluate_relay_alert_delivery(
    input: RelayAlertDeliveryInput<'_>,
) -> Result<RelayAlertDeliveryReport, PheromoneRelayError> {
    validate_delivery_profile(input.delivery_profile, input.now_unix_ms)?;
    validate_delivery_handoff_report(
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    let source_handoff_report_sha256 = canonical_sha256(input.handoff_report)?;
    let receiver_map = delivery_receiver_map(input.delivery_profile)?;
    let route_map = handoff_route_map(input.handoff_report)?;
    let mut seen_results = BTreeSet::new();
    let mut seen_alerts = BTreeSet::new();
    let mut results = Vec::new();
    let mut delayed_count = 0u64;
    let mut failed_count = 0u64;
    let mut unknown_count = 0u64;

    for evidence in input.evidence {
        validate_delivery_evidence_shape(evidence)?;
        if evidence.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence local kernel id mismatch".to_string(),
            ));
        }
        if evidence.observed_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence timestamp is in the future".to_string(),
            ));
        }
        if input
            .now_unix_ms
            .saturating_sub(evidence.observed_at_unix_ms)
            > input.delivery_profile.max_evidence_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence is stale".to_string(),
            ));
        }
        if evidence.source_handoff_report_sha256 != source_handoff_report_sha256 {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence is not bound to the handoff report".to_string(),
            ));
        }
        if !seen_results.insert(evidence.result_id.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery result {}",
                evidence.result_id
            )));
        }
        let receiver = receiver_map
            .get(evidence.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "delivery evidence references unknown receiver {}",
                    evidence.receiver_id
                ))
            })?;
        let route = route_map
            .get(evidence.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "handoff report has no route for receiver {}",
                    evidence.receiver_id
                ))
            })?;
        if evidence.kind != receiver.kind
            || evidence.kind != route.kind
            || evidence.target_ref != receiver.target_ref
            || evidence.target_ref != route.target_ref
            || evidence.notification_route != receiver.notification_route
            || evidence.notification_route != route.notification_route
            || evidence.opsgenie != receiver.opsgenie
            || evidence.opsgenie != route.opsgenie
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence route does not match receiver {}",
                evidence.receiver_id
            )));
        }
        if evidence.runbook != receiver.runbook {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence runbook does not match receiver {}",
                evidence.receiver_id
            )));
        }
        if evidence.severity < receiver.severity_floor || evidence.severity < route.highest_severity
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence weakens alert severity for {}",
                evidence.alert_code
            )));
        }
        if !route.alert_codes.contains(&evidence.alert_code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence alert {} is not in handoff route",
                evidence.alert_code
            )));
        }
        if !seen_alerts.insert((evidence.receiver_id.as_str(), evidence.alert_code.as_str())) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery evidence for alert {}",
                evidence.alert_code
            )));
        }
        if evidence.status == RelayAlertDeliveryStatus::Delayed {
            delayed_count = delayed_count.saturating_add(1);
        } else if evidence.status == RelayAlertDeliveryStatus::Failed {
            failed_count = failed_count.saturating_add(1);
        } else if evidence.status == RelayAlertDeliveryStatus::Unknown {
            unknown_count = unknown_count.saturating_add(1);
        }
        results.push(RelayAlertDeliveryResult {
            result_id: evidence.result_id.clone(),
            receiver_id: evidence.receiver_id.clone(),
            kind: evidence.kind,
            target_ref: evidence.target_ref.clone(),
            notification_route: evidence.notification_route.clone(),
            opsgenie: evidence.opsgenie.clone(),
            alert_code: evidence.alert_code.clone(),
            dedupe_key: evidence.dedupe_key.clone(),
            severity: evidence.severity,
            runbook: evidence.runbook.clone(),
            status: evidence.status,
            observed_at_unix_ms: evidence.observed_at_unix_ms,
            downstream_evidence_sha256: evidence.downstream_evidence_sha256.clone(),
        });
    }

    let mut missing = Vec::new();
    for route in input
        .handoff_report
        .routes
        .iter()
        .filter(|route| route.ready)
    {
        for alert_code in &route.alert_codes {
            if !seen_alerts.contains(&(route.receiver_id.as_str(), alert_code.as_str())) {
                missing.push((route.receiver_id.clone(), alert_code.clone()));
            }
        }
    }
    if !missing.is_empty() {
        let rendered = missing
            .iter()
            .map(|(receiver, alert)| format!("{receiver}:{alert}"))
            .collect::<Vec<_>>()
            .join(",");
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "missing delivery evidence for {rendered}"
        )));
    }

    results.sort_by(|left, right| {
        left.receiver_id
            .cmp(&right.receiver_id)
            .then_with(|| left.alert_code.cmp(&right.alert_code))
            .then_with(|| left.result_id.cmp(&right.result_id))
    });
    let delivered_count = results
        .iter()
        .filter(|result| {
            matches!(
                result.status,
                RelayAlertDeliveryStatus::Delivered
                    | RelayAlertDeliveryStatus::Accepted
                    | RelayAlertDeliveryStatus::Duplicate
                    | RelayAlertDeliveryStatus::OperatorAcknowledged
            )
        })
        .count() as u64;
    let accepted = delayed_count == 0 && failed_count == 0 && unknown_count == 0;
    Ok(RelayAlertDeliveryReport {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "delivery_attention_required"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256,
        source_alert_report_sha256: input.handoff_report.source_alert_report_sha256.clone(),
        source_trend_report_sha256: input.handoff_report.source_trend_report_sha256.clone(),
        critical_firing_count: input.handoff_report.critical_firing_count,
        delivered_count,
        delayed_count,
        failed_count,
        unknown_count,
        results,
        checks: vec![
            RelayAlertCheck {
                code: "handoff_report".to_string(),
                accepted: true,
                detail: "handoff report is fresh and hash-bound".to_string(),
            },
            RelayAlertCheck {
                code: "delivery_evidence".to_string(),
                accepted,
                detail: "downstream delivery evidence covers every handoff alert".to_string(),
            },
        ],
    })
}

pub fn evaluate_relay_alert_acknowledgement(
    input: RelayAlertAcknowledgementInput<'_>,
) -> Result<RelayAlertAcknowledgementReport, PheromoneRelayError> {
    validate_delivery_profile(input.delivery_profile, input.now_unix_ms)?;
    validate_delivery_handoff_report(
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    validate_delivery_report(
        input.delivery_report,
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    let source_delivery_report_sha256 = canonical_sha256(input.delivery_report)?;
    let mut acknowledgements = Vec::new();
    let mut acknowledged_count = 0u64;
    let mut pending_count = 0u64;
    let mut failed_count = 0u64;
    for result in &input.delivery_report.results {
        if result.observed_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery result timestamp is in the future".to_string(),
            ));
        }
        if input.now_unix_ms.saturating_sub(result.observed_at_unix_ms)
            > input.delivery_profile.max_acknowledgement_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery result is stale for acknowledgement".to_string(),
            ));
        }
        if result.status == RelayAlertDeliveryStatus::Failed {
            failed_count = failed_count.saturating_add(1);
        } else if result.status.requires_attention() {
            pending_count = pending_count.saturating_add(1);
        } else {
            acknowledged_count = acknowledged_count.saturating_add(1);
        }
        acknowledgements.push(RelayAlertAcknowledgement {
            result_id: result.result_id.clone(),
            receiver_id: result.receiver_id.clone(),
            alert_code: result.alert_code.clone(),
            dedupe_key: result.dedupe_key.clone(),
            status: result.status,
            acknowledged_at_unix_ms: input.now_unix_ms,
            downstream_evidence_sha256: result.downstream_evidence_sha256.clone(),
        });
    }
    let accepted = pending_count == 0 && failed_count == 0;
    Ok(RelayAlertAcknowledgementReport {
        schema: PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "acknowledgement_attention_required"
        }
        .to_string(),
        local_kernel_id: input.delivery_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256: input.delivery_report.source_handoff_report_sha256.clone(),
        source_delivery_report_sha256,
        acknowledged_count,
        pending_count,
        failed_count,
        acknowledgements,
        checks: vec![RelayAlertCheck {
            code: "delivery_report".to_string(),
            accepted,
            detail: "delivery outcomes are summarized without notifying downstream systems"
                .to_string(),
        }],
    })
}

pub fn generate_relay_alert_handoff_drift_report(
    input: RelayAlertHandoffDriftInput<'_>,
) -> Result<RelayAlertHandoffDriftReport, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "drift lower bound is after upper bound".to_string(),
        ));
    }
    validate_delivery_profile(input.delivery_profile, input.until_unix_ms)?;
    let mut drifts = Vec::new();
    let mut delivery_index = BTreeMap::<(String, String), &RelayAlertDeliveryResult>::new();
    let mut delivery_report_count = 0u64;
    for report in input.delivery_reports {
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        if report.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report local kernel id mismatch".to_string(),
            ));
        }
        delivery_report_count = delivery_report_count.saturating_add(1);
        for result in &report.results {
            delivery_index.insert(
                (result.receiver_id.clone(), result.alert_code.clone()),
                result,
            );
        }
    }

    let mut handoff_report_count = 0u64;
    for handoff in input.handoff_reports {
        if handoff.generated_at_unix_ms < input.since_unix_ms
            || handoff.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        validate_delivery_handoff_report(handoff, input.delivery_profile, input.until_unix_ms)?;
        handoff_report_count = handoff_report_count.saturating_add(1);
        for route in &handoff.routes {
            for alert_code in &route.alert_codes {
                let key = (route.receiver_id.clone(), alert_code.clone());
                match delivery_index.get(&key) {
                    Some(result) => {
                        if result.severity < route.highest_severity {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "severity_weakening".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery evidence weakens handoff severity".to_string(),
                            });
                        }
                        if result.target_ref != route.target_ref
                            || result.notification_route != route.notification_route
                            || result.opsgenie != route.opsgenie
                        {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "route_alias_drift".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery route aliases differ from handoff route"
                                    .to_string(),
                            });
                        }
                        if result.status.requires_attention() {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "delivery_attention_required".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery status requires operator attention".to_string(),
                            });
                        }
                    }
                    None => drifts.push(RelayAlertHandoffDrift {
                        code: "missing_delivery_result".to_string(),
                        receiver_id: route.receiver_id.clone(),
                        alert_code: alert_code.clone(),
                        detail: "handoff alert has no downstream delivery evidence".to_string(),
                    }),
                }
            }
        }
    }
    for drift in &drifts {
        if !is_bounded_code(&drift.code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "drift code is not bounded".to_string(),
            ));
        }
    }
    let accepted = drifts.is_empty();
    Ok(RelayAlertHandoffDriftReport {
        schema: PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "handoff_drift_detected"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.until_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        handoff_report_count,
        delivery_report_count,
        drift_count: drifts.len() as u64,
        drifts,
        checks: vec![RelayAlertCheck {
            code: "handoff_delivery_intersection".to_string(),
            accepted,
            detail: "handoff and downstream delivery reports intersect by bounded route aliases"
                .to_string(),
        }],
    })
}

pub fn normalize_relay_alert_delivery_evidence(
    input: RelayAlertNormalizationInput<'_>,
) -> Result<RelayAlertNormalizationReport, PheromoneRelayError> {
    validate_normalization_profile(input.profile, input.now_unix_ms)?;
    if input.sources.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization input has no downstream sources".to_string(),
        ));
    }
    let receivers = normalization_receiver_map(input.profile)?;
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    for source in input.sources {
        reject_downstream_source_secrets(source)?;
        let normalized =
            normalize_downstream_source(source, &receivers, input.profile, input.now_unix_ms)?;
        let key = (
            normalized.source_handoff_report_sha256.clone(),
            normalized.receiver_id.clone(),
            normalized.alert_code.clone(),
        );
        if !seen.insert(key) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "normalization source mapping is ambiguous".to_string(),
            ));
        }
        evidence.push(normalized);
    }
    evidence.sort_by(|left, right| {
        left.receiver_id
            .cmp(&right.receiver_id)
            .then_with(|| left.alert_code.cmp(&right.alert_code))
            .then_with(|| left.result_id.cmp(&right.result_id))
    });
    let evidence_hashes = evidence
        .iter()
        .map(canonical_sha256)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RelayAlertNormalizationReport {
        schema: PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_count: input.sources.len() as u64,
        normalized_count: evidence.len() as u64,
        evidence_hashes,
        evidence,
        checks: vec![RelayAlertCheck {
            code: "normalization".to_string(),
            accepted: true,
            detail: "local downstream exports normalized into Chio delivery evidence".to_string(),
        }],
    })
}

pub fn generate_relay_alert_delivery_drift_report_v2(
    input: RelayAlertDeliveryDriftInputV2<'_>,
) -> Result<RelayAlertDeliveryDriftReportV2, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "drift lower bound is after upper bound".to_string(),
        ));
    }
    validate_delivery_profile(input.delivery_profile, input.until_unix_ms)?;

    let mut handoffs_by_hash = BTreeMap::new();
    let mut ordered_handoffs = Vec::new();
    for handoff in input.handoff_reports {
        if handoff.generated_at_unix_ms < input.since_unix_ms
            || handoff.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        validate_delivery_handoff_report(
            handoff,
            input.delivery_profile,
            handoff.generated_at_unix_ms,
        )?;
        let hash = canonical_sha256(handoff)?;
        if handoffs_by_hash.insert(hash.clone(), handoff).is_some() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate handoff report hash in drift window".to_string(),
            ));
        }
        ordered_handoffs.push((hash, handoff));
    }

    let mut drifts = Vec::new();
    let mut delivery_index =
        BTreeMap::<(String, String, String), (&RelayAlertDeliveryResult, String)>::new();
    let mut delivery_report_count = 0u64;
    for report in input.delivery_reports {
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        if report.schema != PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(
                report.schema.clone(),
            ));
        }
        if report.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report local kernel id mismatch".to_string(),
            ));
        }
        let report_hash = canonical_sha256(report)?;
        delivery_report_count = delivery_report_count.saturating_add(1);
        if !handoffs_by_hash.contains_key(&report.source_handoff_report_sha256) {
            drifts.push(RelayAlertDeliveryDriftV2 {
                code: "unbound_delivery_report".to_string(),
                source_handoff_report_sha256: report.source_handoff_report_sha256.clone(),
                matched_delivery_report_sha256: Some(report_hash.clone()),
                receiver_id: "unknown".to_string(),
                alert_code: "unknown".to_string(),
                detail: "delivery report source handoff hash is outside the review window"
                    .to_string(),
            });
        }
        for result in &report.results {
            validate_delivery_result(result)?;
            let key = (
                report.source_handoff_report_sha256.clone(),
                result.receiver_id.clone(),
                result.alert_code.clone(),
            );
            if delivery_index
                .insert(key, (result, report_hash.clone()))
                .is_some()
            {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "duplicate delivery result across drift reports".to_string(),
                ));
            }
        }
    }

    if ordered_handoffs.is_empty() && delivery_report_count == 0 {
        drifts.push(RelayAlertDeliveryDriftV2 {
            code: "no_window_evidence".to_string(),
            source_handoff_report_sha256: "0".repeat(64),
            matched_delivery_report_sha256: None,
            receiver_id: "unknown".to_string(),
            alert_code: "unknown".to_string(),
            detail: "no handoff or delivery reports were present in the requested window"
                .to_string(),
        });
    }

    for (handoff_hash, handoff) in &ordered_handoffs {
        for route in handoff.routes.iter().filter(|route| route.ready) {
            for alert_code in &route.alert_codes {
                let key = (
                    handoff_hash.clone(),
                    route.receiver_id.clone(),
                    alert_code.clone(),
                );
                match delivery_index.get(&key) {
                    Some((result, report_hash)) => {
                        if result.severity < route.highest_severity {
                            drifts.push(RelayAlertDeliveryDriftV2 {
                                code: "severity_weakening".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery evidence weakens handoff severity".to_string(),
                            });
                        }
                        if result.target_ref != route.target_ref
                            || result.notification_route != route.notification_route
                            || result.opsgenie != route.opsgenie
                        {
                            drifts.push(RelayAlertDeliveryDriftV2 {
                                code: "route_alias_drift".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery route aliases differ from handoff route"
                                    .to_string(),
                            });
                        }
                        if result.status.requires_attention() {
                            drifts.push(RelayAlertDeliveryDriftV2 {
                                code: "delivery_attention_required".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery status requires operator attention".to_string(),
                            });
                        }
                    }
                    None => drifts.push(RelayAlertDeliveryDriftV2 {
                        code: "missing_delivery_result".to_string(),
                        source_handoff_report_sha256: handoff_hash.clone(),
                        matched_delivery_report_sha256: None,
                        receiver_id: route.receiver_id.clone(),
                        alert_code: alert_code.clone(),
                        detail: "handoff alert has no source-bound downstream delivery evidence"
                            .to_string(),
                    }),
                }
            }
        }
    }
    for drift in &drifts {
        if !is_bounded_code(&drift.code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "drift code is not bounded".to_string(),
            ));
        }
    }
    let accepted = drifts.is_empty();
    Ok(RelayAlertDeliveryDriftReportV2 {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_V2_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "delivery_drift_detected"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.until_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        handoff_report_count: ordered_handoffs.len() as u64,
        delivery_report_count,
        drift_count: drifts.len() as u64,
        drifts,
        checks: vec![RelayAlertCheck {
            code: "source_bound_delivery_intersection".to_string(),
            accepted,
            detail: "handoff and delivery reports intersect by source handoff hash".to_string(),
        }],
    })
}

pub fn generate_relay_alert_route_review_packet(
    input: RelayAlertRouteReviewInput<'_>,
) -> Result<RelayAlertRouteReviewPacket, PheromoneRelayError> {
    validate_route_owner_profile(input.route_owner_profile, input.now_unix_ms)?;
    validate_review_source_chain(&input)?;
    let source_handoff_report_sha256 = canonical_sha256(input.handoff_report)?;
    let source_delivery_report_sha256 = canonical_sha256(input.delivery_report)?;
    let source_acknowledgement_report_sha256 = canonical_sha256(input.acknowledgement_report)?;
    let source_drift_report_sha256 = canonical_sha256(input.drift_report)?;
    let owner_map = route_owner_map(input.route_owner_profile)?;
    let drift_keys = input
        .drift_report
        .drifts
        .iter()
        .map(|drift| (drift.receiver_id.as_str(), drift.alert_code.as_str()))
        .collect::<BTreeSet<_>>();
    let delivery_status = input
        .delivery_report
        .results
        .iter()
        .map(|result| {
            (
                (result.receiver_id.as_str(), result.alert_code.as_str()),
                result.status,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reviews = Vec::new();
    for route in input
        .handoff_report
        .routes
        .iter()
        .filter(|route| route.ready)
    {
        let owner = owner_map.get(route.receiver_id.as_str()).ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "route owner missing for receiver {}",
                route.receiver_id
            ))
        })?;
        let mut status = "ready";
        for alert_code in &route.alert_codes {
            if drift_keys.contains(&(route.receiver_id.as_str(), alert_code.as_str())) {
                status = "attention_required";
            }
            if delivery_status
                .get(&(route.receiver_id.as_str(), alert_code.as_str()))
                .is_some_and(|delivery_status| delivery_status.requires_attention())
            {
                status = "attention_required";
            }
        }
        reviews.push(RelayAlertRouteReview {
            owner_alias: owner.owner_alias.clone(),
            receiver_id: route.receiver_id.clone(),
            notification_route: route.notification_route.clone(),
            alert_codes: route.alert_codes.clone(),
            status: status.to_string(),
            runbook: owner.runbook.clone(),
        });
    }
    reviews.sort_by(|left, right| {
        left.owner_alias
            .cmp(&right.owner_alias)
            .then_with(|| left.receiver_id.cmp(&right.receiver_id))
    });
    let accepted = input.delivery_report.accepted
        && input.acknowledgement_report.accepted
        && input.drift_report.accepted
        && reviews.iter().all(|review| review.status == "ready");
    Ok(RelayAlertRouteReviewPacket {
        schema: PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "route_review_attention_required"
        }
        .to_string(),
        local_kernel_id: input.handoff_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256,
        source_delivery_report_sha256,
        source_acknowledgement_report_sha256,
        source_drift_report_sha256,
        ready_route_count: input
            .handoff_report
            .routes
            .iter()
            .filter(|route| route.ready)
            .count() as u64,
        owner_review_count: reviews.len() as u64,
        reviews,
        checks: vec![RelayAlertCheck {
            code: "route_owner_review".to_string(),
            accepted,
            detail: "route owners are bound to handoff and delivery evidence".to_string(),
        }],
    })
}

pub fn generate_relay_alert_assurance_package(
    input: RelayAlertAssuranceInput<'_>,
) -> Result<RelayAlertAssurancePackage, PheromoneRelayError> {
    validate_assurance_source_chain(&input)?;
    let delivery_attention_count = input.delivery_report.delayed_count
        + input.delivery_report.failed_count
        + input.delivery_report.unknown_count;
    let acknowledgement_pending_count =
        input.acknowledgement_report.pending_count + input.acknowledgement_report.failed_count;
    let accepted = input.alert_report.accepted
        && input.normalization_report.accepted
        && input.delivery_report.accepted
        && input.acknowledgement_report.accepted
        && input.drift_report.accepted
        && input.review_packet.accepted
        && delivery_attention_count == 0
        && acknowledgement_pending_count == 0;
    let mut operator_action_codes = Vec::new();
    if accepted {
        operator_action_codes.push("ready".to_string());
    } else {
        if !input.alert_report.accepted {
            operator_action_codes.push("active_alerts_present".to_string());
        }
        if !input.normalization_report.accepted {
            operator_action_codes.push("normalization_attention_required".to_string());
        }
        if delivery_attention_count > 0 {
            operator_action_codes.push("delivery_attention_required".to_string());
        }
        if acknowledgement_pending_count > 0 {
            operator_action_codes.push("acknowledgement_attention_required".to_string());
        }
        if input.drift_report.drift_count > 0 || !input.drift_report.accepted {
            operator_action_codes.push("delivery_drift_detected".to_string());
        }
        if !input.review_packet.accepted {
            operator_action_codes.push("route_review_attention_required".to_string());
        }
        if operator_action_codes.is_empty() {
            operator_action_codes.push("assurance_attention_required".to_string());
        }
    }
    for code in &operator_action_codes {
        if !is_bounded_code(code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "assurance action code is not bounded".to_string(),
            ));
        }
    }
    Ok(RelayAlertAssurancePackage {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "assurance_attention_required"
        }
        .to_string(),
        local_kernel_id: input.alert_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_alert_report_sha256: canonical_sha256(input.alert_report)?,
        source_trend_report_sha256: canonical_sha256(input.trend_report)?,
        source_handoff_report_sha256: canonical_sha256(input.handoff_report)?,
        source_normalization_report_sha256: canonical_sha256(input.normalization_report)?,
        source_delivery_report_sha256: canonical_sha256(input.delivery_report)?,
        source_acknowledgement_report_sha256: canonical_sha256(input.acknowledgement_report)?,
        source_drift_report_sha256: canonical_sha256(input.drift_report)?,
        source_review_packet_sha256: canonical_sha256(input.review_packet)?,
        firing_alert_count: input.handoff_report.firing_alert_count,
        critical_firing_alert_count: input.handoff_report.critical_firing_count,
        normalized_count: input.normalization_report.normalized_count,
        ready_route_count: input.review_packet.ready_route_count,
        delivery_attention_count,
        acknowledgement_pending_count,
        drift_count: input.drift_report.drift_count,
        operator_action_codes,
        checks: vec![RelayAlertCheck {
            code: "alert_assurance_chain".to_string(),
            accepted,
            detail: "alert, handoff, normalized delivery, acknowledgement, drift, and review reports are hash-bound".to_string(),
        }],
    })
}

pub fn generate_relay_trend_report(
    input: RelayTrendInput<'_>,
) -> Result<RelayTrendReport, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "trend lower bound is after upper bound".to_string(),
        ));
    }
    validate_alert_profile(input.routing_profile, input.until_unix_ms)?;
    let rule_map = alert_rule_map(input.routing_profile)?;
    let mut points: BTreeMap<String, RelayTrendPoint> = BTreeMap::new();
    let mut source_report_count = 0u64;
    for report in input.observability_reports {
        if report.local_kernel_id != input.local_kernel_id {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "observability report local kernel id mismatch".to_string(),
            ));
        }
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        source_report_count = source_report_count.saturating_add(1);
        for recommendation in &report.recommendations {
            let rule = rule_map.get(&recommendation.code).ok_or_else(|| {
                PheromoneRelayError::AlertRoutingInvalid(format!(
                    "recommendation code {} has no trend rule",
                    recommendation.code
                ))
            })?;
            bump_trend_point(
                &mut points,
                &recommendation.code,
                rule.severity.as_str(),
                report.generated_at_unix_ms,
            )?;
        }
    }
    let mut event_report_count = 0u64;
    for event in input.event_reports {
        if event.local_kernel_id != input.local_kernel_id {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "event report local kernel id mismatch".to_string(),
            ));
        }
        if event.generated_at_unix_ms < input.since_unix_ms
            || event.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        event_report_count = event_report_count.saturating_add(1);
        let code = event
            .stable_failure_code
            .as_deref()
            .unwrap_or(event.code.as_str());
        if !is_bounded_code(code) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "event code {code} is not bounded"
            )));
        }
        bump_trend_point(&mut points, code, "warning", event.generated_at_unix_ms)?;
    }
    Ok(RelayTrendReport {
        schema: PHEROMONE_RELAY_TREND_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.local_kernel_id.to_string(),
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        source_report_count,
        event_report_count,
        points: points.into_values().collect(),
    })
}

fn validate_alert_profile(
    profile: &RelayAlertRoutingProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_source_age_ms == 0 || profile.max_suppression_ms == 0 {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile time bounds must be positive".to_string(),
        ));
    }
    let allowed_labels = profile
        .allowed_label_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in ["notification_route", "opsgenie", "service", "severity"] {
        if !allowed_labels.contains(required) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "routing profile is missing bounded label {required}"
            )));
        }
    }
    let mut route_ids = BTreeSet::new();
    let mut route_targets = BTreeSet::new();
    for route in &profile.routes {
        validate_alert_route(route)?;
        if !route_ids.insert(route.route_id.as_str()) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert route {}",
                route.route_id
            )));
        }
        let target = (
            route.notification_route.as_str(),
            route.opsgenie.as_str(),
            route.target_ref.as_str(),
        );
        if !route_targets.insert(target) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "duplicate alert route target".to_string(),
            ));
        }
    }
    if route_ids.is_empty() {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile has no routes".to_string(),
        ));
    }
    let mut alert_codes = BTreeSet::new();
    for rule in &profile.rules {
        if !is_bounded_code(&rule.alert_code) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert code {} is not bounded",
                rule.alert_code
            )));
        }
        if !route_ids.contains(rule.route_id.as_str()) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "rule {} references unknown route {}",
                rule.alert_code, rule.route_id
            )));
        }
        if !alert_codes.insert(rule.alert_code.as_str()) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert rule {}",
                rule.alert_code
            )));
        }
    }
    if alert_codes.is_empty() {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "routing profile has no rules".to_string(),
        ));
    }
    Ok(())
}

fn validate_alert_route(route: &RelayAlertRoute) -> Result<(), PheromoneRelayError> {
    for (field, value) in [
        ("route_id", route.route_id.as_str()),
        ("notification_route", route.notification_route.as_str()),
        ("opsgenie", route.opsgenie.as_str()),
        ("target_ref", route.target_ref.as_str()),
    ] {
        if !is_bounded_route_token(value) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert route field {field} is not bounded"
            )));
        }
        reject_secret_marker(field, value)?;
    }
    if route.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "alert route target ref must not be a dynamic URL".to_string(),
        ));
    }
    if route.runbook.trim().is_empty()
        || route.runbook.contains("://")
        || route.runbook.to_ascii_lowercase().contains("token")
    {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "alert route runbook must be a local non-secret reference".to_string(),
        ));
    }
    Ok(())
}

fn validate_handoff_profile(
    profile: &RelayAlertHandoffProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_alert_report_age_ms == 0 || profile.max_trend_report_age_ms == 0 {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile age limits must be positive".to_string(),
        ));
    }
    if profile.receivers.is_empty() {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile has no downstream receivers".to_string(),
        ));
    }
    if profile.escalations.is_empty() {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff profile has no escalation mappings".to_string(),
        ));
    }
    let mut escalation_refs = BTreeMap::new();
    for escalation in &profile.escalations {
        validate_handoff_token("escalation_ref", &escalation.escalation_ref)?;
        if escalation_refs
            .insert(escalation.escalation_ref.as_str(), escalation.severity)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate escalation {}",
                escalation.escalation_ref
            )));
        }
        if escalation.max_delay_ms == 0 || !is_bounded_code(&escalation.recommendation_code) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(
                "handoff escalation has invalid bounds".to_string(),
            ));
        }
    }
    let mut receiver_ids = BTreeSet::new();
    let mut target_refs = BTreeSet::new();
    let mut route_keys = BTreeSet::new();
    for receiver in &profile.receivers {
        validate_handoff_receiver(receiver)?;
        if !receiver_ids.insert(receiver.receiver_id.as_str()) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate receiver {}",
                receiver.receiver_id
            )));
        }
        if !target_refs.insert(receiver.target_ref.as_str()) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate receiver target {}",
                receiver.target_ref
            )));
        }
        let route_key = (
            receiver.notification_route.as_str(),
            receiver.opsgenie.as_str(),
        );
        if !route_keys.insert(route_key) {
            return Err(PheromoneRelayError::AlertHandoffInvalid(
                "duplicate handoff route coverage".to_string(),
            ));
        }
        let escalation_severity = escalation_refs
            .get(receiver.escalation_ref.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertHandoffInvalid(format!(
                    "receiver {} references unknown escalation {}",
                    receiver.receiver_id, receiver.escalation_ref
                ))
            })?;
        if receiver.severity_floor > *escalation_severity {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "receiver {} severity floor exceeds escalation {}",
                receiver.receiver_id, receiver.escalation_ref
            )));
        }
    }
    Ok(())
}

fn validate_handoff_receiver(
    receiver: &RelayAlertHandoffReceiver,
) -> Result<(), PheromoneRelayError> {
    if receiver.kind == RelayAlertHandoffSinkKind::Unknown {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff receiver sink kind is unknown".to_string(),
        ));
    }
    for (field, value) in [
        ("receiver_id", receiver.receiver_id.as_str()),
        ("target_ref", receiver.target_ref.as_str()),
        ("notification_route", receiver.notification_route.as_str()),
        ("opsgenie", receiver.opsgenie.as_str()),
        ("escalation_ref", receiver.escalation_ref.as_str()),
    ] {
        validate_handoff_token(field, value)?;
    }
    if receiver.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff target ref must not be a dynamic URL".to_string(),
        ));
    }
    if receiver.runbook.trim().is_empty()
        || receiver.runbook.contains("://")
        || receiver.runbook.to_ascii_lowercase().contains("token")
    {
        return Err(PheromoneRelayError::AlertHandoffInvalid(
            "handoff runbook must be a local non-secret reference".to_string(),
        ));
    }
    Ok(())
}

fn validate_delivery_profile(
    profile: &RelayAlertDeliveryProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_handoff_report_age_ms == 0
        || profile.max_evidence_age_ms == 0
        || profile.max_acknowledgement_age_ms == 0
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile age limits must be positive".to_string(),
        ));
    }
    if profile.receivers.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery profile has no downstream receivers".to_string(),
        ));
    }
    let mut receiver_ids = BTreeSet::new();
    let mut target_refs = BTreeSet::new();
    let mut route_keys = BTreeSet::new();
    for receiver in &profile.receivers {
        validate_delivery_receiver(receiver)?;
        if !receiver_ids.insert(receiver.receiver_id.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery receiver {}",
                receiver.receiver_id
            )));
        }
        if !target_refs.insert(receiver.target_ref.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery target {}",
                receiver.target_ref
            )));
        }
        let route_key = (
            receiver.notification_route.as_str(),
            receiver.opsgenie.as_str(),
        );
        if !route_keys.insert(route_key) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate delivery route coverage".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_normalization_profile(
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_source_age_ms == 0 {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile source age must be positive".to_string(),
        ));
    }
    if profile.receivers.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization profile has no downstream receivers".to_string(),
        ));
    }
    let mut receiver_ids = BTreeSet::new();
    for receiver in &profile.receivers {
        validate_delivery_receiver(receiver)?;
        if !receiver_ids.insert(receiver.receiver_id.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate normalization receiver {}",
                receiver.receiver_id
            )));
        }
    }
    Ok(())
}

fn normalization_receiver_map(
    profile: &RelayAlertNormalizationProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertDeliveryReceiver>, PheromoneRelayError> {
    let mut receivers = BTreeMap::new();
    for receiver in &profile.receivers {
        if receivers
            .insert(receiver.receiver_id.as_str(), receiver)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate normalization receiver {}",
                receiver.receiver_id
            )));
        }
    }
    Ok(receivers)
}

fn normalize_downstream_source(
    source: &Value,
    receivers: &BTreeMap<&str, &RelayAlertDeliveryReceiver>,
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<RelayAlertDeliveryEvidence, PheromoneRelayError> {
    if source
        .get("schema")
        .and_then(Value::as_str)
        .is_some_and(|schema| schema == PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA)
    {
        let evidence: RelayAlertDeliveryEvidence = serde_json::from_value(source.clone())?;
        validate_delivery_evidence_shape(&evidence)?;
        validate_normalized_evidence(&evidence, receivers, profile, now_unix_ms)?;
        return Ok(evidence);
    }

    let receiver_id = json_string(source, &["receiverId", "receiver_id", "receiver"])?;
    let receiver = receivers.get(receiver_id.as_str()).ok_or_else(|| {
        PheromoneRelayError::AlertDeliveryInvalid(format!(
            "normalization receiver {receiver_id} is unknown"
        ))
    })?;
    let alert_code = json_string(source, &["alertCode", "alert_code", "alertname"])?;
    if !is_bounded_code(&alert_code) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized alert code is not bounded".to_string(),
        ));
    }
    let observed_at_unix_ms = json_u64(source, &["observedAtUnixMs", "observed_at_unix_ms"])?;
    if observed_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(observed_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source is stale".to_string(),
        ));
    }
    let status = relay_alert_delivery_status_from_str(
        json_string(source, &["status", "outcome"])?.as_str(),
    )?;
    let severity = relay_alert_severity_from_str(json_string(source, &["severity"])?.as_str())
        .map_err(|error| PheromoneRelayError::AlertDeliveryInvalid(error.to_string()))?;
    let source_handoff_report_sha256 = json_string(
        source,
        &["sourceHandoffReportSha256", "source_handoff_report_sha256"],
    )?;
    if !is_sha256_hex(&source_handoff_report_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source handoff hash is invalid".to_string(),
        ));
    }
    let dedupe_key = json_string(source, &["dedupeKey", "dedupe_key", "fingerprint"])?;
    if !is_bounded_route_token(&dedupe_key) || contains_secret_marker(&dedupe_key) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization dedupe key is not bounded".to_string(),
        ));
    }
    let runbook = json_string(source, &["runbook", "runbook_ref"])
        .unwrap_or_else(|_| receiver.runbook.clone());
    if runbook.trim().is_empty() || runbook.contains("://") || contains_secret_marker(&runbook) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization runbook must be a local non-secret reference".to_string(),
        ));
    }
    let downstream_evidence_sha256 = json_string(
        source,
        &["downstreamEvidenceSha256", "downstream_evidence_sha256"],
    )
    .unwrap_or(canonical_sha256(source)?);
    if !is_sha256_hex(&downstream_evidence_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization downstream evidence hash is invalid".to_string(),
        ));
    }
    let result_id = json_string(source, &["resultId", "result_id"])
        .unwrap_or_else(|_| format!("normalized:{receiver_id}:{alert_code}"));
    validate_delivery_token("result_id", &result_id)?;
    let mut labels = json_labels(source)?;
    labels
        .entry("notification_route".to_string())
        .or_insert_with(|| receiver.notification_route.clone());
    labels
        .entry("opsgenie".to_string())
        .or_insert_with(|| receiver.opsgenie.clone());
    labels
        .entry("service".to_string())
        .or_insert_with(|| "chiodos-pheromone-relay".to_string());
    labels
        .entry("severity".to_string())
        .or_insert_with(|| severity.as_str().to_string());
    labels
        .entry("status".to_string())
        .or_insert_with(|| status.as_str().to_string());
    labels
        .entry("receiver".to_string())
        .or_insert_with(|| receiver.receiver_id.clone());

    let evidence = RelayAlertDeliveryEvidence {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA.to_string(),
        local_kernel_id: profile.local_kernel_id.clone(),
        observed_at_unix_ms,
        result_id,
        receiver_id: receiver.receiver_id.clone(),
        kind: receiver.kind,
        target_ref: receiver.target_ref.clone(),
        notification_route: receiver.notification_route.clone(),
        opsgenie: receiver.opsgenie.clone(),
        alert_code,
        dedupe_key,
        severity,
        runbook,
        status,
        source_handoff_report_sha256,
        downstream_evidence_sha256,
        labels,
    };
    validate_normalized_evidence(&evidence, receivers, profile, now_unix_ms)?;
    Ok(evidence)
}

fn validate_normalized_evidence(
    evidence: &RelayAlertDeliveryEvidence,
    receivers: &BTreeMap<&str, &RelayAlertDeliveryReceiver>,
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    validate_delivery_evidence_shape(evidence)?;
    if evidence.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence local kernel id mismatch".to_string(),
        ));
    }
    if evidence.observed_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(evidence.observed_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence is stale".to_string(),
        ));
    }
    let receiver = receivers
        .get(evidence.receiver_id.as_str())
        .ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "normalization receiver {} is unknown",
                evidence.receiver_id
            ))
        })?;
    validate_evidence_matches_receiver(evidence, receiver)
}

fn validate_evidence_matches_receiver(
    evidence: &RelayAlertDeliveryEvidence,
    receiver: &RelayAlertDeliveryReceiver,
) -> Result<(), PheromoneRelayError> {
    if evidence.kind != receiver.kind
        || evidence.target_ref != receiver.target_ref
        || evidence.notification_route != receiver.notification_route
        || evidence.opsgenie != receiver.opsgenie
        || evidence.severity < receiver.severity_floor
        || evidence.runbook != receiver.runbook
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence does not match receiver contract".to_string(),
        ));
    }
    Ok(())
}

fn validate_delivery_receiver(
    receiver: &RelayAlertDeliveryReceiver,
) -> Result<(), PheromoneRelayError> {
    if receiver.kind == RelayAlertHandoffSinkKind::Unknown {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery receiver sink kind is unknown".to_string(),
        ));
    }
    for (field, value) in [
        ("receiver_id", receiver.receiver_id.as_str()),
        ("target_ref", receiver.target_ref.as_str()),
        ("notification_route", receiver.notification_route.as_str()),
        ("opsgenie", receiver.opsgenie.as_str()),
    ] {
        validate_delivery_token(field, value)?;
    }
    if receiver.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery target ref must not be a dynamic URL".to_string(),
        ));
    }
    if receiver.runbook.trim().is_empty()
        || receiver.runbook.contains("://")
        || contains_secret_marker(&receiver.runbook)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery runbook must be a local non-secret reference".to_string(),
        ));
    }
    if receiver.max_delay_ms == 0 {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery receiver delay bound must be positive".to_string(),
        ));
    }
    Ok(())
}

fn validate_delivery_token(field: &str, value: &str) -> Result<(), PheromoneRelayError> {
    if !is_bounded_route_token(value) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "delivery field {field} is not bounded"
        )));
    }
    if contains_secret_marker(value) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "delivery field {field} appears to contain secret material"
        )));
    }
    Ok(())
}

fn relay_alert_delivery_status_from_str(
    value: &str,
) -> Result<RelayAlertDeliveryStatus, PheromoneRelayError> {
    match value {
        "delivered" => Ok(RelayAlertDeliveryStatus::Delivered),
        "accepted" => Ok(RelayAlertDeliveryStatus::Accepted),
        "failed" => Ok(RelayAlertDeliveryStatus::Failed),
        "delayed" => Ok(RelayAlertDeliveryStatus::Delayed),
        "duplicate" => Ok(RelayAlertDeliveryStatus::Duplicate),
        "unknown" => Ok(RelayAlertDeliveryStatus::Unknown),
        "operator_acknowledged" => Ok(RelayAlertDeliveryStatus::OperatorAcknowledged),
        _ => Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "delivery status {value} is not supported"
        ))),
    }
}

fn json_string(value: &Value, names: &[&str]) -> Result<String, PheromoneRelayError> {
    for name in names {
        if let Some(text) = value.get(*name).and_then(Value::as_str) {
            if text.trim().is_empty() {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "field {name} is empty"
                )));
            }
            return Ok(text.to_string());
        }
    }
    Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
        "missing field {}",
        names.join("/")
    )))
}

fn json_u64(value: &Value, names: &[&str]) -> Result<u64, PheromoneRelayError> {
    for name in names {
        if let Some(number) = value.get(*name).and_then(Value::as_u64) {
            return Ok(number);
        }
    }
    Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
        "missing numeric field {}",
        names.join("/")
    )))
}

fn json_labels(value: &Value) -> Result<BTreeMap<String, String>, PheromoneRelayError> {
    let mut labels = BTreeMap::new();
    if let Some(raw_labels) = value.get("labels") {
        let object = raw_labels.as_object().ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(
                "normalization labels must be an object".to_string(),
            )
        })?;
        for (name, value) in object {
            let text = value.as_str().ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(
                    "normalization label value must be a string".to_string(),
                )
            })?;
            labels.insert(name.clone(), text.to_string());
        }
    }
    Ok(labels)
}

fn reject_downstream_source_secrets(value: &Value) -> Result<(), PheromoneRelayError> {
    match value {
        Value::String(text) => {
            if text.contains("://") || contains_secret_marker(text) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "downstream source contains secret material or a dynamic URL".to_string(),
                ));
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_downstream_source_secrets(item)?;
            }
        }
        Value::Object(object) => {
            for (name, item) in object {
                if contains_secret_marker(name) || name.to_ascii_lowercase().contains("url") {
                    return Err(PheromoneRelayError::AlertDeliveryInvalid(
                        "downstream source contains secret material or a dynamic URL".to_string(),
                    ));
                }
                reject_downstream_source_secrets(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn validate_delivery_evidence_shape(
    evidence: &RelayAlertDeliveryEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    if evidence.kind == RelayAlertHandoffSinkKind::Unknown {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence sink kind is unknown".to_string(),
        ));
    }
    for (field, value) in [
        ("result_id", evidence.result_id.as_str()),
        ("receiver_id", evidence.receiver_id.as_str()),
        ("target_ref", evidence.target_ref.as_str()),
        ("notification_route", evidence.notification_route.as_str()),
        ("opsgenie", evidence.opsgenie.as_str()),
        ("dedupe_key", evidence.dedupe_key.as_str()),
    ] {
        validate_delivery_token(field, value)?;
    }
    if !is_bounded_code(&evidence.alert_code) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery alert code is not bounded".to_string(),
        ));
    }
    if evidence.target_ref.contains("://") {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence target ref must not be a dynamic URL".to_string(),
        ));
    }
    if evidence.runbook.trim().is_empty()
        || evidence.runbook.contains("://")
        || contains_secret_marker(&evidence.runbook)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence runbook must be a local non-secret reference".to_string(),
        ));
    }
    if !is_sha256_hex(&evidence.source_handoff_report_sha256)
        || !is_sha256_hex(&evidence.downstream_evidence_sha256)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence hash is invalid".to_string(),
        ));
    }
    validate_delivery_labels(&evidence.labels, evidence)?;
    Ok(())
}

fn validate_delivery_labels(
    labels: &BTreeMap<String, String>,
    evidence: &RelayAlertDeliveryEvidence,
) -> Result<(), PheromoneRelayError> {
    for (name, value) in labels {
        if !matches!(
            name.as_str(),
            "notification_route" | "opsgenie" | "service" | "severity" | "status" | "receiver"
        ) || !is_bounded_route_token(value)
            || contains_secret_marker(value)
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence contains an unbounded label".to_string(),
            ));
        }
    }
    if labels.get("notification_route") != Some(&evidence.notification_route)
        || labels.get("opsgenie") != Some(&evidence.opsgenie)
        || labels.get("severity").map(String::as_str) != Some(evidence.severity.as_str())
        || labels.get("status").map(String::as_str) != Some(evidence.status.as_str())
        || labels.get("receiver") != Some(&evidence.receiver_id)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery evidence labels do not match delivery fields".to_string(),
        ));
    }
    Ok(())
}

fn validate_delivery_handoff_report(
    report: &RelayAlertHandoffReport,
    profile: &RelayAlertDeliveryProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if report.schema != PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    if !report.accepted || report.code != "accepted" {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report is not accepted".to_string(),
        ));
    }
    if report.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report local kernel id mismatch".to_string(),
        ));
    }
    if report.generated_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(report.generated_at_unix_ms) > profile.max_handoff_report_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report is stale for delivery import".to_string(),
        ));
    }
    if !is_sha256_hex(&report.source_alert_report_sha256)
        || !is_sha256_hex(&report.source_trend_report_sha256)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report source hash is invalid".to_string(),
        ));
    }
    if report.firing_alert_count > 0 && report.routes.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "handoff report has firing alerts without route readiness".to_string(),
        ));
    }
    for route in &report.routes {
        if !route.ready {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "handoff route {} is not ready",
                route.receiver_id
            )));
        }
        validate_delivery_token("receiver_id", &route.receiver_id)?;
        validate_delivery_token("target_ref", &route.target_ref)?;
        validate_delivery_token("notification_route", &route.notification_route)?;
        validate_delivery_token("opsgenie", &route.opsgenie)?;
        validate_delivery_token("escalation_ref", &route.escalation_ref)?;
        if route.kind == RelayAlertHandoffSinkKind::Unknown {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "handoff route sink kind is unknown".to_string(),
            ));
        }
        if route.target_ref.contains("://") {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "handoff route target ref must not be a dynamic URL".to_string(),
            ));
        }
        if route.alert_codes.is_empty() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "handoff route has no alert codes".to_string(),
            ));
        }
        for alert_code in &route.alert_codes {
            if !is_bounded_code(alert_code) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "handoff route alert code is not bounded".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_delivery_report(
    report: &RelayAlertDeliveryReport,
    handoff: &RelayAlertHandoffReport,
    profile: &RelayAlertDeliveryProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if report.schema != PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    if report.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report local kernel id mismatch".to_string(),
        ));
    }
    if report.generated_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report timestamp is in the future".to_string(),
        ));
    }
    if report.source_handoff_report_sha256 != canonical_sha256(handoff)? {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report source handoff hash mismatch".to_string(),
        ));
    }
    if report.source_alert_report_sha256 != handoff.source_alert_report_sha256
        || report.source_trend_report_sha256 != handoff.source_trend_report_sha256
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report source alert or trend hash mismatch".to_string(),
        ));
    }
    let receiver_map = delivery_receiver_map(profile)?;
    let route_map = handoff_route_map(handoff)?;
    let mut seen = BTreeSet::new();
    for result in &report.results {
        validate_delivery_result(result)?;
        if !seen.insert((result.receiver_id.as_str(), result.alert_code.as_str())) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate delivery report result".to_string(),
            ));
        }
        let receiver = receiver_map
            .get(result.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "delivery report references unknown receiver {}",
                    result.receiver_id
                ))
            })?;
        let route = route_map.get(result.receiver_id.as_str()).ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery report receiver {} is absent from handoff",
                result.receiver_id
            ))
        })?;
        if result.target_ref != receiver.target_ref
            || result.target_ref != route.target_ref
            || result.notification_route != receiver.notification_route
            || result.notification_route != route.notification_route
            || result.opsgenie != receiver.opsgenie
            || result.opsgenie != route.opsgenie
            || result.runbook != receiver.runbook
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report result does not match trusted delivery profile".to_string(),
            ));
        }
        if !route.alert_codes.contains(&result.alert_code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report result alert is not in handoff".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_delivery_result(result: &RelayAlertDeliveryResult) -> Result<(), PheromoneRelayError> {
    for (field, value) in [
        ("result_id", result.result_id.as_str()),
        ("receiver_id", result.receiver_id.as_str()),
        ("target_ref", result.target_ref.as_str()),
        ("notification_route", result.notification_route.as_str()),
        ("opsgenie", result.opsgenie.as_str()),
        ("dedupe_key", result.dedupe_key.as_str()),
    ] {
        validate_delivery_token(field, value)?;
    }
    if !is_bounded_code(&result.alert_code) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report alert code is not bounded".to_string(),
        ));
    }
    if result.runbook.trim().is_empty()
        || result.runbook.contains("://")
        || contains_secret_marker(&result.runbook)
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report runbook must be a local non-secret reference".to_string(),
        ));
    }
    if !is_sha256_hex(&result.downstream_evidence_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "delivery report evidence hash is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_route_owner_profile(
    profile: &RelayAlertRouteOwnerProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.trim().is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile is outside its validity window".to_string(),
        ));
    }
    if profile.max_report_age_ms == 0 {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile report age must be positive".to_string(),
        ));
    }
    if profile.owners.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route owner profile has no owners".to_string(),
        ));
    }
    let mut owner_aliases = BTreeSet::new();
    let mut receiver_ids = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for owner in &profile.owners {
        validate_delivery_token("owner_alias", &owner.owner_alias)?;
        if !owner_aliases.insert(owner.owner_alias.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate route owner {}",
                owner.owner_alias
            )));
        }
        if owner.receiver_ids.is_empty() || owner.notification_routes.is_empty() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "route owner must cover receivers and notification routes".to_string(),
            ));
        }
        for receiver_id in &owner.receiver_ids {
            validate_delivery_token("receiver_id", receiver_id)?;
            if !receiver_ids.insert(receiver_id.as_str()) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "duplicate route owner receiver {receiver_id}"
                )));
            }
        }
        for route in &owner.notification_routes {
            validate_delivery_token("notification_route", route)?;
            if !routes.insert(route.as_str()) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "duplicate route owner notification route {route}"
                )));
            }
        }
        if owner.runbook.trim().is_empty()
            || owner.runbook.contains("://")
            || contains_secret_marker(&owner.runbook)
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "route owner runbook must be a local non-secret reference".to_string(),
            ));
        }
    }
    Ok(())
}

fn route_owner_map(
    profile: &RelayAlertRouteOwnerProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertRouteOwner>, PheromoneRelayError> {
    let mut owners = BTreeMap::new();
    for owner in &profile.owners {
        for receiver_id in &owner.receiver_ids {
            if owners.insert(receiver_id.as_str(), owner).is_some() {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "duplicate route owner receiver {receiver_id}"
                )));
            }
        }
    }
    Ok(owners)
}

fn validate_review_source_chain(
    input: &RelayAlertRouteReviewInput<'_>,
) -> Result<(), PheromoneRelayError> {
    let local_kernel_id = input.handoff_report.local_kernel_id.as_str();
    for (name, candidate) in [
        ("delivery", input.delivery_report.local_kernel_id.as_str()),
        (
            "acknowledgement",
            input.acknowledgement_report.local_kernel_id.as_str(),
        ),
        ("drift", input.drift_report.local_kernel_id.as_str()),
        (
            "route owner profile",
            input.route_owner_profile.local_kernel_id.as_str(),
        ),
    ] {
        if candidate != local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "{name} local kernel id mismatch"
            )));
        }
    }
    for (name, generated_at) in [
        ("handoff report", input.handoff_report.generated_at_unix_ms),
        (
            "delivery report",
            input.delivery_report.generated_at_unix_ms,
        ),
        (
            "acknowledgement report",
            input.acknowledgement_report.generated_at_unix_ms,
        ),
        ("drift report", input.drift_report.generated_at_unix_ms),
    ] {
        if generated_at > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "{name} timestamp is in the future"
            )));
        }
        if input.now_unix_ms.saturating_sub(generated_at)
            > input.route_owner_profile.max_report_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "{name} is stale for route review"
            )));
        }
    }
    if input.delivery_report.source_handoff_report_sha256 != canonical_sha256(input.handoff_report)?
        || input.acknowledgement_report.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.acknowledgement_report.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "route review source hash mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_assurance_source_chain(
    input: &RelayAlertAssuranceInput<'_>,
) -> Result<(), PheromoneRelayError> {
    let local_kernel_id = input.alert_report.local_kernel_id.as_str();
    for (name, candidate) in [
        ("handoff", input.handoff_report.local_kernel_id.as_str()),
        (
            "normalization",
            input.normalization_report.local_kernel_id.as_str(),
        ),
        ("delivery", input.delivery_report.local_kernel_id.as_str()),
        (
            "acknowledgement",
            input.acknowledgement_report.local_kernel_id.as_str(),
        ),
        ("drift", input.drift_report.local_kernel_id.as_str()),
        ("review", input.review_packet.local_kernel_id.as_str()),
    ] {
        if candidate != local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "assurance {name} local kernel id mismatch"
            )));
        }
    }
    if input.trend_report.local_kernel_id != local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance trend local kernel id mismatch".to_string(),
        ));
    }
    if input.handoff_report.source_alert_report_sha256 != canonical_sha256(input.alert_report)?
        || input.handoff_report.source_trend_report_sha256 != canonical_sha256(input.trend_report)?
        || input.delivery_report.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.acknowledgement_report.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
        || input.review_packet.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.review_packet.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
        || input.review_packet.source_acknowledgement_report_sha256
            != canonical_sha256(input.acknowledgement_report)?
        || input.review_packet.source_drift_report_sha256 != canonical_sha256(input.drift_report)?
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance source hash mismatch".to_string(),
        ));
    }
    for (name, generated_at) in [
        ("alert report", input.alert_report.generated_at_unix_ms),
        ("handoff report", input.handoff_report.generated_at_unix_ms),
        (
            "normalization report",
            input.normalization_report.generated_at_unix_ms,
        ),
        (
            "delivery report",
            input.delivery_report.generated_at_unix_ms,
        ),
        (
            "acknowledgement report",
            input.acknowledgement_report.generated_at_unix_ms,
        ),
        ("drift report", input.drift_report.generated_at_unix_ms),
        ("review packet", input.review_packet.generated_at_unix_ms),
    ] {
        if generated_at > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "assurance {name} timestamp is in the future"
            )));
        }
    }
    if input.trend_report.until_unix_ms > input.now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance trend report timestamp is in the future".to_string(),
        ));
    }
    Ok(())
}

fn delivery_receiver_map(
    profile: &RelayAlertDeliveryProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertDeliveryReceiver>, PheromoneRelayError> {
    let mut receivers = BTreeMap::new();
    for receiver in &profile.receivers {
        if receivers
            .insert(receiver.receiver_id.as_str(), receiver)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery receiver {}",
                receiver.receiver_id
            )));
        }
    }
    Ok(receivers)
}

fn handoff_route_map(
    report: &RelayAlertHandoffReport,
) -> Result<BTreeMap<&str, &RelayAlertHandoffRouteReadiness>, PheromoneRelayError> {
    let mut routes = BTreeMap::new();
    for route in &report.routes {
        if routes.insert(route.receiver_id.as_str(), route).is_some() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate handoff route {}",
                route.receiver_id
            )));
        }
    }
    Ok(routes)
}

fn validate_handoff_token(field: &str, value: &str) -> Result<(), PheromoneRelayError> {
    if !is_bounded_route_token(value) {
        return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
            "handoff field {field} is not bounded"
        )));
    }
    reject_handoff_secret_marker(field, value)
}

fn reject_handoff_secret_marker(field: &str, value: &str) -> Result<(), PheromoneRelayError> {
    if contains_secret_marker(value) {
        return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
            "handoff field {field} appears to contain secret material"
        )));
    }
    Ok(())
}

fn reject_secret_marker(field: &str, value: &str) -> Result<(), PheromoneRelayError> {
    if contains_secret_marker(value) {
        return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
            "alert route field {field} appears to contain secret material"
        )));
    }
    Ok(())
}

fn contains_secret_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "secret", "token", "password", "apikey", "api_key", "api-key", "bearer",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn validate_suppression_state(
    state: &RelayAlertSuppressionStateDocument,
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<(), PheromoneRelayError> {
    if state.schema != PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(state.schema.clone()));
    }
    if state.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertRoutingInvalid(
            "suppression state local kernel id mismatch".to_string(),
        ));
    }
    let rules = alert_rule_map(profile)?;
    let routes = alert_route_map(profile)?;
    let mut seen = BTreeSet::new();
    for entry in &state.entries {
        let rule = rules.get(&entry.alert_code).ok_or_else(|| {
            PheromoneRelayError::AlertRoutingInvalid(format!(
                "suppression references unknown alert {}",
                entry.alert_code
            ))
        })?;
        if !routes.contains_key(&entry.route_id) || rule.route_id != entry.route_id {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "suppression route {} does not match alert {}",
                entry.route_id, entry.alert_code
            )));
        }
        if entry.starts_at_unix_ms >= entry.expires_at_unix_ms {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "suppression window is empty".to_string(),
            ));
        }
        let window = entry
            .expires_at_unix_ms
            .saturating_sub(entry.starts_at_unix_ms);
        if window > profile.max_suppression_ms {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "suppression window exceeds routing profile maximum".to_string(),
            ));
        }
        if !is_bounded_code(&entry.reason) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(
                "suppression reason is not bounded".to_string(),
            ));
        }
        let key = (&entry.alert_code, &entry.route_id);
        if !seen.insert(key) {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate suppression for alert {}",
                entry.alert_code
            )));
        }
    }
    Ok(())
}

fn validate_observability_source(
    report: &RelayObservabilityReport,
    profile: &RelayAlertRoutingProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if report.schema != PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    if report.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "observability report local kernel id mismatch".to_string(),
        ));
    }
    if report.generated_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "observability report timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(report.generated_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "observability report is stale".to_string(),
        ));
    }
    for recommendation in &report.recommendations {
        if !is_bounded_code(&recommendation.code) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "recommendation code {} is not bounded",
                recommendation.code
            )));
        }
    }
    let recommendation_codes = report
        .recommendations
        .iter()
        .map(|recommendation| recommendation.code.as_str())
        .collect::<BTreeSet<_>>();
    require_alert_recommendation(
        report.queue.dead_letter > 0,
        &recommendation_codes,
        "dead_letters_present",
    )?;
    require_alert_recommendation(
        report.queue.stale_lease_count > 0,
        &recommendation_codes,
        "stale_leases_present",
    )?;
    require_alert_recommendation(
        report
            .recent_failures
            .iter()
            .any(|failure| failure.code == "relay_nonce_replay" && failure.count > 0),
        &recommendation_codes,
        "relay_nonce_replay",
    )?;
    require_alert_recommendation(
        report
            .recent_failures
            .iter()
            .any(|failure| failure.code == "endpoint_denied" && failure.count > 0),
        &recommendation_codes,
        "endpoint_denied",
    )?;
    require_alert_recommendation(
        report
            .recent_failures
            .iter()
            .any(|failure| failure.code == "catchup_denied" && failure.count > 0),
        &recommendation_codes,
        "catchup_denied",
    )?;
    Ok(())
}

fn validate_handoff_sources(input: &RelayAlertHandoffInput<'_>) -> Result<(), PheromoneRelayError> {
    if input.alert_report.schema != PHEROMONE_RELAY_ALERT_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            input.alert_report.schema.clone(),
        ));
    }
    if input.trend_report.schema != PHEROMONE_RELAY_TREND_REPORT_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            input.trend_report.schema.clone(),
        ));
    }
    let local_kernel_id = input.routing_profile.local_kernel_id.as_str();
    if input.handoff_profile.local_kernel_id != local_kernel_id
        || input.alert_report.local_kernel_id != local_kernel_id
        || input.trend_report.local_kernel_id != local_kernel_id
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "handoff input local kernel id mismatch".to_string(),
        ));
    }
    if input.alert_report.generated_at_unix_ms > input.now_unix_ms
        || input.trend_report.until_unix_ms > input.now_unix_ms
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "handoff source timestamp is in the future".to_string(),
        ));
    }
    if input
        .now_unix_ms
        .saturating_sub(input.alert_report.generated_at_unix_ms)
        > input.handoff_profile.max_alert_report_age_ms
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "alert report is stale for handoff".to_string(),
        ));
    }
    if input
        .now_unix_ms
        .saturating_sub(input.trend_report.until_unix_ms)
        > input.handoff_profile.max_trend_report_age_ms
    {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "trend report is stale for handoff".to_string(),
        ));
    }
    if input.trend_report.since_unix_ms > input.trend_report.until_unix_ms {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "trend report window is invalid".to_string(),
        ));
    }
    if !is_sha256_hex(&input.alert_report.source_report_sha256) {
        return Err(PheromoneRelayError::AlertSourceInvalid(
            "alert report source hash is invalid".to_string(),
        ));
    }
    let routes = alert_route_map(input.routing_profile)?;
    let rules = alert_rule_map(input.routing_profile)?;
    let trend_codes = input
        .trend_report
        .points
        .iter()
        .map(|point| point.code.as_str())
        .collect::<BTreeSet<_>>();
    for alert in &input.alert_report.alerts {
        if !is_bounded_code(&alert.code) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert code {} is not bounded",
                alert.code
            )));
        }
        let rule = rules.get(&alert.code).ok_or_else(|| {
            PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has no routing profile rule",
                alert.code
            ))
        })?;
        let route = routes.get(&rule.route_id).ok_or_else(|| {
            PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} route {} is not defined",
                alert.code, rule.route_id
            ))
        })?;
        let severity = relay_alert_severity_from_str(&alert.severity)?;
        if severity != rule.severity {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} severity does not match routing rule",
                alert.code
            )));
        }
        if !matches!(alert.state.as_str(), "firing" | "suppressed") {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} has unsupported state {}",
                alert.code, alert.state
            )));
        }
        if alert.state == "suppressed"
            && (rule.unsuppressible || severity == RelayAlertSeverity::Critical)
        {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "alert {} hides an unsuppressible or critical alert",
                alert.code
            )));
        }
        if alert.notification_route != route.notification_route
            || alert.opsgenie != route.opsgenie
            || alert.runbook != route.runbook
        {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} does not match routing profile route",
                alert.code
            )));
        }
        if rule.require_event_evidence && alert.event_evidence_sha256.is_empty() {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} is missing required event evidence",
                alert.code
            )));
        }
        for evidence_hash in &alert.event_evidence_sha256 {
            if !is_sha256_hex(evidence_hash) {
                return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                    "alert {} event evidence hash is invalid",
                    alert.code
                )));
            }
        }
        if alert.state == "firing" && !trend_codes.contains(alert.code.as_str()) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "trend report omits firing alert {}",
                alert.code
            )));
        }
        if !is_sha256_hex(&alert.source_report_sha256) {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} source hash is invalid",
                alert.code
            )));
        }
        if alert.source_report_sha256 != input.alert_report.source_report_sha256 {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} source hash does not match alert report",
                alert.code
            )));
        }
        for (name, value) in &alert.labels {
            if !matches!(
                name.as_str(),
                "notification_route" | "opsgenie" | "service" | "severity"
            ) || !is_bounded_route_token(value)
            {
                return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                    "alert {} contains an unbounded label",
                    alert.code
                )));
            }
        }
        if alert.labels.get("notification_route") != Some(&alert.notification_route)
            || alert.labels.get("opsgenie") != Some(&alert.opsgenie)
            || alert.labels.get("severity") != Some(&alert.severity)
        {
            return Err(PheromoneRelayError::AlertSourceInvalid(format!(
                "alert {} labels do not match alert routing fields",
                alert.code
            )));
        }
    }
    for point in &input.trend_report.points {
        if !is_bounded_code(&point.code) || relay_alert_severity_from_str(&point.severity).is_err()
        {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "trend report contains unbounded point data".to_string(),
            ));
        }
    }
    Ok(())
}

fn handoff_escalation_map(
    profile: &RelayAlertHandoffProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertHandoffEscalation>, PheromoneRelayError> {
    let mut escalations = BTreeMap::new();
    for escalation in &profile.escalations {
        if escalations
            .insert(escalation.escalation_ref.as_str(), escalation)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertHandoffInvalid(format!(
                "duplicate escalation {}",
                escalation.escalation_ref
            )));
        }
    }
    Ok(escalations)
}

fn require_alert_recommendation(
    required: bool,
    recommendation_codes: &BTreeSet<&str>,
    code: &str,
) -> Result<(), PheromoneRelayError> {
    if required && !recommendation_codes.contains(code) {
        return Err(PheromoneRelayError::AlertSourceInvalid(format!(
            "observability report omitted required {code} recommendation"
        )));
    }
    Ok(())
}

fn handoff_receiver_route_map(
    profile: &RelayAlertHandoffProfileDocument,
) -> Result<BTreeMap<(String, String), RelayAlertHandoffReceiver>, PheromoneRelayError> {
    let mut receivers = BTreeMap::new();
    for receiver in &profile.receivers {
        let key = (
            receiver.notification_route.clone(),
            receiver.opsgenie.clone(),
        );
        if receivers.insert(key, receiver.clone()).is_some() {
            return Err(PheromoneRelayError::AlertHandoffInvalid(
                "duplicate handoff route coverage".to_string(),
            ));
        }
    }
    Ok(receivers)
}

fn alert_route_map(
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<BTreeMap<String, RelayAlertRoute>, PheromoneRelayError> {
    let mut routes = BTreeMap::new();
    for route in &profile.routes {
        if routes
            .insert(route.route_id.clone(), route.clone())
            .is_some()
        {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert route {}",
                route.route_id
            )));
        }
    }
    Ok(routes)
}

fn alert_rule_map(
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<BTreeMap<String, RelayAlertRule>, PheromoneRelayError> {
    let mut rules = BTreeMap::new();
    for rule in &profile.rules {
        if rules
            .insert(rule.alert_code.clone(), rule.clone())
            .is_some()
        {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "duplicate alert rule {}",
                rule.alert_code
            )));
        }
    }
    Ok(rules)
}

fn matching_event_evidence(
    alert_code: &str,
    input: &RelayAlertEvaluationInput<'_>,
) -> Result<Vec<String>, PheromoneRelayError> {
    let mut evidence = Vec::new();
    for event in input.event_reports {
        if event.schema != PHEROMONE_RELAY_EVENT_REPORT_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(event.schema.clone()));
        }
        if event.local_kernel_id != input.observability.local_kernel_id {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "event report local kernel id mismatch".to_string(),
            ));
        }
        if event.generated_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertSourceInvalid(
                "event report timestamp is in the future".to_string(),
            ));
        }
        let stable = event.stable_failure_code.as_deref();
        if event.code == alert_code || stable == Some(alert_code) {
            evidence.push(canonical_sha256(event)?);
        }
    }
    Ok(evidence)
}

fn active_suppression_until(
    state: Option<&RelayAlertSuppressionStateDocument>,
    alert_code: &str,
    route_id: &str,
    now_unix_ms: u64,
) -> Option<u64> {
    let state = state?;
    state
        .entries
        .iter()
        .find(|entry| {
            entry.alert_code == alert_code
                && entry.route_id == route_id
                && entry.starts_at_unix_ms <= now_unix_ms
                && entry.expires_at_unix_ms > now_unix_ms
        })
        .map(|entry| entry.expires_at_unix_ms)
}

fn alert_labels(
    route: &RelayAlertRoute,
    rule: &RelayAlertRule,
) -> Result<BTreeMap<String, String>, PheromoneRelayError> {
    let mut labels = BTreeMap::new();
    labels.insert(
        "notification_route".to_string(),
        route.notification_route.clone(),
    );
    labels.insert("opsgenie".to_string(), route.opsgenie.clone());
    labels.insert("service".to_string(), "chiodos-pheromone-relay".to_string());
    labels.insert("severity".to_string(), rule.severity.as_str().to_string());
    for (name, value) in &labels {
        if !matches!(
            name.as_str(),
            "notification_route" | "opsgenie" | "service" | "severity"
        ) || !is_bounded_route_token(value)
        {
            return Err(PheromoneRelayError::AlertRoutingInvalid(format!(
                "alert label {name} is not bounded"
            )));
        }
    }
    Ok(labels)
}

fn bump_trend_point(
    points: &mut BTreeMap<String, RelayTrendPoint>,
    code: &str,
    severity: &str,
    observed_at_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if !is_bounded_code(code) {
        return Err(PheromoneRelayError::AlertSourceInvalid(format!(
            "trend code {code} is not bounded"
        )));
    }
    points
        .entry(code.to_string())
        .and_modify(|point| {
            point.count = point.count.saturating_add(1);
            point.first_seen_unix_ms = point.first_seen_unix_ms.min(observed_at_unix_ms);
            point.last_seen_unix_ms = point.last_seen_unix_ms.max(observed_at_unix_ms);
        })
        .or_insert_with(|| RelayTrendPoint {
            code: code.to_string(),
            count: 1,
            first_seen_unix_ms: observed_at_unix_ms,
            last_seen_unix_ms: observed_at_unix_ms,
            severity: severity.to_string(),
        });
    Ok(())
}

fn relay_alert_severity_from_str(value: &str) -> Result<RelayAlertSeverity, PheromoneRelayError> {
    match value {
        "info" => Ok(RelayAlertSeverity::Info),
        "warning" => Ok(RelayAlertSeverity::Warning),
        "critical" => Ok(RelayAlertSeverity::Critical),
        _ => Err(PheromoneRelayError::AlertSourceInvalid(format!(
            "alert severity {value} is not supported"
        ))),
    }
}

fn is_bounded_code(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 96
        && value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-' | '.')
        })
}

fn is_bounded_route_token(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|ch| {
            ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '_' | '-' | '.' | ':' | '/')
        })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySupervisorProfileDocument {
    pub schema: String,
    pub profile: RelayProfile,
    pub service_name: String,
    pub listen: String,
    pub store_path: String,
    pub peer_directory_state_path: String,
    pub signing_key_path: String,
    pub health_path: String,
    pub ready_path: String,
    pub single_writer: bool,
    pub reverse_proxy: RelayReverseProxyProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayReverseProxyProfile {
    pub scheme: String,
    pub pinned_path_prefix: String,
    pub max_body_bytes: usize,
    pub redirects_disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDrillCheck {
    pub code: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
    pub generated_at_unix_ms: u64,
    pub checks: Vec<RelayDrillCheck>,
}

pub fn relay_supervisor_profile_from_json(
    json: &str,
) -> Result<RelaySupervisorProfileDocument, PheromoneRelayError> {
    let profile: RelaySupervisorProfileDocument = serde_json::from_str(json)?;
    if profile.schema != PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(profile.schema));
    }
    Ok(profile)
}

pub fn lint_relay_supervisor_profile(
    profile: &RelaySupervisorProfileDocument,
    now_unix_ms: u64,
) -> RelayDrillReport {
    let mut checks = Vec::new();
    push_drill_check(
        &mut checks,
        profile.schema == PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA,
        "supervisor_schema",
        "supervisor profile declares the current schema",
    );
    push_drill_check(
        &mut checks,
        profile.health_path == PHEROMONE_HEALTH_PATH,
        "health_path",
        "health endpoint path is pinned",
    );
    push_drill_check(
        &mut checks,
        profile.ready_path == PHEROMONE_READY_PATH,
        "ready_path",
        "readiness endpoint path is pinned",
    );
    push_drill_check(
        &mut checks,
        profile.single_writer,
        "single_writer",
        "profile declares a single relay writer boundary",
    );
    push_drill_check(
        &mut checks,
        profile.reverse_proxy.pinned_path_prefix == "/v1/chiodos/pheromone",
        "pinned_path_prefix",
        "reverse proxy pins the Chiodos pheromone path prefix",
    );
    push_drill_check(
        &mut checks,
        profile.reverse_proxy.redirects_disabled,
        "redirects_disabled",
        "reverse proxy disables upstream redirects",
    );
    push_drill_check(
        &mut checks,
        profile.reverse_proxy.max_body_bytes
            <= RelayProfileLimits::production_defaults().max_body_bytes,
        "max_body_bytes",
        "reverse proxy body limit stays within production relay bounds",
    );
    let scheme_ok = match profile.profile {
        RelayProfile::LocalDev => {
            profile.reverse_proxy.scheme == "http" || profile.reverse_proxy.scheme == "https"
        }
        RelayProfile::Production => profile.reverse_proxy.scheme == "https",
    };
    push_drill_check(
        &mut checks,
        scheme_ok,
        "endpoint_scheme",
        "profile endpoint scheme is allowed for the selected relay profile",
    );
    let accepted = checks.iter().all(|check| check.accepted);
    RelayDrillReport {
        schema: PHEROMONE_RELAY_DRILL_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "supervisor_profile_invalid".to_string()
        },
        detail: if accepted {
            "relay supervisor profile accepted".to_string()
        } else {
            "relay supervisor profile rejected".to_string()
        },
        generated_at_unix_ms: now_unix_ms,
        checks,
    }
}

fn push_drill_check(checks: &mut Vec<RelayDrillCheck>, accepted: bool, code: &str, detail: &str) {
    checks.push(RelayDrillCheck {
        code: code.to_string(),
        accepted,
        detail: detail.to_string(),
    });
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayDeliveryReport {
    pub schema: String,
    pub accepted: bool,
    pub recipient_kernel_id: String,
    pub code: String,
    pub receive_report: Option<PheromoneReceiveReport>,
}

#[derive(Debug, Clone)]
pub struct SqlitePheromoneRelayStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqlitePheromoneRelayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PheromoneRelayError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open(path)?)),
        };
        store.run_migrations()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, PheromoneRelayError> {
        let store = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
        };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_nonces (
                sender_kernel_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY(sender_kernel_id, nonce)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_outbox (
                outbox_id TEXT PRIMARY KEY,
                sender_kernel_id TEXT NOT NULL,
                recipient_kernel_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                queued_at_unix_ms INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                next_attempt_unix_ms INTEGER NOT NULL,
                lease_expires_unix_ms INTEGER,
                last_error_code TEXT,
                batch_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_pheromone_relay_outbox_due
                ON chio_pheromone_relay_outbox(status, next_attempt_unix_ms);

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_inbox (
                sender_kernel_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                batch_sha256 TEXT NOT NULL,
                report_json TEXT NOT NULL,
                PRIMARY KEY(sender_kernel_id, nonce)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                outbox_id TEXT NOT NULL,
                code TEXT NOT NULL,
                recorded_at_unix_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_cursors (
                peer_kernel_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                cursor TEXT NOT NULL,
                PRIMARY KEY(peer_kernel_id, treaty_id)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_relay_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_kind TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                code TEXT NOT NULL,
                recorded_at_unix_ms INTEGER NOT NULL,
                report_json TEXT NOT NULL
            );
            "#,
        )?;
        ensure_outbox_queued_column(&conn)?;
        Ok(())
    }

    pub fn enqueue_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        treaty_id: &str,
        batch: &PheromoneGossipBatch,
        queued_at_unix_ms: u64,
    ) -> Result<String, PheromoneRelayError> {
        let outbox_id = canonical_sha256(&serde_json::json!({
            "sender": sender_kernel_id,
            "recipient": recipient_kernel_id,
            "treaty": treaty_id,
            "batch": batch,
            "queuedAtUnixMs": queued_at_unix_ms
        }))?;
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_outbox
                (outbox_id, sender_kernel_id, recipient_kernel_id, treaty_id,
                 queued_at_unix_ms, status, attempts, next_attempt_unix_ms,
                 lease_expires_unix_ms, last_error_code, batch_json)
            VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?5, NULL, NULL, ?6)
            ON CONFLICT(outbox_id) DO NOTHING
            "#,
            params![
                outbox_id,
                sender_kernel_id,
                recipient_kernel_id,
                treaty_id,
                i64_from_u64(queued_at_unix_ms, "queued_at_unix_ms")?,
                serde_json::to_string(batch)?,
            ],
        )?;
        Ok(outbox_id)
    }

    pub fn lease_due_batches(
        &self,
        now_unix_ms: u64,
        max_batches: usize,
    ) -> Result<Vec<RelayOutboxBatch>, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            UPDATE chio_pheromone_relay_outbox
            SET status = 'retry',
                lease_expires_unix_ms = NULL,
                last_error_code = 'stale_lease_recovered'
            WHERE status = 'leased' AND lease_expires_unix_ms <= ?1
            "#,
            params![i64_from_u64(now_unix_ms, "now_unix_ms")?],
        )?;
        let mut stmt = conn.prepare(
            r#"
            SELECT outbox_id, sender_kernel_id, recipient_kernel_id, treaty_id, attempts, batch_json
            FROM chio_pheromone_relay_outbox
            WHERE status IN ('pending', 'retry') AND next_attempt_unix_ms <= ?1
            ORDER BY next_attempt_unix_ms, outbox_id
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(
            params![
                i64_from_u64(now_unix_ms, "now_unix_ms")?,
                i64::try_from(max_batches).map_err(|_| PheromoneRelayError::Sqlite(
                    "max_batches too large".to_string()
                ))?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )?;
        let mut leased = Vec::new();
        for row in rows {
            let (outbox_id, sender_kernel_id, recipient_kernel_id, treaty_id, attempts, batch_json) =
                row?;
            leased.push(RelayOutboxBatch {
                outbox_id,
                sender_kernel_id,
                recipient_kernel_id,
                treaty_id,
                attempts: u64::try_from(attempts).map_err(|_| {
                    PheromoneRelayError::Sqlite("attempt count is negative".to_string())
                })?,
                batch: serde_json::from_str(&batch_json)?,
            });
        }
        drop(stmt);
        let lease_expires = now_unix_ms.saturating_add(30_000);
        for batch in &leased {
            conn.execute(
                r#"
                UPDATE chio_pheromone_relay_outbox
                SET status = 'leased', lease_expires_unix_ms = ?2
                WHERE outbox_id = ?1
                "#,
                params![
                    batch.outbox_id,
                    i64_from_u64(lease_expires, "lease_expires_unix_ms")?
                ],
            )?;
        }
        Ok(leased)
    }

    pub fn mark_delivered(&self, outbox_id: &str) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            "UPDATE chio_pheromone_relay_outbox SET status = 'delivered' WHERE outbox_id = ?1",
            params![outbox_id],
        )?;
        Ok(())
    }

    pub fn mark_retry(
        &self,
        outbox_id: &str,
        code: &str,
        next_attempt_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            UPDATE chio_pheromone_relay_outbox
            SET status = 'retry',
                attempts = attempts + 1,
                next_attempt_unix_ms = ?2,
                lease_expires_unix_ms = NULL,
                last_error_code = ?3
            WHERE outbox_id = ?1
            "#,
            params![
                outbox_id,
                i64_from_u64(next_attempt_unix_ms, "next_attempt_unix_ms")?,
                code,
            ],
        )?;
        conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_attempts
                (outbox_id, code, recorded_at_unix_ms)
            VALUES (?1, ?2, ?3)
            "#,
            params![
                outbox_id,
                code,
                i64_from_u64(next_attempt_unix_ms, "recorded_at_unix_ms")?,
            ],
        )?;
        Ok(())
    }

    pub fn mark_dead_letter(&self, outbox_id: &str, code: &str) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            UPDATE chio_pheromone_relay_outbox
            SET status = 'dead_letter', last_error_code = ?2
            WHERE outbox_id = ?1
            "#,
            params![outbox_id, code],
        )?;
        Ok(())
    }

    pub fn catchup_batches(
        &self,
        recipient_kernel_id: &str,
        treaty_id: &str,
        after_cursor: &str,
        limit: usize,
        max_bytes: usize,
    ) -> Result<(Vec<PheromoneGossipBatch>, String), PheromoneRelayError> {
        if limit == 0 {
            return Err(PheromoneRelayError::CatchupDenied(
                "catch-up limit must be positive".to_string(),
            ));
        }
        let after_rowid = parse_cursor(after_cursor)?;
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT rowid, batch_json
            FROM chio_pheromone_relay_outbox
            WHERE recipient_kernel_id = ?1 AND treaty_id = ?2 AND rowid > ?3
            ORDER BY rowid
            LIMIT ?4
            "#,
        )?;
        let rows = stmt.query_map(
            params![
                recipient_kernel_id,
                treaty_id,
                i64_from_u64(after_rowid, "after_cursor")?,
                i64::try_from(limit).map_err(|_| PheromoneRelayError::CatchupDenied(
                    "catch-up limit is too large".to_string()
                ))?
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut frames = Vec::new();
        let mut bytes = 0usize;
        let mut next_cursor = after_rowid;
        for row in rows {
            let (rowid, batch_json) = row?;
            let batch_bytes = batch_json.len();
            if bytes.saturating_add(batch_bytes) > max_bytes {
                if frames.is_empty() {
                    return Err(PheromoneRelayError::CatchupDenied(
                        "catch-up byte limit exceeded before first frame".to_string(),
                    ));
                }
                break;
            }
            frames.push(serde_json::from_str(&batch_json)?);
            bytes = bytes.saturating_add(batch_bytes);
            next_cursor = u64::try_from(rowid)
                .map_err(|_| PheromoneRelayError::Sqlite("negative cursor rowid".to_string()))?;
        }
        Ok((frames, next_cursor.to_string()))
    }

    pub fn operator_report(
        &self,
        local_kernel_id: &str,
        generated_at_unix_ms: u64,
    ) -> Result<RelayOperatorReport, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status IN ('pending', 'retry', 'leased')",
            [],
            |row| row.get(0),
        )?;
        let delivered: i64 = conn.query_row(
            "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status = 'delivered'",
            [],
            |row| row.get(0),
        )?;
        let inbox: i64 = conn.query_row(
            "SELECT COUNT(*) FROM chio_pheromone_relay_inbox",
            [],
            |row| row.get(0),
        )?;
        Ok(RelayOperatorReport {
            schema: PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA.to_string(),
            accepted: true,
            code: "accepted".to_string(),
            detail: format!("pending={pending}; delivered={delivered}; inbox={inbox}"),
            local_kernel_id: local_kernel_id.to_string(),
            generated_at_unix_ms,
        })
    }

    pub fn health_report(
        &self,
        local_kernel_id: &str,
        generated_at_unix_ms: u64,
        peer_directory_version: Option<u64>,
    ) -> Result<RelayHealthReport, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let queue_depth = count_outbox_statuses(&conn, &["pending", "retry", "leased"])?;
        let retry_count = count_outbox_statuses(&conn, &["retry"])?;
        let dead_letter_count = count_outbox_statuses(&conn, &["dead_letter"])?;
        let inbox_count = count_rows(&conn, "chio_pheromone_relay_inbox")?;
        let cursor_count = count_rows(&conn, "chio_pheromone_relay_cursors")?;
        let stale_lease_count = count_stale_leases(&conn, generated_at_unix_ms)?;
        let oldest_pending = oldest_pending_queued_at(&conn)?;
        let oldest_pending_age_ms =
            oldest_pending.map(|queued| generated_at_unix_ms.saturating_sub(queued));
        let mut checks = Vec::new();
        checks.push(RelayHealthCheck {
            code: "store.connected".to_string(),
            accepted: true,
            detail: "SQLite relay store is reachable".to_string(),
        });
        checks.push(RelayHealthCheck {
            code: "outbox.pressure".to_string(),
            accepted: queue_depth < 10_000,
            detail: format!("queue_depth={queue_depth}"),
        });
        checks.push(RelayHealthCheck {
            code: "leases.fresh".to_string(),
            accepted: stale_lease_count == 0,
            detail: format!("stale_lease_count={stale_lease_count}"),
        });
        let accepted = checks.iter().all(|check| check.accepted);
        Ok(RelayHealthReport {
            schema: PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA.to_string(),
            accepted,
            code: if accepted { "accepted" } else { "degraded" }.to_string(),
            detail: "relay health evaluated from durable store state".to_string(),
            local_kernel_id: local_kernel_id.to_string(),
            generated_at_unix_ms,
            peer_directory_version,
            queue_depth,
            oldest_pending_age_ms,
            retry_count,
            dead_letter_count,
            inbox_count,
            cursor_count,
            stale_lease_count,
            checks,
        })
    }

    pub fn relay_observability_report(
        &self,
        input: RelayObservabilityInput<'_>,
    ) -> Result<RelayObservabilityReport, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let queue = relay_queue_summary(&conn, input.generated_at_unix_ms)?;
        let directory = relay_directory_summary(
            input.peer_directory,
            input.peer_directory_state,
            input.profile,
        );
        let recent_failures = recent_failure_summaries(&conn, input.recent_failure_limit)?;
        let mut recommendations = Vec::new();
        if directory.expires_at_unix_ms.is_none() {
            recommendations.push(RelayOperatorRecommendation {
                code: "directory_unknown".to_string(),
                severity: "warning".to_string(),
            });
        }
        if directory
            .expires_at_unix_ms
            .is_some_and(|expires| expires <= input.generated_at_unix_ms.saturating_add(300_000))
        {
            recommendations.push(RelayOperatorRecommendation {
                code: "directory_expiring".to_string(),
                severity: "warning".to_string(),
            });
        }
        if queue.dead_letter > 0 {
            recommendations.push(RelayOperatorRecommendation {
                code: "dead_letters_present".to_string(),
                severity: "warning".to_string(),
            });
        }
        if queue.stale_lease_count > 0 {
            recommendations.push(RelayOperatorRecommendation {
                code: "stale_leases_present".to_string(),
                severity: "warning".to_string(),
            });
        }
        if queue.retry > 0 {
            recommendations.push(RelayOperatorRecommendation {
                code: "retries_pending".to_string(),
                severity: "info".to_string(),
            });
        }
        let accepted = recommendations.is_empty();
        Ok(RelayObservabilityReport {
            schema: PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA.to_string(),
            accepted,
            code: if accepted { "accepted" } else { "degraded" }.to_string(),
            local_kernel_id: input.local_kernel_id.to_string(),
            generated_at_unix_ms: input.generated_at_unix_ms,
            directory,
            queue,
            recent_failures,
            recommendations,
        })
    }

    pub fn relay_metrics_snapshot(
        &self,
        local_kernel_id: &str,
        generated_at_unix_ms: u64,
    ) -> Result<RelayMetricsSnapshot, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let queue = relay_queue_summary(&conn, generated_at_unix_ms)?;
        let failures = recent_failure_summaries(&conn, 32)?;
        let mut samples = Vec::new();
        push_queue_depth_sample(&mut samples, "pending", queue.pending);
        push_queue_depth_sample(&mut samples, "retry", queue.retry);
        push_queue_depth_sample(&mut samples, "leased", queue.leased);
        push_queue_depth_sample(&mut samples, "delivered", queue.delivered);
        push_queue_depth_sample(&mut samples, "dead_letter", queue.dead_letter);
        samples.push(RelayMetricSample {
            name: "chio_pheromone_relay_oldest_pending_age_seconds".to_string(),
            value: queue.oldest_pending_age_ms.unwrap_or(0) as f64 / 1_000.0,
            labels: BTreeMap::new(),
        });
        samples.push(RelayMetricSample {
            name: "chio_pheromone_relay_stale_leases".to_string(),
            value: queue.stale_lease_count as f64,
            labels: BTreeMap::new(),
        });
        let mut dead_letter_labels = BTreeMap::new();
        dead_letter_labels.insert("reason".to_string(), "observed".to_string());
        samples.push(RelayMetricSample {
            name: "chio_pheromone_relay_dead_letters_total".to_string(),
            value: queue.dead_letter as f64,
            labels: dead_letter_labels,
        });
        for failure in failures {
            let mut labels = BTreeMap::new();
            labels.insert("reason".to_string(), failure.code);
            samples.push(RelayMetricSample {
                name: "chio_pheromone_relay_rejections_total".to_string(),
                value: failure.count as f64,
                labels,
            });
        }
        Ok(RelayMetricsSnapshot {
            schema: PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA.to_string(),
            local_kernel_id: local_kernel_id.to_string(),
            generated_at_unix_ms,
            samples,
        })
    }

    pub fn record_event_report(
        &self,
        report: &RelayEventReport,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_events
                (event_kind, accepted, code, recorded_at_unix_ms, report_json)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                &report.event_kind,
                if report.accepted { 1 } else { 0 },
                &report.code,
                i64_from_u64(report.generated_at_unix_ms, "recorded_at_unix_ms")?,
                serde_json::to_string(report)?,
            ],
        )?;
        Ok(())
    }

    pub fn record_inbox(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        batch: &PheromoneGossipBatch,
        report: &PheromoneReceiveReport,
    ) -> Result<InboxRecordResult, PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let inserted = conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_inbox
                (sender_kernel_id, nonce, batch_sha256, report_json)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(sender_kernel_id, nonce) DO NOTHING
            "#,
            params![
                sender_kernel_id,
                nonce,
                canonical_sha256(batch)?,
                serde_json::to_string(report)?,
            ],
        )?;
        Ok(InboxRecordResult {
            inserted: inserted > 0,
        })
    }
}

impl PheromoneRelayStore for SqlitePheromoneRelayStore {
    fn enqueue_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        treaty_id: &str,
        batch: &PheromoneGossipBatch,
        queued_at_unix_ms: u64,
    ) -> Result<String, PheromoneRelayError> {
        Self::enqueue_batch(
            self,
            sender_kernel_id,
            recipient_kernel_id,
            treaty_id,
            batch,
            queued_at_unix_ms,
        )
    }

    fn lease_due_batches(
        &self,
        now_unix_ms: u64,
        max_batches: usize,
    ) -> Result<Vec<RelayOutboxBatch>, PheromoneRelayError> {
        Self::lease_due_batches(self, now_unix_ms, max_batches)
    }

    fn mark_delivered(&self, outbox_id: &str) -> Result<(), PheromoneRelayError> {
        Self::mark_delivered(self, outbox_id)
    }

    fn mark_retry(
        &self,
        outbox_id: &str,
        code: &str,
        next_attempt_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        Self::mark_retry(self, outbox_id, code, next_attempt_unix_ms)
    }

    fn mark_dead_letter(&self, outbox_id: &str, code: &str) -> Result<(), PheromoneRelayError> {
        Self::mark_dead_letter(self, outbox_id, code)
    }
}

impl RelayNonceRecorder for SqlitePheromoneRelayStore {
    fn record_relay_nonce(
        &self,
        sender_kernel_id: &str,
        nonce: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let conn = self.conn.lock()?;
        let inserted = conn.execute(
            r#"
            INSERT INTO chio_pheromone_relay_nonces
                (sender_kernel_id, nonce, expires_at_unix_ms)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(sender_kernel_id, nonce) DO NOTHING
            "#,
            params![
                sender_kernel_id,
                nonce,
                i64_from_u64(expires_at_unix_ms, "expires_at_unix_ms")?
            ],
        )?;
        if inserted == 0 {
            return Err(PheromoneRelayError::RelayNonceReplay(nonce.to_string()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PheromoneRelayConfig {
    pub local_kernel_id: String,
    pub profile: RelayProfile,
    pub now_unix_ms: u64,
    pub freshness_window_ms: u64,
    pub max_body_bytes: usize,
    pub use_system_clock: bool,
    pub operator_token: Option<String>,
    pub report_dir: Option<PathBuf>,
}

#[async_trait]
pub trait RelayBatchReceiver: Send + Sync {
    async fn receive_batch(
        &self,
        batch: PheromoneGossipBatch,
        authenticated_sender_kernel_id: String,
        received_at_unix_ms: u64,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError>;
}

#[derive(Clone)]
pub struct PheromoneRelayService {
    config: PheromoneRelayConfig,
    directory: PeerDirectory,
    receiver: Arc<dyn RelayBatchReceiver>,
    store: Arc<SqlitePheromoneRelayStore>,
}

impl PheromoneRelayService {
    #[must_use]
    pub fn new(
        config: PheromoneRelayConfig,
        directory: PeerDirectory,
        receiver: Arc<dyn RelayBatchReceiver>,
        store: Arc<SqlitePheromoneRelayStore>,
    ) -> Self {
        Self {
            config,
            directory,
            receiver,
            store,
        }
    }

    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<(), PheromoneRelayError> {
        let max_body_bytes = self.config.max_body_bytes;
        let router = Router::new()
            .route(PHEROMONE_BATCH_RELAY_PATH, post(handle_batch_relay))
            .route(PHEROMONE_CATCHUP_RELAY_PATH, post(handle_catchup_relay))
            .route(PHEROMONE_HEALTH_PATH, get(handle_health))
            .route(PHEROMONE_READY_PATH, get(handle_ready))
            .route(
                PHEROMONE_RELAY_OBSERVABILITY_PATH,
                get(handle_observability),
            )
            .route(PHEROMONE_RELAY_METRICS_PATH, get(handle_metrics))
            .layer(DefaultBodyLimit::max(max_body_bytes))
            .with_state(Arc::new(self));
        axum::serve(listener, router)
            .await
            .map_err(|error| PheromoneRelayError::Http(error.to_string()))
    }

    fn request_now_unix_ms(&self) -> u64 {
        if self.config.use_system_clock {
            system_unix_ms().unwrap_or(self.config.now_unix_ms)
        } else {
            self.config.now_unix_ms
        }
    }

    fn emit_event_report(
        &self,
        event_kind: &str,
        accepted: bool,
        code: &str,
        detail: &str,
        generated_at_unix_ms: u64,
    ) -> Result<(), PheromoneRelayError> {
        let report = RelayEventReport {
            schema: PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
            accepted,
            code: code.to_string(),
            detail: detail.to_string(),
            local_kernel_id: self.config.local_kernel_id.clone(),
            generated_at_unix_ms,
            event_kind: event_kind.to_string(),
            stable_failure_code: if accepted {
                None
            } else {
                Some(code.to_string())
            },
        };
        self.store.record_event_report(&report)?;
        if let Some(report_dir) = &self.config.report_dir {
            std::fs::create_dir_all(report_dir)?;
            let report_hash = canonical_sha256(&report)?;
            let suffix = report_hash.chars().take(12).collect::<String>();
            let filename = format!(
                "{}-{}-{}.json",
                generated_at_unix_ms,
                sanitize_event_part(event_kind),
                suffix
            );
            let path = report_dir.join(filename);
            let json = serde_json::to_string_pretty(&report)?;
            std::fs::write(path, format!("{json}\n"))?;
        }
        Ok(())
    }
}

async fn handle_health(
    State(service): State<Arc<PheromoneRelayService>>,
) -> Result<Json<RelayHealthReport>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    service
        .store
        .health_report(
            &service.config.local_kernel_id,
            now,
            service.directory.version(),
        )
        .map(Json)
        .map_err(|error| relay_http_error(&service, error))
}

async fn handle_ready(
    State(service): State<Arc<PheromoneRelayService>>,
) -> Result<Json<RelayHealthReport>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    let report = service
        .store
        .health_report(
            &service.config.local_kernel_id,
            now,
            service.directory.version(),
        )
        .map_err(|error| relay_http_error(&service, error))?;
    if report.accepted {
        Ok(Json(report))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(RelayOperatorReport {
                schema: PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA.to_string(),
                accepted: false,
                code: report.code.clone(),
                detail: report.detail.clone(),
                local_kernel_id: report.local_kernel_id.clone(),
                generated_at_unix_ms: report.generated_at_unix_ms,
            }),
        ))
    }
}

async fn handle_observability(
    State(service): State<Arc<PheromoneRelayService>>,
    headers: HeaderMap,
) -> Result<Json<RelayObservabilityReport>, (StatusCode, Json<RelayOperatorReport>)> {
    authorize_operator(&service, &headers)?;
    let now = service.request_now_unix_ms();
    service
        .store
        .relay_observability_report(RelayObservabilityInput {
            local_kernel_id: &service.config.local_kernel_id,
            generated_at_unix_ms: now,
            peer_directory: Some(&service.directory),
            peer_directory_state: None,
            profile: service.config.profile,
            recent_failure_limit: 25,
        })
        .map(Json)
        .map_err(|error| relay_http_error(&service, error))
}

async fn handle_metrics(
    State(service): State<Arc<PheromoneRelayService>>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<RelayOperatorReport>)> {
    authorize_operator(&service, &headers)?;
    let now = service.request_now_unix_ms();
    let snapshot = service
        .store
        .relay_metrics_snapshot(&service.config.local_kernel_id, now)
        .map_err(|error| relay_http_error(&service, error))?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        snapshot.render(RelayMetricsFormat::Prometheus),
    )
        .into_response())
}

async fn handle_batch_relay(
    State(service): State<Arc<PheromoneRelayService>>,
    Json(request): Json<PheromoneRelayHttpRequest>,
) -> Result<Json<PheromoneReceiveReport>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    let context = RelayHttpVerificationContext {
        local_kernel_id: service.config.local_kernel_id.clone(),
        method: "POST".to_string(),
        path: PHEROMONE_BATCH_RELAY_PATH.to_string(),
        now_unix_ms: now,
        freshness_window_ms: service.config.freshness_window_ms,
    };
    let batch: PheromoneGossipBatch = request
        .verify_payload(&service.directory, &context, service.store.as_ref())
        .map_err(|error| relay_http_error(&service, error))?;
    let report = service
        .receiver
        .receive_batch(batch.clone(), request.sender_kernel_id.clone(), now)
        .await
        .map_err(|error| relay_http_error(&service, error))?;
    service
        .store
        .record_inbox(&request.sender_kernel_id, &request.nonce, &batch, &report)
        .map_err(|error| relay_http_error(&service, error))?;
    let report_code = report
        .frames
        .iter()
        .find(|frame| !frame.accepted)
        .map(|frame| frame.code.as_str())
        .unwrap_or("accepted");
    service
        .emit_event_report(
            "batch_receive",
            report.accepted,
            report_code,
            "batch received",
            now,
        )
        .map_err(|error| relay_http_error(&service, error))?;
    Ok(Json(report))
}

async fn handle_catchup_relay(
    State(service): State<Arc<PheromoneRelayService>>,
    Json(request): Json<PheromoneRelayHttpRequest>,
) -> Result<Json<CatchupResponse>, (StatusCode, Json<RelayOperatorReport>)> {
    let now = service.request_now_unix_ms();
    let context = RelayHttpVerificationContext {
        local_kernel_id: service.config.local_kernel_id.clone(),
        method: "POST".to_string(),
        path: PHEROMONE_CATCHUP_RELAY_PATH.to_string(),
        now_unix_ms: now,
        freshness_window_ms: service.config.freshness_window_ms,
    };
    let catchup: CatchupRequest = request
        .verify_payload(&service.directory, &context, service.store.as_ref())
        .map_err(|error| relay_http_error(&service, error))?;
    validate_catchup_request(&service, &request.sender_kernel_id, &catchup)
        .map_err(|error| relay_http_error(&service, error))?;
    let peer = service
        .directory
        .peer(&request.sender_kernel_id)
        .map_err(|error| relay_http_error(&service, error))?;
    let (frames, next_cursor) = service
        .store
        .catchup_batches(
            &request.sender_kernel_id,
            &catchup.treaty_id,
            &catchup.after_cursor,
            catchup.limit,
            peer.max_catchup_bytes,
        )
        .map_err(|error| relay_http_error(&service, error))?;
    let response = CatchupResponse {
        schema: PHEROMONE_CATCHUP_RESPONSE_SCHEMA.to_string(),
        accepted: true,
        responder_kernel_id: catchup.responder_kernel_id,
        requester_kernel_id: catchup.requester_kernel_id,
        treaty_id: catchup.treaty_id,
        frames,
        next_cursor,
        code: "accepted".to_string(),
    };
    service
        .emit_event_report("catchup", true, "accepted", "catch-up response served", now)
        .map_err(|error| relay_http_error(&service, error))?;
    Ok(Json(response))
}

fn validate_catchup_request(
    service: &PheromoneRelayService,
    authenticated_sender: &str,
    catchup: &CatchupRequest,
) -> Result<(), PheromoneRelayError> {
    if catchup.schema != PHEROMONE_CATCHUP_REQUEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            catchup.schema.clone(),
        ));
    }
    if catchup.requester_kernel_id != authenticated_sender {
        return Err(PheromoneRelayError::SenderMismatch(format!(
            "catch-up requester {} does not match authenticated sender {}",
            catchup.requester_kernel_id, authenticated_sender
        )));
    }
    if catchup.responder_kernel_id != service.config.local_kernel_id {
        return Err(PheromoneRelayError::RecipientMismatch(format!(
            "catch-up responder {} does not match local receiver {}",
            catchup.responder_kernel_id, service.config.local_kernel_id
        )));
    }
    let peer = service.directory.peer(authenticated_sender)?;
    if catchup.limit == 0 || catchup.limit > peer.max_catchup_frames {
        return Err(PheromoneRelayError::CatchupDenied(format!(
            "catch-up limit {} exceeds peer bound {}",
            catchup.limit, peer.max_catchup_frames
        )));
    }
    if !peer.treaty_subscriptions.contains(&catchup.treaty_id) {
        return Err(PheromoneRelayError::CatchupDenied(format!(
            "peer {} is not subscribed to treaty {}",
            authenticated_sender, catchup.treaty_id
        )));
    }
    Ok(())
}

fn authorize_operator(
    service: &PheromoneRelayService,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<RelayOperatorReport>)> {
    let Some(token) = service.config.operator_token.as_deref() else {
        return Ok(());
    };
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {token}"));
    if authorized {
        Ok(())
    } else {
        Err(relay_http_status_error(
            service,
            PheromoneRelayError::OperatorAuthRequired(
                "operator token is required for relay observability".to_string(),
            ),
            StatusCode::UNAUTHORIZED,
        ))
    }
}

fn relay_http_error(
    service: &PheromoneRelayService,
    error: PheromoneRelayError,
) -> (StatusCode, Json<RelayOperatorReport>) {
    relay_http_status_error(service, error, StatusCode::BAD_REQUEST)
}

fn relay_http_status_error(
    service: &PheromoneRelayService,
    error: PheromoneRelayError,
    status: StatusCode,
) -> (StatusCode, Json<RelayOperatorReport>) {
    let now = service.request_now_unix_ms();
    let code = error.code().to_string();
    let detail = error.to_string();
    let _ = service.emit_event_report("request_rejected", false, &code, &detail, now);
    (
        status,
        Json(RelayOperatorReport {
            schema: PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA.to_string(),
            accepted: false,
            code,
            detail,
            local_kernel_id: service.config.local_kernel_id.clone(),
            generated_at_unix_ms: now,
        }),
    )
}

pub async fn deliver_due_batches(
    store: &(impl PheromoneRelayStore + ?Sized),
    directory: PeerDirectory,
    keypair: Keypair,
    sender_kernel_id: &str,
    now_unix_ms: u64,
    max_batches: usize,
) -> Result<RelayTickReport, PheromoneRelayError> {
    let client = PheromoneRelayClient::new(directory, keypair, now_unix_ms, 60_000)?;
    let due = store.lease_due_batches(now_unix_ms, max_batches)?;
    let mut report = RelayTickReport {
        schema: PHEROMONE_RELAY_TICK_REPORT_SCHEMA.to_string(),
        accepted: true,
        delivered: 0,
        retried: 0,
        dead_lettered: 0,
        duplicate_idempotent: 0,
        failures: Vec::new(),
    };
    for entry in due {
        if entry.sender_kernel_id != sender_kernel_id {
            store.mark_retry(
                &entry.outbox_id,
                "sender_mismatch",
                now_unix_ms.saturating_add(60_000),
            )?;
            report.accepted = false;
            report.retried = report.retried.saturating_add(1);
            report
                .failures
                .push(format!("{}: sender_mismatch", entry.outbox_id));
            continue;
        }
        let nonce = format!("relay-tick:{}:{}", entry.outbox_id, entry.attempts + 1);
        match client
            .post_batch(
                sender_kernel_id,
                &entry.recipient_kernel_id,
                &entry.batch,
                &nonce,
            )
            .await
        {
            Ok(receive_report) if receive_report.accepted => {
                store.mark_delivered(&entry.outbox_id)?;
                report.delivered = report.delivered.saturating_add(1);
            }
            Ok(receive_report) => {
                let code = receive_report
                    .frames
                    .iter()
                    .find(|frame| !frame.accepted)
                    .map(|frame| frame.code.as_str())
                    .unwrap_or("receiver_rejected");
                mark_delivery_failure(store, &entry, code, now_unix_ms, &mut report)?;
            }
            Err(error) => {
                mark_delivery_failure(store, &entry, error.code(), now_unix_ms, &mut report)?;
            }
        }
    }
    Ok(report)
}

fn mark_delivery_failure(
    store: &(impl PheromoneRelayStore + ?Sized),
    entry: &RelayOutboxBatch,
    code: &str,
    now_unix_ms: u64,
    report: &mut RelayTickReport,
) -> Result<(), PheromoneRelayError> {
    report.accepted = false;
    report.failures.push(format!("{}: {code}", entry.outbox_id));
    if entry.attempts.saturating_add(1) >= 3 {
        store.mark_dead_letter(&entry.outbox_id, code)?;
        report.dead_lettered = report.dead_lettered.saturating_add(1);
    } else {
        let backoff_ms = 60_000u64.saturating_mul(entry.attempts.saturating_add(1));
        store.mark_retry(
            &entry.outbox_id,
            code,
            now_unix_ms.saturating_add(backoff_ms),
        )?;
        report.retried = report.retried.saturating_add(1);
    }
    Ok(())
}

pub struct PheromoneRelayClient {
    directory: PeerDirectory,
    keypair: Keypair,
    now_unix_ms: u64,
    freshness_window_ms: u64,
    client: reqwest::Client,
}

impl PheromoneRelayClient {
    pub fn new(
        directory: PeerDirectory,
        keypair: Keypair,
        now_unix_ms: u64,
        freshness_window_ms: u64,
    ) -> Result<Self, PheromoneRelayError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(freshness_window_ms.max(1)))
            .build()
            .map_err(|error| PheromoneRelayError::Http(error.to_string()))?;
        Ok(Self {
            directory,
            keypair,
            now_unix_ms,
            freshness_window_ms,
            client,
        })
    }

    pub async fn post_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        batch: &PheromoneGossipBatch,
        nonce: &str,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
        let url = self
            .directory
            .endpoint_for(recipient_kernel_id, PHEROMONE_BATCH_RELAY_PATH)?;
        let request = sign_relay_http_request(RelayHttpSigningInput {
            sender_kernel_id,
            recipient_kernel_id,
            method: "POST",
            path: PHEROMONE_BATCH_RELAY_PATH,
            nonce,
            sent_at_unix_ms: self.now_unix_ms,
            payload: batch,
            keypair: &self.keypair,
        })?;
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(|error| PheromoneRelayError::TransportError(error.to_string()))?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response
                .text()
                .await
                .unwrap_or_else(|error| error.to_string());
            return Err(PheromoneRelayError::TransportError(format!(
                "relay POST failed with {status}: {detail}"
            )));
        }
        response
            .json::<PheromoneReceiveReport>()
            .await
            .map_err(|error| PheromoneRelayError::Json(error.to_string()))
    }

    #[must_use]
    pub fn freshness_window_ms(&self) -> u64 {
        self.freshness_window_ms
    }
}

fn validate_endpoint(endpoint: &str) -> Result<(), PheromoneRelayError> {
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

fn validate_peer_directory_profile(
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
        if peer.max_catchup_bytes == 0 || peer.max_catchup_bytes > limits.max_catchup_bytes {
            return Err(PheromoneRelayError::RelayProfileDenied(format!(
                "peer {} max catch-up bytes {} exceeds profile bound {}",
                peer.kernel_id, peer.max_catchup_bytes, limits.max_catchup_bytes
            )));
        }
    }
    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn relay_directory_summary(
    directory: Option<&PeerDirectory>,
    state: Option<&PeerDirectoryStateDocument>,
    profile: RelayProfile,
) -> RelayDirectorySummary {
    let active = state.and_then(|document| document.active.as_ref());
    let mut removed_peer_ids = active
        .map(|entry| entry.removed_peer_ids.clone())
        .unwrap_or_default();
    removed_peer_ids.sort();
    let last_rejection_code = state
        .and_then(|document| document.rejected.last())
        .map(|entry| entry.code.clone());
    RelayDirectorySummary {
        active_version: active
            .map(|entry| entry.version)
            .or_else(|| directory.and_then(PeerDirectory::version)),
        active_bundle_sha256: active.map(|entry| entry.bundle_sha256.clone()),
        directory_sha256: active.map(|entry| entry.directory_sha256.clone()),
        issuer: active.map(|entry| entry.bundle.body.issuer.clone()),
        expires_at_unix_ms: active
            .map(|entry| entry.bundle.body.expires_at_unix_ms)
            .or_else(|| {
                directory.map(|peer_directory| peer_directory.document().expires_at_unix_ms)
            }),
        removed_peer_count: u64::try_from(removed_peer_ids.len()).unwrap_or(u64::MAX),
        removed_peer_ids,
        rejected_candidate_count: state
            .map(|document| u64::try_from(document.rejected.len()).unwrap_or(u64::MAX))
            .unwrap_or(0),
        last_rejection_code,
        profile,
    }
}

fn relay_queue_summary(
    conn: &Connection,
    generated_at_unix_ms: u64,
) -> Result<RelayQueueSummary, PheromoneRelayError> {
    let pending = count_outbox_statuses(conn, &["pending"])?;
    let retry = count_outbox_statuses(conn, &["retry"])?;
    let leased = count_outbox_statuses(conn, &["leased"])?;
    let delivered = count_outbox_statuses(conn, &["delivered"])?;
    let dead_letter = count_outbox_statuses(conn, &["dead_letter"])?;
    let oldest_pending = oldest_pending_queued_at(conn)?;
    Ok(RelayQueueSummary {
        pending,
        retry,
        leased,
        delivered,
        dead_letter,
        oldest_pending_age_ms: oldest_pending
            .map(|queued| generated_at_unix_ms.saturating_sub(queued)),
        stale_lease_count: count_stale_leases(conn, generated_at_unix_ms)?,
        inbox_count: count_rows(conn, "chio_pheromone_relay_inbox")?,
        cursor_count: count_rows(conn, "chio_pheromone_relay_cursors")?,
        catchup_event_count: count_catchup_events(conn)?,
    })
}

fn recent_failure_summaries(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<RelayFailureSummary>, PheromoneRelayError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut counts = BTreeMap::<String, u64>::new();
    let mut stmt = conn.prepare(
        r#"
        SELECT code, COUNT(*)
        FROM chio_pheromone_relay_attempts
        GROUP BY code
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (code, count) = row?;
        let count = u64_from_i64(count, "attempt count")?;
        counts
            .entry(code)
            .and_modify(|value| *value = value.saturating_add(count))
            .or_insert(count);
    }
    drop(stmt);

    let mut stmt = conn.prepare(
        r#"
        SELECT last_error_code, COUNT(*)
        FROM chio_pheromone_relay_outbox
        WHERE status = 'dead_letter' AND last_error_code IS NOT NULL
        GROUP BY last_error_code
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (code, count) = row?;
        let count = u64_from_i64(count, "dead-letter count")?;
        counts
            .entry(code)
            .and_modify(|value| *value = value.saturating_add(count))
            .or_insert(count);
    }
    drop(stmt);

    let mut stmt = conn.prepare(
        r#"
        SELECT code, COUNT(*)
        FROM chio_pheromone_relay_events
        WHERE accepted = 0
        GROUP BY code
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (code, count) = row?;
        let count = u64_from_i64(count, "event count")?;
        counts
            .entry(code)
            .and_modify(|value| *value = value.saturating_add(count))
            .or_insert(count);
    }

    let mut summaries = counts
        .into_iter()
        .map(|(code, count)| RelayFailureSummary { code, count })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.code.cmp(&right.code))
    });
    summaries.truncate(limit);
    Ok(summaries)
}

fn push_queue_depth_sample(samples: &mut Vec<RelayMetricSample>, status: &str, value: u64) {
    let mut labels = BTreeMap::new();
    labels.insert("status".to_string(), status.to_string());
    samples.push(RelayMetricSample {
        name: "chio_pheromone_relay_queue_depth".to_string(),
        value: value as f64,
        labels,
    });
}

fn count_catchup_events(conn: &Connection) -> Result<u64, PheromoneRelayError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_pheromone_relay_events WHERE event_kind = 'catchup'",
        [],
        |row| row.get(0),
    )?;
    u64_from_i64(count, "catch-up event count")
}

fn prometheus_help(name: &str) -> &'static str {
    match name {
        "chio_pheromone_relay_queue_depth" => "Relay outbox depth by bounded status.",
        "chio_pheromone_relay_oldest_pending_age_seconds" => {
            "Oldest pending relay outbox age in seconds."
        }
        "chio_pheromone_relay_stale_leases" => "Relay scheduler leases past their expiry.",
        "chio_pheromone_relay_dead_letters_total" => {
            "Total relay outbox batches moved to dead letter."
        }
        "chio_pheromone_relay_rejections_total" => {
            "Total live pheromone relay rejections by bounded reason."
        }
        _ => "Chio relay metric.",
    }
}

fn prometheus_kind(name: &str) -> &'static str {
    match name {
        "chio_pheromone_relay_dead_letters_total" | "chio_pheromone_relay_rejections_total" => {
            "counter"
        }
        _ => "gauge",
    }
}

fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn format_float(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.6}")
    }
}

fn system_unix_ms() -> Option<u64> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_millis()).ok()
}

fn sanitize_event_part(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, PheromoneRelayError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, PheromoneRelayError> {
    i64::try_from(value)
        .map_err(|_| PheromoneRelayError::Sqlite(format!("{field} does not fit signed integer")))
}

fn parse_cursor(cursor: &str) -> Result<u64, PheromoneRelayError> {
    if cursor.trim().is_empty() {
        return Ok(0);
    }
    cursor
        .parse::<u64>()
        .map_err(|_| PheromoneRelayError::CatchupDenied("catch-up cursor is invalid".to_string()))
}

fn ensure_outbox_queued_column(conn: &Connection) -> Result<(), PheromoneRelayError> {
    let mut stmt = conn.prepare("PRAGMA table_info(chio_pheromone_relay_outbox)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == "queued_at_unix_ms" {
            return Ok(());
        }
    }
    conn.execute(
        "ALTER TABLE chio_pheromone_relay_outbox ADD COLUMN queued_at_unix_ms INTEGER NOT NULL DEFAULT 0",
        [],
    )?;
    Ok(())
}

fn count_outbox_statuses(conn: &Connection, statuses: &[&str]) -> Result<u64, PheromoneRelayError> {
    let placeholders = statuses.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status IN ({placeholders})"
    );
    let mut stmt = conn.prepare(&sql)?;
    let count: i64 = stmt.query_row(rusqlite::params_from_iter(statuses.iter()), |row| {
        row.get(0)
    })?;
    u64_from_i64(count, "count")
}

fn count_rows(conn: &Connection, table: &str) -> Result<u64, PheromoneRelayError> {
    let allowed = ["chio_pheromone_relay_inbox", "chio_pheromone_relay_cursors"];
    if !allowed.contains(&table) {
        return Err(PheromoneRelayError::Sqlite(format!(
            "unsupported count table {table}"
        )));
    }
    let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    u64_from_i64(count, "count")
}

fn count_stale_leases(conn: &Connection, now_unix_ms: u64) -> Result<u64, PheromoneRelayError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_pheromone_relay_outbox WHERE status = 'leased' AND lease_expires_unix_ms <= ?1",
        params![i64_from_u64(now_unix_ms, "now_unix_ms")?],
        |row| row.get(0),
    )?;
    u64_from_i64(count, "stale lease count")
}

fn oldest_pending_queued_at(conn: &Connection) -> Result<Option<u64>, PheromoneRelayError> {
    let queued: Option<i64> = conn.query_row(
        "SELECT MIN(queued_at_unix_ms) FROM chio_pheromone_relay_outbox WHERE status IN ('pending', 'retry', 'leased')",
        [],
        |row| row.get(0),
    )?;
    queued
        .map(|value| u64_from_i64(value, "queued_at_unix_ms"))
        .transpose()
}

fn u64_from_i64(value: i64, field: &str) -> Result<u64, PheromoneRelayError> {
    u64::try_from(value).map_err(|_| PheromoneRelayError::Sqlite(format!("{field} is negative")))
}
