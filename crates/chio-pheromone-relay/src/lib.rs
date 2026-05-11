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
            profile: RelayProfile::LocalDev,
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
