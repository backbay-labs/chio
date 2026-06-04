use crate::{
    canonical_sha256, validate_endpoint, validate_peer_directory_profile, PheromoneRelayError,
    PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA, PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA,
    PHEROMONE_PEER_DIRECTORY_SCHEMA, PHEROMONE_PEER_DIRECTORY_STATE_SCHEMA,
};
use chio_core_types::Keypair;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

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
        let local_kernel_id = document.local_kernel_id.trim();
        if local_kernel_id.is_empty() || local_kernel_id != document.local_kernel_id {
            return Err(PheromoneRelayError::PeerDirectoryStale(
                "local kernel id is empty or padded".to_string(),
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
            let peer_kernel_id = peer.kernel_id.trim();
            if peer_kernel_id.is_empty() || peer_kernel_id != peer.kernel_id {
                return Err(PheromoneRelayError::UnknownPeer(
                    "peer kernel id is empty or padded".to_string(),
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

pub(crate) fn record_rejected_candidate(
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

pub(crate) fn removed_peer_ids(
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
