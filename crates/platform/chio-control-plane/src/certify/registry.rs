use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::CliError;

use super::helpers::{ensure_parent_dir, unix_now};
use super::schema::{
    is_supported_certification_registry_version, CERTIFICATION_PUBLIC_SEARCH_SCHEMA,
    CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA, CERTIFICATION_REGISTRY_VERSION,
};
use super::types::{
    CertificationDisputeRecord, CertificationDisputeRequest, CertificationDisputeState,
    CertificationPublicPublisher, CertificationPublicSearchQuery,
    CertificationPublicSearchResponse, CertificationPublicSearchResult, CertificationRegistry,
    CertificationRegistryEntry, CertificationRegistryState, CertificationResolutionResponse,
    CertificationResolutionState, CertificationTransparencyEvent,
    CertificationTransparencyEventKind, CertificationTransparencyQuery,
    CertificationTransparencyResponse, SignedCertificationCheck,
};
use super::verify::{
    certification_artifact_id, verify_certification_registry_entry,
    verify_signed_certification_check,
};

impl Default for CertificationRegistry {
    fn default() -> Self {
        Self {
            version: CERTIFICATION_REGISTRY_VERSION.to_string(),
            artifacts: BTreeMap::new(),
        }
    }
}

impl CertificationRegistry {
    pub(crate) fn load(path: &Path) -> Result<Self, CliError> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut registry: Self = serde_json::from_slice(&bytes)?;
                if !is_supported_certification_registry_version(&registry.version) {
                    return Err(CliError::attest_error(format!(
                        "unsupported certification registry version: {}",
                        registry.version
                    )));
                }
                registry.version = CERTIFICATION_REGISTRY_VERSION.to_string();
                for entry in registry.artifacts.values() {
                    verify_certification_registry_entry(entry)?;
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(CliError::Io(error)),
        }
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), CliError> {
        ensure_parent_dir(path)?;
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub(crate) fn get(&self, artifact_id: &str) -> Option<&CertificationRegistryEntry> {
        self.artifacts.get(artifact_id)
    }

    pub(crate) fn publish(
        &mut self,
        artifact: SignedCertificationCheck,
    ) -> Result<CertificationRegistryEntry, CliError> {
        verify_signed_certification_check(&artifact)?;
        self.version = CERTIFICATION_REGISTRY_VERSION.to_string();
        let artifact_id = certification_artifact_id(&artifact)?;
        if let Some(existing) = self.artifacts.get(&artifact_id) {
            return Ok(existing.clone());
        }

        let published_at = unix_now();
        for existing in self.artifacts.values_mut() {
            if existing.tool_server_id == artifact.body.target.tool_server_id
                && existing.status == CertificationRegistryState::Active
            {
                existing.status = CertificationRegistryState::Superseded;
                existing.superseded_at = Some(published_at);
                existing.superseded_by = Some(artifact_id.clone());
            }
        }

        let entry = CertificationRegistryEntry {
            artifact_sha256: artifact_id.clone(),
            artifact_id: artifact_id.clone(),
            tool_server_id: artifact.body.target.tool_server_id.clone(),
            tool_server_name: artifact.body.target.tool_server_name.clone(),
            verdict: artifact.body.verdict,
            checked_at: artifact.body.checked_at,
            published_at,
            status: CertificationRegistryState::Active,
            superseded_at: None,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            dispute: None,
            artifact,
        };
        self.artifacts.insert(artifact_id, entry.clone());
        Ok(entry)
    }

    pub(crate) fn resolve(&self, tool_server_id: &str) -> CertificationResolutionResponse {
        let mut matches = self
            .artifacts
            .values()
            .filter(|entry| entry.tool_server_id == tool_server_id)
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.published_at
                .cmp(&right.published_at)
                .then(left.checked_at.cmp(&right.checked_at))
                .then(left.artifact_id.cmp(&right.artifact_id))
        });
        let total_entries = matches.len();
        let current = matches
            .iter()
            .rev()
            .find(|entry| entry.status == CertificationRegistryState::Active)
            .cloned()
            .or_else(|| {
                matches
                    .iter()
                    .rev()
                    .filter(|entry| entry.status == CertificationRegistryState::Revoked)
                    .max_by(|left, right| {
                        left.revoked_at
                            .cmp(&right.revoked_at)
                            .then(left.published_at.cmp(&right.published_at))
                            .then(left.checked_at.cmp(&right.checked_at))
                    })
                    .cloned()
            })
            .or_else(|| matches.last().cloned());
        let state = match current.as_ref().map(|entry| entry.status) {
            Some(CertificationRegistryState::Active) => CertificationResolutionState::Active,
            Some(CertificationRegistryState::Superseded) => {
                CertificationResolutionState::Superseded
            }
            Some(CertificationRegistryState::Revoked) => CertificationResolutionState::Revoked,
            None => CertificationResolutionState::NotFound,
        };
        CertificationResolutionResponse {
            tool_server_id: tool_server_id.to_string(),
            state,
            total_entries,
            current,
        }
    }

    pub(crate) fn revoke(
        &mut self,
        artifact_id: &str,
        reason: Option<&str>,
        revoked_at: Option<u64>,
    ) -> Result<CertificationRegistryEntry, CliError> {
        let Some(entry) = self.artifacts.get_mut(artifact_id) else {
            return Err(CliError::attest_error(format!(
                "certification artifact `{artifact_id}` was not found"
            )));
        };
        entry.status = CertificationRegistryState::Revoked;
        entry.revoked_at = Some(revoked_at.unwrap_or_else(unix_now));
        entry.revoked_reason = reason.map(str::to_string);
        Ok(entry.clone())
    }

    pub(crate) fn dispute(
        &mut self,
        artifact_id: &str,
        request: &CertificationDisputeRequest,
    ) -> Result<CertificationRegistryEntry, CliError> {
        let Some(entry) = self.artifacts.get_mut(artifact_id) else {
            return Err(CliError::attest_error(format!(
                "certification artifact `{artifact_id}` was not found"
            )));
        };
        let updated_at = request.updated_at.unwrap_or_else(unix_now);
        let dispute = CertificationDisputeRecord {
            state: request.state,
            updated_at,
            note: request.note.clone(),
        };
        if request.state == CertificationDisputeState::ResolvedRevoked {
            entry.status = CertificationRegistryState::Revoked;
            entry.revoked_at = Some(updated_at);
            if entry.revoked_reason.is_none() {
                entry.revoked_reason = Some(
                    request
                        .note
                        .clone()
                        .unwrap_or_else(|| "dispute resolved as revoked".to_string()),
                );
            }
        }
        entry.dispute = Some(dispute);
        Ok(entry.clone())
    }

    pub(crate) fn search_public(
        &self,
        publisher: &CertificationPublicPublisher,
        metadata_expires_at: u64,
        query: &CertificationPublicSearchQuery,
    ) -> CertificationPublicSearchResponse {
        let mut results = self
            .artifacts
            .values()
            .filter(|entry| {
                query
                    .tool_server_id
                    .as_deref()
                    .is_none_or(|tool_server_id| entry.tool_server_id == tool_server_id)
            })
            .filter(|entry| {
                query
                    .criteria_profile
                    .as_deref()
                    .is_none_or(|criteria_profile| {
                        entry.artifact.body.criteria_profile == criteria_profile
                    })
            })
            .filter(|entry| {
                query
                    .evidence_profile
                    .as_deref()
                    .is_none_or(|evidence_profile| {
                        entry.artifact.body.evidence.evidence_profile == evidence_profile
                    })
            })
            .filter(|entry| query.status.is_none_or(|status| entry.status == status))
            .cloned()
            .map(|entry| CertificationPublicSearchResult {
                publisher: publisher.clone(),
                metadata_expires_at,
                entry,
            })
            .collect::<Vec<_>>();
        results.sort_by(|left, right| {
            left.entry
                .tool_server_id
                .cmp(&right.entry.tool_server_id)
                .then(right.entry.published_at.cmp(&left.entry.published_at))
                .then(right.entry.checked_at.cmp(&left.entry.checked_at))
                .then(left.entry.artifact_id.cmp(&right.entry.artifact_id))
        });
        CertificationPublicSearchResponse {
            schema: CERTIFICATION_PUBLIC_SEARCH_SCHEMA.to_string(),
            generated_at: unix_now(),
            peer_count: 1,
            reachable_count: 1,
            count: results.len(),
            results,
            errors: Vec::new(),
        }
    }

    pub(crate) fn transparency(
        &self,
        publisher: &CertificationPublicPublisher,
        query: &CertificationTransparencyQuery,
    ) -> CertificationTransparencyResponse {
        let mut events = Vec::new();
        for entry in self.artifacts.values() {
            if query
                .tool_server_id
                .as_deref()
                .is_some_and(|tool_server_id| entry.tool_server_id != tool_server_id)
            {
                continue;
            }
            events.push(CertificationTransparencyEvent {
                observed_at: entry.published_at,
                kind: CertificationTransparencyEventKind::Published,
                publisher: publisher.clone(),
                tool_server_id: entry.tool_server_id.clone(),
                artifact_id: entry.artifact_id.clone(),
                verdict: entry.verdict,
                status: entry.status,
                criteria_profile: entry.artifact.body.criteria_profile.clone(),
                evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                superseded_by: entry.superseded_by.clone(),
                revoked_reason: entry.revoked_reason.clone(),
                dispute: entry.dispute.clone(),
            });
            if let Some(superseded_at) = entry.superseded_at {
                events.push(CertificationTransparencyEvent {
                    observed_at: superseded_at,
                    kind: CertificationTransparencyEventKind::Superseded,
                    publisher: publisher.clone(),
                    tool_server_id: entry.tool_server_id.clone(),
                    artifact_id: entry.artifact_id.clone(),
                    verdict: entry.verdict,
                    status: entry.status,
                    criteria_profile: entry.artifact.body.criteria_profile.clone(),
                    evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                    superseded_by: entry.superseded_by.clone(),
                    revoked_reason: entry.revoked_reason.clone(),
                    dispute: entry.dispute.clone(),
                });
            }
            if let Some(revoked_at) = entry.revoked_at {
                events.push(CertificationTransparencyEvent {
                    observed_at: revoked_at,
                    kind: CertificationTransparencyEventKind::Revoked,
                    publisher: publisher.clone(),
                    tool_server_id: entry.tool_server_id.clone(),
                    artifact_id: entry.artifact_id.clone(),
                    verdict: entry.verdict,
                    status: entry.status,
                    criteria_profile: entry.artifact.body.criteria_profile.clone(),
                    evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                    superseded_by: entry.superseded_by.clone(),
                    revoked_reason: entry.revoked_reason.clone(),
                    dispute: entry.dispute.clone(),
                });
            }
            if let Some(dispute) = entry.dispute.clone() {
                let kind = match dispute.state {
                    CertificationDisputeState::Open => {
                        CertificationTransparencyEventKind::DisputeOpened
                    }
                    CertificationDisputeState::UnderReview => {
                        CertificationTransparencyEventKind::DisputeUnderReview
                    }
                    CertificationDisputeState::ResolvedNoChange => {
                        CertificationTransparencyEventKind::DisputeResolvedNoChange
                    }
                    CertificationDisputeState::ResolvedRevoked => {
                        CertificationTransparencyEventKind::DisputeResolvedRevoked
                    }
                };
                events.push(CertificationTransparencyEvent {
                    observed_at: dispute.updated_at,
                    kind,
                    publisher: publisher.clone(),
                    tool_server_id: entry.tool_server_id.clone(),
                    artifact_id: entry.artifact_id.clone(),
                    verdict: entry.verdict,
                    status: entry.status,
                    criteria_profile: entry.artifact.body.criteria_profile.clone(),
                    evidence_profile: entry.artifact.body.evidence.evidence_profile.clone(),
                    superseded_by: entry.superseded_by.clone(),
                    revoked_reason: entry.revoked_reason.clone(),
                    dispute: Some(dispute),
                });
            }
        }
        events.sort_by(|left, right| {
            left.observed_at
                .cmp(&right.observed_at)
                .then(left.artifact_id.cmp(&right.artifact_id))
        });
        CertificationTransparencyResponse {
            schema: CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA.to_string(),
            generated_at: unix_now(),
            peer_count: 1,
            reachable_count: 1,
            count: events.len(),
            events,
            errors: Vec::new(),
        }
    }
}
