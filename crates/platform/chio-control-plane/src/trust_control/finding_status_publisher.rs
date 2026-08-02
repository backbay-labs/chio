//! Operator-side status epoch publisher used by the external M6 cron.
//!
//! The workspace has no job daemon. Deployments invoke this component from
//! their scheduler after the durable outbox reports an eligible intent, or to
//! mint a fresh non-inclusion proof for an admitted purchase. The component
//! rebuilds the sparse map from sticky leaves, signs one advancing epoch, then
//! atomically persists the exact epoch, proof, and any new retracted leaf.

use chio_core::crypto::Keypair;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    build_status_inclusion_proof_input, build_status_non_inclusion_proof_input,
    compute_status_epoch_id, verify_status_proof_input, FindingStatusEpoch,
    FindingStatusFreshnessPolicy, FINDING_STATUS_EPOCH_SCHEMA_V1, FINDING_STATUS_SIGNATURE_DOMAIN,
};
use chio_revocation_oracle::{
    finding_status_empty_leaf_hash, FindingStatusSparseMap, FINDING_STATUS_BRANCH_DOMAIN,
    FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
};
use chio_store_sqlite::{
    FindingRetractionIntentState, FindingStatusEpochAdvance, FindingStatusProofKind,
    FindingStatusProofRecord, FindingStatusStoreError, SqliteFindingStatusStore,
    VerifiedFindingStatusEpochInput, VerifiedFindingStatusProofInput,
};

use super::finding_status_verifier::authorization;
use super::{FindingStatusOperatorPin, FindingStatusServiceBond};

/// External-cron status publisher with the operator signing key.
pub struct FindingStatusEpochPublisher {
    store: SqliteFindingStatusStore,
    operator: FindingStatusOperatorPin,
    service_bond: FindingStatusServiceBond,
    operator_keypair: Keypair,
    max_epoch_age_secs: u64,
}

impl FindingStatusEpochPublisher {
    /// Construct only when the private key matches the governance pin.
    pub fn new(
        store: SqliteFindingStatusStore,
        operator: FindingStatusOperatorPin,
        service_bond: FindingStatusServiceBond,
        operator_keypair: Keypair,
        max_epoch_age_secs: u64,
    ) -> Result<Self, String> {
        authorization(&operator)?
            .validate()
            .map_err(|error| error.to_string())?;
        if max_epoch_age_secs == 0
            || operator_keypair.public_key()
                != operator.authority.key().map_err(|e| e.to_string())?
            || service_bond.feed_id != operator.feed_id
            || service_bond.operator_id != operator.authority.authority_id
        {
            return Err("finding status publisher configuration is not authorized".to_owned());
        }
        Ok(Self {
            store,
            operator,
            service_bond,
            operator_keypair,
            max_epoch_age_secs,
        })
    }

    fn require_live(&self, now: u64) -> Result<u64, String> {
        self.operator
            .require_live(&self.operator.feed_id, now)
            .map_err(|error| error.to_string())?;
        if !self.service_bond.covers(now) {
            return Err("finding status publisher service bond is expired".to_owned());
        }
        let configured_until = now
            .checked_add(self.max_epoch_age_secs)
            .ok_or_else(|| "finding status epoch validity overflowed".to_owned())?;
        let valid_until = configured_until
            .min(self.operator.authority.valid_until)
            .min(self.service_bond.valid_until);
        if valid_until <= now {
            return Err("finding status publisher has no live validity window".to_owned());
        }
        Ok(valid_until)
    }

    fn rebuild_map(&self) -> Result<FindingStatusSparseMap, String> {
        let mut map = FindingStatusSparseMap::new();
        let leaves = match self.store.list_leaves(&self.operator.feed_id) {
            Ok(leaves) => leaves,
            Err(FindingStatusStoreError::MissingFloor { .. }) => Vec::new(),
            Err(error) => return Err(error.to_string()),
        };
        for leaf in leaves {
            map.insert(&leaf.finding_id, &leaf.retraction_intent_sha256)
                .map_err(|error| error.to_string())?;
        }
        Ok(map)
    }

    fn next_map_epoch(&self) -> Result<u64, String> {
        match self.store.get_feed_floor(&self.operator.feed_id) {
            Ok(floor) => floor
                .map_epoch
                .checked_add(1)
                .ok_or_else(|| "finding status map epoch overflowed".to_owned()),
            Err(FindingStatusStoreError::MissingFloor { .. }) => Ok(1),
            Err(error) => Err(error.to_string()),
        }
    }

    fn sign_epoch(
        &self,
        map: &FindingStatusSparseMap,
        map_epoch: u64,
        anchor_refs: &[String],
        now: u64,
    ) -> Result<chio_finding::SignedFindingStatusEpoch, String> {
        let valid_until = self.require_live(now)?;
        let mut body = FindingStatusEpoch {
            schema: FINDING_STATUS_EPOCH_SCHEMA_V1.to_owned(),
            status_epoch_id: String::new(),
            signature_domain: FINDING_STATUS_SIGNATURE_DOMAIN.to_owned(),
            status_map_version: FINDING_STATUS_MAP_VERSION.to_owned(),
            proof_semantics: FINDING_STATUS_PROOF_SEMANTICS.to_owned(),
            feed_id: self.operator.feed_id.clone(),
            key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
            map_epoch,
            operator_id: self.operator.authority.authority_id.clone(),
            operator_key: self.operator_keypair.public_key(),
            operator_key_epoch: self.operator.authority.key_epoch,
            root_hash: hex::encode(map.root().root_hash),
            tree_depth: FINDING_STATUS_SPARSE_DEPTH as u16,
            hash_algorithm: FINDING_STATUS_HASH_ALGORITHM.to_owned(),
            key_hash_domain: FINDING_STATUS_KEY_HASH_DOMAIN.to_owned(),
            empty_leaf_domain: FINDING_STATUS_EMPTY_LEAF_DOMAIN.to_owned(),
            occupied_leaf_domain: FINDING_STATUS_OCCUPIED_LEAF_DOMAIN.to_owned(),
            branch_domain: FINDING_STATUS_BRANCH_DOMAIN.to_owned(),
            empty_leaf_hash: hex::encode(finding_status_empty_leaf_hash()),
            anchor_refs: anchor_refs.to_vec(),
            generated_at: now,
            valid_from: now,
            valid_until,
        };
        body.status_epoch_id = compute_status_epoch_id(&body).map_err(|error| error.to_string())?;
        SignedExportEnvelope::sign(body, &self.operator_keypair).map_err(|error| error.to_string())
    }

    /// Reuse the current signed map for point proofs while it remains live.
    /// A point lookup must not advance the feed floor and thereby evict every
    /// other proof over an unchanged root.
    fn current_epoch_for_point_proof(
        &self,
        map: &FindingStatusSparseMap,
        anchor_refs: &[String],
        now: u64,
    ) -> Result<Option<chio_finding::SignedFindingStatusEpoch>, String> {
        let record = match self.store.get_current_epoch(&self.operator.feed_id) {
            Ok(record) => record,
            Err(FindingStatusStoreError::MissingFloor { .. }) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let signed = chio_finding::parse_signed_status_epoch(&record.signed_epoch_bytes)
            .map_err(|error| error.to_string())?;
        signed.body.validate().map_err(|error| error.to_string())?;
        if signed.signer_key != signed.body.operator_key
            || !signed
                .verify_signature()
                .map_err(|error| error.to_string())?
        {
            return Err("current finding status epoch signature is invalid".to_owned());
        }
        if signed.body.root_hash != hex::encode(map.root().root_hash)
            || signed.body.map_epoch != record.map_epoch
            || signed.body.status_epoch_id != record.epoch_id
            || signed.body.feed_id != record.feed_id
            || signed.body.operator_id != record.operator_id
            || signed.body.key_domain_nonce != record.key_domain_nonce
            || signed.body.operator_key.to_hex() != record.operator_key
            || signed.body.operator_key_epoch != record.operator_key_epoch
        {
            return Err(
                "current finding status epoch does not match the durable sparse map".to_owned(),
            );
        }
        let current_authorization = authorization(&self.operator)?;
        if signed.body.operator_key_epoch < current_authorization.operator.key_epoch
            && signed.body.operator_id == current_authorization.operator.authority_id
        {
            // The store already authenticated this self-consistent epoch under
            // the prior authorization before advancing its durable floor. It
            // cannot be served under a rotated key pin, but it is a valid
            // predecessor: advance the map epoch and sign a replacement.
            return Ok(None);
        }
        chio_finding::verify_signed_status_epoch(&signed, &current_authorization)
            .map_err(|error| error.to_string())?;
        if !anchor_refs.is_empty() && signed.body.anchor_refs != anchor_refs {
            return Err(
                "point proof anchor references do not match the current signed epoch".to_owned(),
            );
        }
        if now < signed.body.valid_from || now < signed.body.generated_at {
            return Err("finding status publisher clock precedes the current epoch".to_owned());
        }
        let age = now - signed.body.generated_at;
        if now >= signed.body.valid_until || age > self.max_epoch_age_secs {
            return Ok(None);
        }
        Ok(Some(signed))
    }

    fn current_proof(
        &self,
        finding_id: &str,
        map_epoch: u64,
        kind: FindingStatusProofKind,
    ) -> Result<Option<FindingStatusProofRecord>, String> {
        match self
            .store
            .get_latest_proof(&self.operator.feed_id, finding_id)
        {
            Ok(Some(proof)) if proof.map_epoch == map_epoch && proof.kind == kind => {
                Ok(Some(proof))
            }
            Ok(_) | Err(FindingStatusStoreError::MissingFloor { .. }) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn persist_point_proof(
        &self,
        signed: &chio_finding::SignedFindingStatusEpoch,
        finding_id: &str,
        kind: FindingStatusProofKind,
        proof_bytes: &[u8],
        retraction_intent_sha256: Option<&str>,
        now: u64,
    ) -> Result<FindingStatusProofRecord, String> {
        let epoch_bytes = chio_core::canonical_json_bytes(signed).map_err(|e| e.to_string())?;
        let operator_key = signed.body.operator_key.to_hex();
        let status_value_bytes =
            (kind == FindingStatusProofKind::Inclusion).then_some(b"retracted".as_slice());
        self.store
            .advance_epoch(&FindingStatusEpochAdvance {
                epoch: VerifiedFindingStatusEpochInput {
                    feed_id: &signed.body.feed_id,
                    operator_id: &signed.body.operator_id,
                    key_domain_nonce: signed.body.key_domain_nonce,
                    map_epoch: signed.body.map_epoch,
                    epoch_id: &signed.body.status_epoch_id,
                    root_hash: &signed.body.root_hash,
                    signed_epoch_bytes: &epoch_bytes,
                    operator_key: &operator_key,
                    operator_key_epoch: signed.body.operator_key_epoch,
                    operator_authorization_sha256: &self.operator.authorization_sha256,
                    generated_at: signed.body.generated_at,
                    valid_until: signed.body.valid_until,
                    recorded_at: now,
                },
                leaves: &[],
                proofs: &[VerifiedFindingStatusProofInput {
                    feed_id: &signed.body.feed_id,
                    operator_id: &signed.body.operator_id,
                    key_domain_nonce: signed.body.key_domain_nonce,
                    map_epoch: signed.body.map_epoch,
                    epoch_id: &signed.body.status_epoch_id,
                    root_hash: &signed.body.root_hash,
                    finding_id,
                    kind,
                    proof_bytes,
                    status_value_bytes,
                    retraction_intent_sha256,
                    checked_at: now,
                    valid_until: signed.body.valid_until,
                    recorded_at: now,
                }],
            })
            .map_err(|error| error.to_string())?;
        self.store
            .get_latest_proof(&signed.body.feed_id, finding_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "published finding status proof disappeared".to_owned())
    }

    /// Publish one dispatch-eligible local retraction exactly once.
    pub fn publish_retraction(
        &self,
        intent_id: &str,
        anchor_refs: &[String],
        now: u64,
    ) -> Result<FindingStatusProofRecord, String> {
        let intent = self
            .store
            .get_retraction_intent(intent_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "finding retraction intent is not durable".to_owned())?;
        if intent.state != FindingRetractionIntentState::DispatchEligible
            && intent.state != FindingRetractionIntentState::Published
        {
            return Err("finding retraction is not eligible for this publisher".to_owned());
        }
        if intent.feed_id != self.operator.feed_id
            || intent.operator_id != self.operator.authority.authority_id
        {
            return Err("finding retraction is not eligible for this publisher".to_owned());
        }
        let mut map = self.rebuild_map()?;
        if intent.state == FindingRetractionIntentState::DispatchEligible {
            map.insert(&intent.finding_id, &intent.intent_sha256)
                .map_err(|error| error.to_string())?;
        }
        let signed = if intent.state == FindingRetractionIntentState::Published {
            match self.current_epoch_for_point_proof(&map, anchor_refs, now)? {
                Some(signed) => signed,
                None => self.sign_epoch(&map, self.next_map_epoch()?, anchor_refs, now)?,
            }
        } else {
            self.sign_epoch(&map, self.next_map_epoch()?, anchor_refs, now)?
        };
        if let Some(proof) = self.current_proof(
            &intent.finding_id,
            signed.body.map_epoch,
            FindingStatusProofKind::Inclusion,
        )? {
            return Ok(proof);
        }
        let sparse = map
            .proof(&intent.finding_id)
            .map_err(|error| error.to_string())?;
        let proof = build_status_inclusion_proof_input(
            &signed,
            &intent.finding_id,
            &intent.intent_sha256,
            &sparse,
            now,
        )
        .map_err(|error| error.to_string())?;
        verify_status_proof_input(
            &proof,
            &authorization(&self.operator)?,
            FindingStatusFreshnessPolicy {
                now,
                max_epoch_age_secs: self.max_epoch_age_secs,
            },
        )
        .map_err(|error| error.to_string())?;
        let proof_bytes = chio_core::canonical_json_bytes(&proof).map_err(|e| e.to_string())?;
        self.persist_point_proof(
            &signed,
            &intent.finding_id,
            FindingStatusProofKind::Inclusion,
            &proof_bytes,
            Some(&intent.intent_sha256),
            now,
        )
    }

    /// Publish a fresh non-inclusion proof for one live finding. This reuses
    /// the current signed epoch while its unchanged map remains live, so a
    /// point lookup cannot invalidate proofs for other findings.
    pub fn publish_non_inclusion(
        &self,
        finding_id: &str,
        anchor_refs: &[String],
        now: u64,
    ) -> Result<FindingStatusProofRecord, String> {
        match self
            .store
            .get_finding_status(&self.operator.feed_id, finding_id)
        {
            Ok(Some(_)) => {
                return Err("pending or retracted finding cannot receive non-inclusion".to_owned());
            }
            Ok(None) | Err(FindingStatusStoreError::MissingFloor { .. }) => {}
            Err(error) => return Err(error.to_string()),
        }
        let map = self.rebuild_map()?;
        let signed = match self.current_epoch_for_point_proof(&map, anchor_refs, now)? {
            Some(signed) => signed,
            None => {
                let map_epoch = self.next_map_epoch()?;
                self.sign_epoch(&map, map_epoch, anchor_refs, now)?
            }
        };
        if let Some(proof) = self.current_proof(
            finding_id,
            signed.body.map_epoch,
            FindingStatusProofKind::NonInclusion,
        )? {
            return Ok(proof);
        }
        let sparse = map.proof(finding_id).map_err(|error| error.to_string())?;
        let proof = build_status_non_inclusion_proof_input(&signed, finding_id, &sparse, now)
            .map_err(|error| error.to_string())?;
        verify_status_proof_input(
            &proof,
            &authorization(&self.operator)?,
            FindingStatusFreshnessPolicy {
                now,
                max_epoch_age_secs: self.max_epoch_age_secs,
            },
        )
        .map_err(|error| error.to_string())?;
        let proof_bytes = chio_core::canonical_json_bytes(&proof).map_err(|e| e.to_string())?;
        self.persist_point_proof(
            &signed,
            finding_id,
            FindingStatusProofKind::NonInclusion,
            &proof_bytes,
            None,
            now,
        )
    }
}
