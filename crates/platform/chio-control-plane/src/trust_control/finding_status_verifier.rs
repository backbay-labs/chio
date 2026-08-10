//! Shared cryptographic and durable verifier for portable finding status.
//!
//! The HTTP projection and kernel admission use this module rather than
//! independently trusting persisted index fields. Exact canonical signed
//! epoch and proof bytes are parsed and verified first. Purchase admission
//! accepts them only at the publisher's already-durable authoritative floor;
//! importing a point proof never advances that floor without the complete map.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_finding::{
    parse_signed_status_epoch, parse_status_proof_input, verify_signed_status_epoch,
    verify_status_proof_input, FindingAuthorityKeyPolicy, FindingStatusFreshnessPolicy,
    FindingStatusOperatorAuthorization, FindingStatusOperatorRole, FindingStatusProofInput,
    SignedFindingStatusEpoch,
};
use chio_kernel::finding_purchase::{
    FindingStatusProofContextView, FindingStatusProofVerifier, VerifiedFindingStatusProof,
};
use chio_store_sqlite::{
    FindingStatusDecision, FindingStatusEpochRecord, FindingStatusProofKind,
    FindingStatusProofRecord, FindingStatusStoreError, FindingStickyStatus,
    SqliteFindingStatusStore, VerifiedFindingStatusProofInput,
};

use super::{
    FindingStatusOperatorPin, FindingStatusServiceBond, FINDING_STATUS_MAX_EPOCH_AGE_SECS,
};

struct PortableStatusMaterial {
    proof: FindingStatusProofInput,
    proof_bytes: Vec<u8>,
    signed_epoch: SignedFindingStatusEpoch,
    signed_epoch_bytes: Vec<u8>,
    verified: VerifiedFindingStatusProof,
}

struct ProofFields<'a> {
    feed_id: &'a str,
    key_domain_nonce: u64,
    map_epoch: u64,
    finding_id: &'a str,
    status_epoch_id: &'a str,
    status_epoch_sha256: &'a str,
    signed_status_epoch_b64: &'a str,
    root_hash: &'a str,
    checked_at: u64,
    kind: FindingStatusProofKind,
}

fn proof_fields(proof: &FindingStatusProofInput) -> ProofFields<'_> {
    match proof {
        FindingStatusProofInput::NonInclusion(value) => ProofFields {
            feed_id: &value.feed_id,
            key_domain_nonce: value.key_domain_nonce,
            map_epoch: value.map_epoch,
            finding_id: &value.finding_id,
            status_epoch_id: &value.status_epoch_id,
            status_epoch_sha256: &value.status_epoch_sha256,
            signed_status_epoch_b64: &value.signed_status_epoch_b64,
            root_hash: &value.root_hash,
            checked_at: value.checked_at,
            kind: FindingStatusProofKind::NonInclusion,
        },
        FindingStatusProofInput::Inclusion(value) => ProofFields {
            feed_id: &value.feed_id,
            key_domain_nonce: value.key_domain_nonce,
            map_epoch: value.map_epoch,
            finding_id: &value.finding_id,
            status_epoch_id: &value.status_epoch_id,
            status_epoch_sha256: &value.status_epoch_sha256,
            signed_status_epoch_b64: &value.signed_status_epoch_b64,
            root_hash: &value.root_hash,
            checked_at: value.checked_at,
            kind: FindingStatusProofKind::Inclusion,
        },
    }
}

pub(crate) fn authorization(
    operator: &FindingStatusOperatorPin,
) -> Result<FindingStatusOperatorAuthorization, String> {
    let key = operator
        .authority
        .key()
        .map_err(|error| error.to_string())?;
    Ok(FindingStatusOperatorAuthorization {
        role: FindingStatusOperatorRole::FindingStatusOperator,
        feed_id: operator.feed_id.clone(),
        operator: FindingAuthorityKeyPolicy {
            authority_id: operator.authority.authority_id.clone(),
            key,
            key_epoch: operator.authority.key_epoch,
            valid_from: operator.authority.valid_from,
            valid_until: operator.authority.valid_until,
            rotation_policy_ref: operator.rotation_policy_ref.clone(),
            revocation_status_ref: operator.authority.revocation_status_ref.clone(),
        },
        revoked_from: operator.revoked_from,
    })
}

fn require_live_operator_and_bond(
    operator: &FindingStatusOperatorPin,
    bond: &FindingStatusServiceBond,
    feed_id: &str,
    now: u64,
) -> Result<(), String> {
    operator
        .require_live(feed_id, now)
        .map_err(|error| error.to_string())?;
    if !bond.covers(now)
        || bond.feed_id != feed_id
        || bond.operator_id != operator.authority.authority_id
    {
        return Err("finding status operator service bond is missing or expired".to_owned());
    }
    Ok(())
}

fn verify_epoch_freshness(
    epoch: &SignedFindingStatusEpoch,
    now: u64,
    max_epoch_age_secs: u64,
) -> Result<(), String> {
    if now == 0 || max_epoch_age_secs == 0 {
        return Err("finding status freshness policy is invalid".to_owned());
    }
    if now < epoch.body.generated_at
        || now < epoch.body.valid_from
        || now >= epoch.body.valid_until
        || now.saturating_sub(epoch.body.generated_at) > max_epoch_age_secs
    {
        return Err("finding status epoch is stale or not yet valid".to_owned());
    }
    Ok(())
}

fn verify_portable_at(
    operator: &FindingStatusOperatorPin,
    bond: &FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    view: &FindingStatusProofContextView<'_>,
    now: u64,
    require_non_inclusion: bool,
) -> Result<PortableStatusMaterial, String> {
    require_live_operator_and_bond(operator, bond, &operator.feed_id, now)?;
    let proof_bytes = STANDARD
        .decode(view.proof_b64)
        .map_err(|_| "finding status proof carrier is not valid base64".to_owned())?;
    let proof = parse_status_proof_input(&proof_bytes).map_err(|error| error.to_string())?;
    let fields = proof_fields(&proof);
    if fields.finding_id != view.expected_finding_id {
        return Err("finding status proof binds a different finding".to_owned());
    }
    if fields.feed_id != view.expected_feed_id {
        return Err("finding status proof binds a different feed".to_owned());
    }
    if fields.map_epoch == 0 {
        return Err("finding status proof map epoch must be nonzero".to_owned());
    }
    let authorization = authorization(operator)?;
    let signed_epoch = verify_status_proof_input(
        &proof,
        &authorization,
        FindingStatusFreshnessPolicy {
            now,
            max_epoch_age_secs,
        },
    )
    .map_err(|error| error.to_string())?;
    if require_non_inclusion && fields.kind != FindingStatusProofKind::NonInclusion {
        return Err("finding is retracted by the verified status feed".to_owned());
    }
    let signed_epoch_bytes = STANDARD
        .decode(fields.signed_status_epoch_b64)
        .map_err(|_| "embedded signed status epoch is not valid base64".to_owned())?;
    let parsed_epoch =
        parse_signed_status_epoch(&signed_epoch_bytes).map_err(|error| error.to_string())?;
    if parsed_epoch != signed_epoch {
        return Err("embedded signed status epoch changed after verification".to_owned());
    }
    let verified = VerifiedFindingStatusProof {
        feed_id: fields.feed_id.to_owned(),
        key_domain_nonce: fields.key_domain_nonce,
        map_epoch: fields.map_epoch,
        status_epoch_id: fields.status_epoch_id.to_owned(),
        status_epoch_artifact_sha256: fields.status_epoch_sha256.to_owned(),
        proof_sha256: chio_core::sha256_hex(&proof_bytes),
        root_hash: fields.root_hash.to_owned(),
        non_inclusion_checked_at: fields.checked_at,
    };
    Ok(PortableStatusMaterial {
        proof,
        proof_bytes,
        signed_epoch,
        signed_epoch_bytes,
        verified,
    })
}

/// Production kernel verifier over the governance pin and durable feed store.
#[derive(Clone)]
pub struct MarketFindingStatusVerifier {
    operator: FindingStatusOperatorPin,
    service_bond: FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    store: SqliteFindingStatusStore,
}

impl MarketFindingStatusVerifier {
    /// Construct the M6 verifier. Invalid or missing freshness configuration
    /// is rejected at installation rather than at first purchase.
    pub fn new(
        operator: FindingStatusOperatorPin,
        service_bond: FindingStatusServiceBond,
        max_epoch_age_secs: u64,
        store: SqliteFindingStatusStore,
    ) -> Result<Self, String> {
        if max_epoch_age_secs == 0 || max_epoch_age_secs > FINDING_STATUS_MAX_EPOCH_AGE_SECS {
            return Err(
                "finding status max epoch age must be a positive I-JSON safe integer".to_owned(),
            );
        }
        authorization(&operator)?
            .validate()
            .map_err(|error| error.to_string())?;
        service_bond
            .validate(&operator)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            operator,
            service_bond,
            max_epoch_age_secs,
            store,
        })
    }

    fn verify_at(
        &self,
        view: &FindingStatusProofContextView<'_>,
        now: u64,
    ) -> Result<PortableStatusMaterial, String> {
        verify_portable_at(
            &self.operator,
            &self.service_bond,
            self.max_epoch_age_secs,
            view,
            now,
            true,
        )
    }
}

impl FindingStatusProofVerifier for MarketFindingStatusVerifier {
    fn verify_status_proof(
        &self,
        view: &FindingStatusProofContextView<'_>,
    ) -> Result<VerifiedFindingStatusProof, String> {
        let proof_bytes = STANDARD
            .decode(view.proof_b64)
            .map_err(|_| "finding status proof carrier is not valid base64".to_owned())?;
        let proof = parse_status_proof_input(&proof_bytes).map_err(|error| error.to_string())?;
        let checked_at = proof_fields(&proof).checked_at;
        Ok(self.verify_at(view, checked_at)?.verified)
    }

    fn verify_status_admission(
        &self,
        view: &FindingStatusProofContextView<'_>,
        verified: &VerifiedFindingStatusProof,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        let material = self.verify_at(view, now_unix_secs)?;
        if &material.verified != verified {
            return Err("finding status proof changed between verification phases".to_owned());
        }
        let fields = proof_fields(&material.proof);
        let epoch = &material.signed_epoch.body;
        match self
            .store
            .get_finding_status(fields.feed_id, fields.finding_id)
        {
            Ok(Some(status)) if status.state == FindingStickyStatus::Pending => {
                return Err("finding retraction publication is pending".to_owned());
            }
            Ok(_) | Err(FindingStatusStoreError::MissingFloor { .. }) => {}
            Err(error) => return Err(error.to_string()),
        }
        let current_epoch = self
            .store
            .get_current_epoch(fields.feed_id)
            .map_err(|error| error.to_string())?;
        verify_epoch_record(
            &self.operator,
            &self.service_bond,
            self.max_epoch_age_secs,
            &current_epoch,
            now_unix_secs,
        )?;
        if current_epoch.map_epoch > fields.map_epoch {
            return Err(
                "finding status proof is a rollback from the authoritative publisher floor"
                    .to_owned(),
            );
        }
        if current_epoch.map_epoch < fields.map_epoch {
            return Err(
                "finding status proof does not bind the authoritative publisher floor".to_owned(),
            );
        }
        if current_epoch.signed_epoch_bytes != material.signed_epoch_bytes {
            return Err(
                "finding status proof equivocates at the authoritative publisher floor".to_owned(),
            );
        }
        self.store
            .observe_verified_non_inclusion(&VerifiedFindingStatusProofInput {
                feed_id: fields.feed_id,
                operator_id: &epoch.operator_id,
                key_domain_nonce: fields.key_domain_nonce,
                map_epoch: fields.map_epoch,
                epoch_id: fields.status_epoch_id,
                root_hash: fields.root_hash,
                finding_id: fields.finding_id,
                kind: FindingStatusProofKind::NonInclusion,
                proof_bytes: &material.proof_bytes,
                status_value_bytes: None,
                retraction_intent_sha256: None,
                checked_at: fields.checked_at,
                valid_until: epoch.valid_until,
                recorded_at: now_unix_secs,
            })
            .map_err(|error| error.to_string())?;
        match self
            .store
            .status_for_purchase(fields.feed_id, fields.finding_id, now_unix_secs)
            .map_err(|error| error.to_string())?
        {
            FindingStatusDecision::VerifiedLive(record)
                if record.proof_sha256 == verified.proof_sha256
                    && record.map_epoch == verified.map_epoch
                    && record.epoch_id == verified.status_epoch_id
                    && record.root_hash == verified.root_hash =>
            {
                Ok(())
            }
            FindingStatusDecision::VerifiedLive(_) => {
                Err("durable finding status evidence differs from the verified proof".to_owned())
            }
            FindingStatusDecision::Pending(_) => {
                Err("finding retraction publication is pending".to_owned())
            }
            FindingStatusDecision::Retracted(_) => Err("finding is retracted".to_owned()),
        }
    }
}

/// Cryptographically re-verify one retained root before projecting it.
pub(crate) fn verify_epoch_record(
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    record: &FindingStatusEpochRecord,
    now: u64,
) -> Result<(), String> {
    require_live_operator_and_bond(operator, service_bond, &record.feed_id, now)?;
    let signed =
        parse_signed_status_epoch(&record.signed_epoch_bytes).map_err(|error| error.to_string())?;
    verify_signed_status_epoch(&signed, &authorization(operator)?)
        .map_err(|error| error.to_string())?;
    verify_epoch_freshness(&signed, now, max_epoch_age_secs)?;
    let body = &signed.body;
    if record.feed_id != body.feed_id
        || record.operator_id != body.operator_id
        || record.key_domain_nonce != body.key_domain_nonce
        || record.map_epoch != body.map_epoch
        || record.epoch_id != body.status_epoch_id
        || record.root_hash != body.root_hash
        || record.signed_epoch_sha256 != chio_core::sha256_hex(&record.signed_epoch_bytes)
        || record.operator_key != body.operator_key.to_hex()
        || record.operator_key_epoch != body.operator_key_epoch
        || record.operator_authorization_sha256 != operator.authorization_sha256
        || record.generated_at != body.generated_at
        || record.valid_until != body.valid_until
    {
        return Err("durable finding status epoch fields do not match its signed bytes".to_owned());
    }
    Ok(())
}

/// Cryptographically re-verify one retained portable proof before serving it.
pub(crate) fn verify_proof_record(
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    record: &FindingStatusProofRecord,
    now: u64,
) -> Result<(), String> {
    let proof_b64 = STANDARD.encode(&record.proof_bytes);
    let material = verify_portable_at(
        operator,
        service_bond,
        max_epoch_age_secs,
        &FindingStatusProofContextView {
            proof_b64: &proof_b64,
            expected_finding_id: &record.finding_id,
            expected_feed_id: &record.feed_id,
        },
        now,
        false,
    )?;
    let fields = proof_fields(&material.proof);
    let inclusion_fields_match = match &material.proof {
        FindingStatusProofInput::NonInclusion(_) => {
            record.status_value_bytes.is_none() && record.retraction_intent_sha256.is_none()
        }
        FindingStatusProofInput::Inclusion(value) => {
            record.status_value_bytes.as_deref() == Some(b"retracted".as_slice())
                && record.retraction_intent_sha256.as_deref()
                    == Some(value.retraction_intent_sha256.as_str())
        }
    };
    if record.kind != fields.kind
        || record.feed_id != fields.feed_id
        || record.operator_id != material.signed_epoch.body.operator_id
        || record.key_domain_nonce != fields.key_domain_nonce
        || record.map_epoch != fields.map_epoch
        || record.epoch_id != fields.status_epoch_id
        || record.root_hash != fields.root_hash
        || record.finding_id != fields.finding_id
        || record.proof_sha256 != material.verified.proof_sha256
        || record.checked_at != fields.checked_at
        || record.valid_until != material.signed_epoch.body.valid_until
        || record.signed_epoch_sha256 != material.verified.status_epoch_artifact_sha256
        || record.signed_epoch_bytes != material.signed_epoch_bytes
        || !inclusion_fields_match
    {
        return Err(
            "durable finding status proof fields do not match its verified bytes".to_owned(),
        );
    }
    Ok(())
}
