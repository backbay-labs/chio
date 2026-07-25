use std::collections::BTreeMap;

use chio_core::crypto::{Keypair, PublicKey};
use chio_credit::factor::{
    classify_assignment_not_applied, verify_assignment_acknowledgement,
    verify_assignment_agreement, verify_assignment_bind_authorization,
    verify_assignment_not_applied, verify_receivable_claim, AssignmentAcknowledgementBodyV1,
    AssignmentAcknowledgementInputV1, AssignmentAcknowledgementVerificationV1,
    AssignmentAgreementTrustV1, AssignmentAgreementVerificationV1,
    AssignmentBindAuthorizationTrustV1, AssignmentBindAuthorizationVerificationV1,
    AssignmentNotAppliedBodyV1, AssignmentNotAppliedClassificationV1, AssignmentNotAppliedInputV1,
    AssignmentNotAppliedReasonV1, AssignmentNotAppliedVerificationV1, AssignmentOfferV1,
    AssignmentResultAuthorityTrustV1, FactorError, NormalizedAssignmentRequestV1,
    ReceivableClaimTrustV1, ReceivableClaimV1, ReceivableClaimVerificationV1,
    SignedAssignmentAcknowledgementV1, SignedAssignmentAgreementV1,
    SignedAssignmentBindAuthorizationV1, SignedAssignmentNotAppliedV1,
    VerifiedAssignmentAcknowledgementV1, VerifiedAssignmentAuthorizationSetV1,
    VerifiedAssignmentNotAppliedV1, VerifiedReceivableClaimV1,
};
use chio_credit::obligation::{
    verify_obligation_status_proof, CreditAdmissionError, CreditAdmissionStore,
    CreditAdmissionStoreAdapter, CreditExposureReservationRecordV1, ObligationAssignmentCasInputV1,
    ObligationAssignmentCasV1, ObligationAssignmentOperationSnapshotV1, ObligationAtomV1,
    ObligationError, ObligationStatusProofTrustV1, ObligationStatusProofVerificationContextV1,
    SignedObligationStatusProofV1, VerifiedObligationStatusProofV1,
    OBLIGATION_ASSIGNMENT_CAS_SCHEMA,
};
use chio_kernel::admission_operation::{
    verified_factor_assignment_applied_projection,
    verified_factor_assignment_not_applied_projection,
};

use super::*;

const FACTOR_AUTHORITY_CONFIG_DIGEST_DOMAIN: &[u8] =
    b"chio.factor.assignment-authority-config.digest.v1\0";
const FACTOR_ACTIVE_AUTHORITY_SET_DIGEST_DOMAIN: &[u8] =
    b"chio.factor.active-assignment-authority-set.digest.v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FactorAssignmentAuthorityCoordinateV1 {
    bind_authority_id: String,
    bind_authority_key_epoch: u64,
    seller_id: String,
    seller_key_epoch: u64,
    buyer_id: String,
    buyer_key_epoch: u64,
    status_authority_id: String,
    status_authority_key_epoch: u64,
    result_authority_id: String,
    result_authority_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FactorAssignmentAuthorityConfigPreimageV1<'a> {
    coordinate: &'a FactorAssignmentAuthorityCoordinateV1,
    bind_authority_key: String,
    bind_max_lifetime_ms: u64,
    seller_key: String,
    buyer_key: String,
    status_authority_key: String,
    status_max_proof_lifetime_ms: u64,
    result_authority_key: String,
    claim_trust_configuration_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FactorActiveAuthoritySetPreimageV1<'a> {
    configuration_digests: &'a [String],
}

#[derive(Clone)]
pub struct FactorAssignmentVerificationAuthorityV1 {
    bind_authorization_trust: AssignmentBindAuthorizationTrustV1,
    agreement_trust: AssignmentAgreementTrustV1,
    status_proof_trust: ObligationStatusProofTrustV1,
    result_trust: AssignmentResultAuthorityTrustV1,
    result_authority_id: String,
    result_authority_key_epoch: u64,
    result_authority_key: PublicKey,
    claim_trust: ReceivableClaimTrustV1,
    coordinate: FactorAssignmentAuthorityCoordinateV1,
    configuration_digest: String,
}

impl FactorAssignmentVerificationAuthorityV1 {
    pub fn new(
        bind_authorization_trust: AssignmentBindAuthorizationTrustV1,
        agreement_trust: AssignmentAgreementTrustV1,
        status_proof_trust: ObligationStatusProofTrustV1,
        claim_trust: ReceivableClaimTrustV1,
        result_authority_id: String,
        result_authority_key_epoch: u64,
        result_authority_key: PublicKey,
    ) -> Result<Self, FactorError> {
        if status_proof_trust.authority_id() != result_authority_id
            || status_proof_trust.authority_key_epoch() != result_authority_key_epoch
            || status_proof_trust.authority_key() != &result_authority_key
        {
            return Err(FactorError::InvalidField("result_status_authority"));
        }
        let result_trust = AssignmentResultAuthorityTrustV1::new(
            result_authority_id.clone(),
            result_authority_key.clone(),
            result_authority_key_epoch,
        )?;
        let coordinate = FactorAssignmentAuthorityCoordinateV1 {
            bind_authority_id: bind_authorization_trust.authority_id().to_owned(),
            bind_authority_key_epoch: bind_authorization_trust.authority_key_epoch(),
            seller_id: agreement_trust.seller_id().to_owned(),
            seller_key_epoch: agreement_trust.seller_key_epoch(),
            buyer_id: agreement_trust.buyer_id().to_owned(),
            buyer_key_epoch: agreement_trust.buyer_key_epoch(),
            status_authority_id: status_proof_trust.authority_id().to_owned(),
            status_authority_key_epoch: status_proof_trust.authority_key_epoch(),
            result_authority_id: result_authority_id.clone(),
            result_authority_key_epoch,
        };
        let configuration_digest = factor_domain_digest(
            FACTOR_AUTHORITY_CONFIG_DIGEST_DOMAIN,
            &FactorAssignmentAuthorityConfigPreimageV1 {
                coordinate: &coordinate,
                bind_authority_key: bind_authorization_trust.authority_key().to_hex(),
                bind_max_lifetime_ms: bind_authorization_trust.max_lifetime_ms(),
                seller_key: agreement_trust.seller_key().to_hex(),
                buyer_key: agreement_trust.buyer_key().to_hex(),
                status_authority_key: status_proof_trust.authority_key().to_hex(),
                status_max_proof_lifetime_ms: status_proof_trust.max_proof_lifetime_ms(),
                result_authority_key: result_authority_key.to_hex(),
                claim_trust_configuration_digest: claim_trust.configuration_digest(),
            },
        )?;
        Ok(Self {
            bind_authorization_trust,
            agreement_trust,
            status_proof_trust,
            result_trust,
            result_authority_id,
            result_authority_key_epoch,
            result_authority_key,
            claim_trust,
            coordinate,
            configuration_digest,
        })
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
}

#[derive(Clone)]
pub struct FactorAssignmentSigningAuthorityV1 {
    authority_id: String,
    authority_key_epoch: u64,
    signer: Keypair,
}

impl FactorAssignmentSigningAuthorityV1 {
    pub fn new(
        authority_id: String,
        authority_key_epoch: u64,
        signer: Keypair,
    ) -> Result<Self, FactorError> {
        AssignmentResultAuthorityTrustV1::new(
            authority_id.clone(),
            signer.public_key(),
            authority_key_epoch,
        )?;
        Ok(Self {
            authority_id,
            authority_key_epoch,
            signer,
        })
    }
}

#[derive(Clone)]
pub struct FactorAssignmentAuthorityRegistryV1 {
    active: Vec<FactorAssignmentVerificationAuthorityV1>,
    retained: Vec<FactorAssignmentVerificationAuthorityV1>,
    active_set_digest: String,
}

impl FactorAssignmentAuthorityRegistryV1 {
    pub fn new<A, R>(active: A, retained: R) -> Result<Self, FactorError>
    where
        A: IntoIterator<Item = FactorAssignmentVerificationAuthorityV1>,
        R: IntoIterator<Item = FactorAssignmentVerificationAuthorityV1>,
    {
        let active: Vec<_> = active.into_iter().collect();
        let retained: Vec<_> = retained.into_iter().collect();
        if active.is_empty() {
            return Err(FactorError::InvalidField("active_authorities"));
        }
        let mut coordinates = Vec::with_capacity(active.len());
        let mut configuration_digests = Vec::with_capacity(active.len() + retained.len());
        let mut trusted_keys = BTreeMap::new();
        for authority in &active {
            if coordinates.contains(&authority.coordinate) {
                return Err(FactorError::InvalidField("authority_coordinate"));
            }
            coordinates.push(authority.coordinate.clone());
        }
        for authority in active.iter().chain(&retained) {
            if configuration_digests.contains(&authority.configuration_digest) {
                return Err(FactorError::InvalidField("authority_configuration"));
            }
            configuration_digests.push(authority.configuration_digest.clone());
            for (authority_id, key_epoch, public_key) in [
                (
                    authority.bind_authorization_trust.authority_id(),
                    authority.bind_authorization_trust.authority_key_epoch(),
                    authority.bind_authorization_trust.authority_key(),
                ),
                (
                    authority.agreement_trust.seller_id(),
                    authority.agreement_trust.seller_key_epoch(),
                    authority.agreement_trust.seller_key(),
                ),
                (
                    authority.agreement_trust.buyer_id(),
                    authority.agreement_trust.buyer_key_epoch(),
                    authority.agreement_trust.buyer_key(),
                ),
                (
                    authority.status_proof_trust.authority_id(),
                    authority.status_proof_trust.authority_key_epoch(),
                    authority.status_proof_trust.authority_key(),
                ),
                (
                    &authority.result_authority_id,
                    authority.result_authority_key_epoch,
                    &authority.result_authority_key,
                ),
            ] {
                let coordinate = (authority_id.to_owned(), key_epoch);
                let public_key = public_key.to_hex();
                if trusted_keys
                    .insert(coordinate, public_key.clone())
                    .is_some_and(|existing| existing != public_key)
                {
                    return Err(FactorError::InvalidField("authority_key"));
                }
            }
        }
        let mut configuration_digests: Vec<_> = active
            .iter()
            .map(|authority| authority.configuration_digest.clone())
            .collect();
        configuration_digests.sort_unstable();
        let active_set_digest = factor_domain_digest(
            FACTOR_ACTIVE_AUTHORITY_SET_DIGEST_DOMAIN,
            &FactorActiveAuthoritySetPreimageV1 {
                configuration_digests: &configuration_digests,
            },
        )?;
        Ok(Self {
            active,
            retained,
            active_set_digest,
        })
    }

    #[must_use]
    pub fn active_set_digest(&self) -> &str {
        &self.active_set_digest
    }

    fn active_for_verified(
        &self,
        authorization: &VerifiedAssignmentAuthorizationSetV1,
        status_proof: &VerifiedObligationStatusProofV1,
        claim: &VerifiedReceivableClaimV1,
    ) -> Option<&FactorAssignmentVerificationAuthorityV1> {
        let coordinate = coordinate_from_verified(authorization, status_proof);
        self.active.iter().find(|authority| {
            authority.coordinate == coordinate
                && authority.claim_trust.configuration_digest()
                    == claim.trust_configuration_digest()
        })
    }

    fn get_for_signed(
        &self,
        bind: &SignedAssignmentBindAuthorizationV1,
        agreement: &SignedAssignmentAgreementV1,
        status_proof: &SignedObligationStatusProofV1,
        result_authority_id: &str,
        result_authority_key_epoch: u64,
        configuration_digest: &str,
    ) -> Option<&FactorAssignmentVerificationAuthorityV1> {
        let coordinate = coordinate_from_signed(
            bind,
            agreement,
            status_proof,
            result_authority_id,
            result_authority_key_epoch,
        );
        self.active.iter().chain(&self.retained).find(|authority| {
            authority.coordinate == coordinate
                && authority.configuration_digest == configuration_digest
        })
    }
}

fn factor_domain_digest(domain: &[u8], value: &impl Serialize) -> Result<String, FactorError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| FactorError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn coordinate_from_verified(
    authorization: &VerifiedAssignmentAuthorizationSetV1,
    status_proof: &VerifiedObligationStatusProofV1,
) -> FactorAssignmentAuthorityCoordinateV1 {
    FactorAssignmentAuthorityCoordinateV1 {
        bind_authority_id: authorization.body().authority_id().to_owned(),
        bind_authority_key_epoch: authorization.body().authority_key_epoch(),
        seller_id: authorization.agreement().body().seller_id().to_owned(),
        seller_key_epoch: authorization.agreement().seller_key_epoch(),
        buyer_id: authorization.agreement().body().buyer_id().to_owned(),
        buyer_key_epoch: authorization.agreement().buyer_key_epoch(),
        status_authority_id: status_proof.body().authority_id().to_owned(),
        status_authority_key_epoch: status_proof.body().authority_key_epoch(),
        result_authority_id: status_proof.body().authority_id().to_owned(),
        result_authority_key_epoch: status_proof.body().authority_key_epoch(),
    }
}

fn coordinate_from_signed(
    bind: &SignedAssignmentBindAuthorizationV1,
    agreement: &SignedAssignmentAgreementV1,
    status_proof: &SignedObligationStatusProofV1,
    result_authority_id: &str,
    result_authority_key_epoch: u64,
) -> FactorAssignmentAuthorityCoordinateV1 {
    FactorAssignmentAuthorityCoordinateV1 {
        bind_authority_id: bind.body().authority_id().to_owned(),
        bind_authority_key_epoch: bind.body().authority_key_epoch(),
        seller_id: agreement.seller_signature().party_id().to_owned(),
        seller_key_epoch: agreement.seller_signature().party_key_epoch(),
        buyer_id: agreement.buyer_signature().party_id().to_owned(),
        buyer_key_epoch: agreement.buyer_signature().party_key_epoch(),
        status_authority_id: status_proof.body().authority_id().to_owned(),
        status_authority_key_epoch: status_proof.body().authority_key_epoch(),
        result_authority_id: result_authority_id.to_owned(),
        result_authority_key_epoch,
    }
}

#[derive(Clone)]
pub struct SqliteFactorAssignmentStore {
    store: SqliteAdmissionOperationStore,
    authorities: Arc<FactorAssignmentAuthorityRegistryV1>,
    authority_set_generation: u64,
}

pub struct FactorAssignmentCommitV1<'a> {
    pub operation: &'a AdmissionOperationV1,
    pub recovery_lease: &'a AdmissionRecoveryLease,
    pub request: &'a NormalizedAssignmentRequestV1,
    pub claim: &'a VerifiedReceivableClaimV1,
    pub offer: &'a AssignmentOfferV1,
    pub authorization: &'a VerifiedAssignmentAuthorizationSetV1,
    pub status_proof: &'a VerifiedObligationStatusProofV1,
    pub signing_authority: &'a FactorAssignmentSigningAuthorityV1,
    pub active_fence: &'a StoreMutationFence,
    pub trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableFactorAssignmentResultV1 {
    Applied(VerifiedAssignmentAcknowledgementV1),
    NotApplied(VerifiedAssignmentNotAppliedV1),
}

impl DurableFactorAssignmentResultV1 {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        match self {
            Self::Applied(result) => result.canonical_bytes(),
            Self::NotApplied(result) => result.canonical_bytes(),
        }
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        match self {
            Self::Applied(result) => result.envelope_digest(),
            Self::NotApplied(result) => result.envelope_digest(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFactorAssignmentResultV1 {
    result: DurableFactorAssignmentResultV1,
    authority_set_generation: u64,
    authority_set_digest: String,
    authority_configuration_digest: String,
    receipt_digest: String,
    iou_digest: String,
    participant_digest: String,
    participant_commit_sequence: u64,
    observed_head_sequence: u64,
    observed_head_digest: String,
    resulting_head_sequence: u64,
    resulting_head_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactorAssignmentAuthoritySetHeadV1 {
    generation: u64,
    digest: String,
}

impl FactorAssignmentAuthoritySetHeadV1 {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl StoredFactorAssignmentResultV1 {
    #[must_use]
    pub const fn result(&self) -> &DurableFactorAssignmentResultV1 {
        &self.result
    }

    #[must_use]
    pub const fn authority_set_generation(&self) -> u64 {
        self.authority_set_generation
    }

    #[must_use]
    pub fn authority_set_digest(&self) -> &str {
        &self.authority_set_digest
    }

    #[must_use]
    pub fn authority_configuration_digest(&self) -> &str {
        &self.authority_configuration_digest
    }

    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    #[must_use]
    pub fn iou_digest(&self) -> &str {
        &self.iou_digest
    }

    #[must_use]
    pub fn participant_digest(&self) -> &str {
        &self.participant_digest
    }

    #[must_use]
    pub const fn participant_commit_sequence(&self) -> u64 {
        self.participant_commit_sequence
    }

    #[must_use]
    pub const fn observed_head_sequence(&self) -> u64 {
        self.observed_head_sequence
    }

    #[must_use]
    pub fn observed_head_digest(&self) -> &str {
        &self.observed_head_digest
    }

    #[must_use]
    pub const fn resulting_head_sequence(&self) -> u64 {
        self.resulting_head_sequence
    }

    #[must_use]
    pub fn resulting_head_digest(&self) -> &str {
        &self.resulting_head_digest
    }

    #[must_use]
    pub fn into_result(self) -> DurableFactorAssignmentResultV1 {
        self.result
    }
}

struct VerifiedFactorAssignmentSubmission {
    authorization: VerifiedAssignmentAuthorizationSetV1,
    status_proof: VerifiedObligationStatusProofV1,
    claim: VerifiedReceivableClaimV1,
}

#[derive(Clone)]
struct StoredCreditAdmission {
    record: CreditExposureReservationRecordV1,
}

impl CreditAdmissionStore for StoredCreditAdmission {
    fn lookup_record_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<CreditExposureReservationRecordV1>, CreditAdmissionError> {
        Ok((self.record.operation_id() == operation_id).then(|| self.record.clone()))
    }
}

fn credit_admission_for_atom(
    transaction: &Transaction<'_>,
    atom: &ObligationAtomV1,
) -> Result<CreditAdmissionStoreAdapter<StoredCreditAdmission>, AdmissionOperationStoreError> {
    let atom_digest = atom.digest().map_err(obligation_error)?;
    let operation_id = transaction
        .query_row(
            r#"
            SELECT operation_id
            FROM obligation_atoms
            WHERE obligation_id = ?1 AND atom_digest = ?2
            "#,
            params![atom.obligation_id(), atom_digest],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("factor claim obligation has no source operation"))?;
    let record = credit_exposure::load_credit_exposure_reservation_tx(transaction, &operation_id)?
        .ok_or_else(|| invariant("factor claim has no committed credit admission"))?;
    record
        .validate_committed_obligation(atom)
        .map_err(|error| invariant(error.to_string()))?;
    Ok(CreditAdmissionStoreAdapter::new(StoredCreditAdmission {
        record,
    }))
}

struct LoadedFactorAssignmentResultV1 {
    stored: StoredFactorAssignmentResultV1,
    request_json: Vec<u8>,
    claim_json: Vec<u8>,
    receipt_json: Vec<u8>,
    iou_json: Vec<u8>,
    offer_json: Vec<u8>,
    bind_authorization_json: Vec<u8>,
    agreement_json: Vec<u8>,
    status_proof_json: Vec<u8>,
}

struct StoredFactorAssignmentRowV1 {
    obligation_id: String,
    obligation_atom_digest: String,
    outcome: String,
    authority_set_generation: i64,
    authority_set_digest: String,
    authority_configuration_digest: String,
    normalized_request_digest: String,
    normalized_request_json: Vec<u8>,
    claim_digest: String,
    claim_json: Vec<u8>,
    receipt_digest: String,
    receipt_json: Vec<u8>,
    iou_digest: String,
    iou_json: Vec<u8>,
    offer_digest: String,
    offer_json: Vec<u8>,
    bind_authorization_body_digest: String,
    bind_authorization_envelope_digest: String,
    bind_authorization_json: Vec<u8>,
    agreement_body_digest: String,
    agreement_artifact_digest: String,
    agreement_seller_signature_digest: String,
    agreement_buyer_signature_digest: String,
    agreement_json: Vec<u8>,
    assignment_authorization_set_digest: String,
    status_proof_body_digest: String,
    status_proof_envelope_digest: String,
    status_proof_json: Vec<u8>,
    result_id: String,
    result_body_digest: String,
    result_envelope_digest: String,
    result_signature_digest: String,
    result_json: Vec<u8>,
    observed_head_sequence: i64,
    observed_head_digest: String,
    resulting_head_sequence: i64,
    resulting_head_digest: String,
    participant_digest: String,
    participant_commit_sequence: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FactorAssignmentParticipantPreimageV1<'a> {
    domain: &'static str,
    operation_id: &'a str,
    authority_set_generation: u64,
    authority_set_digest: &'a str,
    authority_configuration_digest: &'a str,
    normalized_request_digest: &'a str,
    claim_digest: &'a str,
    receipt_digest: &'a str,
    iou_digest: &'a str,
    offer_digest: &'a str,
    bind_authorization_body_digest: &'a str,
    bind_authorization_envelope_digest: &'a str,
    agreement_body_digest: &'a str,
    agreement_artifact_digest: &'a str,
    seller_signature_digest: &'a str,
    buyer_signature_digest: &'a str,
    authorization_set_digest: &'a str,
    status_proof_body_digest: &'a str,
    status_proof_envelope_digest: &'a str,
    obligation_id: &'a str,
    observed_head_sequence: u64,
    observed_head_digest: &'a str,
    outcome: &'a str,
    result_id: &'a str,
    result_body_digest: &'a str,
    result_envelope_digest: &'a str,
    result_signature_digest: &'a str,
    resulting_disposition_version: u64,
    resulting_disposition_digest: &'a str,
    resulting_snapshot_version: u64,
    resulting_resource_fence: u64,
}

impl SqliteAdmissionOperationStore {
    pub fn factor_assignment_authority_set_head(
        &self,
    ) -> Result<Option<FactorAssignmentAuthoritySetHeadV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let head = transaction
            .query_row(
                r#"
                SELECT generation, active_set_digest
                FROM factor_assignment_authority_sets
                ORDER BY generation DESC
                LIMIT 1
                "#,
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?
            .map(|(generation, digest)| {
                Ok::<_, AdmissionOperationStoreError>(FactorAssignmentAuthoritySetHeadV1 {
                    generation: stored_u64(generation, "factor_authority_set_generation")?,
                    digest,
                })
            })
            .transpose()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(head)
    }

    pub fn activate_factor_assignment_authorities(
        &self,
        authorities: FactorAssignmentAuthorityRegistryV1,
        expected_generation: u64,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<SqliteFactorAssignmentStore, AdmissionOperationStoreError> {
        let active_set_digest = authorities.active_set_digest().to_owned();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let current = transaction
            .query_row(
                r#"
                SELECT generation, active_set_digest
                FROM factor_assignment_authority_sets
                ORDER BY generation DESC
                LIMIT 1
                "#,
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let current_generation = current
            .as_ref()
            .map(|(generation, _)| stored_u64(*generation, "factor_authority_set_generation"))
            .transpose()?
            .unwrap_or(0);
        if current_generation != expected_generation {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let generation = if current
            .as_ref()
            .is_some_and(|(_, digest)| digest == &active_set_digest)
        {
            current_generation
        } else {
            let generation = current_generation
                .checked_add(1)
                .ok_or_else(|| invariant("factor authority set generation overflow"))?;
            let previous_digest = current.as_ref().map(|(_, digest)| digest.as_str());
            transaction
                .execute(
                    r#"
                    INSERT INTO factor_assignment_authority_sets (
                        generation, active_set_digest, previous_active_set_digest,
                        activated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    "#,
                    params![
                        sqlite_i64(generation, "factor_authority_set_generation")?,
                        &active_set_digest,
                        previous_digest,
                        sqlite_i64(trusted_now_unix_ms, "factor_authority_set_activated_at")?,
                        &active_fence.store_uuid,
                        &active_fence.lease_id,
                        sqlite_i64(active_fence.owner_epoch, "factor_authority_set_owner_epoch")?,
                    ],
                )
                .map_err(factor_sqlite_error)?;
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    "factor_assignment_authority_set",
                    "factor_assignment_authority_set",
                    "active",
                    generation,
                )
                .map_err(map_owner_error)?;
            generation
        };
        self.commit_write(transaction)?;
        if generation != current_generation {
            self.sync_after_write(&connection)?;
        }
        Ok(SqliteFactorAssignmentStore {
            store: self.clone(),
            authorities: Arc::new(authorities),
            authority_set_generation: generation,
        })
    }
}

impl SqliteFactorAssignmentStore {
    pub fn commit_factor_assignment(
        &self,
        commit: FactorAssignmentCommitV1<'_>,
    ) -> Result<DurableFactorAssignmentResultV1, AdmissionOperationStoreError> {
        let mut connection = self.store.connection()?;
        let transaction = self
            .store
            .begin_write(&mut connection, Some(commit.active_fence))?;
        if let Some(loaded) = load_factor_assignment_result_tx(
            &transaction,
            commit.operation.binding().operation_id(),
            &self.authorities,
        )? {
            verify_exact_replay(&loaded, &commit)?;
            return Ok(loaded.stored.into_result());
        }
        verify_active_authority_set(
            &transaction,
            self.authority_set_generation,
            self.authorities.active_set_digest(),
        )?;
        let authority = self
            .authorities
            .active_for_verified(commit.authorization, commit.status_proof, commit.claim)
            .ok_or_else(|| invariant("factor assignment authority tuple is not active"))?;
        if commit.signing_authority.authority_id != authority.result_authority_id
            || commit.signing_authority.authority_key_epoch != authority.result_authority_key_epoch
            || commit.signing_authority.signer.public_key() != authority.result_authority_key
        {
            return Err(invariant(
                "factor assignment signer is not the active verification authority",
            ));
        }
        verify_trusted_time(&transaction, commit.trusted_now_unix_ms)?;
        verify_participant_recovery_tx(
            &transaction,
            &self.store.serving_owner,
            commit.operation,
            commit.recovery_lease,
            commit.trusted_now_unix_ms,
        )?;
        let submission = verify_submission(&transaction, &commit, authority)?;
        let current =
            obligation::load_durable_obligation(&transaction, commit.request.obligation_id())?
                .ok_or(AdmissionOperationStoreError::NotFound)?;
        if current.atom().digest().map_err(obligation_error)?
            != commit.request.obligation_atom_digest()
        {
            return Err(invariant(
                "factor assignment targets a different obligation atom",
            ));
        }
        let reason = classify_not_applied(
            &current,
            &submission,
            commit.request,
            commit.offer,
            commit.trusted_now_unix_ms,
        )?;
        let (result, successor) = match reason {
            Some(reason) => (
                DurableFactorAssignmentResultV1::NotApplied(build_not_applied(
                    &commit,
                    authority,
                    &submission,
                    &current,
                    reason,
                )?),
                None,
            ),
            None => {
                let successor = assignment_successor(
                    commit.operation,
                    commit.request,
                    &current,
                    &submission,
                    commit.trusted_now_unix_ms,
                )?;
                (
                    DurableFactorAssignmentResultV1::Applied(build_acknowledgement(
                        &commit,
                        authority,
                        &submission,
                        &current,
                        &successor,
                    )?),
                    Some(successor),
                )
            }
        };
        let participant_digest = participant_digest(
            self.authority_set_generation,
            self.authorities.active_set_digest(),
            authority.configuration_digest(),
            &commit,
            &submission,
            &current,
            successor.as_ref(),
            &result,
        )?;
        append_participant_update_tx(
            &transaction,
            &self.store.serving_owner,
            commit.operation,
            commit.recovery_lease,
            &participant_digest,
            commit.trusted_now_unix_ms,
        )?;
        let terminal_source =
            load_by_operation_id_tx(&transaction, commit.operation.binding().operation_id())?
                .ok_or(AdmissionOperationStoreError::NotFound)?;
        let participant_commit_sequence = load_participant_commit_sequence(
            &transaction,
            commit.operation.binding().operation_id(),
            &participant_digest,
            commit.trusted_now_unix_ms,
            commit.active_fence,
        )?;
        if let Some(successor) = &successor {
            obligation::append_obligation_disposition_transition(
                &transaction,
                commit.operation.binding().operation_id(),
                current.atom(),
                current.disposition(),
                successor,
                current.settlement_lifecycle(),
                current.snapshot_version(),
                current.resource_fence(),
                &participant_digest,
                commit.trusted_now_unix_ms,
                commit.active_fence,
            )?;
        }
        let resulting =
            obligation::load_durable_obligation(&transaction, commit.request.obligation_id())?
                .ok_or(AdmissionOperationStoreError::NotFound)?;
        insert_factor_assignment_result(
            &transaction,
            &commit,
            &submission,
            &current,
            &resulting,
            &result,
            &participant_digest,
            participant_commit_sequence,
            self.authority_set_generation,
            self.authorities.active_set_digest(),
            authority.configuration_digest(),
        )?;
        let terminal_projection = factor_terminal_projection(&commit, &result)?;
        let (terminal, terminal_changed) = self
            .store
            .commit_terminal_projection_from_source_in_transaction(
                &transaction,
                &terminal_projection,
                &terminal_source,
            )?;
        let expected_terminal_state = match &result {
            DurableFactorAssignmentResultV1::Applied(_) => {
                AdmissionOperationState::EconomicMutationApplied
            }
            DurableFactorAssignmentResultV1::NotApplied(_) => {
                AdmissionOperationState::EconomicMutationNotApplied
            }
        };
        if !terminal_changed || terminal.state != expected_terminal_state {
            return Err(invariant(
                "factor assignment did not terminalize its admission operation",
            ));
        }
        self.store.commit_write(transaction)?;
        self.store.sync_after_write(&connection)?;
        Ok(result)
    }

    pub fn load_factor_assignment_result(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<StoredFactorAssignmentResultV1>, AdmissionOperationStoreError> {
        let mut connection = self.store.connection()?;
        let transaction = self.store.begin_read(&mut connection)?;
        load_factor_assignment_result_tx(&transaction, operation_id, &self.authorities)
            .map(|loaded| loaded.map(|loaded| loaded.stored))
    }
}

fn factor_terminal_projection(
    commit: &FactorAssignmentCommitV1<'_>,
    result: &DurableFactorAssignmentResultV1,
) -> Result<AdmissionTerminalProjection, AdmissionOperationStoreError> {
    let context = AdmissionProjectionContext {
        operation_id: commit.operation.binding().operation_id().clone(),
        request_id: commit.operation.binding().request_id().clone(),
        expected_operation_version: commit.operation.version(),
        trusted_time_unix_ms: commit.trusted_now_unix_ms,
        coordinator_lease_id: commit.recovery_lease.coordinator_lease_id().clone(),
        coordinator_lease_epoch: commit.recovery_lease.coordinator_lease_epoch(),
        store_fence: commit.active_fence.clone(),
    };
    match result {
        DurableFactorAssignmentResultV1::Applied(result) => {
            verified_factor_assignment_applied_projection(commit.operation, context, result)
        }
        DurableFactorAssignmentResultV1::NotApplied(result) => {
            verified_factor_assignment_not_applied_projection(commit.operation, context, result)
        }
    }
    .map_err(AdmissionOperationStoreError::from)
}

fn verify_terminal_result(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    result: &DurableFactorAssignmentResultV1,
) -> Result<(), AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, operation_id)?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let (expected_state, expected_id, expected_digest) = match result {
        DurableFactorAssignmentResultV1::Applied(result) => (
            AdmissionOperationState::EconomicMutationApplied,
            result.body().acknowledgement_id(),
            result.envelope_digest(),
        ),
        DurableFactorAssignmentResultV1::NotApplied(result) => (
            AdmissionOperationState::EconomicMutationNotApplied,
            result.body().result_id(),
            result.envelope_digest(),
        ),
    };
    if stored.operation.state() != expected_state
        || !matches!(
            stored.operation.terminal_replay(),
            Some(AdmissionTerminalReplay::EconomicMutation {
                result_id,
                result_digest,
                ..
            }) if result_id.as_str() == expected_id
                && result_digest.as_str() == expected_digest
        )
    {
        return Err(invariant(
            "factor assignment result lacks its terminal admission operation",
        ));
    }
    Ok(())
}

fn verify_exact_replay(
    loaded: &LoadedFactorAssignmentResultV1,
    commit: &FactorAssignmentCommitV1<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    if loaded.request_json != commit.request.canonical_bytes().map_err(factor_error)?
        || loaded.claim_json != commit.claim.claim_canonical_bytes()
        || loaded.receipt_json != commit.claim.receipt_canonical_bytes()
        || loaded.iou_json != commit.claim.iou_canonical_bytes()
        || loaded.offer_json != commit.offer.canonical_bytes().map_err(factor_error)?
        || loaded.bind_authorization_json
            != commit.authorization.bind_authorization().canonical_bytes()
        || loaded.agreement_json != commit.authorization.agreement().canonical_bytes()
        || loaded.status_proof_json != commit.status_proof.canonical_bytes()
    {
        return Err(invariant(
            "factor assignment replay conflicts with its durable result",
        ));
    }
    Ok(())
}

fn verify_active_authority_set(
    transaction: &Transaction<'_>,
    expected_generation: u64,
    expected_digest: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let current = transaction
        .query_row(
            r#"
            SELECT generation, active_set_digest
            FROM factor_assignment_authority_sets
            ORDER BY generation DESC
            LIMIT 1
            "#,
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((generation, digest)) = current else {
        return Err(AdmissionOperationStoreError::Fenced);
    };
    if stored_u64(generation, "factor_authority_set_generation")? != expected_generation
        || digest != expected_digest
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

fn load_factor_assignment_result_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    authorities: &FactorAssignmentAuthorityRegistryV1,
) -> Result<Option<LoadedFactorAssignmentResultV1>, AdmissionOperationStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT obligation_id, obligation_atom_digest, outcome,
                   authority_set_generation, authority_set_digest,
                   authority_configuration_digest,
                   normalized_request_digest, normalized_request_json,
                   claim_digest, claim_json, receipt_digest, receipt_json,
                   iou_digest, iou_json, offer_digest, offer_json,
                   bind_authorization_body_digest, bind_authorization_envelope_digest,
                   bind_authorization_json, agreement_body_digest,
                   agreement_artifact_digest, agreement_seller_signature_digest,
                   agreement_buyer_signature_digest, agreement_json,
                   assignment_authorization_set_digest, status_proof_body_digest,
                   status_proof_envelope_digest, status_proof_json, result_id,
                   result_body_digest, result_envelope_digest, result_signature_digest,
                   result_json, observed_head_sequence, observed_head_digest,
                   resulting_head_sequence, resulting_head_digest, participant_digest,
                   participant_commit_sequence, store_uuid, store_lease_id, store_owner_epoch
            FROM obligation_assignment_results
            WHERE operation_id = ?1
            "#,
            [operation_id.as_str()],
            |row| {
                Ok(StoredFactorAssignmentRowV1 {
                    obligation_id: row.get(0)?,
                    obligation_atom_digest: row.get(1)?,
                    outcome: row.get(2)?,
                    authority_set_generation: row.get(3)?,
                    authority_set_digest: row.get(4)?,
                    authority_configuration_digest: row.get(5)?,
                    normalized_request_digest: row.get(6)?,
                    normalized_request_json: row.get(7)?,
                    claim_digest: row.get(8)?,
                    claim_json: row.get(9)?,
                    receipt_digest: row.get(10)?,
                    receipt_json: row.get(11)?,
                    iou_digest: row.get(12)?,
                    iou_json: row.get(13)?,
                    offer_digest: row.get(14)?,
                    offer_json: row.get(15)?,
                    bind_authorization_body_digest: row.get(16)?,
                    bind_authorization_envelope_digest: row.get(17)?,
                    bind_authorization_json: row.get(18)?,
                    agreement_body_digest: row.get(19)?,
                    agreement_artifact_digest: row.get(20)?,
                    agreement_seller_signature_digest: row.get(21)?,
                    agreement_buyer_signature_digest: row.get(22)?,
                    agreement_json: row.get(23)?,
                    assignment_authorization_set_digest: row.get(24)?,
                    status_proof_body_digest: row.get(25)?,
                    status_proof_envelope_digest: row.get(26)?,
                    status_proof_json: row.get(27)?,
                    result_id: row.get(28)?,
                    result_body_digest: row.get(29)?,
                    result_envelope_digest: row.get(30)?,
                    result_signature_digest: row.get(31)?,
                    result_json: row.get(32)?,
                    observed_head_sequence: row.get(33)?,
                    observed_head_digest: row.get(34)?,
                    resulting_head_sequence: row.get(35)?,
                    resulting_head_digest: row.get(36)?,
                    participant_digest: row.get(37)?,
                    participant_commit_sequence: row.get(38)?,
                    store_uuid: row.get(39)?,
                    store_lease_id: row.get(40)?,
                    store_owner_epoch: row.get(41)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let (result_authority_id, result_authority_key_epoch) = match row.outcome.as_str() {
        "applied" => {
            let signed: SignedAssignmentAcknowledgementV1 =
                decode_factor_json(&row.result_json, "assignment acknowledgement")?;
            (
                signed.body().authority_id().to_owned(),
                signed.body().authority_key_epoch(),
            )
        }
        "not_applied" => {
            let signed: SignedAssignmentNotAppliedV1 =
                decode_factor_json(&row.result_json, "assignment not applied")?;
            (
                signed.body().authority_id().to_owned(),
                signed.body().authority_key_epoch(),
            )
        }
        _ => return Err(invariant("factor assignment result outcome is invalid")),
    };
    let signed_bind: SignedAssignmentBindAuthorizationV1 = decode_factor_json(
        &row.bind_authorization_json,
        "assignment bind authorization",
    )?;
    let signed_agreement: SignedAssignmentAgreementV1 =
        decode_factor_json(&row.agreement_json, "assignment agreement")?;
    let signed_status = SignedObligationStatusProofV1::from_canonical_bytes(&row.status_proof_json)
        .map_err(obligation_error)?;
    let authority = authorities
        .get_for_signed(
            &signed_bind,
            &signed_agreement,
            &signed_status,
            &result_authority_id,
            result_authority_key_epoch,
            &row.authority_configuration_digest,
        )
        .ok_or_else(|| invariant("factor assignment result authority tuple is not configured"))?;
    let authority_set_generation = stored_u64(
        row.authority_set_generation,
        "factor_authority_set_generation",
    )?;
    let authority_set_exists: bool = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1
            FROM factor_assignment_authority_sets
            WHERE generation = ?1 AND active_set_digest = ?2
            "#,
            params![row.authority_set_generation, &row.authority_set_digest],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !authority_set_exists {
        return Err(invariant(
            "factor assignment result authority set is not retained",
        ));
    }
    let observed_head_sequence =
        stored_u64(row.observed_head_sequence, "factor_observed_head_sequence")?;
    let resulting_head_sequence = stored_u64(
        row.resulting_head_sequence,
        "factor_resulting_head_sequence",
    )?;
    let observed = obligation::load_durable_obligation_at_head(
        transaction,
        &row.obligation_id,
        observed_head_sequence,
        &row.observed_head_digest,
    )?
    .ok_or_else(|| invariant("factor assignment observed head is absent"))?;
    let resulting = obligation::load_durable_obligation_at_head(
        transaction,
        &row.obligation_id,
        resulting_head_sequence,
        &row.resulting_head_digest,
    )?
    .ok_or_else(|| invariant("factor assignment resulting head is absent"))?;
    let request: NormalizedAssignmentRequestV1 = decode_factor_json(
        &row.normalized_request_json,
        "normalized assignment request",
    )?;
    let claim_body: ReceivableClaimV1 = decode_factor_json(&row.claim_json, "receivable claim")?;
    let offer: AssignmentOfferV1 = decode_factor_json(&row.offer_json, "assignment offer")?;
    request.validate().map_err(factor_error)?;
    offer.validate().map_err(factor_error)?;
    let status_head = load_status_head(transaction, signed_status.body())?;
    let status_proof = verify_obligation_status_proof(
        &row.status_proof_json,
        &ObligationStatusProofVerificationContextV1 {
            atom: status_head.atom(),
            disposition: status_head.disposition(),
            settlement_lifecycle: status_head.settlement_lifecycle(),
            snapshot_version: status_head.snapshot_version(),
            resource_fence: status_head.resource_fence(),
            trust: &authority.status_proof_trust,
            trusted_now_unix_ms: signed_status.body().issued_at_unix_ms(),
        },
    )
    .map_err(obligation_error)?;
    let credit_admission = credit_admission_for_atom(transaction, status_head.atom())?;
    let claim = verify_receivable_claim(
        &row.claim_json,
        &row.receipt_json,
        &row.iou_json,
        &credit_admission,
        &ReceivableClaimVerificationV1 {
            atom: status_head.atom(),
            disposition: status_head.disposition(),
            settlement_lifecycle: status_head.settlement_lifecycle(),
            status_proof: &status_proof,
            trusted_now_unix_ms: claim_body.built_at_unix_ms(),
            trust: &authority.claim_trust,
        },
    )
    .map_err(factor_error)?;
    let bind = verify_assignment_bind_authorization(
        &row.bind_authorization_json,
        &AssignmentBindAuthorizationVerificationV1 {
            operation_id: operation_id.as_str(),
            normalized_request_digest: &row.normalized_request_digest,
            obligation_atom_digest: request.obligation_atom_digest(),
            seller_id: request.seller_id(),
            buyer_id: request.buyer_id(),
            agreement_id: signed_agreement.body().agreement_id(),
            buyer_settlement_destination_ref: request.buyer_settlement_destination_ref(),
            effective_at_unix_ms: request.effective_at_unix_ms(),
            action_nonce: request.action_nonce(),
            trust: &authority.bind_authorization_trust,
            trusted_now_unix_ms: request.effective_at_unix_ms(),
        },
    )
    .map_err(factor_error)?;
    let agreement = verify_assignment_agreement(
        &row.agreement_json,
        &AssignmentAgreementVerificationV1 {
            operation_id: operation_id.as_str(),
            normalized_request_digest: &row.normalized_request_digest,
            assignment_authority_digest: bind.envelope_digest(),
            trust: &authority.agreement_trust,
        },
    )
    .map_err(factor_error)?;
    let authorization =
        VerifiedAssignmentAuthorizationSetV1::new(bind, agreement).map_err(factor_error)?;
    authorization
        .validate_submission_binding(&request, claim.claim(), &offer)
        .map_err(factor_error)?;
    let status = status_proof.body();
    if claim.claim().status_proof_digest() != status_proof.envelope_digest()
        || status.obligation_id() != request.obligation_id()
        || status.obligation_atom_digest() != request.obligation_atom_digest()
        || status.current_creditor_id() != request.seller_id()
        || status.disposition_version() != request.expected_disposition_version()
        || status.disposition_lifecycle_fence() != request.expected_disposition_lifecycle_fence()
        || status.settlement_lifecycle_version() != request.expected_settlement_lifecycle_version()
        || status.settlement_lifecycle_fence() != request.expected_settlement_lifecycle_fence()
        || status.due_at_unix_ms() != request.due_at_unix_ms()
    {
        return Err(invariant(
            "factor assignment result has a different status snapshot",
        ));
    }
    let result = match row.outcome.as_str() {
        "applied" => DurableFactorAssignmentResultV1::Applied(
            verify_assignment_acknowledgement(
                &row.result_json,
                &AssignmentAcknowledgementVerificationV1 {
                    atom: observed.atom(),
                    request: &request,
                    claim: &claim,
                    offer: &offer,
                    authorization: &authorization,
                    status_proof: &status_proof,
                    resulting_disposition: resulting.disposition(),
                    trust: &authority.result_trust,
                },
            )
            .map_err(factor_error)?,
        ),
        "not_applied" => DurableFactorAssignmentResultV1::NotApplied(
            verify_assignment_not_applied(
                &row.result_json,
                &AssignmentNotAppliedVerificationV1 {
                    atom: observed.atom(),
                    request: &request,
                    claim: &claim,
                    offer: &offer,
                    authorization: &authorization,
                    status_proof: &status_proof,
                    observed_disposition: observed.disposition(),
                    observed_settlement_lifecycle: observed.settlement_lifecycle(),
                    observed_snapshot_version: observed.snapshot_version(),
                    observed_resource_fence: observed.resource_fence(),
                    no_mutation_proof_digest: observed.head_digest(),
                    trust: &authority.result_trust,
                },
            )
            .map_err(factor_error)?,
        ),
        _ => return Err(invariant("factor assignment result outcome is invalid")),
    };
    let computed_participant_digest = participant_digest_from_parts(
        operation_id.as_str(),
        authority_set_generation,
        &row.authority_set_digest,
        &row.authority_configuration_digest,
        &request,
        &claim,
        &offer,
        &authorization,
        &status_proof,
        &observed,
        &resulting,
        &result,
    )?;
    let participant_commit_sequence = stored_u64(
        row.participant_commit_sequence,
        "factor_participant_commit_sequence",
    )?;
    let exact_commit: bool = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1
            FROM admission_operation_commits
            WHERE commit_sequence = ?1 AND operation_id = ?2
              AND mutation_kind = 'participant_update' AND participant_digest = ?3
              AND store_uuid = ?4 AND store_lease_id = ?5 AND store_owner_epoch = ?6
            "#,
            params![
                row.participant_commit_sequence,
                operation_id.as_str(),
                &row.participant_digest,
                &row.store_uuid,
                &row.store_lease_id,
                row.store_owner_epoch,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let result_id = match &result {
        DurableFactorAssignmentResultV1::Applied(result) => result.body().acknowledgement_id(),
        DurableFactorAssignmentResultV1::NotApplied(result) => result.body().result_id(),
    };
    let result_body_digest = match &result {
        DurableFactorAssignmentResultV1::Applied(result) => result.body_digest(),
        DurableFactorAssignmentResultV1::NotApplied(result) => result.body_digest(),
    };
    let result_signature_digest = match &result {
        DurableFactorAssignmentResultV1::Applied(result) => result.signature_digest(),
        DurableFactorAssignmentResultV1::NotApplied(result) => result.signature_digest(),
    };
    let head_relation_matches = match &result {
        DurableFactorAssignmentResultV1::Applied(_) => {
            resulting_head_sequence
                == observed_head_sequence
                    .checked_add(1)
                    .ok_or_else(|| invariant("factor assignment head sequence overflow"))?
                && resulting.head_digest() != observed.head_digest()
        }
        DurableFactorAssignmentResultV1::NotApplied(_) => {
            resulting_head_sequence == observed_head_sequence
                && resulting.head_digest() == observed.head_digest()
        }
    };
    let source_head_count: i64 = transaction
        .query_row(
            r#"
            SELECT COUNT(*) FROM obligation_head_commits
            WHERE source_operation_id = ?1 AND source_kind <> 'initial_projection'
            "#,
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let source_head_matches = match &result {
        DurableFactorAssignmentResultV1::Applied(_) => source_head_count == 1,
        DurableFactorAssignmentResultV1::NotApplied(_) => source_head_count == 0,
    };
    if row.obligation_atom_digest != observed.atom().digest().map_err(obligation_error)?
        || row.normalized_request_digest != request.digest().map_err(factor_error)?
        || row.authority_configuration_digest != authority.configuration_digest
        || row.claim_digest != claim.claim_digest()
        || row.receipt_digest != claim.receipt_digest()
        || row.iou_digest != claim.iou_digest()
        || row.offer_digest != offer.digest().map_err(factor_error)?
        || row.bind_authorization_body_digest != authorization.bind_authorization().body_digest()
        || row.bind_authorization_envelope_digest
            != authorization.bind_authorization().envelope_digest()
        || row.agreement_body_digest != authorization.agreement().body_digest()
        || row.agreement_artifact_digest != authorization.agreement().artifact_digest()
        || row.agreement_seller_signature_digest
            != authorization.agreement().seller_signature_digest()
        || row.agreement_buyer_signature_digest
            != authorization.agreement().buyer_signature_digest()
        || row.assignment_authorization_set_digest != authorization.digest()
        || row.status_proof_body_digest != status_proof.body_digest()
        || row.status_proof_envelope_digest != status_proof.envelope_digest()
        || row.result_id != result_id
        || row.result_body_digest != result_body_digest
        || row.result_envelope_digest != result.envelope_digest()
        || row.result_signature_digest != result_signature_digest
        || row.participant_digest != computed_participant_digest
        || !exact_commit
        || !head_relation_matches
        || !source_head_matches
    {
        return Err(invariant(
            "factor assignment result differs from its canonical artifacts",
        ));
    }
    verify_terminal_result(transaction, operation_id, &result)?;
    Ok(Some(LoadedFactorAssignmentResultV1 {
        stored: StoredFactorAssignmentResultV1 {
            result,
            authority_set_generation,
            authority_set_digest: row.authority_set_digest,
            authority_configuration_digest: row.authority_configuration_digest,
            receipt_digest: row.receipt_digest,
            iou_digest: row.iou_digest,
            participant_digest: row.participant_digest,
            participant_commit_sequence,
            observed_head_sequence,
            observed_head_digest: row.observed_head_digest,
            resulting_head_sequence,
            resulting_head_digest: row.resulting_head_digest,
        },
        request_json: row.normalized_request_json,
        claim_json: row.claim_json,
        receipt_json: row.receipt_json,
        iou_json: row.iou_json,
        offer_json: row.offer_json,
        bind_authorization_json: row.bind_authorization_json,
        agreement_json: row.agreement_json,
        status_proof_json: row.status_proof_json,
    }))
}

#[allow(clippy::too_many_arguments)]
fn insert_factor_assignment_result(
    transaction: &Transaction<'_>,
    commit: &FactorAssignmentCommitV1<'_>,
    submission: &VerifiedFactorAssignmentSubmission,
    observed: &DurableObligationV1,
    resulting: &DurableObligationV1,
    result: &DurableFactorAssignmentResultV1,
    participant_digest: &str,
    participant_commit_sequence: u64,
    authority_set_generation: u64,
    authority_set_digest: &str,
    authority_configuration_digest: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let (outcome, result_id, result_body_digest, result_signature_digest) = match result {
        DurableFactorAssignmentResultV1::Applied(result) => (
            "applied",
            result.body().acknowledgement_id(),
            result.body_digest(),
            result.signature_digest(),
        ),
        DurableFactorAssignmentResultV1::NotApplied(result) => (
            "not_applied",
            result.body().result_id(),
            result.body_digest(),
            result.signature_digest(),
        ),
    };
    let request_digest = commit.request.digest().map_err(factor_error)?;
    let claim_digest = submission.claim.claim_digest();
    let offer_digest = commit.offer.digest().map_err(factor_error)?;
    let atom_digest = observed.atom().digest().map_err(obligation_error)?;
    let authorization = &submission.authorization;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_assignment_results (
                operation_id, obligation_id, obligation_atom_digest, outcome,
                authority_set_generation, authority_set_digest,
                authority_configuration_digest, normalized_request_digest,
                normalized_request_json, claim_digest, claim_json, receipt_digest,
                receipt_json, iou_digest, iou_json, offer_digest, offer_json,
                bind_authorization_body_digest,
                bind_authorization_envelope_digest, bind_authorization_json,
                agreement_body_digest, agreement_artifact_digest,
                agreement_seller_signature_digest, agreement_buyer_signature_digest,
                agreement_json, assignment_authorization_set_digest,
                status_proof_body_digest, status_proof_envelope_digest, status_proof_json,
                result_id, result_body_digest, result_envelope_digest,
                result_signature_digest, result_json, observed_head_sequence,
                observed_head_digest, resulting_head_sequence, resulting_head_digest,
                participant_digest, participant_commit_sequence, store_uuid,
                store_lease_id, store_owner_epoch
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34,
                ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43
            )
            "#,
            params![
                commit.operation.binding().operation_id().as_str(),
                observed.atom().obligation_id(),
                &atom_digest,
                outcome,
                sqlite_i64(authority_set_generation, "factor_authority_set_generation")?,
                authority_set_digest,
                authority_configuration_digest,
                &request_digest,
                commit.request.canonical_bytes().map_err(factor_error)?,
                claim_digest,
                submission.claim.claim_canonical_bytes(),
                submission.claim.receipt_digest(),
                submission.claim.receipt_canonical_bytes(),
                submission.claim.iou_digest(),
                submission.claim.iou_canonical_bytes(),
                &offer_digest,
                commit.offer.canonical_bytes().map_err(factor_error)?,
                authorization.bind_authorization().body_digest(),
                authorization.bind_authorization().envelope_digest(),
                authorization.bind_authorization().canonical_bytes(),
                authorization.agreement().body_digest(),
                authorization.agreement().artifact_digest(),
                authorization.agreement().seller_signature_digest(),
                authorization.agreement().buyer_signature_digest(),
                authorization.agreement().canonical_bytes(),
                authorization.digest(),
                submission.status_proof.body_digest(),
                submission.status_proof.envelope_digest(),
                submission.status_proof.canonical_bytes(),
                result_id,
                result_body_digest,
                result.envelope_digest(),
                result_signature_digest,
                result.canonical_bytes(),
                sqlite_i64(observed.head_sequence(), "factor_observed_head_sequence")?,
                observed.head_digest(),
                sqlite_i64(resulting.head_sequence(), "factor_resulting_head_sequence")?,
                resulting.head_digest(),
                participant_digest,
                sqlite_i64(
                    participant_commit_sequence,
                    "factor_participant_commit_sequence"
                )?,
                &commit.active_fence.store_uuid,
                &commit.active_fence.lease_id,
                sqlite_i64(commit.active_fence.owner_epoch, "factor_store_owner_epoch")?,
            ],
        )
        .map_err(factor_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "factor assignment result did not insert exactly once",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn participant_digest(
    authority_set_generation: u64,
    authority_set_digest: &str,
    authority_configuration_digest: &str,
    commit: &FactorAssignmentCommitV1<'_>,
    submission: &VerifiedFactorAssignmentSubmission,
    observed: &DurableObligationV1,
    successor: Option<&ObligationDispositionRecordV1>,
    result: &DurableFactorAssignmentResultV1,
) -> Result<String, AdmissionOperationStoreError> {
    let resulting_disposition = successor.unwrap_or_else(|| observed.disposition());
    let resulting_snapshot_version = if successor.is_some() {
        observed
            .snapshot_version()
            .checked_add(1)
            .ok_or_else(|| invariant("factor assignment snapshot version overflow"))?
    } else {
        observed.snapshot_version()
    };
    let resulting_resource_fence = if successor.is_some() {
        observed
            .resource_fence()
            .checked_add(1)
            .ok_or_else(|| invariant("factor assignment resource fence overflow"))?
    } else {
        observed.resource_fence()
    };
    digest_participant_preimage(
        commit.operation.binding().operation_id().as_str(),
        authority_set_generation,
        authority_set_digest,
        authority_configuration_digest,
        commit.request,
        &submission.claim,
        commit.offer,
        &submission.authorization,
        &submission.status_proof,
        observed,
        resulting_disposition,
        resulting_snapshot_version,
        resulting_resource_fence,
        result,
    )
}

#[allow(clippy::too_many_arguments)]
fn participant_digest_from_parts(
    operation_id: &str,
    authority_set_generation: u64,
    authority_set_digest: &str,
    authority_configuration_digest: &str,
    request: &NormalizedAssignmentRequestV1,
    claim: &VerifiedReceivableClaimV1,
    offer: &AssignmentOfferV1,
    authorization: &VerifiedAssignmentAuthorizationSetV1,
    status_proof: &VerifiedObligationStatusProofV1,
    observed: &DurableObligationV1,
    resulting: &DurableObligationV1,
    result: &DurableFactorAssignmentResultV1,
) -> Result<String, AdmissionOperationStoreError> {
    digest_participant_preimage(
        operation_id,
        authority_set_generation,
        authority_set_digest,
        authority_configuration_digest,
        request,
        claim,
        offer,
        authorization,
        status_proof,
        observed,
        resulting.disposition(),
        resulting.snapshot_version(),
        resulting.resource_fence(),
        result,
    )
}

#[allow(clippy::too_many_arguments)]
fn digest_participant_preimage(
    operation_id: &str,
    authority_set_generation: u64,
    authority_set_digest: &str,
    authority_configuration_digest: &str,
    request: &NormalizedAssignmentRequestV1,
    claim: &VerifiedReceivableClaimV1,
    offer: &AssignmentOfferV1,
    authorization: &VerifiedAssignmentAuthorizationSetV1,
    status_proof: &VerifiedObligationStatusProofV1,
    observed: &DurableObligationV1,
    resulting_disposition: &ObligationDispositionRecordV1,
    resulting_snapshot_version: u64,
    resulting_resource_fence: u64,
    result: &DurableFactorAssignmentResultV1,
) -> Result<String, AdmissionOperationStoreError> {
    let (outcome, result_id, result_body_digest, result_envelope_digest, result_signature_digest) =
        match result {
            DurableFactorAssignmentResultV1::Applied(result) => (
                "applied",
                result.body().acknowledgement_id(),
                result.body_digest(),
                result.envelope_digest(),
                result.signature_digest(),
            ),
            DurableFactorAssignmentResultV1::NotApplied(result) => (
                "not_applied",
                result.body().result_id(),
                result.body_digest(),
                result.envelope_digest(),
                result.signature_digest(),
            ),
        };
    let normalized_request_digest = request.digest().map_err(factor_error)?;
    let offer_digest = offer.digest().map_err(factor_error)?;
    let resulting_disposition_digest = resulting_disposition
        .digest(observed.atom())
        .map_err(obligation_error)?;
    let preimage = FactorAssignmentParticipantPreimageV1 {
        domain: "chio.factor.assignment-participant.v1",
        operation_id,
        authority_set_generation,
        authority_set_digest,
        authority_configuration_digest,
        normalized_request_digest: &normalized_request_digest,
        claim_digest: claim.claim_digest(),
        receipt_digest: claim.receipt_digest(),
        iou_digest: claim.iou_digest(),
        offer_digest: &offer_digest,
        bind_authorization_body_digest: authorization.bind_authorization().body_digest(),
        bind_authorization_envelope_digest: authorization.bind_authorization().envelope_digest(),
        agreement_body_digest: authorization.agreement().body_digest(),
        agreement_artifact_digest: authorization.agreement().artifact_digest(),
        seller_signature_digest: authorization.agreement().seller_signature_digest(),
        buyer_signature_digest: authorization.agreement().buyer_signature_digest(),
        authorization_set_digest: authorization.digest(),
        status_proof_body_digest: status_proof.body_digest(),
        status_proof_envelope_digest: status_proof.envelope_digest(),
        obligation_id: observed.atom().obligation_id(),
        observed_head_sequence: observed.head_sequence(),
        observed_head_digest: observed.head_digest(),
        outcome,
        result_id,
        result_body_digest,
        result_envelope_digest,
        result_signature_digest,
        resulting_disposition_version: resulting_disposition.version(),
        resulting_disposition_digest: &resulting_disposition_digest,
        resulting_snapshot_version,
        resulting_resource_fence,
    };
    canonical_json_bytes(&preimage)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| invariant(format!("factor assignment digest failed: {error}")))
}

fn load_participant_commit_sequence(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    participant_digest: &str,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<u64, AdmissionOperationStoreError> {
    transaction
        .query_row(
            r#"
            SELECT commit_sequence
            FROM admission_operation_commits
            WHERE operation_id = ?1 AND mutation_kind = 'participant_update'
              AND participant_digest = ?2 AND recorded_at_unix_ms = ?3
              AND store_uuid = ?4 AND store_lease_id = ?5 AND store_owner_epoch = ?6
            "#,
            params![
                operation_id.as_str(),
                participant_digest,
                sqlite_i64(committed_at_unix_ms, "factor_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "factor_store_owner_epoch")?,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)
        .and_then(|sequence| stored_u64(sequence, "factor_participant_commit_sequence"))
}

fn decode_factor_json<T>(bytes: &[u8], label: &str) -> Result<T, AdmissionOperationStoreError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| invariant(format!("factor {label} is invalid: {error}")))?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| invariant(format!("factor {label} encoding failed: {error}")))?;
    if canonical != bytes {
        return Err(invariant(format!("factor {label} is not canonical")));
    }
    Ok(value)
}

fn factor_sqlite_error(error: rusqlite::Error) -> AdmissionOperationStoreError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        invariant(format!(
            "factor assignment conflicts with durable state: {error}"
        ))
    } else {
        sqlite_error(error)
    }
}

fn verify_submission(
    transaction: &Transaction<'_>,
    commit: &FactorAssignmentCommitV1<'_>,
    authority: &FactorAssignmentVerificationAuthorityV1,
) -> Result<VerifiedFactorAssignmentSubmission, AdmissionOperationStoreError> {
    commit.request.validate().map_err(factor_error)?;
    commit.offer.validate().map_err(factor_error)?;
    let request_digest = commit.request.digest().map_err(factor_error)?;
    if commit.operation.binding().kind() != AdmissionOperationKind::GovernedEconomicMutation
        || commit.operation.state() != AdmissionOperationState::MutationSubmitted
        || commit.operation.binding().effect_class() != SideEffectClass::Monetary
        || commit.operation.binding().immutable_request_hash().as_str() != request_digest
        || commit.operation.binding().operation_id().as_str()
            != commit.authorization.body().operation_id()
        || commit
            .operation
            .supplemental_authorization_digest()
            .is_none_or(|digest| digest.as_str() != commit.authorization.digest())
    {
        return Err(invariant(
            "factor assignment does not match its admission operation",
        ));
    }
    let supplied_bind = commit.authorization.bind_authorization();
    let supplied_agreement = commit.authorization.agreement();
    let agreement_body = supplied_agreement.body();
    let verified_bind = verify_assignment_bind_authorization(
        supplied_bind.canonical_bytes(),
        &AssignmentBindAuthorizationVerificationV1 {
            operation_id: commit.operation.binding().operation_id().as_str(),
            normalized_request_digest: &request_digest,
            obligation_atom_digest: commit.request.obligation_atom_digest(),
            seller_id: commit.request.seller_id(),
            buyer_id: commit.request.buyer_id(),
            agreement_id: agreement_body.agreement_id(),
            buyer_settlement_destination_ref: commit.request.buyer_settlement_destination_ref(),
            effective_at_unix_ms: commit.request.effective_at_unix_ms(),
            action_nonce: commit.request.action_nonce(),
            trust: &authority.bind_authorization_trust,
            trusted_now_unix_ms: supplied_bind.body().issued_at_unix_ms(),
        },
    )
    .map_err(factor_error)?;
    let verified_agreement = verify_assignment_agreement(
        supplied_agreement.canonical_bytes(),
        &AssignmentAgreementVerificationV1 {
            operation_id: commit.operation.binding().operation_id().as_str(),
            normalized_request_digest: &request_digest,
            assignment_authority_digest: verified_bind.envelope_digest(),
            trust: &authority.agreement_trust,
        },
    )
    .map_err(factor_error)?;
    let authorization =
        VerifiedAssignmentAuthorizationSetV1::new(verified_bind, verified_agreement)
            .map_err(factor_error)?;
    if authorization.digest() != commit.authorization.digest() {
        return Err(invariant(
            "factor assignment authorization changed during verification",
        ));
    }
    authorization
        .validate_submission_binding(commit.request, commit.claim.claim(), commit.offer)
        .map_err(factor_error)?;
    if commit.claim.claim().status_proof_digest() != commit.status_proof.envelope_digest() {
        return Err(invariant(
            "factor assignment claim has a different status proof",
        ));
    }
    let status = commit.status_proof.body();
    if status.obligation_id() != commit.request.obligation_id()
        || status.obligation_atom_digest() != commit.request.obligation_atom_digest()
        || status.current_creditor_id() != commit.request.seller_id()
        || status.disposition_version() != commit.request.expected_disposition_version()
        || status.disposition_lifecycle_fence()
            != commit.request.expected_disposition_lifecycle_fence()
        || status.settlement_lifecycle_version()
            != commit.request.expected_settlement_lifecycle_version()
        || status.settlement_lifecycle_fence()
            != commit.request.expected_settlement_lifecycle_fence()
        || status.due_at_unix_ms() != commit.request.due_at_unix_ms()
    {
        return Err(invariant(
            "factor assignment request has a different status snapshot",
        ));
    }
    let status_head = load_status_head(transaction, status)?;
    commit
        .claim
        .claim()
        .validate_against_atom(status_head.atom())
        .map_err(factor_error)?;
    if status.issued_at_unix_ms() > commit.claim.claim().built_at_unix_ms()
        || commit.claim.claim().built_at_unix_ms() > commit.offer.issued_at_unix_ms()
        || commit.offer.issued_at_unix_ms() > commit.request.effective_at_unix_ms()
        || commit.claim.claim().built_at_unix_ms() > commit.trusted_now_unix_ms
        || commit.claim.claim().built_at_unix_ms() >= status.expires_at_unix_ms()
        || commit.claim.claim().built_at_unix_ms() >= status_head.atom().due_at_unix_ms()
    {
        return Err(invariant(
            "factor assignment evidence is not causally ordered",
        ));
    }
    let status_proof = verify_obligation_status_proof(
        commit.status_proof.canonical_bytes(),
        &ObligationStatusProofVerificationContextV1 {
            atom: status_head.atom(),
            disposition: status_head.disposition(),
            settlement_lifecycle: status_head.settlement_lifecycle(),
            snapshot_version: status_head.snapshot_version(),
            resource_fence: status_head.resource_fence(),
            trust: &authority.status_proof_trust,
            trusted_now_unix_ms: status.issued_at_unix_ms(),
        },
    )
    .map_err(obligation_error)?;
    if status_proof.envelope_digest() != commit.status_proof.envelope_digest() {
        return Err(invariant(
            "factor assignment status proof changed during verification",
        ));
    }
    let credit_admission = credit_admission_for_atom(transaction, status_head.atom())?;
    let claim = verify_receivable_claim(
        commit.claim.claim_canonical_bytes(),
        commit.claim.receipt_canonical_bytes(),
        commit.claim.iou_canonical_bytes(),
        &credit_admission,
        &ReceivableClaimVerificationV1 {
            atom: status_head.atom(),
            disposition: status_head.disposition(),
            settlement_lifecycle: status_head.settlement_lifecycle(),
            status_proof: &status_proof,
            trusted_now_unix_ms: commit.claim.claim().built_at_unix_ms(),
            trust: &authority.claim_trust,
        },
    )
    .map_err(factor_error)?;
    if claim.claim_digest() != commit.claim.claim_digest()
        || claim.receipt_digest() != commit.claim.receipt_digest()
        || claim.iou_digest() != commit.claim.iou_digest()
        || claim.trust_configuration_digest() != commit.claim.trust_configuration_digest()
    {
        return Err(invariant(
            "factor assignment claim changed during verification",
        ));
    }
    Ok(VerifiedFactorAssignmentSubmission {
        authorization,
        status_proof,
        claim,
    })
}

fn load_status_head(
    transaction: &Transaction<'_>,
    status: &chio_credit::obligation::ObligationStatusProofBodyV1,
) -> Result<DurableObligationV1, AdmissionOperationStoreError> {
    let _ = obligation::load_durable_obligation(transaction, status.obligation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let head = transaction
        .query_row(
            r#"
            SELECT head_sequence, head_digest
            FROM obligation_head_commits
            WHERE obligation_id = ?1
              AND disposition_version = ?2
              AND disposition_lifecycle_fence = ?3
              AND disposition_digest = ?4
              AND settlement_version = ?5
              AND settlement_lifecycle_fence = ?6
              AND settlement_lifecycle_digest = ?7
              AND snapshot_version = ?8
              AND resource_fence = ?9
            "#,
            params![
                status.obligation_id(),
                sqlite_i64(
                    status.disposition_version(),
                    "obligation_disposition_version"
                )?,
                sqlite_i64(
                    status.disposition_lifecycle_fence(),
                    "obligation_disposition_lifecycle_fence"
                )?,
                status.disposition_digest(),
                sqlite_i64(
                    status.settlement_lifecycle_version(),
                    "obligation_settlement_version"
                )?,
                sqlite_i64(
                    status.settlement_lifecycle_fence(),
                    "obligation_settlement_lifecycle_fence"
                )?,
                status.settlement_lifecycle_digest(),
                sqlite_i64(status.snapshot_version(), "obligation_snapshot_version")?,
                sqlite_i64(status.resource_fence(), "obligation_resource_fence")?,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("factor assignment status head is not durable"))?;
    obligation::load_durable_obligation_at_head(
        transaction,
        status.obligation_id(),
        stored_u64(head.0, "obligation_head_sequence")?,
        &head.1,
    )?
    .ok_or_else(|| invariant("factor assignment status head is not durable"))
}

fn classify_not_applied(
    current: &DurableObligationV1,
    submission: &VerifiedFactorAssignmentSubmission,
    request: &NormalizedAssignmentRequestV1,
    offer: &AssignmentOfferV1,
    trusted_now_unix_ms: u64,
) -> Result<Option<AssignmentNotAppliedReasonV1>, AdmissionOperationStoreError> {
    if trusted_now_unix_ms < submission.status_proof.body().issued_at_unix_ms()
        || trusted_now_unix_ms < submission.authorization.body().issued_at_unix_ms()
        || trusted_now_unix_ms < offer.issued_at_unix_ms()
        || trusted_now_unix_ms < request.effective_at_unix_ms()
    {
        return Err(invariant(
            "factor assignment artifacts are not yet effective",
        ));
    }
    classify_assignment_not_applied(&AssignmentNotAppliedClassificationV1 {
        atom: current.atom(),
        request,
        offer,
        authorization: &submission.authorization,
        status_proof: &submission.status_proof,
        observed_disposition: current.disposition(),
        observed_settlement_lifecycle: current.settlement_lifecycle(),
        observed_snapshot_version: current.snapshot_version(),
        observed_resource_fence: current.resource_fence(),
        decided_at_unix_ms: trusted_now_unix_ms,
    })
    .map_err(factor_error)
}

fn assignment_successor(
    operation: &AdmissionOperationV1,
    request: &NormalizedAssignmentRequestV1,
    current: &DurableObligationV1,
    submission: &VerifiedFactorAssignmentSubmission,
    trusted_now_unix_ms: u64,
) -> Result<ObligationDispositionRecordV1, AdmissionOperationStoreError> {
    let snapshot = ObligationAssignmentOperationSnapshotV1::new(
        operation.binding().operation_id().as_str().to_owned(),
        request.digest().map_err(factor_error)?,
        current.disposition(),
        current.settlement_lifecycle(),
        current.snapshot_version(),
        current.resource_fence(),
    )
    .map_err(obligation_error)?
    .attach_supplemental_authorization(&submission.authorization)
    .map_err(obligation_error)?;
    let assignment = ObligationAssignmentCasV1::new(
        snapshot,
        ObligationAssignmentCasInputV1 {
            schema: OBLIGATION_ASSIGNMENT_CAS_SCHEMA.to_owned(),
            operation_id: operation.binding().operation_id().as_str().to_owned(),
            normalized_request_digest: request.digest().map_err(factor_error)?,
            agreement_id: submission
                .authorization
                .agreement()
                .body()
                .agreement_id()
                .to_owned(),
            buyer_id: request.buyer_id().to_owned(),
            buyer_settlement_destination_ref: request.buyer_settlement_destination_ref().to_owned(),
            supplemental_authorization_digest: submission.authorization.digest().to_owned(),
            status_proof_digest: submission.status_proof.envelope_digest().to_owned(),
            effective_at_unix_ms: request.effective_at_unix_ms(),
        },
        submission.authorization.clone(),
        request,
    )
    .map_err(obligation_error)?;
    current
        .disposition()
        .compare_and_swap_assignment(
            current.atom(),
            current.settlement_lifecycle(),
            &submission.status_proof,
            &assignment,
            trusted_now_unix_ms,
        )
        .map_err(obligation_error)
}

fn build_acknowledgement(
    commit: &FactorAssignmentCommitV1<'_>,
    authority: &FactorAssignmentVerificationAuthorityV1,
    submission: &VerifiedFactorAssignmentSubmission,
    current: &DurableObligationV1,
    successor: &ObligationDispositionRecordV1,
) -> Result<VerifiedAssignmentAcknowledgementV1, AdmissionOperationStoreError> {
    let agreement = submission.authorization.agreement();
    let body = AssignmentAcknowledgementBodyV1::new(AssignmentAcknowledgementInputV1 {
        operation_id: commit
            .operation
            .binding()
            .operation_id()
            .as_str()
            .to_owned(),
        normalized_request_digest: commit.request.digest().map_err(factor_error)?,
        agreement_id: agreement.body().agreement_id().to_owned(),
        agreement_body_digest: agreement.body_digest().to_owned(),
        obligation_id: current.atom().obligation_id().to_owned(),
        obligation_atom_digest: current.atom().digest().map_err(obligation_error)?,
        buyer_id: commit.request.buyer_id().to_owned(),
        buyer_settlement_destination_ref: commit
            .request
            .buyer_settlement_destination_ref()
            .to_owned(),
        assignment_authorization_set_digest: submission.authorization.digest().to_owned(),
        status_proof_digest: submission.status_proof.envelope_digest().to_owned(),
        prior_disposition_version: current.disposition().version(),
        prior_disposition_lifecycle_fence: current.disposition().lifecycle_fence(),
        prior_disposition_digest: current
            .disposition()
            .digest(current.atom())
            .map_err(obligation_error)?,
        resulting_disposition_version: successor.version(),
        resulting_disposition_lifecycle_fence: successor.lifecycle_fence(),
        resulting_disposition_digest: successor.digest(current.atom()).map_err(obligation_error)?,
        expected_snapshot_version: current.snapshot_version(),
        resulting_snapshot_version: current
            .snapshot_version()
            .checked_add(1)
            .ok_or_else(|| invariant("factor assignment snapshot version overflow"))?,
        expected_resource_fence: current.resource_fence(),
        resulting_resource_fence: current
            .resource_fence()
            .checked_add(1)
            .ok_or_else(|| invariant("factor assignment resource fence overflow"))?,
        authority_id: authority.result_authority_id.clone(),
        authority_key_epoch: authority.result_authority_key_epoch,
        effective_at_unix_ms: commit.request.effective_at_unix_ms(),
        due_at_unix_ms: current.atom().due_at_unix_ms(),
        acknowledged_at_unix_ms: commit.trusted_now_unix_ms,
    })
    .map_err(factor_error)?;
    let signed = SignedAssignmentAcknowledgementV1::sign(body, &commit.signing_authority.signer)
        .map_err(factor_error)?;
    verify_assignment_acknowledgement(
        &signed.canonical_bytes().map_err(factor_error)?,
        &AssignmentAcknowledgementVerificationV1 {
            atom: current.atom(),
            request: commit.request,
            claim: &submission.claim,
            offer: commit.offer,
            authorization: &submission.authorization,
            status_proof: &submission.status_proof,
            resulting_disposition: successor,
            trust: &authority.result_trust,
        },
    )
    .map_err(factor_error)
}

fn build_not_applied(
    commit: &FactorAssignmentCommitV1<'_>,
    authority: &FactorAssignmentVerificationAuthorityV1,
    submission: &VerifiedFactorAssignmentSubmission,
    current: &DurableObligationV1,
    reason: AssignmentNotAppliedReasonV1,
) -> Result<VerifiedAssignmentNotAppliedV1, AdmissionOperationStoreError> {
    let agreement = submission.authorization.agreement();
    let body = AssignmentNotAppliedBodyV1::new(AssignmentNotAppliedInputV1 {
        operation_id: commit
            .operation
            .binding()
            .operation_id()
            .as_str()
            .to_owned(),
        normalized_request_digest: commit.request.digest().map_err(factor_error)?,
        agreement_id: agreement.body().agreement_id().to_owned(),
        agreement_body_digest: agreement.body_digest().to_owned(),
        obligation_id: current.atom().obligation_id().to_owned(),
        obligation_atom_digest: current.atom().digest().map_err(obligation_error)?,
        assignment_authorization_set_digest: submission.authorization.digest().to_owned(),
        status_proof_digest: submission.status_proof.envelope_digest().to_owned(),
        expected_disposition_version: commit.request.expected_disposition_version(),
        expected_disposition_lifecycle_fence: commit.request.expected_disposition_lifecycle_fence(),
        expected_settlement_lifecycle_version: commit
            .request
            .expected_settlement_lifecycle_version(),
        expected_settlement_lifecycle_fence: commit.request.expected_settlement_lifecycle_fence(),
        expected_snapshot_version: submission.status_proof.body().snapshot_version(),
        expected_resource_fence: submission.status_proof.body().resource_fence(),
        observed_disposition_version: current.disposition().version(),
        observed_disposition_lifecycle_fence: current.disposition().lifecycle_fence(),
        observed_disposition_digest: current
            .disposition()
            .digest(current.atom())
            .map_err(obligation_error)?,
        observed_settlement_lifecycle_version: current.settlement_lifecycle().version(),
        observed_settlement_lifecycle_fence: current.settlement_lifecycle().lifecycle_fence(),
        observed_settlement_lifecycle_digest: current
            .settlement_lifecycle()
            .digest(current.atom())
            .map_err(obligation_error)?,
        observed_snapshot_version: current.snapshot_version(),
        resource_fence: current.resource_fence(),
        reason,
        no_mutation_proof_digest: current.head_digest().to_owned(),
        authority_id: authority.result_authority_id.clone(),
        authority_key_epoch: authority.result_authority_key_epoch,
        decided_at_unix_ms: commit.trusted_now_unix_ms,
    })
    .map_err(factor_error)?;
    let signed = SignedAssignmentNotAppliedV1::sign(body, &commit.signing_authority.signer)
        .map_err(factor_error)?;
    verify_assignment_not_applied(
        &signed.canonical_bytes().map_err(factor_error)?,
        &AssignmentNotAppliedVerificationV1 {
            atom: current.atom(),
            request: commit.request,
            claim: &submission.claim,
            offer: commit.offer,
            authorization: &submission.authorization,
            status_proof: &submission.status_proof,
            observed_disposition: current.disposition(),
            observed_settlement_lifecycle: current.settlement_lifecycle(),
            observed_snapshot_version: current.snapshot_version(),
            observed_resource_fence: current.resource_fence(),
            no_mutation_proof_digest: current.head_digest(),
            trust: &authority.result_trust,
        },
    )
    .map_err(factor_error)
}

fn factor_error(error: FactorError) -> AdmissionOperationStoreError {
    invariant(format!("invalid factor assignment: {error}"))
}

fn obligation_error(error: ObligationError) -> AdmissionOperationStoreError {
    invariant(format!("invalid factor assignment obligation: {error}"))
}
