use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::factor::{NormalizedAssignmentRequestV1, VerifiedAssignmentAuthorizationSetV1};

use super::{
    domain_digest, validate_digest, validate_text, validate_time, ObligationAtomV1,
    ObligationDispositionRecordV1, ObligationDispositionTransitionV1, ObligationDispositionV1,
    ObligationError,
};

pub const OBLIGATION_SETTLEMENT_LIFECYCLE_SCHEMA: &str = "chio.obligation.settlement-lifecycle.v1";
pub const OBLIGATION_STATUS_PROOF_SCHEMA: &str = "chio.obligation.status-proof.v1";
pub const OBLIGATION_ASSIGNMENT_OPERATION_SNAPSHOT_SCHEMA: &str =
    "chio.obligation.assignment-operation-snapshot.v1";
pub const OBLIGATION_ASSIGNMENT_CAS_SCHEMA: &str = "chio.obligation.assignment-cas.v1";

const SETTLEMENT_LIFECYCLE_DIGEST_DOMAIN: &[u8] =
    b"chio.obligation.settlement-lifecycle.digest.v1\0";
const STATUS_PROOF_ID_DOMAIN: &[u8] = b"chio.obligation.status-proof.id.v1\0";
const STATUS_PROOF_BODY_DIGEST_DOMAIN: &[u8] = b"chio.obligation.status-proof.body.v1\0";
const STATUS_PROOF_TRUST_CONFIGURATION_DOMAIN: &[u8] =
    b"chio.obligation.status-proof-trust.configuration.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObligationSettlementStateV1 {
    Pending,
    Settled {
        settlement_id: String,
        evidence_digest: String,
    },
    Failed {
        failure_digest: String,
    },
}

impl ObligationSettlementStateV1 {
    fn validate(&self) -> Result<(), ObligationError> {
        match self {
            Self::Pending => Ok(()),
            Self::Settled {
                settlement_id,
                evidence_digest,
            } => {
                validate_text("settlement_id", settlement_id)?;
                validate_digest("settlement_evidence_digest", evidence_digest)
            }
            Self::Failed { failure_digest } => {
                validate_digest("settlement_failure_digest", failure_digest)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObligationSettlementTransitionV1 {
    Produced {
        authority_digest: String,
    },
    Settle {
        settlement_id: String,
        evidence_digest: String,
        authority_digest: String,
    },
    Fail {
        failure_digest: String,
        authority_digest: String,
    },
}

impl ObligationSettlementTransitionV1 {
    fn validate(&self) -> Result<(), ObligationError> {
        match self {
            Self::Produced { authority_digest } => {
                validate_digest("settlement_authority_digest", authority_digest)
            }
            Self::Settle {
                settlement_id,
                evidence_digest,
                authority_digest,
            } => {
                validate_text("settlement_id", settlement_id)?;
                validate_digest("settlement_evidence_digest", evidence_digest)?;
                validate_digest("settlement_authority_digest", authority_digest)
            }
            Self::Fail {
                failure_digest,
                authority_digest,
            } => {
                validate_digest("settlement_failure_digest", failure_digest)?;
                validate_digest("settlement_authority_digest", authority_digest)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationSettlementLifecycleV1 {
    schema: String,
    obligation_id: String,
    atom_digest: String,
    state: ObligationSettlementStateV1,
    version: u64,
    lifecycle_fence: u64,
    last_transition: ObligationSettlementTransitionV1,
}

impl ObligationSettlementLifecycleV1 {
    pub fn pending(atom: &ObligationAtomV1) -> Result<Self, ObligationError> {
        atom.validate()?;
        let lifecycle = Self {
            schema: OBLIGATION_SETTLEMENT_LIFECYCLE_SCHEMA.to_owned(),
            obligation_id: atom.obligation_id().to_owned(),
            atom_digest: atom.digest()?,
            state: ObligationSettlementStateV1::Pending,
            version: 1,
            lifecycle_fence: 1,
            last_transition: ObligationSettlementTransitionV1::Produced {
                authority_digest: atom.pre_action_authority_digest().to_owned(),
            },
        };
        lifecycle.validate_against(atom)?;
        Ok(lifecycle)
    }

    pub fn advance(
        &self,
        atom: &ObligationAtomV1,
        transition: ObligationSettlementTransitionV1,
    ) -> Result<Self, ObligationError> {
        self.validate_against(atom)?;
        transition.validate()?;
        let state = match (&self.state, &transition) {
            (
                ObligationSettlementStateV1::Pending,
                ObligationSettlementTransitionV1::Settle {
                    settlement_id,
                    evidence_digest,
                    ..
                },
            ) => ObligationSettlementStateV1::Settled {
                settlement_id: settlement_id.clone(),
                evidence_digest: evidence_digest.clone(),
            },
            (
                ObligationSettlementStateV1::Pending,
                ObligationSettlementTransitionV1::Fail { failure_digest, .. },
            ) => ObligationSettlementStateV1::Failed {
                failure_digest: failure_digest.clone(),
            },
            _ => return Err(ObligationError::IllegalDispositionTransition),
        };
        let next = Self {
            schema: self.schema.clone(),
            obligation_id: self.obligation_id.clone(),
            atom_digest: self.atom_digest.clone(),
            state,
            version: self
                .version
                .checked_add(1)
                .ok_or(ObligationError::InvalidField("settlement_version"))?,
            lifecycle_fence: self
                .lifecycle_fence
                .checked_add(1)
                .ok_or(ObligationError::InvalidField("settlement_lifecycle_fence"))?,
            last_transition: transition,
        };
        next.validate_against(atom)?;
        Ok(next)
    }

    pub fn validate_successor(
        &self,
        atom: &ObligationAtomV1,
        successor: &Self,
    ) -> Result<(), ObligationError> {
        self.validate_against(atom)?;
        successor.validate_against(atom)?;
        let expected = self.advance(atom, successor.last_transition.clone())?;
        if &expected == successor {
            Ok(())
        } else {
            Err(ObligationError::InvalidField("settlement_successor"))
        }
    }

    pub fn validate_against(&self, atom: &ObligationAtomV1) -> Result<(), ObligationError> {
        atom.validate()?;
        if self.schema != OBLIGATION_SETTLEMENT_LIFECYCLE_SCHEMA {
            return Err(ObligationError::InvalidField("settlement_schema"));
        }
        validate_digest("settlement_obligation_id", &self.obligation_id)?;
        validate_digest("settlement_atom_digest", &self.atom_digest)?;
        if self.obligation_id != atom.obligation_id() || self.atom_digest != atom.digest()? {
            return Err(ObligationError::InvalidField("settlement_atom_binding"));
        }
        validate_time("settlement_version", self.version)?;
        validate_time("settlement_lifecycle_fence", self.lifecycle_fence)?;
        if self.version != self.lifecycle_fence {
            return Err(ObligationError::InvalidField("settlement_lifecycle_fence"));
        }
        self.state.validate()?;
        self.last_transition.validate()?;
        let valid = match (&self.state, &self.last_transition) {
            (
                ObligationSettlementStateV1::Pending,
                ObligationSettlementTransitionV1::Produced { authority_digest },
            ) => {
                self.version == 1
                    && self.lifecycle_fence == 1
                    && authority_digest == atom.pre_action_authority_digest()
            }
            (
                ObligationSettlementStateV1::Settled {
                    settlement_id,
                    evidence_digest,
                },
                ObligationSettlementTransitionV1::Settle {
                    settlement_id: transitioned_id,
                    evidence_digest: transitioned_evidence,
                    ..
                },
            ) => {
                self.version > 1
                    && settlement_id == transitioned_id
                    && evidence_digest == transitioned_evidence
            }
            (
                ObligationSettlementStateV1::Failed { failure_digest },
                ObligationSettlementTransitionV1::Fail {
                    failure_digest: transitioned_failure,
                    ..
                },
            ) => self.version > 1 && failure_digest == transitioned_failure,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(ObligationError::InvalidField("settlement_transition"))
        }
    }

    pub fn digest(&self, atom: &ObligationAtomV1) -> Result<String, ObligationError> {
        self.validate_against(atom)?;
        domain_digest(SETTLEMENT_LIFECYCLE_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub const fn state(&self) -> &ObligationSettlementStateV1 {
        &self.state
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn lifecycle_fence(&self) -> u64 {
        self.lifecycle_fence
    }
}

pub struct ObligationStatusProofContextV1<'a> {
    pub atom: &'a ObligationAtomV1,
    pub disposition: &'a ObligationDispositionRecordV1,
    pub settlement_lifecycle: &'a ObligationSettlementLifecycleV1,
    pub snapshot_version: u64,
    pub resource_fence: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub authority_id: &'a str,
    pub authority_key_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationStatusProofBodyV1 {
    schema: String,
    proof_id: String,
    obligation_id: String,
    obligation_atom_digest: String,
    debtor_id: String,
    original_creditor_id: String,
    current_creditor_id: String,
    current_settlement_destination_ref: String,
    disposition: ObligationDispositionV1,
    disposition_digest: String,
    disposition_version: u64,
    disposition_lifecycle_fence: u64,
    settlement_state: ObligationSettlementStateV1,
    settlement_lifecycle_digest: String,
    settlement_lifecycle_version: u64,
    settlement_lifecycle_fence: u64,
    snapshot_version: u64,
    resource_fence: u64,
    due_at_unix_ms: u64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    authority_id: String,
    authority_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObligationStatusProofIdPreimage<'a> {
    schema: &'a str,
    obligation_id: &'a str,
    obligation_atom_digest: &'a str,
    debtor_id: &'a str,
    original_creditor_id: &'a str,
    current_creditor_id: &'a str,
    current_settlement_destination_ref: &'a str,
    disposition: &'a ObligationDispositionV1,
    disposition_digest: &'a str,
    disposition_version: u64,
    disposition_lifecycle_fence: u64,
    settlement_state: &'a ObligationSettlementStateV1,
    settlement_lifecycle_digest: &'a str,
    settlement_lifecycle_version: u64,
    settlement_lifecycle_fence: u64,
    snapshot_version: u64,
    resource_fence: u64,
    due_at_unix_ms: u64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    authority_id: &'a str,
    authority_key_epoch: u64,
}

impl ObligationStatusProofBodyV1 {
    pub fn new(context: &ObligationStatusProofContextV1<'_>) -> Result<Self, ObligationError> {
        context.atom.validate()?;
        context.disposition.validate_against(context.atom)?;
        context
            .settlement_lifecycle
            .validate_against(context.atom)?;
        validate_time("snapshot_version", context.snapshot_version)?;
        validate_time("resource_fence", context.resource_fence)?;
        validate_time("issued_at_unix_ms", context.issued_at_unix_ms)?;
        validate_time("expires_at_unix_ms", context.expires_at_unix_ms)?;
        validate_text("status_authority_id", context.authority_id)?;
        validate_time("status_authority_key_epoch", context.authority_key_epoch)?;
        if context.issued_at_unix_ms < context.atom.created_at_unix_ms()
            || context.expires_at_unix_ms <= context.issued_at_unix_ms
            || context.expires_at_unix_ms > context.atom.due_at_unix_ms()
        {
            return Err(ObligationError::InvalidField("status_proof_window"));
        }
        let current = context.disposition.current_creditor(context.atom)?;
        let mut body = Self {
            schema: OBLIGATION_STATUS_PROOF_SCHEMA.to_owned(),
            proof_id: String::new(),
            obligation_id: context.atom.obligation_id().to_owned(),
            obligation_atom_digest: context.atom.digest()?,
            debtor_id: context.atom.debtor_id().to_owned(),
            original_creditor_id: context.atom.original_creditor_id().to_owned(),
            current_creditor_id: current.creditor_id().to_owned(),
            current_settlement_destination_ref: current.settlement_destination_ref().to_owned(),
            disposition: context.disposition.disposition().clone(),
            disposition_digest: context.disposition.digest(context.atom)?,
            disposition_version: context.disposition.version(),
            disposition_lifecycle_fence: context.disposition.lifecycle_fence(),
            settlement_state: context.settlement_lifecycle.state().clone(),
            settlement_lifecycle_digest: context.settlement_lifecycle.digest(context.atom)?,
            settlement_lifecycle_version: context.settlement_lifecycle.version(),
            settlement_lifecycle_fence: context.settlement_lifecycle.lifecycle_fence(),
            snapshot_version: context.snapshot_version,
            resource_fence: context.resource_fence,
            due_at_unix_ms: context.atom.due_at_unix_ms(),
            issued_at_unix_ms: context.issued_at_unix_ms,
            expires_at_unix_ms: context.expires_at_unix_ms,
            authority_id: context.authority_id.to_owned(),
            authority_key_epoch: context.authority_key_epoch,
        };
        body.proof_id = body.derived_proof_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), ObligationError> {
        if self.schema != OBLIGATION_STATUS_PROOF_SCHEMA {
            return Err(ObligationError::InvalidField("status_proof_schema"));
        }
        validate_digest("status_proof_id", &self.proof_id)?;
        validate_digest("status_obligation_id", &self.obligation_id)?;
        validate_digest("status_atom_digest", &self.obligation_atom_digest)?;
        validate_text("status_debtor_id", &self.debtor_id)?;
        validate_text("status_original_creditor_id", &self.original_creditor_id)?;
        validate_text("status_current_creditor_id", &self.current_creditor_id)?;
        validate_text(
            "status_current_settlement_destination_ref",
            &self.current_settlement_destination_ref,
        )?;
        self.disposition.validate()?;
        validate_digest("status_disposition_digest", &self.disposition_digest)?;
        validate_time("status_disposition_version", self.disposition_version)?;
        validate_time(
            "status_disposition_lifecycle_fence",
            self.disposition_lifecycle_fence,
        )?;
        self.settlement_state.validate()?;
        validate_digest(
            "status_settlement_lifecycle_digest",
            &self.settlement_lifecycle_digest,
        )?;
        validate_time(
            "status_settlement_lifecycle_version",
            self.settlement_lifecycle_version,
        )?;
        validate_time(
            "status_settlement_lifecycle_fence",
            self.settlement_lifecycle_fence,
        )?;
        validate_time("status_snapshot_version", self.snapshot_version)?;
        validate_time("status_resource_fence", self.resource_fence)?;
        validate_time("status_due_at_unix_ms", self.due_at_unix_ms)?;
        validate_time("status_issued_at_unix_ms", self.issued_at_unix_ms)?;
        validate_time("status_expires_at_unix_ms", self.expires_at_unix_ms)?;
        validate_text("status_authority_id", &self.authority_id)?;
        validate_time("status_authority_key_epoch", self.authority_key_epoch)?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms > self.due_at_unix_ms
            || self.proof_id != self.derived_proof_id()?
        {
            return Err(ObligationError::InvalidField("status_proof_binding"));
        }
        Ok(())
    }

    fn derived_proof_id(&self) -> Result<String, ObligationError> {
        domain_digest(
            STATUS_PROOF_ID_DOMAIN,
            &ObligationStatusProofIdPreimage {
                schema: &self.schema,
                obligation_id: &self.obligation_id,
                obligation_atom_digest: &self.obligation_atom_digest,
                debtor_id: &self.debtor_id,
                original_creditor_id: &self.original_creditor_id,
                current_creditor_id: &self.current_creditor_id,
                current_settlement_destination_ref: &self.current_settlement_destination_ref,
                disposition: &self.disposition,
                disposition_digest: &self.disposition_digest,
                disposition_version: self.disposition_version,
                disposition_lifecycle_fence: self.disposition_lifecycle_fence,
                settlement_state: &self.settlement_state,
                settlement_lifecycle_digest: &self.settlement_lifecycle_digest,
                settlement_lifecycle_version: self.settlement_lifecycle_version,
                settlement_lifecycle_fence: self.settlement_lifecycle_fence,
                snapshot_version: self.snapshot_version,
                resource_fence: self.resource_fence,
                due_at_unix_ms: self.due_at_unix_ms,
                issued_at_unix_ms: self.issued_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
                authority_id: &self.authority_id,
                authority_key_epoch: self.authority_key_epoch,
            },
        )
    }

    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    #[must_use]
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> &str {
        &self.obligation_atom_digest
    }

    #[must_use]
    pub fn current_creditor_id(&self) -> &str {
        &self.current_creditor_id
    }

    #[must_use]
    pub fn current_settlement_destination_ref(&self) -> &str {
        &self.current_settlement_destination_ref
    }

    #[must_use]
    pub const fn disposition(&self) -> &ObligationDispositionV1 {
        &self.disposition
    }

    #[must_use]
    pub const fn settlement_state(&self) -> &ObligationSettlementStateV1 {
        &self.settlement_state
    }

    #[must_use]
    pub fn disposition_digest(&self) -> &str {
        &self.disposition_digest
    }

    #[must_use]
    pub const fn disposition_version(&self) -> u64 {
        self.disposition_version
    }

    #[must_use]
    pub const fn disposition_lifecycle_fence(&self) -> u64 {
        self.disposition_lifecycle_fence
    }

    #[must_use]
    pub fn settlement_lifecycle_digest(&self) -> &str {
        &self.settlement_lifecycle_digest
    }

    #[must_use]
    pub const fn settlement_lifecycle_version(&self) -> u64 {
        self.settlement_lifecycle_version
    }

    #[must_use]
    pub const fn settlement_lifecycle_fence(&self) -> u64 {
        self.settlement_lifecycle_fence
    }

    #[must_use]
    pub const fn snapshot_version(&self) -> u64 {
        self.snapshot_version
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        self.resource_fence
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }

    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    #[must_use]
    pub const fn authority_key_epoch(&self) -> u64 {
        self.authority_key_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedObligationStatusProofV1(SignedExportEnvelope<ObligationStatusProofBodyV1>);

impl SignedObligationStatusProofV1 {
    pub fn sign(
        body: ObligationStatusProofBodyV1,
        signer: &Keypair,
    ) -> Result<Self, ObligationError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| ObligationError::Canonicalization(error.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ObligationError> {
        canonical_json_bytes(self)
            .map_err(|error| ObligationError::Canonicalization(error.to_string()))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ObligationError> {
        let signed: Self = serde_json::from_slice(bytes)
            .map_err(|error| ObligationError::Canonicalization(error.to_string()))?;
        if signed.canonical_bytes()?.as_slice() != bytes {
            return Err(ObligationError::Canonicalization(
                "obligation status proof is not canonical".to_owned(),
            ));
        }
        Ok(signed)
    }

    pub fn digest(&self) -> Result<String, ObligationError> {
        self.0.body.validate()?;
        self.canonical_bytes().map(|bytes| sha256_hex(&bytes))
    }

    #[must_use]
    pub const fn body(&self) -> &ObligationStatusProofBodyV1 {
        &self.0.body
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusProofTrustConfigurationPreimageV1<'a> {
    authority_id: &'a str,
    authority_key: String,
    authority_key_epoch: u64,
    max_proof_lifetime_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ObligationStatusProofTrustV1 {
    authority_id: String,
    authority_key: PublicKey,
    authority_key_epoch: u64,
    max_proof_lifetime_ms: u64,
    configuration_digest: String,
}

impl ObligationStatusProofTrustV1 {
    pub fn new(
        authority_id: String,
        authority_key: PublicKey,
        authority_key_epoch: u64,
        max_proof_lifetime_ms: u64,
    ) -> Result<Self, ObligationError> {
        validate_text("trusted_status_authority_id", &authority_id)?;
        validate_time("trusted_status_authority_key_epoch", authority_key_epoch)?;
        validate_time("max_status_proof_lifetime_ms", max_proof_lifetime_ms)?;
        let configuration_digest = domain_digest(
            STATUS_PROOF_TRUST_CONFIGURATION_DOMAIN,
            &StatusProofTrustConfigurationPreimageV1 {
                authority_id: &authority_id,
                authority_key: authority_key.to_hex(),
                authority_key_epoch,
                max_proof_lifetime_ms,
            },
        )?;
        Ok(Self {
            authority_id,
            authority_key,
            authority_key_epoch,
            max_proof_lifetime_ms,
            configuration_digest,
        })
    }

    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    #[must_use]
    pub const fn authority_key_epoch(&self) -> u64 {
        self.authority_key_epoch
    }

    #[must_use]
    pub const fn authority_key(&self) -> &PublicKey {
        &self.authority_key
    }

    #[must_use]
    pub const fn max_proof_lifetime_ms(&self) -> u64 {
        self.max_proof_lifetime_ms
    }

    #[must_use]
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedObligationStatusProofV1 {
    signed: SignedObligationStatusProofV1,
    body_digest: String,
    envelope_digest: String,
    canonical_bytes: Vec<u8>,
    trust_configuration_digest: String,
}

impl VerifiedObligationStatusProofV1 {
    #[must_use]
    pub const fn body(&self) -> &ObligationStatusProofBodyV1 {
        self.signed.body()
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn trust_configuration_digest(&self) -> &str {
        &self.trust_configuration_digest
    }

    #[must_use]
    pub const fn signer_key(&self) -> &PublicKey {
        &self.signed.0.signer_key
    }

    fn ensure_current(&self, trusted_now_unix_ms: u64) -> Result<(), ObligationError> {
        if trusted_now_unix_ms < self.body().issued_at_unix_ms
            || trusted_now_unix_ms >= self.body().expires_at_unix_ms
            || trusted_now_unix_ms >= self.body().due_at_unix_ms
        {
            return Err(ObligationError::StatusProofNotCurrent);
        }
        Ok(())
    }
}

pub struct ObligationStatusProofVerificationContextV1<'a> {
    pub atom: &'a ObligationAtomV1,
    pub disposition: &'a ObligationDispositionRecordV1,
    pub settlement_lifecycle: &'a ObligationSettlementLifecycleV1,
    pub snapshot_version: u64,
    pub resource_fence: u64,
    pub trust: &'a ObligationStatusProofTrustV1,
    pub trusted_now_unix_ms: u64,
}

pub fn verify_obligation_status_proof(
    canonical_envelope: &[u8],
    context: &ObligationStatusProofVerificationContextV1<'_>,
) -> Result<VerifiedObligationStatusProofV1, ObligationError> {
    let signed = SignedObligationStatusProofV1::from_canonical_bytes(canonical_envelope)?;
    signed.body().validate()?;
    if signed.0.signer_key != context.trust.authority_key
        || signed.body().authority_id != context.trust.authority_id
        || signed.body().authority_key_epoch != context.trust.authority_key_epoch
        || !signed
            .0
            .verify_signature()
            .map_err(|error| ObligationError::Canonicalization(error.to_string()))?
    {
        return Err(ObligationError::StatusProofAuthorityVerification);
    }
    let proof_lifetime = signed
        .body()
        .expires_at_unix_ms
        .checked_sub(signed.body().issued_at_unix_ms)
        .ok_or(ObligationError::StatusProofNotCurrent)?;
    if proof_lifetime > context.trust.max_proof_lifetime_ms {
        return Err(ObligationError::StatusProofNotCurrent);
    }
    let expected = ObligationStatusProofBodyV1::new(&ObligationStatusProofContextV1 {
        atom: context.atom,
        disposition: context.disposition,
        settlement_lifecycle: context.settlement_lifecycle,
        snapshot_version: context.snapshot_version,
        resource_fence: context.resource_fence,
        issued_at_unix_ms: signed.body().issued_at_unix_ms,
        expires_at_unix_ms: signed.body().expires_at_unix_ms,
        authority_id: &context.trust.authority_id,
        authority_key_epoch: context.trust.authority_key_epoch,
    })?;
    if signed.body() != &expected {
        return Err(ObligationError::StatusProofAuthorityVerification);
    }
    let verified = VerifiedObligationStatusProofV1 {
        body_digest: domain_digest(STATUS_PROOF_BODY_DIGEST_DOMAIN, signed.body())?,
        envelope_digest: signed.digest()?,
        canonical_bytes: canonical_envelope.to_vec(),
        trust_configuration_digest: context.trust.configuration_digest().to_owned(),
        signed,
    };
    verified.ensure_current(context.trusted_now_unix_ms)?;
    Ok(verified)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationAssignmentOperationSnapshotV1 {
    schema: String,
    operation_id: String,
    normalized_request_digest: String,
    expected_disposition_version: u64,
    expected_disposition_lifecycle_fence: u64,
    expected_settlement_lifecycle_version: u64,
    expected_settlement_lifecycle_fence: u64,
    expected_snapshot_version: u64,
    expected_resource_fence: u64,
    supplemental_authorization_digest: Option<String>,
}

impl ObligationAssignmentOperationSnapshotV1 {
    pub fn new(
        operation_id: String,
        normalized_request_digest: String,
        disposition: &ObligationDispositionRecordV1,
        settlement_lifecycle: &ObligationSettlementLifecycleV1,
        snapshot_version: u64,
        resource_fence: u64,
    ) -> Result<Self, ObligationError> {
        let operation = Self {
            schema: OBLIGATION_ASSIGNMENT_OPERATION_SNAPSHOT_SCHEMA.to_owned(),
            operation_id,
            normalized_request_digest,
            expected_disposition_version: disposition.version(),
            expected_disposition_lifecycle_fence: disposition.lifecycle_fence(),
            expected_settlement_lifecycle_version: settlement_lifecycle.version(),
            expected_settlement_lifecycle_fence: settlement_lifecycle.lifecycle_fence(),
            expected_snapshot_version: snapshot_version,
            expected_resource_fence: resource_fence,
            supplemental_authorization_digest: None,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub fn attach_supplemental_authorization(
        &self,
        authorization: &VerifiedAssignmentAuthorizationSetV1,
    ) -> Result<Self, ObligationError> {
        if authorization.body().operation_id() != self.operation_id
            || authorization.body().normalized_request_digest() != self.normalized_request_digest
        {
            return Err(ObligationError::SupplementalAuthorizationMismatch);
        }
        let digest = authorization.digest();
        match self.supplemental_authorization_digest.as_deref() {
            Some(attached) if attached != digest => {
                Err(ObligationError::SupplementalAuthorizationMismatch)
            }
            Some(_) => Ok(self.clone()),
            None => {
                let mut attached = self.clone();
                attached.supplemental_authorization_digest = Some(digest.to_owned());
                Ok(attached)
            }
        }
    }

    fn validate(&self) -> Result<(), ObligationError> {
        if self.schema != OBLIGATION_ASSIGNMENT_OPERATION_SNAPSHOT_SCHEMA {
            return Err(ObligationError::InvalidField("assignment_operation_schema"));
        }
        validate_digest("assignment_operation_id", &self.operation_id)?;
        validate_digest(
            "assignment_normalized_request_digest",
            &self.normalized_request_digest,
        )?;
        validate_time(
            "assignment_expected_disposition_version",
            self.expected_disposition_version,
        )?;
        validate_time(
            "assignment_expected_disposition_lifecycle_fence",
            self.expected_disposition_lifecycle_fence,
        )?;
        validate_time(
            "assignment_expected_settlement_lifecycle_version",
            self.expected_settlement_lifecycle_version,
        )?;
        validate_time(
            "assignment_expected_settlement_lifecycle_fence",
            self.expected_settlement_lifecycle_fence,
        )?;
        validate_time(
            "assignment_expected_snapshot_version",
            self.expected_snapshot_version,
        )?;
        validate_time(
            "assignment_expected_resource_fence",
            self.expected_resource_fence,
        )?;
        if let Some(digest) = &self.supplemental_authorization_digest {
            validate_digest("supplemental_authorization_digest", digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationAssignmentCasInputV1 {
    pub schema: String,
    pub operation_id: String,
    pub normalized_request_digest: String,
    pub agreement_id: String,
    pub buyer_id: String,
    pub buyer_settlement_destination_ref: String,
    pub supplemental_authorization_digest: String,
    pub status_proof_digest: String,
    pub effective_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationAssignmentCasV1 {
    operation: ObligationAssignmentOperationSnapshotV1,
    input: ObligationAssignmentCasInputV1,
    authorization: VerifiedAssignmentAuthorizationSetV1,
}

impl ObligationAssignmentCasV1 {
    pub fn new(
        operation: ObligationAssignmentOperationSnapshotV1,
        input: ObligationAssignmentCasInputV1,
        authorization: VerifiedAssignmentAuthorizationSetV1,
        request: &NormalizedAssignmentRequestV1,
    ) -> Result<Self, ObligationError> {
        operation.validate()?;
        request
            .validate()
            .map_err(|_| ObligationError::CompareAndSwapConflict)?;
        authorization
            .agreement()
            .body()
            .validate_against_request(request)
            .map_err(|_| ObligationError::CompareAndSwapConflict)?;
        if input.schema != OBLIGATION_ASSIGNMENT_CAS_SCHEMA {
            return Err(ObligationError::InvalidField("assignment_cas_schema"));
        }
        validate_digest("assignment_operation_id", &input.operation_id)?;
        validate_digest(
            "assignment_normalized_request_digest",
            &input.normalized_request_digest,
        )?;
        validate_text("assignment_agreement_id", &input.agreement_id)?;
        validate_text("assignment_buyer_id", &input.buyer_id)?;
        validate_text(
            "assignment_buyer_settlement_destination_ref",
            &input.buyer_settlement_destination_ref,
        )?;
        validate_digest(
            "supplemental_authorization_digest",
            &input.supplemental_authorization_digest,
        )?;
        validate_digest("assignment_status_proof_digest", &input.status_proof_digest)?;
        validate_time(
            "assignment_effective_at_unix_ms",
            input.effective_at_unix_ms,
        )?;
        if operation.operation_id != input.operation_id
            || operation.normalized_request_digest != input.normalized_request_digest
            || request
                .digest()
                .map_err(|_| ObligationError::CompareAndSwapConflict)?
                != input.normalized_request_digest
            || request.expected_disposition_version() != operation.expected_disposition_version
            || request.expected_disposition_lifecycle_fence()
                != operation.expected_disposition_lifecycle_fence
            || request.expected_settlement_lifecycle_version()
                != operation.expected_settlement_lifecycle_version
            || request.expected_settlement_lifecycle_fence()
                != operation.expected_settlement_lifecycle_fence
            || authorization.body().operation_id() != input.operation_id
            || authorization.body().normalized_request_digest() != input.normalized_request_digest
            || authorization.body().buyer_id() != input.buyer_id
            || authorization.body().agreement_id() != input.agreement_id
            || authorization.body().buyer_settlement_destination_ref()
                != input.buyer_settlement_destination_ref
            || authorization.body().effective_at_unix_ms() != input.effective_at_unix_ms
            || request.buyer_id() != input.buyer_id
            || request.buyer_settlement_destination_ref() != input.buyer_settlement_destination_ref
            || request.effective_at_unix_ms() != input.effective_at_unix_ms
        {
            return Err(ObligationError::CompareAndSwapConflict);
        }
        match operation.supplemental_authorization_digest.as_deref() {
            None => return Err(ObligationError::MissingSupplementalAuthorization),
            Some(attached)
                if attached != input.supplemental_authorization_digest
                    || attached != authorization.digest() =>
            {
                return Err(ObligationError::SupplementalAuthorizationMismatch);
            }
            Some(_) => {}
        }
        Ok(Self {
            operation,
            input,
            authorization,
        })
    }
}

impl ObligationDispositionRecordV1 {
    pub fn compare_and_swap_assignment(
        &self,
        atom: &ObligationAtomV1,
        settlement_lifecycle: &ObligationSettlementLifecycleV1,
        status_proof: &VerifiedObligationStatusProofV1,
        assignment: &ObligationAssignmentCasV1,
        trusted_now_unix_ms: u64,
    ) -> Result<Self, ObligationError> {
        self.validate_against(atom)?;
        let operation = &assignment.operation;
        let input = &assignment.input;
        if matches!(self.disposition(), ObligationDispositionV1::Assigned { .. }) {
            return Err(ObligationError::CompareAndSwapConflict);
        }
        settlement_lifecycle.validate_against(atom)?;
        status_proof.ensure_current(trusted_now_unix_ms)?;
        assignment
            .authorization
            .ensure_current(trusted_now_unix_ms)
            .map_err(|_| ObligationError::SupplementalAuthorizationMismatch)?;
        if assignment.authorization.body().obligation_atom_digest() != atom.digest()?
            || assignment.authorization.body().seller_id() != atom.original_creditor_id()
            || assignment.authorization.body().buyer_id() != input.buyer_id
        {
            return Err(ObligationError::SupplementalAuthorizationMismatch);
        }
        if input.status_proof_digest != status_proof.envelope_digest
            || status_proof.body().obligation_id != atom.obligation_id()
            || status_proof.body().obligation_atom_digest != atom.digest()?
            || status_proof.body().snapshot_version != operation.expected_snapshot_version
            || status_proof.body().resource_fence != operation.expected_resource_fence
            || status_proof.body().settlement_lifecycle_version
                != operation.expected_settlement_lifecycle_version
            || status_proof.body().settlement_lifecycle_fence
                != operation.expected_settlement_lifecycle_fence
            || settlement_lifecycle.version() != operation.expected_settlement_lifecycle_version
            || settlement_lifecycle.lifecycle_fence()
                != operation.expected_settlement_lifecycle_fence
            || status_proof.body().settlement_state != *settlement_lifecycle.state()
            || status_proof.body().settlement_lifecycle_digest
                != settlement_lifecycle.digest(atom)?
            || input.effective_at_unix_ms < status_proof.body().issued_at_unix_ms
            || input.effective_at_unix_ms >= status_proof.body().expires_at_unix_ms
            || input.effective_at_unix_ms >= atom.due_at_unix_ms()
            || input.effective_at_unix_ms > trusted_now_unix_ms
        {
            return Err(ObligationError::CompareAndSwapConflict);
        }
        if self.version != operation.expected_disposition_version
            || self.lifecycle_fence != operation.expected_disposition_lifecycle_fence
            || status_proof.body().disposition_version != operation.expected_disposition_version
            || status_proof.body().disposition_lifecycle_fence
                != operation.expected_disposition_lifecycle_fence
            || status_proof.body().disposition != *self.disposition()
            || status_proof.body().disposition_digest != self.digest(atom)?
            || !matches!(self.disposition(), ObligationDispositionV1::PerCall)
            || !matches!(
                settlement_lifecycle.state(),
                ObligationSettlementStateV1::Pending
            )
            || status_proof.body().current_creditor_id != atom.original_creditor_id()
        {
            return Err(ObligationError::CompareAndSwapConflict);
        }
        self.advance_assignment(
            atom,
            ObligationDispositionTransitionV1::Assign {
                operation_id: input.operation_id.clone(),
                normalized_request_digest: input.normalized_request_digest.clone(),
                status_proof_digest: input.status_proof_digest.clone(),
                agreement_id: input.agreement_id.clone(),
                creditor_id: input.buyer_id.clone(),
                settlement_destination_ref: input.buyer_settlement_destination_ref.clone(),
                authority_digest: input.supplemental_authorization_digest.clone(),
            },
        )
    }
}
