use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

mod credit_admission;
mod credit_facility_bind;
mod status;

pub use credit_admission::*;
pub use credit_facility_bind::*;
pub use status::*;

pub const OBLIGATION_ATOM_SCHEMA: &str = "chio.obligation.atom.v1";
pub const OBLIGATION_DISPOSITION_SCHEMA: &str = "chio.obligation.disposition.v1";
pub const OBLIGATION_CLAIM_INDEX_V1: u32 = 0;

const OBLIGATION_ID_DOMAIN: &str = "chio.obligation.id.v1";
const OBLIGATION_ATOM_DIGEST_DOMAIN: &[u8] = b"chio.obligation.atom.digest.v1\0";
const OBLIGATION_PAYEE_BINDING_DIGEST_DOMAIN: &[u8] = b"chio.obligation.payee-binding.digest.v1\0";
const OBLIGATION_DISPOSITION_DIGEST_DOMAIN: &[u8] = b"chio.obligation.disposition.digest.v1\0";
const OBLIGATION_TRANSITION_DIGEST_DOMAIN: &[u8] =
    b"chio.obligation.disposition-transition.digest.v1\0";
const MAX_TEXT_CHARS: usize = 2_048;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObligationPayeeBindingDigestBodyV1<'a> {
    beneficiary_id: &'a str,
    settlement_destination_ref: &'a str,
}

pub fn derive_obligation_payee_binding_digest(
    beneficiary_id: &str,
    settlement_destination_ref: &str,
) -> Result<String, ObligationError> {
    validate_text("payee_beneficiary_id", beneficiary_id)?;
    validate_text(
        "payee_settlement_destination_ref",
        settlement_destination_ref,
    )?;
    domain_digest(
        OBLIGATION_PAYEE_BINDING_DIGEST_DOMAIN,
        &ObligationPayeeBindingDigestBodyV1 {
            beneficiary_id,
            settlement_destination_ref,
        },
    )
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObligationError {
    #[error("invalid obligation field `{0}`")]
    InvalidField(&'static str),
    #[error("illegal obligation disposition transition")]
    IllegalDispositionTransition,
    #[error("assignment requires an exact supplemental authorization compare-and-swap")]
    AssignmentRequiresCompareAndSwap,
    #[error("obligation status proof authority verification failed")]
    StatusProofAuthorityVerification,
    #[error("obligation status proof is not current")]
    StatusProofNotCurrent,
    #[error("obligation compare-and-swap conflicted")]
    CompareAndSwapConflict,
    #[error("obligation assignment is missing supplemental authorization")]
    MissingSupplementalAuthorization,
    #[error("obligation assignment supplemental authorization does not match")]
    SupplementalAuthorizationMismatch,
    #[error("obligation canonicalization failed: {0}")]
    Canonicalization(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObligationCreditElectionV1 {
    NotCredit,
    CreditFacility {
        facility_id: String,
        authority_digest: String,
    },
}

impl ObligationCreditElectionV1 {
    fn validate(&self) -> Result<(), ObligationError> {
        match self {
            Self::NotCredit => Ok(()),
            Self::CreditFacility {
                facility_id,
                authority_digest,
            } => {
                validate_text("facility_id", facility_id)?;
                validate_digest("credit_authority_digest", authority_digest)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationAtomInputV1 {
    pub economic_intent_digest: String,
    pub source_receipt_id: String,
    pub source_receipt_digest: String,
    pub debtor_id: String,
    pub original_creditor_id: String,
    pub original_settlement_destination_ref: String,
    pub payee_binding_digest: String,
    pub amount: MonetaryAmount,
    pub credit_election: ObligationCreditElectionV1,
    pub pre_action_authority_digest: String,
    pub created_at_unix_ms: u64,
    pub due_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationAtomV1 {
    schema: String,
    obligation_id: String,
    claim_index: u32,
    economic_intent_digest: String,
    source_receipt_id: String,
    source_receipt_digest: String,
    debtor_id: String,
    original_creditor_id: String,
    original_settlement_destination_ref: String,
    payee_binding_digest: String,
    amount: MonetaryAmount,
    credit_election: ObligationCreditElectionV1,
    pre_action_authority_digest: String,
    created_at_unix_ms: u64,
    due_at_unix_ms: u64,
}

impl ObligationAtomV1 {
    pub fn new(input: ObligationAtomInputV1) -> Result<Self, ObligationError> {
        let obligation_id =
            derive_obligation_id(&input.economic_intent_digest, &input.source_receipt_digest)?;
        let atom = Self {
            schema: OBLIGATION_ATOM_SCHEMA.to_owned(),
            obligation_id,
            claim_index: OBLIGATION_CLAIM_INDEX_V1,
            economic_intent_digest: input.economic_intent_digest,
            source_receipt_id: input.source_receipt_id,
            source_receipt_digest: input.source_receipt_digest,
            debtor_id: input.debtor_id,
            original_creditor_id: input.original_creditor_id,
            original_settlement_destination_ref: input.original_settlement_destination_ref,
            payee_binding_digest: input.payee_binding_digest,
            amount: input.amount,
            credit_election: input.credit_election,
            pre_action_authority_digest: input.pre_action_authority_digest,
            created_at_unix_ms: input.created_at_unix_ms,
            due_at_unix_ms: input.due_at_unix_ms,
        };
        atom.validate()?;
        Ok(atom)
    }

    pub fn validate(&self) -> Result<(), ObligationError> {
        if self.schema != OBLIGATION_ATOM_SCHEMA {
            return Err(ObligationError::InvalidField("schema"));
        }
        if self.claim_index != OBLIGATION_CLAIM_INDEX_V1 {
            return Err(ObligationError::InvalidField("claim_index"));
        }
        validate_digest("economic_intent_digest", &self.economic_intent_digest)?;
        validate_text("source_receipt_id", &self.source_receipt_id)?;
        validate_digest("source_receipt_digest", &self.source_receipt_digest)?;
        validate_text("debtor_id", &self.debtor_id)?;
        validate_text("original_creditor_id", &self.original_creditor_id)?;
        validate_text(
            "original_settlement_destination_ref",
            &self.original_settlement_destination_ref,
        )?;
        validate_digest("payee_binding_digest", &self.payee_binding_digest)?;
        if derive_obligation_payee_binding_digest(
            &self.original_creditor_id,
            &self.original_settlement_destination_ref,
        )? != self.payee_binding_digest
        {
            return Err(ObligationError::InvalidField("payee_binding_digest"));
        }
        validate_money(&self.amount)?;
        self.credit_election.validate()?;
        validate_digest(
            "pre_action_authority_digest",
            &self.pre_action_authority_digest,
        )?;
        validate_time("created_at_unix_ms", self.created_at_unix_ms)?;
        validate_time("due_at_unix_ms", self.due_at_unix_ms)?;
        if self.debtor_id == self.original_creditor_id
            || self.due_at_unix_ms <= self.created_at_unix_ms
        {
            return Err(ObligationError::InvalidField("obligation_terms"));
        }
        if derive_obligation_id(&self.economic_intent_digest, &self.source_receipt_digest)?
            != self.obligation_id
        {
            return Err(ObligationError::InvalidField("obligation_id"));
        }
        Ok(())
    }

    #[must_use]
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }

    #[must_use]
    pub const fn claim_index(&self) -> u32 {
        self.claim_index
    }

    #[must_use]
    pub fn economic_intent_digest(&self) -> &str {
        &self.economic_intent_digest
    }

    #[must_use]
    pub fn source_receipt_id(&self) -> &str {
        &self.source_receipt_id
    }

    #[must_use]
    pub fn source_receipt_digest(&self) -> &str {
        &self.source_receipt_digest
    }

    #[must_use]
    pub fn debtor_id(&self) -> &str {
        &self.debtor_id
    }

    #[must_use]
    pub fn original_creditor_id(&self) -> &str {
        &self.original_creditor_id
    }

    #[must_use]
    pub fn original_settlement_destination_ref(&self) -> &str {
        &self.original_settlement_destination_ref
    }

    #[must_use]
    pub fn payee_binding_digest(&self) -> &str {
        &self.payee_binding_digest
    }

    #[must_use]
    pub const fn amount(&self) -> &MonetaryAmount {
        &self.amount
    }

    #[must_use]
    pub const fn credit_election(&self) -> &ObligationCreditElectionV1 {
        &self.credit_election
    }

    #[must_use]
    pub fn pre_action_authority_digest(&self) -> &str {
        &self.pre_action_authority_digest
    }

    #[must_use]
    pub const fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }

    pub fn digest(&self) -> Result<String, ObligationError> {
        self.validate()?;
        domain_digest(OBLIGATION_ATOM_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationCreditorBindingV1 {
    creditor_id: String,
    settlement_destination_ref: String,
}

impl ObligationCreditorBindingV1 {
    fn new(
        creditor_id: String,
        settlement_destination_ref: String,
    ) -> Result<Self, ObligationError> {
        validate_text("creditor_id", &creditor_id)?;
        validate_text("settlement_destination_ref", &settlement_destination_ref)?;
        Ok(Self {
            creditor_id,
            settlement_destination_ref,
        })
    }

    #[must_use]
    pub fn creditor_id(&self) -> &str {
        &self.creditor_id
    }

    #[must_use]
    pub fn settlement_destination_ref(&self) -> &str {
        &self.settlement_destination_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObligationDispositionV1 {
    PerCall,
    Assigned {
        agreement_id: String,
        creditor_id: String,
        settlement_destination_ref: String,
    },
    Channelized {
        channel_id: String,
        reservation_id: String,
    },
    ClearingReserved {
        round_id: String,
    },
    ClearingSatisfied {
        round_id: String,
        satisfaction_digest: String,
    },
}

impl ObligationDispositionV1 {
    fn validate(&self) -> Result<(), ObligationError> {
        match self {
            Self::PerCall => Ok(()),
            Self::Assigned {
                agreement_id,
                creditor_id,
                settlement_destination_ref,
            } => {
                validate_text("agreement_id", agreement_id)?;
                validate_text("creditor_id", creditor_id)?;
                validate_text("settlement_destination_ref", settlement_destination_ref)
            }
            Self::Channelized {
                channel_id,
                reservation_id,
            } => {
                validate_text("channel_id", channel_id)?;
                validate_text("reservation_id", reservation_id)
            }
            Self::ClearingReserved { round_id } => validate_text("round_id", round_id),
            Self::ClearingSatisfied {
                round_id,
                satisfaction_digest,
            } => {
                validate_text("round_id", round_id)?;
                validate_digest("satisfaction_digest", satisfaction_digest)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObligationDispositionTransitionV1 {
    Produced {
        authority_digest: String,
    },
    Assign {
        operation_id: String,
        normalized_request_digest: String,
        status_proof_digest: String,
        agreement_id: String,
        creditor_id: String,
        settlement_destination_ref: String,
        authority_digest: String,
    },
    ReserveChannel {
        channel_id: String,
        reservation_id: String,
        authority_digest: String,
    },
    ReserveClearing {
        round_id: String,
        authority_digest: String,
    },
    ReleaseClearing {
        round_id: String,
        abort_digest: String,
        zero_dispatch_proof_digest: String,
        authority_digest: String,
    },
    SatisfyClearing {
        round_id: String,
        satisfaction_digest: String,
        authority_digest: String,
    },
}

impl ObligationDispositionTransitionV1 {
    fn validate(&self) -> Result<(), ObligationError> {
        match self {
            Self::Produced { authority_digest } => {
                validate_digest("authority_digest", authority_digest)
            }
            Self::Assign {
                operation_id,
                normalized_request_digest,
                status_proof_digest,
                agreement_id,
                creditor_id,
                settlement_destination_ref,
                authority_digest,
            } => {
                validate_digest("assignment_operation_id", operation_id)?;
                validate_digest(
                    "assignment_normalized_request_digest",
                    normalized_request_digest,
                )?;
                validate_digest("assignment_status_proof_digest", status_proof_digest)?;
                validate_text("agreement_id", agreement_id)?;
                validate_text("creditor_id", creditor_id)?;
                validate_text("settlement_destination_ref", settlement_destination_ref)?;
                validate_digest("authority_digest", authority_digest)
            }
            Self::ReserveChannel {
                channel_id,
                reservation_id,
                authority_digest,
            } => {
                validate_text("channel_id", channel_id)?;
                validate_text("reservation_id", reservation_id)?;
                validate_digest("authority_digest", authority_digest)
            }
            Self::ReserveClearing {
                round_id,
                authority_digest,
            } => {
                validate_text("round_id", round_id)?;
                validate_digest("authority_digest", authority_digest)
            }
            Self::ReleaseClearing {
                round_id,
                abort_digest,
                zero_dispatch_proof_digest,
                authority_digest,
            } => {
                validate_text("round_id", round_id)?;
                validate_digest("abort_digest", abort_digest)?;
                validate_digest("zero_dispatch_proof_digest", zero_dispatch_proof_digest)?;
                validate_digest("authority_digest", authority_digest)
            }
            Self::SatisfyClearing {
                round_id,
                satisfaction_digest,
                authority_digest,
            } => {
                validate_text("round_id", round_id)?;
                validate_digest("satisfaction_digest", satisfaction_digest)?;
                validate_digest("authority_digest", authority_digest)
            }
        }
    }

    pub fn digest(&self) -> Result<String, ObligationError> {
        self.validate()?;
        domain_digest(OBLIGATION_TRANSITION_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationDispositionRecordV1 {
    schema: String,
    obligation_id: String,
    atom_digest: String,
    disposition: ObligationDispositionV1,
    version: u64,
    lifecycle_fence: u64,
    last_transition: ObligationDispositionTransitionV1,
}

impl ObligationDispositionRecordV1 {
    pub fn produced(atom: &ObligationAtomV1) -> Result<Self, ObligationError> {
        atom.validate()?;
        let record = Self {
            schema: OBLIGATION_DISPOSITION_SCHEMA.to_owned(),
            obligation_id: atom.obligation_id.clone(),
            atom_digest: atom.digest()?,
            disposition: ObligationDispositionV1::PerCall,
            version: 1,
            lifecycle_fence: 1,
            last_transition: ObligationDispositionTransitionV1::Produced {
                authority_digest: atom.pre_action_authority_digest.clone(),
            },
        };
        record.validate_against(atom)?;
        Ok(record)
    }

    pub fn advance(
        &self,
        atom: &ObligationAtomV1,
        transition: ObligationDispositionTransitionV1,
    ) -> Result<Self, ObligationError> {
        if matches!(transition, ObligationDispositionTransitionV1::Assign { .. }) {
            return Err(ObligationError::AssignmentRequiresCompareAndSwap);
        }
        self.advance_inner(atom, transition)
    }

    pub fn validate_successor(
        &self,
        atom: &ObligationAtomV1,
        successor: &Self,
    ) -> Result<(), ObligationError> {
        self.validate_against(atom)?;
        successor.validate_against(atom)?;
        let expected = match self.advance_inner(atom, successor.last_transition.clone()) {
            Ok(expected) => expected,
            Err(ObligationError::IllegalDispositionTransition) => {
                return Err(ObligationError::InvalidField("disposition_successor"));
            }
            Err(error) => return Err(error),
        };
        if &expected == successor {
            Ok(())
        } else {
            Err(ObligationError::InvalidField("disposition_successor"))
        }
    }

    pub(super) fn advance_assignment(
        &self,
        atom: &ObligationAtomV1,
        transition: ObligationDispositionTransitionV1,
    ) -> Result<Self, ObligationError> {
        if !matches!(transition, ObligationDispositionTransitionV1::Assign { .. }) {
            return Err(ObligationError::IllegalDispositionTransition);
        }
        self.advance_inner(atom, transition)
    }

    fn advance_inner(
        &self,
        atom: &ObligationAtomV1,
        transition: ObligationDispositionTransitionV1,
    ) -> Result<Self, ObligationError> {
        self.validate_against(atom)?;
        transition.validate()?;
        let disposition = match (&self.disposition, &transition) {
            (
                ObligationDispositionV1::PerCall,
                ObligationDispositionTransitionV1::Assign {
                    agreement_id,
                    creditor_id,
                    settlement_destination_ref,
                    ..
                },
            ) if creditor_id != atom.debtor_id() && creditor_id != atom.original_creditor_id() => {
                ObligationDispositionV1::Assigned {
                    agreement_id: agreement_id.clone(),
                    creditor_id: creditor_id.clone(),
                    settlement_destination_ref: settlement_destination_ref.clone(),
                }
            }
            (
                ObligationDispositionV1::PerCall,
                ObligationDispositionTransitionV1::ReserveChannel {
                    channel_id,
                    reservation_id,
                    ..
                },
            ) => ObligationDispositionV1::Channelized {
                channel_id: channel_id.clone(),
                reservation_id: reservation_id.clone(),
            },
            (
                ObligationDispositionV1::PerCall,
                ObligationDispositionTransitionV1::ReserveClearing { round_id, .. },
            ) => ObligationDispositionV1::ClearingReserved {
                round_id: round_id.clone(),
            },
            (
                ObligationDispositionV1::ClearingReserved { round_id },
                ObligationDispositionTransitionV1::ReleaseClearing {
                    round_id: released, ..
                },
            ) if round_id == released => ObligationDispositionV1::PerCall,
            (
                ObligationDispositionV1::ClearingReserved { round_id },
                ObligationDispositionTransitionV1::SatisfyClearing {
                    round_id: satisfied,
                    satisfaction_digest,
                    ..
                },
            ) if round_id == satisfied => ObligationDispositionV1::ClearingSatisfied {
                round_id: round_id.clone(),
                satisfaction_digest: satisfaction_digest.clone(),
            },
            _ => return Err(ObligationError::IllegalDispositionTransition),
        };
        let version = self
            .version
            .checked_add(1)
            .ok_or(ObligationError::InvalidField("version"))?;
        let lifecycle_fence = self
            .lifecycle_fence
            .checked_add(1)
            .ok_or(ObligationError::InvalidField("lifecycle_fence"))?;
        let next = Self {
            schema: self.schema.clone(),
            obligation_id: self.obligation_id.clone(),
            atom_digest: self.atom_digest.clone(),
            disposition,
            version,
            lifecycle_fence,
            last_transition: transition,
        };
        next.validate_against(atom)?;
        Ok(next)
    }

    pub fn validate_against(&self, atom: &ObligationAtomV1) -> Result<(), ObligationError> {
        atom.validate()?;
        if self.schema != OBLIGATION_DISPOSITION_SCHEMA {
            return Err(ObligationError::InvalidField("schema"));
        }
        validate_digest("obligation_id", &self.obligation_id)?;
        validate_digest("atom_digest", &self.atom_digest)?;
        if self.obligation_id != atom.obligation_id || self.atom_digest != atom.digest()? {
            return Err(ObligationError::InvalidField("atom_binding"));
        }
        validate_time("version", self.version)?;
        validate_time("lifecycle_fence", self.lifecycle_fence)?;
        if self.version != self.lifecycle_fence {
            return Err(ObligationError::InvalidField("lifecycle_fence"));
        }
        self.disposition.validate()?;
        self.last_transition.validate()?;
        let non_genesis = !matches!(
            &self.last_transition,
            ObligationDispositionTransitionV1::Produced { .. }
        );
        if non_genesis && self.version == 1 {
            return Err(ObligationError::InvalidField("disposition_transition"));
        }
        let valid = match (&self.disposition, &self.last_transition) {
            (
                ObligationDispositionV1::PerCall,
                ObligationDispositionTransitionV1::Produced { authority_digest },
            ) => {
                self.version == 1
                    && self.lifecycle_fence == 1
                    && authority_digest == atom.pre_action_authority_digest()
            }
            (
                ObligationDispositionV1::PerCall,
                ObligationDispositionTransitionV1::ReleaseClearing { .. },
            ) => self.version > 1,
            (
                ObligationDispositionV1::Assigned {
                    agreement_id,
                    creditor_id,
                    settlement_destination_ref,
                },
                ObligationDispositionTransitionV1::Assign {
                    agreement_id: transitioned_agreement,
                    creditor_id: transitioned_creditor,
                    settlement_destination_ref: transitioned_destination,
                    ..
                },
            ) => {
                agreement_id == transitioned_agreement
                    && creditor_id == transitioned_creditor
                    && settlement_destination_ref == transitioned_destination
                    && creditor_id != atom.debtor_id()
                    && creditor_id != atom.original_creditor_id()
            }
            (
                ObligationDispositionV1::Channelized {
                    channel_id,
                    reservation_id,
                },
                ObligationDispositionTransitionV1::ReserveChannel {
                    channel_id: transitioned_channel,
                    reservation_id: transitioned_reservation,
                    ..
                },
            ) => channel_id == transitioned_channel && reservation_id == transitioned_reservation,
            (
                ObligationDispositionV1::ClearingReserved { round_id },
                ObligationDispositionTransitionV1::ReserveClearing {
                    round_id: transitioned,
                    ..
                },
            ) => round_id == transitioned,
            (
                ObligationDispositionV1::ClearingSatisfied {
                    round_id,
                    satisfaction_digest,
                },
                ObligationDispositionTransitionV1::SatisfyClearing {
                    round_id: transitioned_round,
                    satisfaction_digest: transitioned_satisfaction,
                    ..
                },
            ) => round_id == transitioned_round && satisfaction_digest == transitioned_satisfaction,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(ObligationError::InvalidField("disposition_transition"))
        }
    }

    pub fn current_creditor(
        &self,
        atom: &ObligationAtomV1,
    ) -> Result<ObligationCreditorBindingV1, ObligationError> {
        self.validate_against(atom)?;
        match &self.disposition {
            ObligationDispositionV1::Assigned {
                creditor_id,
                settlement_destination_ref,
                ..
            } => ObligationCreditorBindingV1::new(
                creditor_id.clone(),
                settlement_destination_ref.clone(),
            ),
            _ => ObligationCreditorBindingV1::new(
                atom.original_creditor_id.clone(),
                atom.original_settlement_destination_ref.clone(),
            ),
        }
    }

    #[must_use]
    pub const fn disposition(&self) -> &ObligationDispositionV1 {
        &self.disposition
    }

    #[must_use]
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }

    #[must_use]
    pub fn atom_digest(&self) -> &str {
        &self.atom_digest
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn lifecycle_fence(&self) -> u64 {
        self.lifecycle_fence
    }

    #[must_use]
    pub const fn last_transition(&self) -> &ObligationDispositionTransitionV1 {
        &self.last_transition
    }

    pub fn digest(&self, atom: &ObligationAtomV1) -> Result<String, ObligationError> {
        self.validate_against(atom)?;
        domain_digest(OBLIGATION_DISPOSITION_DIGEST_DOMAIN, self)
    }
}

fn derive_obligation_id(
    economic_intent_digest: &str,
    source_receipt_digest: &str,
) -> Result<String, ObligationError> {
    validate_digest("economic_intent_digest", economic_intent_digest)?;
    validate_digest("source_receipt_digest", source_receipt_digest)?;
    let preimage = (
        OBLIGATION_ID_DOMAIN,
        economic_intent_digest,
        source_receipt_digest,
        OBLIGATION_CLAIM_INDEX_V1,
    );
    let bytes = canonical_json_bytes(&preimage)
        .map_err(|error| ObligationError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ObligationError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ObligationError::Canonicalization(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&bytes);
    Ok(sha256_hex(&preimage))
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ObligationError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_TEXT_CHARS
        || value.chars().any(char::is_control)
    {
        Err(ObligationError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), ObligationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ObligationError::InvalidField(field))
    }
}

fn validate_money(amount: &MonetaryAmount) -> Result<(), ObligationError> {
    if amount.units == 0
        || amount.units > I_JSON_MAX_SAFE_INTEGER
        || amount.currency.len() != 3
        || !amount
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        Err(ObligationError::InvalidField("amount"))
    } else {
        Ok(())
    }
}

fn validate_time(field: &'static str, value: u64) -> Result<(), ObligationError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(ObligationError::InvalidField(field))
    } else {
        Ok(())
    }
}
