use super::*;
use crate::obligation::{
    ObligationAtomV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
    ObligationDispositionV1, ObligationSettlementLifecycleV1, ObligationSettlementStateV1,
    VerifiedObligationStatusProofV1,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentAcknowledgementInputV1 {
    pub operation_id: String,
    pub normalized_request_digest: String,
    pub agreement_id: String,
    pub agreement_body_digest: String,
    pub obligation_id: String,
    pub obligation_atom_digest: String,
    pub buyer_id: String,
    pub buyer_settlement_destination_ref: String,
    pub assignment_authorization_set_digest: String,
    pub status_proof_digest: String,
    pub prior_disposition_version: u64,
    pub prior_disposition_lifecycle_fence: u64,
    pub prior_disposition_digest: String,
    pub resulting_disposition_version: u64,
    pub resulting_disposition_lifecycle_fence: u64,
    pub resulting_disposition_digest: String,
    pub expected_snapshot_version: u64,
    pub resulting_snapshot_version: u64,
    pub expected_resource_fence: u64,
    pub resulting_resource_fence: u64,
    pub authority_id: String,
    pub authority_key_epoch: u64,
    pub effective_at_unix_ms: u64,
    pub due_at_unix_ms: u64,
    pub acknowledged_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentAcknowledgementBodyV1 {
    schema: String,
    acknowledgement_id: String,
    operation_id: String,
    normalized_request_digest: String,
    agreement_id: String,
    agreement_body_digest: String,
    obligation_id: String,
    obligation_atom_digest: String,
    prior_disposition_kind: String,
    buyer_id: String,
    buyer_settlement_destination_ref: String,
    assignment_authorization_set_digest: String,
    status_proof_digest: String,
    prior_disposition_version: u64,
    prior_disposition_lifecycle_fence: u64,
    prior_disposition_digest: String,
    resulting_disposition_version: u64,
    resulting_disposition_lifecycle_fence: u64,
    resulting_disposition_digest: String,
    expected_snapshot_version: u64,
    resulting_snapshot_version: u64,
    expected_resource_fence: u64,
    resulting_resource_fence: u64,
    authority_id: String,
    authority_key_epoch: u64,
    effective_at_unix_ms: u64,
    due_at_unix_ms: u64,
    acknowledged_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentAcknowledgementIdPreimage<'a> {
    schema: &'a str,
    operation_id: &'a str,
    normalized_request_digest: &'a str,
    agreement_id: &'a str,
    agreement_body_digest: &'a str,
    obligation_id: &'a str,
    obligation_atom_digest: &'a str,
    prior_disposition_kind: &'a str,
    buyer_id: &'a str,
    buyer_settlement_destination_ref: &'a str,
    assignment_authorization_set_digest: &'a str,
    status_proof_digest: &'a str,
    prior_disposition_version: u64,
    prior_disposition_lifecycle_fence: u64,
    prior_disposition_digest: &'a str,
    resulting_disposition_version: u64,
    resulting_disposition_lifecycle_fence: u64,
    resulting_disposition_digest: &'a str,
    expected_snapshot_version: u64,
    resulting_snapshot_version: u64,
    expected_resource_fence: u64,
    resulting_resource_fence: u64,
    authority_id: &'a str,
    authority_key_epoch: u64,
    effective_at_unix_ms: u64,
    due_at_unix_ms: u64,
    acknowledged_at_unix_ms: u64,
}

impl AssignmentAcknowledgementBodyV1 {
    pub fn new(input: AssignmentAcknowledgementInputV1) -> Result<Self, FactorError> {
        let mut body = Self {
            schema: FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
            acknowledgement_id: String::new(),
            operation_id: input.operation_id,
            normalized_request_digest: input.normalized_request_digest,
            agreement_id: input.agreement_id,
            agreement_body_digest: input.agreement_body_digest,
            obligation_id: input.obligation_id,
            obligation_atom_digest: input.obligation_atom_digest,
            prior_disposition_kind: "per_call".to_owned(),
            buyer_id: input.buyer_id,
            buyer_settlement_destination_ref: input.buyer_settlement_destination_ref,
            assignment_authorization_set_digest: input.assignment_authorization_set_digest,
            status_proof_digest: input.status_proof_digest,
            prior_disposition_version: input.prior_disposition_version,
            prior_disposition_lifecycle_fence: input.prior_disposition_lifecycle_fence,
            prior_disposition_digest: input.prior_disposition_digest,
            resulting_disposition_version: input.resulting_disposition_version,
            resulting_disposition_lifecycle_fence: input.resulting_disposition_lifecycle_fence,
            resulting_disposition_digest: input.resulting_disposition_digest,
            expected_snapshot_version: input.expected_snapshot_version,
            resulting_snapshot_version: input.resulting_snapshot_version,
            expected_resource_fence: input.expected_resource_fence,
            resulting_resource_fence: input.resulting_resource_fence,
            authority_id: input.authority_id,
            authority_key_epoch: input.authority_key_epoch,
            effective_at_unix_ms: input.effective_at_unix_ms,
            due_at_unix_ms: input.due_at_unix_ms,
            acknowledged_at_unix_ms: input.acknowledged_at_unix_ms,
        };
        body.acknowledgement_id = body.derived_acknowledgement_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_SCHEMA {
            return Err(FactorError::InvalidField("acknowledgement_schema"));
        }
        if self.prior_disposition_kind != "per_call" {
            return Err(FactorError::InvalidField("prior_disposition_kind"));
        }
        for (field, value) in [
            ("acknowledgement_id", &self.acknowledgement_id),
            ("operation_id", &self.operation_id),
            ("normalized_request_digest", &self.normalized_request_digest),
            ("agreement_body_digest", &self.agreement_body_digest),
            ("obligation_id", &self.obligation_id),
            ("obligation_atom_digest", &self.obligation_atom_digest),
            (
                "assignment_authorization_set_digest",
                &self.assignment_authorization_set_digest,
            ),
            ("status_proof_digest", &self.status_proof_digest),
            ("prior_disposition_digest", &self.prior_disposition_digest),
            (
                "resulting_disposition_digest",
                &self.resulting_disposition_digest,
            ),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("agreement_id", &self.agreement_id),
            ("buyer_id", &self.buyer_id),
            (
                "buyer_settlement_destination_ref",
                &self.buyer_settlement_destination_ref,
            ),
            ("authority_id", &self.authority_id),
        ] {
            validate_text(field, value)?;
        }
        for (field, value) in [
            ("prior_disposition_version", self.prior_disposition_version),
            (
                "prior_disposition_lifecycle_fence",
                self.prior_disposition_lifecycle_fence,
            ),
            (
                "resulting_disposition_version",
                self.resulting_disposition_version,
            ),
            (
                "resulting_disposition_lifecycle_fence",
                self.resulting_disposition_lifecycle_fence,
            ),
            ("expected_snapshot_version", self.expected_snapshot_version),
            (
                "resulting_snapshot_version",
                self.resulting_snapshot_version,
            ),
            ("expected_resource_fence", self.expected_resource_fence),
            ("resulting_resource_fence", self.resulting_resource_fence),
            ("authority_key_epoch", self.authority_key_epoch),
            ("effective_at_unix_ms", self.effective_at_unix_ms),
            ("due_at_unix_ms", self.due_at_unix_ms),
            ("acknowledged_at_unix_ms", self.acknowledged_at_unix_ms),
        ] {
            validate_positive(field, value)?;
        }
        if self.prior_disposition_version != self.prior_disposition_lifecycle_fence
            || self.resulting_disposition_version != self.resulting_disposition_lifecycle_fence
            || self.resulting_disposition_version
                != self
                    .prior_disposition_version
                    .checked_add(1)
                    .ok_or(FactorError::ArithmeticOverflow)?
            || self.resulting_snapshot_version
                != self
                    .expected_snapshot_version
                    .checked_add(1)
                    .ok_or(FactorError::ArithmeticOverflow)?
            || self.resulting_resource_fence
                != self
                    .expected_resource_fence
                    .checked_add(1)
                    .ok_or(FactorError::ArithmeticOverflow)?
            || self.effective_at_unix_ms > self.acknowledged_at_unix_ms
            || self.acknowledged_at_unix_ms >= self.due_at_unix_ms
            || self.acknowledgement_id != self.derived_acknowledgement_id()?
        {
            return Err(FactorError::InvalidField("acknowledgement_terms"));
        }
        Ok(())
    }

    fn derived_acknowledgement_id(&self) -> Result<String, FactorError> {
        domain_digest(
            ACKNOWLEDGEMENT_ID_DOMAIN,
            &AssignmentAcknowledgementIdPreimage {
                schema: &self.schema,
                operation_id: &self.operation_id,
                normalized_request_digest: &self.normalized_request_digest,
                agreement_id: &self.agreement_id,
                agreement_body_digest: &self.agreement_body_digest,
                obligation_id: &self.obligation_id,
                obligation_atom_digest: &self.obligation_atom_digest,
                prior_disposition_kind: &self.prior_disposition_kind,
                buyer_id: &self.buyer_id,
                buyer_settlement_destination_ref: &self.buyer_settlement_destination_ref,
                assignment_authorization_set_digest: &self.assignment_authorization_set_digest,
                status_proof_digest: &self.status_proof_digest,
                prior_disposition_version: self.prior_disposition_version,
                prior_disposition_lifecycle_fence: self.prior_disposition_lifecycle_fence,
                prior_disposition_digest: &self.prior_disposition_digest,
                resulting_disposition_version: self.resulting_disposition_version,
                resulting_disposition_lifecycle_fence: self.resulting_disposition_lifecycle_fence,
                resulting_disposition_digest: &self.resulting_disposition_digest,
                expected_snapshot_version: self.expected_snapshot_version,
                resulting_snapshot_version: self.resulting_snapshot_version,
                expected_resource_fence: self.expected_resource_fence,
                resulting_resource_fence: self.resulting_resource_fence,
                authority_id: &self.authority_id,
                authority_key_epoch: self.authority_key_epoch,
                effective_at_unix_ms: self.effective_at_unix_ms,
                due_at_unix_ms: self.due_at_unix_ms,
                acknowledged_at_unix_ms: self.acknowledged_at_unix_ms,
            },
        )
    }

    pub fn digest(&self) -> Result<String, FactorError> {
        self.validate()?;
        domain_digest(ACKNOWLEDGEMENT_BODY_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn acknowledgement_id(&self) -> &str {
        &self.acknowledgement_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn normalized_request_digest(&self) -> &str {
        &self.normalized_request_digest
    }

    #[must_use]
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }

    #[must_use]
    pub fn agreement_id(&self) -> &str {
        &self.agreement_id
    }

    #[must_use]
    pub fn agreement_body_digest(&self) -> &str {
        &self.agreement_body_digest
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> &str {
        &self.obligation_atom_digest
    }

    #[must_use]
    pub fn prior_disposition_kind(&self) -> &str {
        &self.prior_disposition_kind
    }

    #[must_use]
    pub fn buyer_id(&self) -> &str {
        &self.buyer_id
    }

    #[must_use]
    pub fn buyer_settlement_destination_ref(&self) -> &str {
        &self.buyer_settlement_destination_ref
    }

    #[must_use]
    pub fn assignment_authorization_set_digest(&self) -> &str {
        &self.assignment_authorization_set_digest
    }

    #[must_use]
    pub fn status_proof_digest(&self) -> &str {
        &self.status_proof_digest
    }

    #[must_use]
    pub const fn prior_disposition_version(&self) -> u64 {
        self.prior_disposition_version
    }

    #[must_use]
    pub const fn prior_disposition_lifecycle_fence(&self) -> u64 {
        self.prior_disposition_lifecycle_fence
    }

    #[must_use]
    pub fn prior_disposition_digest(&self) -> &str {
        &self.prior_disposition_digest
    }

    #[must_use]
    pub const fn resulting_disposition_version(&self) -> u64 {
        self.resulting_disposition_version
    }

    #[must_use]
    pub const fn resulting_disposition_lifecycle_fence(&self) -> u64 {
        self.resulting_disposition_lifecycle_fence
    }

    #[must_use]
    pub fn resulting_disposition_digest(&self) -> &str {
        &self.resulting_disposition_digest
    }

    #[must_use]
    pub const fn expected_snapshot_version(&self) -> u64 {
        self.expected_snapshot_version
    }

    #[must_use]
    pub const fn resulting_snapshot_version(&self) -> u64 {
        self.resulting_snapshot_version
    }

    #[must_use]
    pub const fn expected_resource_fence(&self) -> u64 {
        self.expected_resource_fence
    }

    #[must_use]
    pub const fn resulting_resource_fence(&self) -> u64 {
        self.resulting_resource_fence
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
    pub const fn effective_at_unix_ms(&self) -> u64 {
        self.effective_at_unix_ms
    }

    #[must_use]
    pub const fn due_at_unix_ms(&self) -> u64 {
        self.due_at_unix_ms
    }

    #[must_use]
    pub const fn acknowledged_at_unix_ms(&self) -> u64 {
        self.acknowledged_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedAssignmentAcknowledgementV1(SignedExportEnvelope<AssignmentAcknowledgementBodyV1>);

impl SignedAssignmentAcknowledgementV1 {
    pub fn sign(
        body: AssignmentAcknowledgementBodyV1,
        signer: &Keypair,
    ) -> Result<Self, FactorError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| FactorError::Canonicalization(error.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        canonical_bytes(self)
    }

    #[must_use]
    pub const fn body(&self) -> &AssignmentAcknowledgementBodyV1 {
        &self.0.body
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentNotAppliedReasonV1 {
    AlreadyAssigned,
    DispositionConflict,
    SettlementNotPending,
    StatusProofExpired,
    AuthorizationExpired,
    RequestExpired,
    OfferExpired,
    PastDue,
    OperationConflict,
}

pub struct AssignmentNotAppliedClassificationV1<'a> {
    pub atom: &'a ObligationAtomV1,
    pub request: &'a NormalizedAssignmentRequestV1,
    pub offer: &'a AssignmentOfferV1,
    pub authorization: &'a VerifiedAssignmentAuthorizationSetV1,
    pub status_proof: &'a VerifiedObligationStatusProofV1,
    pub observed_disposition: &'a ObligationDispositionRecordV1,
    pub observed_settlement_lifecycle: &'a ObligationSettlementLifecycleV1,
    pub observed_snapshot_version: u64,
    pub observed_resource_fence: u64,
    pub decided_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentNotAppliedInputV1 {
    pub operation_id: String,
    pub normalized_request_digest: String,
    pub agreement_id: String,
    pub agreement_body_digest: String,
    pub obligation_id: String,
    pub obligation_atom_digest: String,
    pub assignment_authorization_set_digest: String,
    pub status_proof_digest: String,
    pub expected_disposition_version: u64,
    pub expected_disposition_lifecycle_fence: u64,
    pub expected_settlement_lifecycle_version: u64,
    pub expected_settlement_lifecycle_fence: u64,
    pub expected_snapshot_version: u64,
    pub expected_resource_fence: u64,
    pub observed_disposition_version: u64,
    pub observed_disposition_lifecycle_fence: u64,
    pub observed_disposition_digest: String,
    pub observed_settlement_lifecycle_version: u64,
    pub observed_settlement_lifecycle_fence: u64,
    pub observed_settlement_lifecycle_digest: String,
    pub observed_snapshot_version: u64,
    pub resource_fence: u64,
    pub reason: AssignmentNotAppliedReasonV1,
    pub no_mutation_proof_digest: String,
    pub authority_id: String,
    pub authority_key_epoch: u64,
    pub decided_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentNotAppliedBodyV1 {
    schema: String,
    result_id: String,
    operation_id: String,
    normalized_request_digest: String,
    agreement_id: String,
    agreement_body_digest: String,
    obligation_id: String,
    obligation_atom_digest: String,
    assignment_authorization_set_digest: String,
    status_proof_digest: String,
    expected_disposition_version: u64,
    expected_disposition_lifecycle_fence: u64,
    expected_settlement_lifecycle_version: u64,
    expected_settlement_lifecycle_fence: u64,
    expected_snapshot_version: u64,
    expected_resource_fence: u64,
    observed_disposition_version: u64,
    observed_disposition_lifecycle_fence: u64,
    observed_disposition_digest: String,
    observed_settlement_lifecycle_version: u64,
    observed_settlement_lifecycle_fence: u64,
    observed_settlement_lifecycle_digest: String,
    observed_snapshot_version: u64,
    resource_fence: u64,
    reason: AssignmentNotAppliedReasonV1,
    no_mutation_proof_digest: String,
    authority_id: String,
    authority_key_epoch: u64,
    decided_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentNotAppliedIdPreimage<'a> {
    schema: &'a str,
    operation_id: &'a str,
    normalized_request_digest: &'a str,
    agreement_id: &'a str,
    agreement_body_digest: &'a str,
    obligation_id: &'a str,
    obligation_atom_digest: &'a str,
    assignment_authorization_set_digest: &'a str,
    status_proof_digest: &'a str,
    expected_disposition_version: u64,
    expected_disposition_lifecycle_fence: u64,
    expected_settlement_lifecycle_version: u64,
    expected_settlement_lifecycle_fence: u64,
    expected_snapshot_version: u64,
    expected_resource_fence: u64,
    observed_disposition_version: u64,
    observed_disposition_lifecycle_fence: u64,
    observed_disposition_digest: &'a str,
    observed_settlement_lifecycle_version: u64,
    observed_settlement_lifecycle_fence: u64,
    observed_settlement_lifecycle_digest: &'a str,
    observed_snapshot_version: u64,
    resource_fence: u64,
    reason: AssignmentNotAppliedReasonV1,
    no_mutation_proof_digest: &'a str,
    authority_id: &'a str,
    authority_key_epoch: u64,
    decided_at_unix_ms: u64,
}

impl AssignmentNotAppliedBodyV1 {
    pub fn new(input: AssignmentNotAppliedInputV1) -> Result<Self, FactorError> {
        let mut body = Self {
            schema: FACTOR_ASSIGNMENT_NOT_APPLIED_SCHEMA.to_owned(),
            result_id: String::new(),
            operation_id: input.operation_id,
            normalized_request_digest: input.normalized_request_digest,
            agreement_id: input.agreement_id,
            agreement_body_digest: input.agreement_body_digest,
            obligation_id: input.obligation_id,
            obligation_atom_digest: input.obligation_atom_digest,
            assignment_authorization_set_digest: input.assignment_authorization_set_digest,
            status_proof_digest: input.status_proof_digest,
            expected_disposition_version: input.expected_disposition_version,
            expected_disposition_lifecycle_fence: input.expected_disposition_lifecycle_fence,
            expected_settlement_lifecycle_version: input.expected_settlement_lifecycle_version,
            expected_settlement_lifecycle_fence: input.expected_settlement_lifecycle_fence,
            expected_snapshot_version: input.expected_snapshot_version,
            expected_resource_fence: input.expected_resource_fence,
            observed_disposition_version: input.observed_disposition_version,
            observed_disposition_lifecycle_fence: input.observed_disposition_lifecycle_fence,
            observed_disposition_digest: input.observed_disposition_digest,
            observed_settlement_lifecycle_version: input.observed_settlement_lifecycle_version,
            observed_settlement_lifecycle_fence: input.observed_settlement_lifecycle_fence,
            observed_settlement_lifecycle_digest: input.observed_settlement_lifecycle_digest,
            observed_snapshot_version: input.observed_snapshot_version,
            resource_fence: input.resource_fence,
            reason: input.reason,
            no_mutation_proof_digest: input.no_mutation_proof_digest,
            authority_id: input.authority_id,
            authority_key_epoch: input.authority_key_epoch,
            decided_at_unix_ms: input.decided_at_unix_ms,
        };
        body.result_id = body.derived_result_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), FactorError> {
        if self.schema != FACTOR_ASSIGNMENT_NOT_APPLIED_SCHEMA {
            return Err(FactorError::InvalidField("not_applied_schema"));
        }
        for (field, value) in [
            ("result_id", &self.result_id),
            ("operation_id", &self.operation_id),
            ("normalized_request_digest", &self.normalized_request_digest),
            ("agreement_body_digest", &self.agreement_body_digest),
            ("obligation_id", &self.obligation_id),
            ("obligation_atom_digest", &self.obligation_atom_digest),
            (
                "assignment_authorization_set_digest",
                &self.assignment_authorization_set_digest,
            ),
            ("status_proof_digest", &self.status_proof_digest),
            (
                "observed_disposition_digest",
                &self.observed_disposition_digest,
            ),
            (
                "observed_settlement_lifecycle_digest",
                &self.observed_settlement_lifecycle_digest,
            ),
            ("no_mutation_proof_digest", &self.no_mutation_proof_digest),
        ] {
            validate_digest(field, value)?;
        }
        validate_text("agreement_id", &self.agreement_id)?;
        validate_text("authority_id", &self.authority_id)?;
        for (field, value) in [
            (
                "expected_disposition_version",
                self.expected_disposition_version,
            ),
            (
                "expected_disposition_lifecycle_fence",
                self.expected_disposition_lifecycle_fence,
            ),
            (
                "expected_settlement_lifecycle_version",
                self.expected_settlement_lifecycle_version,
            ),
            (
                "expected_settlement_lifecycle_fence",
                self.expected_settlement_lifecycle_fence,
            ),
            ("expected_snapshot_version", self.expected_snapshot_version),
            ("expected_resource_fence", self.expected_resource_fence),
            (
                "observed_disposition_version",
                self.observed_disposition_version,
            ),
            (
                "observed_disposition_lifecycle_fence",
                self.observed_disposition_lifecycle_fence,
            ),
            (
                "observed_settlement_lifecycle_version",
                self.observed_settlement_lifecycle_version,
            ),
            (
                "observed_settlement_lifecycle_fence",
                self.observed_settlement_lifecycle_fence,
            ),
            ("observed_snapshot_version", self.observed_snapshot_version),
            ("resource_fence", self.resource_fence),
            ("authority_key_epoch", self.authority_key_epoch),
            ("decided_at_unix_ms", self.decided_at_unix_ms),
        ] {
            validate_positive(field, value)?;
        }
        if self.expected_disposition_version != self.expected_disposition_lifecycle_fence
            || self.expected_settlement_lifecycle_version
                != self.expected_settlement_lifecycle_fence
            || self.observed_disposition_version != self.observed_disposition_lifecycle_fence
            || self.observed_settlement_lifecycle_version
                != self.observed_settlement_lifecycle_fence
            || self.result_id != self.derived_result_id()?
        {
            return Err(FactorError::InvalidField("not_applied_terms"));
        }
        Ok(())
    }

    fn derived_result_id(&self) -> Result<String, FactorError> {
        domain_digest(
            NOT_APPLIED_ID_DOMAIN,
            &AssignmentNotAppliedIdPreimage {
                schema: &self.schema,
                operation_id: &self.operation_id,
                normalized_request_digest: &self.normalized_request_digest,
                agreement_id: &self.agreement_id,
                agreement_body_digest: &self.agreement_body_digest,
                obligation_id: &self.obligation_id,
                obligation_atom_digest: &self.obligation_atom_digest,
                assignment_authorization_set_digest: &self.assignment_authorization_set_digest,
                status_proof_digest: &self.status_proof_digest,
                expected_disposition_version: self.expected_disposition_version,
                expected_disposition_lifecycle_fence: self.expected_disposition_lifecycle_fence,
                expected_settlement_lifecycle_version: self.expected_settlement_lifecycle_version,
                expected_settlement_lifecycle_fence: self.expected_settlement_lifecycle_fence,
                expected_snapshot_version: self.expected_snapshot_version,
                expected_resource_fence: self.expected_resource_fence,
                observed_disposition_version: self.observed_disposition_version,
                observed_disposition_lifecycle_fence: self.observed_disposition_lifecycle_fence,
                observed_disposition_digest: &self.observed_disposition_digest,
                observed_settlement_lifecycle_version: self.observed_settlement_lifecycle_version,
                observed_settlement_lifecycle_fence: self.observed_settlement_lifecycle_fence,
                observed_settlement_lifecycle_digest: &self.observed_settlement_lifecycle_digest,
                observed_snapshot_version: self.observed_snapshot_version,
                resource_fence: self.resource_fence,
                reason: self.reason,
                no_mutation_proof_digest: &self.no_mutation_proof_digest,
                authority_id: &self.authority_id,
                authority_key_epoch: self.authority_key_epoch,
                decided_at_unix_ms: self.decided_at_unix_ms,
            },
        )
    }

    pub fn digest(&self) -> Result<String, FactorError> {
        self.validate()?;
        domain_digest(NOT_APPLIED_BODY_DIGEST_DOMAIN, self)
    }

    #[must_use]
    pub fn result_id(&self) -> &str {
        &self.result_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn normalized_request_digest(&self) -> &str {
        &self.normalized_request_digest
    }

    #[must_use]
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }

    #[must_use]
    pub fn agreement_id(&self) -> &str {
        &self.agreement_id
    }

    #[must_use]
    pub fn agreement_body_digest(&self) -> &str {
        &self.agreement_body_digest
    }

    #[must_use]
    pub fn obligation_atom_digest(&self) -> &str {
        &self.obligation_atom_digest
    }

    #[must_use]
    pub fn assignment_authorization_set_digest(&self) -> &str {
        &self.assignment_authorization_set_digest
    }

    #[must_use]
    pub fn status_proof_digest(&self) -> &str {
        &self.status_proof_digest
    }

    #[must_use]
    pub const fn expected_disposition_version(&self) -> u64 {
        self.expected_disposition_version
    }

    #[must_use]
    pub const fn expected_disposition_lifecycle_fence(&self) -> u64 {
        self.expected_disposition_lifecycle_fence
    }

    #[must_use]
    pub const fn expected_settlement_lifecycle_version(&self) -> u64 {
        self.expected_settlement_lifecycle_version
    }

    #[must_use]
    pub const fn expected_settlement_lifecycle_fence(&self) -> u64 {
        self.expected_settlement_lifecycle_fence
    }

    #[must_use]
    pub const fn expected_snapshot_version(&self) -> u64 {
        self.expected_snapshot_version
    }

    #[must_use]
    pub const fn expected_resource_fence(&self) -> u64 {
        self.expected_resource_fence
    }

    #[must_use]
    pub const fn observed_disposition_version(&self) -> u64 {
        self.observed_disposition_version
    }

    #[must_use]
    pub const fn observed_disposition_lifecycle_fence(&self) -> u64 {
        self.observed_disposition_lifecycle_fence
    }

    #[must_use]
    pub fn observed_disposition_digest(&self) -> &str {
        &self.observed_disposition_digest
    }

    #[must_use]
    pub const fn observed_settlement_lifecycle_version(&self) -> u64 {
        self.observed_settlement_lifecycle_version
    }

    #[must_use]
    pub const fn observed_settlement_lifecycle_fence(&self) -> u64 {
        self.observed_settlement_lifecycle_fence
    }

    #[must_use]
    pub fn observed_settlement_lifecycle_digest(&self) -> &str {
        &self.observed_settlement_lifecycle_digest
    }

    #[must_use]
    pub const fn observed_snapshot_version(&self) -> u64 {
        self.observed_snapshot_version
    }

    #[must_use]
    pub fn no_mutation_proof_digest(&self) -> &str {
        &self.no_mutation_proof_digest
    }

    #[must_use]
    pub const fn reason(&self) -> AssignmentNotAppliedReasonV1 {
        self.reason
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        self.resource_fence
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
    pub const fn decided_at_unix_ms(&self) -> u64 {
        self.decided_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedAssignmentNotAppliedV1(SignedExportEnvelope<AssignmentNotAppliedBodyV1>);

impl SignedAssignmentNotAppliedV1 {
    pub fn sign(body: AssignmentNotAppliedBodyV1, signer: &Keypair) -> Result<Self, FactorError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| FactorError::Canonicalization(error.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FactorError> {
        canonical_bytes(self)
    }

    #[must_use]
    pub const fn body(&self) -> &AssignmentNotAppliedBodyV1 {
        &self.0.body
    }
}

#[derive(Debug, Clone)]
pub struct AssignmentResultAuthorityTrustV1 {
    authority_id: String,
    authority_key: PublicKey,
    authority_key_epoch: u64,
}

impl AssignmentResultAuthorityTrustV1 {
    pub fn new(
        authority_id: String,
        authority_key: PublicKey,
        authority_key_epoch: u64,
    ) -> Result<Self, FactorError> {
        validate_text("trusted_result_authority_id", &authority_id)?;
        validate_positive("trusted_result_authority_key_epoch", authority_key_epoch)?;
        Ok(Self {
            authority_id,
            authority_key,
            authority_key_epoch,
        })
    }
}

pub struct AssignmentAcknowledgementVerificationV1<'a> {
    pub atom: &'a ObligationAtomV1,
    pub request: &'a NormalizedAssignmentRequestV1,
    pub claim: &'a VerifiedReceivableClaimV1,
    pub offer: &'a AssignmentOfferV1,
    pub authorization: &'a VerifiedAssignmentAuthorizationSetV1,
    pub status_proof: &'a VerifiedObligationStatusProofV1,
    pub resulting_disposition: &'a ObligationDispositionRecordV1,
    pub trust: &'a AssignmentResultAuthorityTrustV1,
}

pub struct AssignmentNotAppliedVerificationV1<'a> {
    pub atom: &'a ObligationAtomV1,
    pub request: &'a NormalizedAssignmentRequestV1,
    pub claim: &'a VerifiedReceivableClaimV1,
    pub offer: &'a AssignmentOfferV1,
    pub authorization: &'a VerifiedAssignmentAuthorizationSetV1,
    pub status_proof: &'a VerifiedObligationStatusProofV1,
    pub observed_disposition: &'a ObligationDispositionRecordV1,
    pub observed_settlement_lifecycle: &'a ObligationSettlementLifecycleV1,
    pub observed_snapshot_version: u64,
    pub observed_resource_fence: u64,
    pub no_mutation_proof_digest: &'a str,
    pub trust: &'a AssignmentResultAuthorityTrustV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssignmentAcknowledgementV1 {
    signed: SignedAssignmentAcknowledgementV1,
    body_digest: String,
    envelope_digest: String,
    signature_digest: String,
    canonical_bytes: Vec<u8>,
}

impl VerifiedAssignmentAcknowledgementV1 {
    #[must_use]
    pub const fn body(&self) -> &AssignmentAcknowledgementBodyV1 {
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
    pub fn signature_digest(&self) -> &str {
        &self.signature_digest
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssignmentNotAppliedV1 {
    signed: SignedAssignmentNotAppliedV1,
    body_digest: String,
    envelope_digest: String,
    signature_digest: String,
    canonical_bytes: Vec<u8>,
}

impl VerifiedAssignmentNotAppliedV1 {
    #[must_use]
    pub const fn body(&self) -> &AssignmentNotAppliedBodyV1 {
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
    pub fn signature_digest(&self) -> &str {
        &self.signature_digest
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

pub fn verify_assignment_acknowledgement(
    canonical_acknowledgement: &[u8],
    context: &AssignmentAcknowledgementVerificationV1<'_>,
) -> Result<VerifiedAssignmentAcknowledgementV1, FactorError> {
    let signed: SignedAssignmentAcknowledgementV1 =
        parse_canonical(canonical_acknowledgement, "assignment acknowledgement")?;
    let body = signed.body();
    body.validate()?;
    context
        .atom
        .validate()
        .map_err(|_| FactorError::BindingMismatch)?;
    context.request.validate()?;
    let claim = context.claim.claim();
    claim.validate_against_atom(context.atom)?;
    context.offer.validate()?;
    context
        .authorization
        .agreement()
        .body()
        .validate_against_request(context.request)?;
    context
        .resulting_disposition
        .validate_against(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    verify_result_authority(
        body.authority_id(),
        body.authority_key_epoch(),
        &signed.0,
        context.status_proof,
        context.trust,
    )?;
    let request_digest = context.request.digest()?;
    let atom_digest = context
        .atom
        .digest()
        .map_err(|_| FactorError::BindingMismatch)?;
    let agreement = context.authorization.agreement().body();
    let status = context.status_proof.body();
    let resulting_digest = context
        .resulting_disposition
        .digest(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    let transition_matches = matches!(
        context.resulting_disposition.last_transition(),
        ObligationDispositionTransitionV1::Assign {
            operation_id,
            normalized_request_digest,
            status_proof_digest,
            agreement_id,
            creditor_id,
            settlement_destination_ref,
            authority_digest,
        } if operation_id == body.operation_id()
            && normalized_request_digest == &request_digest
            && status_proof_digest == context.status_proof.envelope_digest()
            && agreement_id == agreement.agreement_id()
            && creditor_id == context.request.buyer_id()
            && settlement_destination_ref
                == context.request.buyer_settlement_destination_ref()
            && authority_digest == context.authorization.digest()
    );
    if body.operation_id() != context.authorization.body().operation_id()
        || body.normalized_request_digest() != request_digest
        || context.request.claim_digest() != claim.digest()?
        || claim.status_proof_digest() != context.status_proof.envelope_digest()
        || context.request.offer_digest() != context.offer.digest()?
        || context.offer.seller_id() != context.request.seller_id()
        || context.offer.due_at_unix_ms() != context.request.due_at_unix_ms()
        || status.issued_at_unix_ms() > claim.built_at_unix_ms()
        || claim.built_at_unix_ms() > context.offer.issued_at_unix_ms()
        || context.offer.issued_at_unix_ms() > context.request.effective_at_unix_ms()
        || claim.built_at_unix_ms() >= status.expires_at_unix_ms()
        || claim.built_at_unix_ms() >= context.atom.due_at_unix_ms()
        || body.agreement_id() != agreement.agreement_id()
        || body.agreement_body_digest() != context.authorization.agreement().body_digest()
        || body.obligation_id() != context.atom.obligation_id()
        || body.obligation_atom_digest() != atom_digest
        || body.buyer_id() != context.request.buyer_id()
        || body.buyer_settlement_destination_ref()
            != context.request.buyer_settlement_destination_ref()
        || body.assignment_authorization_set_digest() != context.authorization.digest()
        || body.status_proof_digest() != context.status_proof.envelope_digest()
        || body.prior_disposition_version() != status.disposition_version()
        || body.prior_disposition_lifecycle_fence() != status.disposition_lifecycle_fence()
        || body.prior_disposition_digest() != status.disposition_digest()
        || body.resulting_disposition_version() != context.resulting_disposition.version()
        || body.resulting_disposition_lifecycle_fence()
            != context.resulting_disposition.lifecycle_fence()
        || body.resulting_disposition_digest() != resulting_digest
        || body.expected_snapshot_version() != status.snapshot_version()
        || body.resulting_snapshot_version()
            != status
                .snapshot_version()
                .checked_add(1)
                .ok_or(FactorError::ArithmeticOverflow)?
        || body.expected_resource_fence() != status.resource_fence()
        || body.resulting_resource_fence()
            != status
                .resource_fence()
                .checked_add(1)
                .ok_or(FactorError::ArithmeticOverflow)?
        || body.effective_at_unix_ms() != context.request.effective_at_unix_ms()
        || body.due_at_unix_ms() != context.atom.due_at_unix_ms()
        || body.acknowledged_at_unix_ms() >= status.expires_at_unix_ms()
        || body.acknowledged_at_unix_ms() >= context.authorization.body().expires_at_unix_ms()
        || body.acknowledged_at_unix_ms() >= context.request.expires_at_unix_ms()
        || body.acknowledged_at_unix_ms() >= context.offer.expires_at_unix_ms()
        || body.acknowledged_at_unix_ms() < context.request.effective_at_unix_ms()
        || body.acknowledged_at_unix_ms() < context.offer.issued_at_unix_ms()
        || body.acknowledged_at_unix_ms() < context.authorization.body().issued_at_unix_ms()
        || body.acknowledged_at_unix_ms() < status.issued_at_unix_ms()
        || status.obligation_id() != context.atom.obligation_id()
        || status.obligation_atom_digest() != atom_digest
        || status.current_creditor_id() != context.request.seller_id()
        || status.disposition_version() != context.request.expected_disposition_version()
        || status.disposition_lifecycle_fence()
            != context.request.expected_disposition_lifecycle_fence()
        || status.settlement_lifecycle_version()
            != context.request.expected_settlement_lifecycle_version()
        || status.settlement_lifecycle_fence()
            != context.request.expected_settlement_lifecycle_fence()
        || status.due_at_unix_ms() != context.request.due_at_unix_ms()
        || status.due_at_unix_ms() != context.atom.due_at_unix_ms()
        || !matches!(status.disposition(), ObligationDispositionV1::PerCall)
        || !matches!(
            status.settlement_state(),
            ObligationSettlementStateV1::Pending
        )
        || context.resulting_disposition.disposition()
            != &(ObligationDispositionV1::Assigned {
                agreement_id: agreement.agreement_id().to_owned(),
                creditor_id: context.request.buyer_id().to_owned(),
                settlement_destination_ref: context
                    .request
                    .buyer_settlement_destination_ref()
                    .to_owned(),
            })
        || !transition_matches
    {
        return Err(FactorError::BindingMismatch);
    }
    Ok(VerifiedAssignmentAcknowledgementV1 {
        body_digest: signed.body().digest()?,
        envelope_digest: sha256_hex(canonical_acknowledgement),
        signature_digest: sha256_hex(signed.0.signature.to_hex().as_bytes()),
        canonical_bytes: canonical_acknowledgement.to_vec(),
        signed,
    })
}

pub fn verify_assignment_not_applied(
    canonical_result: &[u8],
    context: &AssignmentNotAppliedVerificationV1<'_>,
) -> Result<VerifiedAssignmentNotAppliedV1, FactorError> {
    let signed: SignedAssignmentNotAppliedV1 =
        parse_canonical(canonical_result, "assignment not applied")?;
    let body = signed.body();
    body.validate()?;
    context
        .atom
        .validate()
        .map_err(|_| FactorError::BindingMismatch)?;
    context.request.validate()?;
    let claim = context.claim.claim();
    claim.validate_against_atom(context.atom)?;
    context.offer.validate()?;
    context
        .authorization
        .agreement()
        .body()
        .validate_against_request(context.request)?;
    context
        .observed_disposition
        .validate_against(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    context
        .observed_settlement_lifecycle
        .validate_against(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    verify_result_authority(
        body.authority_id(),
        body.authority_key_epoch(),
        &signed.0,
        context.status_proof,
        context.trust,
    )?;
    let request_digest = context.request.digest()?;
    let atom_digest = context
        .atom
        .digest()
        .map_err(|_| FactorError::BindingMismatch)?;
    let agreement = context.authorization.agreement().body();
    let status = context.status_proof.body();
    let observed_disposition_digest = context
        .observed_disposition
        .digest(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    let observed_settlement_digest = context
        .observed_settlement_lifecycle
        .digest(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    let reason_matches = classify_assignment_not_applied(&AssignmentNotAppliedClassificationV1 {
        atom: context.atom,
        request: context.request,
        offer: context.offer,
        authorization: context.authorization,
        status_proof: context.status_proof,
        observed_disposition: context.observed_disposition,
        observed_settlement_lifecycle: context.observed_settlement_lifecycle,
        observed_snapshot_version: context.observed_snapshot_version,
        observed_resource_fence: context.observed_resource_fence,
        decided_at_unix_ms: body.decided_at_unix_ms(),
    })? == Some(body.reason());
    if body.operation_id() != context.authorization.body().operation_id()
        || body.normalized_request_digest() != request_digest
        || context.request.claim_digest() != claim.digest()?
        || claim.status_proof_digest() != context.status_proof.envelope_digest()
        || context.request.offer_digest() != context.offer.digest()?
        || context.offer.seller_id() != context.request.seller_id()
        || context.offer.due_at_unix_ms() != context.request.due_at_unix_ms()
        || status.issued_at_unix_ms() > claim.built_at_unix_ms()
        || claim.built_at_unix_ms() > context.offer.issued_at_unix_ms()
        || context.offer.issued_at_unix_ms() > context.request.effective_at_unix_ms()
        || claim.built_at_unix_ms() >= status.expires_at_unix_ms()
        || claim.built_at_unix_ms() >= context.atom.due_at_unix_ms()
        || body.agreement_id() != agreement.agreement_id()
        || body.agreement_body_digest() != context.authorization.agreement().body_digest()
        || body.obligation_id() != context.atom.obligation_id()
        || body.obligation_atom_digest() != atom_digest
        || body.assignment_authorization_set_digest() != context.authorization.digest()
        || body.status_proof_digest() != context.status_proof.envelope_digest()
        || body.expected_disposition_version() != context.request.expected_disposition_version()
        || body.expected_disposition_lifecycle_fence()
            != context.request.expected_disposition_lifecycle_fence()
        || body.expected_settlement_lifecycle_version()
            != context.request.expected_settlement_lifecycle_version()
        || body.expected_settlement_lifecycle_fence()
            != context.request.expected_settlement_lifecycle_fence()
        || body.expected_snapshot_version() != status.snapshot_version()
        || body.expected_resource_fence() != status.resource_fence()
        || body.observed_disposition_version() != context.observed_disposition.version()
        || body.observed_disposition_lifecycle_fence()
            != context.observed_disposition.lifecycle_fence()
        || body.observed_disposition_digest() != observed_disposition_digest
        || body.observed_settlement_lifecycle_version()
            != context.observed_settlement_lifecycle.version()
        || body.observed_settlement_lifecycle_fence()
            != context.observed_settlement_lifecycle.lifecycle_fence()
        || body.observed_settlement_lifecycle_digest() != observed_settlement_digest
        || body.observed_snapshot_version() != context.observed_snapshot_version
        || body.resource_fence() != context.observed_resource_fence
        || body.no_mutation_proof_digest() != context.no_mutation_proof_digest
        || body.decided_at_unix_ms() < context.request.effective_at_unix_ms()
        || body.decided_at_unix_ms() < context.offer.issued_at_unix_ms()
        || body.decided_at_unix_ms() < context.authorization.body().issued_at_unix_ms()
        || body.decided_at_unix_ms() < status.issued_at_unix_ms()
        || status.obligation_id() != context.atom.obligation_id()
        || status.obligation_atom_digest() != atom_digest
        || status.current_creditor_id() != context.request.seller_id()
        || status.disposition_version() != context.request.expected_disposition_version()
        || status.disposition_lifecycle_fence()
            != context.request.expected_disposition_lifecycle_fence()
        || status.settlement_lifecycle_version()
            != context.request.expected_settlement_lifecycle_version()
        || status.settlement_lifecycle_fence()
            != context.request.expected_settlement_lifecycle_fence()
        || status.due_at_unix_ms() != context.request.due_at_unix_ms()
        || status.due_at_unix_ms() != context.atom.due_at_unix_ms()
        || !matches!(status.disposition(), ObligationDispositionV1::PerCall)
        || !matches!(
            status.settlement_state(),
            ObligationSettlementStateV1::Pending
        )
        || !reason_matches
    {
        return Err(FactorError::BindingMismatch);
    }
    Ok(VerifiedAssignmentNotAppliedV1 {
        body_digest: signed.body().digest()?,
        envelope_digest: sha256_hex(canonical_result),
        signature_digest: sha256_hex(signed.0.signature.to_hex().as_bytes()),
        canonical_bytes: canonical_result.to_vec(),
        signed,
    })
}

pub fn classify_assignment_not_applied(
    context: &AssignmentNotAppliedClassificationV1<'_>,
) -> Result<Option<AssignmentNotAppliedReasonV1>, FactorError> {
    context
        .atom
        .validate()
        .map_err(|_| FactorError::BindingMismatch)?;
    context.request.validate()?;
    context.offer.validate()?;
    context
        .observed_disposition
        .validate_against(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    context
        .observed_settlement_lifecycle
        .validate_against(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    let status = context.status_proof.body();
    let observed_settlement_digest = context
        .observed_settlement_lifecycle
        .digest(context.atom)
        .map_err(|_| FactorError::BindingMismatch)?;
    if matches!(
        context.observed_disposition.disposition(),
        ObligationDispositionV1::Assigned { .. }
    ) {
        return Ok(Some(AssignmentNotAppliedReasonV1::AlreadyAssigned));
    }
    if context.observed_disposition.version() != context.request.expected_disposition_version()
        || context.observed_disposition.lifecycle_fence()
            != context.request.expected_disposition_lifecycle_fence()
        || !matches!(
            context.observed_disposition.disposition(),
            ObligationDispositionV1::PerCall
        )
    {
        return Ok(Some(AssignmentNotAppliedReasonV1::DispositionConflict));
    }
    if !matches!(
        context.observed_settlement_lifecycle.state(),
        ObligationSettlementStateV1::Pending
    ) {
        return Ok(Some(AssignmentNotAppliedReasonV1::SettlementNotPending));
    }
    if context.decided_at_unix_ms >= context.atom.due_at_unix_ms() {
        return Ok(Some(AssignmentNotAppliedReasonV1::PastDue));
    }
    if context.decided_at_unix_ms >= status.expires_at_unix_ms() {
        return Ok(Some(AssignmentNotAppliedReasonV1::StatusProofExpired));
    }
    if context.decided_at_unix_ms >= context.authorization.body().expires_at_unix_ms() {
        return Ok(Some(AssignmentNotAppliedReasonV1::AuthorizationExpired));
    }
    if context.decided_at_unix_ms >= context.request.expires_at_unix_ms() {
        return Ok(Some(AssignmentNotAppliedReasonV1::RequestExpired));
    }
    if context.decided_at_unix_ms >= context.offer.expires_at_unix_ms() {
        return Ok(Some(AssignmentNotAppliedReasonV1::OfferExpired));
    }
    if context.observed_snapshot_version != status.snapshot_version()
        || context.observed_resource_fence != status.resource_fence()
        || context.observed_settlement_lifecycle.version()
            != context.request.expected_settlement_lifecycle_version()
        || context.observed_settlement_lifecycle.lifecycle_fence()
            != context.request.expected_settlement_lifecycle_fence()
        || context.observed_settlement_lifecycle.version() != status.settlement_lifecycle_version()
        || context.observed_settlement_lifecycle.lifecycle_fence()
            != status.settlement_lifecycle_fence()
        || observed_settlement_digest != status.settlement_lifecycle_digest()
    {
        return Ok(Some(AssignmentNotAppliedReasonV1::OperationConflict));
    }
    Ok(None)
}

fn verify_result_authority<T: Serialize + Clone>(
    authority_id: &str,
    authority_key_epoch: u64,
    signed: &SignedExportEnvelope<T>,
    status_proof: &VerifiedObligationStatusProofV1,
    trust: &AssignmentResultAuthorityTrustV1,
) -> Result<(), FactorError> {
    if authority_id != trust.authority_id
        || authority_id != status_proof.body().authority_id()
        || authority_key_epoch != trust.authority_key_epoch
        || authority_key_epoch != status_proof.body().authority_key_epoch()
        || signed.signer_key != trust.authority_key
        || &signed.signer_key != status_proof.signer_key()
        || !signed
            .verify_signature()
            .map_err(|error| FactorError::Canonicalization(error.to_string()))?
    {
        return Err(FactorError::AuthorityVerification);
    }
    Ok(())
}
