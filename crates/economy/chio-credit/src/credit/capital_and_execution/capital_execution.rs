use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionInstructionAction {
    LockReserve,
    HoldReserve,
    ReleaseReserve,
    TransferFunds,
    CancelInstruction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionRole {
    OperatorTreasury,
    ExternalCapitalProvider,
    AgentCounterparty,
    LiabilityProvider,
    Reinsurer,
    FacilityProvider,
    Custodian,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionRailKind {
    Manual,
    Api,
    Ach,
    Wire,
    Ledger,
    Sandbox,
    Web3,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionIntendedState {
    PendingExecution,
    CancellationPending,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalExecutionReconciledState {
    NotObserved,
    Matched,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionWindow {
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionRail {
    pub kind: CapitalExecutionRailKind,
    pub rail_id: String,
    pub custody_provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_account_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_account_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionObservation {
    pub observed_at: u64,
    pub external_reference_id: String,
    pub amount: MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionInstructionSupportBoundary {
    pub capital_book_authoritative: bool,
    pub external_execution_authoritative: bool,
    pub automatic_dispatch_supported: bool,
    pub custody_neutral_instruction_supported: bool,
}

impl Default for CapitalExecutionInstructionSupportBoundary {
    fn default() -> Self {
        Self {
            capital_book_authoritative: true,
            external_execution_authoritative: false,
            automatic_dispatch_supported: false,
            custody_neutral_instruction_supported: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionInstructionArtifact {
    pub schema: String,
    pub instruction_id: String,
    pub issued_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub source_id: String,
    pub source_kind: CapitalBookSourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_flow_row_id: Option<String>,
    pub action: CapitalExecutionInstructionAction,
    pub owner_role: CapitalExecutionRole,
    pub counterparty_role: CapitalExecutionRole,
    pub counterparty_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<MonetaryAmount>,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    pub intended_state: CapitalExecutionIntendedState,
    pub reconciled_state: CapitalExecutionReconciledState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_instruction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    pub support_boundary: CapitalExecutionInstructionSupportBoundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
    pub description: String,
}

impl CapitalExecutionInstructionArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA {
            return Err(format!(
                "capital instruction schema must be {CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA}"
            ));
        }
        validate_non_empty_clean(&self.instruction_id, "capital instruction instructionId")?;
        self.query.validate()?;
        validate_non_empty_clean(&self.subject_key, "capital instruction subjectKey")?;
        validate_non_empty_clean(&self.source_id, "capital instruction sourceId")?;
        validate_non_empty_clean(&self.counterparty_id, "capital instruction counterpartyId")?;
        validate_capital_execution_envelope(
            &self.authority_chain,
            &self.execution_window,
            &self.rail,
            self.issued_at,
        )?;
        ensure_capital_execution_owner_authority(&self.authority_chain, self.owner_role)?;
        validate_capital_instruction_action_shape(self)?;
        validate_capital_instruction_reconciliation(self)?;
        Ok(())
    }
}

pub type SignedCapitalExecutionInstruction =
    SignedExportEnvelope<CapitalExecutionInstructionArtifact>;

pub fn validate_capital_execution_envelope(
    authority_chain: &[CapitalExecutionAuthorityStep],
    execution_window: &CapitalExecutionWindow,
    rail: &CapitalExecutionRail,
    issued_at: u64,
) -> Result<(), String> {
    if authority_chain.is_empty() {
        return Err("capital execution requires at least one authorityChain step".to_string());
    }
    validate_non_empty_clean(&rail.rail_id, "capital execution rail.railId")?;
    validate_non_empty_clean(
        &rail.custody_provider_id,
        "capital execution rail.custodyProviderId",
    )?;
    if execution_window.not_before > execution_window.not_after {
        return Err(
            "capital execution executionWindow requires notBefore <= notAfter".to_string(),
        );
    }
    if execution_window.not_after < issued_at {
        return Err("capital execution executionWindow is already expired".to_string());
    }
    for step in authority_chain {
        validate_non_empty_clean(
            &step.principal_id,
            "capital execution authorityChain principalId",
        )?;
        validate_capital_execution_authority_step_proof(step)?;
        if step.approved_at > step.expires_at {
            return Err(
                "capital execution authorityChain requires approvedAt <= expiresAt".to_string(),
            );
        }
        if step.approved_at > issued_at {
            return Err(format!(
                "capital execution authority step `{}` approvedAt is after instruction issuance",
                step.principal_id
            ));
        }
        if step.expires_at < issued_at {
            return Err(format!(
                "capital execution authority step `{}` is stale at issuance time",
                step.principal_id
            ));
        }
        if step.expires_at < execution_window.not_after {
            return Err(format!(
                "capital execution authority step `{}` expires before the execution window closes",
                step.principal_id
            ));
        }
    }
    ensure_capital_execution_custodian_authority(authority_chain, rail)
}

pub fn ensure_capital_execution_owner_authority(
    authority_chain: &[CapitalExecutionAuthorityStep],
    owner_role: CapitalExecutionRole,
) -> Result<(), String> {
    if authority_chain.iter().any(|step| step.role == owner_role) {
        Ok(())
    } else {
        Err("capital execution authorityChain is missing source-owner approval".to_string())
    }
}

pub fn ensure_capital_execution_custodian_authority(
    authority_chain: &[CapitalExecutionAuthorityStep],
    rail: &CapitalExecutionRail,
) -> Result<(), String> {
    if authority_chain.iter().any(|step| {
        step.role == CapitalExecutionRole::Custodian
            && step.principal_id == rail.custody_provider_id
    }) {
        Ok(())
    } else {
        Err(
            "capital execution authorityChain is missing the custody-provider execution step"
                .to_string(),
        )
    }
}

fn validate_capital_instruction_action_shape(
    artifact: &CapitalExecutionInstructionArtifact,
) -> Result<(), String> {
    match artifact.action {
        CapitalExecutionInstructionAction::TransferFunds => {
            if artifact.source_kind != CapitalBookSourceKind::FacilityCommitment {
                return Err(
                    "transfer_funds instructions require sourceKind=facility_commitment"
                        .to_string(),
                );
            }
            validate_present_clean(
                artifact.governed_receipt_id.as_deref(),
                "capital instruction governedReceiptId",
            )?;
            validate_present_clean(
                artifact.completion_flow_row_id.as_deref(),
                "capital instruction completionFlowRowId",
            )?;
        }
        CapitalExecutionInstructionAction::LockReserve
        | CapitalExecutionInstructionAction::HoldReserve
        | CapitalExecutionInstructionAction::ReleaseReserve => {
            if artifact.source_kind != CapitalBookSourceKind::ReserveBook {
                return Err("reserve instructions require sourceKind=reserve_book".to_string());
            }
            if artifact.governed_receipt_id.is_some() || artifact.completion_flow_row_id.is_some() {
                return Err(
                    "governed receipt provenance is only valid for transfer_funds instructions"
                        .to_string(),
                );
            }
        }
        CapitalExecutionInstructionAction::CancelInstruction => {
            if artifact.amount.is_some() {
                return Err("cancel_instruction does not accept an amount".to_string());
            }
            validate_present_clean(
                artifact.related_instruction_id.as_deref(),
                "capital instruction relatedInstructionId",
            )?;
            if artifact.observed_execution.is_some() {
                return Err(
                    "cancel_instruction cannot carry observedExecution movement data".to_string(),
                );
            }
        }
    }
    if artifact.action != CapitalExecutionInstructionAction::CancelInstruction {
        let amount = artifact.amount.as_ref().ok_or_else(|| {
            "capital instructions require amount for non-cancel actions".to_string()
        })?;
        validate_positive_amount(amount, "capital instruction amount")?;
    }
    Ok(())
}

fn validate_capital_instruction_reconciliation(
    artifact: &CapitalExecutionInstructionArtifact,
) -> Result<(), String> {
    match (&artifact.observed_execution, &artifact.amount) {
        (Some(observed), Some(intended)) => {
            validate_non_empty_clean(
                &observed.external_reference_id,
                "capital instruction observedExecution externalReferenceId",
            )?;
            validate_positive_amount(&observed.amount, "capital instruction observedExecution amount")?;
            if &observed.amount != intended {
                return Err(
                    "capital instruction observedExecution amount does not match intended amount"
                        .to_string(),
                );
            }
            if observed.observed_at < artifact.execution_window.not_before
                || observed.observed_at > artifact.execution_window.not_after
            {
                return Err(
                    "capital instruction observedExecution timestamp falls outside the execution window"
                        .to_string(),
                );
            }
            if artifact.reconciled_state != CapitalExecutionReconciledState::Matched {
                return Err(
                    "capital instruction observedExecution requires reconciledState=matched"
                        .to_string(),
                );
            }
        }
        (Some(_), None) => {
            return Err(
                "observedExecution is only valid when the instruction carries an intended amount"
                    .to_string(),
            );
        }
        (None, _) => {
            if artifact.reconciled_state != CapitalExecutionReconciledState::NotObserved {
                return Err(
                    "capital instruction without observedExecution requires reconciledState=not_observed"
                        .to_string(),
                );
            }
        }
    }
    Ok(())
}

fn validate_present_clean(value: Option<&str>, label: &str) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("{label} is required"))?;
    validate_non_empty_clean(value, label)
}

fn validate_non_empty_clean(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if value.trim() != value {
        return Err(format!("{label} cannot contain surrounding whitespace"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} cannot contain control characters"));
    }
    Ok(())
}

fn validate_positive_amount(amount: &MonetaryAmount, label: &str) -> Result<(), String> {
    if amount.units == 0 {
        return Err(format!("{label} must be greater than zero"));
    }
    validate_non_empty_clean(&amount.currency, &format!("{label} currency"))
}
