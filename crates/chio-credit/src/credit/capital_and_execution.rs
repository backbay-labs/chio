#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_event_limit: Option<usize>,
}

impl Default for CapitalBookQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            facility_limit: Some(10),
            bond_limit: Some(10),
            loss_event_limit: Some(25),
        }
    }
}

impl CapitalBookQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.receipt_limit, 100, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn facility_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.facility_limit, 10, MAX_CREDIT_FACILITY_LIST_LIMIT)
    }

    #[must_use]
    pub fn bond_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.bond_limit, 10, MAX_CREDIT_BOND_LIST_LIMIT)
    }

    #[must_use]
    pub fn loss_event_limit_or_default(&self) -> usize {
        bounded_limit_or_default(
            self.loss_event_limit,
            25,
            MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT,
        )
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.facility_limit = Some(self.facility_limit_or_default());
        normalized.bond_limit = Some(self.bond_limit_or_default());
        normalized.loss_event_limit = Some(self.loss_event_limit_or_default());
        normalized
    }

    #[must_use]
    pub fn exposure_query(&self) -> ExposureLedgerQuery {
        ExposureLedgerQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            receipt_limit: self.receipt_limit,
            decision_limit: Some(1),
        }
    }

    #[must_use]
    pub fn facility_query(&self) -> CreditFacilityListQuery {
        CreditFacilityListQuery {
            facility_id: None,
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: self.facility_limit,
        }
    }

    #[must_use]
    pub fn bond_query(&self) -> CreditBondListQuery {
        CreditBondListQuery {
            bond_id: None,
            facility_id: None,
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            disposition: None,
            lifecycle_state: None,
            limit: self.bond_limit,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.exposure_query().validate()?;
        if self.agent_subject.is_none() {
            return Err(
                "capital book queries require --agent-subject because source-of-funds truth must resolve one counterparty"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookSourceKind {
    FacilityCommitment,
    ReserveBook,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookRole {
    OperatorTreasury,
    ExternalCapitalProvider,
    AgentCounterparty,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookEventKind {
    Commit,
    Hold,
    Draw,
    Disburse,
    Release,
    Repay,
    Impair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookEvidenceKind {
    CreditFacility,
    CreditBond,
    CreditLossLifecycle,
    Receipt,
    SettlementReconciliation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookEvidenceReference {
    pub kind: CapitalBookEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSupportBoundary {
    pub source_of_funds_authoritative: bool,
    pub mixed_currency_netting_supported: bool,
    pub custody_execution_supported: bool,
    pub automatic_capital_execution_supported: bool,
}

impl Default for CapitalBookSupportBoundary {
    fn default() -> Self {
        Self {
            source_of_funds_authoritative: true,
            mixed_currency_netting_supported: false,
            custody_execution_supported: false,
            automatic_capital_execution_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSource {
    pub source_id: String,
    pub kind: CapitalBookSourceKind,
    pub owner_role: CapitalBookRole,
    pub counterparty_role: CapitalBookRole,
    pub counterparty_id: String,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capital_source: Option<CreditFacilityCapitalSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawn_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disbursed_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repaid_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impaired_amount: Option<MonetaryAmount>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookEvent {
    pub event_id: String,
    pub kind: CapitalBookEventKind,
    pub occurred_at: u64,
    pub source_id: String,
    pub owner_role: CapitalBookRole,
    pub counterparty_role: CapitalBookRole,
    pub counterparty_id: String,
    pub amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_facilities: u64,
    pub returned_facilities: u64,
    pub matching_bonds: u64,
    pub returned_bonds: u64,
    pub matching_loss_events: u64,
    pub returned_loss_events: u64,
    pub currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub funding_sources: u64,
    pub ledger_events: u64,
    pub truncated_receipts: bool,
    pub truncated_facilities: bool,
    pub truncated_bonds: bool,
    pub truncated_loss_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub support_boundary: CapitalBookSupportBoundary,
    pub summary: CapitalBookSummary,
    pub sources: Vec<CapitalBookSource>,
    pub events: Vec<CapitalBookEvent>,
}

pub type SignedCapitalBookReport = SignedExportEnvelope<CapitalBookReport>;

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
pub struct CapitalExecutionAuthorityStep {
    pub role: CapitalExecutionRole,
    pub principal_id: String,
    pub approved_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalAllocationDecisionOutcome {
    Allocate,
    Queue,
    ManualReview,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalAllocationDecisionReasonCode {
    MissingGovernedReceipt,
    AmbiguousGovernedReceipt,
    MissingRequestedAmount,
    FacilityManualReview,
    FacilityDenied,
    ManualCapitalSource,
    ReserveBookMissing,
    UtilizationCeilingExceeded,
    ConcentrationCapExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationInstructionDraft {
    pub source_id: String,
    pub source_kind: CapitalBookSourceKind,
    pub action: CapitalExecutionInstructionAction,
    pub amount: MonetaryAmount,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionFinding {
    pub code: CapitalAllocationDecisionReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionSupportBoundary {
    pub capital_book_authoritative: bool,
    pub simulation_first_only: bool,
    pub automatic_dispatch_supported: bool,
    pub external_execution_authoritative: bool,
}

impl Default for CapitalAllocationDecisionSupportBoundary {
    fn default() -> Self {
        Self {
            capital_book_authoritative: true,
            simulation_first_only: true,
            automatic_dispatch_supported: false,
            external_execution_authoritative: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionArtifact {
    pub schema: String,
    pub allocation_id: String,
    pub issued_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub governed_receipt_id: String,
    pub intent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub requested_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<CapitalBookSourceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_source_id: Option<String>,
    pub outcome: CapitalAllocationDecisionOutcome,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_outstanding_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projected_outstanding_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_delta_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utilization_ceiling_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concentration_cap_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instruction_drafts: Vec<CapitalAllocationInstructionDraft>,
    pub support_boundary: CapitalAllocationDecisionSupportBoundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CapitalAllocationDecisionFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
    pub description: String,
}

pub type SignedCapitalAllocationDecision = SignedExportEnvelope<CapitalAllocationDecisionArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationQuery {
    pub bond_id: String,
    pub autonomy_tier: GovernedAutonomyTier,
    pub runtime_assurance_tier: RuntimeAssuranceTier,
    pub call_chain_present: bool,
}

impl CreditBondedExecutionSimulationQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.bond_id.trim().is_empty() {
            return Err("bonded execution simulation requires --bond-id".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionControlPolicy {
    pub version: String,
    pub kill_switch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_autonomy_tier: Option<GovernedAutonomyTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    pub require_delegated_call_chain: bool,
    pub require_locked_reserve: bool,
    pub deny_if_bond_not_active: bool,
    pub deny_if_outstanding_delinquency: bool,
}

impl Default for CreditBondedExecutionControlPolicy {
    fn default() -> Self {
        Self {
            version: "chio.credit.bonded-execution-control-policy.default.v1".to_string(),
            kill_switch: false,
            maximum_autonomy_tier: None,
            minimum_runtime_assurance_tier: None,
            require_delegated_call_chain: true,
            require_locked_reserve: false,
            deny_if_bond_not_active: true,
            deny_if_outstanding_delinquency: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondedExecutionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondedExecutionFindingCode {
    KillSwitchEnabled,
    AutonomyGatingUnsupported,
    BondNotActive,
    BondDispositionUnsupported,
    ActiveFacilityUnavailable,
    RuntimePrerequisiteUnmet,
    CertificationPrerequisiteUnmet,
    RuntimeAssuranceBelowAutonomyMinimum,
    RuntimeAssuranceBelowPolicyMinimum,
    MissingDelegatedCallChain,
    AutonomyTierAbovePolicyMaximum,
    ReserveNotLocked,
    OutstandingDelinquency,
    LossLifecycleHistoryTruncated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionFinding {
    pub code: CreditBondedExecutionFindingCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSupportBoundary {
    pub operator_control_policy_supported: bool,
    pub kill_switch_supported: bool,
    pub sandbox_simulation_supported: bool,
    pub external_escrow_execution_supported: bool,
}

impl Default for CreditBondedExecutionSupportBoundary {
    fn default() -> Self {
        Self {
            operator_control_policy_supported: true,
            kill_switch_supported: true,
            sandbox_simulation_supported: true,
            external_escrow_execution_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionEvaluation {
    pub decision: CreditBondedExecutionDecision,
    pub autonomy_tier: GovernedAutonomyTier,
    pub runtime_assurance_tier: RuntimeAssuranceTier,
    pub bond_lifecycle_state: CreditBondLifecycleState,
    pub bond_disposition: CreditBondDisposition,
    pub sandbox_integration_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outstanding_delinquency_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditBondedExecutionFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationDelta {
    pub decision_changed: bool,
    pub sandbox_integration_changed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationRequest {
    pub query: CreditBondedExecutionSimulationQuery,
    pub policy: CreditBondedExecutionControlPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondedExecutionSimulationReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditBondedExecutionSimulationQuery,
    pub policy: CreditBondedExecutionControlPolicy,
    pub support_boundary: CreditBondedExecutionSupportBoundary,
    pub bond: SignedCreditBond,
    pub default_evaluation: CreditBondedExecutionEvaluation,
    pub simulated_evaluation: CreditBondedExecutionEvaluation,
    pub delta: CreditBondedExecutionSimulationDelta,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn valid_capital_instruction_artifact() -> CapitalExecutionInstructionArtifact {
        CapitalExecutionInstructionArtifact {
            schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
            instruction_id: "cei-validator-1".to_string(),
            issued_at: 10,
            query: CapitalBookQuery {
                agent_subject: Some("subject-1".to_string()),
                ..CapitalBookQuery::default()
            },
            subject_key: "subject-1".to_string(),
            source_id: "capital-source:bond:cbd-1".to_string(),
            source_kind: CapitalBookSourceKind::ReserveBook,
            governed_receipt_id: None,
            completion_flow_row_id: None,
            action: CapitalExecutionInstructionAction::LockReserve,
            owner_role: CapitalExecutionRole::OperatorTreasury,
            counterparty_role: CapitalExecutionRole::AgentCounterparty,
            counterparty_id: "subject-1".to_string(),
            amount: Some(MonetaryAmount {
                units: 400,
                currency: "USD".to_string(),
            }),
            authority_chain: vec![
                CapitalExecutionAuthorityStep {
                    role: CapitalExecutionRole::OperatorTreasury,
                    principal_id: "treasury-1".to_string(),
                    approved_at: 9,
                    expires_at: 20,
                    note: None,
                },
                CapitalExecutionAuthorityStep {
                    role: CapitalExecutionRole::Custodian,
                    principal_id: "custodian-1".to_string(),
                    approved_at: 9,
                    expires_at: 20,
                    note: None,
                },
            ],
            execution_window: CapitalExecutionWindow {
                not_before: 10,
                not_after: 20,
            },
            rail: CapitalExecutionRail {
                kind: CapitalExecutionRailKind::Manual,
                rail_id: "rail-1".to_string(),
                custody_provider_id: "custodian-1".to_string(),
                source_account_ref: Some("reserve-main".to_string()),
                destination_account_ref: None,
                jurisdiction: Some("US-NY".to_string()),
            },
            intended_state: CapitalExecutionIntendedState::PendingExecution,
            reconciled_state: CapitalExecutionReconciledState::Matched,
            related_instruction_id: None,
            observed_execution: Some(CapitalExecutionObservation {
                observed_at: 12,
                external_reference_id: "wire-1".to_string(),
                amount: MonetaryAmount {
                    units: 400,
                    currency: "USD".to_string(),
                },
            }),
            support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
            evidence_refs: Vec::new(),
            description: "lock reserve".to_string(),
        }
    }

    #[test]
    fn bounded_limit_helper_preserves_default_and_clamps_edges() {
        assert_eq!(bounded_limit_or_default(None, 50, 100), 50);
        assert_eq!(bounded_limit_or_default(Some(0), 50, 100), 1);
        assert_eq!(bounded_limit_or_default(Some(75), 50, 100), 75);
        assert_eq!(bounded_limit_or_default(Some(250), 50, 100), 100);
    }

    #[test]
    fn exposure_ledger_query_clamps_limits() {
        let query = ExposureLedgerQuery {
            receipt_limit: Some(5_000),
            decision_limit: Some(9_000),
            ..ExposureLedgerQuery::default()
        };

        assert_eq!(
            query.receipt_limit_or_default(),
            MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT
        );
        assert_eq!(
            query.decision_limit_or_default(),
            MAX_EXPOSURE_LEDGER_DECISION_LIMIT
        );
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.decision_limit,
            Some(MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
        );
    }

    #[test]
    fn exposure_ledger_query_requires_anchor() {
        let query = ExposureLedgerQuery::default();
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("require at least one anchor")
        );
    }

    #[test]
    fn capital_execution_instruction_requires_source_owner_authority() {
        let mut artifact = valid_capital_instruction_artifact();
        let owner_role = artifact.owner_role;
        artifact
            .authority_chain
            .retain(|step| step.role != owner_role);

        let error = artifact
            .validate()
            .expect_err("missing source-owner authority must reject");
        assert!(error.contains("source-owner approval"));
    }

    #[test]
    fn exposure_ledger_query_rejects_blank_filter_values() {
        let query = ExposureLedgerQuery {
            agent_subject: Some(" ".to_string()),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("--agent-subject must be non-empty")
        );

        let query = ExposureLedgerQuery {
            tool_server: Some(" tool-server ".to_string()),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("--tool-server must not contain surrounding whitespace")
        );
    }

    #[test]
    fn exposure_ledger_query_requires_tool_server_when_tool_name_present() {
        let query = ExposureLedgerQuery {
            agent_subject: Some("subject-1".to_string()),
            tool_name: Some("transfer".to_string()),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("must also specify --tool-server")
        );
    }

    #[test]
    fn exposure_ledger_query_rejects_inverted_time_window() {
        let query = ExposureLedgerQuery {
            agent_subject: Some("subject-1".to_string()),
            since: Some(20),
            until: Some(10),
            ..ExposureLedgerQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("less than or equal to --until")
        );
    }

    #[test]
    fn credit_backtest_query_requires_subject_scope() {
        let query = CreditBacktestQuery {
            capability_id: Some("cap-1".to_string()),
            ..CreditBacktestQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("require --agent-subject")
        );
    }

    #[test]
    fn credit_backtest_query_clamps_limits() {
        let query = CreditBacktestQuery {
            agent_subject: Some("subject-1".to_string()),
            receipt_limit: Some(5_000),
            decision_limit: Some(9_000),
            window_count: Some(999),
            stale_after_seconds: Some(0),
            window_seconds: Some(0),
            ..CreditBacktestQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.decision_limit,
            Some(MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
        );
        assert_eq!(
            normalized.window_count,
            Some(MAX_CREDIT_BACKTEST_WINDOW_LIMIT)
        );
        assert_eq!(normalized.window_seconds, Some(1));
        assert_eq!(normalized.stale_after_seconds, Some(1));
    }

    #[test]
    fn provider_risk_package_query_requires_subject_scope() {
        let query = CreditProviderRiskPackageQuery {
            capability_id: Some("cap-1".to_string()),
            ..CreditProviderRiskPackageQuery::default()
        };
        assert!(
            query
                .validate()
                .unwrap_err()
                .contains("require --agent-subject")
        );
    }

    #[test]
    fn provider_risk_package_query_clamps_recent_loss_limit() {
        let query = CreditProviderRiskPackageQuery {
            agent_subject: Some("subject-1".to_string()),
            recent_loss_limit: Some(999),
            ..CreditProviderRiskPackageQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.recent_loss_limit,
            Some(MAX_CREDIT_PROVIDER_LOSS_LIMIT)
        );
    }

    #[test]
    fn capital_book_query_requires_subject_scope() {
        let query = CapitalBookQuery {
            capability_id: Some("cap-1".to_string()),
            ..CapitalBookQuery::default()
        };
        assert!(query.validate().unwrap_err().contains("--agent-subject"));
    }

    #[test]
    fn capital_book_query_clamps_limits() {
        let query = CapitalBookQuery {
            agent_subject: Some("subject-1".to_string()),
            receipt_limit: Some(5_000),
            facility_limit: Some(999),
            bond_limit: Some(999),
            loss_event_limit: Some(999),
            ..CapitalBookQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(
            normalized.receipt_limit,
            Some(MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
        );
        assert_eq!(
            normalized.facility_limit,
            Some(MAX_CREDIT_FACILITY_LIST_LIMIT)
        );
        assert_eq!(normalized.bond_limit, Some(MAX_CREDIT_BOND_LIST_LIMIT));
        assert_eq!(
            normalized.loss_event_limit,
            Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT)
        );
    }

    #[test]
    fn bonded_execution_simulation_query_requires_bond_id() {
        let query = CreditBondedExecutionSimulationQuery {
            bond_id: "   ".to_string(),
            autonomy_tier: GovernedAutonomyTier::Delegated,
            runtime_assurance_tier: RuntimeAssuranceTier::Attested,
            call_chain_present: true,
        };
        assert!(query.validate().unwrap_err().contains("--bond-id"));
    }

    #[test]
    fn bonded_execution_control_policy_defaults_fail_closed() {
        let policy = CreditBondedExecutionControlPolicy::default();
        assert!(!policy.kill_switch);
        assert!(policy.require_delegated_call_chain);
        assert!(policy.deny_if_bond_not_active);
        assert!(policy.deny_if_outstanding_delinquency);
    }

    #[test]
    fn capital_execution_instruction_artifact_validates_authority_and_reconciliation() {
        let artifact = valid_capital_instruction_artifact();
        artifact.validate().unwrap();
    }

    #[test]
    fn capital_execution_instruction_rejects_control_character_identities() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.instruction_id = "cei-1\ncei-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character instruction id to fail"),
            Err(error) => error,
        };
        assert!(error.contains("instructionId"));
        assert!(error.contains("control characters"));

        let mut artifact = valid_capital_instruction_artifact();
        artifact.subject_key = "subject-1\nsubject-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character subject key to fail"),
            Err(error) => error,
        };
        assert!(error.contains("subjectKey"));
        assert!(error.contains("control characters"));

        let mut artifact = valid_capital_instruction_artifact();
        artifact.rail.rail_id = "rail-1\nrail-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character rail id to fail"),
            Err(error) => error,
        };
        assert!(error.contains("railId"));
        assert!(error.contains("control characters"));

        let mut artifact = valid_capital_instruction_artifact();
        artifact.authority_chain[0].principal_id = "principal-1\nprincipal-2".to_string();
        let error = match artifact.validate() {
            Ok(_) => panic!("expected control-character authority principal to fail"),
            Err(error) => error,
        };
        assert!(error.contains("principalId"));
        assert!(error.contains("control characters"));
    }

    #[test]
    fn capital_execution_envelope_rejects_stale_authority() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.execution_window.not_after = 30;
        let error = validate_capital_execution_envelope(
            &artifact.authority_chain,
            &artifact.execution_window,
            &artifact.rail,
            21,
        )
        .unwrap_err();

        assert!(error.contains("stale"));
    }

    #[test]
    fn capital_execution_envelope_rejects_future_dated_authority_approval() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.authority_chain[0].approved_at = artifact.issued_at + 1;

        let error = validate_capital_execution_envelope(
            &artifact.authority_chain,
            &artifact.execution_window,
            &artifact.rail,
            artifact.issued_at,
        )
        .unwrap_err();

        assert!(error.contains("approvedAt"));
        assert!(error.contains("after instruction issuance"));
    }

    #[test]
    fn capital_instruction_artifact_rejects_transfer_without_completion_flow() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.source_kind = CapitalBookSourceKind::FacilityCommitment;
        artifact.action = CapitalExecutionInstructionAction::TransferFunds;
        artifact.governed_receipt_id = Some("rcpt-1".to_string());
        artifact.completion_flow_row_id = None;

        let error = artifact.validate().unwrap_err();

        assert!(error.contains("completionFlowRowId"));
    }

    #[test]
    fn capital_instruction_artifact_rejects_observed_execution_amount_mismatch() {
        let mut artifact = valid_capital_instruction_artifact();
        artifact.observed_execution = Some(CapitalExecutionObservation {
            observed_at: 12,
            external_reference_id: "wire-1".to_string(),
            amount: MonetaryAmount {
                units: 401,
                currency: "USD".to_string(),
            },
        });

        let error = artifact.validate().unwrap_err();

        assert!(error.contains("does not match intended amount"));
    }

    #[test]
    fn credit_bond_list_query_clamps_limit() {
        let query = CreditBondListQuery {
            agent_subject: Some("subject-1".to_string()),
            limit: Some(9_999),
            ..CreditBondListQuery::default()
        };
        let normalized = query.normalized();
        assert_eq!(normalized.limit, Some(MAX_CREDIT_BOND_LIST_LIMIT));
    }

    #[test]
    fn credit_bond_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCreditBond::sign(
            CreditBondArtifact {
                schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
                bond_id: "cbd-1".to_string(),
                issued_at: 10,
                expires_at: 20,
                lifecycle_state: CreditBondLifecycleState::Active,
                supersedes_bond_id: None,
                report: CreditBondReport {
                    schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
                    generated_at: 10,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    exposure: ExposureLedgerSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        active_decisions: 0,
                        superseded_decisions: 0,
                        actionable_receipts: 0,
                        pending_settlement_receipts: 0,
                        failed_settlement_receipts: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        truncated_receipts: false,
                        truncated_decisions: false,
                    },
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditBondDisposition::Hold,
                    prerequisites: CreditBondPrerequisites {
                        active_facility_required: false,
                        active_facility_met: true,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        currency_coherent: true,
                    },
                    support_boundary: CreditBondSupportBoundary::default(),
                    latest_facility_id: Some("cfd-1".to_string()),
                    terms: Some(CreditBondTerms {
                        facility_id: "cfd-1".to_string(),
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        collateral_amount: MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        },
                        reserve_requirement_amount: MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        },
                        outstanding_exposure_amount: MonetaryAmount {
                            units: 0,
                            currency: "USD".to_string(),
                        },
                        reserve_ratio_bps: 1_000,
                        coverage_ratio_bps: 10_000,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: vec![CreditBondFinding {
                        code: CreditBondReasonCode::ReserveHeld,
                        description: "reserve state is held".to_string(),
                        evidence_refs: Vec::new(),
                    }],
                },
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCreditBond =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn provider_risk_package_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let exposure = SignedExposureLedgerReport::sign(
            ExposureLedgerReport {
                schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
                generated_at: 1,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: ExposureLedgerSupportBoundary::default(),
                summary: ExposureLedgerSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    active_decisions: 0,
                    superseded_decisions: 0,
                    actionable_receipts: 0,
                    pending_settlement_receipts: 0,
                    failed_settlement_receipts: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    truncated_receipts: false,
                    truncated_decisions: false,
                },
                positions: vec![ExposureLedgerCurrencyPosition {
                    currency: "USD".to_string(),
                    governed_max_exposure_units: 4_000,
                    reserved_units: 0,
                    settled_units: 4_000,
                    pending_units: 0,
                    failed_units: 0,
                    provisional_loss_units: 0,
                    recovered_units: 0,
                    quoted_premium_units: 0,
                    active_quoted_premium_units: 0,
                }],
                receipts: Vec::new(),
                decisions: Vec::new(),
            },
            &keypair,
        )
        .unwrap();
        let scorecard = SignedCreditScorecardReport::sign(
            CreditScorecardReport {
                schema: CREDIT_SCORECARD_SCHEMA.to_string(),
                generated_at: 2,
                filters: ExposureLedgerQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..ExposureLedgerQuery::default()
                },
                support_boundary: CreditScorecardSupportBoundary::default(),
                summary: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 0,
                    returned_decisions: 0,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 0.95,
                    anomaly_count: 0,
                    probationary: false,
                },
                reputation: CreditScorecardReputationContext {
                    effective_score: 0.95,
                    probationary: false,
                    resolved_tier: None,
                    imported_signal_count: 0,
                    accepted_imported_signal_count: 0,
                },
                positions: exposure.body.positions.clone(),
                probation: CreditScorecardProbationStatus {
                    probationary: false,
                    reasons: Vec::new(),
                    receipt_count: 1,
                    span_days: 1,
                    target_receipt_count: 1,
                    target_span_days: 1,
                },
                dimensions: Vec::new(),
                anomalies: Vec::new(),
            },
            &keypair,
        )
        .unwrap();
        let envelope = SignedCreditProviderRiskPackage::sign(
            CreditProviderRiskPackage {
                schema: CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA.to_string(),
                generated_at: 3,
                subject_key: "subject-1".to_string(),
                filters: CreditProviderRiskPackageQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CreditProviderRiskPackageQuery::default()
                },
                support_boundary: CreditProviderRiskPackageSupportBoundary::default(),
                exposure,
                scorecard,
                facility_report: CreditFacilityReport {
                    schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
                    generated_at: 3,
                    filters: ExposureLedgerQuery {
                        agent_subject: Some("subject-1".to_string()),
                        ..ExposureLedgerQuery::default()
                    },
                    scorecard: CreditScorecardSummary {
                        matching_receipts: 1,
                        returned_receipts: 1,
                        matching_decisions: 0,
                        returned_decisions: 0,
                        currencies: vec!["USD".to_string()],
                        mixed_currency_book: false,
                        confidence: CreditScorecardConfidence::High,
                        band: CreditScorecardBand::Prime,
                        overall_score: 0.95,
                        anomaly_count: 0,
                        probationary: false,
                    },
                    disposition: CreditFacilityDisposition::Grant,
                    prerequisites: CreditFacilityPrerequisites {
                        minimum_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
                        runtime_assurance_met: true,
                        certification_required: false,
                        certification_met: true,
                        manual_review_required: false,
                    },
                    support_boundary: CreditFacilitySupportBoundary::default(),
                    terms: Some(CreditFacilityTerms {
                        credit_limit: MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        },
                        utilization_ceiling_bps: 8_000,
                        reserve_ratio_bps: 1_500,
                        concentration_cap_bps: 3_000,
                        ttl_seconds: 86_400,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: Vec::new(),
                },
                compliance_score: None,
                latest_facility: Some(CreditProviderFacilitySnapshot {
                    facility_id: "cfd-1".to_string(),
                    issued_at: 3,
                    expires_at: 4,
                    disposition: CreditFacilityDisposition::Grant,
                    lifecycle_state: CreditFacilityLifecycleState::Active,
                    credit_limit: Some(MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    }),
                    supersedes_facility_id: None,
                    signer_key: keypair.public_key().to_hex(),
                }),
                runtime_assurance: Some(CreditRuntimeAssuranceState {
                    governed_receipts: 1,
                    runtime_assurance_receipts: 1,
                    highest_tier: Some(RuntimeAssuranceTier::Verified),
                    latest_schema: Some("chio.runtime-attestation.azure-maa.jwt.v1".to_string()),
                    latest_verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                    latest_verifier: Some("verifier.chio".to_string()),
                    latest_evidence_sha256: Some("sha256-runtime".to_string()),
                    observed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    stale: false,
                }),
                certification: CreditCertificationState {
                    required: false,
                    state: None,
                    artifact_id: None,
                    checked_at: None,
                    published_at: None,
                },
                recent_loss_history: CreditRecentLossHistory {
                    summary: CreditRecentLossSummary {
                        matching_loss_events: 0,
                        returned_loss_events: 0,
                        failed_settlement_events: 0,
                        provisional_loss_events: 0,
                        recovered_events: 0,
                    },
                    entries: Vec::new(),
                },
                evidence_refs: Vec::new(),
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCreditProviderRiskPackage =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_book_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCapitalBookReport::sign(
            CapitalBookReport {
                schema: CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
                generated_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                support_boundary: CapitalBookSupportBoundary::default(),
                summary: CapitalBookSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_facilities: 1,
                    returned_facilities: 1,
                    matching_bonds: 1,
                    returned_bonds: 1,
                    matching_loss_events: 1,
                    returned_loss_events: 1,
                    currencies: vec!["USD".to_string()],
                    mixed_currency_book: false,
                    funding_sources: 2,
                    ledger_events: 3,
                    truncated_receipts: false,
                    truncated_facilities: false,
                    truncated_bonds: false,
                    truncated_loss_events: false,
                },
                sources: vec![
                    CapitalBookSource {
                        source_id: "capital-source:facility:cfd-1".to_string(),
                        kind: CapitalBookSourceKind::FacilityCommitment,
                        owner_role: CapitalBookRole::OperatorTreasury,
                        counterparty_role: CapitalBookRole::AgentCounterparty,
                        counterparty_id: "subject-1".to_string(),
                        currency: "USD".to_string(),
                        jurisdiction: None,
                        capital_source: Some(CreditFacilityCapitalSource::OperatorInternal),
                        facility_id: Some("cfd-1".to_string()),
                        bond_id: Some("cbd-1".to_string()),
                        committed_amount: Some(MonetaryAmount {
                            units: 4_000,
                            currency: "USD".to_string(),
                        }),
                        held_amount: None,
                        drawn_amount: Some(MonetaryAmount {
                            units: 500,
                            currency: "USD".to_string(),
                        }),
                        disbursed_amount: Some(MonetaryAmount {
                            units: 2_000,
                            currency: "USD".to_string(),
                        }),
                        released_amount: None,
                        repaid_amount: None,
                        impaired_amount: None,
                        description: "facility source".to_string(),
                    },
                    CapitalBookSource {
                        source_id: "capital-source:bond:cbd-1".to_string(),
                        kind: CapitalBookSourceKind::ReserveBook,
                        owner_role: CapitalBookRole::OperatorTreasury,
                        counterparty_role: CapitalBookRole::AgentCounterparty,
                        counterparty_id: "subject-1".to_string(),
                        currency: "USD".to_string(),
                        jurisdiction: None,
                        capital_source: Some(CreditFacilityCapitalSource::OperatorInternal),
                        facility_id: Some("cfd-1".to_string()),
                        bond_id: Some("cbd-1".to_string()),
                        committed_amount: None,
                        held_amount: Some(MonetaryAmount {
                            units: 400,
                            currency: "USD".to_string(),
                        }),
                        drawn_amount: None,
                        disbursed_amount: None,
                        released_amount: Some(MonetaryAmount {
                            units: 50,
                            currency: "USD".to_string(),
                        }),
                        repaid_amount: Some(MonetaryAmount {
                            units: 200,
                            currency: "USD".to_string(),
                        }),
                        impaired_amount: Some(MonetaryAmount {
                            units: 300,
                            currency: "USD".to_string(),
                        }),
                        description: "bond source".to_string(),
                    },
                ],
                events: vec![CapitalBookEvent {
                    event_id: "commit:cfd-1".to_string(),
                    kind: CapitalBookEventKind::Commit,
                    occurred_at: 10,
                    source_id: "capital-source:facility:cfd-1".to_string(),
                    owner_role: CapitalBookRole::OperatorTreasury,
                    counterparty_role: CapitalBookRole::AgentCounterparty,
                    counterparty_id: "subject-1".to_string(),
                    amount: MonetaryAmount {
                        units: 4_000,
                        currency: "USD".to_string(),
                    },
                    facility_id: Some("cfd-1".to_string()),
                    bond_id: None,
                    loss_event_id: None,
                    receipt_id: None,
                    description: "commit".to_string(),
                    evidence_refs: vec![CapitalBookEvidenceReference {
                        kind: CapitalBookEvidenceKind::CreditFacility,
                        reference_id: "cfd-1".to_string(),
                        observed_at: Some(10),
                        locator: Some("credit-facility:cfd-1".to_string()),
                    }],
                }],
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalBookReport =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_execution_instruction_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCapitalExecutionInstruction::sign(
            CapitalExecutionInstructionArtifact {
                schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
                instruction_id: "cei-1".to_string(),
                issued_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                source_id: "capital-source:bond:cbd-1".to_string(),
                source_kind: CapitalBookSourceKind::ReserveBook,
                governed_receipt_id: None,
                completion_flow_row_id: None,
                action: CapitalExecutionInstructionAction::LockReserve,
                owner_role: CapitalExecutionRole::OperatorTreasury,
                counterparty_role: CapitalExecutionRole::AgentCounterparty,
                counterparty_id: "subject-1".to_string(),
                amount: Some(MonetaryAmount {
                    units: 400,
                    currency: "USD".to_string(),
                }),
                authority_chain: vec![
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::OperatorTreasury,
                        principal_id: "treasury-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::Custodian,
                        principal_id: "custodian-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 10,
                    not_after: 20,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Manual,
                    rail_id: "rail-1".to_string(),
                    custody_provider_id: "custodian-1".to_string(),
                    source_account_ref: Some("reserve-main".to_string()),
                    destination_account_ref: None,
                    jurisdiction: Some("US-NY".to_string()),
                },
                intended_state: CapitalExecutionIntendedState::PendingExecution,
                reconciled_state: CapitalExecutionReconciledState::Matched,
                related_instruction_id: None,
                observed_execution: Some(CapitalExecutionObservation {
                    observed_at: 12,
                    external_reference_id: "wire-1".to_string(),
                    amount: MonetaryAmount {
                        units: 400,
                        currency: "USD".to_string(),
                    },
                }),
                support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
                evidence_refs: vec![CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::CreditBond,
                    reference_id: "cbd-1".to_string(),
                    observed_at: Some(10),
                    locator: Some("credit-bond:cbd-1".to_string()),
                }],
                description: "lock reserve".to_string(),
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalExecutionInstruction =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn capital_allocation_decision_round_trip_signature_verifies() {
        let keypair = Keypair::generate();
        let envelope = SignedCapitalAllocationDecision::sign(
            CapitalAllocationDecisionArtifact {
                schema: CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA.to_string(),
                allocation_id: "cad-1".to_string(),
                issued_at: 10,
                query: CapitalBookQuery {
                    agent_subject: Some("subject-1".to_string()),
                    ..CapitalBookQuery::default()
                },
                subject_key: "subject-1".to_string(),
                governed_receipt_id: "rc-1".to_string(),
                intent_id: "intent-1".to_string(),
                approval_token_id: Some("approval-1".to_string()),
                capability_id: "cap-1".to_string(),
                tool_server: "ledger".to_string(),
                tool_name: "transfer".to_string(),
                requested_amount: MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                },
                facility_id: Some("cfd-1".to_string()),
                bond_id: Some("cbd-1".to_string()),
                source_id: Some("capital-source:facility:cfd-1".to_string()),
                source_kind: Some(CapitalBookSourceKind::FacilityCommitment),
                reserve_source_id: Some("capital-source:bond:cbd-1".to_string()),
                outcome: CapitalAllocationDecisionOutcome::Allocate,
                authority_chain: vec![
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::OperatorTreasury,
                        principal_id: "treasury-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                    CapitalExecutionAuthorityStep {
                        role: CapitalExecutionRole::Custodian,
                        principal_id: "custodian-1".to_string(),
                        approved_at: 9,
                        expires_at: 20,
                        note: None,
                    },
                ],
                execution_window: CapitalExecutionWindow {
                    not_before: 10,
                    not_after: 20,
                },
                rail: CapitalExecutionRail {
                    kind: CapitalExecutionRailKind::Manual,
                    rail_id: "rail-1".to_string(),
                    custody_provider_id: "custodian-1".to_string(),
                    source_account_ref: Some("facility-main".to_string()),
                    destination_account_ref: Some("merchant-1".to_string()),
                    jurisdiction: Some("US-NY".to_string()),
                },
                current_outstanding_amount: Some(MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                }),
                projected_outstanding_amount: Some(MonetaryAmount {
                    units: 300,
                    currency: "USD".to_string(),
                }),
                current_reserve_amount: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                required_reserve_amount: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                reserve_delta_amount: None,
                utilization_ceiling_amount: Some(MonetaryAmount {
                    units: 900,
                    currency: "USD".to_string(),
                }),
                concentration_cap_amount: Some(MonetaryAmount {
                    units: 350,
                    currency: "USD".to_string(),
                }),
                instruction_drafts: vec![CapitalAllocationInstructionDraft {
                    source_id: "capital-source:facility:cfd-1".to_string(),
                    source_kind: CapitalBookSourceKind::FacilityCommitment,
                    action: CapitalExecutionInstructionAction::TransferFunds,
                    amount: MonetaryAmount {
                        units: 300,
                        currency: "USD".to_string(),
                    },
                    description: "transfer approved funds".to_string(),
                }],
                support_boundary: CapitalAllocationDecisionSupportBoundary::default(),
                findings: Vec::new(),
                evidence_refs: vec![CapitalBookEvidenceReference {
                    kind: CapitalBookEvidenceKind::Receipt,
                    reference_id: "rc-1".to_string(),
                    observed_at: Some(10),
                    locator: Some("receipt:rc-1".to_string()),
                }],
                description: "allocate governed action".to_string(),
            },
            &keypair,
        )
        .unwrap();

        assert!(envelope.verify_signature().unwrap());
        let restored: SignedCapitalAllocationDecision =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        assert!(restored.verify_signature().unwrap());
    }
}
