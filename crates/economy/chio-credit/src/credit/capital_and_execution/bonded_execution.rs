use super::*;

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
