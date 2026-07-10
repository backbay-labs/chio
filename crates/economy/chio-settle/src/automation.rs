use chio_core::hashing::sha256;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use serde::{Deserialize, Serialize};

use crate::SettlementError;

pub const CHIO_SETTLEMENT_AUTOMATION_JOB_SCHEMA: &str = "chio.settlement-automation-job.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAutomationTriggerKind {
    Cron,
    Log,
    CustomLogic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementWatchdogKind {
    EscrowTimeout,
    FinalityObservation,
    BondExpiry,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAutomationOutcome {
    Executed,
    DuplicateSuppressed,
    DelayedButSafe,
    ManualOverrideRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementWatchdogJob {
    pub schema: String,
    pub job_id: String,
    pub kind: SettlementWatchdogKind,
    pub trigger_kind: SettlementAutomationTriggerKind,
    pub chain_id: String,
    pub replay_window_secs: u64,
    pub cron_expression: String,
    pub state_fingerprint: String,
    pub operator_override_required: bool,
    pub reference_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementAutomationExecution {
    pub job_id: String,
    pub fired_at: u64,
    pub executed_at: u64,
    pub observed_state_fingerprint: String,
    pub duplicate_suppressed: bool,
    pub operator_override_used: bool,
    pub outcome: SettlementAutomationOutcome,
}

pub fn build_settlement_watchdog_job(
    dispatch: &Web3SettlementDispatchArtifact,
    cron_expression: &str,
    replay_window_secs: u64,
) -> Result<SettlementWatchdogJob, SettlementError> {
    if cron_expression.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "settlement watchdog cron expression is required".to_string(),
        ));
    }
    if replay_window_secs == 0 {
        return Err(SettlementError::InvalidInput(
            "settlement watchdog replay window must be non-zero".to_string(),
        ));
    }
    let state_fingerprint = sha256(
        format!(
            "dispatch_id={}\nchain_id={}\nescrow_id={}\nescrow_contract={}\nsettlement_token_address={}\nbeneficiary_address={}\noperator_key_hash={}\nsettlement_path={:?}\namount_units={}\namount_currency={}",
            dispatch.dispatch_id,
            dispatch.chain_id,
            dispatch.escrow_id,
            dispatch.escrow_contract,
            dispatch.settlement_token_address,
            dispatch.beneficiary_address,
            dispatch.operator_key_hash,
            dispatch.settlement_path,
            dispatch.settlement_amount.units,
            dispatch.settlement_amount.currency
        )
        .as_bytes(),
    )
    .to_hex_prefixed();
    Ok(SettlementWatchdogJob {
        schema: CHIO_SETTLEMENT_AUTOMATION_JOB_SCHEMA.to_string(),
        job_id: format!("chio-settle-watchdog-{}", dispatch.dispatch_id),
        kind: SettlementWatchdogKind::FinalityObservation,
        trigger_kind: SettlementAutomationTriggerKind::Cron,
        chain_id: dispatch.chain_id.clone(),
        replay_window_secs,
        cron_expression: cron_expression.to_string(),
        state_fingerprint,
        operator_override_required: true,
        reference_id: dispatch.dispatch_id.clone(),
    })
}

pub fn build_bond_watchdog_job(
    chain_id: &str,
    vault_id: &str,
    expires_at: u64,
    cron_expression: &str,
    replay_window_secs: u64,
) -> Result<SettlementWatchdogJob, SettlementError> {
    if chain_id.trim().is_empty() || vault_id.trim().is_empty() || cron_expression.trim().is_empty()
    {
        return Err(SettlementError::InvalidInput(
            "bond watchdog requires chain, vault id, and cron expression".to_string(),
        ));
    }
    if expires_at == 0 || replay_window_secs == 0 {
        return Err(SettlementError::InvalidInput(
            "bond watchdog expiry and replay window must be non-zero".to_string(),
        ));
    }
    let state_fingerprint =
        sha256(format!("{chain_id}:{vault_id}:{expires_at}").as_bytes()).to_hex_prefixed();
    Ok(SettlementWatchdogJob {
        schema: CHIO_SETTLEMENT_AUTOMATION_JOB_SCHEMA.to_string(),
        job_id: format!("chio-bond-watchdog-{vault_id}"),
        kind: SettlementWatchdogKind::BondExpiry,
        trigger_kind: SettlementAutomationTriggerKind::Cron,
        chain_id: chain_id.to_string(),
        replay_window_secs,
        cron_expression: cron_expression.to_string(),
        state_fingerprint,
        operator_override_required: true,
        reference_id: vault_id.to_string(),
    })
}

pub fn assess_watchdog_execution(
    job: &SettlementWatchdogJob,
    execution: &SettlementAutomationExecution,
) -> Result<(), SettlementError> {
    if job.job_id != execution.job_id {
        return Err(SettlementError::Verification(format!(
            "watchdog execution {} does not match job {}",
            execution.job_id, job.job_id
        )));
    }
    if execution.executed_at < execution.fired_at {
        return Err(SettlementError::Verification(
            "watchdog execution cannot complete before it fires".to_string(),
        ));
    }
    if execution.observed_state_fingerprint != job.state_fingerprint {
        return Err(SettlementError::Verification(
            "watchdog execution state fingerprint drifted".to_string(),
        ));
    }
    let delay = execution.executed_at.saturating_sub(execution.fired_at);
    if delay > job.replay_window_secs
        && execution.outcome != SettlementAutomationOutcome::DelayedButSafe
    {
        return Err(SettlementError::Verification(format!(
            "watchdog delay {} exceeds replay window {} without delayed-safe outcome",
            delay, job.replay_window_secs
        )));
    }
    if execution.duplicate_suppressed
        && execution.outcome != SettlementAutomationOutcome::DuplicateSuppressed
    {
        return Err(SettlementError::Verification(
            "watchdog duplicate suppression must be explicit".to_string(),
        ));
    }
    if job.operator_override_required && !execution.operator_override_used {
        return Err(SettlementError::Verification(
            "watchdog execution must retain operator override control".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chio_core::web3::settlement::Web3SettlementDispatchArtifact;

    use super::{
        assess_watchdog_execution, build_bond_watchdog_job, build_settlement_watchdog_job,
        SettlementAutomationExecution, SettlementAutomationOutcome,
    };

    use chio_test_support::prelude::*;

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        serde_json::from_str(include_str!(
            "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .test_unwrap()
    }

    #[test]
    fn builds_settlement_watchdog_job() {
        let dispatch = sample_dispatch();
        let job = build_settlement_watchdog_job(&dispatch, "*/5 * * * *", 600).test_unwrap();

        assert_eq!(job.reference_id, dispatch.dispatch_id);
        assert!(job.operator_override_required);

        let mut changed_key = dispatch.clone();
        changed_key.operator_key_hash =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let changed_key_job =
            build_settlement_watchdog_job(&changed_key, "*/5 * * * *", 600).test_unwrap();
        assert_ne!(job.state_fingerprint, changed_key_job.state_fingerprint);

        let mut changed_token = dispatch.clone();
        changed_token.settlement_token_address =
            "0x465F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string();
        let changed_token_job =
            build_settlement_watchdog_job(&changed_token, "*/5 * * * *", 600).test_unwrap();
        assert_ne!(job.state_fingerprint, changed_token_job.state_fingerprint);
    }

    #[test]
    fn builds_bond_watchdog_job() {
        let job = build_bond_watchdog_job(
            "eip155:8453",
            "vault-001",
            1_744_000_600,
            "*/10 * * * *",
            900,
        )
        .test_unwrap();

        assert_eq!(job.reference_id, "vault-001");
    }

    #[test]
    fn validates_watchdog_execution() {
        let dispatch = sample_dispatch();
        let job = build_settlement_watchdog_job(&dispatch, "*/5 * * * *", 600).test_unwrap();
        let execution = SettlementAutomationExecution {
            job_id: job.job_id.clone(),
            fired_at: 1_744_000_000,
            executed_at: 1_744_000_060,
            observed_state_fingerprint: job.state_fingerprint.clone(),
            duplicate_suppressed: false,
            operator_override_used: true,
            outcome: SettlementAutomationOutcome::Executed,
        };

        assess_watchdog_execution(&job, &execution).test_unwrap();
    }
}
