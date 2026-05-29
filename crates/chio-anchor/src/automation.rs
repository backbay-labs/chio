use chio_core::hashing::sha256;
use serde::{Deserialize, Serialize};

use crate::{
    AnchorError, EvmAnchorTarget, PreparedDelegateRegistration, PreparedEvmRootPublication,
};

pub const CHIO_ANCHOR_AUTOMATION_JOB_SCHEMA: &str = "chio.anchor-automation-job.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnchorAutomationTriggerKind {
    Cron,
    Log,
    CustomLogic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnchorAutomationExecutionOutcome {
    Executed,
    DuplicateSuppressed,
    DelayedButSafe,
    ManualOverrideRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorAutomationForwarder {
    pub delegate_address: String,
    pub delegate_expires_at: u64,
    pub registration: PreparedDelegateRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorAutomationJob {
    pub schema: String,
    pub job_id: String,
    pub trigger_kind: AnchorAutomationTriggerKind,
    pub chain_id: String,
    pub cron_expression: String,
    pub checkpoint_seq: u64,
    pub contract_address: String,
    pub state_fingerprint: String,
    pub replay_window_secs: u64,
    pub operator_override_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_forwarder: Option<AnchorAutomationForwarder>,
    pub publication: PreparedEvmRootPublication,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorAutomationExecution {
    pub job_id: String,
    pub fired_at: u64,
    pub executed_at: u64,
    pub observed_checkpoint_seq: u64,
    pub observed_state_fingerprint: String,
    pub duplicate_suppressed: bool,
    pub operator_override_used: bool,
    pub outcome: AnchorAutomationExecutionOutcome,
}

pub fn build_anchor_publication_job(
    target: &EvmAnchorTarget,
    cron_expression: &str,
    replay_window_secs: u64,
    publication: PreparedEvmRootPublication,
    delegate_registration: Option<PreparedDelegateRegistration>,
) -> Result<AnchorAutomationJob, AnchorError> {
    if cron_expression.trim().is_empty() {
        return Err(AnchorError::InvalidInput(
            "anchor automation cron expression is required".to_string(),
        ));
    }
    if replay_window_secs == 0 {
        return Err(AnchorError::InvalidInput(
            "anchor automation replay window must be non-zero".to_string(),
        ));
    }

    let state_fingerprint = sha256(
        format!(
            "{}:{}:{}:{}",
            publication.chain_id,
            publication.checkpoint_seq,
            publication.merkle_root,
            publication.publisher_address
        )
        .as_bytes(),
    )
    .to_hex_prefixed();

    let delegate_forwarder = match delegate_registration {
        Some(registration) => Some(AnchorAutomationForwarder {
            delegate_address: registration.delegate_address.clone(),
            delegate_expires_at: registration.expires_at,
            registration,
        }),
        None => None,
    };

    Ok(AnchorAutomationJob {
        schema: CHIO_ANCHOR_AUTOMATION_JOB_SCHEMA.to_string(),
        job_id: format!(
            "chio-anchor-{}-{}",
            target.chain_id.replace(':', "-"),
            publication.checkpoint_seq
        ),
        trigger_kind: AnchorAutomationTriggerKind::Cron,
        chain_id: target.chain_id.clone(),
        cron_expression: cron_expression.to_string(),
        checkpoint_seq: publication.checkpoint_seq,
        contract_address: publication.contract_address.clone(),
        state_fingerprint,
        replay_window_secs,
        operator_override_required: publication.requires_delegate_authorization,
        delegate_forwarder,
        publication,
    })
}

pub fn assess_anchor_automation_execution(
    job: &AnchorAutomationJob,
    execution: &AnchorAutomationExecution,
) -> Result<(), AnchorError> {
    if job.job_id != execution.job_id {
        return Err(AnchorError::Verification(format!(
            "anchor automation execution {} does not match job {}",
            execution.job_id, job.job_id
        )));
    }
    if execution.executed_at < execution.fired_at {
        return Err(AnchorError::Verification(
            "anchor automation execution cannot complete before it fired".to_string(),
        ));
    }
    if execution.observed_checkpoint_seq != job.checkpoint_seq {
        return Err(AnchorError::Verification(format!(
            "anchor automation observed checkpoint {} does not match expected {}",
            execution.observed_checkpoint_seq, job.checkpoint_seq
        )));
    }
    if execution.observed_state_fingerprint != job.state_fingerprint {
        return Err(AnchorError::Verification(
            "anchor automation state fingerprint drifted from the scheduled publication"
                .to_string(),
        ));
    }
    let delay = execution.executed_at.saturating_sub(execution.fired_at);
    if delay > job.replay_window_secs
        && execution.outcome != AnchorAutomationExecutionOutcome::DelayedButSafe
    {
        return Err(AnchorError::Verification(format!(
            "anchor automation delay {} exceeds replay window {} without explicit delayed-safe outcome",
            delay, job.replay_window_secs
        )));
    }
    if execution.duplicate_suppressed
        && execution.outcome != AnchorAutomationExecutionOutcome::DuplicateSuppressed
    {
        return Err(AnchorError::Verification(
            "duplicate suppression must be reported explicitly".to_string(),
        ));
    }
    if job.operator_override_required && !execution.operator_override_used {
        return Err(AnchorError::Verification(
            "delegate-driven anchor automation must record operator override availability"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chio_core::crypto::Keypair;
    use chio_core::web3::{
        SignedWeb3IdentityBinding, Web3IdentityBindingCertificate, Web3KeyBindingPurpose,
        CHIO_KEY_BINDING_CERTIFICATE_SCHEMA,
    };
    use chio_kernel::checkpoint::KernelCheckpoint;

    use crate::{
        assess_anchor_automation_execution, build_anchor_publication_job,
        checkpoint_statement_from_kernel, kernel_checkpoint_from_statement,
        prepare_delegate_registration, prepare_root_publication, AnchorAutomationExecution,
        AnchorAutomationExecutionOutcome, EvmAnchorTarget,
    };

    use chio_test_support::prelude::*;

    fn sample_binding() -> SignedWeb3IdentityBinding {
        let keypair = Keypair::generate();
        let certificate = Web3IdentityBindingCertificate {
            schema: CHIO_KEY_BINDING_CERTIFICATE_SCHEMA.to_string(),
            chio_identity: "did:chio:test-operator".to_string(),
            chio_public_key: keypair.public_key(),
            chain_scope: vec!["eip155:8453".to_string()],
            purpose: vec![Web3KeyBindingPurpose::Anchor],
            settlement_address: "0x1000000000000000000000000000000000000001".to_string(),
            issued_at: 1_744_000_000,
            expires_at: 1_744_086_400,
            nonce: "bind-001".to_string(),
        };
        SignedWeb3IdentityBinding {
            signature: keypair.sign_canonical(&certificate).test_unwrap().0,
            certificate,
        }
    }

    fn sample_checkpoint() -> KernelCheckpoint {
        let proof: chio_core::web3::AnchorInclusionProof = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
        ))
        .test_unwrap();
        kernel_checkpoint_from_statement(&checkpoint_statement_from_kernel(
            &kernel_checkpoint_from_statement(&proof.checkpoint_statement),
        ))
    }

    fn sample_target() -> EvmAnchorTarget {
        EvmAnchorTarget {
            chain_id: "eip155:8453".to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
            contract_address: "0x1000000000000000000000000000000000000003".to_string(),
            operator_address: "0x1000000000000000000000000000000000000001".to_string(),
            publisher_address: "0x1000000000000000000000000000000000000002".to_string(),
        }
    }

    #[test]
    fn builds_anchor_automation_job_with_delegate() {
        let binding = sample_binding();
        let checkpoint = sample_checkpoint();
        let target = sample_target();
        let publication = prepare_root_publication(&target, &checkpoint, &binding).test_unwrap();
        let registration = prepare_delegate_registration(
            &target,
            "0x1000000000000000000000000000000000000002",
            1_744_086_400,
        )
        .test_unwrap();

        let job = build_anchor_publication_job(
            &target,
            "0 */6 * * *",
            900,
            publication,
            Some(registration),
        )
        .test_unwrap();

        assert_eq!(job.schema, "chio.anchor-automation-job.v1");
        assert!(job.operator_override_required);
        assert!(job.delegate_forwarder.is_some());
    }

    #[test]
    fn validates_anchor_automation_execution() {
        let binding = sample_binding();
        let checkpoint = sample_checkpoint();
        let target = sample_target();
        let publication = prepare_root_publication(&target, &checkpoint, &binding).test_unwrap();
        let registration = prepare_delegate_registration(
            &target,
            "0x1000000000000000000000000000000000000002",
            1_744_086_400,
        )
        .test_unwrap();
        let job = build_anchor_publication_job(
            &target,
            "0 */6 * * *",
            900,
            publication,
            Some(registration),
        )
        .test_unwrap();
        let execution = AnchorAutomationExecution {
            job_id: job.job_id.clone(),
            fired_at: 1_744_000_000,
            executed_at: 1_744_000_030,
            observed_checkpoint_seq: job.checkpoint_seq,
            observed_state_fingerprint: job.state_fingerprint.clone(),
            duplicate_suppressed: false,
            operator_override_used: true,
            outcome: AnchorAutomationExecutionOutcome::Executed,
        };

        assess_anchor_automation_execution(&job, &execution).test_unwrap();
    }
}
