//! Signed-artifact schema registry and fail-closed compatibility gate.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::capability::{
    aggregate_invocation::AGGREGATE_BUDGET_ROOT_SCHEMA,
    cumulative_approval::CUMULATIVE_APPROVAL_ROOT_SCHEMA, features::CHIO_CAPABILITIES_SCHEMA,
    governance::THRESHOLD_APPROVAL_PROPOSAL_SCHEMA, token::CHIO_CAPABILITY_SCHEMA,
};
use crate::economic_continuity::{
    CHIO_ECONOMIC_EFFECT_DISPATCH_COMMIT_SCHEMA, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use crate::error::{Error, Result};
use crate::oracle::CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA;
use crate::receipt::{body::CHIO_RECEIPT_SCHEMA, lineage::CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA};
use crate::runtime_attestation::{
    AWS_NITRO_ATTESTATION_SCHEMA, AZURE_MAA_ATTESTATION_SCHEMA,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
};
use crate::session::{CHIO_REQUEST_LINEAGE_RECORD_SCHEMA, CHIO_SESSION_ANCHOR_SCHEMA};

/// Anchor-batch signed artifact schema. Defined here so non-anchor verifiers
/// can reject unknown signed artifacts before loading the `chio-anchor` crate.
pub const CHIO_ANCHOR_BATCH_V1_SCHEMA: &str = "chio.anchor_batch.v1";
pub const CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA: &str = "chio.anchor-inclusion-proof.v1";
pub const CHIO_ANCHOR_INCLUSION_PROOF_V2_SCHEMA: &str = "chio.anchor-inclusion-proof.v2";
pub const CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA: &str = "chio.anchor-proof-bundle.v1";
pub const CHIO_ANCHOR_PROOF_BUNDLE_V2_SCHEMA: &str = "chio.anchor-proof-bundle.v2";
pub const CHIO_BUDGET_SNAPSHOT_ANCHOR_PROVENANCE_V1_SCHEMA: &str =
    "chio.budget-snapshot-anchor-provenance.v1";
pub const CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA: &str = "chio.bilateral-signature-slice.v1";
pub const CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_V1_SCHEMA: &str =
    "chio.frost.authorization-slot-checkpoint.v1";
pub const CHIO_FROST_AUTHORIZATION_V1_SCHEMA: &str = "chio.frost.authorization.v1";
pub const CHIO_FROST_EPOCH_CHECKPOINT_V1_SCHEMA: &str = "chio.frost.epoch-checkpoint.v1";
pub const CHIO_FROST_ROSTER_V1_SCHEMA: &str = "chio.frost.roster.v1";
pub const CHIO_CLEARING_PARTICIPANT_SNAPSHOT_V1_SCHEMA: &str =
    "chio.clearing.participant-snapshot.v1";
pub const CHIO_CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.clearing.participant-snapshot-acknowledgement.v1";
pub const CHIO_CLEARING_INPUT_MANIFEST_V1_SCHEMA: &str = "chio.clearing.input-manifest.v1";
pub const CHIO_CLEARING_NETTING_ROUND_CORE_V1_SCHEMA: &str = "chio.clearing.netting-round-core.v1";
pub const CHIO_CLEARING_PARTICIPANT_STATEMENT_V1_SCHEMA: &str =
    "chio.clearing.participant-statement.v1";
pub const CHIO_CLEARING_SETTLEMENT_INTENT_V1_SCHEMA: &str = "chio.clearing.settlement-intent.v1";
pub const CHIO_CLEARING_SETTLEMENT_RECONCILIATION_V1_SCHEMA: &str =
    "chio.clearing.settlement-reconciliation.v1";
pub const CHIO_CLEARING_ROUND_SATISFACTION_V1_SCHEMA: &str = "chio.clearing.round-satisfaction.v1";
pub const CHIO_CLEARING_ZERO_INTENT_RECONCILIATION_V1_SCHEMA: &str =
    "chio.clearing.zero-intent-reconciliation.v1";
pub const CHIO_CLEARING_ATOM_TRANSFORMATION_V1_SCHEMA: &str =
    "chio.clearing.atom-transformation.v1";
pub const CHIO_CLEARING_OUTPUT_MANIFEST_V1_SCHEMA: &str = "chio.clearing.output-manifest.v1";
pub const CHIO_CLEARING_PARTICIPANT_ACCEPTANCE_V1_SCHEMA: &str =
    "chio.clearing.participant-acceptance.v1";
pub const CHIO_CLEARING_ROUND_FINALIZATION_V1_SCHEMA: &str = "chio.clearing.round-finalization.v1";
pub const CHIO_CLEARING_ZERO_DISPATCH_PROOF_V1_SCHEMA: &str =
    "chio.clearing.zero-dispatch-proof.v1";
pub const CHIO_CLEARING_ROUND_ABORT_V1_SCHEMA: &str = "chio.clearing.round-abort.v1";
pub const CHIO_CHANNEL_FUNDING_EVIDENCE_V1_SCHEMA: &str = "chio.channel.funding-evidence.v1";
pub const CHIO_CHANNEL_OPEN_INTENT_V1_SCHEMA: &str = "chio.channel.open-intent.v1";
pub const CHIO_CHANNEL_FUNDING_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.channel.funding-acknowledgement.v1";
pub const CHIO_CHANNEL_OPEN_V1_SCHEMA: &str = "chio.channel.open.v1";
pub const CHIO_CHANNEL_RESERVATION_V1_SCHEMA: &str = "chio.channel.reservation.v1";
pub const CHIO_CHANNEL_STATE_V1_SCHEMA: &str = "chio.channel.state.v1";
pub const CHIO_CHANNEL_CLOSE_V1_SCHEMA: &str = "chio.channel.close.v1";
pub const CHIO_CHANNEL_DISPUTE_V1_SCHEMA: &str = "chio.channel.dispute.v1";
pub const CHIO_CHANNEL_RELEASE_AUTHORIZATION_V1_SCHEMA: &str =
    "chio.channel.release-authorization.v1";
pub const CHIO_CHANNEL_TERMINAL_OUTCOME_COMMITMENT_V1_SCHEMA: &str =
    "chio.channel.terminal-outcome-commitment.v1";
pub const CHIO_FINCRED_CREDIT_SCORECARD_V1_SCHEMA: &str = "chio.fincred.credit-scorecard.v1";
pub const CHIO_FINCRED_EXPOSURE_HISTORY_V1_SCHEMA: &str = "chio.fincred.exposure-history.v1";
pub const CHIO_FINCRED_SETTLEMENT_RELIABILITY_V1_SCHEMA: &str =
    "chio.fincred.settlement-reliability.v1";
pub const CHIO_FINCRED_PREMIUM_HISTORY_V1_SCHEMA: &str = "chio.fincred.premium-history.v1";
pub const CHIO_FINCRED_LOSS_HISTORY_V1_SCHEMA: &str = "chio.fincred.loss-history.v1";
pub const CHIO_FINCRED_SOURCE_MEMBER_V1_SCHEMA: &str = "chio.fincred.source-member.v1";
pub const CHIO_FINCRED_SOURCE_CHECKPOINT_V1_SCHEMA: &str = "chio.fincred.source-checkpoint.v1";
pub const CHIO_FINCRED_SOURCE_COMPLETENESS_ATTESTATION_V1_SCHEMA: &str =
    "chio.fincred.source-completeness-attestation.v1";
pub const CHIO_FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_V1_SCHEMA: &str =
    "chio.financial-agent-passport.source-manifest.v1";
pub const CHIO_FINANCIAL_AGENT_PASSPORT_PRESENTATION_CHALLENGE_V1_SCHEMA: &str =
    "chio.financial-agent-passport-presentation-challenge.v1";
/// Cognition-market finding artifact.
pub const CHIO_FINDING_V1_SCHEMA: &str = "chio.finding.v1";
/// Cognition-market venue admission bundle.
pub const CHIO_FINDING_ADMISSION_V1_SCHEMA: &str = "chio.finding.admission.v1";
/// Cognition-market bond-backing collateral allocation.
pub const CHIO_FINDING_BOND_BACKING_V1_SCHEMA: &str = "chio.finding.bond-backing.v1";
/// Cognition-market reusable challenge-verifier profile.
pub const CHIO_FINDING_CHALLENGE_VERIFIER_PROFILE_V1_SCHEMA: &str =
    "chio.finding.challenge-verifier-profile.v1";
/// Cognition-market failed-delivery terminal.
pub const CHIO_FINDING_FAILED_DELIVERY_V1_SCHEMA: &str = "chio.finding.failed-delivery.v1";
/// Cognition-market seller market terms.
pub const CHIO_FINDING_MARKET_TERMS_V1_SCHEMA: &str = "chio.finding.market-terms.v1";
/// Cognition-market settled purchase record.
pub const CHIO_FINDING_PURCHASE_RECORD_V1_SCHEMA: &str = "chio.finding.purchase-record.v1";
/// Cognition-market issuer-signed seller authorization.
pub const CHIO_FINDING_SELLER_AUTHORIZATION_V1_SCHEMA: &str =
    "chio.finding.seller-authorization.v1";
/// Cognition-market verifier facet report.
pub const CHIO_FINDING_VERIFIER_REPORT_V1_SCHEMA: &str = "chio.finding.verifier-report.v1";
pub const CHIO_FISCAL_CHARTER_V1_SCHEMA: &str = "chio.fiscal.charter.v1";
pub const CHIO_FISCAL_SCHEDULE_V1_SCHEMA: &str = "chio.fiscal.schedule.v1";
pub const CHIO_FISCAL_PROPOSAL_V1_SCHEMA: &str = "chio.fiscal.proposal.v1";
pub const CHIO_FISCAL_PROPOSAL_ADMISSION_V1_SCHEMA: &str = "chio.fiscal.proposal-admission.v1";
pub const CHIO_FISCAL_APPROVAL_V1_SCHEMA: &str = "chio.fiscal.approval.v1";
pub const CHIO_FISCAL_ACTIVATION_V1_SCHEMA: &str = "chio.fiscal.activation.v1";
pub const CHIO_FISCAL_CONSUMER_READINESS_V1_SCHEMA: &str = "chio.fiscal.consumer-readiness.v1";
pub const CHIO_FISCAL_CONTINUITY_CHECKPOINT_V1_SCHEMA: &str =
    "chio.fiscal.continuity-checkpoint.v1";
pub const CHIO_ECONSIM_QUALIFICATION_MATRIX_V1_SCHEMA: &str =
    "chio.econsim.qualification-matrix.v1";
pub const CHIO_OBLIGATION_STATUS_PROOF_V1_SCHEMA: &str = "chio.obligation.status-proof.v1";
pub const CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA: &str = "chio.credit.facility-bind.v1";
pub const CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA: &str = "chio.credit.receivable-iou-envelope.v1";
pub const CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA: &str =
    "chio.factor.assignment-bind-authorization.v1";
pub const CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA: &str = "chio.factor.assignment-agreement.v1";
pub const CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.factor.assignment-acknowledgement.v1";
pub const CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA: &str =
    "chio.factor.assignment-not-applied.v1";
pub const CHIO_OUTCOME_PREDICATE_V1_SCHEMA: &str = "chio.outcome.predicate.v1";
pub const CHIO_OUTCOME_PRICING_V1_SCHEMA: &str = "chio.outcome.pricing.v1";
pub const CHIO_OUTCOME_SLA_V1_SCHEMA: &str = "chio.outcome.sla.v1";
pub const CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA: &str = "chio.outcome.eligibility.v1";
pub const CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA: &str = "chio.outcome.delivery-checkpoint.v1";
pub const CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    "chio.outcome.delivery-acknowledgement.v1";
pub const CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA: &str =
    "chio.outcome.delivery-nonacceptance.v1";
pub const CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA: &str = "chio.outcome.output-provenance.v1";
pub const CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA: &str = "chio.outcome.contractual-zero.v1";
pub const CHIO_PARAMETRIC_POLICY_V1_SCHEMA: &str = "chio.parametric.policy.v1";
pub const CHIO_TRANSACTION_PASSPORT_V1_SCHEMA: &str = "chio.transaction-passport.v1";
pub const CHIO_TRANSACTION_EVIDENCE_GRAPH_V1_SCHEMA: &str = "chio.transaction.evidence-graph.v1";
pub const CHIO_TRANSACTION_CLAIM_SET_V1_SCHEMA: &str = "chio.transaction.claim-set.v1";
pub const CHIO_TRANSACTION_VERIFIER_POLICY_V1_SCHEMA: &str = "chio.transaction.verifier-policy.v1";
pub const CHIO_TRANSACTION_VERIFIER_REPORT_V1_SCHEMA: &str = "chio.transaction.verifier-report.v1";
pub const CHIO_TRANSACTION_RUNTIME_SECURITY_REPORT_V1_SCHEMA: &str =
    "chio.transaction.runtime-security-report.v1";
pub const CHIO_CAPABILITY_PROOF_V1_SCHEMA: &str = "chio.capability.proof.v1";
pub const CHIO_GUARD_DECISION_V1_SCHEMA: &str = "chio.guard.decision.v1";
pub const CHIO_POLICY_BUNDLE_V1_SCHEMA: &str = "chio.policy.bundle.v1";
pub const CHIO_TRUST_ROOT_V1_SCHEMA: &str = "chio.trust.root.v1";
pub const CHIO_REQUEST_DIGEST_V1_SCHEMA: &str = "chio.request.digest.v1";
pub const CHIO_RESPONSE_DIGEST_V1_SCHEMA: &str = "chio.response.digest.v1";
pub const CHIO_COMMERCE_ORDER_CONTEXT_V1_SCHEMA: &str = "chio.commerce.order-context.v1";
pub const CHIO_COMMERCE_EVENT_LOG_V1_SCHEMA: &str = "chio.commerce.event-log.v1";
pub const CHIO_COMMERCE_PAYMENT_LIFECYCLE_V1_SCHEMA: &str = "chio.commerce.payment-lifecycle.v1";
pub const CHIO_COMMERCE_MANDATE_ALLOWANCE_LEDGER_V1_SCHEMA: &str =
    "chio.commerce.mandate-allowance-ledger.v1";
pub const CHIO_COMMERCE_PROTOCOL_PAYLOAD_V1_SCHEMA: &str = "chio.commerce.protocol-payload.v1";
pub const CHIO_COMMERCE_SETTLEMENT_PACKET_V1_SCHEMA: &str = "chio.commerce.settlement-packet.v1";
pub const CHIO_COMMERCE_PROVIDER_PASSPORT_V1_SCHEMA: &str = "chio.commerce.provider-passport.v1";
pub const CHIO_COMMERCE_REPUTATION_SNAPSHOT_V1_SCHEMA: &str =
    "chio.commerce.reputation-snapshot.v1";
pub const CHIO_COMMERCE_FEDERATION_TRUST_BUNDLE_V1_SCHEMA: &str =
    "chio.commerce.federation-trust-bundle.v1";
pub const CHIO_COMMERCE_ORDER_PASSPORT_V1_SCHEMA: &str = "chio.commerce.order-passport.v1";
pub const CHIO_COMMERCE_PROVIDER_DISCOVERY_SNAPSHOT_V1_SCHEMA: &str =
    "chio.commerce.provider-discovery-snapshot.v1";
pub const CHIO_COMMERCE_PROVIDER_SELECTION_REPORT_V1_SCHEMA: &str =
    "chio.commerce.provider-selection-report.v1";
pub const CHIO_COMMERCE_SLA_COMMITMENT_V1_SCHEMA: &str = "chio.commerce.sla-commitment.v1";
pub const CHIO_COMMERCE_SLA_PERFORMANCE_REPORT_V1_SCHEMA: &str =
    "chio.commerce.sla-performance-report.v1";
pub const CHIO_WORKFLOW_PREFLIGHT_PLAN_V1_SCHEMA: &str = "chio.workflow.preflight-plan.v1";
pub const CHIO_WORKFLOW_PREFLIGHT_REPORT_V1_SCHEMA: &str = "chio.workflow.preflight-report.v1";
pub const CHIO_CRYPTO_VERIFICATION_CONTEXT_V1_SCHEMA: &str = "chio.crypto.verification-context.v1";
pub const CHIO_TRUST_KEY_STATE_V1_SCHEMA: &str = "chio.trust.key-state.v1";
pub const CHIO_TRUST_REVOCATION_SNAPSHOT_V1_SCHEMA: &str = "chio.trust.revocation-snapshot.v1";
pub const CHIO_TRUST_SCORECARD_SNAPSHOT_V1_SCHEMA: &str = "chio.trust.scorecard-snapshot.v1";
pub const CHIO_TRUST_REPUTATION_IMPORT_REPORT_V1_SCHEMA: &str =
    "chio.trust.reputation-import-report.v1";
pub const CHIO_DISCLOSURE_VERIFIER_PRIVACY_PROFILE_V1_SCHEMA: &str =
    "chio.disclosure.verifier-privacy-profile.v1";
pub const CHIO_DISCLOSURE_CRYPTO_CONTEXT_REPORT_V1_SCHEMA: &str =
    "chio.disclosure.crypto-context-report.v1";
pub const CHIO_ATTEST_SELECTIVE_DISCLOSURE_PROOF_V1_SCHEMA: &str =
    "chio.attest.selective-disclosure-proof.v1";
pub const CHIO_BBS_PROJECTION_MANIFEST_V2_SCHEMA: &str = "chio.bbs-projection.manifest.v2";
pub const CHIO_DISCLOSURE_CAPSULE_V1_SCHEMA: &str = "chio.disclosure.capsule.v1";
pub const CHIO_LINEAGE_SIGNED_SUBGRAPH_V1_SCHEMA: &str = "chio.lineage.signed-subgraph.v1";
pub const CHIO_DISCLOSURE_LEAKAGE_LEDGER_V1_SCHEMA: &str = "chio.disclosure.leakage-ledger.v1";
pub const CHIO_DISCLOSURE_LINEAGE_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.disclosure.lineage-verifier-report.v1";
pub const CHIO_TRANSPARENCY_INCLUSION_PROOF_V1_SCHEMA: &str =
    "chio.transparency.inclusion-proof.v1";
pub const CHIO_TRANSPARENCY_INCLUSION_PROOF_V2_SCHEMA: &str =
    "chio.transparency.inclusion-proof.v2";
pub const CHIO_POLICY_ACTIVATION_RECEIPT_V1_SCHEMA: &str = "chio.policy.activation-receipt.v1";
pub const CHIO_RUNTIME_EXECUTION_LEASE_V1_SCHEMA: &str = "chio.runtime.execution-lease.v1";
pub const CHIO_RUNTIME_TOOL_SERVER_ACK_V1_SCHEMA: &str = "chio.runtime.tool-server-ack.v1";
pub const CHIO_RUNTIME_TRUSTED_TIME_PROOF_V1_SCHEMA: &str = "chio.runtime.trusted-time-proof.v1";
pub const CHIO_RUNTIME_REVOCATION_FRESHNESS_PROOF_V1_SCHEMA: &str =
    "chio.runtime.revocation-freshness-proof.v1";
pub const CHIO_RUNTIME_SANDBOX_ATTESTATION_V1_SCHEMA: &str = "chio.runtime.sandbox-attestation.v1";
pub const CHIO_RUNTIME_ATTACK_SIMULATION_REPORT_V1_SCHEMA: &str =
    "chio.runtime.attack-simulation-report.v1";
pub const CHIO_RUNTIME_CHAOS_RUN_REPORT_V1_SCHEMA: &str = "chio.runtime.chaos-run-report.v1";
pub const CHIO_RISK_COMPTROLLER_REPORT_V1_SCHEMA: &str = "chio.risk.comptroller-report.v1";
pub const CHIO_RISK_COLLATERAL_POSITION_REPORT_V1_SCHEMA: &str =
    "chio.risk.collateral-position-report.v1";
pub const CHIO_RISK_GUARANTEE_DECISION_V1_SCHEMA: &str = "chio.risk.guarantee-decision.v1";
pub const CHIO_RISK_ADJUDICATION_JURISDICTION_RECEIPT_V1_SCHEMA: &str =
    "chio.risk.adjudication-jurisdiction-receipt.v1";
/// Schema id for the unified spend/exposure comptroller surface projection.
pub const CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA: &str = "chio.comptroller.surface-report.v1";
pub const CHIO_ENTERPRISE_DATA_GOVERNANCE_REPORT_V1_SCHEMA: &str =
    "chio.enterprise.data-governance-report.v1";
pub const CHIO_ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_V1_SCHEMA: &str =
    "chio.enterprise.evidence-export-bundle.v1";
pub const CHIO_ENTERPRISE_TELEMETRY_PROJECTION_V1_SCHEMA: &str =
    "chio.enterprise.telemetry-projection.v1";
pub const CHIO_ENTERPRISE_APPROVAL_CASE_V1_SCHEMA: &str = "chio.enterprise.approval-case.v1";
pub const CHIO_ENTERPRISE_CONTROL_EVIDENCE_MAP_V1_SCHEMA: &str =
    "chio.enterprise.control-evidence-map.v1";
pub const CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA: &str = "chio.agent-web-proof-envelope.v1";
pub const CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA: &str = "chio.agent-web-proof-envelope.v2";
pub const CHIO_AGENT_WEB_EXTERNAL_PROJECTION_MANIFEST_V1_SCHEMA: &str =
    "chio.agent-web.external-projection-manifest.v1";
pub const CHIO_AGENT_WEB_INTEROP_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.agent-web.interop-verifier-report.v1";
pub const CHIO_PROOF_ROOM_BUNDLE_V1_SCHEMA: &str = "chio.proof-room.bundle.v1";
pub const CHIO_PROOF_ROOM_VERIFIER_REPORT_V1_SCHEMA: &str = "chio.proof-room.verifier-report.v1";
pub const CHIO_PROOF_ROOM_FIXTURE_CATALOG_V1_SCHEMA: &str = "chio.proof-room.fixture-catalog.v1";
pub const CHIO_PROOF_ROOM_FIXTURE_ROOT_CATALOG_V1_SCHEMA: &str =
    "chio.proof-room.fixture-root-catalog.v1";
pub const CHIO_PROOF_ROOM_RECEIPT_EVIDENCE_V1_SCHEMA: &str = "chio.proof-room.receipt-evidence.v1";
pub const CHIO_PROOF_DOCKER_QUICKSTART_EVIDENCE_V1_SCHEMA: &str =
    "chio.proof.docker-quickstart-evidence.v1";
pub const CHIO_PROOF_RELEASE_TRUTH_V1_SCHEMA: &str = "chio.proof.release-truth.v1";
pub const CHIO_PROOF_FIRST_RUN_CAPABILITY_PROOF_V1_SCHEMA: &str =
    "chio.proof.first-run.capability-proof.v1";
pub const CHIO_PROOF_FIRST_RUN_GUARD_REPORT_V1_SCHEMA: &str =
    "chio.proof.first-run.guard-report.v1";
pub const CHIO_PROOF_FIRST_RUN_TRUST_ROOTS_V1_SCHEMA: &str = "chio.proof.first-run.trust-roots.v1";
pub const CHIO_PROOF_FIRST_RUN_COMMAND_LOG_V1_SCHEMA: &str = "chio.proof.first-run.command-log.v1";
pub const CHIO_RUNTIME_TERMINAL_RECEIPT_V1_SCHEMA: &str = "chio.runtime.terminal-receipt.v1";
pub const CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA: &str = "chio.web3-settlement-dispatch.v1";
pub const CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V1_SCHEMA: &str =
    "chio.web3-settlement-execution-receipt.v1";
pub const CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA: &str = "chio.web3-settlement-dispatch.v2";
pub const CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V2_SCHEMA: &str =
    "chio.web3-settlement-execution-receipt.v2";
pub const CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_V1_SCHEMA: &str =
    "chio.web3-settlement-proof-bundle.v1";
pub const CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.public-settlement-verifier-report.v1";
pub const CHIO_SWARM_TASK_GRAPH_V1_SCHEMA: &str = "chio.swarm.task-graph.v1";
pub const CHIO_SWARM_CONTINUATION_TOKEN_V1_SCHEMA: &str = "chio.swarm.continuation-token.v1";
pub const CHIO_SWARM_DELEGATION_WITNESS_CHAIN_V1_SCHEMA: &str =
    "chio.swarm.delegation-witness-chain.v1";
pub const CHIO_SWARM_JOIN_RECEIPT_V1_SCHEMA: &str = "chio.swarm.join-receipt.v1";
pub const CHIO_SWARM_ROUTE_PLAN_RECEIPT_V1_SCHEMA: &str = "chio.swarm.route-plan-receipt.v1";
pub const CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_V1_SCHEMA: &str =
    "chio.swarm.terminal-graph-receipt.v1";
pub const CHIO_SWARM_BUDGET_POOL_V1_SCHEMA: &str = "chio.swarm.budget-pool.v1";
pub const CHIO_SWARM_REVOCATION_EPOCH_V1_SCHEMA: &str = "chio.swarm.revocation-epoch.v1";
pub const CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_V1_SCHEMA: &str =
    "chio.swarm.authority-verifier-report.v1";

type SignedArtifactSchemaSpec = (&'static str, Option<(&'static str, &'static str)>);

const SIGNED_ARTIFACT_SCHEMA_SPECS: &[SignedArtifactSchemaSpec] = &[
    (
        AGGREGATE_BUDGET_ROOT_SCHEMA,
        Some(("aggregate_budget_root_binding", "protocol-primitives-v1")),
    ),
    (
        CHIO_BUDGET_SNAPSHOT_ANCHOR_PROVENANCE_V1_SCHEMA,
        Some((
            "budget_snapshot_anchor_provenance",
            "economic-state-continuity-v1",
        )),
    ),
    (
        CHIO_CAPABILITIES_SCHEMA,
        Some((
            "capability_negotiation",
            "schema-registry/v1/capability-negotiation",
        )),
    ),
    (
        CHIO_CAPABILITY_SCHEMA,
        Some(("capability_token", "schema-registry/v1/capability-token-v1")),
    ),
    (
        CUMULATIVE_APPROVAL_ROOT_SCHEMA,
        Some(("cumulative_approval_root_binding", "protocol-primitives-v1")),
    ),
    (
        THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
        Some(("threshold_approval_proposal", "protocol-primitives-v1")),
    ),
    (
        CHIO_RECEIPT_SCHEMA,
        Some(("receipt", "schema-registry/v1/receipt-v1")),
    ),
    (
        CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
        Some(("receipt_lineage", "schema-registry/v1/receipt-lineage-v1")),
    ),
    (
        CHIO_ANCHOR_BATCH_V1_SCHEMA,
        Some(("anchor_batch", "schema-registry/v1/anchor-batch-v1")),
    ),
    (
        CHIO_ANCHOR_INCLUSION_PROOF_V1_SCHEMA,
        Some(("anchor_inclusion_proof", "public-settlement-v1")),
    ),
    (
        CHIO_ANCHOR_INCLUSION_PROOF_V2_SCHEMA,
        Some(("anchor_inclusion_proof", "checkpoint-transparency-v2")),
    ),
    (
        CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA,
        Some(("anchor_proof_bundle", "public-settlement-v1")),
    ),
    (
        CHIO_ANCHOR_PROOF_BUNDLE_V2_SCHEMA,
        Some(("anchor_proof_bundle", "checkpoint-transparency-v2")),
    ),
    (
        CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA,
        Some(("bilateral_dsse_signature_slice", "federation-dsse-slice")),
    ),
    (
        CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_V1_SCHEMA,
        Some((
            "frost_authorization_slot_checkpoint",
            "frost-quorum-substrate-v1",
        )),
    ),
    (
        CHIO_FROST_AUTHORIZATION_V1_SCHEMA,
        Some(("frost_authorization", "frost-quorum-substrate-v1")),
    ),
    (
        CHIO_FROST_EPOCH_CHECKPOINT_V1_SCHEMA,
        Some(("frost_epoch_checkpoint", "frost-quorum-substrate-v1")),
    ),
    (
        CHIO_FROST_ROSTER_V1_SCHEMA,
        Some(("frost_roster", "frost-quorum-substrate-v1")),
    ),
    (
        CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
        Some(("economic_resource_head", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
        Some(("economic_state_batch", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
        Some(("economic_effect_slot", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
        Some(("economic_state_anchor_view", "economic-state-continuity-v1")),
    ),
    (
        CHIO_ECONOMIC_EFFECT_DISPATCH_COMMIT_SCHEMA,
        Some((
            "economic_effect_dispatch_commit",
            "economic-state-continuity-v1",
        )),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_SNAPSHOT_V1_SCHEMA,
        Some(("clearing_participant_snapshot", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "clearing_participant_snapshot_acknowledgement",
            "ws4-clearing-v1",
        )),
    ),
    (
        CHIO_CLEARING_INPUT_MANIFEST_V1_SCHEMA,
        Some(("clearing_input_manifest", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_NETTING_ROUND_CORE_V1_SCHEMA,
        Some(("clearing_netting_round_core", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_STATEMENT_V1_SCHEMA,
        Some(("clearing_participant_statement", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_SETTLEMENT_INTENT_V1_SCHEMA,
        Some(("clearing_settlement_intent", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_SETTLEMENT_RECONCILIATION_V1_SCHEMA,
        Some(("clearing_settlement_reconciliation", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ROUND_SATISFACTION_V1_SCHEMA,
        Some(("clearing_round_satisfaction", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ZERO_INTENT_RECONCILIATION_V1_SCHEMA,
        Some(("clearing_zero_intent_reconciliation", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ATOM_TRANSFORMATION_V1_SCHEMA,
        Some(("clearing_atom_transformation", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_OUTPUT_MANIFEST_V1_SCHEMA,
        Some(("clearing_output_manifest", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_PARTICIPANT_ACCEPTANCE_V1_SCHEMA,
        Some(("clearing_participant_acceptance", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ROUND_FINALIZATION_V1_SCHEMA,
        Some(("clearing_round_finalization", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ZERO_DISPATCH_PROOF_V1_SCHEMA,
        Some(("clearing_zero_dispatch_proof", "ws4-clearing-v1")),
    ),
    (
        CHIO_CLEARING_ROUND_ABORT_V1_SCHEMA,
        Some(("clearing_round_abort", "ws4-clearing-v1")),
    ),
    (
        CHIO_CHANNEL_FUNDING_EVIDENCE_V1_SCHEMA,
        Some(("channel_funding_evidence", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_OPEN_INTENT_V1_SCHEMA,
        Some(("channel_open_intent", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_FUNDING_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "channel_funding_acknowledgement",
            "micro-escrow-channels-v1",
        )),
    ),
    (
        CHIO_CHANNEL_OPEN_V1_SCHEMA,
        Some(("channel_open", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_RESERVATION_V1_SCHEMA,
        Some(("channel_reservation", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_STATE_V1_SCHEMA,
        Some(("channel_state", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_CLOSE_V1_SCHEMA,
        Some(("channel_close", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_DISPUTE_V1_SCHEMA,
        Some(("channel_dispute", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_RELEASE_AUTHORIZATION_V1_SCHEMA,
        Some(("channel_release_authorization", "micro-escrow-channels-v1")),
    ),
    (
        CHIO_CHANNEL_TERMINAL_OUTCOME_COMMITMENT_V1_SCHEMA,
        Some((
            "channel_terminal_outcome_commitment",
            "micro-escrow-channels-v1",
        )),
    ),
    (
        CHIO_FINCRED_CREDIT_SCORECARD_V1_SCHEMA,
        Some(("financial_credit_scorecard", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_EXPOSURE_HISTORY_V1_SCHEMA,
        Some(("financial_exposure_history", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SETTLEMENT_RELIABILITY_V1_SCHEMA,
        Some((
            "financial_settlement_reliability",
            "financial-credentials-v1",
        )),
    ),
    (
        CHIO_FINCRED_PREMIUM_HISTORY_V1_SCHEMA,
        Some(("financial_premium_history", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_LOSS_HISTORY_V1_SCHEMA,
        Some(("financial_loss_history", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SOURCE_MEMBER_V1_SCHEMA,
        Some(("financial_source_member", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SOURCE_CHECKPOINT_V1_SCHEMA,
        Some(("financial_source_checkpoint", "financial-credentials-v1")),
    ),
    (
        CHIO_FINCRED_SOURCE_COMPLETENESS_ATTESTATION_V1_SCHEMA,
        Some((
            "financial_source_completeness_attestation",
            "financial-credentials-v1",
        )),
    ),
    (
        CHIO_FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_V1_SCHEMA,
        Some(("agent_passport_source_manifest", "financial-credentials-v1")),
    ),
    (
        CHIO_FINANCIAL_AGENT_PASSPORT_PRESENTATION_CHALLENGE_V1_SCHEMA,
        Some((
            "agent_passport_presentation_challenge",
            "financial-credentials-v1",
        )),
    ),
    (
        CHIO_FINDING_V1_SCHEMA,
        Some(("finding", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_ADMISSION_V1_SCHEMA,
        Some(("finding_admission", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_BOND_BACKING_V1_SCHEMA,
        Some(("finding_bond_backing", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_CHALLENGE_VERIFIER_PROFILE_V1_SCHEMA,
        Some(("finding_challenge_verifier_profile", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_FAILED_DELIVERY_V1_SCHEMA,
        Some(("finding_failed_delivery", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_MARKET_TERMS_V1_SCHEMA,
        Some(("finding_market_terms", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_PURCHASE_RECORD_V1_SCHEMA,
        Some(("finding_purchase_record", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_SELLER_AUTHORIZATION_V1_SCHEMA,
        Some(("finding_seller_authorization", "finding-market-v1")),
    ),
    (
        CHIO_FINDING_VERIFIER_REPORT_V1_SCHEMA,
        Some(("finding_verifier_report", "finding-market-v1")),
    ),
    (
        CHIO_FISCAL_CHARTER_V1_SCHEMA,
        Some(("fiscal_charter", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_SCHEDULE_V1_SCHEMA,
        Some(("fiscal_schedule", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_PROPOSAL_V1_SCHEMA,
        Some(("fiscal_proposal", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_PROPOSAL_ADMISSION_V1_SCHEMA,
        Some(("fiscal_proposal_admission", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_APPROVAL_V1_SCHEMA,
        Some(("fiscal_approval", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_ACTIVATION_V1_SCHEMA,
        Some(("fiscal_activation", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_CONSUMER_READINESS_V1_SCHEMA,
        Some(("fiscal_consumer_readiness", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_FISCAL_CONTINUITY_CHECKPOINT_V1_SCHEMA,
        Some(("fiscal_continuity_checkpoint", "fiscal-constitutions-v1")),
    ),
    (
        CHIO_ECONSIM_QUALIFICATION_MATRIX_V1_SCHEMA,
        Some((
            "economic_simulation_qualification_matrix",
            "economic-wind-tunnel-v1",
        )),
    ),
    (
        CHIO_OBLIGATION_STATUS_PROOF_V1_SCHEMA,
        Some(("obligation_status_proof", "receivables-factoring-v1")),
    ),
    (
        CHIO_CREDIT_FACILITY_BIND_V1_SCHEMA,
        Some(("credit_facility_bind", "credit-admission-v1")),
    ),
    (
        CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA,
        Some(("credit_iou_envelope", "receivables-factoring-v1")),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_BIND_AUTHORIZATION_V1_SCHEMA,
        Some((
            "factor_assignment_bind_authorization",
            "receivables-factoring-v1",
        )),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_AGREEMENT_V1_SCHEMA,
        Some(("factor_assignment_agreement", "receivables-factoring-v1")),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "factor_assignment_acknowledgement",
            "receivables-factoring-v1",
        )),
    ),
    (
        CHIO_FACTOR_ASSIGNMENT_NOT_APPLIED_V1_SCHEMA,
        Some(("factor_assignment_not_applied", "receivables-factoring-v1")),
    ),
    (
        CHIO_OUTCOME_PREDICATE_V1_SCHEMA,
        Some(("outcome_predicate", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_PRICING_V1_SCHEMA,
        Some(("outcome_pricing", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_SLA_V1_SCHEMA,
        Some(("outcome_sla", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA,
        Some(("outcome_eligibility", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA,
        Some(("outcome_delivery_checkpoint", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA,
        Some((
            "outcome_delivery_acknowledgement",
            "verified-outcome-pricing-v1",
        )),
    ),
    (
        CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA,
        Some((
            "outcome_delivery_nonacceptance",
            "verified-outcome-pricing-v1",
        )),
    ),
    (
        CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA,
        Some(("outcome_output_provenance", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA,
        Some(("outcome_contractual_zero", "verified-outcome-pricing-v1")),
    ),
    (
        CHIO_PARAMETRIC_POLICY_V1_SCHEMA,
        Some(("parametric_policy", "parametric-insurance-v1")),
    ),
    (CHIO_SESSION_ANCHOR_SCHEMA, None),
    (CHIO_REQUEST_LINEAGE_RECORD_SCHEMA, None),
    (
        CHIO_TRANSACTION_PASSPORT_V1_SCHEMA,
        Some(("transaction_passport", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_EVIDENCE_GRAPH_V1_SCHEMA,
        Some(("transaction_evidence_graph", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_CLAIM_SET_V1_SCHEMA,
        Some(("transaction_claim_set", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_VERIFIER_POLICY_V1_SCHEMA,
        Some(("transaction_verifier_policy", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_VERIFIER_REPORT_V1_SCHEMA,
        Some(("transaction_verifier_report", "transaction-passport-v1")),
    ),
    (
        CHIO_TRANSACTION_RUNTIME_SECURITY_REPORT_V1_SCHEMA,
        Some(("transaction_runtime_security_report", "runtime-security-v1")),
    ),
    (
        CHIO_CAPABILITY_PROOF_V1_SCHEMA,
        Some(("capability_proof", "transaction-passport-v1")),
    ),
    (
        CHIO_GUARD_DECISION_V1_SCHEMA,
        Some(("guard_decision", "transaction-passport-v1")),
    ),
    (
        CHIO_POLICY_BUNDLE_V1_SCHEMA,
        Some(("policy_bundle", "transaction-passport-v1")),
    ),
    (
        CHIO_TRUST_ROOT_V1_SCHEMA,
        Some(("trust_root", "transaction-passport-v1")),
    ),
    (
        CHIO_REQUEST_DIGEST_V1_SCHEMA,
        Some(("request_digest", "transaction-passport-v1")),
    ),
    (
        CHIO_RESPONSE_DIGEST_V1_SCHEMA,
        Some(("response_digest", "transaction-passport-v1")),
    ),
    (
        CHIO_COMMERCE_ORDER_CONTEXT_V1_SCHEMA,
        Some(("commerce_order_context", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_EVENT_LOG_V1_SCHEMA,
        Some(("commerce_event_log", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PAYMENT_LIFECYCLE_V1_SCHEMA,
        Some(("commerce_payment_lifecycle", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_MANDATE_ALLOWANCE_LEDGER_V1_SCHEMA,
        Some(("commerce_mandate_allowance_ledger", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PROTOCOL_PAYLOAD_V1_SCHEMA,
        Some(("commerce_protocol_payload", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_SETTLEMENT_PACKET_V1_SCHEMA,
        Some(("commerce_settlement_packet", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PROVIDER_PASSPORT_V1_SCHEMA,
        Some(("commerce_provider_passport", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_REPUTATION_SNAPSHOT_V1_SCHEMA,
        Some(("commerce_reputation_snapshot", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_FEDERATION_TRUST_BUNDLE_V1_SCHEMA,
        Some(("commerce_federation_trust_bundle", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_ORDER_PASSPORT_V1_SCHEMA,
        Some(("commerce_order_passport", "commerce-payments-v1")),
    ),
    (
        CHIO_COMMERCE_PROVIDER_DISCOVERY_SNAPSHOT_V1_SCHEMA,
        Some(("commerce_provider_discovery_snapshot", "trust-market-v1")),
    ),
    (
        CHIO_COMMERCE_PROVIDER_SELECTION_REPORT_V1_SCHEMA,
        Some(("commerce_provider_selection_report", "trust-market-v1")),
    ),
    (
        CHIO_COMMERCE_SLA_COMMITMENT_V1_SCHEMA,
        Some(("commerce_sla_commitment", "trust-market-v1")),
    ),
    (
        CHIO_COMMERCE_SLA_PERFORMANCE_REPORT_V1_SCHEMA,
        Some(("commerce_sla_performance_report", "trust-market-v1")),
    ),
    (
        CHIO_WORKFLOW_PREFLIGHT_PLAN_V1_SCHEMA,
        Some(("workflow_preflight_plan", "workflow-preflight-v1")),
    ),
    (
        CHIO_WORKFLOW_PREFLIGHT_REPORT_V1_SCHEMA,
        Some(("workflow_preflight_report", "workflow-preflight-v1")),
    ),
    (
        CHIO_CRYPTO_VERIFICATION_CONTEXT_V1_SCHEMA,
        Some(("crypto_verification_context", "crypto-context-v1")),
    ),
    (
        CHIO_TRUST_KEY_STATE_V1_SCHEMA,
        Some(("trust_key_state", "crypto-context-v1")),
    ),
    (
        CHIO_TRUST_REVOCATION_SNAPSHOT_V1_SCHEMA,
        Some(("trust_revocation_snapshot", "crypto-context-v1")),
    ),
    (
        CHIO_TRUST_SCORECARD_SNAPSHOT_V1_SCHEMA,
        Some(("trust_scorecard_snapshot", "trust-market-v1")),
    ),
    (
        CHIO_TRUST_REPUTATION_IMPORT_REPORT_V1_SCHEMA,
        Some(("trust_reputation_import_report", "trust-market-v1")),
    ),
    (
        CHIO_DISCLOSURE_VERIFIER_PRIVACY_PROFILE_V1_SCHEMA,
        Some(("disclosure_verifier_privacy_profile", "crypto-context-v1")),
    ),
    (
        CHIO_DISCLOSURE_CRYPTO_CONTEXT_REPORT_V1_SCHEMA,
        Some(("disclosure_crypto_context_report", "crypto-context-v1")),
    ),
    (
        CHIO_ATTEST_SELECTIVE_DISCLOSURE_PROOF_V1_SCHEMA,
        Some((
            "chio_attest_selective_disclosure_proof",
            "chio-final-architecture/v1",
        )),
    ),
    (
        CHIO_BBS_PROJECTION_MANIFEST_V2_SCHEMA,
        Some(("bbs_projection_manifest", "crypto-context-v1")),
    ),
    (
        CHIO_DISCLOSURE_CAPSULE_V1_SCHEMA,
        Some(("disclosure_capsule", "disclosure-lineage-v1")),
    ),
    (
        CHIO_LINEAGE_SIGNED_SUBGRAPH_V1_SCHEMA,
        Some(("lineage_signed_subgraph", "disclosure-lineage-v1")),
    ),
    (
        CHIO_DISCLOSURE_LEAKAGE_LEDGER_V1_SCHEMA,
        Some(("disclosure_leakage_ledger", "disclosure-lineage-v1")),
    ),
    (
        CHIO_DISCLOSURE_LINEAGE_VERIFIER_REPORT_V1_SCHEMA,
        Some((
            "disclosure_lineage_verifier_report",
            "disclosure-lineage-v1",
        )),
    ),
    (
        CHIO_TRANSPARENCY_INCLUSION_PROOF_V1_SCHEMA,
        Some(("transparency_inclusion_proof", "crypto-context-v1")),
    ),
    (
        CHIO_TRANSPARENCY_INCLUSION_PROOF_V2_SCHEMA,
        Some((
            "transparency_anchored_inclusion_proof",
            "checkpoint-transparency-v2",
        )),
    ),
    (
        CHIO_POLICY_ACTIVATION_RECEIPT_V1_SCHEMA,
        Some(("policy_activation_receipt", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_EXECUTION_LEASE_V1_SCHEMA,
        Some(("runtime_execution_lease", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_TOOL_SERVER_ACK_V1_SCHEMA,
        Some(("runtime_tool_server_ack", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_TRUSTED_TIME_PROOF_V1_SCHEMA,
        Some(("runtime_trusted_time_proof", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_REVOCATION_FRESHNESS_PROOF_V1_SCHEMA,
        Some(("runtime_revocation_freshness_proof", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_SANDBOX_ATTESTATION_V1_SCHEMA,
        Some(("runtime_sandbox_attestation", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_ATTACK_SIMULATION_REPORT_V1_SCHEMA,
        Some(("runtime_attack_simulation_report", "runtime-security-v1")),
    ),
    (
        CHIO_RUNTIME_CHAOS_RUN_REPORT_V1_SCHEMA,
        Some(("runtime_chaos_run_report", "runtime-security-v1")),
    ),
    (
        CHIO_RISK_COMPTROLLER_REPORT_V1_SCHEMA,
        Some(("risk_comptroller_report", "enterprise-export-v1")),
    ),
    (
        CHIO_RISK_COLLATERAL_POSITION_REPORT_V1_SCHEMA,
        Some(("risk_collateral_position_report", "trust-market-v1")),
    ),
    (
        CHIO_RISK_GUARANTEE_DECISION_V1_SCHEMA,
        Some(("risk_guarantee_decision", "trust-market-v1")),
    ),
    (
        CHIO_RISK_ADJUDICATION_JURISDICTION_RECEIPT_V1_SCHEMA,
        Some(("risk_adjudication_jurisdiction_receipt", "trust-market-v1")),
    ),
    (
        CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA,
        Some((
            "chio_comptroller_surface_report",
            "chio-comptroller-surface/v1",
        )),
    ),
    (
        CHIO_ENTERPRISE_DATA_GOVERNANCE_REPORT_V1_SCHEMA,
        Some(("enterprise_data_governance_report", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_V1_SCHEMA,
        Some(("enterprise_evidence_export_bundle", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_TELEMETRY_PROJECTION_V1_SCHEMA,
        Some(("enterprise_telemetry_projection", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_APPROVAL_CASE_V1_SCHEMA,
        Some(("enterprise_approval_case", "enterprise-export-v1")),
    ),
    (
        CHIO_ENTERPRISE_CONTROL_EVIDENCE_MAP_V1_SCHEMA,
        Some(("enterprise_control_evidence_map", "enterprise-export-v1")),
    ),
    (
        CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA,
        Some(("agent_web_proof_envelope", "agent-web-interop-v1")),
    ),
    (
        CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA,
        Some(("agent_web_proof_envelope", "agent-web-interop-v2")),
    ),
    (
        CHIO_AGENT_WEB_EXTERNAL_PROJECTION_MANIFEST_V1_SCHEMA,
        Some((
            "agent_web_external_projection_manifest",
            "agent-web-interop-v1",
        )),
    ),
    (
        CHIO_AGENT_WEB_INTEROP_VERIFIER_REPORT_V1_SCHEMA,
        Some(("agent_web_interop_verifier_report", "agent-web-interop-v1")),
    ),
    (
        CHIO_PROOF_ROOM_BUNDLE_V1_SCHEMA,
        Some(("proof_room_bundle", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_VERIFIER_REPORT_V1_SCHEMA,
        Some(("proof_room_verifier_report", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_FIXTURE_CATALOG_V1_SCHEMA,
        Some(("proof_room_fixture_catalog", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_FIXTURE_ROOT_CATALOG_V1_SCHEMA,
        Some(("proof_room_fixture_root_catalog", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_ROOM_RECEIPT_EVIDENCE_V1_SCHEMA,
        Some(("proof_room_receipt_evidence", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_DOCKER_QUICKSTART_EVIDENCE_V1_SCHEMA,
        Some(("proof_docker_quickstart_evidence", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_RELEASE_TRUTH_V1_SCHEMA,
        Some(("proof_release_truth", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_CAPABILITY_PROOF_V1_SCHEMA,
        Some(("proof_first_run_capability_proof", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_GUARD_REPORT_V1_SCHEMA,
        Some(("proof_first_run_guard_report", "proof-room-v1")),
    ),
    (
        CHIO_RUNTIME_TERMINAL_RECEIPT_V1_SCHEMA,
        Some(("runtime_terminal_receipt", "runtime-security-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_TRUST_ROOTS_V1_SCHEMA,
        Some(("proof_first_run_trust_roots", "proof-room-v1")),
    ),
    (
        CHIO_PROOF_FIRST_RUN_COMMAND_LOG_V1_SCHEMA,
        Some(("proof_first_run_command_log", "proof-room-v1")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_DISPATCH_V1_SCHEMA,
        Some(("web3_settlement_dispatch", "public-settlement-v1")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V1_SCHEMA,
        Some(("web3_settlement_execution_receipt", "public-settlement-v1")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_DISPATCH_V2_SCHEMA,
        Some(("web3_settlement_dispatch", "public-settlement-v2")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_EXECUTION_RECEIPT_V2_SCHEMA,
        Some(("web3_settlement_execution_receipt", "public-settlement-v2")),
    ),
    (
        CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_V1_SCHEMA,
        Some(("web3_settlement_proof_bundle", "public-settlement-v1")),
    ),
    (
        CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_V1_SCHEMA,
        Some(("public_settlement_verifier_report", "public-settlement-v1")),
    ),
    (
        CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA,
        Some(("oracle_conversion_evidence", "public-settlement-v1")),
    ),
    (
        CHIO_SWARM_TASK_GRAPH_V1_SCHEMA,
        Some(("swarm_task_graph", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_CONTINUATION_TOKEN_V1_SCHEMA,
        Some(("swarm_continuation_token", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_DELEGATION_WITNESS_CHAIN_V1_SCHEMA,
        Some(("swarm_delegation_witness_chain", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_JOIN_RECEIPT_V1_SCHEMA,
        Some(("swarm_join_receipt", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_ROUTE_PLAN_RECEIPT_V1_SCHEMA,
        Some(("swarm_route_plan_receipt", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_V1_SCHEMA,
        Some(("swarm_terminal_graph_receipt", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_BUDGET_POOL_V1_SCHEMA,
        Some(("swarm_budget_pool", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_REVOCATION_EPOCH_V1_SCHEMA,
        Some(("swarm_revocation_epoch", "swarm-authority-v1")),
    ),
    (
        CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_V1_SCHEMA,
        Some(("swarm_authority_verifier_report", "swarm-authority-v1")),
    ),
    (AZURE_MAA_ATTESTATION_SCHEMA, None),
    (AWS_NITRO_ATTESTATION_SCHEMA, None),
    (GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA, None),
    (ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, None),
];

const fn known_signed_artifact_schemas() -> [&'static str; SIGNED_ARTIFACT_SCHEMA_SPECS.len()] {
    let mut schemas = [""; SIGNED_ARTIFACT_SCHEMA_SPECS.len()];
    let mut index = 0;
    while index < SIGNED_ARTIFACT_SCHEMA_SPECS.len() {
        schemas[index] = SIGNED_ARTIFACT_SCHEMA_SPECS[index].0;
        index += 1;
    }
    schemas
}

const KNOWN_SIGNED_ARTIFACT_SCHEMA_LIST: [&str; SIGNED_ARTIFACT_SCHEMA_SPECS.len()] =
    known_signed_artifact_schemas();

/// Known signed artifacts accepted by the core compatibility gate.
pub const KNOWN_SIGNED_ARTIFACT_SCHEMAS: &[&str] = &KNOWN_SIGNED_ARTIFACT_SCHEMA_LIST;

/// Lightweight registry entry for schema-aware verifiers and reports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedArtifactSchemaEntry {
    pub schema: String,
    pub artifact_kind: String,
    pub introduced_by: String,
}

/// Return whether a schema ID is known to this verifier build.
#[must_use]
pub fn is_supported_signed_artifact_schema(schema: &str) -> bool {
    KNOWN_SIGNED_ARTIFACT_SCHEMAS.contains(&schema)
}

/// Fail closed on unknown signed-artifact schema IDs.
pub fn validate_signed_artifact_schema(schema: &str) -> Result<()> {
    if is_supported_signed_artifact_schema(schema) {
        Ok(())
    } else {
        Err(Error::CanonicalJson(format!(
            "unsupported signed-artifact schema: {schema}"
        )))
    }
}

/// Built-in registry entries mirrored by `spec/schemas/registry.json`.
#[must_use]
pub fn built_in_signed_artifact_registry() -> Vec<SignedArtifactSchemaEntry> {
    SIGNED_ARTIFACT_SCHEMA_SPECS
        .iter()
        .filter_map(|(schema, registry)| {
            registry.map(|(artifact_kind, introduced_by)| SignedArtifactSchemaEntry {
                schema: schema.to_string(),
                artifact_kind: artifact_kind.to_string(),
                introduced_by: introduced_by.to_string(),
            })
        })
        .collect()
}
