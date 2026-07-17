//! Signed-artifact schema registry and fail-closed compatibility gate.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::capability::{features::CHIO_CAPABILITIES_SCHEMA, token::CHIO_CAPABILITY_SCHEMA};
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
pub const CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA: &str = "chio.anchor-proof-bundle.v1";
pub const CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA: &str = "chio.bilateral-signature-slice.v1";
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
        CHIO_ANCHOR_PROOF_BUNDLE_V1_SCHEMA,
        Some(("anchor_proof_bundle", "public-settlement-v1")),
    ),
    (
        CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA,
        Some(("bilateral_dsse_signature_slice", "federation-dsse-slice")),
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
