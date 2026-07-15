// Chio CLI -- command-line interface for the Chio runtime kernel.
//
// Provides commands for:
//
// - `chio run --policy <path> -- <command> [args...]`
//   Spawn an agent subprocess, set up the length-prefixed transport over
//   stdin/stdout pipes, and run the kernel message loop.
//
// - `chio check --policy <path> --tool <name> --params <json>`
//   Load a policy, create a kernel, and evaluate one tool call in preflight
//   mode, or in full mode with an explicit output fixture.
//
// - `chio mcp serve --policy <path> --server-id <id> -- <command> [args...]`
//   Wrap an MCP server subprocess with the Chio kernel and expose an
//   MCP-compatible edge over stdio for stock MCP clients.

mod admin;
mod archive;
mod cert;
mod commands {
    pub mod bind;
    pub mod guard_blocklist;
}
mod did;
mod doctor;
mod guard;
mod guards;
mod lineage;
mod market;
mod passport;
mod policies;
mod scaffold;
mod settle;

// Shared imports for the CLI module tree. These live at the crate root so the
// `cli/*` submodules (which each begin with `use super::*;`) inherit them,
// matching the single coherent `#[path] mod` strategy. The `pub use`
// re-exports keep `crate::CliError`, `crate::policy`, and the sibling
// control-plane modules reachable from the standalone `src/*.rs` command
// modules.
pub use chio_control_plane::{
    authority_public_key_from_seed_file, build_kernel, certify, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    enterprise_federation, evidence_export, federation_policy, issuance,
    issue_default_capabilities, load_or_create_authority_keypair, passport_verifier, policy,
    reputation, require_control_token, rotate_authority_keypair, scim_lifecycle, trust_control,
    CliError,
};
pub use chio_mcp_remote as remote_mcp;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, warn};

use chio_api_protect::{ProtectConfig, ProtectProxy};
use chio_core::appraisal::{
    RuntimeAttestationAppraisalImportRequest, RuntimeAttestationAppraisalRequest,
    RuntimeAttestationAppraisalResultExportRequest, RuntimeAttestationImportedAppraisalPolicy,
    SignedRuntimeAttestationAppraisalResult,
};
use chio_core::capability::{
    governance::GovernedAutonomyTier,
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::{ChioScope, MonetaryAmount},
};
use chio_core::crypto::Keypair;
use chio_core::message::{AgentMessage, KernelMessage, ToolCallError, ToolCallResult};
use chio_core::session::{
    OperationContext, OperationTerminalState, RequestId, SessionId, SessionOperation,
    ToolCallOperation,
};
use chio_kernel::transport::{ChioTransport, TransportError};
use chio_kernel::{
    ChioKernel, RevocationStore, SessionOperationResponse, ToolCallOutput,
    ToolCallRequest as KernelToolCallRequest, ToolCallStream,
};
use chio_mcp_adapter::adapter::McpAdapterConfig;
use chio_mcp_adapter::edge::{ChioMcpEdge, McpEdgeConfig};
use chio_mcp_adapter::server::AdaptedMcpServer;

use crate::policy::load_policy;

#[path = "cli/types.rs"]
mod types_cli;
#[allow(unused_imports)]
pub(crate) use types_cli::{
    ApiCommands, ArenaCommands, CertCommands, CertifyCommands, CertifyRegistryCommands, CheckMode,
    ChioAttestCommands, ChioBuyerCommands, ChioFederationCommands, ChioRuntimeQuoteCommands,
    ChioSupplyChainCommands, Cli, Commands, CommerceCommands, ConformanceCommands, DidCommands,
    EvidenceCommands, EvidenceFederationPolicyCommands, GuardBlocklistCommands, GuardCommands,
    GuardMarketCommands, LineageCommands, McpCommands, OutputFormat, PassportChallengeCommands,
    PassportCommands, PassportIssuanceCommands, PassportOid4vpCommands, PassportPolicyCommands,
    PassportStatusCommands, ProofCollectKind, ProofCommands, ProofDoctorScenario,
    ProofExportRedactProfile, ProofFixtureCommands, ProofVerifyRequirement,
    ReceiptCheckpointCommands, ReceiptCommands, ReceiptRetentionCommands, ReplayArgs,
    ReplaySubcommand, ReputationCommands,
    SettleCommands, TrafficArgs, TrustAuthorizationContextCommands, TrustBehavioralFeedCommands,
    TrustCapitalAllocationCommands, TrustCapitalBookCommands, TrustCapitalInstructionCommands,
    TrustCommands, TrustCreditBacktestCommands, TrustCreditBondCommands,
    TrustCreditFacilityCommands, TrustCreditLossLifecycleCommands, TrustCreditScorecardCommands,
    TrustEvidenceShareCommands, TrustExposureLedgerCommands, TrustFederationPolicyCommands,
    TrustLiabilityMarketCommands, TrustLiabilityProviderCommands, TrustProviderCommands,
    TrustProviderRiskPackageCommands, TrustRuntimeAttestationAppraisalCommands,
    TrustUnderwritingAppealCommands, TrustUnderwritingDecisionCommands,
    TrustUnderwritingInputCommands, WorkflowCommands,
};
#[path = "cli/chio/types.rs"]
mod chio_types;
use chio_types::{
    ChioAuthorityCommands, ChioPheromoneCommands, ChioPheromoneRelayAlertAssuranceArchiveCommands,
    ChioPheromoneRelayAlertAssuranceArchivePackageCommands,
    ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands,
    ChioPheromoneRelayAlertAssuranceCloseoutCommands, ChioPheromoneRelayAlertAssuranceCommands,
    ChioPheromoneRelayAlertAssurancePhysicalDrillCommands,
    ChioPheromoneRelayAlertAssuranceRetentionCommands,
    ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands, ChioPheromoneRelayAlertCommands,
    ChioPheromoneRelayAlertDeliveryCommands, ChioPheromoneRelayCommands,
    ChioPheromoneRelayDirectoryCommands, ChioPheromoneRelaySupervisorCommands, ChioRuntimeCommands,
    ChioRuntimeOpsCommands, ChioRuntimeOpsRetentionCommands, ChioRuntimeOrchestrateCommands,
    ChioRuntimePeerWeightsCommands, ChioRuntimePheromoneCommands, ChioRuntimePolicyCommands,
    ChioTreatyCommands, ChioTrustBundleCommands,
};
#[path = "cli/doctor.rs"]
mod doctor_cli;
#[allow(unused_imports)]
pub(crate) use doctor_cli::{
    cmd_doctor, render_doctor_human, render_doctor_json, write_doctor_report, DoctorArgs,
};
#[path = "cli/dispatch/mod.rs"]
mod dispatch_cli;
#[cfg(test)]
pub(crate) use dispatch_cli::{cmd_chio_attest_runtime_quote_verify, write_cli_error};
#[path = "cli/chio/dispatch.rs"]
mod chio_dispatch;
use chio_dispatch::*;

fn main() {
    dispatch_cli::run();
}
#[path = "cli/runtime.rs"]
mod runtime_cli;
#[allow(unused_imports)]
pub(crate) use runtime_cli::{
    cli_normalized_url_authority, cmd_api_protect, cmd_check, cmd_mcp_serve, cmd_mcp_serve_http,
    cmd_run, cmd_start, cmd_trust_revoke, cmd_trust_serve, cmd_trust_status,
    is_cli_ipv6_unicast_link_local, is_cli_ipv6_unique_local, optional_secret_with_env_fallback,
    parse_tenant_read_tokens, parse_trusted_capability_issuers_from_env,
    remote_mcp_auth_egress_contract, require_receipt_db_path, require_revocation_db_path,
    verdict_label, CHIO_START_NO_UPSTREAM_URL, CHIO_START_SIDECAR_OPENAPI_SPEC,
};
#[path = "cli/runtime/trust_reports.rs"]
mod runtime_trust_reports;
#[path = "cli/trust_commands.rs"]
mod trust_commands_cli;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use trust_commands_cli::select_receipt_for_explain;
#[allow(unused_imports)]
pub(crate) use trust_commands_cli::{
    bilateral_field, build_underwriting_policy_input_query, cmd_receipt_audit,
    cmd_receipt_checkpoint_create, cmd_receipt_checkpoint_status, cmd_receipt_checkpoint_verify,
    cmd_receipt_explain, cmd_receipt_flush, cmd_receipt_health, cmd_receipt_list,
    cmd_receipt_resolve_dead_letter, cmd_receipt_retention_repair, cmd_trust_credit_backtest_export,
    cmd_trust_credit_loss_lifecycle_evaluate, cmd_trust_credit_loss_lifecycle_issue,
    cmd_trust_credit_loss_lifecycle_list, cmd_trust_liability_auto_bind_issue,
    cmd_trust_liability_bound_coverage_issue, cmd_trust_liability_claim_adjudication_issue,
    cmd_trust_liability_claim_dispute_issue, cmd_trust_liability_claim_issue,
    cmd_trust_liability_claim_payout_instruction_issue,
    cmd_trust_liability_claim_payout_receipt_issue, cmd_trust_liability_claim_response_issue,
    cmd_trust_liability_claim_settlement_instruction_issue,
    cmd_trust_liability_claim_settlement_receipt_issue, cmd_trust_liability_claims_list,
    cmd_trust_liability_market_list, cmd_trust_liability_placement_issue,
    cmd_trust_liability_pricing_authority_issue, cmd_trust_liability_provider_issue,
    cmd_trust_liability_provider_list, cmd_trust_liability_provider_resolve,
    cmd_trust_liability_quote_request_issue, cmd_trust_liability_quote_response_issue,
    cmd_trust_provider_risk_package_export, cmd_trust_runtime_attestation_appraisal_export,
    cmd_trust_runtime_attestation_appraisal_import,
    cmd_trust_runtime_attestation_appraisal_result_export, cmd_trust_underwriting_appeal_create,
    cmd_trust_underwriting_appeal_resolve, cmd_trust_underwriting_decision_evaluate,
    cmd_trust_underwriting_decision_issue, cmd_trust_underwriting_decision_list,
    cmd_trust_underwriting_decision_simulate, cmd_trust_underwriting_input_export,
    decision_details, explain_decision_label, explain_dsse_envelope, explain_dual_signed_receipt,
    explain_receipt_value, finish_receipt_for_explain, inspect_bilateral_envelope_trace,
    is_bilateral_artifacts_value, json_path_str, load_credit_bonded_execution_control_policy,
    load_existing_kernel_checkpoint_keypair, load_json_or_yaml,
    load_liability_auto_bind_issue_request, load_liability_bound_coverage_issue_request,
    load_liability_claim_adjudication_issue_request, load_liability_claim_dispute_issue_request,
    load_liability_claim_issue_request, load_liability_claim_payout_instruction_issue_request,
    load_liability_claim_payout_receipt_issue_request, load_liability_claim_response_issue_request,
    load_liability_claim_settlement_instruction_issue_request,
    load_liability_claim_settlement_receipt_issue_request, load_liability_placement_issue_request,
    load_liability_pricing_authority_issue_request, load_liability_provider_report,
    load_liability_quote_request_issue_request, load_liability_quote_response_issue_request,
    load_receipt_for_explain, load_runtime_attestation_evidence,
    load_runtime_attestation_import_policy, load_signed_runtime_attestation_appraisal_result,
    load_underwriting_decision_policy, local_receipt_read_context, local_receipt_store,
    optional_u64, parse_credit_bond_disposition, parse_credit_bond_lifecycle_state,
    parse_credit_facility_disposition, parse_credit_facility_lifecycle_state,
    parse_credit_loss_lifecycle_event_kind, parse_governed_autonomy_tier,
    parse_liability_coverage_class, parse_liability_provider_lifecycle_state,
    parse_runtime_assurance_tier, parse_underwriting_appeal_resolution,
    parse_underwriting_appeal_status, parse_underwriting_decision_outcome,
    parse_underwriting_lifecycle_state, print_bilateral_human, print_receipt_operator_json,
    push_receipt_explain_matches, push_writer_counters_human, receipt_checkpoint_report_error,
    receipt_health_report_error, receipt_operator_json_value, receipt_value_matches_id,
    render_bilateral_explain, render_receipt_checkpoint_create_human,
    render_receipt_checkpoint_status_human, render_receipt_flush_human,
    render_receipt_health_human, repair_hint, trusted_kernel_keys_from_authority,
    BudgetQueryBackend, CreditBacktestExportArgs, CreditLossLifecycleListArgs,
    LiabilityClaimsListArgs, LiabilityMarketListArgs, ProviderRiskPackageExportArgs, QueryBackend,
    ReceiptExplainArgs, ReceiptListArgs, ReceiptOperatorJsonEnvelope, SignedQueryBackend,
    UnderwritingAppealResolveArgs, UnderwritingDecisionIssueArgs, UnderwritingDecisionListArgs,
    UnderwritingDecisionSimulateArgs, UnderwritingPolicyInputArgs,
    CHIO_CLI_RECEIPT_AUDIT_SCHEMA, CHIO_CLI_RECEIPT_CHECKPOINT_CREATE_SCHEMA,
    CHIO_CLI_RECEIPT_CHECKPOINT_STATUS_SCHEMA, CHIO_CLI_RECEIPT_CHECKPOINT_VERIFY_SCHEMA,
    CHIO_CLI_RECEIPT_FLUSH_SCHEMA, CHIO_CLI_RECEIPT_HEALTH_SCHEMA,
};
#[path = "cli/session/mod.rs"]
mod session_cli;
#[allow(unused_imports)]
pub(crate) use session_cli::{
    control_request_id, handle_agent_message, make_error_receipt, normalize_agent_message,
    print_summary, select_capability_for_request, tool_response_messages, SessionStats,
};
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use session_cli::{StubSqlResultToolServer, StubStreamingToolServer, StubToolServer};
#[path = "cli/conformance.rs"]
mod conformance_cli;
#[allow(unused_imports)]
pub(crate) use conformance_cli::{
    cmd_conformance_fetch_peers, cmd_conformance_run, download_and_verify, extract_archive,
    parse_peer_selection, parse_report_format, resolve_peers_lock_path,
    validate_extracted_peer_binary, write_human_report, write_json_report,
    FETCH_PEERS_HTTP_TIMEOUT_SECS,
};
#[path = "cli/mcp.rs"]
mod mcp_cli;
#[allow(unused_imports)]
pub(crate) use mcp_cli::{
    cmd_mcp_wrap, cmd_mcp_wrap_e2e_fixture, cmd_mcp_wrap_run, load_tools_fixture, McpWrapArgs,
};
#[path = "cli/replay.rs"]
mod replay_cli;
pub(crate) use replay_cli::{cmd_replay, load_trusted_kernel_pubkey};
#[path = "cli/arena.rs"]
mod arena_cli;
pub(crate) use arena_cli::{cmd_arena_evolve, cmd_arena_replay, cmd_arena_run};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "main_tests_support.rs"]
mod cli_entrypoint_support;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "main_tests_parsing.rs"]
mod cli_entrypoint_parsing_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "main_tests_surfaces.rs"]
mod cli_entrypoint_surface_tests;
