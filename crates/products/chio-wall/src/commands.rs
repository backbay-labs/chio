use std::collections::BTreeSet;
use std::fmt::Debug;
use std::fs;
use std::path::Path;

use chio_control_plane::{evidence_export, CliError};
use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_guards::mcp_tool::{McpDefaultAction, McpToolConfig};
use chio_guards::McpToolGuard;
use chio_kernel::build_checkpoint;
use chio_store_sqlite::SqliteReceiptStore;
use chio_wall_core::{
    ChioWallArtifact, ChioWallArtifactKind, ChioWallAuthorizationContext, ChioWallBuyerMotion,
    ChioWallBuyerReviewPackage, ChioWallControlPackage, ChioWallControlProfile,
    ChioWallControlSurface, ChioWallDeniedAccessRecord, ChioWallGuardDecision,
    ChioWallGuardOutcome, ChioWallInformationDomain, ChioWallPolicySnapshot,
    CHIO_WALL_AUTHORIZATION_CONTEXT_SCHEMA, CHIO_WALL_BUYER_REVIEW_PACKAGE_SCHEMA,
    CHIO_WALL_CONTROL_PACKAGE_SCHEMA, CHIO_WALL_CONTROL_PROFILE_SCHEMA,
    CHIO_WALL_DENIED_ACCESS_RECORD_SCHEMA, CHIO_WALL_GUARD_OUTCOME_SCHEMA,
    CHIO_WALL_POLICY_SNAPSHOT_SCHEMA,
};
use chrono::Utc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const CHIO_WALL_WORKFLOW_ID: &str = "workflow-information-domain-barrier";
const CHIO_WALL_WORKFLOW_BOUNDARY: &str =
    "Information-domain tool access evidence for one bounded barrier-control workflow.";
const CHIO_WALL_DECISION: &str = "proceed_chio_wall_only";
const CHIO_WALL_CONTROL_OWNER: &str = "barrier-control-room";
const CHIO_WALL_SUPPORT_OWNER: &str = "chio-wall-ops";
const CHIO_WALL_POLICY_ID: &str = "chio.wall.research_execution_barrier.v1";
const CHIO_WALL_ACTOR_LABEL: &str = "research-agent-alpha";
const CHIO_WALL_REQUESTED_TOOL: &str = "execution_oms.submit_order";
const CHIO_WALL_ALLOWED_TOOLS: &[&str] = &[
    "research_news.read",
    "research_model.run",
    "research_review.export",
];

fn current_utc_date() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn chio_wall_request_id() -> String {
    format!("chio-wall-request-{}-01", current_utc_date())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ChioWallExportSummary {
    workflow_id: String,
    buyer_motion: String,
    control_surface: String,
    source_domain: String,
    requested_domain: String,
    control_owner: String,
    support_owner: String,
    control_profile_file: String,
    policy_snapshot_file: String,
    authorization_context_file: String,
    guard_outcome_file: String,
    denied_access_record_file: String,
    buyer_review_package_file: String,
    control_package_file: String,
    chio_evidence_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChioWallDocRefs {
    brief_file: String,
    readme_file: String,
    control_path_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChioWallValidationReport {
    workflow_id: String,
    decision: String,
    buyer_motion: String,
    control_surface: String,
    source_domain: String,
    requested_domain: String,
    control_path: ChioWallExportSummary,
    docs: ChioWallDocRefs,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChioWallDecisionRecord {
    decision: String,
    selected_buyer_motion: String,
    selected_control_surface: String,
    selected_source_domain: String,
    selected_requested_domain: String,
    control_owner: String,
    support_owner: String,
    deferred_scope: Vec<String>,
}

fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let bytes =
        fs::read(path).map_err(|error| CliError::Other(format!("{}: {error}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CliError::Other(format!("{}: {error}", path.display())))
}

fn ensure_file_exists(path: &Path) -> Result<(), CliError> {
    if !path.is_file() {
        return Err(CliError::Other(format!(
            "required Chio-Wall artifact file is missing: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_non_empty_directory(path: &Path) -> Result<(), CliError> {
    if !path.is_dir() {
        return Err(CliError::Other(format!(
            "required Chio-Wall evidence directory is missing: {}",
            path.display()
        )));
    }
    if fs::read_dir(path)?.next().is_none() {
        return Err(CliError::Other(format!(
            "required Chio-Wall evidence directory is empty: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_only_expected_package_entries(
    output: &Path,
    expected_entries: &[&'static str],
) -> Result<(), CliError> {
    let expected = expected_entries.iter().copied().collect::<BTreeSet<_>>();
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        let entry_name = entry.file_name().into_string().map_err(|_| {
            CliError::Other(format!(
                "unexpected non-UTF-8 Chio-Wall package entry: {}",
                entry.path().display()
            ))
        })?;
        if !expected.contains(entry_name.as_str()) {
            return Err(CliError::Other(format!(
                "unexpected Chio-Wall package entry: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn ensure_equal<T: Debug + PartialEq>(
    field: &'static str,
    actual: &T,
    expected: &T,
) -> Result<(), CliError> {
    if actual != expected {
        return Err(CliError::Other(format!(
            "{field} mismatch: expected {expected:?}, got {actual:?}"
        )));
    }
    Ok(())
}

fn ensure_empty_directory(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(CliError::Other(format!(
                "output path must not be a symlink: {}",
                path.display()
            )));
        }
        if !path.is_dir() {
            return Err(CliError::Other(format!(
                "output path must be a directory: {}",
                path.display()
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            return Err(CliError::Other(format!(
                "output directory must be empty: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn relative_display(root: &Path, path: &Path) -> Result<String, CliError> {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string())
        .map_err(|error| CliError::Other(error.to_string()))
}

fn chio_wall_doc_refs() -> ChioWallDocRefs {
    ChioWallDocRefs {
        brief_file: "docs/chio-wall/BRIEF.md".to_string(),
        readme_file: "docs/chio-wall/README.md".to_string(),
        control_path_file: "docs/chio-wall/CONTROL_PATH.md".to_string(),
        operations_file: "docs/chio-wall/OPERATIONS.md".to_string(),
        validation_package_file: "docs/chio-wall/VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/chio-wall/DECISION_RECORD.md".to_string(),
    }
}

fn build_control_profile() -> ChioWallControlProfile {
    ChioWallControlProfile {
        schema: CHIO_WALL_CONTROL_PROFILE_SCHEMA.to_string(),
        profile_id: format!("chio-wall-control-profile-{}", current_utc_date()),
        workflow_id: CHIO_WALL_WORKFLOW_ID.to_string(),
        buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
        control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
        source_domain: ChioWallInformationDomain::Research,
        protected_domain: ChioWallInformationDomain::Execution,
        retained_artifact_policy:
            "retain_authorization_context_guard_outcome_and_denied_access_records".to_string(),
        intended_use:
            "Barrier review for denied cross-domain tool access over one bounded control path."
                .to_string(),
        fail_closed: true,
    }
}

fn build_policy_snapshot() -> ChioWallPolicySnapshot {
    ChioWallPolicySnapshot {
        schema: CHIO_WALL_POLICY_SNAPSHOT_SCHEMA.to_string(),
        policy_id: CHIO_WALL_POLICY_ID.to_string(),
        source_domain: ChioWallInformationDomain::Research,
        allowed_tools: CHIO_WALL_ALLOWED_TOOLS
            .iter()
            .map(|tool| (*tool).to_string())
            .collect(),
        fail_closed: true,
        note: "The initial Chio-Wall lane reuses Chio tool-guard mechanics through one fail-closed allowlist for the research domain."
            .to_string(),
    }
}

fn build_authorization_context() -> ChioWallAuthorizationContext {
    ChioWallAuthorizationContext {
        schema: CHIO_WALL_AUTHORIZATION_CONTEXT_SCHEMA.to_string(),
        request_id: chio_wall_request_id(),
        workflow_id: CHIO_WALL_WORKFLOW_ID.to_string(),
        actor_label: CHIO_WALL_ACTOR_LABEL.to_string(),
        buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
        control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
        source_domain: ChioWallInformationDomain::Research,
        requested_domain: ChioWallInformationDomain::Execution,
        tool_name: CHIO_WALL_REQUESTED_TOOL.to_string(),
        policy_reference: CHIO_WALL_POLICY_ID.to_string(),
    }
}

fn build_guard_outcome(
    context: &ChioWallAuthorizationContext,
    policy: &ChioWallPolicySnapshot,
) -> ChioWallGuardOutcome {
    let guard = McpToolGuard::with_config(McpToolConfig {
        enabled: true,
        allow: policy.allowed_tools.clone(),
        block: vec![],
        default_action: McpDefaultAction::Block,
        max_args_size: Some(1024),
    });
    let tool_allowed = matches!(
        guard.is_allowed(&context.tool_name),
        chio_guards::mcp_tool::ToolDecision::Allow
    );
    ChioWallGuardOutcome {
        schema: CHIO_WALL_GUARD_OUTCOME_SCHEMA.to_string(),
        request_id: context.request_id.clone(),
        workflow_id: context.workflow_id.clone(),
        decision: if tool_allowed {
            ChioWallGuardDecision::Allow
        } else {
            ChioWallGuardDecision::Deny
        },
        guard_name: "mcp-tool".to_string(),
        pipeline_name: "guard-pipeline".to_string(),
        matched_policy: context.policy_reference.clone(),
        evaluated_tool: context.tool_name.clone(),
        allowed_tools: policy.allowed_tools.clone(),
        reason: if tool_allowed {
            format!(
                "tool `{}` is allowed for the `{}` domain under `{}`",
                context.tool_name,
                context.source_domain.as_str(),
                context.policy_reference
            )
        } else {
            format!(
                "tool `{}` is outside the allowlist for the `{}` domain and is denied fail-closed before `{}` access can cross into `{}`",
                context.tool_name,
                context.source_domain.as_str(),
                context.source_domain.as_str(),
                context.requested_domain.as_str()
            )
        },
        fail_closed: true,
    }
}

fn build_denied_access_record(
    context: &ChioWallAuthorizationContext,
    outcome: &ChioWallGuardOutcome,
) -> Result<ChioWallDeniedAccessRecord, CliError> {
    if outcome.decision != ChioWallGuardDecision::Deny {
        return Err(CliError::Other(
            "Chio-Wall export expects the bounded control-path scenario to deny cross-domain access"
                .to_string(),
        ));
    }
    Ok(ChioWallDeniedAccessRecord {
        schema: CHIO_WALL_DENIED_ACCESS_RECORD_SCHEMA.to_string(),
        request_id: context.request_id.clone(),
        workflow_id: context.workflow_id.clone(),
        source_domain: context.source_domain,
        requested_domain: context.requested_domain,
        tool_name: context.tool_name.clone(),
        escalation_owner: CHIO_WALL_CONTROL_OWNER.to_string(),
        support_owner: CHIO_WALL_SUPPORT_OWNER.to_string(),
        note: "Chio-Wall records one denied cross-domain tool-access event and routes follow-up through the barrier control-room owner."
            .to_string(),
    })
}

fn chio_wall_capability_with_id(
    id: &str,
    subject: &Keypair,
    issuer: &Keypair,
) -> Result<CapabilityToken, CliError> {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "chio-wall".to_string(),
                    tool_name: CHIO_WALL_REQUESTED_TOOL.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 100,
            expires_at: 10_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .map_err(CliError::from)
}

fn chio_wall_receipt(
    authorization_context: &ChioWallAuthorizationContext,
    guard_outcome: &ChioWallGuardOutcome,
    denied_access_record: &ChioWallDeniedAccessRecord,
    policy_snapshot: &ChioWallPolicySnapshot,
    capability_id: &str,
    kernel_keypair: &Keypair,
) -> Result<ChioReceipt, CliError> {
    let metadata = serde_json::json!({
        "schema": "chio.wall.receipt_metadata.v1",
        "authorizationContext": authorization_context,
        "guardOutcome": guard_outcome,
        "deniedAccessRecord": denied_access_record,
        "policySnapshot": policy_snapshot,
    });
    let content_hash = sha256_hex(&canonical_json_bytes(&metadata)?);
    let policy_hash = sha256_hex(&canonical_json_bytes(policy_snapshot)?);
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "workflowId": authorization_context.workflow_id,
        "requestId": authorization_context.request_id,
        "actor": authorization_context.actor_label,
        "sourceDomain": authorization_context.source_domain.as_str(),
        "requestedDomain": authorization_context.requested_domain.as_str(),
        "toolName": authorization_context.tool_name,
        "policyReference": authorization_context.policy_reference,
        "guardDecision": guard_outcome.decision.as_str(),
    }))?;
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-chio-wall-control-path-1".to_string(),
            timestamp: 1_712_104_800,
            capability_id: capability_id.to_string(),
            tool_server: "chio-wall".to_string(),
            tool_name: authorization_context.tool_name.clone(),
            action,
            decision: Some(Decision::Deny {
                reason: guard_outcome.reason.clone(),
                guard: guard_outcome.guard_name.clone(),
            }),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash,
            policy_hash,
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_keypair.public_key(),
            bbs_projection_version: None,
        },
        kernel_keypair,
    )
    .map_err(CliError::from)
}

fn create_chio_wall_receipt_db(
    receipt_db_path: &Path,
    authorization_context: &ChioWallAuthorizationContext,
    guard_outcome: &ChioWallGuardOutcome,
    denied_access_record: &ChioWallDeniedAccessRecord,
    policy_snapshot: &ChioWallPolicySnapshot,
) -> Result<(), CliError> {
    let store = SqliteReceiptStore::open(receipt_db_path)?;
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let kernel = Keypair::generate();
    let capability = chio_wall_capability_with_id("cap-chio-wall-1", &subject, &issuer)?;
    let receipt = chio_wall_receipt(
        authorization_context,
        guard_outcome,
        denied_access_record,
        policy_snapshot,
        &capability.body().id,
        &kernel,
    )?;
    let seq = store.append_chio_receipt_returning_seq(&receipt)?;
    let canonical = store.receipts_canonical_bytes_range(seq, seq)?;
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>(),
        &kernel,
    )?;
    store.store_checkpoint(&checkpoint)?;
    Ok(())
}

fn write_chio_evidence_package(
    output: &Path,
    authorization_context: &ChioWallAuthorizationContext,
    guard_outcome: &ChioWallGuardOutcome,
    denied_access_record: &ChioWallDeniedAccessRecord,
    policy_snapshot: &ChioWallPolicySnapshot,
) -> Result<(), CliError> {
    let receipt_staging = tempfile::tempdir()?;
    let receipt_db_path = receipt_staging.path().join("chio-wall-receipts.sqlite3");
    let chio_evidence_dir = output.join("chio-evidence");

    create_chio_wall_receipt_db(
        &receipt_db_path,
        authorization_context,
        guard_outcome,
        denied_access_record,
        policy_snapshot,
    )?;

    evidence_export::cmd_evidence_export(
        &chio_evidence_dir,
        None,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
        false,
        Some(&receipt_db_path),
        None,
        None,
    )?;

    let _ = fs::remove_file(receipt_db_path);
    Ok(())
}

fn expected_artifact_path(kind: ChioWallArtifactKind) -> &'static str {
    match kind {
        ChioWallArtifactKind::ControlProfile => "control-profile.json",
        ChioWallArtifactKind::PolicySnapshot => "policy-snapshot.json",
        ChioWallArtifactKind::AuthorizationContext => "authorization-context.json",
        ChioWallArtifactKind::GuardOutcome => "guard-outcome.json",
        ChioWallArtifactKind::DeniedAccessRecord => "denied-access-record.json",
        ChioWallArtifactKind::BuyerReviewPackage => "buyer-review-package.json",
        ChioWallArtifactKind::ChioEvidenceExport => "chio-evidence",
    }
}

fn validate_contract(
    label: &'static str,
    result: Result<(), chio_wall_core::ChioWallContractError>,
) -> Result<(), CliError> {
    result.map_err(|error| CliError::Other(format!("{label}: {error}")))
}

fn verify_control_path_export(
    output: &Path,
    summary: &ChioWallExportSummary,
) -> Result<(), CliError> {
    let control_profile_path = output.join("control-profile.json");
    let policy_snapshot_path = output.join("policy-snapshot.json");
    let authorization_context_path = output.join("authorization-context.json");
    let guard_outcome_path = output.join("guard-outcome.json");
    let denied_access_record_path = output.join("denied-access-record.json");
    let buyer_review_package_path = output.join("buyer-review-package.json");
    let control_package_path = output.join("control-package.json");
    let control_path_summary_path = output.join("control-path-summary.json");
    let chio_evidence_dir = output.join("chio-evidence");
    let expected_entries = [
        "control-profile.json",
        "policy-snapshot.json",
        "authorization-context.json",
        "guard-outcome.json",
        "denied-access-record.json",
        "buyer-review-package.json",
        "control-package.json",
        "control-path-summary.json",
        "chio-evidence",
    ];

    for path in [
        &control_profile_path,
        &policy_snapshot_path,
        &authorization_context_path,
        &guard_outcome_path,
        &denied_access_record_path,
        &buyer_review_package_path,
        &control_package_path,
        &control_path_summary_path,
    ] {
        ensure_file_exists(path)?;
    }
    ensure_non_empty_directory(&chio_evidence_dir)?;
    ensure_only_expected_package_entries(output, &expected_entries)?;

    let control_profile: ChioWallControlProfile = read_json_file(&control_profile_path)?;
    let policy_snapshot: ChioWallPolicySnapshot = read_json_file(&policy_snapshot_path)?;
    let authorization_context: ChioWallAuthorizationContext =
        read_json_file(&authorization_context_path)?;
    let guard_outcome: ChioWallGuardOutcome = read_json_file(&guard_outcome_path)?;
    let denied_access_record: ChioWallDeniedAccessRecord =
        read_json_file(&denied_access_record_path)?;
    let buyer_review_package: ChioWallBuyerReviewPackage =
        read_json_file(&buyer_review_package_path)?;
    let control_package: ChioWallControlPackage = read_json_file(&control_package_path)?;
    let on_disk_summary: ChioWallExportSummary = read_json_file(&control_path_summary_path)?;

    validate_contract("control-profile.json", control_profile.validate())?;
    validate_contract("policy-snapshot.json", policy_snapshot.validate())?;
    validate_contract(
        "authorization-context.json",
        authorization_context.validate(),
    )?;
    validate_contract("guard-outcome.json", guard_outcome.validate())?;
    validate_contract("denied-access-record.json", denied_access_record.validate())?;
    validate_contract("buyer-review-package.json", buyer_review_package.validate())?;
    validate_contract("control-package.json", control_package.validate())?;

    ensure_equal("control-path-summary.json", &on_disk_summary, summary)?;
    ensure_equal(
        "summary.control_profile_file",
        &summary.control_profile_file,
        &control_profile_path.display().to_string(),
    )?;
    ensure_equal(
        "summary.policy_snapshot_file",
        &summary.policy_snapshot_file,
        &policy_snapshot_path.display().to_string(),
    )?;
    ensure_equal(
        "summary.authorization_context_file",
        &summary.authorization_context_file,
        &authorization_context_path.display().to_string(),
    )?;
    ensure_equal(
        "summary.guard_outcome_file",
        &summary.guard_outcome_file,
        &guard_outcome_path.display().to_string(),
    )?;
    ensure_equal(
        "summary.denied_access_record_file",
        &summary.denied_access_record_file,
        &denied_access_record_path.display().to_string(),
    )?;
    ensure_equal(
        "summary.buyer_review_package_file",
        &summary.buyer_review_package_file,
        &buyer_review_package_path.display().to_string(),
    )?;
    ensure_equal(
        "summary.control_package_file",
        &summary.control_package_file,
        &control_package_path.display().to_string(),
    )?;
    ensure_equal(
        "summary.chio_evidence_dir",
        &summary.chio_evidence_dir,
        &chio_evidence_dir.display().to_string(),
    )?;

    ensure_equal(
        "control_profile.workflow_id",
        &control_profile.workflow_id,
        &authorization_context.workflow_id,
    )?;
    ensure_equal(
        "control_profile.buyer_motion",
        &control_profile.buyer_motion,
        &authorization_context.buyer_motion,
    )?;
    ensure_equal(
        "control_profile.control_surface",
        &control_profile.control_surface,
        &authorization_context.control_surface,
    )?;
    ensure_equal(
        "control_profile.source_domain",
        &control_profile.source_domain,
        &authorization_context.source_domain,
    )?;
    ensure_equal(
        "control_profile.protected_domain",
        &control_profile.protected_domain,
        &authorization_context.requested_domain,
    )?;
    ensure_equal(
        "policy_snapshot.policy_id",
        &policy_snapshot.policy_id,
        &authorization_context.policy_reference,
    )?;
    ensure_equal(
        "policy_snapshot.allowed_tools",
        &policy_snapshot.allowed_tools,
        &guard_outcome.allowed_tools,
    )?;
    ensure_equal(
        "guard_outcome.request_id",
        &guard_outcome.request_id,
        &authorization_context.request_id,
    )?;
    ensure_equal(
        "guard_outcome.workflow_id",
        &guard_outcome.workflow_id,
        &authorization_context.workflow_id,
    )?;
    ensure_equal(
        "guard_outcome.matched_policy",
        &guard_outcome.matched_policy,
        &authorization_context.policy_reference,
    )?;
    ensure_equal(
        "guard_outcome.evaluated_tool",
        &guard_outcome.evaluated_tool,
        &authorization_context.tool_name,
    )?;
    ensure_equal(
        "denied_access_record.request_id",
        &denied_access_record.request_id,
        &authorization_context.request_id,
    )?;
    ensure_equal(
        "denied_access_record.workflow_id",
        &denied_access_record.workflow_id,
        &authorization_context.workflow_id,
    )?;
    ensure_equal(
        "denied_access_record.source_domain",
        &denied_access_record.source_domain,
        &authorization_context.source_domain,
    )?;
    ensure_equal(
        "denied_access_record.requested_domain",
        &denied_access_record.requested_domain,
        &authorization_context.requested_domain,
    )?;
    ensure_equal(
        "denied_access_record.tool_name",
        &denied_access_record.tool_name,
        &authorization_context.tool_name,
    )?;

    ensure_equal(
        "buyer_review_package.workflow_id",
        &buyer_review_package.workflow_id,
        &control_package.workflow_id,
    )?;
    ensure_equal(
        "buyer_review_package.buyer_motion",
        &buyer_review_package.buyer_motion,
        &control_package.buyer_motion,
    )?;
    ensure_equal(
        "buyer_review_package.control_surface",
        &buyer_review_package.control_surface,
        &control_package.control_surface,
    )?;
    ensure_equal(
        "buyer_review_package.control_owner",
        &buyer_review_package.control_owner,
        &control_package.control_owner,
    )?;
    ensure_equal(
        "buyer_review_package.support_owner",
        &buyer_review_package.support_owner,
        &control_package.support_owner,
    )?;
    ensure_equal(
        "buyer_review_package.control_package_file",
        &buyer_review_package.control_package_file,
        &relative_display(output, &control_package_path)?,
    )?;
    ensure_equal(
        "buyer_review_package.authorization_context_file",
        &buyer_review_package.authorization_context_file,
        &relative_display(output, &authorization_context_path)?,
    )?;
    ensure_equal(
        "buyer_review_package.policy_snapshot_file",
        &buyer_review_package.policy_snapshot_file,
        &relative_display(output, &policy_snapshot_path)?,
    )?;
    ensure_equal(
        "buyer_review_package.guard_outcome_file",
        &buyer_review_package.guard_outcome_file,
        &relative_display(output, &guard_outcome_path)?,
    )?;
    ensure_equal(
        "buyer_review_package.denied_access_record_file",
        &buyer_review_package.denied_access_record_file,
        &relative_display(output, &denied_access_record_path)?,
    )?;
    ensure_equal(
        "buyer_review_package.chio_evidence_dir",
        &buyer_review_package.chio_evidence_dir,
        &relative_display(output, &chio_evidence_dir)?,
    )?;
    ensure_equal(
        "control_package.profile_file",
        &control_package.profile_file,
        &relative_display(output, &control_profile_path)?,
    )?;
    ensure_equal(
        "control_package.buyer_review_package_file",
        &control_package.buyer_review_package_file,
        &relative_display(output, &buyer_review_package_path)?,
    )?;
    ensure_equal(
        "control_package.chio_evidence_dir",
        &control_package.chio_evidence_dir,
        &relative_display(output, &chio_evidence_dir)?,
    )?;

    for artifact in &control_package.artifacts {
        let expected_path = expected_artifact_path(artifact.artifact_kind);
        ensure_equal(
            "control_package.artifacts[].relative_path",
            &artifact.relative_path,
            &expected_path.to_string(),
        )?;
        let path = output.join(&artifact.relative_path);
        if artifact.artifact_kind == ChioWallArtifactKind::ChioEvidenceExport {
            ensure_non_empty_directory(&path)?;
        } else {
            ensure_file_exists(&path)?;
        }
    }

    Ok(())
}

fn export_control_path(output: &Path) -> Result<ChioWallExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let control_profile = build_control_profile();
    let policy_snapshot = build_policy_snapshot();
    let authorization_context = build_authorization_context();
    let guard_outcome = build_guard_outcome(&authorization_context, &policy_snapshot);
    let denied_access_record = build_denied_access_record(&authorization_context, &guard_outcome)?;

    control_profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    policy_snapshot
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    authorization_context
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    guard_outcome
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    denied_access_record
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;

    let control_profile_path = output.join("control-profile.json");
    let policy_snapshot_path = output.join("policy-snapshot.json");
    let authorization_context_path = output.join("authorization-context.json");
    let guard_outcome_path = output.join("guard-outcome.json");
    let denied_access_record_path = output.join("denied-access-record.json");

    write_json_file(&control_profile_path, &control_profile)?;
    write_json_file(&policy_snapshot_path, &policy_snapshot)?;
    write_json_file(&authorization_context_path, &authorization_context)?;
    write_json_file(&guard_outcome_path, &guard_outcome)?;
    write_json_file(&denied_access_record_path, &denied_access_record)?;

    write_chio_evidence_package(
        output,
        &authorization_context,
        &guard_outcome,
        &denied_access_record,
        &policy_snapshot,
    )?;

    let control_package_path = output.join("control-package.json");
    let buyer_review_package_path = output.join("buyer-review-package.json");

    let buyer_review_package = ChioWallBuyerReviewPackage {
        schema: CHIO_WALL_BUYER_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!("chio-wall-buyer-review-{}", current_utc_date()),
        workflow_id: CHIO_WALL_WORKFLOW_ID.to_string(),
        buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
        control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
        control_owner: CHIO_WALL_CONTROL_OWNER.to_string(),
        support_owner: CHIO_WALL_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        control_package_file: relative_display(output, &control_package_path)?,
        authorization_context_file: relative_display(output, &authorization_context_path)?,
        policy_snapshot_file: relative_display(output, &policy_snapshot_path)?,
        guard_outcome_file: relative_display(output, &guard_outcome_path)?,
        denied_access_record_file: relative_display(output, &denied_access_record_path)?,
        chio_evidence_dir: "chio-evidence".to_string(),
        note: "Chio-Wall stays bounded to one denied cross-domain tool-access scenario for one control-room barrier-review buyer motion."
            .to_string(),
    };
    buyer_review_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&buyer_review_package_path, &buyer_review_package)?;

    let control_package = ChioWallControlPackage {
        schema: CHIO_WALL_CONTROL_PACKAGE_SCHEMA.to_string(),
        package_id: format!("chio-wall-control-package-{}", current_utc_date()),
        workflow_id: CHIO_WALL_WORKFLOW_ID.to_string(),
        same_system_boundary: CHIO_WALL_WORKFLOW_BOUNDARY.to_string(),
        buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
        control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
        control_owner: CHIO_WALL_CONTROL_OWNER.to_string(),
        support_owner: CHIO_WALL_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        profile_file: relative_display(output, &control_profile_path)?,
        buyer_review_package_file: relative_display(output, &buyer_review_package_path)?,
        chio_evidence_dir: "chio-evidence".to_string(),
        artifacts: vec![
            ChioWallArtifact {
                artifact_kind: ChioWallArtifactKind::ControlProfile,
                relative_path: relative_display(output, &control_profile_path)?,
            },
            ChioWallArtifact {
                artifact_kind: ChioWallArtifactKind::PolicySnapshot,
                relative_path: relative_display(output, &policy_snapshot_path)?,
            },
            ChioWallArtifact {
                artifact_kind: ChioWallArtifactKind::AuthorizationContext,
                relative_path: relative_display(output, &authorization_context_path)?,
            },
            ChioWallArtifact {
                artifact_kind: ChioWallArtifactKind::GuardOutcome,
                relative_path: relative_display(output, &guard_outcome_path)?,
            },
            ChioWallArtifact {
                artifact_kind: ChioWallArtifactKind::DeniedAccessRecord,
                relative_path: relative_display(output, &denied_access_record_path)?,
            },
            ChioWallArtifact {
                artifact_kind: ChioWallArtifactKind::BuyerReviewPackage,
                relative_path: relative_display(output, &buyer_review_package_path)?,
            },
            ChioWallArtifact {
                artifact_kind: ChioWallArtifactKind::ChioEvidenceExport,
                relative_path: "chio-evidence".to_string(),
            },
        ],
    };
    control_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&control_package_path, &control_package)?;

    let summary = ChioWallExportSummary {
        workflow_id: CHIO_WALL_WORKFLOW_ID.to_string(),
        buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview
            .as_str()
            .to_string(),
        control_surface: ChioWallControlSurface::ToolAccessDomainBoundary
            .as_str()
            .to_string(),
        source_domain: ChioWallInformationDomain::Research.as_str().to_string(),
        requested_domain: ChioWallInformationDomain::Execution.as_str().to_string(),
        control_owner: CHIO_WALL_CONTROL_OWNER.to_string(),
        support_owner: CHIO_WALL_SUPPORT_OWNER.to_string(),
        control_profile_file: control_profile_path.display().to_string(),
        policy_snapshot_file: policy_snapshot_path.display().to_string(),
        authorization_context_file: authorization_context_path.display().to_string(),
        guard_outcome_file: guard_outcome_path.display().to_string(),
        denied_access_record_file: denied_access_record_path.display().to_string(),
        buyer_review_package_file: buyer_review_package_path.display().to_string(),
        control_package_file: control_package_path.display().to_string(),
        chio_evidence_dir: output.join("chio-evidence").display().to_string(),
    };
    write_json_file(&output.join("control-path-summary.json"), &summary)?;
    verify_control_path_export(output, &summary)?;

    Ok(summary)
}

/// Environment keys an operator sets to enable SIEM alert dispatch in the serve
/// mode. Alerting is operator-configured: each backend needs a secret routing
/// key, so absent keys mean "alerting disabled" (a legitimate deploy), not a
/// fault. When set, the configured backends drive a real `AlertingExporter`
/// wired to the registry metrics sink.
const PAGERDUTY_ROUTING_KEY_ENV: &str = "CHIO_SIEM_ALERT_PAGERDUTY_ROUTING_KEY";
const PAGERDUTY_ENDPOINT_ENV: &str = "CHIO_SIEM_ALERT_PAGERDUTY_ENDPOINT";
const OPSGENIE_API_KEY_ENV: &str = "CHIO_SIEM_ALERT_OPSGENIE_API_KEY";
const OPSGENIE_ENDPOINT_ENV: &str = "CHIO_SIEM_ALERT_OPSGENIE_ENDPOINT";

/// Environment keys an operator sets to enable a SOC export sink in the serve
/// mode. A SOC export sink is a real durable audit-export consumer (unlike
/// alerting, which is a notification overlay); at least one is required before
/// serving. The generic webhook sink is the most general SOC receiver: with
/// default config it forwards EVERY audit row. Absent keys mean "no webhook SOC
/// sink configured" (another sink may still be wired later).
const WEBHOOK_URL_ENV: &str = "CHIO_SIEM_WEBHOOK_URL";
const WEBHOOK_BEARER_TOKEN_ENV: &str = "CHIO_SIEM_WEBHOOK_BEARER_TOKEN";

/// The manager's always-on malformed-row producer. Seeding its soc_export
/// series at zero keeps the `chio_soc_export_total` family present from serve
/// start so `ChioSocExportMetricsMissing` fires only on a true scrape gap,
/// never on a healthy-but-quiet (or zero-SOC-exporter) deploy.
const DESERIALIZE_EXPORTER: &str = "_deserialize";

/// Opt-in production SIEM export serve mode. Runs the ExporterManager
/// cursor-pull loop against `receipt_db` with a persisted per-exporter
/// high-water mark in `cursor_db` (at-least-once delivery) and a registry-backed
/// metrics sink, until an interrupt.
///
/// Alerting (PagerDuty/OpsGenie) is operator-configured via the
/// `CHIO_SIEM_ALERT_*` environment keys: when a backend is configured the serve
/// path installs the same registry metrics sink into a real `AlertingExporter`
/// (so `chio_alert_dispatch_total`/`_latency` emit real production values) and
/// pre-registers the alert-dispatch series at zero.
pub fn cmd_chio_wall_siem_export(receipt_db: &Path, cursor_db: &Path) -> Result<(), CliError> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| {
        CliError::cli_other_error(format!("tokio runtime init failed: {error}"))
    })?;
    runtime.block_on(serve_siem_export(receipt_db, cursor_db))
}

async fn serve_siem_export(receipt_db: &Path, cursor_db: &Path) -> Result<(), CliError> {
    let config = chio_siem::SiemConfig {
        db_path: receipt_db.to_path_buf(),
        cursor_db_path: Some(cursor_db.to_path_buf()),
        ..chio_siem::SiemConfig::default()
    };
    let metrics_sink: std::sync::Arc<dyn chio_siem::SiemMetricsSink> =
        std::sync::Arc::new(crate::registry_metrics_sink::RegistryMetricsSink);
    let mut manager = chio_siem::ExporterManager::new(config)
        .map_err(|error| CliError::cli_other_error(format!("open ExporterManager: {error}")))?
        .with_metrics_sink(metrics_sink.clone());

    let mut registered_exporters: Vec<String> = Vec::new();
    let mut alert_routes: Vec<String> = Vec::new();

    // Operator-configured SOC export sinks. Each is a real durable audit-export
    // consumer (the generic webhook forwards EVERY audit row); registering at
    // least one is what satisfies the fail-closed gate below. Wired from the
    // CHIO_SIEM_* endpoint env the same way the alert backends are.
    for exporter in configured_soc_exporters()? {
        registered_exporters.push(exporter.name().to_string());
        manager.add_exporter(exporter);
    }

    // Operator-configured alerting. Alerting is NOT always-on: each backend
    // needs a secret routing key, so it runs only when configured. When
    // configured, the SAME registry metrics sink is installed into the
    // AlertingExporter so chio_alert_dispatch_total/_latency emit REAL values on
    // real dispatches, and the exporter is registered with the manager so its
    // per-poll dispatch loop drives those metrics. Alerting is a notification
    // overlay, so it runs ALONGSIDE a SOC sink and never satisfies the gate on
    // its own.
    let alert_backends = configured_alert_backends()?;
    if let Some((alerting, routes)) =
        build_serve_alerting_exporter(alert_backends, metrics_sink.clone())
    {
        // Alerting is registered with the manager so its per-poll dispatch loop
        // runs, but it is NOT added to `registered_exporters` (the SOC-export
        // sink list): it is a notification overlay, not a SOC export sink, so it
        // must not seed or feed the chio_soc_export_total / SOC DLQ families. Its
        // own alert-dispatch series is seeded from `alert_routes` below.
        alert_routes = routes;
        manager.add_exporter(Box::new(alerting));
    }

    // Fail closed unless a real SOC export sink is configured. With zero
    // exporters the manager advances its cursor while exporting nowhere; with
    // ONLY alerting it advances past allow/low-severity audit rows the
    // notification overlay never exports. Refuse to start so a misconfigured
    // deploy is loud, not silently lossy.
    ensure_serve_has_consumer(&registered_exporters)?;

    // Pre-register the soc/dlq/alert-dispatch series at zero so the
    // absent_over_time backstops fire only on a true scrape gap. alert_dispatch
    // is ALWAYS seeded: per configured route when alerting is enabled, or under a
    // `disabled` sentinel for a SOC-only serve, because the shipped alert pack's
    // ChioAlertDispatchMetricsMissing is unconditional and would otherwise page a
    // legitimate SOC-only deploy.
    let registered_refs: Vec<&str> = registered_exporters.iter().map(String::as_str).collect();
    let route_refs: Vec<&str> = alert_routes.iter().map(String::as_str).collect();
    preregister_serve_metrics(&registered_refs, &route_refs);

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Receipt-log gap/lag watchdog: sample the receipt store's health on an
    // interval and publish the uncheckpointed-range and checkpoint-age gauges.
    // Never panics; logs and continues on error.
    let watchdog = spawn_receipt_watchdog(receipt_db.to_path_buf(), cancel_rx.clone());

    // Prometheus scrape endpoint: serve the SOC-export / DLQ / alert-dispatch /
    // checkpoint families this process records so a co-located agent can scrape
    // them. A bind failure logs and the serve continues without the endpoint
    // rather than aborting the export loop.
    let metrics_addr = crate::metrics_server::configured_metrics_addr();
    let metrics_endpoint = match crate::metrics_server::bind_metrics_endpoint(&metrics_addr).await {
        Ok(listener) => Some(crate::metrics_server::spawn_metrics_endpoint(
            listener,
            cancel_rx.clone(),
        )),
        Err(error) => {
            eprintln!("SIEM metrics scrape endpoint bind failed on {metrics_addr}: {error}");
            None
        }
    };

    let handle = tokio::spawn(async move {
        manager.run(cancel_rx).await;
    });
    // Serve until an interrupt, then cancel and drain in-flight work.
    let _ = tokio::signal::ctrl_c().await;
    let _ = cancel_tx.send(true);
    let _ = handle.await;
    let _ = watchdog.await;
    if let Some(metrics_endpoint) = metrics_endpoint {
        let _ = metrics_endpoint.await;
    }
    Ok(())
}

/// Spawn the receipt-log watchdog loop for the serve path. Each tick samples
/// `receipt_store_health()` off the async runtime (SQLite is blocking) and
/// records the watchdog gauges; a sampling failure logs and the loop continues
/// rather than aborting the serve.
fn spawn_receipt_watchdog(
    receipt_db: std::path::PathBuf,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let db = receipt_db.clone();
                    let sampled = tokio::task::spawn_blocking(move || sample_receipt_health(&db)).await;
                    match sampled {
                        Ok(Ok(report)) => {
                            let now_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis() as u64)
                                .unwrap_or(0);
                            chio_kernel::record_receipt_health_gauges(&report, now_ms);
                        }
                        Ok(Err(error)) => {
                            eprintln!("receipt-store health sample failed: {error}");
                        }
                        Err(error) => {
                            eprintln!("receipt-store health task join failed: {error}");
                        }
                    }
                }
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

fn sample_receipt_health(
    receipt_db: &Path,
) -> Result<chio_kernel::receipt_store::ReceiptStoreHealthReport, String> {
    // Sample via a READ-ONLY open (no create/WAL/writer-pool), matching the
    // read-only receipt-polling contract. The watchdog observes a receipt DB the
    // kernel owns: `open` would create a mistyped path, switch the mount to WAL,
    // spin a writer pool, and fail outright on a read-only mount. The read-only
    // sampler reports a missing DB as missing (NotFound) instead of creating it;
    // the caller logs and continues on any error.
    SqliteReceiptStore::receipt_store_health_read_only(receipt_db)
        .map_err(|error| error.to_string())
}

/// Read the operator-configured SIEM alert backends from the environment.
/// Returns an empty vec when alerting is disabled (no secrets set); returns an
/// error (fail-closed) when a backend is requested but cannot be constructed, so
/// a misconfigured endpoint denies the serve start rather than silently dropping
/// the alert pipeline.
fn configured_alert_backends() -> Result<Vec<Box<dyn chio_siem::AlertBackend>>, CliError> {
    let mut backends: Vec<Box<dyn chio_siem::AlertBackend>> = Vec::new();

    if let Some(routing_key) = non_empty_env(PAGERDUTY_ROUTING_KEY_ENV) {
        let endpoint = non_empty_env(PAGERDUTY_ENDPOINT_ENV)
            .unwrap_or_else(|| "https://events.pagerduty.com".to_string());
        let backend =
            chio_siem::PagerDutyBackend::with_endpoint(routing_key, endpoint).map_err(|error| {
                CliError::cli_other_error(format!("configure PagerDuty alert backend: {error}"))
            })?;
        backends.push(Box::new(backend));
    }

    if let Some(api_key) = non_empty_env(OPSGENIE_API_KEY_ENV) {
        let endpoint = non_empty_env(OPSGENIE_ENDPOINT_ENV)
            .unwrap_or_else(|| "https://api.opsgenie.com".to_string());
        let backend =
            chio_siem::OpsGenieBackend::with_endpoint(api_key, endpoint).map_err(|error| {
                CliError::cli_other_error(format!("configure OpsGenie alert backend: {error}"))
            })?;
        backends.push(Box::new(backend));
    }

    Ok(backends)
}

/// Read the operator-configured SOC export sinks from the environment. Returns
/// an empty vec when no SOC endpoint is configured; returns an error
/// (fail-closed) when a sink is requested but cannot be constructed, so a
/// misconfigured endpoint denies the serve start rather than silently dropping
/// audit-export coverage.
///
/// Currently wires the generic webhook sink, the most general SOC receiver: with
/// default config it forwards EVERY audit row (not just high-severity denials),
/// so it is a complete SOC export sink. A deployment sets `CHIO_SIEM_WEBHOOK_URL`
/// (https) and optionally `CHIO_SIEM_WEBHOOK_BEARER_TOKEN`. Splunk/Elastic/etc.
/// are registered here the same way as they gain endpoint env keys.
fn configured_soc_exporters() -> Result<Vec<Box<dyn chio_siem::Exporter>>, CliError> {
    let mut exporters: Vec<Box<dyn chio_siem::Exporter>> = Vec::new();

    if let Some(url) = non_empty_env(WEBHOOK_URL_ENV) {
        let bearer_token = non_empty_env(WEBHOOK_BEARER_TOKEN_ENV);
        let exporter =
            chio_siem::WebhookExporter::from_endpoint(url, bearer_token).map_err(|error| {
                CliError::cli_other_error(format!(
                    "configure SIEM webhook SOC export sink: {error}"
                ))
            })?;
        exporters.push(Box::new(exporter));
    }

    Ok(exporters)
}

/// Read a trimmed, non-empty environment value, treating unset/blank as absent.
///
/// Returns the TRIMMED value: a mounted secret with a trailing newline would
/// otherwise pass the non-empty check but be handed back verbatim, so
/// `CHIO_SIEM_WEBHOOK_URL` could fail URL/egress validation or a bearer token
/// could be sent with an embedded newline.
fn non_empty_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

/// Build the operator-configured alerting exporter with the registry metrics
/// sink installed, alongside the backend route names to pre-register at zero.
///
/// Returns `None` when no alert backend is configured (alerting disabled). When
/// backends are present, the shared `RegistryMetricsSink` is installed into the
/// exporter so `chio_alert_dispatch_total` / `chio_alert_dispatch_latency_seconds`
/// emit REAL values on every real dispatch.
fn build_serve_alerting_exporter(
    backends: Vec<Box<dyn chio_siem::AlertBackend>>,
    metrics_sink: std::sync::Arc<dyn chio_siem::SiemMetricsSink>,
) -> Option<(chio_siem::AlertingExporter, Vec<String>)> {
    if backends.is_empty() {
        return None;
    }
    let routes: Vec<String> = backends
        .iter()
        .map(|backend| backend.name().to_string())
        .collect();
    let mut builder = chio_siem::AlertingExporter::builder(chio_siem::AlertingConfig::default())
        .with_metrics_sink(metrics_sink);
    for backend in backends {
        builder = builder.with_backend(backend);
    }
    Some((builder.build(), routes))
}

/// The AlertingExporter's registered name. Alerting is a NOTIFICATION overlay,
/// not an audit-export sink, so it does not satisfy the SOC-export requirement.
/// Must stay in sync with `chio_siem::AlertingExporter::name()`.
const ALERTING_EXPORTER_NAME: &str = "alerting";

/// Sentinel `route` label for the zero-baseline `chio_alert_dispatch_total`
/// series seeded when alerting is NOT configured (a SOC-only serve). The shipped
/// alert pack carries an unconditional `ChioAlertDispatchMetricsMissing`
/// (`absent_over_time`), so the family must be present-at-zero even with no
/// backends, or a legitimate SOC-only deployment pages on an intentionally
/// silent alert pipeline. The zero value is accurate: no alert dispatches
/// occurred because alerting is disabled.
const ALERT_ROUTE_DISABLED: &str = "disabled";

/// Fail closed unless the serve mode has at least one real SOC EXPORT sink.
///
/// With zero registered exporters the manager parses batches and advances its
/// cursor, silently discarding receipts. An alerting-only deploy is lossy in a
/// subtler way: `AlertingExporter` returns every event as "processed" (so the
/// manager advances the high-water mark) but only delivers high-severity denials
/// to PagerDuty/OpsGenie and drops every allow/low-severity receipt. If alerting
/// is the ONLY consumer the cursor advances past audit rows no durable SOC export
/// sink ever received - silently losing SOC export coverage and permanently
/// skipping those rows for any SOC sink added later. Require a real SOC export
/// sink (Splunk/Elastic/Webhook/...) before serving; alerting may run ALONGSIDE
/// one but must not be the sole consumer.
fn ensure_serve_has_consumer(registered_exporters: &[String]) -> Result<(), CliError> {
    let has_soc_export_sink = registered_exporters
        .iter()
        .any(|name| name != ALERTING_EXPORTER_NAME);
    if !has_soc_export_sink {
        return Err(CliError::cli_other_error(
            "chio-wall siem-export requires a real SOC export sink (Splunk/Elastic/Webhook/...): \
             alerting alone is a notification overlay that delivers only high-severity denials \
             and drops every other receipt, so advancing the read cursor past receipts it did \
             not export would silently lose SOC export coverage. Configure a SOC export sink \
             (alerting may run alongside one) before serving."
                .to_string(),
        ));
    }
    Ok(())
}

/// Pre-register the SIEM serve-mode metric series at zero so the absent-metric
/// backstops fire only on a true scrape gap.
///
/// The soc_export/dlq_depth families are seeded from the always-on
/// `_deserialize` producer plus every registered SOC exporter, so
/// `ChioSocExportMetricsMissing` stays quiet on a healthy-but-quiet (or
/// zero-SOC-exporter) deploy. The alert_dispatch family is ALWAYS seeded at
/// zero: for each configured alert route when alerting is enabled, or under a
/// single `disabled` sentinel route for a SOC-only serve. The shipped alert pack
/// carries an unconditional `ChioAlertDispatchMetricsMissing`
/// (`absent_over_time`), so leaving the family absent when alerting is disabled
/// would page a legitimate SOC-only deployment; a present-at-zero series makes
/// `absent_over_time` fire only on a true scrape gap.
fn preregister_serve_metrics(registered_exporters: &[&str], alert_routes: &[&str]) {
    use chio_metrics_spec::runtime::families;

    // Seed the FIXED (non-deployment-configured) alert-pack series at zero. The
    // siem-export binary starts its own metrics server and renders the full alert
    // pack, but it does not go through the chio-cli tracing init that normally
    // calls this, so families like chio_fail_open_suspected_total /
    // chio_dispatch_failure_total / chio_capability_revocation_lag_seconds are
    // otherwise absent and their absent_over_time backstops can false-fire on a
    // healthy-but-quiet deploy. The operator-configured soc/dlq/alert routes
    // below are seeded only when present, since their label domain is
    // deployment-specific.
    chio_metrics_spec::runtime::preregister_known_label_sets();

    // Always-on baseline: the manager's malformed-row producer keeps the
    // soc_export family present even on a zero-exporter deploy.
    families::SOC_EXPORT_TOTAL.preregister(&[DESERIALIZE_EXPORTER, "malformed"]);

    for exporter in registered_exporters {
        // The manager records `success` on success (aligned with the
        // soc_export_error_ratio recording rules) and manages a per-exporter DLQ
        // depth gauge; seed both so the families exist before the first poll.
        families::SOC_EXPORT_TOTAL.preregister(&[exporter, "success"]);
        families::DLQ_DEPTH.preregister(&[exporter]);
    }

    if alert_routes.is_empty() {
        // SOC-only serve (no PagerDuty/OpsGenie configured): seed a zero baseline
        // under the `disabled` sentinel so the unconditional
        // ChioAlertDispatchMetricsMissing rule does not page an intentionally
        // silent alert pipeline.
        families::ALERT_DISPATCH_TOTAL.preregister(&[ALERT_ROUTE_DISABLED, "success"]);
        families::ALERT_DISPATCH_TOTAL.preregister(&[ALERT_ROUTE_DISABLED, "error"]);
    } else {
        for route in alert_routes {
            // The AlertingExporter records `success`/`error` per dispatch.
            families::ALERT_DISPATCH_TOTAL.preregister(&[route, "success"]);
            families::ALERT_DISPATCH_TOTAL.preregister(&[route, "error"]);
        }
    }
}

pub fn cmd_chio_wall_control_path_export(output: &Path, json: bool) -> Result<(), CliError> {
    let summary = export_control_path(output)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("workflow_id:           {}", summary.workflow_id);
        println!("buyer_motion:          {}", summary.buyer_motion);
        println!("control_surface:       {}", summary.control_surface);
        println!("control_profile:       {}", summary.control_profile_file);
        println!("policy_snapshot:       {}", summary.policy_snapshot_file);
        println!(
            "authorization_context: {}",
            summary.authorization_context_file
        );
        println!("guard_outcome:         {}", summary.guard_outcome_file);
        println!(
            "denied_access_record:  {}",
            summary.denied_access_record_file
        );
        println!(
            "buyer_review_package:  {}",
            summary.buyer_review_package_file
        );
        println!("control_package:       {}", summary.control_package_file);
        println!("chio_evidence:          {}", summary.chio_evidence_dir);
    }
    Ok(())
}

pub fn cmd_chio_wall_control_path_validate(output: &Path, json: bool) -> Result<(), CliError> {
    ensure_empty_directory(output)?;
    let control_path_dir = output.join("control-path");
    let summary = export_control_path(&control_path_dir)?;
    let docs = chio_wall_doc_refs();

    let report = ChioWallValidationReport {
        workflow_id: CHIO_WALL_WORKFLOW_ID.to_string(),
        decision: CHIO_WALL_DECISION.to_string(),
        buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview
            .as_str()
            .to_string(),
        control_surface: ChioWallControlSurface::ToolAccessDomainBoundary
            .as_str()
            .to_string(),
        source_domain: ChioWallInformationDomain::Research.as_str().to_string(),
        requested_domain: ChioWallInformationDomain::Execution.as_str().to_string(),
        control_path: summary,
        docs: docs.clone(),
    };
    write_json_file(&output.join("validation-report.json"), &report)?;

    let decision_record = ChioWallDecisionRecord {
        decision: CHIO_WALL_DECISION.to_string(),
        selected_buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview
            .as_str()
            .to_string(),
        selected_control_surface: ChioWallControlSurface::ToolAccessDomainBoundary
            .as_str()
            .to_string(),
        selected_source_domain: ChioWallInformationDomain::Research.as_str().to_string(),
        selected_requested_domain: ChioWallInformationDomain::Execution.as_str().to_string(),
        control_owner: CHIO_WALL_CONTROL_OWNER.to_string(),
        support_owner: CHIO_WALL_SUPPORT_OWNER.to_string(),
        deferred_scope: vec![
            "additional buyer motions".to_string(),
            "generic barrier-platform breadth".to_string(),
            "folding Chio-Wall into MERCURY".to_string(),
            "multi-product platform hardening".to_string(),
        ],
    };
    write_json_file(&output.join("expansion-decision.json"), &decision_record)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("workflow_id:      {}", report.workflow_id);
        println!("decision:         {}", report.decision);
        println!("buyer_motion:     {}", report.buyer_motion);
        println!("control_surface:  {}", report.control_surface);
        println!(
            "control_path_dir: {}",
            output.join("control-path").display()
        );
        println!(
            "validation_report: {}",
            output.join("validation-report.json").display()
        );
        println!(
            "expansion_decision: {}",
            output.join("expansion-decision.json").display()
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use chio_core::receipt::decision::Decision;
    use chio_siem::event::SiemEvent;
    use chio_siem::exporter::ExportFuture;
    use chio_siem::{Exporter, ExporterManager, SiemConfig};
    use tokio::sync::watch;

    fn unique_test_dir(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}"))
    }

    #[derive(Clone, Default)]
    struct CapturingExporter {
        events: Arc<Mutex<Vec<SiemEvent>>>,
    }

    impl CapturingExporter {
        fn events(&self) -> Vec<SiemEvent> {
            self.events.lock().expect("events lock").clone()
        }
    }

    impl Exporter for CapturingExporter {
        fn name(&self) -> &str {
            "chio-wall-capturing-exporter"
        }

        fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
            let sink = self.events.clone();
            let owned = events.to_vec();
            Box::pin(async move {
                sink.lock().expect("events lock").extend(owned.clone());
                Ok(owned.len())
            })
        }
    }

    #[test]
    fn build_guard_outcome_allows_research_tool_when_present_in_policy() {
        let mut context = build_authorization_context();
        context.tool_name = CHIO_WALL_ALLOWED_TOOLS[0].to_string();
        let policy = build_policy_snapshot();

        let outcome = build_guard_outcome(&context, &policy);
        assert_eq!(outcome.decision, ChioWallGuardDecision::Allow);
        assert_eq!(outcome.evaluated_tool, CHIO_WALL_ALLOWED_TOOLS[0]);
        assert!(outcome.reason.contains("is allowed"));
        outcome.validate().expect("allow outcome validates");
    }

    #[test]
    fn build_denied_access_record_rejects_allow_outcome() {
        let mut context = build_authorization_context();
        context.tool_name = CHIO_WALL_ALLOWED_TOOLS[0].to_string();
        let policy = build_policy_snapshot();
        let outcome = build_guard_outcome(&context, &policy);

        let error = build_denied_access_record(&context, &outcome)
            .expect_err("allow outcome should not generate denied-access record");
        assert!(error
            .to_string()
            .contains("expects the bounded control-path scenario to deny"));
    }

    #[test]
    fn ensure_empty_directory_rejects_non_empty_dir() {
        let dir = unique_test_dir("chio-wall-non-empty");
        fs::create_dir_all(&dir).expect("create temp dir");
        fs::write(dir.join("sentinel.txt"), b"occupied").expect("write sentinel");

        let error = ensure_empty_directory(&dir).expect_err("non-empty dir should fail");
        assert!(error.to_string().contains("output directory must be empty"));

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_empty_directory_rejects_symlink_dir() {
        let target = unique_test_dir("chio-wall-output-target");
        let link = unique_test_dir("chio-wall-output-link");
        fs::create_dir_all(&target).expect("create target dir");
        std::os::unix::fs::symlink(&target, &link).expect("create output symlink");

        let error = ensure_empty_directory(&link).expect_err("symlink dir should fail");

        assert!(error.to_string().contains("symlink"));
        let _ = fs::remove_file(link);
        let _ = fs::remove_dir_all(target);
    }

    #[test]
    fn validate_pipeline_emits_bounded_control_room_decision() {
        let output = unique_test_dir("chio-wall-validate-unit");

        cmd_chio_wall_control_path_validate(&output, false).expect("validate pipeline succeeds");

        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("validation-report.json")).expect("read"))
                .expect("parse validation report");
        assert_eq!(report["decision"].as_str(), Some(CHIO_WALL_DECISION));
        assert_eq!(
            report["buyerMotion"].as_str(),
            Some(ChioWallBuyerMotion::ControlRoomBarrierReview.as_str())
        );
        assert_eq!(
            report["controlSurface"].as_str(),
            Some(ChioWallControlSurface::ToolAccessDomainBoundary.as_str())
        );

        let decision: serde_json::Value = serde_json::from_slice(
            &fs::read(output.join("expansion-decision.json")).expect("read decision"),
        )
        .expect("parse decision record");
        assert_eq!(decision["decision"].as_str(), Some(CHIO_WALL_DECISION));
        assert_eq!(
            decision["selectedBuyerMotion"].as_str(),
            Some(ChioWallBuyerMotion::ControlRoomBarrierReview.as_str())
        );
        assert!(decision["deferredScope"]
            .as_array()
            .expect("deferred scope")
            .iter()
            .any(|item| item.as_str() == Some("generic barrier-platform breadth")));

        let _ = fs::remove_dir_all(output);
    }

    #[test]
    fn control_path_export_reconciliation_rejects_missing_artifact_file() {
        let output = unique_test_dir("chio-wall-export-reconcile");
        let summary = export_control_path(&output).expect("export control path");
        fs::remove_file(output.join("guard-outcome.json")).expect("remove guard outcome");

        let error = verify_control_path_export(&output, &summary)
            .expect_err("missing guard outcome should fail reconciliation");

        assert!(error.to_string().contains("guard-outcome.json"));
        let _ = fs::remove_dir_all(output);
    }

    #[test]
    fn control_path_export_keeps_sqlite_staging_outside_package() {
        let output = unique_test_dir("chio-wall-export-staging");
        fs::create_dir_all(&output).expect("create output directory");
        let started = Arc::new(Barrier::new(2));
        let stop = Arc::new(AtomicBool::new(false));
        let saw_sqlite_staging = Arc::new(AtomicBool::new(false));
        let monitor = {
            let output = output.clone();
            let started = Arc::clone(&started);
            let stop = Arc::clone(&stop);
            let saw_sqlite_staging = Arc::clone(&saw_sqlite_staging);
            thread::spawn(move || {
                started.wait();
                while !stop.load(Ordering::Acquire) {
                    let found = fs::read_dir(&output)
                        .expect("read output directory")
                        .filter_map(Result::ok)
                        .any(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".chio-wall-receipts.sqlite3")
                        });
                    if found {
                        saw_sqlite_staging.store(true, Ordering::Release);
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            })
        };

        started.wait();
        let export = export_control_path(&output);
        stop.store(true, Ordering::Release);
        monitor.join().expect("join package monitor");

        export.expect("export control path");
        assert!(!saw_sqlite_staging.load(Ordering::Acquire));
        let _ = fs::remove_dir_all(output);
    }

    #[test]
    fn control_path_export_reconciliation_rejects_unexpected_top_level_artifact() {
        let output = unique_test_dir("chio-wall-export-closed");
        let summary = export_control_path(&output).expect("export control path");
        fs::write(output.join(".chio-wall-receipts.sqlite3"), b"stale db")
            .expect("write undeclared artifact");

        let error = verify_control_path_export(&output, &summary)
            .expect_err("undeclared top-level artifact should fail reconciliation");

        assert!(error
            .to_string()
            .contains("unexpected Chio-Wall package entry"));
        assert!(error.to_string().contains(".chio-wall-receipts.sqlite3"));
        let _ = fs::remove_dir_all(output);
    }

    #[tokio::test]
    async fn chio_wall_denied_receipt_exports_through_chio_siem() {
        let output = unique_test_dir("chio-wall-siem");
        fs::create_dir_all(&output).expect("create temp dir");

        let authorization_context = build_authorization_context();
        let policy_snapshot = build_policy_snapshot();
        let guard_outcome = build_guard_outcome(&authorization_context, &policy_snapshot);
        assert_eq!(guard_outcome.decision, ChioWallGuardDecision::Deny);

        let denied_access_record =
            build_denied_access_record(&authorization_context, &guard_outcome)
                .expect("deny outcome should build record");
        let receipt_db_path = output.join("chio-wall-integration.sqlite3");
        create_chio_wall_receipt_db(
            &receipt_db_path,
            &authorization_context,
            &guard_outcome,
            &denied_access_record,
            &policy_snapshot,
        )
        .expect("create Chio-Wall receipt db");

        let exporter = CapturingExporter::default();
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db_path.clone(),
            poll_interval: std::time::Duration::from_millis(25),
            batch_size: 10,
            max_retries: 0,
            base_backoff_ms: 0,
            dlq_capacity: 100,
            rate_limit: None,
            trusted_kernel_keys: std::collections::BTreeSet::new(),
            read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
            cursor_db_path: None,
        })
        .expect("open ExporterManager");
        manager.add_exporter(Box::new(exporter.clone()));

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let run_handle = tokio::spawn(async move {
            manager.run(cancel_rx).await;
            manager
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        cancel_tx.send(true).expect("cancel signal sends");
        let manager = run_handle.await.expect("manager task completes");

        let events = exporter.events();
        assert_eq!(events.len(), 1, "one Chio-Wall receipt should be exported");
        assert_eq!(events[0].receipt.tool_server, "chio-wall");
        assert_eq!(events[0].receipt.tool_name, CHIO_WALL_REQUESTED_TOOL);
        match &events[0].receipt.decision {
            Some(Decision::Deny { guard, .. }) => assert_eq!(guard, "mcp-tool"),
            other => panic!("expected denied Chio-Wall receipt, got {other:?}"),
        }
        assert_eq!(manager.dlq_len(), 0, "successful export should not DLQ");

        let _ = fs::remove_dir_all(output);
    }

    /// A no-network alert backend so serve-mode alerting wiring can be exercised
    /// without an external PagerDuty/OpsGenie endpoint.
    struct StubAlertBackend {
        route: String,
    }

    impl chio_siem::AlertBackend for StubAlertBackend {
        fn name(&self) -> &str {
            &self.route
        }

        fn dispatch<'a>(
            &'a self,
            _alert: &'a chio_siem::Alert,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), chio_siem::ExportError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(()) })
        }
    }

    fn serve_deny_event(guard: &str) -> SiemEvent {
        use chio_core::receipt::kinds;
        use chio_core::receipt::metadata::GuardEvidence;

        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("hash receipt parameters");
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "serve-alert-rcpt".to_string(),
                timestamp: 1_700_000_000,
                capability_id: "cap".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action,
                decision: Some(Decision::Deny {
                    reason: "denied".to_string(),
                    guard: guard.to_string(),
                }),
                receipt_kind: kinds::ReceiptKind::MediatedDecision,
                boundary_class: kinds::BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: kinds::ToolOrigin::CallerExecuted,
                redaction_mode: kinds::RedactionMode::None,
                actor_chain: Vec::new(),
                content_hash: "c".to_string(),
                policy_hash: "p".to_string(),
                evidence: vec![GuardEvidence {
                    guard_name: guard.to_string(),
                    verdict: false,
                    details: None,
                }],
                metadata: None,
                trust_level: kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign serve-mode deny receipt");
        SiemEvent::from_receipt(receipt)
    }

    /// The serve-mode alerting wiring installs the registry metrics sink into a
    /// real AlertingExporter, so a real dispatch emits chio_alert_dispatch_total.
    #[tokio::test]
    async fn serve_alerting_wiring_emits_real_alert_dispatch_metric() {
        use chio_siem::Exporter;

        // Unique route so the process-global counter is not shared with any
        // other test in this binary.
        let route = "chio-wall-serve-alert-dispatch-test";
        let sink: std::sync::Arc<dyn chio_siem::SiemMetricsSink> =
            std::sync::Arc::new(crate::registry_metrics_sink::RegistryMetricsSink);
        let backend = Box::new(StubAlertBackend {
            route: route.to_string(),
        });

        let (exporter, routes) = build_serve_alerting_exporter(vec![backend], sink)
            .expect("a configured backend yields an alerting exporter");
        assert_eq!(routes, vec![route.to_string()]);

        // ForbiddenPathGuard derives High severity, meeting the default alerting
        // threshold, so the exporter dispatches to the test backend.
        let event = serve_deny_event("ForbiddenPathGuard");
        let processed = exporter
            .export_batch(std::slice::from_ref(&event))
            .await
            .expect("alert dispatch succeeds");
        assert_eq!(processed, 1, "the single deny event is dispatched");

        let mut body = String::new();
        chio_metrics_spec::runtime::families::ALERT_DISPATCH_TOTAL.render(&mut body);
        assert!(
            body.contains(&format!(
                "chio_alert_dispatch_total{{route=\"{route}\",outcome=\"success\"}} 1"
            )),
            "the wired serve-mode sink must emit a real alert_dispatch value: {body}"
        );
    }

    /// The serve path seeds soc_export/dlq_depth (always) and alert_dispatch
    /// (only when alerting is configured) at zero, so the absent-metric
    /// backstops fire only on a true scrape gap.
    #[test]
    fn serve_metrics_preregister_seeds_series_at_zero() {
        let exporter = "chio-wall-serve-seed-exporter";
        let route = "chio-wall-serve-seed-route";

        preregister_serve_metrics(&[exporter], &[route]);

        let mut soc = String::new();
        chio_metrics_spec::runtime::families::SOC_EXPORT_TOTAL.render(&mut soc);
        assert!(
            soc.contains(&format!(
                "chio_soc_export_total{{exporter=\"{exporter}\",outcome=\"success\"}} 0"
            )),
            "configured exporter soc_export must seed the success outcome at zero: {soc}"
        );
        assert!(
            soc.contains(
                "chio_soc_export_total{exporter=\"_deserialize\",outcome=\"malformed\"} 0"
            ),
            "the always-on _deserialize baseline must seed at zero: {soc}"
        );

        let mut dlq = String::new();
        chio_metrics_spec::runtime::families::DLQ_DEPTH.render(&mut dlq);
        assert!(
            dlq.contains(&format!("chio_dlq_depth{{exporter=\"{exporter}\"}} 0")),
            "configured exporter dlq_depth must seed at zero: {dlq}"
        );

        let mut alert = String::new();
        chio_metrics_spec::runtime::families::ALERT_DISPATCH_TOTAL.render(&mut alert);
        assert!(
            alert.contains(&format!(
                "chio_alert_dispatch_total{{route=\"{route}\",outcome=\"success\"}} 0"
            )),
            "configured alert route must seed success at zero: {alert}"
        );
        assert!(
            alert.contains(&format!(
                "chio_alert_dispatch_total{{route=\"{route}\",outcome=\"error\"}} 0"
            )),
            "configured alert route must seed error at zero: {alert}"
        );
    }

    /// The siem-export serve path renders the full alert pack but does not run
    /// the chio-cli tracing init that seeds the FIXED alert-pack series.
    /// `preregister_serve_metrics` must therefore seed them (fail-open /
    /// dispatch-failure / revocation-lag) so their absent_over_time backstops
    /// cannot false-fire on a healthy-but-quiet siem-export deploy.
    #[test]
    fn serve_metrics_preregister_seeds_fixed_alert_pack_series() {
        preregister_serve_metrics(&[], &[]);

        let mut body = String::new();
        chio_metrics_spec::runtime::render_alert_pack_families(&mut body);
        assert!(
            body.contains("chio_fail_open_suspected_total{surface=\"tower\"}"),
            "fixed fail-open series must be present at zero on the serve path: {body}"
        );
        assert!(
            body.contains("chio_dispatch_failure_total{"),
            "fixed dispatch-failure series must be present on the serve path: {body}"
        );
        assert!(
            body.contains("chio_capability_revocation_lag_seconds"),
            "fixed revocation-lag series must be present on the serve path: {body}"
        );
    }

    /// Alerting is operator-configured: with no alert backend, the serve wiring
    /// builds no AlertingExporter (and thus seeds no alert_dispatch series), so a
    /// legitimately alerting-disabled deploy does not falsely advertise the
    /// pipeline.
    #[test]
    fn serve_alerting_disabled_builds_no_exporter() {
        let sink: std::sync::Arc<dyn chio_siem::SiemMetricsSink> =
            std::sync::Arc::new(crate::registry_metrics_sink::RegistryMetricsSink);
        assert!(build_serve_alerting_exporter(Vec::new(), sink).is_none());
    }

    /// The serve mode must fail closed when no consumer is configured, rather
    /// than silently advancing the cursor over receipts nothing exports.
    #[test]
    fn serve_fails_closed_with_no_configured_consumer() {
        let error = ensure_serve_has_consumer(&[]).expect_err("zero consumers must fail closed");
        assert!(
            error.to_string().contains("SOC export sink"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn serve_accepts_a_real_soc_export_sink() {
        // A real SOC export sink (Splunk/Elastic/Webhook/...) satisfies the gate.
        assert!(ensure_serve_has_consumer(&["splunk".to_string()]).is_ok());
        // Alerting running ALONGSIDE a SOC sink is also fine.
        assert!(ensure_serve_has_consumer(&["alerting".to_string(), "splunk".to_string()]).is_ok());
    }

    /// The serve path wires a real SOC export sink from the CHIO_SIEM_WEBHOOK_*
    /// env, so a deploy that configures a webhook endpoint builds a real
    /// "webhook" consumer that satisfies the fail-closed gate. Only this test
    /// touches CHIO_SIEM_WEBHOOK_URL, so the set/remove cannot race another
    /// test's configured_soc_exporters() call.
    #[test]
    fn serve_soc_webhook_wiring_builds_a_real_consumer_and_passes_the_gate() {
        // Unconfigured: no SOC sink is fabricated, so the gate still fails closed.
        std::env::remove_var(WEBHOOK_URL_ENV);
        assert!(
            configured_soc_exporters()
                .expect("no SOC endpoint configured is not an error")
                .is_empty(),
            "no phantom consumer when unconfigured"
        );

        // Configured: a real "webhook" SOC consumer is built and satisfies the
        // gate that alerting alone cannot.
        std::env::set_var(WEBHOOK_URL_ENV, "https://soc.example.test/ingest");
        let exporters = configured_soc_exporters().expect("a webhook endpoint builds a SOC sink");
        std::env::remove_var(WEBHOOK_URL_ENV);

        let names: Vec<String> = exporters.iter().map(|e| e.name().to_string()).collect();
        assert_eq!(
            names,
            vec!["webhook".to_string()],
            "one real webhook SOC sink is registered"
        );
        assert!(
            ensure_serve_has_consumer(&names).is_ok(),
            "a wired SOC sink satisfies the fail-closed gate"
        );
    }

    /// Alerting is a notification overlay, not a SOC export sink. It returns
    /// every event as "processed" (so the manager advances the high-water mark)
    /// but only delivers high-severity denials and drops every allow/low-severity
    /// receipt. An alerting-ONLY serve config must be rejected at startup so the
    /// cursor never advances past audit rows no durable SOC export sink received.
    #[test]
    fn serve_fails_closed_when_only_alerting_is_configured() {
        let error = ensure_serve_has_consumer(&["alerting".to_string()])
            .expect_err("an alerting-only serve config must fail closed");
        assert!(
            error.to_string().contains("SOC export sink"),
            "unexpected error: {error}"
        );
    }

    /// The receipt-log watchdog samples health via a READ-ONLY open. A missing
    /// receipt DB must be reported as missing and must NOT be created (a
    /// create-on-open path would spawn an empty DB on a mistyped path and fail
    /// outright on a read-only mount).
    #[test]
    fn watchdog_sample_receipt_health_does_not_create_a_missing_db() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let missing = std::env::temp_dir().join(format!(
            "chio-wall-watchdog-missing-{}-{nonce}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        assert!(
            !missing.exists(),
            "precondition: the DB path must be absent"
        );

        let error = sample_receipt_health(&missing)
            .expect_err("a missing receipt DB must report missing, not be created");
        assert!(
            error.contains("does not exist"),
            "unexpected error: {error}"
        );
        assert!(
            !missing.exists(),
            "the watchdog must not create the missing receipt DB"
        );

        let _ = std::fs::remove_file(&missing);
    }

    /// `non_empty_env` returns a trimmed value, so a mounted secret with a
    /// trailing newline is not handed back verbatim. Uses a unique key so it
    /// cannot race.
    #[test]
    fn non_empty_env_returns_trimmed_value() {
        const KEY: &str = "CHIO_SIEM_TEST_TRIM_1218_UNIQUE";
        std::env::set_var(KEY, "  https://soc.example.test/ingest\n");
        let value = non_empty_env(KEY);
        std::env::remove_var(KEY);
        assert_eq!(
            value,
            Some("https://soc.example.test/ingest".to_string()),
            "surrounding whitespace/newlines must be trimmed"
        );

        std::env::set_var(KEY, "   \n\t ");
        let blank = non_empty_env(KEY);
        std::env::remove_var(KEY);
        assert_eq!(blank, None, "a whitespace-only value is treated as absent");
    }

    /// A SOC-only serve (no PagerDuty/OpsGenie configured) still ships the alert
    /// pack, whose ChioAlertDispatchMetricsMissing rule is unconditional, so
    /// preregister_serve_metrics must seed a zero chio_alert_dispatch_total
    /// baseline (under the `disabled` sentinel route) or the deployment pages on
    /// an intentionally silent alert pipeline.
    #[test]
    fn soc_only_serve_seeds_a_disabled_alert_dispatch_baseline() {
        preregister_serve_metrics(&["webhook"], &[]);
        let mut rendered = String::new();
        chio_metrics_spec::runtime::families::ALERT_DISPATCH_TOTAL.render(&mut rendered);
        assert!(
            rendered.contains("chio_alert_dispatch_total{route=\"disabled\""),
            "a SOC-only serve must seed a disabled alert-dispatch baseline: {rendered}"
        );
    }
}
