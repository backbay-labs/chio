use std::collections::BTreeSet;
use std::fmt::Debug;
use std::fs;
use std::path::Path;

use chio_control_plane::{evidence_export, CliError};
use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
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
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_keypair.public_key(),
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
    let receipt_db_path = output.join(".chio-wall-receipts.sqlite3");
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
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::receipt::Decision;
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
}
