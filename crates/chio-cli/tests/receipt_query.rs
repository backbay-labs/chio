//! Integration tests for GET /v1/receipts/query endpoint.
//!
//! Tests verify filtering, cursor pagination, total_count, and auth enforcement.
//! Also covers lineage endpoints (GET /v1/lineage/:id, /chain) and agent filter.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::appraisal::{
    derive_runtime_attestation_appraisal, RuntimeAttestationAppraisalImportReport,
    RuntimeAttestationAppraisalReport, RuntimeAttestationAppraisalRequest,
    RuntimeAttestationAppraisalResult, RuntimeAttestationAppraisalResultExportRequest,
    RuntimeAttestationImportDisposition, RuntimeAttestationImportReasonCode,
    RuntimeAttestationImportedAppraisalPolicy, RuntimeAttestationNormalizedClaimCode,
    RuntimeAttestationPolicyOutcome, SignedRuntimeAttestationAppraisalReport,
    SignedRuntimeAttestationAppraisalResult, AWS_NITRO_ATTESTATION_SCHEMA,
    AZURE_MAA_ATTESTATION_SCHEMA, ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA,
    GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA, RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA,
};
use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, GovernedAutonomyTier,
    GovernedCallChainContext, GovernedCallChainProvenance, MeteredBillingQuote,
    MeteredSettlementMode, MonetaryAmount, Operation, RuntimeAssuranceTier,
    RuntimeAttestationEvidence, ToolGrant, WorkloadIdentity,
};
use chio_core::credit::{
    CapitalAllocationDecisionOutcome, CapitalAllocationDecisionReasonCode, CapitalBookSourceKind,
    CapitalExecutionInstructionAction, CapitalExecutionIntendedState,
    CapitalExecutionReconciledState, CreditBondLifecycleState, CreditLossLifecycleArtifact,
    CreditLossLifecycleEventKind, CreditLossLifecycleFinding, CreditLossLifecycleQuery,
    CreditLossLifecycleReasonCode, CreditLossLifecycleReport, CreditLossLifecycleSummary,
    CreditLossLifecycleSupportBoundary, CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, FinancialBudgetAuthorityReceiptMetadata,
    FinancialBudgetAuthorizeReceiptMetadata, FinancialBudgetHoldAuthorityMetadata,
    FinancialBudgetTerminalReceiptMetadata, FinancialReceiptMetadata,
    GovernedApprovalReceiptMetadata, GovernedCommerceReceiptMetadata,
    GovernedTransactionReceiptMetadata, MeteredBillingReceiptMetadata, ReceiptAttributionMetadata,
    RuntimeAssuranceReceiptMetadata, SettlementStatus, ToolCallAction,
};
use chio_kernel::{
    build_checkpoint, AuthorizationContextReport, BudgetUsageRecord, CapabilitySnapshot,
    CreditBacktestReport, CreditBondListReport, CreditBondReport,
    CreditBondedExecutionSimulationReport, CreditFacilityListReport, CreditFacilityReport,
    CreditLossLifecycleListReport, FederatedEvidenceShareImport, LiabilityMarketWorkflowReport,
    LiabilityProviderListReport, LiabilityProviderResolutionReport, ReceiptStore,
    SignedBehavioralFeed, SignedCapitalAllocationDecision, SignedCapitalBookReport,
    SignedCapitalExecutionInstruction, SignedCreditBond, SignedCreditFacility,
    SignedCreditLossLifecycle, SignedCreditProviderRiskPackage, SignedCreditScorecardReport,
    SignedExposureLedgerReport, SignedLiabilityAutoBindDecision, SignedLiabilityBoundCoverage,
    SignedLiabilityClaimDispute, SignedLiabilityClaimPackage, SignedLiabilityClaimResponse,
    SignedLiabilityPlacement, SignedLiabilityPricingAuthority, SignedLiabilityProvider,
    SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse, SignedUnderwritingDecision,
    SignedUnderwritingPolicyInput, StoredToolReceipt, UnderwritingAppealRecord,
    UnderwritingDecisionListReport, UnderwritingDecisionReport, UnderwritingSimulationReport,
};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
use reqwest::blocking::Client;
use rusqlite::Connection;

// --- Test helpers ---

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn build_test_client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(120))
        .build()
        .expect("build reqwest client")
}

const TEST_REPUTATION_RECEIPT_TARGET: u64 = 100;
const LARGE_RECEIPT_HISTORY_LEN: u64 = 128;
const CAPITAL_ALLOCATION_QUEUE_HISTORY_LEN: u64 = 240;

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

fn tool_action(parameters: serde_json::Value) -> ToolCallAction {
    ToolCallAction::from_parameters(parameters).expect("hash tool action parameters")
}

fn sample_google_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now_secs();
    RuntimeAttestationEvidence {
        schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(30),
        expires_at: now.saturating_add(300),
        evidence_sha256: "sha256-google-attestation-report".to_string(),
        runtime_identity: Some("spiffe://chio.example/workloads/google".to_string()),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled",
                "audiences": ["https://chio.example/verifier"]
            }
        })),
    }
}

fn sample_azure_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now_secs();
    RuntimeAttestationEvidence {
        schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(30),
        expires_at: now.saturating_add(300),
        evidence_sha256: "sha256-azure-attestation-report".to_string(),
        runtime_identity: Some("spiffe://chio.example/workloads/azure".to_string()),
        workload_identity: Some(
            WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/azure")
                .expect("parse azure workload identity"),
        ),
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    }
}

fn sample_aws_nitro_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now_secs();
    RuntimeAttestationEvidence {
        schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
        verifier: "https://nitro.chio.example/verifier".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(30),
        expires_at: now.saturating_add(300),
        evidence_sha256: "sha256-aws-nitro-attestation-report".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "awsNitro": {
                "moduleId": "i-chio-nitro-enclave",
                "digest": "SHA384:chio-nitro-measurement",
                "pcrs": {
                    "0": "8f7f1be8",
                    "1": "1a2b3c4d"
                }
            }
        })),
    }
}

fn sample_enterprise_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = unix_now_secs();
    RuntimeAttestationEvidence {
        schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
        verifier: "https://enterprise-verifier.chio.example".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(30),
        expires_at: now.saturating_add(300),
        evidence_sha256: "sha256-enterprise-attestation-report".to_string(),
        runtime_identity: Some("spiffe://chio.example/workloads/enterprise".to_string()),
        workload_identity: Some(
            WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/enterprise")
                .expect("parse enterprise workload identity"),
        ),
        claims: Some(serde_json::json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_signed_envelope",
                "moduleId": "enterprise-module-1",
                "digest": "SHA256:enterprise-module-digest",
                "pcrs": {
                    "0": "abcd1234",
                    "7": "ef567890"
                },
                "hardwareModel": "enterprise_hsm_backed_runtime",
                "secureBoot": "enabled"
            }
        })),
    }
}

fn reserve_listen_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
}

struct ServerGuard {
    child: Child,
    _service_lock: MutexGuard<'static, ()>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn trust_service_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read_child_stderr(child: &mut Child) -> String {
    let Some(stderr) = child.stderr.take() else {
        return String::new();
    };
    let mut reader = std::io::BufReader::new(stderr);
    let mut output = String::new();
    let _ = std::io::Read::read_to_string(&mut reader, &mut output);
    output
}

fn write_test_reputation_policy(receipt_db_path: &Path) -> PathBuf {
    let policy_path = receipt_db_path
        .parent()
        .expect("receipt db parent")
        .join("test-reputation-policy.yaml");
    let policy = format!(
        r#"hushspec: "0.1.0"
name: "receipt-query-test-reputation"
description: "Test reputation policy for receipt query integration fixtures"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - read_file
      - safe_invoke
extensions:
  reputation:
    scoring:
      temporal_decay_half_life_days: 30
      probationary_receipt_count: {TEST_REPUTATION_RECEIPT_TARGET}
      probationary_min_days: 30
      probationary_score_ceiling: 0.60
    tiers:
      mature:
        score_range: [0.0, 1.0]
        max_scope:
          operations: [invoke, read, get, read_result]
          ttl_seconds: 300
"#
    );
    std::fs::write(&policy_path, policy).expect("write test reputation policy");
    policy_path
}

fn spawn_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    receipt_db_path: &PathBuf,
    revocation_db_path: &PathBuf,
    authority_db_path: &PathBuf,
    budget_db_path: &PathBuf,
) -> ServerGuard {
    let service_lock = trust_service_test_lock();
    let policy_path = write_test_reputation_policy(receipt_db_path);
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--policy",
            policy_path.to_str().expect("policy path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard {
        child,
        _service_lock: service_lock,
    }
}

fn spawn_trust_service_without_receipt_db(
    listen: std::net::SocketAddr,
    service_token: &str,
    revocation_db_path: &PathBuf,
    authority_db_path: &PathBuf,
    budget_db_path: &PathBuf,
) -> ServerGuard {
    let service_lock = trust_service_test_lock();
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service without receipt db");
    ServerGuard {
        child,
        _service_lock: service_lock,
    }
}

fn wait_for_trust_service_result(
    client: &Client,
    base_url: &str,
    service: &mut ServerGuard,
) -> Result<(), String> {
    for _ in 0..900 {
        if let Some(status) = service.child.try_wait().expect("poll trust service child") {
            let stderr = read_child_stderr(&mut service.child);
            return Err(format!(
                "trust service exited before becoming ready (status {status}): {stderr}"
            ));
        }
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return Ok(()),
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
    Err("trust service did not become ready before timeout".to_string())
}

fn wait_for_trust_service(client: &Client, base_url: &str) {
    let mut last_error = None;
    for _ in 0..900 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(response) => {
                last_error = Some(format!("health returned {}", response.status()));
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                last_error = Some(error.to_string());
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    panic!(
        "trust service did not become ready: {}",
        last_error.unwrap_or_else(|| "no health response observed".to_string())
    );
}

fn assert_trust_service_auth_required(client: &Client, base_url: &str, path: &str) {
    let response = client
        .get(format!("{base_url}{path}"))
        .send()
        .unwrap_or_else(|error| panic!("send unauthenticated request to {path}: {error}"));
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    let body: serde_json::Value = response
        .json()
        .unwrap_or_else(|error| panic!("parse unauthenticated error body for {path}: {error}"));
    assert!(body["error"]
        .as_str()
        .unwrap_or_else(|| panic!("extract unauthenticated error string for {path}"))
        .contains("missing or invalid control bearer token"));
}

fn assert_trust_service_get_error(
    client: &Client,
    base_url: &str,
    service_token: &str,
    path: &str,
    status: reqwest::StatusCode,
    expected_error_fragment: &str,
) {
    let response = client
        .get(format!("{base_url}{path}"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .unwrap_or_else(|error| panic!("send authorized request to {path}: {error}"));
    assert_eq!(response.status(), status, "unexpected status for {path}");
    let body: serde_json::Value = response
        .json()
        .unwrap_or_else(|error| panic!("parse error body for {path}: {error}"));
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_else(|| panic!("extract error string for {path}"))
            .contains(expected_error_fragment),
        "expected error for {path} to contain `{expected_error_fragment}`, got {body:?}"
    );
}

fn record_test_credit_loss_event(
    receipt_db_path: &PathBuf,
    bond: &SignedCreditBond,
    event_id: &str,
    amount_units: u64,
) -> SignedCreditLossLifecycle {
    record_test_credit_loss_event_with_kind(
        receipt_db_path,
        bond,
        event_id,
        CreditLossLifecycleEventKind::Delinquency,
        amount_units,
        CreditBondLifecycleState::Impaired,
        CreditLossLifecycleReasonCode::DelinquencyRecorded,
        "test delinquency lifecycle event",
    )
}

fn record_test_credit_loss_event_with_kind(
    receipt_db_path: &PathBuf,
    bond: &SignedCreditBond,
    event_id: &str,
    event_kind: CreditLossLifecycleEventKind,
    amount_units: u64,
    projected_bond_lifecycle_state: CreditBondLifecycleState,
    finding_code: CreditLossLifecycleReasonCode,
    finding_description: &str,
) -> SignedCreditLossLifecycle {
    let keypair = Keypair::generate();
    let issued_at = unix_now_secs();
    let currency = bond
        .body
        .report
        .terms
        .as_ref()
        .map(|terms| terms.collateral_amount.currency.clone())
        .unwrap_or_else(|| "USD".to_string());
    let report = CreditLossLifecycleReport {
        schema: CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
        generated_at: issued_at,
        query: CreditLossLifecycleQuery {
            bond_id: bond.body.bond_id.clone(),
            event_kind,
            amount: None,
        },
        summary: CreditLossLifecycleSummary {
            bond_id: bond.body.bond_id.clone(),
            facility_id: bond.body.report.latest_facility_id.clone(),
            capability_id: bond.body.report.filters.capability_id.clone(),
            agent_subject: bond.body.report.filters.agent_subject.clone(),
            tool_server: bond.body.report.filters.tool_server.clone(),
            tool_name: bond.body.report.filters.tool_name.clone(),
            current_bond_lifecycle_state: bond.body.lifecycle_state,
            projected_bond_lifecycle_state,
            current_delinquent_amount: matches!(
                event_kind,
                CreditLossLifecycleEventKind::Delinquency | CreditLossLifecycleEventKind::WriteOff
            )
            .then(|| MonetaryAmount {
                units: amount_units,
                currency: currency.clone(),
            }),
            current_recovered_amount: (event_kind == CreditLossLifecycleEventKind::Recovery).then(
                || MonetaryAmount {
                    units: amount_units,
                    currency: currency.clone(),
                },
            ),
            current_written_off_amount: (event_kind == CreditLossLifecycleEventKind::WriteOff)
                .then(|| MonetaryAmount {
                    units: amount_units,
                    currency: currency.clone(),
                }),
            current_released_reserve_amount: (event_kind
                == CreditLossLifecycleEventKind::ReserveRelease)
                .then(|| MonetaryAmount {
                    units: amount_units,
                    currency: currency.clone(),
                }),
            current_slashed_reserve_amount: (event_kind
                == CreditLossLifecycleEventKind::ReserveSlash)
                .then(|| MonetaryAmount {
                    units: amount_units,
                    currency: currency.clone(),
                }),
            outstanding_delinquent_amount: matches!(
                event_kind,
                CreditLossLifecycleEventKind::Delinquency | CreditLossLifecycleEventKind::WriteOff
            )
            .then(|| MonetaryAmount {
                units: amount_units,
                currency: currency.clone(),
            }),
            releaseable_reserve_amount: bond
                .body
                .report
                .terms
                .as_ref()
                .map(|terms| terms.reserve_requirement_amount.clone()),
            reserve_control_source_id: None,
            execution_state: None,
            appeal_state: None,
            appeal_window_ends_at: None,
            event_amount: Some(MonetaryAmount {
                units: amount_units,
                currency: currency.clone(),
            }),
        },
        support_boundary: CreditLossLifecycleSupportBoundary::default(),
        findings: vec![CreditLossLifecycleFinding {
            code: finding_code,
            description: finding_description.to_string(),
            evidence_refs: Vec::new(),
        }],
    };
    let artifact = CreditLossLifecycleArtifact {
        schema: CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
        event_id: event_id.to_string(),
        issued_at,
        bond_id: bond.body.bond_id.clone(),
        event_kind,
        projected_bond_lifecycle_state,
        reserve_control_source_id: None,
        authority_chain: Vec::new(),
        execution_window: None,
        rail: None,
        observed_execution: None,
        reconciled_state: None,
        execution_state: None,
        appeal_state: None,
        appeal_window_ends_at: None,
        description: None,
        report,
    };
    let event =
        SignedCreditLossLifecycle::sign(artifact, &keypair).expect("sign test loss lifecycle");
    let mut store = SqliteReceiptStore::open(receipt_db_path).expect("open store for loss event");
    store
        .record_credit_loss_lifecycle(&event)
        .expect("record test loss lifecycle");
    event
}

fn record_test_capability_snapshot(
    store: &mut SqliteReceiptStore,
    capability_id: &str,
    issuer: &Keypair,
    subject: &Keypair,
    tool_server: &str,
    tool_name: &str,
    dpop_required: Option<bool>,
) {
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: tool_server.to_string(),
                    tool_name: tool_name.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(10),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 5_000,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 20_000,
                        currency: "USD".to_string(),
                    }),
                    dpop_required,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 1_000,
            expires_at: 20_000,
            delegation_chain: vec![],
        },
        issuer,
    )
    .expect("sign test capability");
    store
        .record_capability_snapshot(&token, None)
        .expect("record test capability snapshot");
}

/// Build a ChioReceipt for test insertion.
fn make_receipt(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    decision: Decision,
    timestamp: u64,
    cost: Option<u64>,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = cost.map(|c| {
        serde_json::json!({
            "financial": {
                "grant_index": 0u32,
                "cost_charged": c,
                "currency": "USD",
                "budget_remaining": 1000u64,
                "budget_total": 2000u64,
                "delegation_depth": 0u32,
                "root_budget_holder": "root-agent",
                "settlement_status": "pending"
            }
        })
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({})),
            decision,
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_financial_receipt(
    id: &str,
    capability_id: &str,
    subject_key: Option<&str>,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    decision: Decision,
    timestamp: u64,
    cost_charged: u64,
    attempted_cost: Option<u64>,
    root_budget_holder: &str,
    delegation_depth: u32,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
        guarantee_level: "ha_quorum_commit".to_string(),
        authority_profile: "authoritative_hold_event".to_string(),
        metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
        hold_id: format!("budget-hold:{id}:capability:0"),
        budget_term: Some("http://leader-a:7".to_string()),
        authority: Some(FinancialBudgetHoldAuthorityMetadata {
            authority_id: "http://leader-a".to_string(),
            lease_id: "http://leader-a#term-7".to_string(),
            lease_epoch: 7,
        }),
        authorize: FinancialBudgetAuthorizeReceiptMetadata {
            event_id: Some(format!("budget-hold:{id}:capability:0:authorize")),
            budget_commit_index: Some(41),
            exposure_units: cost_charged.max(attempted_cost.unwrap_or(0)),
            committed_cost_units_after: cost_charged.max(attempted_cost.unwrap_or(0)),
        },
        terminal: Some(FinancialBudgetTerminalReceiptMetadata {
            disposition: if cost_charged == 0 {
                "released".to_string()
            } else {
                "reconciled".to_string()
            },
            event_id: Some(format!("budget-hold:{id}:capability:0:terminal")),
            budget_commit_index: Some(42),
            exposure_units: cost_charged.max(attempted_cost.unwrap_or(0)),
            realized_spend_units: cost_charged,
            committed_cost_units_after: cost_charged,
        }),
    };
    let metadata = serde_json::json!({
        "attribution": subject_key.map(|subject_key| ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: issuer_key.to_string(),
            delegation_depth,
            grant_index: Some(0),
        }),
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged,
            currency: "USD".to_string(),
            budget_remaining: 900u64,
            budget_total: 1000u64,
            delegation_depth,
            root_budget_holder: root_budget_holder.to_string(),
            payment_reference: None,
            settlement_status: if attempted_cost.is_some() && cost_charged == 0 {
                SettlementStatus::NotApplicable
            } else {
                SettlementStatus::Settled
            },
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost,
        },
        "budget_authority": budget_authority,
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({})),
            decision,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_financial_receipt_with_budget_authority(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 75,
            currency: "USD".to_string(),
            budget_remaining: 925u64,
            budget_total: 1000u64,
            delegation_depth: 0,
            root_budget_holder: "root-budget-holder".to_string(),
            payment_reference: Some("pi-budget-lineage-1".to_string()),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "budget_authority": FinancialBudgetAuthorityReceiptMetadata {
            guarantee_level: "ha_quorum_commit".to_string(),
            authority_profile: "authoritative_hold_event".to_string(),
            metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
            hold_id: "budget-hold:req-query-1:cap-budget-lineage:0".to_string(),
            budget_term: Some("http://leader-a:7".to_string()),
            authority: Some(FinancialBudgetHoldAuthorityMetadata {
                authority_id: "http://leader-a".to_string(),
                lease_id: "http://leader-a#term-7".to_string(),
                lease_epoch: 7,
            }),
            authorize: FinancialBudgetAuthorizeReceiptMetadata {
                event_id: Some(
                    "budget-hold:req-query-1:cap-budget-lineage:0:authorize".to_string(),
                ),
                budget_commit_index: Some(41),
                exposure_units: 120,
                committed_cost_units_after: 120,
            },
            terminal: Some(FinancialBudgetTerminalReceiptMetadata {
                disposition: "reconciled".to_string(),
                event_id: Some(
                    "budget-hold:req-query-1:cap-budget-lineage:0:reconcile".to_string(),
                ),
                budget_commit_index: Some(42),
                exposure_units: 120,
                realized_spend_units: 75,
                committed_cost_units_after: 75,
            }),
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "sku": "budget-lineage" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_financial_receipt_with_settlement_status(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    cost_charged: u64,
    settlement_status: SettlementStatus,
    payment_reference: Option<&str>,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
        guarantee_level: "ha_quorum_commit".to_string(),
        authority_profile: "authoritative_hold_event".to_string(),
        metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
        hold_id: format!("budget-hold:{id}:capability:0"),
        budget_term: Some("http://leader-a:7".to_string()),
        authority: Some(FinancialBudgetHoldAuthorityMetadata {
            authority_id: "http://leader-a".to_string(),
            lease_id: "http://leader-a#term-7".to_string(),
            lease_epoch: 7,
        }),
        authorize: FinancialBudgetAuthorizeReceiptMetadata {
            event_id: Some(format!("budget-hold:{id}:capability:0:authorize")),
            budget_commit_index: Some(41),
            exposure_units: cost_charged,
            committed_cost_units_after: cost_charged,
        },
        terminal: Some(FinancialBudgetTerminalReceiptMetadata {
            disposition: match settlement_status {
                SettlementStatus::Failed => "released".to_string(),
                _ => "reconciled".to_string(),
            },
            event_id: Some(format!("budget-hold:{id}:capability:0:terminal")),
            budget_commit_index: Some(42),
            exposure_units: cost_charged,
            realized_spend_units: if matches!(settlement_status, SettlementStatus::Failed) {
                0
            } else {
                cost_charged
            },
            committed_cost_units_after: if matches!(settlement_status, SettlementStatus::Failed) {
                0
            } else {
                cost_charged
            },
        }),
    };
    let metadata = serde_json::json!({
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged,
            currency: "USD".to_string(),
            budget_remaining: 900u64,
            budget_total: 1000u64,
            delegation_depth: 0,
            root_budget_holder: "root-budget-holder".to_string(),
            payment_reference: payment_reference.map(ToOwned::to_owned),
            settlement_status,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "budget_authority": budget_authority
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "sku": "reconcile-me" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_governed_financial_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    cost_charged: u64,
    root_budget_holder: &str,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: issuer_key.to_string(),
            delegation_depth: 1,
            grant_index: Some(0),
        },
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged,
            currency: "USD".to_string(),
            budget_remaining: 250u64,
            budget_total: 1000u64,
            delegation_depth: 1,
            root_budget_holder: root_budget_holder.to_string(),
            payment_reference: Some("payment-risk-1".to_string()),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: "intent-risk-1".to_string(),
            intent_hash: "intent-hash-risk-1".to_string(),
            purpose: "purchase governed compute".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units: 900,
                currency: "USD".to_string(),
            }),
            commerce: Some(GovernedCommerceReceiptMetadata {
                seller: "seller-risk".to_string(),
                shared_payment_token_id: "spt-risk-1".to_string(),
            }),
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-risk-1".to_string(),
                approver_key: issuer_key.to_string(),
                approved: true,
            }),
            runtime_assurance: None,
            call_chain: None,
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "sku": "insured-feed" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_governed_receipt(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 4200,
            currency: "USD".to_string(),
            budget_remaining: 5800u64,
            budget_total: 10_000u64,
            delegation_depth: 0,
            root_budget_holder: "ops-root".to_string(),
            payment_reference: Some("pi_governed_1".to_string()),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: "intent-ops-1".to_string(),
            intent_hash: "intent-hash-ops-1".to_string(),
            purpose: "approve vendor payout".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            }),
            commerce: None,
            metered_billing: Some(MeteredBillingReceiptMetadata {
                settlement_mode: MeteredSettlementMode::AllowThenSettle,
                quote: MeteredBillingQuote {
                    quote_id: "quote-ops-1".to_string(),
                    provider: "billing.chio".to_string(),
                    billing_unit: "1k_tokens".to_string(),
                    quoted_units: 12,
                    quoted_cost: MonetaryAmount {
                        units: 3800,
                        currency: "USD".to_string(),
                    },
                    issued_at: 1_900,
                    expires_at: Some(2_600),
                },
                max_billed_units: Some(18),
                usage_evidence: None,
            }),
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-ops-1".to_string(),
                approver_key: "approver-key-1".to_string(),
                approved: true,
            }),
            runtime_assurance: None,
            call_chain: None,
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "invoice_id": "inv-1001" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_governed_authorization_receipt_with_options(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    settlement_status: SettlementStatus,
    financial_currency: &str,
    exposure_units: u64,
    exposure_currency: &str,
    include_metered_billing: bool,
    include_call_chain: bool,
) -> ChioReceipt {
    make_governed_authorization_receipt_with_runtime_profile(
        id,
        capability_id,
        subject_key,
        issuer_key,
        tool_server,
        tool_name,
        timestamp,
        settlement_status,
        financial_currency,
        exposure_units,
        exposure_currency,
        include_metered_billing,
        include_call_chain,
        AZURE_MAA_ATTESTATION_SCHEMA,
        Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
        RuntimeAssuranceTier::Verified,
        "verifier.chio",
        "sha256-attestation-auth-1",
    )
}

#[allow(clippy::too_many_arguments)]
fn make_governed_authorization_receipt_with_runtime_profile(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    settlement_status: SettlementStatus,
    financial_currency: &str,
    exposure_units: u64,
    exposure_currency: &str,
    include_metered_billing: bool,
    include_call_chain: bool,
    runtime_schema: &str,
    runtime_verifier_family: Option<chio_core::appraisal::AttestationVerifierFamily>,
    runtime_tier: RuntimeAssuranceTier,
    runtime_verifier: &str,
    runtime_evidence_sha256: &str,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: issuer_key.to_string(),
            delegation_depth: 1,
            grant_index: Some(0),
        },
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: exposure_units,
            currency: financial_currency.to_string(),
            budget_remaining: 10_000u64.saturating_sub(exposure_units),
            budget_total: 10_000u64,
            delegation_depth: 1,
            root_budget_holder: "ops-root".to_string(),
            payment_reference: Some("pi_authorization_1".to_string()),
            settlement_status,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: "intent-auth-1".to_string(),
            intent_hash: "intent-hash-auth-1".to_string(),
            purpose: "delegate external partner workflow".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units: exposure_units,
                currency: exposure_currency.to_string(),
            }),
            commerce: Some(GovernedCommerceReceiptMetadata {
                seller: "merchant.example".to_string(),
                shared_payment_token_id: "spt_live_auth_1".to_string(),
            }),
            metered_billing: include_metered_billing.then_some(MeteredBillingReceiptMetadata {
                settlement_mode: MeteredSettlementMode::AllowThenSettle,
                quote: MeteredBillingQuote {
                    quote_id: "quote-auth-1".to_string(),
                    provider: "billing.chio".to_string(),
                    billing_unit: "1k_tokens".to_string(),
                    quoted_units: 12,
                    quoted_cost: MonetaryAmount {
                        units: exposure_units.saturating_sub(400),
                        currency: financial_currency.to_string(),
                    },
                    issued_at: 1_900,
                    expires_at: Some(2_600),
                },
                max_billed_units: Some(18),
                usage_evidence: None,
            }),
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-auth-1".to_string(),
                approver_key: issuer_key.to_string(),
                approved: true,
            }),
            runtime_assurance: Some(RuntimeAssuranceReceiptMetadata {
                schema: runtime_schema.to_string(),
                verifier_family: runtime_verifier_family,
                tier: runtime_tier,
                verifier: runtime_verifier.to_string(),
                evidence_sha256: runtime_evidence_sha256.to_string(),
                workload_identity: None,
            }),
            call_chain: include_call_chain.then_some(GovernedCallChainProvenance::asserted(
                GovernedCallChainContext {
                    chain_id: "chain-ext-1".to_string(),
                    parent_request_id: "req-upstream-1".to_string(),
                    parent_receipt_id: Some("rcpt-upstream-1".to_string()),
                    origin_subject: "subject-root".to_string(),
                    delegator_subject: "subject-delegator".to_string(),
                },
            )),
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "invoice_id": "inv-auth-1001" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_governed_authorization_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
) -> ChioReceipt {
    make_governed_authorization_receipt_with_options(
        id,
        capability_id,
        subject_key,
        issuer_key,
        tool_server,
        tool_name,
        timestamp,
        SettlementStatus::Settled,
        "USD",
        4_200,
        "USD",
        true,
        true,
    )
}

fn make_credit_history_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    settlement_status: SettlementStatus,
    financial_currency: &str,
    exposure_units: u64,
    exposure_currency: &str,
    include_runtime_assurance: bool,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: issuer_key.to_string(),
            delegation_depth: 1,
            grant_index: Some(0),
        },
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: exposure_units,
            currency: financial_currency.to_string(),
            budget_remaining: 100_000u64.saturating_sub(exposure_units),
            budget_total: 100_000u64,
            delegation_depth: 1,
            root_budget_holder: "ops-root".to_string(),
            payment_reference: Some(format!("pi-{id}")),
            settlement_status,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: format!("intent-{id}"),
            intent_hash: format!("intent-hash-{id}"),
            purpose: "credit backtest fixture".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units: exposure_units,
                currency: exposure_currency.to_string(),
            }),
            commerce: Some(GovernedCommerceReceiptMetadata {
                seller: "merchant.example".to_string(),
                shared_payment_token_id: format!("spt-{id}"),
            }),
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: format!("approval-{id}"),
                approver_key: issuer_key.to_string(),
                approved: true,
            }),
            runtime_assurance: include_runtime_assurance.then_some(RuntimeAssuranceReceiptMetadata {
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                tier: RuntimeAssuranceTier::Verified,
                verifier: "verifier.chio".to_string(),
                evidence_sha256: format!("sha256-{id}"),
                workload_identity: None,
            }),
            call_chain: None,
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "invoice_id": format!("inv-{id}") })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_governed_authorization_receipt_without_runtime_assurance(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    currency: &str,
    units: u64,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: issuer_key.to_string(),
            delegation_depth: 1,
            grant_index: Some(0),
        },
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: units,
            currency: currency.to_string(),
            budget_remaining: 50_000u64.saturating_sub(units),
            budget_total: 50_000u64,
            delegation_depth: 1,
            root_budget_holder: "ops-root".to_string(),
            payment_reference: Some("pi_facility_1".to_string()),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: "intent-facility-1".to_string(),
            intent_hash: "intent-hash-facility-1".to_string(),
            purpose: "credit facility prerequisite test".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: None,
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-facility-1".to_string(),
                approver_key: issuer_key.to_string(),
                approved: true,
            }),
            runtime_assurance: None,
            call_chain: None,
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "invoice_id": "inv-facility-1001" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_underwriting_simulation_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    runtime_tier: RuntimeAssuranceTier,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: issuer_key.to_string(),
            delegation_depth: 1,
            grant_index: Some(0),
        },
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 100,
            currency: "USD".to_string(),
            budget_remaining: 9_900u64,
            budget_total: 10_000u64,
            delegation_depth: 1,
            root_budget_holder: "ops-root".to_string(),
            payment_reference: Some(format!("pi-sim-{id}")),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: format!("intent-sim-{id}"),
            intent_hash: format!("intent-hash-sim-{id}"),
            purpose: "simulate underwriting policy".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            commerce: None,
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: format!("approval-sim-{id}"),
                approver_key: issuer_key.to_string(),
                approved: true,
            }),
            runtime_assurance: Some(RuntimeAssuranceReceiptMetadata {
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                tier: runtime_tier,
                verifier: "verifier.chio".to_string(),
                evidence_sha256: format!("sha256-attestation-sim-{id}"),
                workload_identity: None,
            }),
            call_chain: None,
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "simulation": true })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_governed_x402_receipt(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 4200,
            currency: "USD".to_string(),
            budget_remaining: 5800u64,
            budget_total: 10_000u64,
            delegation_depth: 0,
            root_budget_holder: "ops-root".to_string(),
            payment_reference: Some("x402_txn_ops_1".to_string()),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: Some(serde_json::json!({
                "payment": {
                    "authorization_id": "x402_txn_ops_1",
                    "adapter_metadata": {
                        "adapter": "x402",
                        "mode": "prepaid",
                        "network": "base"
                    },
                    "preauthorized_units": 4200,
                    "recorded_units": 4200
                }
            })),
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: "intent-x402-ops-1".to_string(),
            intent_hash: "intent-hash-x402-ops-1".to_string(),
            purpose: "purchase premium API result".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            }),
            commerce: None,
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-x402-ops-1".to_string(),
                approver_key: "approver-key-x402".to_string(),
                approved: true,
            }),
            runtime_assurance: None,
            call_chain: None,
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "sku": "dataset-pro" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_governed_acp_receipt(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 4200,
            currency: "USD".to_string(),
            budget_remaining: 5800u64,
            budget_total: 10_000u64,
            delegation_depth: 0,
            root_budget_holder: "ops-root".to_string(),
            payment_reference: Some("acp_hold_ops_1".to_string()),
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: Some(serde_json::json!({
                "payment": {
                    "authorization_id": "acp_hold_ops_1",
                    "adapter_metadata": {
                        "adapter": "acp",
                        "mode": "shared_payment_token_hold",
                        "provider": "stripe",
                        "seller": "merchant.example"
                    },
                    "preauthorized_units": 4200,
                    "recorded_units": 4200
                }
            })),
            oracle_evidence: None,
            attempted_cost: None,
        },
        "governed_transaction": GovernedTransactionReceiptMetadata {
            intent_id: "intent-acp-ops-1".to_string(),
            intent_hash: "intent-hash-acp-ops-1".to_string(),
            purpose: "purchase seller-bound result".to_string(),
            server_id: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            max_amount: Some(MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            }),
            commerce: Some(GovernedCommerceReceiptMetadata {
                seller: "merchant.example".to_string(),
                shared_payment_token_id: "spt_live_ops_1".to_string(),
            }),
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-acp-ops-1".to_string(),
                approver_key: "approver-key-acp".to_string(),
                approved: true,
            }),
            runtime_assurance: None,
            call_chain: None,
            autonomy: None,
            economic_authorization: None,
        }
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: tool_action(serde_json::json!({ "sku": "merchant-result-pro" })),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

/// Common test setup: create temp dir, insert receipts, start trust service, return setup info.
struct TestSetup {
    dir: PathBuf,
    _receipt_db_path: PathBuf,
    _revocation_db_path: PathBuf,
    _authority_db_path: PathBuf,
    _budget_db_path: PathBuf,
    base_url: String,
    service_token: String,
    _service: ServerGuard,
    client: Client,
}

fn setup_with_receipts(prefix: &str) -> TestSetup {
    let dir = unique_dir(prefix);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    // Insert test receipts directly into SQLite before the service starts.
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");

        // 3 receipts with cap-1
        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "files",
                "read",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();

        // 1 receipt with cap-2
        store
            .append_chio_receipt(&make_receipt(
                "r-4",
                "cap-2",
                "shell",
                "bash",
                Decision::Allow,
                1003,
                None,
            ))
            .unwrap();

        // 1 denied receipt with cap-1
        store
            .append_chio_receipt(&make_receipt(
                "r-5",
                "cap-1",
                "shell",
                "bash",
                Decision::Deny {
                    reason: "policy".to_string(),
                    guard: "allow_guard".to_string(),
                },
                1004,
                Some(200),
            ))
            .unwrap();
    }

    let service_token = "test-secret-token".to_string();
    let client = build_test_client();
    let mut startup_error = None;
    let mut started = None;
    for _ in 0..3 {
        let listen = reserve_listen_addr();
        let mut service = spawn_trust_service(
            listen,
            &service_token,
            &receipt_db_path,
            &revocation_db_path,
            &authority_db_path,
            &budget_db_path,
        );
        let base_url = format!("http://{listen}");
        match wait_for_trust_service_result(&client, &base_url, &mut service) {
            Ok(()) => {
                started = Some((service, base_url));
                break;
            }
            Err(error) => {
                startup_error = Some(error);
                drop(service);
            }
        }
    }
    let (service, base_url) = started.unwrap_or_else(|| {
        panic!(
            "trust service did not become ready after retries: {}",
            startup_error
                .clone()
                .unwrap_or_else(|| "unknown startup failure".to_string())
        )
    });
    if let Some(error) = startup_error.take() {
        eprintln!("receipt_query startup retry recovered after: {error}");
    }

    TestSetup {
        dir,
        _receipt_db_path: receipt_db_path,
        _revocation_db_path: revocation_db_path,
        _authority_db_path: authority_db_path,
        _budget_db_path: budget_db_path,
        base_url,
        service_token,
        _service: service,
        client,
    }
}

// --- Tests ---

/// GET /v1/receipts/query with no filters returns all stored receipts and correct totalCount.
#[test]
fn test_receipt_query_no_filters() {
    let setup = setup_with_receipts("chio-rq-no-filters");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(
        total_count, 5,
        "all 5 inserted receipts should be in totalCount"
    );
    assert_eq!(
        receipts.len(),
        5,
        "all 5 receipts should be returned with default limit"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/receipts/query?capabilityId=cap-1 returns only receipts with capability_id == "cap-1".
#[test]
fn test_receipt_query_filter_capability() {
    let setup = setup_with_receipts("chio-rq-filter-cap");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("capabilityId", "cap-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(total_count, 4, "4 receipts have cap-1");
    assert_eq!(receipts.len(), 4);

    for receipt in receipts {
        assert_eq!(
            receipt["capability_id"].as_str().expect("capability_id"),
            "cap-1",
            "all returned receipts must have capability_id == cap-1"
        );
    }

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_receipt_query_surfaces_governed_transaction_metadata() {
    let dir = unique_dir("chio-rq-governed");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_receipt(
                "r-governed-1",
                "cap-governed-1",
                "payments",
                "submit_wire",
                2_000,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-governed-secret-token".to_string();
    let mut service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service_result(&client, &base_url, &mut service)
        .expect("wait for trust service");

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-governed-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one governed receipt");

    let governed = &receipts[0]["metadata"]["governed_transaction"];
    assert_eq!(governed["intent_id"], "intent-ops-1");
    assert_eq!(governed["purpose"], "approve vendor payout");
    assert_eq!(governed["server_id"], "payments");
    assert_eq!(governed["tool_name"], "submit_wire");
    assert_eq!(governed["max_amount"]["units"].as_u64(), Some(4200));
    assert_eq!(
        governed["metered_billing"]["settlementMode"],
        "allow_then_settle"
    );
    assert_eq!(
        governed["metered_billing"]["quote"]["quoteId"],
        "quote-ops-1"
    );
    assert_eq!(
        governed["metered_billing"]["quote"]["quotedCost"]["units"].as_u64(),
        Some(3800)
    );
    assert_eq!(
        governed["metered_billing"]["maxBilledUnits"].as_u64(),
        Some(18)
    );
    assert_eq!(governed["approval"]["token_id"], "approval-ops-1");
    assert_eq!(governed["approval"]["approved"], true);

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["cost_charged"].as_u64(), Some(4200));
    assert_eq!(financial["payment_reference"], "pi_governed_1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_receipt_query_surfaces_x402_payment_metadata() {
    let dir = unique_dir("chio-rq-x402");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "r-x402-1",
                "cap-x402-1",
                "payments",
                "fetch_dataset",
                2_100,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-x402-secret-token".to_string();
    let mut service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service_result(&client, &base_url, &mut service)
        .expect("wait for trust service");

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-x402-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one x402 receipt");

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["payment_reference"], "x402_txn_ops_1");
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "x402_txn_ops_1"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "x402"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["mode"],
        "prepaid"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["network"],
        "base"
    );

    let governed = &receipts[0]["metadata"]["governed_transaction"];
    assert_eq!(governed["intent_id"], "intent-x402-ops-1");
    assert_eq!(governed["approval"]["token_id"], "approval-x402-ops-1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_receipt_query_surfaces_acp_payment_metadata() {
    let dir = unique_dir("chio-rq-acp");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_acp_receipt(
                "r-acp-1",
                "cap-acp-1",
                "commerce",
                "checkout",
                2_200,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-acp-secret-token".to_string();
    let mut service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service_result(&client, &base_url, &mut service)
        .expect("wait for trust service");

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-acp-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one acp receipt");

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["payment_reference"], "acp_hold_ops_1");
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "acp_hold_ops_1"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "acp"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["mode"],
        "shared_payment_token_hold"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["seller"],
        "merchant.example"
    );

    let governed = &receipts[0]["metadata"]["governed_transaction"];
    assert_eq!(governed["intent_id"], "intent-acp-ops-1");
    assert_eq!(governed["commerce"]["seller"], "merchant.example");
    assert_eq!(
        governed["commerce"]["shared_payment_token_id"],
        "spt_live_ops_1"
    );
    assert_eq!(governed["approval"]["token_id"], "approval-acp-ops-1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn receipt_query_surfaces_financial_hold_lineage_and_guarantee_level() {
    let dir = unique_dir("chio-rq-budget-lineage");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_financial_receipt_with_budget_authority(
                "r-budget-lineage-1",
                "cap-budget-lineage-1",
                "payments",
                "charge",
                2_250,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-budget-lineage-secret-token".to_string();
    let mut service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service_result(&client, &base_url, &mut service)
        .expect("wait for trust service");

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-budget-lineage-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts is array");
    assert_eq!(receipts.len(), 1, "expected one financial receipt");

    let financial = &receipts[0]["metadata"]["financial"];
    assert_eq!(financial["cost_charged"].as_u64(), Some(75));
    assert_eq!(financial["settlement_status"].as_str(), Some("settled"));

    let budget_authority = &receipts[0]["metadata"]["budget_authority"];
    assert_eq!(
        budget_authority["guarantee_level"].as_str(),
        Some("ha_quorum_commit")
    );
    assert_eq!(
        budget_authority["hold_id"].as_str(),
        Some("budget-hold:req-query-1:cap-budget-lineage:0")
    );
    assert_eq!(
        budget_authority["budget_term"].as_str(),
        Some("http://leader-a:7")
    );
    assert_eq!(
        budget_authority["authority"]["authority_id"].as_str(),
        Some("http://leader-a")
    );
    assert_eq!(
        budget_authority["authority"]["lease_id"].as_str(),
        Some("http://leader-a#term-7")
    );
    assert_eq!(
        budget_authority["authority"]["lease_epoch"].as_u64(),
        Some(7)
    );
    assert_eq!(
        budget_authority["authorize"]["event_id"].as_str(),
        Some("budget-hold:req-query-1:cap-budget-lineage:0:authorize")
    );
    assert_eq!(
        budget_authority["authorize"]["budget_commit_index"].as_u64(),
        Some(41)
    );
    assert_eq!(
        budget_authority["terminal"]["disposition"].as_str(),
        Some("reconciled")
    );
    assert_eq!(
        budget_authority["terminal"]["event_id"].as_str(),
        Some("budget-hold:req-query-1:cap-budget-lineage:0:reconcile")
    );
    assert_eq!(
        budget_authority["terminal"]["budget_commit_index"].as_u64(),
        Some(42)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Two requests with cursor yield non-overlapping sequential results.
#[test]
fn test_receipt_query_cursor_pagination() {
    let setup = setup_with_receipts("chio-rq-cursor");

    // First page: limit=2
    let response1 = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "2")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send first request");

    assert_eq!(response1.status(), reqwest::StatusCode::OK);
    let body1: serde_json::Value = response1.json().expect("parse json page 1");
    let receipts1 = body1["receipts"].as_array().expect("receipts page 1");
    assert_eq!(receipts1.len(), 2, "first page should have 2 receipts");

    let next_cursor = body1["nextCursor"]
        .as_u64()
        .expect("nextCursor should be present after page 1");

    // Second page: use cursor
    let response2 = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "2"), ("cursor", &next_cursor.to_string())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send second request");

    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = response2.json().expect("parse json page 2");
    let receipts2 = body2["receipts"].as_array().expect("receipts page 2");
    assert_eq!(receipts2.len(), 2, "second page should have 2 receipts");

    // The two pages must not overlap (receipts have unique ids).
    let ids1: Vec<&str> = receipts1
        .iter()
        .map(|r| r["id"].as_str().expect("receipt id"))
        .collect();
    let ids2: Vec<&str> = receipts2
        .iter()
        .map(|r| r["id"].as_str().expect("receipt id"))
        .collect();
    for id in &ids1 {
        assert!(
            !ids2.contains(id),
            "receipt {id} appeared on both page 1 and page 2"
        );
    }

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// totalCount reflects the full filtered set, not just the page size.
#[test]
fn test_receipt_query_total_count() {
    let setup = setup_with_receipts("chio-rq-total-count");

    // Fetch only 1 receipt but total should be 5.
    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(receipts.len(), 1, "only 1 receipt on this page");
    assert_eq!(total_count, 5, "totalCount should reflect full set of 5");

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// Request without Authorization header returns 401.
#[test]
fn test_receipt_query_requires_auth() {
    let setup = setup_with_receipts("chio-rq-auth");

    // No Authorization header.
    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .send()
        .expect("send request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "request without auth should return 401"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

// --- Lineage helper ---

/// Build a minimal CapabilityToken for test lineage insertion.
fn make_capability_token(
    id: &str,
    subject_keypair: &Keypair,
    issuer_keypair: &Keypair,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer_keypair.public_key(),
        subject: subject_keypair.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 9999999999,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, issuer_keypair).expect("sign capability token")
}

/// Pre-populate the capability_lineage table before the service starts.
fn prepopulate_lineage(db_path: &PathBuf, entries: &[(&CapabilityToken, Option<&str>)]) {
    let store = SqliteReceiptStore::open(db_path).expect("open receipt store for lineage");
    for (token, parent_id) in entries {
        store
            .record_capability_snapshot(token, *parent_id)
            .expect("record_capability_snapshot");
    }
}

// --- Lineage endpoint tests ---

/// GET /v1/lineage/:capability_id returns 200 with matching snapshot fields.
#[test]
fn test_lineage_get_capability_snapshot() {
    let dir = unique_dir("chio-lineage-get");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let token = make_capability_token("cap-lineage-1", &subject_kp, &issuer_kp);
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    prepopulate_lineage(&receipt_db_path, &[(&token, None)]);

    let listen = reserve_listen_addr();
    let service_token = "lineage-get-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/lineage/cap-lineage-1"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send lineage request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for lineage GET"
    );
    let body: serde_json::Value = response.json().expect("parse lineage json");
    assert_eq!(
        body["capability_id"].as_str().expect("capability_id"),
        "cap-lineage-1"
    );
    assert_eq!(
        body["subject_key"].as_str().expect("subject_key"),
        subject_hex
    );
    assert_eq!(body["issuer_key"].as_str().expect("issuer_key"), issuer_hex);
    assert_eq!(
        body["delegation_depth"].as_u64().expect("delegation_depth"),
        0
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/lineage/:capability_id/chain returns root-first delegation chain.
#[test]
fn test_lineage_get_delegation_chain() {
    let dir = unique_dir("chio-lineage-chain");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let subj_kp = Keypair::generate();

    // 3-level chain: root -> parent -> child
    let root = make_capability_token("chain-root", &subj_kp, &issuer_kp);
    let parent = make_capability_token("chain-parent", &subj_kp, &issuer_kp);
    let child = make_capability_token("chain-child", &subj_kp, &issuer_kp);

    prepopulate_lineage(
        &receipt_db_path,
        &[
            (&root, None),
            (&parent, Some("chain-root")),
            (&child, Some("chain-parent")),
        ],
    );

    let listen = reserve_listen_addr();
    let service_token = "chain-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/lineage/chain-child/chain"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send chain request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for chain GET"
    );
    let chain: Vec<serde_json::Value> = response.json().expect("parse chain json");
    assert_eq!(chain.len(), 3, "chain should have 3 entries");

    // Root-first ordering: delegation_depth 0, 1, 2
    assert_eq!(
        chain[0]["capability_id"].as_str().expect("id"),
        "chain-root"
    );
    assert_eq!(chain[0]["delegation_depth"].as_u64().expect("depth"), 0);
    assert_eq!(
        chain[1]["capability_id"].as_str().expect("id"),
        "chain-parent"
    );
    assert_eq!(chain[1]["delegation_depth"].as_u64().expect("depth"), 1);
    assert_eq!(
        chain[2]["capability_id"].as_str().expect("id"),
        "chain-child"
    );
    assert_eq!(chain[2]["delegation_depth"].as_u64().expect("depth"), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/lineage/:capability_id returns 404 for unknown capability_id.
#[test]
fn test_lineage_not_found() {
    let setup = setup_with_receipts("chio-lineage-404");

    let response = setup
        .client
        .get(format!("{}/v1/lineage/nonexistent-cap-id", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send lineage 404 request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown capability_id should return 404"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/lineage/:capability_id requires Authorization header.
#[test]
fn test_lineage_requires_auth() {
    let setup = setup_with_receipts("chio-lineage-auth");

    let response = setup
        .client
        .get(format!("{}/v1/lineage/any-cap-id", setup.base_url))
        .send()
        .expect("send unauthenticated lineage request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "lineage endpoint without auth should return 401"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/receipts/query?agentSubject=<hex> filters receipts by agent subject.
#[test]
fn test_agent_subject_filter_via_http() {
    let dir = unique_dir("chio-agent-filter");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let agent1_kp = Keypair::generate();
    let agent2_kp = Keypair::generate();
    let agent1_hex = agent1_kp.public_key().to_hex();

    // Two capability tokens, one per agent
    let cap1 = make_capability_token("cap-agent1", &agent1_kp, &issuer_kp);
    let cap2 = make_capability_token("cap-agent2", &agent2_kp, &issuer_kp);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&cap1, None)
            .expect("record cap1");
        store
            .record_capability_snapshot(&cap2, None)
            .expect("record cap2");

        // 2 receipts for agent1, 1 for agent2
        store
            .append_chio_receipt(&make_receipt(
                "ra-1",
                "cap-agent1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "ra-2",
                "cap-agent1",
                "files",
                "read",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "ra-3",
                "cap-agent2",
                "shell",
                "bash",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "agent-filter-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("agentSubject", agent1_hex.as_str())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send agent filter request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for agent filter"
    );
    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(
        receipts.len(),
        2,
        "only agent1's 2 receipts should be returned"
    );
    for r in receipts {
        assert_eq!(
            r["capability_id"].as_str().expect("capability_id"),
            "cap-agent1",
            "all returned receipts must belong to agent1"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/agents/:subject_key/receipts returns receipts for the given agent.
#[test]
fn test_agent_receipts_endpoint() {
    let dir = unique_dir("chio-agent-receipts");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let agent1_kp = Keypair::generate();
    let agent2_kp = Keypair::generate();
    let agent1_hex = agent1_kp.public_key().to_hex();

    let cap1 = make_capability_token("cap-ar-agent1", &agent1_kp, &issuer_kp);
    let cap2 = make_capability_token("cap-ar-agent2", &agent2_kp, &issuer_kp);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&cap1, None)
            .expect("record cap1");
        store
            .record_capability_snapshot(&cap2, None)
            .expect("record cap2");

        store
            .append_chio_receipt(&make_receipt(
                "rb-1",
                "cap-ar-agent1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "rb-2",
                "cap-ar-agent1",
                "files",
                "read",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "rb-3",
                "cap-ar-agent2",
                "shell",
                "bash",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "agent-receipts-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/agents/{agent1_hex}/receipts"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send agent receipts request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for agent receipts"
    );
    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(
        receipts.len(),
        2,
        "only agent1's 2 receipts should be returned"
    );
    for r in receipts {
        assert_eq!(
            r["capability_id"].as_str().expect("capability_id"),
            "cap-ar-agent1",
            "all returned receipts must belong to agent1"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/receipts/analytics returns aggregate metrics over the receipt corpus.
#[test]
fn test_receipt_analytics_endpoint() {
    let setup = setup_with_receipts("chio-receipt-analytics");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/analytics", setup.base_url))
        .query(&[("timeBucket", "day"), ("groupLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send analytics request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for analytics"
    );
    let body: serde_json::Value = response.json().expect("parse analytics json");
    assert_eq!(body["summary"]["totalReceipts"].as_u64(), Some(5));
    assert_eq!(body["summary"]["allowCount"].as_u64(), Some(4));
    assert_eq!(body["summary"]["denyCount"].as_u64(), Some(1));

    let by_tool = body["byTool"].as_array().expect("byTool array");
    assert!(
        by_tool.iter().any(|row| {
            row["toolServer"].as_str() == Some("shell")
                && row["toolName"].as_str() == Some("bash")
                && row["metrics"]["totalReceipts"].as_u64() == Some(4)
        }),
        "shell/bash aggregate should be present"
    );

    let by_time = body["byTime"].as_array().expect("byTime array");
    assert_eq!(
        by_time.len(),
        1,
        "all fixture receipts fall into one day bucket"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/reports/cost-attribution returns multi-hop delegation attribution with
/// root/leaf aggregation and lineage-complete chains.
#[test]
fn test_cost_attribution_report_endpoint() {
    let dir = unique_dir("chio-cost-attribution");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let root = make_capability_token("cap-cost-root", &root_kp, &issuer_kp);
    let child = make_capability_token("cap-cost-child", &leaf_kp, &issuer_kp);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root");
        store
            .record_capability_snapshot(&child, Some("cap-cost-root"))
            .expect("record child");

        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-cost-1",
                "cap-cost-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                2_000,
                150,
                None,
                &root_hex,
                1,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-cost-2",
                "cap-cost-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                2_001,
                0,
                Some(50),
                &root_hex,
                1,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "cost-attribution-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/cost-attribution"))
        .query(&[
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("limit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send cost attribution request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for cost attribution report"
    );
    let body: serde_json::Value = response.json().expect("parse cost attribution json");
    assert_eq!(body["summary"]["matchingReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["returnedReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["totalCostCharged"].as_u64(), Some(150));
    assert_eq!(body["summary"]["totalAttemptedCost"].as_u64(), Some(50));
    assert_eq!(body["summary"]["lineageGapCount"].as_u64(), Some(0));

    let by_root = body["byRoot"].as_array().expect("byRoot array");
    assert_eq!(by_root.len(), 1);
    assert_eq!(
        by_root[0]["rootSubjectKey"].as_str(),
        Some(root_hex.as_str())
    );
    assert_eq!(by_root[0]["receiptCount"].as_u64(), Some(2));

    let by_leaf = body["byLeaf"].as_array().expect("byLeaf array");
    assert_eq!(by_leaf.len(), 1);
    assert_eq!(
        by_leaf[0]["rootSubjectKey"].as_str(),
        Some(root_hex.as_str())
    );
    assert_eq!(
        by_leaf[0]["leafSubjectKey"].as_str(),
        Some(leaf_hex.as_str())
    );
    assert_eq!(by_leaf[0]["totalCostCharged"].as_u64(), Some(150));
    assert_eq!(by_leaf[0]["totalAttemptedCost"].as_u64(), Some(50));

    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(receipts.len(), 2);
    assert!(receipts
        .iter()
        .all(|row| row["lineageComplete"].as_bool() == Some(true)));
    assert!(receipts.iter().all(|row| row["chain"]
        .as_array()
        .map_or(false, |chain| chain.len() == 2)));

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/reports/operator composes activity, budget pressure, and compliance readiness.
#[test]
fn test_operator_report_endpoint() {
    let dir = unique_dir("chio-operator-report");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-op-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_000,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign root capability");
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-op-child".to_string(),
            issuer: issuer_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope,
            issued_at: 1_100,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign child capability");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root lineage");
        store
            .record_capability_snapshot(&child, Some("cap-op-root"))
            .expect("record child lineage");

        let seq = store
            .append_chio_receipt_returning_seq(&make_financial_receipt(
                "rc-op-1",
                "cap-op-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                3_000,
                850,
                None,
                &root_hex,
                1,
            ))
            .expect("append checkpointed receipt");
        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-op-2",
                "cap-op-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                3_001,
                0,
                Some(100),
                &root_hex,
                1,
            ))
            .expect("append uncheckpointed receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        budgets
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-op-child".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 3_100,
                seq: 1,
                total_cost_exposed: 850,
                total_cost_realized_spend: 0,
            })
            .expect("upsert budget usage");
    }

    let listen = reserve_listen_addr();
    let service_token = "operator-report-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("agentSubject", leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("budgetLimit", "10"),
            ("attributionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for operator report"
    );
    let body: serde_json::Value = response.json().expect("parse operator report json");

    assert_eq!(
        body["activity"]["summary"]["totalReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(body["activity"]["summary"]["allowCount"].as_u64(), Some(1));
    assert_eq!(body["activity"]["summary"]["denyCount"].as_u64(), Some(1));
    assert_eq!(
        body["budgetUtilization"]["summary"]["matchingGrants"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["budgetUtilization"]["summary"]["nearLimitCount"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["toolServer"].as_str(),
        Some("shell")
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["toolName"].as_str(),
        Some("bash")
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["remainingCostUnits"].as_u64(),
        Some(150)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["invocations"]["limit"].as_u64(),
        Some(5)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["invocations"]["remaining"].as_u64(),
        Some(3)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["money"]["limit"].as_u64(),
        Some(1000)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["dimensions"]["money"]["remaining"].as_u64(),
        Some(150)
    );
    assert_eq!(
        body["compliance"]["evidenceReadyReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["compliance"]["uncheckpointedReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["compliance"]["pendingSettlementReceipts"].as_u64(),
        Some(0)
    );
    assert_eq!(
        body["compliance"]["failedSettlementReceipts"].as_u64(),
        Some(0)
    );
    assert_eq!(
        body["compliance"]["directEvidenceExportSupported"].as_bool(),
        Some(false)
    );
    assert_eq!(
        body["compliance"]["childReceiptScope"].as_str(),
        Some("omitted_no_join_path")
    );
    assert!(body["compliance"]["exportScopeNote"]
        .as_str()
        .expect("export scope note")
        .contains("tool filters narrow the operator report only"));
    assert_eq!(
        body["settlementReconciliation"]["summary"]["matchingReceipts"].as_u64(),
        Some(0)
    );
    let attribution_row = body["costAttribution"]["receipts"]
        .as_array()
        .expect("cost attribution receipts")
        .iter()
        .find(|row| row["receiptId"] == "rc-op-1")
        .expect("operator attribution row");
    assert_eq!(
        attribution_row["budgetAuthority"]["guarantee_level"].as_str(),
        Some("ha_quorum_commit")
    );
    assert_eq!(
        attribution_row["budgetAuthority"]["hold_id"].as_str(),
        Some("budget-hold:rc-op-1:capability:0")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_settlement_reconciliation_report_and_action_endpoint() {
    let dir = unique_dir("chio-settlement-reconciliation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_financial_receipt_with_settlement_status(
                "rc-settle-pending",
                "cap-settlement-1",
                "payments",
                "checkout",
                4_000,
                125,
                SettlementStatus::Pending,
                Some("hold-pending-1"),
            ))
            .expect("append pending settlement receipt");
        store
            .append_chio_receipt(&make_financial_receipt_with_settlement_status(
                "rc-settle-failed",
                "cap-settlement-1",
                "payments",
                "checkout",
                4_001,
                200,
                SettlementStatus::Failed,
                Some("hold-failed-1"),
            ))
            .expect("append failed settlement receipt");
        store
            .append_chio_receipt(&make_financial_receipt_with_settlement_status(
                "rc-settle-settled",
                "cap-settlement-1",
                "payments",
                "checkout",
                4_002,
                250,
                SettlementStatus::Settled,
                Some("hold-settled-1"),
            ))
            .expect("append settled receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "settlement-report-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let initial = client
        .get(format!("{base_url}/v1/reports/settlements"))
        .query(&[
            ("capabilityId", "cap-settlement-1"),
            ("settlementLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send settlement report request");

    assert_eq!(initial.status(), reqwest::StatusCode::OK);
    let initial_body: serde_json::Value = initial.json().expect("parse initial report");
    assert_eq!(
        initial_body["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(initial_body["summary"]["pendingReceipts"].as_u64(), Some(1));
    assert_eq!(initial_body["summary"]["failedReceipts"].as_u64(), Some(1));
    assert_eq!(
        initial_body["summary"]["actionableReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        initial_body["receipts"][0]["reconciliationState"].as_str(),
        Some("open")
    );

    let reconcile = client
        .post(format!("{base_url}/v1/settlements/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": "rc-settle-pending",
            "reconciliationState": "reconciled",
            "note": "confirmed externally"
        }))
        .send()
        .expect("send settlement reconciliation update");

    assert_eq!(reconcile.status(), reqwest::StatusCode::OK);
    let reconcile_body: serde_json::Value = reconcile.json().expect("parse reconcile response");
    assert_eq!(reconcile_body["receiptId"], "rc-settle-pending");
    assert_eq!(reconcile_body["reconciliationState"], "reconciled");
    assert_eq!(reconcile_body["note"], "confirmed externally");
    assert!(reconcile_body["updatedAt"].as_u64().is_some());

    let updated = client
        .get(format!("{base_url}/v1/reports/settlements"))
        .query(&[
            ("capabilityId", "cap-settlement-1"),
            ("settlementLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send updated settlement report request");

    assert_eq!(updated.status(), reqwest::StatusCode::OK);
    let updated_body: serde_json::Value = updated.json().expect("parse updated report");
    assert_eq!(
        updated_body["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["actionableReceipts"].as_u64(),
        Some(1)
    );
    let reconciled_row = updated_body["receipts"]
        .as_array()
        .expect("settlement receipts array")
        .iter()
        .find(|row| row["receiptId"] == "rc-settle-pending")
        .expect("pending receipt should still be present");
    assert_eq!(reconciled_row["reconciliationState"], "reconciled");
    assert_eq!(reconciled_row["note"], "confirmed externally");
    assert_eq!(
        reconciled_row["budgetAuthority"]["guarantee_level"].as_str(),
        Some("ha_quorum_commit")
    );
    assert_eq!(
        reconciled_row["budgetAuthority"]["hold_id"].as_str(),
        Some("budget-hold:rc-settle-pending:capability:0")
    );

    let operator = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("capabilityId", "cap-settlement-1"),
            ("settlementLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");

    assert_eq!(operator.status(), reqwest::StatusCode::OK);
    let operator_body: serde_json::Value = operator.json().expect("parse operator report");
    assert_eq!(
        operator_body["settlementReconciliation"]["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["settlementReconciliation"]["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_metered_billing_reconciliation_report_and_action_endpoint() {
    let dir = unique_dir("chio-metered-billing-reconciliation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-metered-1",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&make_governed_receipt(
                "rc-metered-1",
                "cap-metered-1",
                "shell",
                "bash",
                6_000,
            ))
            .expect("append first metered governed receipt");
        store
            .append_chio_receipt(&make_governed_receipt(
                "rc-metered-2",
                "cap-metered-1",
                "shell",
                "bash",
                6_001,
            ))
            .expect("append second metered governed receipt");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "rc-metered-non-governed",
                "cap-metered-2",
                "shell",
                "bash",
                6_002,
            ))
            .expect("append non-metered governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "metered-billing-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let initial = client
        .get(format!("{base_url}/v1/reports/metered-billing"))
        .query(&[("capabilityId", "cap-metered-1"), ("meteredLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send metered billing report request");
    let initial_status = initial.status();
    let initial_text = initial.text().expect("read initial metered report body");
    assert_eq!(
        initial_status,
        reqwest::StatusCode::OK,
        "metered billing report body: {initial_text}"
    );
    let initial_body: serde_json::Value =
        serde_json::from_str(&initial_text).expect("parse initial metered report");
    assert_eq!(
        initial_body["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        initial_body["summary"]["missingEvidenceReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        initial_body["summary"]["actionableReceipts"].as_u64(),
        Some(2)
    );

    let reconcile = client
        .post(format!("{base_url}/v1/metered-billing/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": "rc-metered-1",
            "adapterKind": "manual_meter",
            "evidenceId": "usage-chio-1",
            "observedUnits": 17,
            "billedCost": {
                "units": 4200,
                "currency": "USD"
            },
            "evidenceSha256": "sha256-metered-1",
            "recordedAt": 6100,
            "reconciliationState": "reconciled",
            "note": "approved quote overrun after review"
        }))
        .send()
        .expect("send metered billing reconciliation update");

    assert_eq!(reconcile.status(), reqwest::StatusCode::OK);
    let reconcile_body: serde_json::Value = reconcile.json().expect("parse metered response");
    assert_eq!(reconcile_body["receiptId"], "rc-metered-1");
    assert_eq!(reconcile_body["reconciliationState"], "reconciled");
    assert_eq!(
        reconcile_body["evidence"]["usageEvidence"]["evidenceKind"],
        "manual_meter"
    );
    assert_eq!(
        reconcile_body["evidence"]["usageEvidence"]["observedUnits"],
        17
    );
    assert_eq!(reconcile_body["evidence"]["billedCost"]["units"], 4200);

    let replay = client
        .post(format!("{base_url}/v1/metered-billing/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": "rc-metered-2",
            "adapterKind": "manual_meter",
            "evidenceId": "usage-chio-1",
            "observedUnits": 10,
            "billedCost": {
                "units": 3200,
                "currency": "USD"
            },
            "recordedAt": 6101,
            "reconciliationState": "open"
        }))
        .send()
        .expect("send replay metered billing update");
    assert_eq!(replay.status(), reqwest::StatusCode::CONFLICT);

    let non_metered = client
        .post(format!("{base_url}/v1/metered-billing/reconcile"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "receiptId": "rc-metered-non-governed",
            "adapterKind": "manual_meter",
            "evidenceId": "usage-chio-2",
            "observedUnits": 8,
            "billedCost": {
                "units": 4200,
                "currency": "USD"
            },
            "recordedAt": 6102,
            "reconciliationState": "open"
        }))
        .send()
        .expect("send non-metered reconciliation update");
    assert_eq!(non_metered.status(), reqwest::StatusCode::CONFLICT);

    let updated = client
        .get(format!("{base_url}/v1/reports/metered-billing"))
        .query(&[("capabilityId", "cap-metered-1"), ("meteredLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send updated metered billing report request");
    assert_eq!(updated.status(), reqwest::StatusCode::OK);
    let updated_body: serde_json::Value = updated.json().expect("parse updated metered report");
    assert_eq!(
        updated_body["summary"]["evidenceAttachedReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["missingEvidenceReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["overQuotedUnitsReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["overQuotedCostReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        updated_body["summary"]["actionableReceipts"].as_u64(),
        Some(1)
    );
    let reconciled_row = updated_body["receipts"]
        .as_array()
        .expect("metered billing receipts array")
        .iter()
        .find(|row| row["receiptId"] == "rc-metered-1")
        .expect("first metered receipt row");
    assert_eq!(
        reconciled_row["evidence"]["usageEvidence"]["evidenceId"],
        "usage-chio-1"
    );
    assert_eq!(reconciled_row["evidenceMissing"], false);
    assert_eq!(reconciled_row["exceedsQuotedUnits"], true);
    assert_eq!(reconciled_row["exceedsQuotedCost"], true);
    assert_eq!(reconciled_row["financialMismatch"], false);
    assert_eq!(reconciled_row["actionRequired"], false);

    let operator = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[("capabilityId", "cap-metered-1"), ("meteredLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");
    let operator_status = operator.status();
    let operator_body_text = operator.text().expect("read operator report body");
    assert_eq!(
        operator_status,
        reqwest::StatusCode::OK,
        "operator report body: {operator_body_text}"
    );
    let operator_body: serde_json::Value =
        serde_json::from_str(&operator_body_text).expect("parse operator report");
    assert_eq!(
        operator_body["meteredBillingReconciliation"]["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["meteredBillingReconciliation"]["summary"]["reconciledReceipts"].as_u64(),
        Some(1)
    );

    let feed = client
        .get(format!("{base_url}/v1/reports/behavioral-feed"))
        .query(&[
            ("capabilityId", "cap-metered-1"),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("receiptLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send behavioral feed request");
    assert_eq!(feed.status(), reqwest::StatusCode::OK);
    let feed: SignedBehavioralFeed = feed.json().expect("parse signed behavioral feed");
    assert!(feed
        .verify_signature()
        .expect("verify metered behavioral feed signature"));
    assert_eq!(feed.body.metered_billing.metered_receipts, 2);
    assert_eq!(feed.body.metered_billing.evidence_attached_receipts, 1);
    assert_eq!(feed.body.metered_billing.missing_evidence_receipts, 1);
    let metered_feed_row = feed
        .body
        .receipts
        .iter()
        .find(|row| row.receipt_id == "rc-metered-1")
        .expect("metered feed row");
    assert!(metered_feed_row.governed.is_some());
    assert_eq!(
        metered_feed_row
            .governed
            .as_ref()
            .expect("governed metadata")
            .metered_billing
            .as_ref()
            .expect("metered billing metadata")
            .usage_evidence,
        None
    );
    assert_eq!(
        metered_feed_row
            .metered_reconciliation
            .as_ref()
            .expect("metered reconciliation row")
            .evidence
            .as_ref()
            .expect("evidence")
            .usage_evidence
            .evidence_id,
        "usage-chio-1"
    );

    let receipt_query = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("capabilityId", "cap-metered-1"), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send receipt query request");
    assert_eq!(receipt_query.status(), reqwest::StatusCode::OK);
    let receipt_query_body: serde_json::Value =
        receipt_query.json().expect("parse receipt query response");
    let queried_receipt = receipt_query_body["receipts"]
        .as_array()
        .expect("receipts array")
        .iter()
        .find(|row| row["id"] == "rc-metered-1")
        .expect("queried metered receipt");
    assert!(
        queried_receipt["metadata"]["governed_transaction"]["metered_billing"]["usageEvidence"]
            .is_null()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_and_cli() {
    let dir = unique_dir("chio-authorization-context");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-1",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-auth-1",
                "cap-auth-1",
                &subject_hex,
                &issuer_hex,
                "shell",
                "bash",
                7_000,
            ))
            .expect("append authorization receipt");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "rc-auth-2",
                "cap-auth-1",
                "shell",
                "bash",
                7_001,
            ))
            .expect("append second governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[("capabilityId", "cap-auth-1"), ("authorizationLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization context request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().expect("parse authorization context report");
    assert_eq!(
        body["schema"].as_str(),
        Some("chio.oauth.authorization-context-report.v1")
    );
    assert_eq!(
        body["profile"]["schema"].as_str(),
        Some("chio.oauth.authorization-profile.v1")
    );
    assert_eq!(body["profile"]["id"].as_str(), Some("chio-governed-rar-v1"));
    assert_eq!(
        body["profile"]["authoritativeSource"].as_str(),
        Some("governed_receipt_projection")
    );
    assert_eq!(
        body["profile"]["unsupportedShapesFailClosed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        body["profile"]["portableIdentityBinding"]["portableSubjectClaim"].as_str(),
        Some("sub")
    );
    assert_eq!(
        body["profile"]["portableIdentityBinding"]["chioIssuerProvenanceClaim"].as_str(),
        Some("chio_issuer_dids")
    );
    assert_eq!(
        body["profile"]["governedAuthBinding"]["authoritativeSource"].as_str(),
        Some("metadata.governed_transaction")
    );
    assert!(
        body["profile"]["portableClaimCatalog"]["selectivelyDisclosableClaims"]
            .as_array()
            .expect("portable claim catalog")
            .iter()
            .any(|value| value.as_str() == Some("chio_issuer_dids"))
    );
    assert_eq!(body["summary"]["matchingReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["approvalReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["approvedReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["commerceReceipts"].as_u64(), Some(1));
    assert_eq!(body["summary"]["meteredBillingReceipts"].as_u64(), Some(1));
    assert_eq!(
        body["summary"]["runtimeAssuranceReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(body["summary"]["callChainReceipts"].as_u64(), Some(1));
    assert_eq!(body["summary"]["maxAmountReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["senderBoundReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["dpopBoundReceipts"].as_u64(), Some(2));
    assert_eq!(
        body["summary"]["runtimeAssuranceBoundReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["summary"]["delegatedSenderBoundReceipts"].as_u64(),
        Some(0)
    );

    let auth_row = body["receipts"]
        .as_array()
        .expect("authorization receipts array")
        .iter()
        .find(|row| row["receiptId"] == "rc-auth-1")
        .expect("authorization receipt row");
    let detail_types = auth_row["authorizationDetails"]
        .as_array()
        .expect("authorization details")
        .iter()
        .map(|detail| detail["type"].as_str().expect("detail type"))
        .collect::<Vec<_>>();
    assert!(detail_types.contains(&"chio_governed_tool"));
    assert!(detail_types.contains(&"chio_governed_commerce"));
    assert!(detail_types.contains(&"chio_governed_metered_billing"));
    assert_eq!(
        auth_row["transactionContext"]["approvalTokenId"].as_str(),
        Some("approval-auth-1")
    );
    assert_eq!(
        auth_row["transactionContext"]["runtimeAssuranceTier"].as_str(),
        Some("verified")
    );
    assert_eq!(
        auth_row["transactionContext"]["runtimeAssuranceSchema"].as_str(),
        Some("chio.runtime-attestation.azure-maa.jwt.v1")
    );
    assert_eq!(
        auth_row["transactionContext"]["runtimeAssuranceVerifierFamily"].as_str(),
        Some("azure_maa")
    );
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["chainId"].as_str(),
        Some("chain-ext-1")
    );
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["parentReceiptId"].as_str(),
        Some("rcpt-upstream-1")
    );
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["evidenceClass"].as_str(),
        Some("asserted")
    );
    assert_eq!(
        auth_row["senderConstraint"]["subjectKey"].as_str(),
        Some(subject_hex.as_str())
    );
    assert_eq!(
        auth_row["senderConstraint"]["subjectKeySource"].as_str(),
        Some("receipt_attribution")
    );
    assert_eq!(
        auth_row["senderConstraint"]["issuerKey"].as_str(),
        Some(issuer_hex.as_str())
    );
    assert_eq!(
        auth_row["senderConstraint"]["issuerKeySource"].as_str(),
        Some("receipt_attribution")
    );
    assert_eq!(
        auth_row["senderConstraint"]["matchedGrantIndex"].as_u64(),
        Some(0)
    );
    assert_eq!(
        auth_row["senderConstraint"]["proofRequired"].as_bool(),
        Some(true)
    );
    assert_eq!(
        auth_row["senderConstraint"]["proofType"].as_str(),
        Some("chio_dpop_v1")
    );
    assert_eq!(
        auth_row["senderConstraint"]["proofSchema"].as_str(),
        Some("chio.dpop_proof.v1")
    );
    assert_eq!(
        auth_row["senderConstraint"]["runtimeAssuranceBound"].as_bool(),
        Some(true)
    );
    assert_eq!(
        auth_row["senderConstraint"]["delegatedCallChainBound"].as_bool(),
        Some(false)
    );

    let operator = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[("capabilityId", "cap-auth-1"), ("authorizationLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");
    assert_eq!(operator.status(), reqwest::StatusCode::OK);
    let operator_body: serde_json::Value = operator.json().expect("parse operator report");
    assert_eq!(
        operator_body["authorizationContext"]["summary"]["callChainReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        operator_body["authorizationContext"]["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "authorization-context",
            "list",
            "--capability",
            "cap-auth-1",
            "--limit",
            "10",
        ])
        .output()
        .expect("run authorization-context CLI");
    assert!(
        cli_output.status.success(),
        "authorization-context CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: AuthorizationContextReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse authorization CLI json");
    assert_eq!(
        cli_report.schema,
        "chio.oauth.authorization-context-report.v1"
    );
    assert_eq!(cli_report.profile.id, "chio-governed-rar-v1");
    assert_eq!(
        cli_report
            .profile
            .sender_constraints
            .subject_binding
            .as_str(),
        "capability_subject"
    );
    assert_eq!(cli_report.summary.matching_receipts, 2);
    assert_eq!(cli_report.summary.sender_bound_receipts, 2);
    assert_eq!(cli_report.summary.dpop_bound_receipts, 2);
    let cli_row = cli_report
        .receipts
        .iter()
        .find(|row| row.receipt_id == "rc-auth-1")
        .expect("authorization CLI row");
    assert_eq!(
        cli_row
            .transaction_context
            .runtime_assurance_schema
            .as_deref(),
        Some("chio.runtime-attestation.azure-maa.jwt.v1")
    );
    assert_eq!(
        cli_row
            .transaction_context
            .runtime_assurance_verifier_family,
        Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa)
    );
    assert_eq!(
        cli_row
            .transaction_context
            .call_chain
            .as_ref()
            .expect("call chain")
            .chain_id,
        "chain-ext-1"
    );
    assert!(cli_row.sender_constraint.proof_required);
    assert_eq!(
        cli_row.sender_constraint.proof_type.as_deref(),
        Some("chio_dpop_v1")
    );
    assert_eq!(cli_row.sender_constraint.issuer_key, issuer_hex);
    assert_eq!(
        cli_row.sender_constraint.issuer_key_source.as_str(),
        "receipt_attribution"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn authorization_context_report_does_not_mark_asserted_call_chain_as_sender_bound() {
    let dir = unique_dir("chio-authorization-context-asserted-call-chain");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-asserted",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-auth-asserted",
                "cap-auth-asserted",
                &subject_hex,
                &issuer_hex,
                "shell",
                "bash",
                7_050,
            ))
            .expect("append asserted authorization receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-asserted-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-asserted"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization context request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().expect("parse authorization context report");
    assert_eq!(body["summary"]["matchingReceipts"].as_u64(), Some(1));
    assert_eq!(
        body["summary"]["delegatedSenderBoundReceipts"].as_u64(),
        Some(0)
    );
    let auth_row = body["receipts"]
        .as_array()
        .expect("authorization receipts array")
        .iter()
        .find(|row| row["receiptId"] == "rc-auth-asserted")
        .expect("asserted authorization receipt row");
    assert_eq!(
        auth_row["transactionContext"]["callChain"]["evidenceClass"].as_str(),
        Some("asserted")
    );
    assert_eq!(
        auth_row["senderConstraint"]["delegatedCallChainBound"].as_bool(),
        Some(false)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_metadata_and_review_pack_surfaces() {
    let dir = unique_dir("chio-authorization-review-pack");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-pack-1",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-auth-pack-1",
                "cap-auth-pack-1",
                &subject_hex,
                &issuer_hex,
                "shell",
                "bash",
                7_100,
            ))
            .expect("append authorization receipt");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "rc-auth-pack-2",
                "cap-auth-pack-1",
                "shell",
                "bash",
                7_101,
            ))
            .expect("append second governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-review-pack-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let metadata_response = client
        .get(format!(
            "{base_url}/v1/reports/authorization-profile-metadata"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization profile metadata request");
    assert_eq!(metadata_response.status(), reqwest::StatusCode::OK);
    let metadata_body: serde_json::Value = metadata_response
        .json()
        .expect("parse authorization profile metadata response");
    assert_eq!(
        metadata_body["schema"].as_str(),
        Some("chio.oauth.authorization-metadata.v1")
    );
    assert_eq!(
        metadata_body["profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );
    assert_eq!(
        metadata_body["reportSchema"].as_str(),
        Some("chio.oauth.authorization-context-report.v1")
    );
    assert_eq!(
        metadata_body["discovery"]["discoveryInformationalOnly"].as_bool(),
        Some(true)
    );
    assert!(metadata_body["discovery"]["protectedResourceMetadataPaths"]
        .as_array()
        .expect("protected resource metadata paths")
        .iter()
        .any(|value| value.as_str() == Some("/.well-known/oauth-protected-resource/mcp")));
    assert_eq!(
        metadata_body["supportBoundary"]["senderConstrainedProjection"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["supportBoundary"]["hostedRequestTimeAuthorizationSupported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["supportBoundary"]["resourceIndicatorBindingSupported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["supportBoundary"]["reviewerEvidenceRuntimeAuthorizationSupported"].as_bool(),
        Some(false)
    );
    assert!(metadata_body["exampleMapping"]["senderConstraintFields"]
        .as_array()
        .expect("sender constraint field list")
        .iter()
        .any(|value| value.as_str() == Some("subjectKey")));
    assert!(metadata_body["exampleMapping"]["senderConstraintFields"]
        .as_array()
        .expect("sender constraint field list")
        .iter()
        .any(|value| value.as_str() == Some("issuerKey")));
    assert!(metadata_body["exampleMapping"]["transactionContextFields"]
        .as_array()
        .expect("transaction context field list")
        .iter()
        .any(|value| value.as_str() == Some("runtimeAssuranceSchema")));
    assert!(metadata_body["exampleMapping"]["transactionContextFields"]
        .as_array()
        .expect("transaction context field list")
        .iter()
        .any(|value| value.as_str() == Some("runtimeAssuranceVerifierFamily")));
    assert_eq!(
        metadata_body["profile"]["portableIdentityBinding"]["chioProvenanceAnchor"].as_str(),
        Some("did:chio")
    );
    assert_eq!(
        metadata_body["profile"]["governedAuthBinding"]["authoritativeSource"].as_str(),
        Some("metadata.governed_transaction")
    );
    assert_eq!(
        metadata_body["profile"]["requestTimeContract"]["authorizationDetailsParameter"].as_str(),
        Some("authorization_details")
    );
    assert_eq!(
        metadata_body["profile"]["resourceBinding"]["requestResourceMustMatchProtectedResource"]
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        metadata_body["profile"]["artifactBoundary"]["approvalTokensRuntimeAdmissionSupported"]
            .as_bool(),
        Some(false)
    );

    let review_pack_response = client
        .get(format!("{base_url}/v1/reports/authorization-review-pack"))
        .query(&[
            ("capabilityId", "cap-auth-pack-1"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send authorization review pack request");
    assert_eq!(review_pack_response.status(), reqwest::StatusCode::OK);
    let review_pack_body: serde_json::Value = review_pack_response
        .json()
        .expect("parse authorization review pack response");
    assert_eq!(
        review_pack_body["schema"].as_str(),
        Some("chio.oauth.authorization-review-pack.v1")
    );
    assert_eq!(
        review_pack_body["summary"]["matchingReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        review_pack_body["summary"]["returnedReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        review_pack_body["summary"]["dpopRequiredReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        review_pack_body["summary"]["runtimeAssuranceReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        review_pack_body["summary"]["delegatedCallChainReceipts"].as_u64(),
        Some(1)
    );
    let review_record = review_pack_body["records"]
        .as_array()
        .expect("authorization review pack records")
        .iter()
        .find(|row| row["receiptId"] == "rc-auth-pack-1")
        .expect("review-pack record for first governed receipt");
    assert_eq!(
        review_record["authorizationContext"]["senderConstraint"]["subjectKey"].as_str(),
        Some(subject_hex.as_str())
    );
    assert_eq!(
        review_record["authorizationContext"]["senderConstraint"]["issuerKey"].as_str(),
        Some(issuer_hex.as_str())
    );
    assert_eq!(
        review_record["governedTransaction"]["intent_id"].as_str(),
        Some("intent-auth-1")
    );
    assert_eq!(
        review_record["signedReceipt"]["id"].as_str(),
        Some("rc-auth-pack-1")
    );

    let cli_metadata_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "authorization-context",
            "metadata",
        ])
        .output()
        .expect("run authorization metadata CLI");
    assert!(
        cli_metadata_output.status.success(),
        "authorization metadata CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_metadata_output.stdout),
        String::from_utf8_lossy(&cli_metadata_output.stderr)
    );
    let cli_metadata_body: serde_json::Value = serde_json::from_slice(&cli_metadata_output.stdout)
        .expect("parse authorization metadata CLI json");
    assert_eq!(
        cli_metadata_body["schema"].as_str(),
        Some("chio.oauth.authorization-metadata.v1")
    );
    assert_eq!(
        cli_metadata_body["profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );

    let cli_review_pack_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "authorization-context",
            "review-pack",
            "--capability",
            "cap-auth-pack-1",
            "--limit",
            "10",
        ])
        .output()
        .expect("run authorization review-pack CLI");
    assert!(
        cli_review_pack_output.status.success(),
        "authorization review-pack CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_review_pack_output.stdout),
        String::from_utf8_lossy(&cli_review_pack_output.stderr)
    );
    let cli_review_pack_body: serde_json::Value =
        serde_json::from_slice(&cli_review_pack_output.stdout)
            .expect("parse authorization review-pack CLI json");
    assert_eq!(
        cli_review_pack_body["schema"].as_str(),
        Some("chio.oauth.authorization-review-pack.v1")
    );
    assert_eq!(
        cli_review_pack_body["summary"]["returnedReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        cli_review_pack_body["metadata"]["profile"]["id"].as_str(),
        Some("chio-governed-rar-v1")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_invalid_chio_oauth_profile_projection() {
    let dir = unique_dir("chio-authorization-context-invalid");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-invalid",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        let keypair = Keypair::generate();
        let invalid_receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "rc-auth-invalid".to_string(),
                timestamp: 8_000,
                capability_id: "cap-auth-invalid".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: tool_action(serde_json::json!({ "invoice_id": "inv-invalid-1" })),
                decision: Decision::Allow,
                content_hash: "content-invalid".to_string(),
                policy_hash: "policy-invalid".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_hex.clone(),
                        issuer_key: issuer_hex.clone(),
                        delegation_depth: 1,
                        grant_index: Some(0),
                    },
                    "governed_transaction": GovernedTransactionReceiptMetadata {
                        intent_id: "intent-auth-invalid".to_string(),
                        intent_hash: "".to_string(),
                        purpose: "broken enterprise profile".to_string(),
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        max_amount: Some(MonetaryAmount {
                            units: 4200,
                            currency: "USD".to_string(),
                        }),
                        commerce: None,
                        metered_billing: None,
                        approval: Some(GovernedApprovalReceiptMetadata {
                            token_id: "approval-auth-invalid".to_string(),
                            approver_key: issuer_hex.clone(),
                            approved: true,
                        }),
                        runtime_assurance: None,
                        call_chain: None,
                        autonomy: None,
                        economic_authorization: None,
                    }
                })),
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign invalid authorization receipt");

        store
            .append_chio_receipt(&invalid_receipt)
            .expect("append invalid authorization receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-invalid-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-invalid"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send invalid authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse invalid authorization context response");
    let error = body["error"]
        .as_str()
        .expect("authorization context error message");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("transactionContext.intentHash"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_missing_sender_binding_material() {
    let dir = unique_dir("chio-authorization-context-missing-sender");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_x402_receipt(
                "rc-auth-no-sender",
                "cap-auth-no-sender",
                "shell",
                "bash",
                8_100,
            ))
            .expect("append missing sender authorization receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-missing-sender-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-no-sender"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send missing sender authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse missing sender authorization context response");
    let error = body["error"]
        .as_str()
        .expect("missing sender authorization context error");
    assert!(error.contains("sender-constrained profile"));
    assert!(error.contains("subjectKey"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_missing_issuer_binding_material() {
    let dir = unique_dir("chio-authorization-context-missing-issuer");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-no-issuer",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-auth-no-issuer",
                "cap-auth-no-issuer",
                &subject_hex,
                "",
                "shell",
                "bash",
                8_101,
            ))
            .expect("append missing issuer authorization receipt");
    }
    let connection = Connection::open(&receipt_db_path).expect("open raw receipt db");
    connection
        .execute(
            "UPDATE capability_lineage SET issuer_key = '' WHERE capability_id = ?1",
            ["cap-auth-no-issuer"],
        )
        .expect("clear lineage issuer key");

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-missing-issuer-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-no-issuer"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send missing issuer authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse missing issuer authorization context response");
    let error = body["error"]
        .as_str()
        .expect("missing issuer authorization context error");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("issuerKey"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_incomplete_runtime_assurance_projection() {
    let dir = unique_dir("chio-authorization-context-invalid-assurance");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-invalid-assurance",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        let keypair = Keypair::generate();
        let invalid_receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "rc-auth-invalid-assurance".to_string(),
                timestamp: 8_150,
                capability_id: "cap-auth-invalid-assurance".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: tool_action(serde_json::json!({ "cmd": "echo auth" })),
                decision: Decision::Allow,
                content_hash: "content-invalid-assurance".to_string(),
                policy_hash: "policy-invalid-assurance".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_hex.clone(),
                        issuer_key: issuer_hex.clone(),
                        delegation_depth: 1,
                        grant_index: Some(0),
                    },
                    "governed_transaction": GovernedTransactionReceiptMetadata {
                        intent_id: "intent-auth-invalid-assurance".to_string(),
                        intent_hash: "intent-hash-invalid-assurance".to_string(),
                        purpose: "broken runtime assurance profile".to_string(),
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        max_amount: Some(MonetaryAmount {
                            units: 4200,
                            currency: "USD".to_string(),
                        }),
                        commerce: None,
                        metered_billing: None,
                        approval: Some(GovernedApprovalReceiptMetadata {
                            token_id: "approval-auth-invalid-assurance".to_string(),
                            approver_key: issuer_hex.clone(),
                            approved: true,
                        }),
                        runtime_assurance: Some(RuntimeAssuranceReceiptMetadata {
                            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                            verifier_family: Some(
                                chio_core::appraisal::AttestationVerifierFamily::AzureMaa,
                            ),
                            tier: RuntimeAssuranceTier::Verified,
                            verifier: "".to_string(),
                            evidence_sha256: "sha256-invalid-assurance".to_string(),
                            workload_identity: None,
                        }),
                        call_chain: None,
                        autonomy: None,
                        economic_authorization: None,
                    }
                })),
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign invalid assurance receipt");

        store
            .append_chio_receipt(&invalid_receipt)
            .expect("append invalid assurance receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-invalid-assurance-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-invalid-assurance"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send invalid runtime assurance authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse invalid runtime assurance authorization context response");
    let error = body["error"]
        .as_str()
        .expect("runtime assurance authorization context error");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("transactionContext.runtimeAssuranceVerifier"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_authorization_context_report_rejects_invalid_delegated_call_chain_projection() {
    let dir = unique_dir("chio-authorization-context-invalid-call-chain");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        record_test_capability_snapshot(
            &mut store,
            "cap-auth-invalid-call-chain",
            &issuer_kp,
            &subject_kp,
            "shell",
            "bash",
            Some(true),
        );
        let keypair = Keypair::generate();
        let invalid_receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "rc-auth-invalid-call-chain".to_string(),
                timestamp: 8_151,
                capability_id: "cap-auth-invalid-call-chain".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: tool_action(serde_json::json!({ "cmd": "echo delegated" })),
                decision: Decision::Allow,
                content_hash: "content-invalid-call-chain".to_string(),
                policy_hash: "policy-invalid-call-chain".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_hex.clone(),
                        issuer_key: issuer_hex.clone(),
                        delegation_depth: 1,
                        grant_index: Some(0),
                    },
                    "governed_transaction": GovernedTransactionReceiptMetadata {
                        intent_id: "intent-auth-invalid-call-chain".to_string(),
                        intent_hash: "intent-hash-invalid-call-chain".to_string(),
                        purpose: "broken delegated profile".to_string(),
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        max_amount: Some(MonetaryAmount {
                            units: 4200,
                            currency: "USD".to_string(),
                        }),
                        commerce: None,
                        metered_billing: None,
                        approval: Some(GovernedApprovalReceiptMetadata {
                            token_id: "approval-auth-invalid-call-chain".to_string(),
                            approver_key: issuer_hex.clone(),
                            approved: true,
                        }),
                        runtime_assurance: None,
                        call_chain: Some(GovernedCallChainProvenance::asserted(
                            GovernedCallChainContext {
                                chain_id: "chain-invalid-1".to_string(),
                                parent_request_id: "parent-invalid-1".to_string(),
                                parent_receipt_id: Some("rcpt-parent-invalid-1".to_string()),
                                origin_subject: "".to_string(),
                                delegator_subject: "upstream-delegator".to_string(),
                            },
                        )),
                        autonomy: None,
                        economic_authorization: None,
                    }
                })),
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign invalid delegated receipt");

        store
            .append_chio_receipt(&invalid_receipt)
            .expect("append invalid delegated receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "authorization-context-invalid-call-chain-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/authorization-context"))
        .query(&[
            ("capabilityId", "cap-auth-invalid-call-chain"),
            ("authorizationLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send invalid delegated authorization context request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body: serde_json::Value = response
        .json()
        .expect("parse invalid delegated authorization context response");
    let error = body["error"]
        .as_str()
        .expect("delegated authorization context error");
    assert!(error.contains("Chio OAuth authorization profile"));
    assert!(error.contains("transactionContext.callChain.originSubject"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Shared evidence references appear in operator reports, the direct query endpoint, and CLI output.
#[test]
fn test_shared_evidence_reporting_surfaces() {
    let dir = unique_dir("chio-shared-evidence-report");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let remote_issuer_kp = Keypair::generate();
    let remote_root_kp = Keypair::generate();
    let remote_delegate_kp = Keypair::generate();
    let local_issuer_kp = Keypair::generate();
    let local_root_kp = Keypair::generate();
    let local_leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let remote_root_hex = remote_root_kp.public_key().to_hex();
    let remote_delegate_hex = remote_delegate_kp.public_key().to_hex();
    let remote_issuer_hex = remote_issuer_kp.public_key().to_hex();
    let _local_root_hex = local_root_kp.public_key().to_hex();
    let local_leaf_hex = local_leaf_kp.public_key().to_hex();
    let local_issuer_hex = local_issuer_kp.public_key().to_hex();

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let local_root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-local-root".to_string(),
            issuer: local_issuer_kp.public_key(),
            subject: local_root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_500,
            expires_at: 20_000,
            delegation_chain: vec![],
        },
        &local_issuer_kp,
    )
    .expect("sign local root capability");
    let local_child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-local-child".to_string(),
            issuer: local_issuer_kp.public_key(),
            subject: local_leaf_kp.public_key(),
            scope,
            issued_at: 1_600,
            expires_at: 20_000,
            delegation_chain: vec![],
        },
        &local_issuer_kp,
    )
    .expect("sign local child capability");

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .import_federated_evidence_share(&FederatedEvidenceShareImport {
                share_id: "share-cross-org".to_string(),
                manifest_hash: "manifest-cross-org".to_string(),
                exported_at: 1_400,
                issuer: "org-remote".to_string(),
                partner: "org-local".to_string(),
                signer_public_key: remote_issuer_hex.clone(),
                require_proofs: true,
                query_json: r#"{"capabilityId":"cap-remote-root"}"#.to_string(),
                tool_receipts: vec![StoredToolReceipt {
                    seq: 1,
                    receipt: make_financial_receipt(
                        "rc-remote-1",
                        "cap-remote-delegate",
                        Some(&remote_delegate_hex),
                        &remote_issuer_hex,
                        "shell",
                        "bash",
                        Decision::Allow,
                        1_350,
                        300,
                        None,
                        &remote_root_hex,
                        1,
                    ),
                }],
                capability_lineage: vec![
                    CapabilitySnapshot {
                        capability_id: "cap-remote-root".to_string(),
                        subject_key: remote_root_hex.clone(),
                        issuer_key: remote_issuer_hex.clone(),
                        issued_at: 1_000,
                        expires_at: 20_000,
                        grants_json: serde_json::to_string(&ChioScope::default())
                            .expect("serialize remote root grants"),
                        delegation_depth: 0,
                        parent_capability_id: None,
                    },
                    CapabilitySnapshot {
                        capability_id: "cap-remote-delegate".to_string(),
                        subject_key: remote_delegate_hex.clone(),
                        issuer_key: remote_issuer_hex.clone(),
                        issued_at: 1_100,
                        expires_at: 20_000,
                        grants_json: serde_json::to_string(&ChioScope::default())
                            .expect("serialize remote delegate grants"),
                        delegation_depth: 1,
                        parent_capability_id: Some("cap-remote-root".to_string()),
                    },
                ],
            })
            .expect("import federated evidence share");
        store
            .record_capability_snapshot(&local_root, None)
            .expect("record local root lineage");
        store
            .record_capability_snapshot(&local_child, Some("cap-local-root"))
            .expect("record local child lineage");
        store
            .record_federated_lineage_bridge(
                "cap-local-root",
                "cap-remote-delegate",
                Some("share-cross-org"),
            )
            .expect("record remote lineage bridge");

        let seq = store
            .append_chio_receipt_returning_seq(&make_financial_receipt(
                "rc-local-1",
                "cap-local-child",
                Some(&local_leaf_hex),
                &local_issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                1_700,
                450,
                None,
                &remote_root_hex,
                3,
            ))
            .expect("append shared-evidence receipt");
        store
            .append_chio_receipt(&make_financial_receipt(
                "rc-local-2",
                "cap-local-child",
                Some(&local_leaf_hex),
                &local_issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "policy".to_string(),
                    guard: "kernel".to_string(),
                },
                1_701,
                0,
                Some(200),
                &remote_root_hex,
                3,
            ))
            .expect("append second shared-evidence receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        budgets
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-local-child".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 1_800,
                seq: 1,
                total_cost_exposed: 450,
                total_cost_realized_spend: 0,
            })
            .expect("upsert budget usage");
    }

    let listen = reserve_listen_addr();
    let service_token = "shared-evidence-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let operator_response = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("agentSubject", local_leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("budgetLimit", "10"),
            ("attributionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");
    assert_eq!(operator_response.status(), reqwest::StatusCode::OK);
    let operator_body: serde_json::Value = operator_response
        .json()
        .expect("parse operator report body");
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingShares"].as_u64(),
        Some(1)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingReferences"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingLocalReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["remoteLineageRecords"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["references"]
            .as_array()
            .expect("shared evidence references")
            .len(),
        2
    );

    let shared_response = client
        .get(format!("{base_url}/v1/federation/evidence-shares"))
        .query(&[("agentSubject", local_leaf_hex.as_str())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send shared evidence request");
    assert_eq!(shared_response.status(), reqwest::StatusCode::OK);
    let shared_body: serde_json::Value =
        shared_response.json().expect("parse shared evidence body");
    assert_eq!(shared_body["summary"]["matchingShares"].as_u64(), Some(1));
    assert_eq!(
        shared_body["summary"]["matchingReferences"].as_u64(),
        Some(2)
    );
    assert!(shared_body["references"]
        .as_array()
        .expect("references array")
        .iter()
        .all(|row| row["share"]["partner"].as_str() == Some("org-local")));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "evidence-share",
            "list",
            "--agent-subject",
            &local_leaf_hex,
            "--json",
        ])
        .output()
        .expect("run shared evidence CLI");
    assert!(
        cli_output.status.success(),
        "shared evidence CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_body: serde_json::Value =
        serde_json::from_slice(&cli_output.stdout).expect("parse shared evidence CLI json");
    assert_eq!(cli_body["summary"]["matchingShares"].as_u64(), Some(1));
    assert_eq!(cli_body["summary"]["matchingReferences"].as_u64(), Some(2));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Behavioral feeds expose signed risk-facing exports over both trust-control and local CLI.
#[test]
fn test_behavioral_feed_export_surfaces() {
    let dir = unique_dir("chio-behavioral-feed");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-risk-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_000,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign root capability");
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-risk-child".to_string(),
            issuer: issuer_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope,
            issued_at: 1_100,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign child capability");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root lineage");
        store
            .record_capability_snapshot(&child, Some("cap-risk-root"))
            .expect("record child lineage");

        let seq = store
            .append_chio_receipt_returning_seq(&make_governed_financial_receipt(
                "rc-risk-1",
                "cap-risk-child",
                &leaf_hex,
                &issuer_hex,
                "shell",
                "bash",
                5_000,
                750,
                &root_hex,
            ))
            .expect("append governed receipt");
        store
            .append_chio_receipt(&make_financial_receipt_with_settlement_status(
                "rc-risk-2",
                "cap-risk-child",
                "shell",
                "bash",
                5_001,
                200,
                SettlementStatus::Pending,
                Some("payment-risk-2"),
            ))
            .expect("append pending receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        budgets
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-risk-child".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 5_100,
                seq: 1,
                total_cost_exposed: 950,
                total_cost_realized_spend: 0,
            })
            .expect("upsert budget usage");
    }

    let listen = reserve_listen_addr();
    let service_token = "behavioral-feed-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/behavioral-feed"))
        .query(&[
            ("agentSubject", leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("receiptLimit", "5000"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send behavioral feed request");
    let response_status = response.status();
    let response_text = response.text().expect("read behavioral feed body");
    assert_eq!(
        response_status,
        reqwest::StatusCode::OK,
        "behavioral feed body: {response_text}"
    );
    let feed: SignedBehavioralFeed =
        serde_json::from_str(&response_text).expect("parse behavioral feed");
    assert!(feed
        .verify_signature()
        .expect("verify behavioral feed signature"));
    assert_eq!(feed.body.schema, "chio.behavioral-feed.v1");
    assert_eq!(feed.body.filters.receipt_limit, Some(200));
    assert_eq!(feed.body.privacy.matching_receipts, 2);
    assert_eq!(feed.body.decisions.allow_count, 2);
    assert_eq!(feed.body.governed_actions.governed_receipts, 1);
    assert_eq!(feed.body.governed_actions.approved_receipts, 1);
    assert_eq!(feed.body.settlements.pending_receipts, 1);
    assert_eq!(feed.body.settlements.settled_receipts, 1);
    assert_eq!(feed.body.receipts.len(), 2);
    assert_eq!(
        feed.body
            .reputation
            .as_ref()
            .expect("reputation summary")
            .subject_key,
        leaf_hex
    );
    let budget_authority_row = feed
        .body
        .receipts
        .iter()
        .find(|row| row.receipt_id == "rc-risk-2")
        .expect("budget authority feed row");
    assert_eq!(
        budget_authority_row
            .budget_authority
            .as_ref()
            .expect("budget authority")
            .guarantee_level,
        "ha_quorum_commit"
    );
    assert_eq!(
        budget_authority_row
            .budget_authority
            .as_ref()
            .expect("budget authority")
            .hold_id,
        "budget-hold:rc-risk-2:capability:0"
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "behavioral-feed",
            "export",
            "--agent-subject",
            &leaf_hex,
            "--tool-server",
            "shell",
            "--tool-name",
            "bash",
            "--receipt-limit",
            "5000",
        ])
        .output()
        .expect("run behavioral feed CLI");
    assert!(
        cli_output.status.success(),
        "behavioral feed CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_feed: SignedBehavioralFeed =
        serde_json::from_slice(&cli_output.stdout).expect("parse behavioral feed CLI json");
    assert!(cli_feed
        .verify_signature()
        .expect("verify behavioral feed CLI signature"));
    assert_eq!(cli_feed.body.schema, "chio.behavioral-feed.v1");
    assert_eq!(cli_feed.body.filters.receipt_limit, Some(200));
    assert_eq!(cli_feed.body.governed_actions.commerce_receipts, 1);
    assert_eq!(cli_feed.body.privacy.returned_receipts, 2);
    assert_eq!(cli_feed.signer_key, feed.signer_key);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_attestation_appraisal_export_surfaces() {
    let dir = unique_dir("chio-runtime-appraisal");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let attestation_path = dir.join("runtime-attestation.json");
    let policy_path = dir.join("runtime-policy.yaml");
    let attestation = sample_google_runtime_attestation();
    std::fs::write(
        &attestation_path,
        serde_json::to_vec_pretty(&attestation).expect("serialize attestation"),
    )
    .expect("write attestation file");
    std::fs::write(
        &policy_path,
        r#"hushspec: "0.1.0"
name: runtime-appraisal
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
      verified:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 300
    trusted_verifiers:
      google_prod:
        schema: chio.runtime-attestation.google-confidential-vm.jwt.v1
        verifier: https://confidentialcomputing.googleapis.com
        verifier_family: google_attestation
        effective_tier: verified
        max_evidence_age_seconds: 120
        allowed_attestation_types: [confidential_vm]
        required_assertions:
          hardwareModel: GCP_AMD_SEV
          secureBoot: enabled
"#,
    )
    .expect("write runtime policy file");

    let listen = reserve_listen_addr();
    let service_token = "runtime-appraisal-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&RuntimeAttestationAppraisalRequest {
            runtime_attestation: attestation.clone(),
        })
        .send()
        .expect("send runtime appraisal request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedRuntimeAttestationAppraisalReport =
        response.json().expect("parse signed appraisal report");
    assert!(report
        .verify_signature()
        .expect("verify signed runtime appraisal"));
    assert_eq!(
        report.body.schema,
        "chio.runtime-attestation.appraisal-report.v1"
    );
    assert_eq!(
        report.body.appraisal.evidence.schema,
        "chio.runtime-attestation.google-confidential-vm.jwt.v1"
    );
    assert_eq!(
        report.body.appraisal.verifier_family,
        chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation
    );
    assert_eq!(
        report.body.appraisal.normalized_assertions["secureBoot"],
        serde_json::json!("enabled")
    );
    let artifact = report
        .body
        .appraisal
        .artifact
        .as_ref()
        .expect("appraisal export should carry nested artifact");
    assert_eq!(
        artifact.schema,
        "chio.runtime-attestation.appraisal-artifact.v1"
    );
    assert_eq!(artifact.verifier.adapter, "google_confidential_vm");
    assert_eq!(
        artifact.claims.normalized_assertions["secureBoot"],
        serde_json::json!("enabled")
    );
    assert!(artifact.claims.normalized_claims.iter().any(|claim| {
        claim.code == chio_core::appraisal::RuntimeAttestationNormalizedClaimCode::SecureBootState
            && claim.legacy_assertion_key == "secureBoot"
            && claim.provenance
                == chio_core::appraisal::RuntimeAttestationClaimProvenance::VendorClaims
            && claim.value == serde_json::json!("enabled")
    }));
    assert_eq!(
        artifact.policy.effective_tier,
        RuntimeAssuranceTier::Attested
    );
    assert_eq!(
        artifact.policy.reasons,
        vec![
            chio_core::appraisal::RuntimeAttestationAppraisalReason::from_code(
                chio_core::appraisal::RuntimeAttestationAppraisalReasonCode::EvidenceVerified
            )
        ]
    );
    assert!(!report.body.policy_outcome.trust_policy_configured);
    assert!(report.body.policy_outcome.accepted);
    assert_eq!(
        report.body.policy_outcome.effective_tier,
        RuntimeAssuranceTier::Attested
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "appraisal",
            "export",
            "--input",
            attestation_path.to_str().expect("attestation path"),
            "--policy-file",
            policy_path.to_str().expect("policy path"),
        ])
        .output()
        .expect("run runtime appraisal CLI");
    assert!(
        cli_output.status.success(),
        "runtime appraisal CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedRuntimeAttestationAppraisalReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse runtime appraisal CLI json");
    assert!(cli_report
        .verify_signature()
        .expect("verify runtime appraisal CLI signature"));
    assert!(cli_report.body.policy_outcome.trust_policy_configured);
    assert!(cli_report.body.policy_outcome.accepted);
    assert_eq!(
        cli_report.body.policy_outcome.effective_tier,
        RuntimeAssuranceTier::Verified
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_attestation_appraisal_result_import_export_surfaces() {
    let dir = unique_dir("chio-runtime-appraisal-result");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let attestation_path = dir.join("runtime-attestation.json");
    let signed_result_path = dir.join("signed-appraisal-result.json");
    let runtime_policy_path = dir.join("runtime-policy.yaml");
    let import_policy_path = dir.join("import-policy.json");
    let rejecting_policy_path = dir.join("rejecting-import-policy.json");
    let attestation = sample_google_runtime_attestation();
    std::fs::write(
        &attestation_path,
        serde_json::to_vec_pretty(&attestation).expect("serialize attestation"),
    )
    .expect("write attestation file");
    std::fs::write(
        &runtime_policy_path,
        r#"hushspec: "0.1.0"
name: runtime-appraisal-result
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 60
      verified:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          ttl_seconds: 300
    trusted_verifiers:
      google_prod:
        schema: chio.runtime-attestation.google-confidential-vm.jwt.v1
        verifier: https://confidentialcomputing.googleapis.com
        verifier_family: google_attestation
        effective_tier: verified
        max_evidence_age_seconds: 120
        allowed_attestation_types: [confidential_vm]
        required_assertions:
          hardwareModel: GCP_AMD_SEV
          secureBoot: enabled
"#,
    )
    .expect("write runtime policy file");

    let listen = reserve_listen_addr();
    let service_token = "runtime-appraisal-result-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal-result"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&RuntimeAttestationAppraisalResultExportRequest {
            issuer: "did:chio:test:remote-exporter".to_string(),
            runtime_attestation: attestation.clone(),
        })
        .send()
        .expect("send runtime appraisal result export request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let exported: SignedRuntimeAttestationAppraisalResult =
        response.json().expect("parse signed appraisal result");
    assert!(exported
        .verify_signature()
        .expect("verify signed appraisal result"));
    assert_eq!(
        exported.body.schema,
        "chio.runtime-attestation.appraisal-result.v1"
    );
    assert_eq!(exported.body.issuer, "did:chio:test:remote-exporter");
    assert_eq!(
        exported.body.subject.runtime_identity.as_deref(),
        Some("spiffe://chio.example/workloads/google")
    );
    std::fs::write(
        &signed_result_path,
        serde_json::to_vec_pretty(&exported).expect("serialize signed result"),
    )
    .expect("write signed result file");

    let import_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec!["did:chio:test:remote-exporter".to_string()],
        trusted_signer_keys: vec![exported.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: Some(RuntimeAssuranceTier::Basic),
        required_claims: std::iter::once((
            RuntimeAttestationNormalizedClaimCode::SecureBootState,
            "enabled".to_string(),
        ))
        .collect(),
    };
    std::fs::write(
        &import_policy_path,
        serde_json::to_vec_pretty(&import_policy).expect("serialize import policy"),
    )
    .expect("write import policy file");

    let import_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported,
            "localPolicy": import_policy,
        }))
        .send()
        .expect("send runtime appraisal import request");
    assert_eq!(import_response.status(), reqwest::StatusCode::OK);
    let import_report: RuntimeAttestationAppraisalImportReport =
        import_response.json().expect("parse import report");
    assert_eq!(
        import_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Attenuate
    );
    assert_eq!(
        import_report.local_policy_outcome.effective_tier,
        RuntimeAssuranceTier::Basic
    );
    assert_eq!(
        import_report.local_policy_outcome.reason_codes,
        vec![RuntimeAttestationImportReasonCode::TierAttenuated]
    );

    let cli_export_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "appraisal",
            "export-result",
            "--issuer",
            "did:chio:test:cli-exporter",
            "--input",
            attestation_path.to_str().expect("attestation path"),
            "--policy-file",
            runtime_policy_path.to_str().expect("runtime policy path"),
        ])
        .output()
        .expect("run appraisal result export CLI");
    assert!(
        cli_export_output.status.success(),
        "runtime appraisal result export CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_export_output.stdout),
        String::from_utf8_lossy(&cli_export_output.stderr)
    );
    let cli_result: SignedRuntimeAttestationAppraisalResult =
        serde_json::from_slice(&cli_export_output.stdout)
            .expect("parse appraisal result export CLI json");
    assert!(cli_result
        .verify_signature()
        .expect("verify appraisal result export CLI signature"));
    assert!(
        cli_result
            .body
            .exporter_policy_outcome
            .trust_policy_configured
    );
    assert_eq!(
        cli_result.body.exporter_policy_outcome.effective_tier,
        RuntimeAssuranceTier::Verified
    );

    let rejecting_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec!["did:chio:test:remote-exporter".to_string()],
        trusted_signer_keys: vec![cli_result.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: std::iter::once((
            RuntimeAttestationNormalizedClaimCode::SecureBootState,
            "disabled".to_string(),
        ))
        .collect(),
    };
    std::fs::write(
        &rejecting_policy_path,
        serde_json::to_vec_pretty(&rejecting_policy).expect("serialize rejecting policy"),
    )
    .expect("write rejecting policy file");

    let cli_import_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "trust",
            "appraisal",
            "import",
            "--input",
            signed_result_path.to_str().expect("signed result path"),
            "--policy-file",
            rejecting_policy_path
                .to_str()
                .expect("rejecting policy path"),
        ])
        .output()
        .expect("run appraisal import CLI");
    assert!(
        cli_import_output.status.success(),
        "runtime appraisal import CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_import_output.stdout),
        String::from_utf8_lossy(&cli_import_output.stderr)
    );
    let cli_import_report: RuntimeAttestationAppraisalImportReport =
        serde_json::from_slice(&cli_import_output.stdout).expect("parse appraisal import CLI json");
    assert_eq!(
        cli_import_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(cli_import_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::ClaimMismatch));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_attestation_appraisal_result_qualification_covers_mixed_providers_and_fail_closed_imports(
) {
    struct ProviderCase {
        name: &'static str,
        attestation: RuntimeAttestationEvidence,
        expected_family: chio_core::appraisal::AttestationVerifierFamily,
        required_claim: (RuntimeAttestationNormalizedClaimCode, &'static str),
    }

    let dir = unique_dir("chio-runtime-appraisal-mixed-provider");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "runtime-appraisal-mixed-provider-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let providers = vec![
        ProviderCase {
            name: "azure",
            attestation: sample_azure_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::AzureMaa,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::AttestationType,
                "sgx",
            ),
        },
        ProviderCase {
            name: "aws_nitro",
            attestation: sample_aws_nitro_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::AwsNitro,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::ModuleId,
                "i-chio-nitro-enclave",
            ),
        },
        ProviderCase {
            name: "google",
            attestation: sample_google_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::HardwareModel,
                "GCP_AMD_SEV",
            ),
        },
        ProviderCase {
            name: "enterprise",
            attestation: sample_enterprise_runtime_attestation(),
            expected_family: chio_core::appraisal::AttestationVerifierFamily::EnterpriseVerifier,
            required_claim: (
                RuntimeAttestationNormalizedClaimCode::ModuleId,
                "enterprise-module-1",
            ),
        },
    ];

    for provider in &providers {
        let issuer = format!("did:chio:test:{}-exporter", provider.name);
        let response = client
            .post(format!(
                "{base_url}/v1/reports/runtime-attestation-appraisal-result"
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            )
            .json(&RuntimeAttestationAppraisalResultExportRequest {
                issuer: issuer.clone(),
                runtime_attestation: provider.attestation.clone(),
            })
            .send()
            .expect("send runtime appraisal result export request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let exported: SignedRuntimeAttestationAppraisalResult =
            response.json().expect("parse signed appraisal result");
        assert!(exported
            .verify_signature()
            .expect("verify signed appraisal result"));
        assert_eq!(exported.body.issuer, issuer);
        assert_eq!(
            exported.body.appraisal.verifier.verifier_family,
            provider.expected_family
        );
        assert!(
            exported
                .body
                .appraisal
                .claims
                .normalized_claims
                .iter()
                .any(|claim| claim.code == provider.required_claim.0),
            "provider {} should project required normalized claim",
            provider.name
        );

        let import_policy = RuntimeAttestationImportedAppraisalPolicy {
            trusted_issuers: vec![exported.body.issuer.clone()],
            trusted_signer_keys: vec![exported.signer_key.to_hex()],
            allowed_verifier_families: vec![provider.expected_family],
            max_result_age_seconds: Some(300),
            max_evidence_age_seconds: Some(300),
            maximum_effective_tier: None,
            required_claims: BTreeMap::from([(
                provider.required_claim.0,
                provider.required_claim.1.to_string(),
            )]),
        };
        let import_response = client
            .post(format!(
                "{base_url}/v1/reports/runtime-attestation-appraisal/import"
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            )
            .json(&serde_json::json!({
                "signedResult": exported,
                "localPolicy": import_policy,
            }))
            .send()
            .expect("send runtime appraisal import request");
        assert_eq!(import_response.status(), reqwest::StatusCode::OK);
        let import_report: RuntimeAttestationAppraisalImportReport =
            import_response.json().expect("parse import report");
        assert_eq!(
            import_report.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Allow,
            "provider {} should import cleanly",
            provider.name
        );
        assert_eq!(
            import_report.local_policy_outcome.effective_tier,
            RuntimeAssuranceTier::Attested
        );
    }

    let google_export = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal-result"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&RuntimeAttestationAppraisalResultExportRequest {
            issuer: "did:chio:test:google-negative-exporter".to_string(),
            runtime_attestation: sample_google_runtime_attestation(),
        })
        .send()
        .expect("export google result for negative paths");
    assert_eq!(google_export.status(), reqwest::StatusCode::OK);
    let exported_google: SignedRuntimeAttestationAppraisalResult =
        google_export.json().expect("parse exported google result");

    let contradictory_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec![exported_google.body.issuer.clone()],
        trusted_signer_keys: vec![exported_google.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: BTreeMap::from([(
            RuntimeAttestationNormalizedClaimCode::HardwareModel,
            "GCP_INTEL_TDX".to_string(),
        )]),
    };
    let contradictory_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported_google.clone(),
            "localPolicy": contradictory_policy,
        }))
        .send()
        .expect("import contradictory google result");
    assert_eq!(contradictory_response.status(), reqwest::StatusCode::OK);
    let contradictory_report: RuntimeAttestationAppraisalImportReport = contradictory_response
        .json()
        .expect("parse contradictory import report");
    assert_eq!(
        contradictory_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(contradictory_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::ClaimMismatch));

    let unsupported_family_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec![exported_google.body.issuer.clone()],
        trusted_signer_keys: vec![exported_google.signer_key.to_hex()],
        allowed_verifier_families: vec![chio_core::appraisal::AttestationVerifierFamily::AzureMaa],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: BTreeMap::new(),
    };
    let unsupported_family_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported_google.clone(),
            "localPolicy": unsupported_family_policy,
        }))
        .send()
        .expect("import unsupported-family google result");
    assert_eq!(
        unsupported_family_response.status(),
        reqwest::StatusCode::OK
    );
    let unsupported_family_report: RuntimeAttestationAppraisalImportReport =
        unsupported_family_response
            .json()
            .expect("parse unsupported-family import report");
    assert_eq!(
        unsupported_family_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(unsupported_family_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::UnsupportedVerifierFamily));

    let stale_evidence_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec![exported_google.body.issuer.clone()],
        trusted_signer_keys: vec![exported_google.signer_key.to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(300),
        max_evidence_age_seconds: Some(1),
        maximum_effective_tier: None,
        required_claims: BTreeMap::new(),
    };
    let stale_evidence_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": exported_google.clone(),
            "localPolicy": stale_evidence_policy,
        }))
        .send()
        .expect("import stale-evidence google result");
    assert_eq!(stale_evidence_response.status(), reqwest::StatusCode::OK);
    let stale_evidence_report: RuntimeAttestationAppraisalImportReport = stale_evidence_response
        .json()
        .expect("parse stale-evidence import report");
    assert_eq!(
        stale_evidence_report.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(stale_evidence_report
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::EvidenceStale));

    let replay_attestation = sample_google_runtime_attestation();
    let replay_appraisal = derive_runtime_attestation_appraisal(&replay_attestation)
        .expect("derive appraisal for stale replay test");
    let stale_replay_report = RuntimeAttestationAppraisalReport {
        schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
        generated_at: unix_now_secs().saturating_sub(600),
        appraisal: replay_appraisal,
        policy_outcome: RuntimeAttestationPolicyOutcome {
            trust_policy_configured: false,
            accepted: true,
            effective_tier: RuntimeAssuranceTier::Attested,
            reason: None,
        },
    };
    let stale_replay_result = RuntimeAttestationAppraisalResult::from_report(
        "did:chio:test:stale-replay-exporter",
        &stale_replay_report,
    )
    .expect("build stale replay result");
    let stale_replay_signer = Keypair::generate();
    let signed_stale_replay =
        SignedRuntimeAttestationAppraisalResult::sign(stale_replay_result, &stale_replay_signer)
            .expect("sign stale replay result");
    let stale_replay_policy = RuntimeAttestationImportedAppraisalPolicy {
        trusted_issuers: vec!["did:chio:test:stale-replay-exporter".to_string()],
        trusted_signer_keys: vec![stale_replay_signer.public_key().to_hex()],
        allowed_verifier_families: vec![
            chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
        ],
        max_result_age_seconds: Some(120),
        max_evidence_age_seconds: Some(300),
        maximum_effective_tier: None,
        required_claims: BTreeMap::new(),
    };
    let stale_replay_response = client
        .post(format!(
            "{base_url}/v1/reports/runtime-attestation-appraisal/import"
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "signedResult": signed_stale_replay,
            "localPolicy": stale_replay_policy,
        }))
        .send()
        .expect("import stale replay result");
    assert_eq!(stale_replay_response.status(), reqwest::StatusCode::OK);
    let stale_replay_import: RuntimeAttestationAppraisalImportReport = stale_replay_response
        .json()
        .expect("parse stale replay import report");
    assert_eq!(
        stale_replay_import.local_policy_outcome.disposition,
        RuntimeAttestationImportDisposition::Reject
    );
    assert!(stale_replay_import
        .local_policy_outcome
        .reason_codes
        .contains(&RuntimeAttestationImportReasonCode::ResultStale));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_exposure_ledger_report_surfaces() {
    let dir = unique_dir("chio-exposure-ledger");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-exposure-1";
    let issuer_key = "issuer-exposure-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-settled-1",
                "cap-exposure-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
                SettlementStatus::Settled,
                "USD",
                4_200,
                "USD",
                false,
                false,
            ))
            .expect("append settled exposure receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-pending-1",
                "cap-exposure-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp.saturating_sub(1),
                SettlementStatus::Pending,
                "USD",
                1_800,
                "USD",
                false,
                false,
            ))
            .expect("append pending exposure receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-failed-1",
                "cap-exposure-3",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp.saturating_sub(2),
                SettlementStatus::Failed,
                "USD",
                1_200,
                "USD",
                false,
                false,
            ))
            .expect("append failed exposure receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "exposure-ledger-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let issue_response = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "since": timestamp,
                "until": timestamp,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue underwriting decision for exposure ledger");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let decision: SignedUnderwritingDecision = issue_response
        .json()
        .expect("parse exposure underwriting decision");
    let quoted_premium_units = decision
        .body
        .premium
        .quoted_amount
        .as_ref()
        .map(|amount| amount.units)
        .expect("quoted premium amount");

    let response = client
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send exposure ledger request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedExposureLedgerReport = response.json().expect("parse signed exposure ledger");
    assert!(report
        .verify_signature()
        .expect("verify exposure ledger signature"));
    assert_eq!(report.body.schema, "chio.credit.exposure-ledger.v1");
    assert_eq!(report.body.summary.matching_receipts, 3);
    assert_eq!(report.body.summary.returned_receipts, 3);
    assert_eq!(report.body.summary.matching_decisions, 1);
    assert_eq!(report.body.summary.returned_decisions, 1);
    assert_eq!(report.body.summary.active_decisions, 1);
    assert_eq!(report.body.summary.superseded_decisions, 0);
    assert_eq!(report.body.summary.actionable_receipts, 2);
    assert_eq!(report.body.summary.pending_settlement_receipts, 1);
    assert_eq!(report.body.summary.failed_settlement_receipts, 1);
    assert_eq!(report.body.summary.currencies, vec!["USD"]);
    assert!(!report.body.summary.mixed_currency_book);
    assert_eq!(report.body.positions.len(), 1);
    let position = &report.body.positions[0];
    assert_eq!(position.currency, "USD");
    assert_eq!(position.governed_max_exposure_units, 7_200);
    assert_eq!(position.reserved_units, 3_000);
    assert_eq!(position.settled_units, 4_200);
    assert_eq!(position.pending_units, 1_800);
    assert_eq!(position.failed_units, 1_200);
    assert_eq!(position.provisional_loss_units, 1_200);
    assert_eq!(position.recovered_units, 0);
    assert_eq!(position.quoted_premium_units, quoted_premium_units);
    assert_eq!(position.active_quoted_premium_units, quoted_premium_units);
    assert_eq!(report.body.receipts.len(), 3);
    assert!(report
        .body
        .receipts
        .iter()
        .all(|row| !row.evidence_refs.is_empty()));
    assert_eq!(report.body.decisions.len(), 1);
    assert_eq!(
        report.body.decisions[0]
            .quoted_premium_amount
            .as_ref()
            .map(|amount| amount.units),
        Some(quoted_premium_units)
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "exposure-ledger",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
            "--decision-limit",
            "10",
        ])
        .output()
        .expect("run exposure ledger CLI");
    assert!(
        cli_output.status.success(),
        "exposure ledger CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedExposureLedgerReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse exposure ledger CLI json");
    assert!(cli_report
        .verify_signature()
        .expect("verify exposure ledger CLI signature"));
    assert_eq!(cli_report.body.summary.matching_receipts, 3);
    assert_eq!(cli_report.body.summary.matching_decisions, 1);
    assert_eq!(cli_report.body.positions[0].reserved_units, 3_000);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_exposure_ledger_requires_anchor() {
    let dir = unique_dir("chio-exposure-ledger-anchor");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "exposure-ledger-anchor-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[("receiptLimit", "10"), ("decisionLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send exposure ledger request without anchor");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse exposure ledger anchor failure");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("require at least one anchor"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_exposure_ledger_rejects_contradictory_currency_row() {
    let dir = unique_dir("chio-exposure-ledger-currency-conflict");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-exposure-conflict-1";
    let issuer_key = "issuer-exposure-conflict-1";
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-exposure-conflict-1",
                "cap-exposure-conflict-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(60),
                SettlementStatus::Settled,
                "USD",
                2_000,
                "EUR",
                false,
                false,
            ))
            .expect("append contradictory currency receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "exposure-ledger-currency-conflict-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[
            ("agentSubject", subject_key),
            ("toolServer", "ledger"),
            ("toolName", "transfer"),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send contradictory exposure ledger request");
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = response
        .json()
        .expect("parse contradictory exposure ledger error");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("cannot project one exposure row across multiple currencies"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_scorecard_report_surfaces() {
    let dir = unique_dir("chio-credit-scorecard");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-1";
    let issuer_key = "issuer-credit-1";
    let now = unix_now_secs();
    let settled_at = now.saturating_sub(3 * 86_400);
    let pending_at = now.saturating_sub(2 * 86_400);
    let failed_at = now.saturating_sub(86_400);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-credit-settled-1",
                "cap-credit-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                settled_at,
                SettlementStatus::Settled,
                "USD",
                5_000,
                "USD",
                false,
                false,
            ))
            .expect("append settled credit receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-credit-pending-1",
                "cap-credit-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                pending_at,
                SettlementStatus::Pending,
                "USD",
                2_000,
                "USD",
                false,
                false,
            ))
            .expect("append pending credit receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-credit-failed-1",
                "cap-credit-3",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                failed_at,
                SettlementStatus::Failed,
                "USD",
                1_500,
                "USD",
                false,
                false,
            ))
            .expect("append failed credit receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-scorecard-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let issue_response = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "since": settled_at,
                "until": settled_at,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue underwriting decision for credit scorecard");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);

    let response = client
        .get(format!("{base_url}/v1/reports/credit-scorecard"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit scorecard request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedCreditScorecardReport =
        response.json().expect("parse signed credit scorecard");
    assert!(report
        .verify_signature()
        .expect("verify credit scorecard signature"));
    assert_eq!(report.body.schema, "chio.credit.scorecard.v1");
    assert_eq!(report.body.summary.matching_receipts, 3);
    assert_eq!(report.body.summary.matching_decisions, 1);
    assert_eq!(report.body.summary.currencies, vec!["USD"]);
    assert!(report.body.summary.probationary);
    assert_eq!(
        report.body.summary.confidence,
        chio_core::credit::CreditScorecardConfidence::Low
    );
    assert_eq!(
        report.body.summary.band,
        chio_core::credit::CreditScorecardBand::Probationary
    );
    assert_eq!(report.body.positions.len(), 1);
    assert_eq!(report.body.dimensions.len(), 4);
    assert!(report.body.summary.overall_score >= 0.0 && report.body.summary.overall_score <= 1.0);
    assert!(report.body.anomalies.iter().any(|anomaly| {
        anomaly.code == chio_core::credit::CreditScorecardReasonCode::PendingSettlementBacklog
    }));
    assert!(report.body.anomalies.iter().any(|anomaly| {
        anomaly.code == chio_core::credit::CreditScorecardReasonCode::FailedSettlementBacklog
    }));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "credit-scorecard",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
            "--decision-limit",
            "10",
        ])
        .output()
        .expect("run credit scorecard CLI");
    assert!(
        cli_output.status.success(),
        "credit scorecard CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedCreditScorecardReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit scorecard CLI json");
    assert!(cli_report
        .verify_signature()
        .expect("verify credit scorecard CLI signature"));
    assert_eq!(cli_report.body.summary.matching_receipts, 3);
    assert!(cli_report.body.summary.probationary);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_scorecard_requires_agent_subject() {
    let dir = unique_dir("chio-credit-scorecard-anchor");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-scorecard-anchor-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/credit-scorecard"))
        .query(&[("toolServer", "ledger"), ("receiptLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit scorecard request without subject");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse credit scorecard anchor failure");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("require --agent-subject"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_scorecard_requires_matching_history() {
    let dir = unique_dir("chio-credit-scorecard-history");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-scorecard-history-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/credit-scorecard"))
        .query(&[("agentSubject", "missing-subject"), ("receiptLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit scorecard request without history");
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = response
        .json()
        .expect("parse credit scorecard history failure");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one matching governed receipt"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_issue_and_list_surfaces() {
    let dir = unique_dir("chio-credit-facility-grant");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-facility-grant-1";
    let issuer_key = "issuer-facility-grant-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-facility-grant-{day}"),
                    &format!("cap-facility-grant-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append facility grant receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-grant-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let evaluate_response = client
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit facility evaluate request");
    assert_eq!(evaluate_response.status(), reqwest::StatusCode::OK);
    let evaluate_report: CreditFacilityReport = evaluate_response
        .json()
        .expect("parse credit facility evaluate report");
    assert_eq!(evaluate_report.schema, "chio.credit.facility-report.v1");
    assert_eq!(
        evaluate_report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant
    );
    assert!(evaluate_report.prerequisites.runtime_assurance_met);
    assert!(!evaluate_report.prerequisites.certification_required);
    assert!(evaluate_report.terms.is_some());

    let remote_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("send facility issue request");
    assert_eq!(remote_issue.status(), reqwest::StatusCode::OK);
    let first_facility: SignedCreditFacility = remote_issue
        .json()
        .expect("parse first signed credit facility");
    assert_eq!(first_facility.body.schema, "chio.credit.facility.v1");
    assert_eq!(
        first_facility.body.report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant
    );
    assert_eq!(
        first_facility.body.lifecycle_state,
        chio_core::credit::CreditFacilityLifecycleState::Active
    );

    let remote_supersede = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            },
            "supersedesFacilityId": first_facility.body.facility_id
        }))
        .send()
        .expect("send superseding facility issue request");
    assert_eq!(remote_supersede.status(), reqwest::StatusCode::OK);
    let second_facility: SignedCreditFacility = remote_supersede
        .json()
        .expect("parse second signed credit facility");
    assert_eq!(
        second_facility.body.supersedes_facility_id.as_deref(),
        Some(first_facility.body.facility_id.as_str())
    );

    let remote_list = client
        .get(format!("{base_url}/v1/reports/facilities"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit facility list request");
    assert_eq!(remote_list.status(), reqwest::StatusCode::OK);
    let list_report: CreditFacilityListReport = remote_list
        .json()
        .expect("parse credit facility list report");
    assert_eq!(list_report.schema, "chio.credit.facility-list.v1");
    assert_eq!(list_report.summary.matching_facilities, 2);
    assert_eq!(list_report.summary.active_facilities, 1);
    assert_eq!(list_report.summary.superseded_facilities, 1);
    assert_eq!(list_report.summary.granted_facilities, 2);
    let first_row = list_report
        .facilities
        .iter()
        .find(|row| row.facility.body.facility_id == first_facility.body.facility_id)
        .expect("first facility row");
    assert_eq!(
        first_row.lifecycle_state,
        chio_core::credit::CreditFacilityLifecycleState::Superseded
    );
    let second_row = list_report
        .facilities
        .iter()
        .find(|row| row.facility.body.facility_id == second_facility.body.facility_id)
        .expect("second facility row");
    assert_eq!(
        second_row.lifecycle_state,
        chio_core::credit::CreditFacilityLifecycleState::Active
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "facility",
            "list",
            "--agent-subject",
            subject_key,
            "--limit",
            "10",
        ])
        .output()
        .expect("run credit facility list CLI");
    assert!(
        cli_output.status.success(),
        "credit facility list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditFacilityListReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit facility CLI list");
    assert_eq!(cli_report.summary.matching_facilities, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_issue_endpoints_require_service_auth() {
    let dir = unique_dir("chio-credit-issue-auth");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-issue-auth-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_response = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-auth-facility",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send unauthenticated facility issue request");
    assert_eq!(
        facility_response.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        facility_response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    let facility_body: serde_json::Value = facility_response
        .json()
        .expect("parse unauthenticated facility issue error");
    assert!(facility_body["error"]
        .as_str()
        .expect("facility error string")
        .contains("missing or invalid control bearer token"));

    let bond_response = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-auth-bond",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send unauthenticated bond issue request");
    assert_eq!(bond_response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        bond_response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    let bond_body: serde_json::Value = bond_response
        .json()
        .expect("parse unauthenticated bond issue error");
    assert!(bond_body["error"]
        .as_str()
        .expect("bond error string")
        .contains("missing or invalid control bearer token"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_issue_endpoints_require_receipt_db_configuration() {
    let dir = unique_dir("chio-credit-issue-missing-receipt-db");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "credit-issue-receipt-db-token";
    let _service = spawn_trust_service_without_receipt_db(
        listen,
        service_token,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_response = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-receipt-db-facility",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send facility issue request without receipt db");
    assert_eq!(facility_response.status(), reqwest::StatusCode::CONFLICT);
    let facility_body: serde_json::Value = facility_response
        .json()
        .expect("parse missing receipt db facility error");
    assert!(facility_body["error"]
        .as_str()
        .expect("facility error string")
        .contains("credit facility issuance requires --receipt-db"));

    let bond_response = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": "missing-receipt-db-bond",
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send bond issue request without receipt db");
    assert_eq!(bond_response.status(), reqwest::StatusCode::CONFLICT);
    let bond_body: serde_json::Value = bond_response
        .json()
        .expect("parse missing receipt db bond error");
    assert!(bond_body["error"]
        .as_str()
        .expect("bond error string")
        .contains("credit bond issuance requires --receipt-db"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_trust_control_report_endpoints_require_service_auth() {
    let dir = unique_dir("chio-trust-report-auth");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "trust-report-auth-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    for path in [
        "/v1/reports/capital-book?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/facility-policy?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/facilities?agentSubject=auth-matrix&limit=10",
        "/v1/reports/bond-policy?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/bonds?agentSubject=auth-matrix&limit=10",
        "/v1/reports/credit-backtest?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/provider-risk-package?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/liability-providers?limit=10",
        "/v1/reports/liability-market?agentSubject=auth-matrix&limit=10",
        "/v1/reports/underwriting-input?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/underwriting-decision?agentSubject=auth-matrix&receiptLimit=10",
        "/v1/reports/underwriting-decisions?agentSubject=auth-matrix&limit=10",
    ] {
        assert_trust_service_auth_required(&client, &base_url, path);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_trust_control_report_endpoints_require_receipt_db_configuration() {
    let dir = unique_dir("chio-trust-report-missing-receipt-db");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "trust-report-receipt-db-token";
    let _service = spawn_trust_service_without_receipt_db(
        listen,
        service_token,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    for (path, status, expected_error_fragment) in [
        (
            "/v1/reports/capital-book?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/facility-policy?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "credit facility evaluation requires --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/facilities?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/bond-policy?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "credit bond evaluation requires --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/bonds?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/credit-backtest?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "credit backtests require --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/provider-risk-package?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::CONFLICT,
            "provider risk package export requires --receipt-db on the trust-control service",
        ),
        (
            "/v1/reports/liability-providers?limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/liability-market?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
        (
            "/v1/reports/underwriting-input?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for underwriting input queries",
        ),
        (
            "/v1/reports/underwriting-decision?agentSubject=missing-receipt-db&receiptLimit=10",
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "trust service is missing receipt_db_path for underwriting decision queries",
        ),
        (
            "/v1/reports/underwriting-decisions?agentSubject=missing-receipt-db&limit=10",
            reqwest::StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ),
    ] {
        assert_trust_service_get_error(
            &client,
            &base_url,
            service_token,
            path,
            status,
            expected_error_fragment,
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_denies_missing_prerequisites() {
    let dir = unique_dir("chio-credit-facility-prerequisites");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(
                &make_governed_authorization_receipt_without_runtime_assurance(
                    "rc-facility-prereq-1",
                    "cap-facility-prereq-1",
                    "subject-facility-prereq-1",
                    "issuer-facility-prereq-1",
                    "ledger",
                    "transfer",
                    unix_now_secs().saturating_sub(60),
                    "USD",
                    4_200,
                ),
            )
            .expect("append credit facility prerequisite receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-prereq-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", "subject-facility-prereq-1"),
            ("toolServer", "ledger"),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit facility prerequisite request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditFacilityReport = response
        .json()
        .expect("parse credit facility prerequisite report");
    assert_eq!(
        report.disposition,
        chio_core::credit::CreditFacilityDisposition::Deny
    );
    assert!(report.terms.is_none());
    assert_eq!(
        report.prerequisites.minimum_runtime_assurance_tier,
        RuntimeAssuranceTier::Verified
    );
    assert!(!report.prerequisites.runtime_assurance_met);
    assert!(report.prerequisites.certification_required);
    assert!(!report.prerequisites.certification_met);
    let finding_codes = report
        .findings
        .iter()
        .map(|finding| finding.code)
        .collect::<Vec<_>>();
    assert!(finding_codes
        .contains(&chio_core::credit::CreditFacilityReasonCode::MissingRuntimeAssurance));
    assert!(finding_codes
        .contains(&chio_core::credit::CreditFacilityReasonCode::CertificationNotActive));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_manual_review_for_mixed_currency_book() {
    let dir = unique_dir("chio-credit-facility-mixed-currency");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-facility-mixed-1";
    let issuer_key = "issuer-facility-mixed-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..15_u64 {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-facility-mixed-usd-{day}"),
                    &format!("cap-facility-mixed-usd-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append usd facility receipt");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-facility-mixed-eur-{day}"),
                    &format!("cap-facility-mixed-eur-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 15) * 86_400),
                    SettlementStatus::Settled,
                    "EUR",
                    5_000,
                    "EUR",
                    false,
                    false,
                ))
                .expect("append eur facility receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-mixed-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "100"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-currency facility request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditFacilityReport = response
        .json()
        .expect("parse mixed-currency facility report");
    assert_eq!(
        report.disposition,
        chio_core::credit::CreditFacilityDisposition::ManualReview
    );
    assert!(report.terms.is_none());
    assert!(report.scorecard.mixed_currency_book);
    assert!(report.findings.iter().any(|finding| {
        finding.code == chio_core::credit::CreditFacilityReasonCode::MixedCurrencyBook
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_facility_report_manual_review_for_mixed_runtime_assurance_provenance() {
    let dir = unique_dir("chio-credit-facility-mixed-runtime-provenance");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-facility-mixed-runtime-1";
    let issuer_key = "issuer-facility-mixed-runtime-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..30_u64 {
            let (schema, family, verifier, evidence_sha) = if day % 2 == 0 {
                (
                    AZURE_MAA_ATTESTATION_SCHEMA,
                    Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                    "https://maa.chio.example",
                    "sha256-mixed-runtime-azure",
                )
            } else {
                (
                    GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
                    Some(chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation),
                    "https://confidentialcomputing.googleapis.com",
                    "sha256-mixed-runtime-google",
                )
            };
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_runtime_profile(
                    &format!("rc-facility-mixed-runtime-{day}"),
                    &format!("cap-facility-mixed-runtime-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_500,
                    "USD",
                    false,
                    false,
                    schema,
                    family,
                    RuntimeAssuranceTier::Verified,
                    verifier,
                    evidence_sha,
                ))
                .expect("append mixed runtime provenance receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-facility-mixed-runtime-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/facility-policy"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "100"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-runtime-provenance facility request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditFacilityReport = response
        .json()
        .expect("parse mixed-runtime-provenance facility report");
    assert_eq!(
        report.disposition,
        chio_core::credit::CreditFacilityDisposition::ManualReview
    );
    assert!(report.terms.is_none());
    assert!(report.findings.iter().any(|finding| {
        finding.code == chio_core::credit::CreditFacilityReasonCode::MixedRuntimeAssuranceProvenance
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_backtest_report_surfaces_drift_and_failure_modes() {
    let dir = unique_dir("chio-credit-backtest");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-backtest-1";
    let issuer_key = "issuer-credit-backtest-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 46..=59_u64 {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-backtest-good-{day}"),
                    &format!("cap-backtest-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    true,
                ))
                .expect("append good backtest receipt");
        }
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-pending-no-runtime-1",
                "cap-backtest-pending-no-runtime-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(35 * 86_400),
                SettlementStatus::Pending,
                "USD",
                20_000,
                "USD",
                false,
            ))
            .expect("append first pending backtest receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-pending-no-runtime-2",
                "cap-backtest-pending-no-runtime-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(34 * 86_400),
                SettlementStatus::Pending,
                "USD",
                20_000,
                "USD",
                false,
            ))
            .expect("append second pending backtest receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-mixed-usd",
                "cap-backtest-mixed-usd",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(23 * 86_400),
                SettlementStatus::Settled,
                "USD",
                4_000,
                "USD",
                true,
            ))
            .expect("append mixed usd receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-mixed-eur",
                "cap-backtest-mixed-eur",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(22 * 86_400),
                SettlementStatus::Settled,
                "EUR",
                4_000,
                "EUR",
                true,
            ))
            .expect("append mixed eur receipt");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-backtest-stale",
                "cap-backtest-stale",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(10 * 86_400),
                SettlementStatus::Settled,
                "USD",
                4_000,
                "USD",
                true,
            ))
            .expect("append stale backtest receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-backtest-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/credit-backtest"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
            ("windowSeconds", "1296000"),
            ("windowCount", "4"),
            ("staleAfterSeconds", "432000"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit backtest request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: CreditBacktestReport = response.json().expect("parse credit backtest report");
    assert_eq!(report.schema, "chio.credit.backtest-report.v1");
    assert_eq!(report.summary.windows_evaluated, 4);
    assert!(report.summary.stale_evidence_windows >= 1);
    assert!(report.summary.mixed_currency_windows >= 1);
    assert!(report.summary.over_utilized_windows >= 1);
    let reason_codes = report
        .windows
        .iter()
        .flat_map(|window| window.reason_codes.iter().copied())
        .collect::<Vec<_>>();
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::MissingRuntimeAssurance));
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::MixedCurrencyBook));
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::StaleEvidence));
    assert!(reason_codes.contains(&chio_kernel::CreditBacktestReasonCode::FacilityOverUtilization));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "credit-backtest",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "200",
            "--decision-limit",
            "50",
            "--window-seconds",
            "1296000",
            "--window-count",
            "4",
            "--stale-after-seconds",
            "432000",
        ])
        .output()
        .expect("run credit backtest CLI");
    assert!(
        cli_output.status.success(),
        "credit backtest CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditBacktestReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit backtest CLI");
    assert_eq!(cli_report.summary.windows_evaluated, 4);
    assert!(cli_report.summary.drift_windows >= 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bond_issue_and_list_surfaces() {
    let dir = unique_dir("chio-credit-bond-lock");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-bond-lock-1";
    let issuer_key = "issuer-credit-bond-lock-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-lock-good-{day}"),
                    &format!("cap-bond-lock-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append good bond receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-bond-lock-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue bond backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let issued_facility: SignedCreditFacility = facility_issue
        .json()
        .expect("parse issued bond backing facility");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bond-lock-pending-1",
                "cap-bond-lock-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending bond receipt");
    }

    let evaluate_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit bond evaluate request");
    assert_eq!(evaluate_response.status(), reqwest::StatusCode::OK);
    let evaluate_report: CreditBondReport = evaluate_response
        .json()
        .expect("parse credit bond evaluate report");
    assert_eq!(evaluate_report.schema, "chio.credit.bond-report.v1");
    assert_eq!(
        evaluate_report.disposition,
        chio_core::credit::CreditBondDisposition::Lock
    );
    assert_eq!(
        evaluate_report.latest_facility_id.as_deref(),
        Some(issued_facility.body.facility_id.as_str())
    );
    assert!(evaluate_report.terms.is_some());
    assert!(evaluate_report
        .findings
        .iter()
        .any(|finding| { finding.code == chio_core::credit::CreditBondReasonCode::ReserveLocked }));

    let first_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue first bond");
    assert_eq!(first_issue.status(), reqwest::StatusCode::OK);
    let first_bond: SignedCreditBond = first_issue.json().expect("parse first bond");
    assert_eq!(first_bond.body.schema, "chio.credit.bond.v1");
    assert_eq!(
        first_bond.body.report.disposition,
        chio_core::credit::CreditBondDisposition::Lock
    );
    assert_eq!(
        first_bond.body.lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Active
    );

    let second_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            },
            "supersedesBondId": first_bond.body.bond_id
        }))
        .send()
        .expect("issue superseding bond");
    assert_eq!(second_issue.status(), reqwest::StatusCode::OK);
    let second_bond: SignedCreditBond = second_issue.json().expect("parse second bond");
    assert_eq!(
        second_bond.body.supersedes_bond_id.as_deref(),
        Some(first_bond.body.bond_id.as_str())
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bonds"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send credit bond list request");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditBondListReport =
        list_response.json().expect("parse credit bond list report");
    assert_eq!(list_report.schema, "chio.credit.bond-list.v1");
    assert_eq!(list_report.summary.matching_bonds, 2);
    assert_eq!(list_report.summary.active_bonds, 1);
    assert_eq!(list_report.summary.superseded_bonds, 1);
    assert_eq!(list_report.summary.locked_bonds, 2);
    let first_row = list_report
        .bonds
        .iter()
        .find(|row| row.bond.body.bond_id == first_bond.body.bond_id)
        .expect("first bond row");
    assert_eq!(
        first_row.lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Superseded
    );
    let second_row = list_report
        .bonds
        .iter()
        .find(|row| row.bond.body.bond_id == second_bond.body.bond_id)
        .expect("second bond row");
    assert_eq!(
        second_row.lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Active
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "bond",
            "list",
            "--agent-subject",
            subject_key,
            "--limit",
            "10",
        ])
        .output()
        .expect("run credit bond list CLI");
    assert!(
        cli_output.status.success(),
        "credit bond list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditBondListReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit bond CLI list");
    assert_eq!(cli_report.summary.matching_bonds, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bond_report_hold_and_release_semantics() {
    let dir = unique_dir("chio-credit-bond-hold-release");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let hold_subject = "subject-credit-bond-hold-1";
    let release_subject = "subject-credit-bond-release-1";
    let issuer_key = "issuer-credit-bond-hold-release-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-hold-{day}"),
                    &format!("cap-bond-hold-{day}"),
                    hold_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append hold history");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-release-{day}"),
                    &format!("cap-bond-release-{day}"),
                    release_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append release history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-bond-hold-release-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": hold_subject,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue hold facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    let hold_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", hold_subject),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send hold bond request");
    assert_eq!(hold_response.status(), reqwest::StatusCode::OK);
    let hold_report: CreditBondReport = hold_response.json().expect("parse hold bond report");
    assert_eq!(
        hold_report.disposition,
        chio_core::credit::CreditBondDisposition::Hold
    );
    assert!(hold_report
        .findings
        .iter()
        .any(|finding| { finding.code == chio_core::credit::CreditBondReasonCode::ReserveHeld }));

    let release_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", release_subject),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send release bond request");
    assert_eq!(release_response.status(), reqwest::StatusCode::OK);
    let release_report: CreditBondReport =
        release_response.json().expect("parse release bond report");
    assert_eq!(
        release_report.disposition,
        chio_core::credit::CreditBondDisposition::Release
    );
    assert!(release_report.latest_facility_id.is_none());
    assert!(release_report.findings.iter().any(|finding| {
        finding.code == chio_core::credit::CreditBondReasonCode::ReserveReleased
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bond_report_impairs_and_fails_closed_on_mixed_currency() {
    let dir = unique_dir("chio-credit-bond-impair-mixed");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let impair_subject = "subject-credit-bond-impair-1";
    let mixed_subject = "subject-credit-bond-mixed-1";
    let issuer_key = "issuer-credit-bond-impair-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-impair-good-{day}"),
                    &format!("cap-bond-impair-good-{day}"),
                    impair_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append impair good history");
        }
        for day in 0..15_u64 {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-mixed-usd-{day}"),
                    &format!("cap-bond-mixed-usd-{day}"),
                    mixed_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append mixed usd history");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bond-mixed-eur-{day}"),
                    &format!("cap-bond-mixed-eur-{day}"),
                    mixed_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 20) * 86_400),
                    SettlementStatus::Settled,
                    "EUR",
                    4_000,
                    "EUR",
                    false,
                    false,
                ))
                .expect("append mixed eur history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-bond-impair-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": impair_subject,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue impair backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bond-impair-failed-1",
                "cap-bond-impair-failed-1",
                impair_subject,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed impair receipt");
    }

    let impair_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", impair_subject),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send impair bond request");
    assert_eq!(impair_response.status(), reqwest::StatusCode::OK);
    let impair_report: CreditBondReport = impair_response.json().expect("parse impair bond report");
    assert_eq!(
        impair_report.disposition,
        chio_core::credit::CreditBondDisposition::Impair
    );
    let impair_codes = impair_report
        .findings
        .iter()
        .map(|finding| finding.code)
        .collect::<Vec<_>>();
    assert!(
        impair_codes.contains(&chio_core::credit::CreditBondReasonCode::FailedSettlementBacklog)
    );
    assert!(
        impair_codes.contains(&chio_core::credit::CreditBondReasonCode::ProvisionalLossOutstanding)
    );

    let mixed_response = client
        .get(format!("{base_url}/v1/reports/bond-policy"))
        .query(&[
            ("agentSubject", mixed_subject),
            ("receiptLimit", "100"),
            ("decisionLimit", "50"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-currency bond request");
    assert_eq!(mixed_response.status(), reqwest::StatusCode::CONFLICT);
    let mixed_body: serde_json::Value = mixed_response
        .json()
        .expect("parse mixed-currency bond error");
    assert!(mixed_body["error"]
        .as_str()
        .expect("mixed currency error string")
        .contains("does not auto-net reserve accounting across currencies"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_loss_lifecycle_issue_and_list_surfaces() {
    let dir = unique_dir("chio-credit-loss-lifecycle");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-loss-1";
    let issuer_key = "issuer-credit-loss-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-loss-good-{day}"),
                    &format!("cap-loss-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append good loss history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-loss-lifecycle-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue loss backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue active bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse active bond");
    let bond_id = bond.body.bond_id.clone();

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-loss-failed-1",
                "cap-loss-failed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed loss receipt");
    }

    let evaluate_response = client
        .get(format!("{base_url}/v1/reports/bond-loss-policy"))
        .query(&[("bondId", bond_id.as_str()), ("eventKind", "delinquency")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send loss lifecycle evaluate request");
    let evaluate_status = evaluate_response.status();
    let evaluate_body = evaluate_response.text().expect("read loss lifecycle body");
    assert_eq!(
        evaluate_status,
        reqwest::StatusCode::OK,
        "loss lifecycle evaluate failed: {evaluate_body}"
    );
    let evaluate_report: CreditLossLifecycleReport =
        serde_json::from_str(&evaluate_body).expect("parse loss lifecycle report");
    assert_eq!(
        evaluate_report.schema,
        "chio.credit.loss-lifecycle-report.v1"
    );
    assert_eq!(
        evaluate_report.query.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::Delinquency
    );
    assert_eq!(
        evaluate_report.summary.projected_bond_lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Impaired
    );
    assert_eq!(
        evaluate_report
            .summary
            .event_amount
            .as_ref()
            .expect("delinquency amount")
            .units,
        8_500
    );

    let issue_response = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "delinquency"
            }
        }))
        .send()
        .expect("issue delinquency lifecycle event");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let event: SignedCreditLossLifecycle =
        issue_response.json().expect("parse loss lifecycle event");
    assert_eq!(event.body.schema, "chio.credit.loss-lifecycle.v1");
    assert_eq!(
        event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::Delinquency
    );
    assert_eq!(
        event.body.projected_bond_lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Impaired
    );

    let bond_list = client
        .get(format!("{base_url}/v1/reports/bonds"))
        .query(&[("bondId", event.body.bond_id.as_str()), ("limit", "5")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list bond after delinquency");
    assert_eq!(bond_list.status(), reqwest::StatusCode::OK);
    let bond_report: CreditBondListReport = bond_list.json().expect("parse bond list");
    assert_eq!(bond_report.summary.matching_bonds, 1);
    assert_eq!(
        bond_report.bonds[0].lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Impaired
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bond-losses"))
        .query(&[("bondId", event.body.bond_id.as_str()), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send loss lifecycle list request");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditLossLifecycleListReport =
        list_response.json().expect("parse loss lifecycle list");
    assert_eq!(list_report.schema, "chio.credit.loss-lifecycle-list.v1");
    assert_eq!(list_report.summary.matching_events, 1);
    assert_eq!(list_report.summary.delinquency_events, 1);
    assert_eq!(
        list_report.events[0].event.body.event_id,
        event.body.event_id
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "loss",
            "list",
            "--bond-id",
            event.body.bond_id.as_str(),
            "--limit",
            "10",
        ])
        .output()
        .expect("run credit loss lifecycle list CLI");
    assert!(
        cli_output.status.success(),
        "credit loss lifecycle list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditLossLifecycleListReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse credit loss lifecycle CLI list");
    assert_eq!(cli_report.summary.matching_events, 1);
    assert_eq!(cli_report.summary.reserve_slash_events, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_loss_lifecycle_recovery_write_off_and_release_fail_closed() {
    let dir = unique_dir("chio-credit-loss-lifecycle-release");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-loss-release-1";
    let issuer_key = "issuer-credit-loss-release-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-loss-release-good-{day}"),
                    &format!("cap-loss-release-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append good release history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-loss-release-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let _facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue release backing facility");

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue release bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse release bond");
    let bond_id = bond.body.bond_id.clone();
    let reserve_amount = bond
        .body
        .report
        .terms
        .as_ref()
        .expect("release bond terms")
        .reserve_requirement_amount
        .clone();

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-loss-release-failed-1",
                "cap-loss-release-failed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed release receipt");
    }

    let delinquency_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "delinquency"
            }
        }))
        .send()
        .expect("issue delinquency before release");
    let delinquency_status = delinquency_issue.status();
    let delinquency_body = delinquency_issue
        .text()
        .expect("read delinquency lifecycle body");
    assert_eq!(
        delinquency_status,
        reqwest::StatusCode::OK,
        "delinquency issue failed: {delinquency_body}"
    );

    let premature_release = client
        .get(format!("{base_url}/v1/reports/bond-loss-policy"))
        .query(&[
            ("bondId", bond_id.as_str()),
            ("eventKind", "reserve_release"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("evaluate premature reserve release");
    assert_eq!(premature_release.status(), reqwest::StatusCode::CONFLICT);
    let premature_release_body: serde_json::Value = premature_release
        .json()
        .expect("parse premature reserve release error");
    assert!(premature_release_body["error"]
        .as_str()
        .expect("premature reserve release error string")
        .contains("cleared first"));

    let recovery_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "recovery",
                "amount": {
                    "units": 3_500,
                    "currency": "USD"
                }
            }
        }))
        .send()
        .expect("issue recovery event");
    assert_eq!(recovery_issue.status(), reqwest::StatusCode::OK);

    let excessive_write_off = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "write_off",
                "amount": {
                    "units": 6_000,
                    "currency": "USD"
                }
            }
        }))
        .send()
        .expect("issue excessive write-off");
    assert_eq!(excessive_write_off.status(), reqwest::StatusCode::CONFLICT);

    let write_off_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "write_off",
                "amount": {
                    "units": 5_000,
                    "currency": "USD"
                }
            }
        }))
        .send()
        .expect("issue write-off event");
    assert_eq!(write_off_issue.status(), reqwest::StatusCode::OK);
    let write_off_event: SignedCreditLossLifecycle =
        write_off_issue.json().expect("parse write-off event");
    assert_eq!(
        write_off_event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::WriteOff
    );

    let release_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_release"
            }
        }))
        .send()
        .expect("issue reserve release event without execution metadata");
    assert_eq!(release_issue.status(), reqwest::StatusCode::BAD_REQUEST);
    let release_issue_body: serde_json::Value = release_issue
        .json()
        .expect("parse reserve release metadata error");
    assert!(release_issue_body["error"]
        .as_str()
        .expect("reserve release metadata error")
        .contains("requires executionWindow"));

    let release_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_release"
            },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-release-manual-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "reserve-book-main"
            },
            "observedExecution": {
                "observedAt": now,
                "externalReferenceId": "reserve-release-wire-1",
                "amount": reserve_amount.clone()
            },
            "appealWindowEndsAt": now.saturating_add(1_800),
            "description": "operator reserve release after cleared delinquency"
        }))
        .send()
        .expect("issue reserve release event");
    assert_eq!(release_issue.status(), reqwest::StatusCode::OK);
    let release_event: SignedCreditLossLifecycle =
        release_issue.json().expect("parse reserve release event");
    assert_eq!(
        release_event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::ReserveRelease
    );
    assert_eq!(
        release_event.body.projected_bond_lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Released
    );
    assert_eq!(
        release_event.body.reserve_control_source_id.as_deref(),
        Some(format!("capital-source:bond:{bond_id}").as_str())
    );
    assert_eq!(
        release_event.body.execution_state,
        Some(chio_core::credit::CreditReserveControlExecutionState::Executed)
    );
    assert_eq!(
        release_event.body.reconciled_state,
        Some(CapitalExecutionReconciledState::Matched)
    );
    assert_eq!(
        release_event.body.appeal_state,
        Some(chio_core::credit::CreditReserveControlAppealState::Open)
    );
    assert_eq!(
        release_event.body.appeal_window_ends_at,
        Some(now.saturating_add(1_800))
    );
    assert_eq!(release_event.body.authority_chain.len(), 2);
    assert_eq!(
        release_event
            .body
            .rail
            .as_ref()
            .map(|rail| rail.custody_provider_id.as_str()),
        Some("custodian-1")
    );
    assert_eq!(
        release_event.body.description.as_deref(),
        Some("operator reserve release after cleared delinquency")
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bond-losses"))
        .query(&[("bondId", bond_id.as_str()), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list release lifecycle events");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditLossLifecycleListReport =
        list_response.json().expect("parse release lifecycle list");
    assert_eq!(list_report.summary.matching_events, 4);
    assert_eq!(list_report.summary.delinquency_events, 1);
    assert_eq!(list_report.summary.recovery_events, 1);
    assert_eq!(list_report.summary.write_off_events, 1);
    assert_eq!(list_report.summary.reserve_release_events, 1);
    assert_eq!(list_report.summary.reserve_slash_events, 0);

    let bond_list = client
        .get(format!("{base_url}/v1/reports/bonds"))
        .query(&[("bondId", bond_id.as_str()), ("limit", "5")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list bond after reserve release");
    assert_eq!(bond_list.status(), reqwest::StatusCode::OK);
    let bond_report: CreditBondListReport = bond_list.json().expect("parse released bond list");
    assert_eq!(
        bond_report.bonds[0].lifecycle_state,
        chio_core::credit::CreditBondLifecycleState::Released
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_loss_lifecycle_reserve_slash_requires_valid_execution_metadata() {
    let dir = unique_dir("chio-credit-loss-lifecycle-slash");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-credit-loss-slash-1";
    let issuer_key = "issuer-credit-loss-slash-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-loss-slash-good-{day}"),
                    &format!("cap-loss-slash-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append good slash history");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "credit-loss-slash-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue slash backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue slash bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse slash bond");
    let bond_id = bond.body.bond_id.clone();

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-loss-slash-failed-1",
                "cap-loss-slash-failed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed slash receipt");
    }

    let delinquency_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "delinquency"
            }
        }))
        .send()
        .expect("issue slash delinquency");
    assert_eq!(delinquency_issue.status(), reqwest::StatusCode::OK);

    let missing_metadata = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_slash"
            }
        }))
        .send()
        .expect("issue reserve slash without metadata");
    assert_eq!(missing_metadata.status(), reqwest::StatusCode::BAD_REQUEST);
    let missing_metadata_body: serde_json::Value = missing_metadata
        .json()
        .expect("parse reserve slash metadata error");
    assert!(missing_metadata_body["error"]
        .as_str()
        .expect("reserve slash metadata error")
        .contains("requires executionWindow"));

    let stale_authority = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_slash"
            },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(100),
                    "expiresAt": now.saturating_sub(10)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(100),
                    "expiresAt": now.saturating_sub(10)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-slash-manual-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "reserve-book-main"
            }
        }))
        .send()
        .expect("issue reserve slash with stale authority");
    assert_eq!(stale_authority.status(), reqwest::StatusCode::CONFLICT);
    let stale_authority_body: serde_json::Value = stale_authority
        .json()
        .expect("parse stale reserve slash response");
    assert!(stale_authority_body["error"]
        .as_str()
        .expect("stale reserve slash error")
        .contains("stale"));

    let slash_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "reserve_slash",
                "amount": {
                    "units": 500,
                    "currency": "USD"
                }
            },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-slash-manual-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "reserve-book-main"
            },
            "appealWindowEndsAt": now.saturating_add(1_800),
            "description": "operator reserve slash against outstanding delinquency"
        }))
        .send()
        .expect("issue reserve slash event");
    assert_eq!(slash_issue.status(), reqwest::StatusCode::OK);
    let slash_event: SignedCreditLossLifecycle =
        slash_issue.json().expect("parse reserve slash event");
    assert_eq!(
        slash_event.body.event_kind,
        chio_core::credit::CreditLossLifecycleEventKind::ReserveSlash
    );
    assert_eq!(
        slash_event
            .body
            .report
            .summary
            .event_amount
            .as_ref()
            .expect("slash amount")
            .units,
        500
    );
    assert_eq!(
        slash_event.body.execution_state,
        Some(chio_core::credit::CreditReserveControlExecutionState::PendingExecution)
    );
    assert_eq!(
        slash_event.body.reconciled_state,
        Some(CapitalExecutionReconciledState::NotObserved)
    );
    assert_eq!(
        slash_event.body.appeal_state,
        Some(chio_core::credit::CreditReserveControlAppealState::Open)
    );
    assert_eq!(
        slash_event.body.reserve_control_source_id.as_deref(),
        Some(format!("capital-source:bond:{bond_id}").as_str())
    );
    assert_eq!(slash_event.body.authority_chain.len(), 2);
    assert_eq!(
        slash_event.body.description.as_deref(),
        Some("operator reserve slash against outstanding delinquency")
    );

    let list_response = client
        .get(format!("{base_url}/v1/reports/bond-losses"))
        .query(&[("bondId", bond_id.as_str()), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list slash lifecycle events");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: CreditLossLifecycleListReport =
        list_response.json().expect("parse slash lifecycle list");
    assert_eq!(list_report.summary.matching_events, 2);
    assert_eq!(list_report.summary.delinquency_events, 1);
    assert_eq!(list_report.summary.reserve_slash_events, 1);
    assert_eq!(list_report.summary.reserve_release_events, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_credit_bonded_execution_simulation_report_surfaces() {
    let dir = unique_dir("chio-credit-bonded-execution-simulation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let kill_switch_policy_file = dir.join("bonded-execution-kill-switch.yaml");

    let subject_key = "subject-credit-bonded-execution-1";
    let issuer_key = "issuer-credit-bonded-execution-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-bonded-execution-good-{day}"),
                    &format!("cap-bonded-execution-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append bonded execution history");
        }
    }

    let kill_switch_policy = chio_kernel::CreditBondedExecutionControlPolicy {
        version: "chio.credit.bonded-execution-control-policy.kill-switch.v1".to_string(),
        kill_switch: true,
        maximum_autonomy_tier: Some(GovernedAutonomyTier::Delegated),
        minimum_runtime_assurance_tier: Some(RuntimeAssuranceTier::Attested),
        require_delegated_call_chain: true,
        require_locked_reserve: false,
        deny_if_bond_not_active: true,
        deny_if_outstanding_delinquency: true,
    };
    std::fs::write(
        &kill_switch_policy_file,
        serde_yml::to_string(&kill_switch_policy).expect("serialize kill switch policy"),
    )
    .expect("write kill switch policy");

    let listen = reserve_listen_addr();
    let service_token = "credit-bonded-execution-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue bonded execution facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bonded-execution-pending-1",
                "cap-bonded-execution-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                6_500,
                "USD",
                true,
            ))
            .expect("append pending bonded execution receipt");
    }

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue bonded execution bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse bonded execution bond");
    let bond_id = bond.body.bond_id.clone();

    let simulation_response = client
        .post(format!("{base_url}/v1/reports/bonded-execution-simulation"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "autonomyTier": "delegated",
                "runtimeAssuranceTier": "attested",
                "callChainPresent": true
            },
            "policy": kill_switch_policy
        }))
        .send()
        .expect("send bonded execution simulation request");
    assert_eq!(simulation_response.status(), reqwest::StatusCode::OK);
    let simulation_report: CreditBondedExecutionSimulationReport = simulation_response
        .json()
        .expect("parse bonded execution simulation report");
    assert_eq!(
        simulation_report.schema,
        "chio.credit.bonded-execution-simulation-report.v1"
    );
    assert_eq!(
        simulation_report.default_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Allow
    );
    assert!(
        simulation_report
            .default_evaluation
            .sandbox_integration_ready
    );
    assert_eq!(
        simulation_report.simulated_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Deny
    );
    assert!(simulation_report.delta.decision_changed);
    assert!(simulation_report
        .delta
        .added_reasons
        .contains(&"kill_switch_enabled".to_string()));
    assert!(simulation_report
        .simulated_evaluation
        .findings
        .iter()
        .any(|finding| {
            finding.code == chio_kernel::CreditBondedExecutionFindingCode::KillSwitchEnabled
        }));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "bond",
            "simulate",
            "--bond-id",
            bond_id.as_str(),
            "--autonomy-tier",
            "delegated",
            "--runtime-assurance-tier",
            "attested",
            "--call-chain-present",
            "--policy-file",
            kill_switch_policy_file
                .to_str()
                .expect("kill switch policy path"),
        ])
        .output()
        .expect("run bonded execution simulation CLI");
    assert!(
        cli_output.status.success(),
        "bonded execution simulation CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: CreditBondedExecutionSimulationReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse bonded execution CLI report");
    assert_eq!(
        cli_report.simulated_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Deny
    );

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-bonded-execution-failed-1",
                "cap-bonded-execution-failed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(30),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed bonded execution receipt");
    }

    let delinquency_issue = client
        .post(format!("{base_url}/v1/bond-losses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "eventKind": "delinquency"
            }
        }))
        .send()
        .expect("issue bonded execution delinquency");
    assert_eq!(delinquency_issue.status(), reqwest::StatusCode::OK);
    let delinquency_event: SignedCreditLossLifecycle = delinquency_issue
        .json()
        .expect("parse bonded execution delinquency");

    let impaired_response = client
        .post(format!("{base_url}/v1/reports/bonded-execution-simulation"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "bondId": bond_id.as_str(),
                "autonomyTier": "delegated",
                "runtimeAssuranceTier": "attested",
                "callChainPresent": true
            },
            "policy": chio_kernel::CreditBondedExecutionControlPolicy::default()
        }))
        .send()
        .expect("send impaired bonded execution simulation request");
    assert_eq!(impaired_response.status(), reqwest::StatusCode::OK);
    let impaired_report: CreditBondedExecutionSimulationReport = impaired_response
        .json()
        .expect("parse impaired bonded execution simulation report");
    assert_eq!(
        impaired_report.simulated_evaluation.decision,
        chio_kernel::CreditBondedExecutionDecision::Deny
    );
    assert_eq!(
        impaired_report
            .simulated_evaluation
            .outstanding_delinquency_amount
            .as_ref()
            .expect("outstanding delinquency amount")
            .units,
        8_500
    );
    let delinquency_finding = impaired_report
        .simulated_evaluation
        .findings
        .iter()
        .find(|finding| {
            finding.code == chio_kernel::CreditBondedExecutionFindingCode::OutstandingDelinquency
        })
        .expect("outstanding delinquency finding");
    assert!(delinquency_finding
        .evidence_refs
        .iter()
        .any(|reference| { reference.reference_id == delinquency_event.body.event_id }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_provider_risk_package_export_surfaces() {
    let dir = unique_dir("chio-provider-risk-package");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-provider-risk-1";
    let issuer_key = "issuer-provider-risk-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-risk-good-{day}"),
                    &format!("cap-risk-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    true,
                ))
                .expect("append provider risk receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "provider-risk-package-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let issue_response = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue provider facility");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let issued_facility: SignedCreditFacility = issue_response
        .json()
        .expect("parse issued provider facility");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-risk-loss-1",
                "cap-risk-loss-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append provider risk loss receipt");
    }

    let response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send provider risk package request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: SignedCreditProviderRiskPackage =
        response.json().expect("parse signed provider risk package");
    assert!(report
        .verify_signature()
        .expect("verify provider risk package signature"));
    assert_eq!(report.body.schema, "chio.credit.provider-risk-package.v1");
    assert_eq!(report.body.subject_key, subject_key);
    assert!(report
        .body
        .exposure
        .verify_signature()
        .expect("verify nested exposure signature"));
    assert!(report
        .body
        .scorecard
        .verify_signature()
        .expect("verify nested scorecard signature"));
    assert!(report.body.recent_loss_history.summary.returned_loss_events >= 1);
    assert_eq!(
        report.body.recent_loss_history.entries[0].receipt_id,
        "rc-risk-loss-1"
    );
    assert_eq!(
        report.body.recent_loss_history.entries[0].settlement_status,
        SettlementStatus::Failed
    );
    assert!(!report.body.evidence_refs.is_empty());
    let latest_facility = report
        .body
        .latest_facility
        .as_ref()
        .expect("latest facility snapshot");
    assert_eq!(
        latest_facility.facility_id,
        issued_facility.body.facility_id
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "provider-risk-package",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "200",
            "--decision-limit",
            "50",
            "--recent-loss-limit",
            "5",
        ])
        .output()
        .expect("run provider risk package CLI");
    assert!(
        cli_output.status.success(),
        "provider risk package CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedCreditProviderRiskPackage =
        serde_json::from_slice(&cli_output.stdout).expect("parse provider risk package CLI");
    assert!(cli_report
        .verify_signature()
        .expect("verify provider risk package CLI signature"));
    assert!(
        cli_report
            .body
            .recent_loss_history
            .summary
            .returned_loss_events
            >= 1
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_book_report_export_surfaces() {
    let dir = unique_dir("chio-capital-book");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-capital-book-1";
    let issuer_key = "issuer-capital-book-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-good-{day}"),
                    &format!("cap-capital-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append capital history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-book-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue capital facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let issued_facility: SignedCreditFacility = facility_issue
        .json()
        .expect("parse issued capital facility");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-capital-pending-1",
                "cap-capital-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending capital receipt");
    }

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue capital bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued capital bond");
    assert_eq!(
        issued_bond.body.report.disposition,
        chio_core::credit::CreditBondDisposition::Lock
    );

    let delinquency = record_test_credit_loss_event_with_kind(
        &receipt_db_path,
        &issued_bond,
        "cll-capital-delinquency-1",
        CreditLossLifecycleEventKind::Delinquency,
        500,
        CreditBondLifecycleState::Impaired,
        CreditLossLifecycleReasonCode::DelinquencyRecorded,
        "capital delinquency event",
    );
    let recovery = record_test_credit_loss_event_with_kind(
        &receipt_db_path,
        &issued_bond,
        "cll-capital-recovery-1",
        CreditLossLifecycleEventKind::Recovery,
        200,
        CreditBondLifecycleState::Impaired,
        CreditLossLifecycleReasonCode::RecoveryRecorded,
        "capital recovery event",
    );
    let reserve_release = record_test_credit_loss_event_with_kind(
        &receipt_db_path,
        &issued_bond,
        "cll-capital-release-1",
        CreditLossLifecycleEventKind::ReserveRelease,
        50,
        CreditBondLifecycleState::Released,
        CreditLossLifecycleReasonCode::ReserveReleased,
        "capital reserve release event",
    );

    let response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send capital book request");
    let status = response.status();
    let response_body = response.text().expect("read capital book response body");
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {response_body}"
    );
    let report: SignedCapitalBookReport =
        serde_json::from_str(&response_body).expect("parse signed capital book");
    assert!(report
        .verify_signature()
        .expect("verify capital book signature"));
    assert_eq!(report.body.schema, "chio.credit.capital-book.v1");
    assert_eq!(report.body.subject_key, subject_key);
    assert_eq!(report.body.summary.funding_sources, 2);
    assert_eq!(report.body.summary.matching_loss_events, 3);
    assert_eq!(report.body.summary.currencies, vec!["USD".to_string()]);

    let facility_source = report
        .body
        .sources
        .iter()
        .find(|source| {
            source.facility_id.as_deref() == Some(issued_facility.body.facility_id.as_str())
        })
        .expect("facility source");
    assert_eq!(
        facility_source.kind,
        chio_core::credit::CapitalBookSourceKind::FacilityCommitment
    );
    assert_eq!(
        facility_source.owner_role,
        chio_core::credit::CapitalBookRole::OperatorTreasury
    );
    assert!(facility_source
        .committed_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));
    assert!(facility_source
        .drawn_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));
    assert!(facility_source
        .disbursed_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));

    let reserve_source = report
        .body
        .sources
        .iter()
        .find(|source| {
            source.kind == chio_core::credit::CapitalBookSourceKind::ReserveBook
                && source.bond_id.as_deref() == Some(issued_bond.body.bond_id.as_str())
        })
        .expect("reserve source");
    assert_eq!(
        reserve_source.kind,
        chio_core::credit::CapitalBookSourceKind::ReserveBook
    );
    assert!(reserve_source
        .held_amount
        .as_ref()
        .is_some_and(|amount| amount.units > 0));
    assert_eq!(
        reserve_source
            .released_amount
            .as_ref()
            .expect("released amount")
            .units,
        50
    );
    assert_eq!(
        reserve_source
            .repaid_amount
            .as_ref()
            .expect("repaid amount")
            .units,
        200
    );
    assert_eq!(
        reserve_source
            .impaired_amount
            .as_ref()
            .expect("impaired amount")
            .units,
        300
    );

    let event_kinds = report
        .body
        .events
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Commit));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Hold));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Draw));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Disburse));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Impair));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Repay));
    assert!(event_kinds.contains(&chio_core::credit::CapitalBookEventKind::Release));
    assert!(report
        .body
        .events
        .iter()
        .any(|event| event.loss_event_id.as_deref() == Some(delinquency.body.event_id.as_str())));
    assert!(report
        .body
        .events
        .iter()
        .any(|event| event.loss_event_id.as_deref() == Some(recovery.body.event_id.as_str())));
    assert!(report.body.events.iter().any(
        |event| event.loss_event_id.as_deref() == Some(reserve_release.body.event_id.as_str())
    ));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "capital-book",
            "export",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "200",
            "--facility-limit",
            "10",
            "--bond-limit",
            "10",
            "--loss-event-limit",
            "10",
        ])
        .output()
        .expect("run capital book CLI");
    assert!(
        cli_output.status.success(),
        "capital book CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: SignedCapitalBookReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse capital book CLI");
    assert!(cli_report
        .verify_signature()
        .expect("verify capital book CLI signature"));
    assert_eq!(cli_report.body.summary.funding_sources, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_book_report_rejects_mixed_currency_and_missing_counterparty() {
    let dir = unique_dir("chio-capital-book-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-capital-book-negative-1";
    let issuer_key = "issuer-capital-book-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..15_u64 {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-negative-usd-{day}"),
                    &format!("cap-capital-negative-usd-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub(day * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append usd negative capital receipt");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-negative-eur-{day}"),
                    &format!("cap-capital-negative-eur-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 20) * 86_400),
                    SettlementStatus::Settled,
                    "EUR",
                    4_000,
                    "EUR",
                    false,
                    false,
                ))
                .expect("append eur negative capital receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-book-negative-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let mixed_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "100"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send mixed-currency capital book request");
    assert_eq!(mixed_response.status(), reqwest::StatusCode::CONFLICT);
    let mixed_body: serde_json::Value = mixed_response
        .json()
        .expect("parse mixed-currency capital book response");
    assert!(mixed_body["error"]
        .as_str()
        .expect("mixed-currency error")
        .contains("one coherent currency"));

    let missing_counterparty = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[("receiptLimit", "100")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send missing-counterparty capital book request");
    assert_eq!(
        missing_counterparty.status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let missing_body: serde_json::Value = missing_counterparty
        .json()
        .expect("parse missing-counterparty capital book response");
    assert!(missing_body["error"]
        .as_str()
        .expect("missing-counterparty error")
        .contains("--agent-subject"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_instruction_issue_surfaces() {
    let dir = unique_dir("chio-capital-instruction");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let input_file = dir.join("capital-instruction.json");

    let subject_key = "subject-capital-instruction-1";
    let issuer_key = "issuer-capital-instruction-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-instruction-good-{day}"),
                    &format!("cap-capital-instruction-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append capital instruction history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-instruction-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-capital-instruction-pending-1",
                "cap-capital-instruction-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending capital receipt");
    }

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");
    let reserve_amount = issued_bond
        .body
        .report
        .terms
        .as_ref()
        .expect("bond terms")
        .reserve_requirement_amount
        .clone();

    let request_json = serde_json::json!({
        "query": {
            "agentSubject": subject_key,
            "receiptLimit": 200,
            "facilityLimit": 10,
            "bondLimit": 10,
            "lossEventLimit": 10
        },
        "sourceKind": "reserve_book",
        "action": "lock_reserve",
        "amount": reserve_amount.clone(),
        "authorityChain": [
            {
                "role": "operator_treasury",
                "principalId": "treasury-1",
                "approvedAt": now.saturating_sub(30),
                "expiresAt": now.saturating_add(3_600)
            },
            {
                "role": "custodian",
                "principalId": "custodian-1",
                "approvedAt": now.saturating_sub(20),
                "expiresAt": now.saturating_add(3_600)
            }
        ],
        "executionWindow": {
            "notBefore": now.saturating_sub(60),
            "notAfter": now.saturating_add(3_600)
        },
        "rail": {
            "kind": "manual",
            "railId": "reserve-manual-1",
            "custodyProviderId": "custodian-1",
            "sourceAccountRef": "reserve-book-main"
        },
        "observedExecution": {
            "observedAt": now,
            "externalReferenceId": "wire-1",
            "amount": reserve_amount.clone()
        }
    });

    let response = client
        .post(format!("{base_url}/v1/capital/instructions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&request_json)
        .send()
        .expect("issue capital instruction");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let instruction: SignedCapitalExecutionInstruction =
        response.json().expect("parse capital instruction");
    assert!(instruction
        .verify_signature()
        .expect("verify capital instruction signature"));
    assert_eq!(
        instruction.body.schema,
        "chio.credit.capital-instruction.v1"
    );
    assert_eq!(instruction.body.subject_key, subject_key);
    assert_eq!(
        instruction.body.action,
        CapitalExecutionInstructionAction::LockReserve
    );
    assert_eq!(
        instruction.body.source_kind,
        chio_core::credit::CapitalBookSourceKind::ReserveBook
    );
    assert_eq!(
        instruction.body.intended_state,
        CapitalExecutionIntendedState::PendingExecution
    );
    assert_eq!(
        instruction.body.reconciled_state,
        CapitalExecutionReconciledState::Matched
    );
    assert_eq!(instruction.body.authority_chain.len(), 2);
    assert!(instruction
        .body
        .evidence_refs
        .iter()
        .any(|evidence| evidence.reference_id == issued_bond.body.bond_id));

    std::fs::write(
        &input_file,
        serde_json::to_vec_pretty(&request_json).expect("serialize capital instruction request"),
    )
    .expect("write capital instruction request");
    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "capital-instruction",
            "issue",
            "--input-file",
            input_file.to_str().expect("capital instruction input file"),
        ])
        .output()
        .expect("run capital instruction CLI");
    assert!(
        cli_output.status.success(),
        "capital instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_instruction: SignedCapitalExecutionInstruction =
        serde_json::from_slice(&cli_output.stdout).expect("parse capital instruction CLI");
    assert!(cli_instruction
        .verify_signature()
        .expect("verify capital instruction CLI signature"));
    assert_eq!(
        cli_instruction.body.action,
        CapitalExecutionInstructionAction::LockReserve
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_instruction_issue_rejects_stale_authority_and_mismatch() {
    let dir = unique_dir("chio-capital-instruction-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-capital-instruction-negative-1";
    let issuer_key = "issuer-capital-instruction-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-instruction-negative-{day}"),
                    &format!("cap-capital-instruction-negative-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append negative capital instruction history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-instruction-negative-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-capital-instruction-negative-pending-1",
                "cap-capital-instruction-negative-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending negative capital receipt");
    }

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");
    let reserve_amount = issued_bond
        .body
        .report
        .terms
        .as_ref()
        .expect("bond terms")
        .reserve_requirement_amount
        .clone();

    let stale_response = client
        .post(format!("{base_url}/v1/capital/instructions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "sourceKind": "reserve_book",
            "action": "release_reserve",
            "amount": reserve_amount.clone(),
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(100),
                    "expiresAt": now.saturating_sub(10)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(100),
                    "expiresAt": now.saturating_sub(10)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-manual-1",
                "custodyProviderId": "custodian-1"
            }
        }))
        .send()
        .expect("send stale capital instruction");
    assert_eq!(stale_response.status(), reqwest::StatusCode::CONFLICT);
    let stale_body: serde_json::Value = stale_response
        .json()
        .expect("parse stale capital instruction response");
    assert!(stale_body["error"]
        .as_str()
        .expect("stale capital instruction error")
        .contains("stale"));

    let mismatch_response = client
        .post(format!("{base_url}/v1/capital/instructions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "sourceKind": "reserve_book",
            "action": "lock_reserve",
            "amount": reserve_amount.clone(),
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "reserve-manual-1",
                "custodyProviderId": "custodian-1"
            },
            "observedExecution": {
                "observedAt": now,
                "externalReferenceId": "wire-mismatch-1",
                "amount": {
                    "units": reserve_amount.units + 1,
                    "currency": reserve_amount.currency.clone()
                }
            }
        }))
        .send()
        .expect("send mismatched capital instruction");
    assert_eq!(mismatch_response.status(), reqwest::StatusCode::CONFLICT);
    let mismatch_body: serde_json::Value = mismatch_response
        .json()
        .expect("parse mismatched capital instruction response");
    assert!(mismatch_body["error"]
        .as_str()
        .expect("mismatched capital instruction error")
        .contains("does not match intended amount"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_allocation_issue_surfaces() {
    let dir = unique_dir("chio-capital-allocation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let input_file = dir.join("capital-allocation.json");

    let subject_key = "subject-capital-allocation-1";
    let issuer_key = "issuer-capital-allocation-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-good-{day}"),
                    &format!("cap-capital-allocation-good-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append capital allocation history receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-allocation-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let issued_facility: SignedCreditFacility = facility_issue
        .json()
        .expect("parse issued capital allocation facility");

    let governed_receipt_id = "rc-capital-allocation-pending-1";
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                governed_receipt_id,
                "cap-capital-allocation-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                30_000,
                "USD",
                false,
                false,
            ))
            .expect("append governed pending receipt");
    }

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let issued_bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");

    let request_json = serde_json::json!({
        "query": {
            "agentSubject": subject_key,
            "receiptLimit": 200,
            "facilityLimit": 10,
            "bondLimit": 10,
            "lossEventLimit": 10
        },
        "receiptId": governed_receipt_id,
        "authorityChain": [
            {
                "role": "operator_treasury",
                "principalId": "treasury-1",
                "approvedAt": now.saturating_sub(30),
                "expiresAt": now.saturating_add(3_600)
            },
            {
                "role": "custodian",
                "principalId": "custodian-1",
                "approvedAt": now.saturating_sub(20),
                "expiresAt": now.saturating_add(3_600)
            }
        ],
        "executionWindow": {
            "notBefore": now.saturating_sub(60),
            "notAfter": now.saturating_add(3_600)
        },
        "rail": {
            "kind": "manual",
            "railId": "capital-allocation-manual-1",
            "custodyProviderId": "custodian-1",
            "sourceAccountRef": "operator-capital-main"
        },
        "description": "allocate governed capital for the selected receipt"
    });

    let response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&request_json)
        .send()
        .expect("issue capital allocation");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let allocation: SignedCapitalAllocationDecision =
        response.json().expect("parse capital allocation");
    assert!(allocation
        .verify_signature()
        .expect("verify capital allocation signature"));
    assert_eq!(allocation.body.schema, "chio.credit.capital-allocation.v1");
    assert_eq!(allocation.body.subject_key, subject_key);
    assert_eq!(allocation.body.governed_receipt_id, governed_receipt_id);
    assert_eq!(
        allocation.body.outcome,
        CapitalAllocationDecisionOutcome::Allocate
    );
    assert_eq!(
        allocation.body.source_kind,
        Some(CapitalBookSourceKind::FacilityCommitment)
    );
    assert_eq!(
        allocation.body.facility_id.as_deref(),
        Some(issued_facility.body.facility_id.as_str())
    );
    assert_eq!(
        allocation.body.bond_id.as_deref(),
        Some(issued_bond.body.bond_id.as_str())
    );
    assert!(allocation.body.source_id.is_some());
    assert!(allocation.body.reserve_source_id.is_some());
    assert!(allocation.body.findings.is_empty());
    assert!(allocation.body.instruction_drafts.iter().any(|draft| {
        draft.action == CapitalExecutionInstructionAction::TransferFunds
            && draft.amount.units == 30_000
            && draft.amount.currency == "USD"
    }));

    std::fs::write(
        &input_file,
        serde_json::to_vec_pretty(&request_json).expect("serialize capital allocation request"),
    )
    .expect("write capital allocation request");
    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "capital-allocation",
            "issue",
            "--input-file",
            input_file.to_str().expect("capital allocation input file"),
        ])
        .output()
        .expect("run capital allocation CLI");
    assert!(
        cli_output.status.success(),
        "capital allocation CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_allocation: SignedCapitalAllocationDecision =
        serde_json::from_slice(&cli_output.stdout).expect("parse capital allocation CLI");
    assert!(cli_allocation
        .verify_signature()
        .expect("verify capital allocation CLI signature"));
    assert_eq!(
        cli_allocation.body.outcome,
        CapitalAllocationDecisionOutcome::Allocate
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_capital_allocation_issue_fail_closed_and_boundary_outcomes() {
    let dir = unique_dir("chio-capital-allocation-boundaries");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let manual_subject = "subject-capital-allocation-manual-1";
    let queue_subject = "subject-capital-allocation-queue-1";
    let issuer_key = "issuer-capital-allocation-boundaries-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-manual-good-{day}"),
                    &format!("cap-capital-allocation-manual-good-{day}"),
                    manual_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append manual allocation history");
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-queue-good-{day}"),
                    &format!("cap-capital-allocation-queue-good-{day}"),
                    queue_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    100,
                    "USD",
                    false,
                    false,
                ))
                .expect("append queue allocation history");
        }
        // Preserve queue-depth boundary coverage without making every large-history fixture pay
        // for the full reserve-depth dataset.
        for day in LARGE_RECEIPT_HISTORY_LEN..CAPITAL_ALLOCATION_QUEUE_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-capital-allocation-queue-good-{day}"),
                    &format!("cap-capital-allocation-queue-good-{day}"),
                    queue_subject,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    100,
                    "USD",
                    false,
                    false,
                ))
                .expect("append queue allocation reserve depth");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "capital-allocation-boundaries-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    for subject_key in [manual_subject, queue_subject] {
        let facility_issue = client
            .post(format!("{base_url}/v1/facilities/issue"))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            )
            .json(&serde_json::json!({
                "query": {
                    "agentSubject": subject_key,
                    "receiptLimit": 200,
                    "decisionLimit": 50
                }
            }))
            .send()
            .expect("issue facility for subject");
        assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    }

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-capital-allocation-manual-pending-1",
                "cap-capital-allocation-manual-pending-1",
                manual_subject,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                30_000,
                "USD",
                false,
                false,
            ))
            .expect("append manual pending governed receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-capital-allocation-queue-pending-1",
                "cap-capital-allocation-queue-pending-1",
                queue_subject,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(120),
                SettlementStatus::Pending,
                "USD",
                50_000,
                "USD",
                false,
                false,
            ))
            .expect("append first queue pending receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-capital-allocation-queue-pending-2",
                "cap-capital-allocation-queue-pending-2",
                queue_subject,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                5_000,
                "USD",
                false,
                false,
            ))
            .expect("append second queue pending receipt");
    }

    let queue_bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": queue_subject,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue queue bond");
    assert_eq!(queue_bond_issue.status(), reqwest::StatusCode::OK);

    let manual_review_response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": manual_subject,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "receiptId": "rc-capital-allocation-manual-pending-1",
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "capital-allocation-manual-boundary-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "operator-capital-main"
            }
        }))
        .send()
        .expect("issue manual-review capital allocation");
    assert_eq!(manual_review_response.status(), reqwest::StatusCode::OK);
    let manual_review: SignedCapitalAllocationDecision = manual_review_response
        .json()
        .expect("parse manual-review capital allocation");
    assert_eq!(
        manual_review.body.outcome,
        CapitalAllocationDecisionOutcome::ManualReview
    );
    assert!(manual_review.body.instruction_drafts.is_empty());
    assert!(manual_review.body.findings.iter().any(|finding| {
        finding.code == CapitalAllocationDecisionReasonCode::ReserveBookMissing
    }));

    let ambiguous_response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": queue_subject,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "capital-allocation-queue-boundary-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "operator-capital-main"
            }
        }))
        .send()
        .expect("issue ambiguous capital allocation");
    assert_eq!(ambiguous_response.status(), reqwest::StatusCode::CONFLICT);
    let ambiguous_body: serde_json::Value = ambiguous_response
        .json()
        .expect("parse ambiguous capital allocation body");
    assert!(ambiguous_body["error"]
        .as_str()
        .expect("ambiguous capital allocation error")
        .contains("multiple approved actionable governed receipts"));

    let queue_response = client
        .post(format!("{base_url}/v1/capital/allocations/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": queue_subject,
                "receiptLimit": 200,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "receiptId": "rc-capital-allocation-queue-pending-2",
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-1",
                    "approvedAt": now.saturating_sub(30),
                    "expiresAt": now.saturating_add(3_600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-1",
                    "approvedAt": now.saturating_sub(20),
                    "expiresAt": now.saturating_add(3_600)
                }
            ],
            "executionWindow": {
                "notBefore": now.saturating_sub(60),
                "notAfter": now.saturating_add(3_600)
            },
            "rail": {
                "kind": "manual",
                "railId": "capital-allocation-queue-boundary-1",
                "custodyProviderId": "custodian-1",
                "sourceAccountRef": "operator-capital-main"
            }
        }))
        .send()
        .expect("issue queued capital allocation");
    assert_eq!(queue_response.status(), reqwest::StatusCode::OK);
    let queued: SignedCapitalAllocationDecision = queue_response
        .json()
        .expect("parse queued capital allocation");
    assert_eq!(queued.body.outcome, CapitalAllocationDecisionOutcome::Queue);
    assert!(queued.body.instruction_drafts.is_empty());
    assert!(queued.body.findings.iter().any(|finding| {
        finding.code == CapitalAllocationDecisionReasonCode::UtilizationCeilingExceeded
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_provider_registry_issue_list_and_resolve_surfaces() {
    let dir = unique_dir("chio-liability-provider-registry");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "liability-provider-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let provider_report = serde_json::json!({
        "schema": "chio.market.provider.v1",
        "providerId": "carrier-alpha",
        "displayName": "Carrier Alpha",
        "providerType": "admitted_carrier",
        "providerUrl": "https://carrier-alpha.example.com",
        "lifecycleState": "active",
        "supportBoundary": {
            "curatedRegistryOnly": true,
            "automaticTrustAdmission": false,
            "permissionlessFederationSupported": false,
            "boundCoverageSupported": false
        },
        "policies": [
            {
                "jurisdiction": "us-ny",
                "coverageClasses": ["tool_execution", "regulatory_response"],
                "supportedCurrencies": ["USD"],
                "requiredEvidence": ["credit_provider_risk_package", "credit_bond"],
                "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                "claimsSupported": true,
                "quoteTtlSeconds": 3600
            },
            {
                "jurisdiction": "eu-de",
                "coverageClasses": ["professional_liability"],
                "supportedCurrencies": ["EUR"],
                "requiredEvidence": ["credit_provider_risk_package", "runtime_attestation_appraisal"],
                "maxCoverageAmount": { "units": 40000, "currency": "EUR" },
                "claimsSupported": true,
                "quoteTtlSeconds": 7200
            }
        ],
        "provenance": {
            "configuredBy": "operator@example.com",
            "configuredAt": unix_now_secs(),
            "sourceRef": "liability-runbook",
            "changeReason": "initial curated provider admission"
        }
    });

    let issue_response = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({ "report": provider_report }))
        .send()
        .expect("issue liability provider");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let issued: SignedLiabilityProvider = issue_response
        .json()
        .expect("parse issued liability provider");
    assert!(issued
        .verify_signature()
        .expect("verify liability provider signature"));
    assert_eq!(issued.body.report.provider_id, "carrier-alpha");

    let list_response = client
        .get(format!("{base_url}/v1/reports/liability-providers"))
        .query(&[
            ("providerId", "carrier-alpha"),
            ("coverageClass", "tool_execution"),
            ("currency", "usd"),
            ("limit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list liability providers");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let list_report: LiabilityProviderListReport =
        list_response.json().expect("parse liability provider list");
    assert_eq!(list_report.summary.matching_providers, 1);
    assert_eq!(
        list_report.providers[0].provider.body.provider_record_id,
        issued.body.provider_record_id
    );

    let resolve_response = client
        .get(format!("{base_url}/v1/liability/providers/resolve"))
        .query(&[
            ("providerId", "carrier-alpha"),
            ("jurisdiction", "us-ny"),
            ("coverageClass", "tool_execution"),
            ("currency", "USD"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("resolve liability provider");
    assert_eq!(resolve_response.status(), reqwest::StatusCode::OK);
    let resolve_report: LiabilityProviderResolutionReport = resolve_response
        .json()
        .expect("parse liability provider resolution");
    assert_eq!(resolve_report.matched_policy.jurisdiction, "us-ny");
    assert!(resolve_report
        .matched_policy
        .supported_currencies
        .iter()
        .any(|currency| currency == "USD"));

    let unsupported_response = client
        .get(format!("{base_url}/v1/liability/providers/resolve"))
        .query(&[
            ("providerId", "carrier-alpha"),
            ("jurisdiction", "us-ny"),
            ("coverageClass", "tool_execution"),
            ("currency", "EUR"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("resolve unsupported liability provider");
    assert_eq!(unsupported_response.status(), reqwest::StatusCode::CONFLICT);
    let unsupported_body: serde_json::Value = unsupported_response
        .json()
        .expect("parse unsupported resolution body");
    assert!(unsupported_body["error"]
        .as_str()
        .expect("error message")
        .contains("does not support"));

    let provider_file = dir.join("provider-beta.json");
    std::fs::write(
        &provider_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "chio.market.provider.v1",
            "providerId": "carrier-beta",
            "displayName": "Carrier Beta",
            "providerType": "risk_pool",
            "providerUrl": "https://carrier-beta.example.com",
            "lifecycleState": "active",
            "supportBoundary": {
                "curatedRegistryOnly": true,
                "automaticTrustAdmission": false,
                "permissionlessFederationSupported": false,
                "boundCoverageSupported": false
            },
            "policies": [
                {
                    "jurisdiction": "us-ca",
                    "coverageClasses": ["financial_loss"],
                    "supportedCurrencies": ["USD"],
                    "requiredEvidence": ["credit_provider_risk_package", "authorization_review_pack"],
                    "maxCoverageAmount": { "units": 75000, "currency": "USD" },
                    "claimsSupported": true,
                    "quoteTtlSeconds": 1800
                }
            ],
            "provenance": {
                "configuredBy": "operator@example.com",
                "configuredAt": unix_now_secs(),
                "sourceRef": "liability-runbook",
                "changeReason": "local CLI provider admission"
            }
        }))
        .expect("serialize provider input"),
    )
    .expect("write provider input");

    let cli_issue_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-provider",
            "issue",
            "--input-file",
            provider_file.to_str().expect("provider file path"),
        ])
        .output()
        .expect("run liability provider issue CLI");
    assert!(
        cli_issue_output.status.success(),
        "liability provider issue CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_issue_output.stdout),
        String::from_utf8_lossy(&cli_issue_output.stderr)
    );
    let cli_issued: SignedLiabilityProvider =
        serde_json::from_slice(&cli_issue_output.stdout).expect("parse liability provider CLI");
    assert_eq!(cli_issued.body.report.provider_id, "carrier-beta");

    let cli_resolve_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "liability-provider",
            "resolve",
            "--provider-id",
            "carrier-beta",
            "--jurisdiction",
            "us-ca",
            "--coverage-class",
            "financial_loss",
            "--currency",
            "USD",
        ])
        .output()
        .expect("run liability provider resolve CLI");
    assert!(
        cli_resolve_output.status.success(),
        "liability provider resolve CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_resolve_output.stdout),
        String::from_utf8_lossy(&cli_resolve_output.stderr)
    );
    let cli_resolved: LiabilityProviderResolutionReport =
        serde_json::from_slice(&cli_resolve_output.stdout)
            .expect("parse liability provider resolve CLI");
    assert_eq!(
        cli_resolved.provider.body.report.provider_id,
        "carrier-beta"
    );
    assert_eq!(cli_resolved.matched_policy.jurisdiction, "us-ca");

    let _ = std::fs::remove_dir_all(&dir);
}

fn run_large_stack_test(name: &str, test_fn: fn()) {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(test_fn)
        .expect("spawn large-stack test thread")
        .join()
        .expect("join large-stack test thread");
}

#[test]
fn test_liability_market_quote_and_bind_workflow_surfaces() {
    run_large_stack_test(
        "test_liability_market_quote_and_bind_workflow_surfaces",
        test_liability_market_quote_and_bind_workflow_surfaces_inner,
    );
}

fn test_liability_market_quote_and_bind_workflow_surfaces_inner() {
    let dir = unique_dir("chio-liability-market-workflow");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-1";
    let issuer_key = "issuer-liability-market-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-liability-market-{day}"),
                    &format!("cap-liability-market-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    true,
                ))
                .expect("append liability-market receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 120,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let _: SignedCreditFacility = facility_issue.json().expect("parse issued facility");

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "120"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-gamma",
                "displayName": "Carrier Gamma",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-gamma.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "phase 90 workflow qualification"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let _: SignedLiabilityProvider = provider_issue
        .json()
        .expect("parse issued liability provider");

    let requested_effective_from = unix_now_secs().saturating_add(7_200);
    let requested_effective_until = requested_effective_from.saturating_add(30 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-gamma",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 25000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue liability quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest =
        quote_request_response.json().expect("parse quote request");
    assert!(quote_request
        .verify_signature()
        .expect("verify quote request signature"));

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "providerQuoteRef": "carrier-gamma-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 25000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 1200, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    let quote_response_status = quote_response_response.status();
    let quote_response_body = quote_response_response
        .text()
        .expect("read quote response body");
    assert_eq!(
        quote_response_status,
        reqwest::StatusCode::OK,
        "quote response request failed with body: {quote_response_body}"
    );
    let quote_response: SignedLiabilityQuoteResponse =
        serde_json::from_str(&quote_response_body).expect("parse quote response");
    assert!(quote_response
        .verify_signature()
        .expect("verify quote response signature"));

    let placement_response = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": quote_response,
            "selectedCoverageAmount": { "units": 25000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 1200, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "placement-gamma-1"
        }))
        .send()
        .expect("issue liability placement");
    assert_eq!(placement_response.status(), reqwest::StatusCode::OK);
    let placement: SignedLiabilityPlacement = placement_response.json().expect("parse placement");
    assert!(placement
        .verify_signature()
        .expect("verify placement signature"));

    let bound_coverage_response = client
        .post(format!("{base_url}/v1/liability/bound-coverages/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "placement": placement,
            "policyNumber": "POL-GAMMA-1",
            "carrierReference": "bind-gamma-1",
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "coverageAmount": { "units": 25000, "currency": "USD" },
            "premiumAmount": { "units": 1200, "currency": "USD" }
        }))
        .send()
        .expect("issue bound coverage");
    assert_eq!(bound_coverage_response.status(), reqwest::StatusCode::OK);
    let bound_coverage: SignedLiabilityBoundCoverage = bound_coverage_response
        .json()
        .expect("parse bound coverage");
    assert!(bound_coverage
        .verify_signature()
        .expect("verify bound coverage signature"));

    let workflow_response = client
        .get(format!("{base_url}/v1/reports/liability-market"))
        .query(&[
            ("agentSubject", subject_key),
            ("coverageClass", "tool_execution"),
            ("currency", "USD"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("query liability market workflows");
    assert_eq!(workflow_response.status(), reqwest::StatusCode::OK);
    let workflow_report: LiabilityMarketWorkflowReport =
        workflow_response.json().expect("parse workflow report");
    assert_eq!(workflow_report.summary.matching_requests, 1);
    assert_eq!(workflow_report.summary.quote_responses, 1);
    assert_eq!(workflow_report.summary.quoted_responses, 1);
    assert_eq!(workflow_report.summary.placements, 1);
    assert_eq!(workflow_report.summary.bound_coverages, 1);
    let row = workflow_report.workflows.first().expect("workflow row");
    assert_eq!(
        row.quote_request.body.risk_package.body.subject_key,
        subject_key
    );
    assert_eq!(
        row.latest_quote_response
            .as_ref()
            .expect("latest response")
            .body
            .provider_quote_ref,
        "carrier-gamma-quote-1"
    );
    assert_eq!(
        row.bound_coverage
            .as_ref()
            .expect("bound coverage")
            .body
            .policy_number,
        "POL-GAMMA-1"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_market_pricing_authority_and_auto_bind_surfaces() {
    run_large_stack_test(
        "test_liability_market_pricing_authority_and_auto_bind_surfaces",
        test_liability_market_pricing_authority_and_auto_bind_surfaces_inner,
    );
}

fn test_liability_market_pricing_authority_and_auto_bind_surfaces_inner() {
    let dir = unique_dir("chio-liability-market-auto-bind");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-auto-bind-1";
    let issuer_key = "issuer-liability-market-auto-bind-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-liability-autobind-{day}"),
                    &format!("cap-liability-autobind-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append liability auto-bind receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-auto-bind-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let facility: SignedCreditFacility = facility_issue.json().expect("parse issued facility");
    assert_eq!(
        facility.body.report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant,
        "unexpected facility report: {:?}",
        facility.body.report
    );
    assert!(
        facility.body.report.terms.is_some(),
        "facility grant missing terms: {:?}",
        facility.body.report
    );

    let underwriting_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200
            }
        }))
        .send()
        .expect("issue underwriting decision");
    assert_eq!(underwriting_issue.status(), reqwest::StatusCode::OK);
    let underwriting_decision: SignedUnderwritingDecision = underwriting_issue
        .json()
        .expect("parse underwriting decision");
    let authority_max_premium = underwriting_decision
        .body
        .premium
        .quoted_amount
        .clone()
        .unwrap_or_else(|| MonetaryAmount {
            units: 25_000,
            currency: "USD".to_string(),
        });
    let quoted_premium_units = authority_max_premium.units.min(1_200);
    assert!(quoted_premium_units > 1);

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "20"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book");
    let capital_book_status = capital_book_response.status();
    let capital_book_body = capital_book_response
        .text()
        .expect("read capital book response body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book request failed with body: {capital_book_body}"
    );
    let capital_book: SignedCapitalBookReport =
        serde_json::from_str(&capital_book_body).expect("parse capital book");
    let facility_source = capital_book
        .body
        .sources
        .iter()
        .find(|source| source.facility_id.as_deref() == Some(facility.body.facility_id.as_str()))
        .expect("capital book facility source");
    let available_coverage_units = facility_source
        .committed_amount
        .as_ref()
        .expect("capital book committed amount")
        .units
        .saturating_sub(
            facility_source
                .disbursed_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        )
        .saturating_sub(
            facility_source
                .impaired_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        );
    let requested_coverage_units = available_coverage_units.min(25_000);
    assert!(requested_coverage_units > 0);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-theta",
                "displayName": "Carrier Theta",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-theta.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "phase 114 auto-bind qualification"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let _: SignedLiabilityProvider = provider_issue
        .json()
        .expect("parse issued liability provider");

    let requested_effective_from = unix_now_secs().saturating_add(7_200);
    let requested_effective_until = requested_effective_from.saturating_add(30 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-theta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue liability quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest =
        quote_request_response.json().expect("parse quote request");

    let pricing_authority_response = client
        .post(format!("{base_url}/v1/liability/pricing-authorities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "facility": facility,
            "underwritingDecision": underwriting_decision,
            "capitalBook": capital_book,
            "envelope": {
                "kind": "provider_delegate",
                "delegateId": "carrier-theta-underwriter"
            },
            "maxCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "maxPremiumAmount": authority_max_premium,
            "expiresAt": unix_now_secs().saturating_add(3000),
            "autoBindEnabled": true
        }))
        .send()
        .expect("issue pricing authority");
    assert_eq!(pricing_authority_response.status(), reqwest::StatusCode::OK);
    let pricing_authority: SignedLiabilityPricingAuthority = pricing_authority_response
        .json()
        .expect("parse pricing authority");
    assert!(pricing_authority
        .verify_signature()
        .expect("verify pricing authority signature"));

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": pricing_authority.body.quote_request.clone(),
            "providerQuoteRef": "carrier-theta-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
                "quotedPremiumAmount": { "units": quoted_premium_units, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    let quote_response_status = quote_response_response.status();
    let quote_response_body = quote_response_response
        .text()
        .expect("read quote response body");
    assert_eq!(
        quote_response_status,
        reqwest::StatusCode::OK,
        "quote response request failed with body: {quote_response_body}"
    );
    let quote_response: SignedLiabilityQuoteResponse =
        serde_json::from_str(&quote_response_body).expect("parse quote response");

    let auto_bind_response = client
        .post(format!("{base_url}/v1/liability/auto-bind/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "authority": pricing_authority.clone(),
            "quoteResponse": quote_response.clone(),
            "policyNumber": "POL-THETA-1",
            "carrierReference": "bind-theta-1",
            "placementRef": "placement-theta-auto-1"
        }))
        .send()
        .expect("issue liability auto-bind");
    let auto_bind_status = auto_bind_response.status();
    let auto_bind_body = auto_bind_response
        .text()
        .expect("read auto-bind response body");
    assert_eq!(
        auto_bind_status,
        reqwest::StatusCode::OK,
        "auto-bind request failed with body: {auto_bind_body}"
    );
    let auto_bind: SignedLiabilityAutoBindDecision =
        serde_json::from_str(&auto_bind_body).expect("parse auto-bind decision");
    assert!(auto_bind
        .verify_signature()
        .expect("verify auto-bind signature"));
    assert_eq!(
        auto_bind.body.disposition,
        chio_kernel::LiabilityAutoBindDisposition::AutoBound
    );
    assert!(auto_bind.body.placement.is_some());
    assert!(auto_bind.body.bound_coverage.is_some());

    let workflow_response = client
        .get(format!("{base_url}/v1/reports/liability-market"))
        .query(&[
            ("agentSubject", subject_key),
            ("coverageClass", "tool_execution"),
            ("currency", "USD"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("query liability market workflows");
    let workflow_status = workflow_response.status();
    let workflow_body = workflow_response
        .text()
        .expect("read workflow response body");
    assert_eq!(
        workflow_status,
        reqwest::StatusCode::OK,
        "workflow report request failed with body: {workflow_body}"
    );
    let workflow_report: serde_json::Value =
        serde_json::from_str(&workflow_body).expect("parse workflow report");
    assert_eq!(workflow_report["summary"]["matchingRequests"], 1);
    assert_eq!(workflow_report["summary"]["pricingAuthorities"], 1);
    assert_eq!(workflow_report["summary"]["autoBindDecisions"], 1);
    assert_eq!(workflow_report["summary"]["autoBoundDecisions"], 1);
    assert_eq!(workflow_report["summary"]["placements"], 1);
    assert_eq!(workflow_report["summary"]["boundCoverages"], 1);
    let row = workflow_report["workflows"]
        .as_array()
        .and_then(|rows| rows.first())
        .expect("workflow row");
    assert!(row["pricingAuthority"].is_object());
    assert!(row["latestAutoBindDecision"].is_object());
    assert_eq!(row["boundCoverage"]["body"]["policyNumber"], "POL-THETA-1");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes() {
    run_large_stack_test(
        "test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes",
        test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes_inner,
    );
}

fn test_liability_market_auto_bind_rejects_stale_provider_and_out_of_envelope_quotes_inner() {
    let dir = unique_dir("chio-liability-market-auto-bind-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-auto-bind-negative-1";
    let issuer_key = "issuer-liability-market-auto-bind-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            let exposure_units = if day < 10 { 100 } else { 5_000 };
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-liability-autobind-negative-{day}"),
                    &format!("cap-liability-autobind-negative-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    exposure_units,
                    "USD",
                    false,
                    false,
                ))
                .expect("append liability auto-bind negative receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-auto-bind-negative-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let initial_facility: SignedCreditFacility = facility_issue.json().expect("parse facility");
    let facility = {
        let issued_at = unix_now_secs();
        let mut report = initial_facility.body.report.clone();
        report.disposition = chio_core::credit::CreditFacilityDisposition::Grant;
        report.prerequisites.manual_review_required = false;
        report.terms = Some(chio_core::credit::CreditFacilityTerms {
            credit_limit: MonetaryAmount {
                units: 1_000_000,
                currency: "USD".to_string(),
            },
            utilization_ceiling_bps: 8_000,
            reserve_ratio_bps: 1_500,
            concentration_cap_bps: 3_000,
            ttl_seconds: 14 * 86_400,
            capital_source: chio_core::credit::CreditFacilityCapitalSource::OperatorInternal,
        });
        let artifact = chio_core::credit::CreditFacilityArtifact {
            schema: chio_core::credit::CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
            facility_id: format!("cfd-phase114-negative-{issued_at}"),
            issued_at,
            expires_at: issued_at.saturating_add(14 * 86_400),
            lifecycle_state: chio_core::credit::CreditFacilityLifecycleState::Active,
            supersedes_facility_id: Some(initial_facility.body.facility_id.clone()),
            report,
        };
        let signed = SignedCreditFacility::sign(artifact, &Keypair::generate())
            .expect("sign controlled grant facility");
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .record_credit_facility(&signed)
            .expect("record controlled grant facility");
        signed
    };

    let underwriting_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 200
            }
        }))
        .send()
        .expect("issue underwriting decision");
    assert_eq!(underwriting_issue.status(), reqwest::StatusCode::OK);
    let underwriting_decision: SignedUnderwritingDecision = underwriting_issue
        .json()
        .expect("parse underwriting decision");
    let authority_max_premium = underwriting_decision
        .body
        .premium
        .quoted_amount
        .clone()
        .unwrap_or_else(|| MonetaryAmount {
            units: 25_000,
            currency: "USD".to_string(),
        });
    let quoted_premium_units = authority_max_premium.units.min(1_200);
    assert!(quoted_premium_units > 1);

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book");
    let capital_book_status = capital_book_response.status();
    let capital_book_body = capital_book_response
        .text()
        .expect("read capital book response body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book request failed with body: {capital_book_body}"
    );
    let capital_book: SignedCapitalBookReport =
        serde_json::from_str(&capital_book_body).expect("parse capital book");
    let facility_source = capital_book
        .body
        .sources
        .iter()
        .find(|source| source.facility_id.as_deref() == Some(facility.body.facility_id.as_str()))
        .expect("capital book facility source");
    let available_coverage_units = facility_source
        .committed_amount
        .as_ref()
        .expect("capital book committed amount")
        .units
        .saturating_sub(
            facility_source
                .disbursed_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        )
        .saturating_sub(
            facility_source
                .impaired_amount
                .as_ref()
                .map_or(0, |amount| amount.units),
        );
    let requested_coverage_units = available_coverage_units.min(20_000);
    assert!(requested_coverage_units > 0);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "200"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-iota",
                "displayName": "Carrier Iota",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-iota.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "phase 114 auto-bind negative qualification"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let initial_provider: SignedLiabilityProvider =
        provider_issue.json().expect("parse initial provider");

    let requested_effective_from = unix_now_secs().saturating_add(3_600);
    let requested_effective_until = requested_effective_from.saturating_add(14 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-iota",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue liability quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest =
        quote_request_response.json().expect("parse quote request");

    let pricing_authority_response = client
        .post(format!("{base_url}/v1/liability/pricing-authorities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "facility": facility,
            "underwritingDecision": underwriting_decision,
            "capitalBook": capital_book,
            "envelope": {
                "kind": "provider_delegate",
                "delegateId": "carrier-iota-underwriter"
            },
            "maxCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
            "maxPremiumAmount": { "units": quoted_premium_units - 1, "currency": "USD" },
            "expiresAt": unix_now_secs().saturating_add(3000),
            "autoBindEnabled": true
        }))
        .send()
        .expect("issue pricing authority");
    assert_eq!(pricing_authority_response.status(), reqwest::StatusCode::OK);
    let pricing_authority: SignedLiabilityPricingAuthority = pricing_authority_response
        .json()
        .expect("parse pricing authority");

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": pricing_authority.body.quote_request.clone(),
            "providerQuoteRef": "carrier-iota-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": requested_coverage_units, "currency": "USD" },
                "quotedPremiumAmount": { "units": quoted_premium_units, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    assert_eq!(quote_response_response.status(), reqwest::StatusCode::OK);
    let quote_response: SignedLiabilityQuoteResponse = quote_response_response
        .json()
        .expect("parse quote response");

    let excessive_auto_bind = client
        .post(format!("{base_url}/v1/liability/auto-bind/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "authority": pricing_authority.clone(),
            "quoteResponse": quote_response.clone(),
            "policyNumber": "POL-IOTA-1"
        }))
        .send()
        .expect("issue excessive auto-bind");
    assert_eq!(excessive_auto_bind.status(), reqwest::StatusCode::CONFLICT);
    let excessive_body: serde_json::Value = excessive_auto_bind
        .json()
        .expect("parse excessive auto-bind body");
    assert!(excessive_body["error"]
        .as_str()
        .expect("excessive auto-bind error")
        .contains("pricing authority ceiling"));

    let superseding_provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-iota",
                "displayName": "Carrier Iota",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-iota.example.com/v2",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "superseding provider record"
                }
            },
            "supersedesProviderRecordId": initial_provider.body.provider_record_id
        }))
        .send()
        .expect("issue superseding provider");
    assert_eq!(superseding_provider_issue.status(), reqwest::StatusCode::OK);

    let stale_input_path = dir.join("stale-auto-bind.json");
    std::fs::write(
        &stale_input_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "authority": pricing_authority,
            "quoteResponse": quote_response,
            "policyNumber": "POL-IOTA-STALE-1"
        }))
        .expect("serialize stale auto-bind input"),
    )
    .expect("write stale auto-bind input");
    let stale_auto_bind = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "auto-bind-issue",
            "--input-file",
            stale_input_path.to_str().expect("stale input path"),
        ])
        .output()
        .expect("run stale auto-bind CLI");
    assert!(
        !stale_auto_bind.status.success(),
        "stale auto-bind CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stale_auto_bind.stdout),
        String::from_utf8_lossy(&stale_auto_bind.stderr)
    );
    let stale_stdout = String::from_utf8_lossy(&stale_auto_bind.stdout);
    let stale_stderr = String::from_utf8_lossy(&stale_auto_bind.stderr);
    assert!(
        stale_stderr.contains("stale provider record"),
        "unexpected stale auto-bind CLI failure\nstdout:\n{stale_stdout}\nstderr:\n{stale_stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch() {
    run_large_stack_test(
        "test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch",
        test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch_inner,
    );
}

fn test_liability_market_rejects_stale_provider_expired_quote_and_placement_mismatch_inner() {
    let dir = unique_dir("chio-liability-market-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-market-negative-1";
    let issuer_key = "issuer-liability-market-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-liability-negative-{day}"),
                    &format!("cap-liability-negative-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    5_000,
                    "USD",
                    true,
                ))
                .expect("append liability-negative receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-market-negative-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 90,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "90"),
            ("decisionLimit", "50"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-delta",
                "displayName": "Carrier Delta",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-delta.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "negative test provider admission"
                }
            }
        }))
        .send()
        .expect("issue liability provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let initial_provider: SignedLiabilityProvider = provider_issue
        .json()
        .expect("parse initial liability provider");

    let requested_effective_from = unix_now_secs().saturating_add(3_600);
    let requested_effective_until = requested_effective_from.saturating_add(14 * 86_400);
    let initial_quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-delta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 20000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue initial quote request");
    assert_eq!(
        initial_quote_request_response.status(),
        reqwest::StatusCode::OK
    );
    let initial_quote_request: SignedLiabilityQuoteRequest = initial_quote_request_response
        .json()
        .expect("parse initial quote request");

    let superseding_provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-delta",
                "displayName": "Carrier Delta",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-delta.example.com/v2",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-market-runbook",
                    "changeReason": "superseding provider record"
                }
            },
            "supersedesProviderRecordId": initial_provider.body.provider_record_id
        }))
        .send()
        .expect("issue superseding provider");
    assert_eq!(superseding_provider_issue.status(), reqwest::StatusCode::OK);

    let stale_quote_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": initial_quote_request,
            "providerQuoteRef": "carrier-delta-stale",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 20000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 900, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue stale quote response");
    assert_eq!(stale_quote_response.status(), reqwest::StatusCode::CONFLICT);
    let stale_body: serde_json::Value = stale_quote_response
        .json()
        .expect("parse stale response body");
    assert!(stale_body["error"]
        .as_str()
        .expect("stale response error")
        .contains("stale provider record"));

    let fresh_quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-delta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 22000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue fresh quote request");
    assert_eq!(
        fresh_quote_request_response.status(),
        reqwest::StatusCode::OK
    );
    let fresh_quote_request: SignedLiabilityQuoteRequest = fresh_quote_request_response
        .json()
        .expect("parse fresh quote request");

    let expiring_quote_expires_at = unix_now_secs().saturating_add(15);
    let expiring_quote_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": fresh_quote_request,
            "providerQuoteRef": "carrier-delta-expiring",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 22000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 950, "currency": "USD" },
                "expiresAt": expiring_quote_expires_at
            }
        }))
        .send()
        .expect("issue expiring quote response");
    assert_eq!(expiring_quote_response.status(), reqwest::StatusCode::OK);
    let expiring_quote_response: SignedLiabilityQuoteResponse = expiring_quote_response
        .json()
        .expect("parse expiring quote response");

    let sleep_until_expired = expiring_quote_response
        .body
        .quoted_terms
        .as_ref()
        .expect("expiring quote response should carry quoted terms")
        .expires_at
        .saturating_sub(unix_now_secs())
        .saturating_add(1);
    thread::sleep(Duration::from_secs(sleep_until_expired));

    let expired_placement = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": expiring_quote_response,
            "selectedCoverageAmount": { "units": 22000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 950, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "expired-placement"
        }))
        .send()
        .expect("issue expired placement");
    assert_eq!(expired_placement.status(), reqwest::StatusCode::CONFLICT);
    let expired_body: serde_json::Value = expired_placement
        .json()
        .expect("parse expired placement body");
    assert!(
        expired_body["error"]
            .as_str()
            .expect("expired placement error")
            .contains("quote expires")
            || expired_body["error"]
                .as_str()
                .expect("expired placement error")
                .contains("after the quote expires")
    );

    let mismatch_quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-delta",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 23000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue mismatch quote request");
    assert_eq!(
        mismatch_quote_request_response.status(),
        reqwest::StatusCode::OK
    );
    let mismatch_quote_request: SignedLiabilityQuoteRequest = mismatch_quote_request_response
        .json()
        .expect("parse mismatch quote request");

    let mismatch_quote_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": mismatch_quote_request,
            "providerQuoteRef": "carrier-delta-mismatch",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 23000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 975, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue mismatch quote response");
    assert_eq!(mismatch_quote_response.status(), reqwest::StatusCode::OK);
    let mismatch_quote_response: SignedLiabilityQuoteResponse = mismatch_quote_response
        .json()
        .expect("parse mismatch quote response");

    let mismatched_placement = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": mismatch_quote_response,
            "selectedCoverageAmount": { "units": 22000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 975, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "mismatched-placement"
        }))
        .send()
        .expect("issue mismatched placement");
    assert_eq!(mismatched_placement.status(), reqwest::StatusCode::CONFLICT);
    let mismatch_body: serde_json::Value = mismatched_placement
        .json()
        .expect("parse mismatched placement body");
    assert!(mismatch_body["error"]
        .as_str()
        .expect("mismatched placement error")
        .contains("must match"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_claim_workflow_surfaces() {
    run_large_stack_test(
        "test_liability_claim_workflow_surfaces",
        test_liability_claim_workflow_surfaces_inner,
    );
}

fn test_liability_claim_workflow_surfaces_inner() {
    let dir = unique_dir("chio-liability-claims-workflow");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-claims-1";
    let issuer_key = "issuer-liability-claims-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..LARGE_RECEIPT_HISTORY_LEN {
            store
                .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                    &format!("rc-liability-claims-{day}"),
                    &format!("cap-liability-claims-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    false,
                    false,
                ))
                .expect("append liability claim receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-claims-token";
    let mut service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue claim backing facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);
    let facility: SignedCreditFacility = facility_issue.json().expect("parse issued facility");
    assert_eq!(
        facility.body.report.disposition,
        chio_core::credit::CreditFacilityDisposition::Grant,
        "unexpected claim workflow facility report: {:?}",
        facility.body.report
    );
    assert!(
        facility.body.report.terms.is_some(),
        "claim workflow facility grant missing terms: {:?}",
        facility.body.report
    );

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-liability-claims-pending-1",
                "cap-liability-claims-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append pending claim receipt");
    }

    let exposure_response = client
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request exposure ledger");
    assert_eq!(exposure_response.status(), reqwest::StatusCode::OK);
    let exposure: SignedExposureLedgerReport = exposure_response
        .json()
        .expect("parse signed exposure ledger");

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue liability claim bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse issued bond");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-liability-claims-failed-1",
                "cap-liability-claims-failed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                8_500,
                "USD",
                true,
            ))
            .expect("append failed claim receipt");
    }

    let loss_event =
        record_test_credit_loss_event(&receipt_db_path, &bond, "cll-liability-claims-1", 8_500);

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse provider risk package");

    let capital_book_response = client
        .get(format!("{base_url}/v1/reports/capital-book"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("facilityLimit", "10"),
            ("bondLimit", "10"),
            ("lossEventLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request capital book report");
    let capital_book_status = capital_book_response.status();
    let capital_book_json = capital_book_response
        .text()
        .expect("read capital book report body");
    assert_eq!(
        capital_book_status,
        reqwest::StatusCode::OK,
        "capital book export failed with body: {capital_book_json}"
    );

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-claims",
                "displayName": "Carrier Claims",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-claims.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-claims-runbook",
                    "changeReason": "phase 91 workflow qualification"
                }
            }
        }))
        .send()
        .expect("issue liability claim provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);
    let _: SignedLiabilityProvider = provider_issue
        .json()
        .expect("parse issued liability provider");

    let requested_effective_from = unix_now_secs().saturating_add(7_200);
    let requested_effective_until = requested_effective_from.saturating_add(30 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-claims",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 25000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue liability quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest =
        quote_request_response.json().expect("parse quote request");

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "providerQuoteRef": "carrier-claims-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 25000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 1200, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue liability quote response");
    assert_eq!(quote_response_response.status(), reqwest::StatusCode::OK);
    let quote_response: SignedLiabilityQuoteResponse = quote_response_response
        .json()
        .expect("parse quote response");

    let placement_response = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": quote_response,
            "selectedCoverageAmount": { "units": 25000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 1200, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "placement-claims-1"
        }))
        .send()
        .expect("issue liability placement");
    assert_eq!(placement_response.status(), reqwest::StatusCode::OK);
    let placement: SignedLiabilityPlacement = placement_response.json().expect("parse placement");

    let bound_coverage_response = client
        .post(format!("{base_url}/v1/liability/bound-coverages/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "placement": placement,
            "policyNumber": "POL-CLAIMS-1",
            "carrierReference": "bind-claims-1",
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "coverageAmount": { "units": 25000, "currency": "USD" },
            "premiumAmount": { "units": 1200, "currency": "USD" }
        }))
        .send()
        .expect("issue bound coverage");
    assert_eq!(bound_coverage_response.status(), reqwest::StatusCode::OK);
    let bound_coverage: SignedLiabilityBoundCoverage = bound_coverage_response
        .json()
        .expect("parse bound coverage");

    let claim_response = client
        .post(format!("{base_url}/v1/liability/claims/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "boundCoverage": bound_coverage,
            "exposure": exposure,
            "bond": bond,
            "lossEvent": loss_event,
            "claimant": "acme@example.com",
            "claimEventAt": requested_effective_from.saturating_add(600),
            "claimAmount": { "units": 20000, "currency": "USD" },
            "claimRef": "CLAIM-1",
            "narrative": "tool execution loss package",
            "receiptIds": ["rc-liability-claims-0", "rc-liability-claims-failed-1"]
        }))
        .send()
        .expect("issue liability claim");
    assert_eq!(claim_response.status(), reqwest::StatusCode::OK);
    let claim: SignedLiabilityClaimPackage = claim_response.json().expect("parse claim package");
    assert!(claim.verify_signature().expect("verify claim signature"));

    let claim_response_issue = client
        .post(format!("{base_url}/v1/liability/claim-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "claim": claim,
            "providerResponseRef": "claims-response-1",
            "disposition": "accepted",
            "coveredAmount": { "units": 15000, "currency": "USD" },
            "responseNote": "partial acceptance"
        }))
        .send()
        .expect("issue claim response");
    assert_eq!(claim_response_issue.status(), reqwest::StatusCode::OK);
    let provider_response: SignedLiabilityClaimResponse =
        claim_response_issue.json().expect("parse claim response");
    assert!(provider_response
        .verify_signature()
        .expect("verify claim response signature"));

    let dispute_issue = match client
        .post(format!("{base_url}/v1/liability/disputes/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerResponse": provider_response,
            "openedBy": "insured@example.com",
            "reason": "remaining loss not covered",
            "note": "requesting neutral review"
        }))
        .send()
    {
        Ok(response) => response,
        Err(error) => {
            let status = service
                .child
                .try_wait()
                .expect("poll trust service after dispute failure");
            let stderr = read_child_stderr(&mut service.child);
            panic!(
                "issue claim dispute: {error:?}\nservice_status: {status:?}\nservice_stderr:\n{stderr}"
            );
        }
    };
    assert_eq!(dispute_issue.status(), reqwest::StatusCode::OK);
    let dispute: SignedLiabilityClaimDispute = dispute_issue.json().expect("parse claim dispute");
    assert!(dispute
        .verify_signature()
        .expect("verify dispute signature"));

    let adjudication_input_path = dir.join("liability-adjudication.json");
    std::fs::write(
        &adjudication_input_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "dispute": dispute,
            "adjudicator": "arbiter@example.com",
            "outcome": "partial_settlement",
            "awardedAmount": { "units": 18000, "currency": "USD" },
            "note": "additional evidence supports a larger settlement"
        }))
        .expect("serialize adjudication input"),
    )
    .expect("write adjudication input");

    drop(service);

    let adjudication_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "adjudication-issue",
            "--input-file",
            adjudication_input_path
                .to_str()
                .expect("adjudication input path"),
        ])
        .output()
        .expect("run liability adjudication CLI");
    assert!(
        adjudication_output.status.success(),
        "liability adjudication CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&adjudication_output.stdout),
        String::from_utf8_lossy(&adjudication_output.stderr)
    );
    let adjudication_json =
        String::from_utf8(adjudication_output.stdout).expect("adjudication CLI json");
    assert!(adjudication_json.contains("\"adjudicationId\""));

    let governed_receipt_id = "rc-liability-claims-payout-1";
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                governed_receipt_id,
                "cap-liability-claims-payout-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(30),
                SettlementStatus::Settled,
                "USD",
                18_000,
                "USD",
                false,
                false,
            ))
            .expect("append settled payout governed receipt");
    }

    let capital_instruction_input_path = dir.join("liability-payout-capital-instruction.json");
    std::fs::write(
        &capital_instruction_input_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 1000,
                "facilityLimit": 10,
                "bondLimit": 10,
                "lossEventLimit": 10
            },
            "sourceKind": "facility_commitment",
            "action": "transfer_funds",
            "governedReceiptId": governed_receipt_id,
            "amount": { "units": 18000, "currency": "USD" },
            "authorityChain": [
                {
                    "role": "operator_treasury",
                    "principalId": "treasury-claims-1",
                    "approvedAt": unix_now_secs().saturating_sub(30),
                    "expiresAt": unix_now_secs().saturating_add(3600)
                },
                {
                    "role": "custodian",
                    "principalId": "custodian-claims-1",
                    "approvedAt": unix_now_secs().saturating_sub(20),
                    "expiresAt": unix_now_secs().saturating_add(3600)
                }
            ],
            "executionWindow": {
                "notBefore": unix_now_secs().saturating_sub(60),
                "notAfter": unix_now_secs().saturating_add(3600)
            },
            "rail": {
                "kind": "manual",
                "railId": "claim-payout-manual-1",
                "custodyProviderId": "custodian-claims-1",
                "sourceAccountRef": "facility-claims-main"
            },
            "description": "automatic claim payout transfer"
        }))
        .expect("serialize payout capital instruction"),
    )
    .expect("write payout capital instruction");

    let capital_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "capital-instruction",
            "issue",
            "--input-file",
            capital_instruction_input_path
                .to_str()
                .expect("payout capital instruction path"),
        ])
        .output()
        .expect("run payout capital instruction CLI");
    assert!(
        capital_instruction_output.status.success(),
        "payout capital instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&capital_instruction_output.stdout),
        String::from_utf8_lossy(&capital_instruction_output.stderr)
    );
    let capital_instruction_json =
        String::from_utf8(capital_instruction_output.stdout).expect("capital instruction json");
    assert!(capital_instruction_json.contains("\"instructionId\""));
    assert!(capital_instruction_json.contains("\"transfer_funds\""));
    assert!(capital_instruction_json.contains("\"facility_commitment\""));

    let payout_instruction_input_path = dir.join("liability-payout-instruction.json");
    std::fs::write(
        &payout_instruction_input_path,
        format!(
            "{{\n  \"adjudication\": {adjudication_json},\n  \"capitalInstruction\": {capital_instruction_json},\n  \"note\": \"execute the adjudicated automatic payout\"\n}}\n"
        ),
    )
    .expect("write payout instruction input");

    let payout_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-payout-instruction-issue",
            "--input-file",
            payout_instruction_input_path
                .to_str()
                .expect("payout instruction input path"),
        ])
        .output()
        .expect("run payout instruction CLI");
    assert!(
        payout_instruction_output.status.success(),
        "payout instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&payout_instruction_output.stdout),
        String::from_utf8_lossy(&payout_instruction_output.stderr)
    );
    let payout_instruction_json =
        String::from_utf8(payout_instruction_output.stdout).expect("payout instruction json");
    assert!(payout_instruction_json.contains("\"payoutInstructionId\""));

    let payout_receipt_input_path = dir.join("liability-payout-receipt.json");
    std::fs::write(
        &payout_receipt_input_path,
        format!(
            "{{\n  \"payoutInstruction\": {payout_instruction_json},\n  \"payoutReceiptRef\": \"claim-payout-confirmation-1\",\n  \"reconciliationState\": \"matched\",\n  \"observedExecution\": {{\n    \"observedAt\": {},\n    \"externalReferenceId\": \"claim-payout-wire-1\",\n    \"amount\": {{ \"units\": 18000, \"currency\": \"USD\" }}\n  }},\n  \"note\": \"custodian matched the payout transfer\"\n}}\n",
            unix_now_secs()
        ),
    )
    .expect("write payout receipt input");

    let payout_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-payout-receipt-issue",
            "--input-file",
            payout_receipt_input_path
                .to_str()
                .expect("payout receipt input path"),
        ])
        .output()
        .expect("run payout receipt CLI");
    assert!(
        payout_receipt_output.status.success(),
        "payout receipt CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&payout_receipt_output.stdout),
        String::from_utf8_lossy(&payout_receipt_output.stderr)
    );
    let payout_receipt_json =
        String::from_utf8(payout_receipt_output.stdout).expect("payout receipt json");
    assert!(payout_receipt_json.contains("\"payoutReceiptId\""));
    assert!(payout_receipt_json.contains("\"matched\""));

    let stale_settlement_instruction_input_path =
        dir.join("liability-stale-settlement-instruction.json");
    std::fs::write(
        &stale_settlement_instruction_input_path,
        format!(
            "{{\n  \"payoutReceipt\": {payout_receipt_json},\n  \"capitalBook\": {capital_book_json},\n  \"settlementKind\": \"facility_reimbursement\",\n  \"settlementAmount\": {{ \"units\": 18000, \"currency\": \"USD\" }},\n  \"topology\": {{\n    \"payer\": {{ \"role\": \"facility_provider\", \"partyId\": \"facility-provider-claims-1\" }},\n    \"payee\": {{ \"role\": \"operator_treasury\", \"partyId\": \"operator-treasury-claims-1\" }},\n    \"beneficiary\": {{ \"role\": \"agent_counterparty\", \"partyId\": \"acme@example.com\" }}\n  }},\n  \"authorityChain\": [\n    {{\n      \"role\": \"facility_provider\",\n      \"principalId\": \"facility-provider-claims-1\",\n      \"approvedAt\": {},\n      \"expiresAt\": {}\n    }},\n    {{\n      \"role\": \"custodian\",\n      \"principalId\": \"custodian-claims-1\",\n      \"approvedAt\": {},\n      \"expiresAt\": {}\n    }}\n  ],\n  \"executionWindow\": {{\n    \"notBefore\": {},\n    \"notAfter\": {}\n  }},\n  \"rail\": {{\n    \"kind\": \"wire\",\n    \"railId\": \"claims-settlement-wire-1\",\n    \"custodyProviderId\": \"custodian-claims-1\",\n    \"sourceAccountRef\": \"facility-provider-recovery-1\"\n  }},\n  \"settlementReference\": \"facility-recovery-reference-1\",\n  \"note\": \"reimburse the operator treasury after claim payout\"\n}}\n",
            unix_now_secs().saturating_sub(600),
            unix_now_secs().saturating_sub(10),
            unix_now_secs().saturating_sub(60),
            unix_now_secs().saturating_add(3600),
            unix_now_secs().saturating_sub(120),
            unix_now_secs().saturating_add(3600)
        ),
    )
    .expect("write stale settlement instruction input");

    let stale_settlement_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-instruction-issue",
            "--input-file",
            stale_settlement_instruction_input_path
                .to_str()
                .expect("stale settlement instruction input path"),
        ])
        .output()
        .expect("run stale settlement instruction CLI");
    assert!(
        !stale_settlement_instruction_output.status.success(),
        "stale settlement instruction CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stale_settlement_instruction_output.stdout),
        String::from_utf8_lossy(&stale_settlement_instruction_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&stale_settlement_instruction_output.stderr).contains("stale"),
        "unexpected stale settlement instruction stderr\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stale_settlement_instruction_output.stdout),
        String::from_utf8_lossy(&stale_settlement_instruction_output.stderr)
    );

    let settlement_instruction_input_path = dir.join("liability-settlement-instruction.json");
    std::fs::write(
        &settlement_instruction_input_path,
        format!(
            "{{\n  \"payoutReceipt\": {payout_receipt_json},\n  \"capitalBook\": {capital_book_json},\n  \"settlementKind\": \"facility_reimbursement\",\n  \"settlementAmount\": {{ \"units\": 18000, \"currency\": \"USD\" }},\n  \"topology\": {{\n    \"payer\": {{ \"role\": \"facility_provider\", \"partyId\": \"facility-provider-claims-1\" }},\n    \"payee\": {{ \"role\": \"operator_treasury\", \"partyId\": \"operator-treasury-claims-1\" }},\n    \"beneficiary\": {{ \"role\": \"agent_counterparty\", \"partyId\": \"acme@example.com\" }}\n  }},\n  \"authorityChain\": [\n    {{\n      \"role\": \"facility_provider\",\n      \"principalId\": \"facility-provider-claims-1\",\n      \"approvedAt\": {},\n      \"expiresAt\": {}\n    }},\n    {{\n      \"role\": \"custodian\",\n      \"principalId\": \"custodian-claims-1\",\n      \"approvedAt\": {},\n      \"expiresAt\": {}\n    }}\n  ],\n  \"executionWindow\": {{\n    \"notBefore\": {},\n    \"notAfter\": {}\n  }},\n  \"rail\": {{\n    \"kind\": \"wire\",\n    \"railId\": \"claims-settlement-wire-1\",\n    \"custodyProviderId\": \"custodian-claims-1\",\n    \"sourceAccountRef\": \"facility-provider-recovery-1\"\n  }},\n  \"settlementReference\": \"facility-recovery-reference-1\",\n  \"note\": \"reimburse the operator treasury after claim payout\"\n}}\n",
            unix_now_secs().saturating_sub(30),
            unix_now_secs().saturating_add(3600),
            unix_now_secs().saturating_sub(20),
            unix_now_secs().saturating_add(3600),
            unix_now_secs().saturating_sub(120),
            unix_now_secs().saturating_add(3600)
        ),
    )
    .expect("write settlement instruction input");

    let settlement_instruction_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-instruction-issue",
            "--input-file",
            settlement_instruction_input_path
                .to_str()
                .expect("settlement instruction input path"),
        ])
        .output()
        .expect("run settlement instruction CLI");
    assert!(
        settlement_instruction_output.status.success(),
        "settlement instruction CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&settlement_instruction_output.stdout),
        String::from_utf8_lossy(&settlement_instruction_output.stderr)
    );
    let settlement_instruction_json = String::from_utf8(settlement_instruction_output.stdout)
        .expect("settlement instruction json");
    assert!(settlement_instruction_json.contains("\"settlementInstructionId\""));
    assert!(settlement_instruction_json.contains("\"facility_reimbursement\""));

    let mismatched_settlement_receipt_input_path =
        dir.join("liability-settlement-receipt-mismatched.json");
    std::fs::write(
        &mismatched_settlement_receipt_input_path,
        format!(
            "{{\n  \"settlementInstruction\": {settlement_instruction_json},\n  \"settlementReceiptRef\": \"claim-settlement-confirmation-bad-1\",\n  \"reconciliationState\": \"matched\",\n  \"observedExecution\": {{\n    \"observedAt\": {},\n    \"externalReferenceId\": \"claim-settlement-wire-bad-1\",\n    \"amount\": {{ \"units\": 18000, \"currency\": \"USD\" }}\n  }},\n  \"observedPayerId\": \"unexpected-facility-provider\",\n  \"observedPayeeId\": \"operator-treasury-claims-1\",\n  \"note\": \"this should fail closed because the observed payer does not match\"\n}}\n",
            unix_now_secs()
        ),
    )
    .expect("write mismatched settlement receipt input");

    let mismatched_settlement_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-receipt-issue",
            "--input-file",
            mismatched_settlement_receipt_input_path
                .to_str()
                .expect("mismatched settlement receipt input path"),
        ])
        .output()
        .expect("run mismatched settlement receipt CLI");
    assert!(
        !mismatched_settlement_receipt_output.status.success(),
        "mismatched settlement receipt CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stdout),
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stderr)
            .contains("payer/payee"),
        "unexpected mismatched settlement receipt stderr\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stdout),
        String::from_utf8_lossy(&mismatched_settlement_receipt_output.stderr)
    );

    let settlement_receipt_input_path = dir.join("liability-settlement-receipt.json");
    std::fs::write(
        &settlement_receipt_input_path,
        format!(
            "{{\n  \"settlementInstruction\": {settlement_instruction_json},\n  \"settlementReceiptRef\": \"claim-settlement-confirmation-1\",\n  \"reconciliationState\": \"matched\",\n  \"observedExecution\": {{\n    \"observedAt\": {},\n    \"externalReferenceId\": \"claim-settlement-wire-1\",\n    \"amount\": {{ \"units\": 18000, \"currency\": \"USD\" }}\n  }},\n  \"observedPayerId\": \"facility-provider-claims-1\",\n  \"observedPayeeId\": \"operator-treasury-claims-1\",\n  \"note\": \"facility reimbursement matched the settlement topology\"\n}}\n",
            unix_now_secs()
        ),
    )
    .expect("write settlement receipt input");

    let settlement_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-settlement-receipt-issue",
            "--input-file",
            settlement_receipt_input_path
                .to_str()
                .expect("settlement receipt input path"),
        ])
        .output()
        .expect("run settlement receipt CLI");
    assert!(
        settlement_receipt_output.status.success(),
        "settlement receipt CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&settlement_receipt_output.stdout),
        String::from_utf8_lossy(&settlement_receipt_output.stderr)
    );
    let settlement_receipt_json =
        String::from_utf8(settlement_receipt_output.stdout).expect("settlement receipt json");
    assert!(settlement_receipt_json.contains("\"settlementReceiptId\""));
    assert!(settlement_receipt_json.contains("\"matched\""));

    let duplicate_payout_receipt_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "liability-market",
            "claim-payout-receipt-issue",
            "--input-file",
            payout_receipt_input_path
                .to_str()
                .expect("payout receipt input path"),
        ])
        .output()
        .expect("run duplicate payout receipt CLI");
    assert!(
        !duplicate_payout_receipt_output.status.success(),
        "duplicate payout receipt CLI unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&duplicate_payout_receipt_output.stdout),
        String::from_utf8_lossy(&duplicate_payout_receipt_output.stderr)
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "liability-market",
            "claims-list",
            "--policy-number",
            "POL-CLAIMS-1",
        ])
        .output()
        .expect("run liability claims list CLI");
    assert!(
        cli_output.status.success(),
        "liability claims list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let claims_stdout = String::from_utf8_lossy(&cli_output.stdout);
    assert!(claims_stdout.contains("matching_claims:       1"));
    assert!(claims_stdout.contains("provider_responses:    1"));
    assert!(claims_stdout.contains("disputes:              1"));
    assert!(claims_stdout.contains("adjudications:         1"));
    assert!(claims_stdout.contains("payout_instructions:   1"));
    assert!(claims_stdout.contains("payout_receipts:       1"));
    assert!(claims_stdout.contains("matched_payouts:       1"));
    assert!(claims_stdout.contains("settlement_instructions:1"));
    assert!(claims_stdout.contains("settlement_receipts:   1"));
    assert!(claims_stdout.contains("matched_settlements:   1"));
    assert!(claims_stdout.contains("counterparty_mismatch_settlements:0"));
    assert!(claims_stdout.contains("policy=POL-CLAIMS-1"));
    assert!(claims_stdout.contains("payout_instruction="));
    assert!(claims_stdout.contains("payout_receipt="));
    assert!(claims_stdout.contains("settlement_instruction="));
    assert!(claims_stdout.contains("settlement_receipt="));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_liability_claim_rejects_oversized_claims_and_invalid_disputes() {
    let dir = unique_dir("chio-liability-claims-negative");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-liability-claims-negative-1";
    let issuer_key = "issuer-liability-claims-negative-1";
    let now = unix_now_secs();
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..100_u64 {
            store
                .append_chio_receipt(&make_credit_history_receipt(
                    &format!("rc-liability-claims-negative-{day}"),
                    &format!("cap-liability-claims-negative-{day}"),
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    now.saturating_sub((day + 2) * 86_400),
                    SettlementStatus::Settled,
                    "USD",
                    4_000,
                    "USD",
                    true,
                ))
                .expect("append negative liability claim receipt");
        }
    }

    let listen = reserve_listen_addr();
    let service_token = "liability-claims-negative-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let facility_issue = client
        .post(format!("{base_url}/v1/facilities/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 100,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue negative facility");
    assert_eq!(facility_issue.status(), reqwest::StatusCode::OK);

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-liability-claims-negative-pending-1",
                "cap-liability-claims-negative-pending-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                now.saturating_sub(60),
                SettlementStatus::Pending,
                "USD",
                8_000,
                "USD",
                true,
            ))
            .expect("append negative pending receipt");
    }

    let exposure_response = client
        .get(format!("{base_url}/v1/reports/exposure-ledger"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request negative exposure ledger");
    assert_eq!(exposure_response.status(), reqwest::StatusCode::OK);
    let exposure: SignedExposureLedgerReport = exposure_response
        .json()
        .expect("parse negative exposure ledger");

    let bond_issue = client
        .post(format!("{base_url}/v1/bonds/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 100,
                "decisionLimit": 50
            }
        }))
        .send()
        .expect("issue negative bond");
    assert_eq!(bond_issue.status(), reqwest::StatusCode::OK);
    let bond: SignedCreditBond = bond_issue.json().expect("parse negative bond");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("reopen receipt store");
        store
            .append_chio_receipt(&make_credit_history_receipt(
                "rc-liability-claims-negative-failed-1",
                "cap-liability-claims-negative-failed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                7_500,
                "USD",
                true,
            ))
            .expect("append negative failed receipt");
    }

    let loss_event = record_test_credit_loss_event(
        &receipt_db_path,
        &bond,
        "cll-liability-claims-negative-1",
        7_500,
    );

    let risk_package_response = client
        .get(format!("{base_url}/v1/reports/provider-risk-package"))
        .query(&[
            ("agentSubject", subject_key),
            ("receiptLimit", "10"),
            ("decisionLimit", "10"),
            ("recentLossLimit", "5"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("request negative provider risk package");
    assert_eq!(risk_package_response.status(), reqwest::StatusCode::OK);
    let risk_package: SignedCreditProviderRiskPackage = risk_package_response
        .json()
        .expect("parse negative provider risk package");

    let provider_issue = client
        .post(format!("{base_url}/v1/liability/providers/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "report": {
                "schema": "chio.market.provider.v1",
                "providerId": "carrier-claims-negative",
                "displayName": "Carrier Claims Negative",
                "providerType": "admitted_carrier",
                "providerUrl": "https://carrier-claims-negative.example.com",
                "lifecycleState": "active",
                "supportBoundary": {
                    "curatedRegistryOnly": true,
                    "automaticTrustAdmission": false,
                    "permissionlessFederationSupported": false,
                    "boundCoverageSupported": true
                },
                "policies": [
                    {
                        "jurisdiction": "us-ny",
                        "coverageClasses": ["tool_execution"],
                        "supportedCurrencies": ["USD"],
                        "requiredEvidence": ["credit_provider_risk_package"],
                        "maxCoverageAmount": { "units": 50000, "currency": "USD" },
                        "claimsSupported": true,
                        "quoteTtlSeconds": 3600
                    }
                ],
                "provenance": {
                    "configuredBy": "operator@example.com",
                    "configuredAt": unix_now_secs(),
                    "sourceRef": "liability-claims-runbook",
                    "changeReason": "phase 91 negative qualification"
                }
            }
        }))
        .send()
        .expect("issue negative provider");
    assert_eq!(provider_issue.status(), reqwest::StatusCode::OK);

    let requested_effective_from = unix_now_secs().saturating_add(7_200);
    let requested_effective_until = requested_effective_from.saturating_add(30 * 86_400);
    let quote_request_response = client
        .post(format!("{base_url}/v1/liability/quote-requests/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerId": "carrier-claims-negative",
            "jurisdiction": "us-ny",
            "coverageClass": "tool_execution",
            "requestedCoverageAmount": { "units": 20000, "currency": "USD" },
            "requestedEffectiveFrom": requested_effective_from,
            "requestedEffectiveUntil": requested_effective_until,
            "riskPackage": risk_package
        }))
        .send()
        .expect("issue negative quote request");
    assert_eq!(quote_request_response.status(), reqwest::StatusCode::OK);
    let quote_request: SignedLiabilityQuoteRequest = quote_request_response
        .json()
        .expect("parse negative quote request");

    let quote_response_response = client
        .post(format!("{base_url}/v1/liability/quote-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteRequest": quote_request,
            "providerQuoteRef": "carrier-claims-negative-quote-1",
            "disposition": "quoted",
            "quotedTerms": {
                "quotedCoverageAmount": { "units": 20000, "currency": "USD" },
                "quotedPremiumAmount": { "units": 1000, "currency": "USD" },
                "expiresAt": unix_now_secs().saturating_add(1800)
            }
        }))
        .send()
        .expect("issue negative quote response");
    assert_eq!(quote_response_response.status(), reqwest::StatusCode::OK);
    let quote_response: SignedLiabilityQuoteResponse = quote_response_response
        .json()
        .expect("parse negative quote response");

    let placement_response = client
        .post(format!("{base_url}/v1/liability/placements/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "quoteResponse": quote_response,
            "selectedCoverageAmount": { "units": 20000, "currency": "USD" },
            "selectedPremiumAmount": { "units": 1000, "currency": "USD" },
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "placementRef": "placement-claims-negative-1"
        }))
        .send()
        .expect("issue negative placement");
    assert_eq!(placement_response.status(), reqwest::StatusCode::OK);
    let placement: SignedLiabilityPlacement =
        placement_response.json().expect("parse negative placement");

    let bound_coverage_response = client
        .post(format!("{base_url}/v1/liability/bound-coverages/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "placement": placement,
            "policyNumber": "POL-CLAIMS-NEG-1",
            "carrierReference": "bind-claims-neg-1",
            "effectiveFrom": requested_effective_from,
            "effectiveUntil": requested_effective_until,
            "coverageAmount": { "units": 20000, "currency": "USD" },
            "premiumAmount": { "units": 1000, "currency": "USD" }
        }))
        .send()
        .expect("issue negative bound coverage");
    assert_eq!(bound_coverage_response.status(), reqwest::StatusCode::OK);
    let bound_coverage: SignedLiabilityBoundCoverage = bound_coverage_response
        .json()
        .expect("parse negative bound coverage");

    let oversized_claim = client
        .post(format!("{base_url}/v1/liability/claims/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "boundCoverage": bound_coverage.clone(),
            "exposure": exposure.clone(),
            "bond": bond.clone(),
            "lossEvent": loss_event.clone(),
            "claimant": "acme@example.com",
            "claimEventAt": requested_effective_from.saturating_add(600),
            "claimAmount": { "units": 25001, "currency": "USD" },
            "claimRef": "CLAIM-NEG-OVERSIZED",
            "narrative": "oversized claim should fail",
            "receiptIds": ["rc-liability-claims-negative-0"]
        }))
        .send()
        .expect("issue oversized claim");
    assert_eq!(oversized_claim.status(), reqwest::StatusCode::BAD_REQUEST);
    let oversized_body: serde_json::Value =
        oversized_claim.json().expect("parse oversized claim body");
    assert!(oversized_body["error"]
        .as_str()
        .expect("oversized claim error")
        .contains("claim_amount cannot exceed bound coverage amount"));

    let valid_claim_response = client
        .post(format!("{base_url}/v1/liability/claims/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "boundCoverage": bound_coverage,
            "exposure": exposure,
            "bond": bond,
            "lossEvent": loss_event,
            "claimant": "acme@example.com",
            "claimEventAt": requested_effective_from.saturating_add(600),
            "claimAmount": { "units": 10000, "currency": "USD" },
            "claimRef": "CLAIM-NEG-VALID",
            "narrative": "valid claim for dispute-state test",
            "receiptIds": ["rc-liability-claims-negative-1", "rc-liability-claims-negative-failed-1"]
        }))
        .send()
        .expect("issue valid negative claim");
    assert_eq!(valid_claim_response.status(), reqwest::StatusCode::OK);
    let valid_claim: SignedLiabilityClaimPackage = valid_claim_response
        .json()
        .expect("parse valid negative claim");

    let accepted_response = client
        .post(format!("{base_url}/v1/liability/claim-responses/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "claim": valid_claim,
            "providerResponseRef": "claims-negative-response-1",
            "disposition": "accepted",
            "coveredAmount": { "units": 10000, "currency": "USD" },
            "responseNote": "fully accepted claim"
        }))
        .send()
        .expect("issue fully accepted response");
    assert_eq!(accepted_response.status(), reqwest::StatusCode::OK);
    let accepted_response: SignedLiabilityClaimResponse = accepted_response
        .json()
        .expect("parse fully accepted response");

    let invalid_dispute = client
        .post(format!("{base_url}/v1/liability/disputes/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "providerResponse": accepted_response,
            "openedBy": "insured@example.com",
            "reason": "should fail because response is fully accepted"
        }))
        .send()
        .expect("issue invalid dispute");
    assert_eq!(invalid_dispute.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_dispute_body: serde_json::Value =
        invalid_dispute.json().expect("parse invalid dispute body");
    assert!(invalid_dispute_body["error"]
        .as_str()
        .expect("invalid dispute error")
        .contains("denied or partially accepted"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_policy_input_export_surfaces() {
    let dir = unique_dir("chio-underwriting-input");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-1";
    let issuer_key = "issuer-underwrite-1";
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-underwrite-1",
                "cap-underwrite-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                6_000,
            ))
            .expect("append governed underwriting receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-input-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/underwriting-input"))
        .query(&[
            ("agentSubject", subject_key),
            ("toolServer", "ledger"),
            ("toolName", "transfer"),
            ("receiptLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting input request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let input: SignedUnderwritingPolicyInput =
        response.json().expect("parse signed underwriting input");
    assert!(input
        .verify_signature()
        .expect("verify underwriting input signature"));
    assert_eq!(input.body.schema, "chio.underwriting.policy-input.v1");
    assert_eq!(input.body.filters.receipt_limit, Some(10));
    assert_eq!(input.body.receipts.matching_receipts, 1);
    assert_eq!(input.body.receipts.runtime_assurance_receipts, 1);
    assert_eq!(input.body.receipts.call_chain_receipts, 1);
    assert_eq!(input.body.receipts.metered_receipts, 1);
    assert_eq!(
        input
            .body
            .runtime_assurance
            .as_ref()
            .expect("runtime assurance summary")
            .highest_tier,
        Some(RuntimeAssuranceTier::Verified)
    );
    assert_eq!(
        input
            .body
            .certification
            .as_ref()
            .expect("certification summary")
            .state,
        chio_core::underwriting::UnderwritingCertificationState::Unavailable
    );
    let reasons = input
        .body
        .signals
        .iter()
        .map(|signal| signal.reason)
        .collect::<Vec<_>>();
    assert!(reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::ProbationaryHistory));
    assert!(
        reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::MissingCertification)
    );
    assert!(
        reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::MeteredBillingMismatch)
    );
    assert!(reasons.contains(&chio_core::underwriting::UnderwritingReasonCode::DelegatedCallChain));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "underwriting-input",
            "export",
            "--agent-subject",
            subject_key,
            "--tool-server",
            "ledger",
            "--tool-name",
            "transfer",
            "--receipt-limit",
            "10",
        ])
        .output()
        .expect("run underwriting input CLI");
    assert!(
        cli_output.status.success(),
        "underwriting input CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_input: SignedUnderwritingPolicyInput =
        serde_json::from_slice(&cli_output.stdout).expect("parse underwriting input CLI json");
    assert!(cli_input
        .verify_signature()
        .expect("verify underwriting input CLI signature"));
    assert_eq!(cli_input.body.schema, "chio.underwriting.policy-input.v1");
    assert_eq!(cli_input.body.receipts.matching_receipts, 1);
    assert_eq!(cli_input.signer_key, input.signer_key);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_policy_input_requires_anchor() {
    let setup = setup_with_receipts("chio-underwriting-anchor");

    let response = setup
        .client
        .get(format!("{}/v1/reports/underwriting-input", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send underwriting input request without anchor");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().expect("parse underwriting input error");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one anchor"));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_report_surfaces() {
    let dir = unique_dir("chio-underwriting-decision");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-decision-1";
    let issuer_key = "issuer-underwrite-decision-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-decision-1",
                "cap-decision-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
            ))
            .expect("append governed underwriting decision receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-decision-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/underwriting-decision"))
        .query(&[("agentSubject", subject_key), ("receiptLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting decision request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionReport =
        response.json().expect("parse underwriting decision report");
    assert_eq!(report.schema, "chio.underwriting.decision-report.v1");
    assert_eq!(
        report.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::ReduceCeiling
    );
    assert_eq!(report.suggested_ceiling_factor, Some(0.5));
    assert_eq!(report.input.receipts.matching_receipts, 1);
    let metered_finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.signal_reason
                == Some(chio_core::underwriting::UnderwritingReasonCode::MeteredBillingMismatch)
        })
        .expect("metered finding");
    assert!(!metered_finding.evidence_refs.is_empty());
    assert_eq!(
        metered_finding.evidence_refs[0].kind,
        chio_core::underwriting::UnderwritingEvidenceKind::MeteredBillingReconciliation
    );
    let call_chain_finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.signal_reason
                == Some(chio_core::underwriting::UnderwritingReasonCode::DelegatedCallChain)
        })
        .expect("call-chain finding");
    assert!(!call_chain_finding.evidence_refs.is_empty());
    assert_eq!(
        call_chain_finding.evidence_refs[0].reference_id,
        "rc-decision-1"
    );

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "underwriting-decision",
            "evaluate",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
        ])
        .output()
        .expect("run underwriting decision CLI");
    assert!(
        cli_output.status.success(),
        "underwriting decision CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: UnderwritingDecisionReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse underwriting decision CLI json");
    assert_eq!(cli_report.schema, "chio.underwriting.decision-report.v1");
    assert_eq!(cli_report.outcome, report.outcome);
    assert_eq!(cli_report.policy.version, report.policy.version);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_steps_up_without_receipt_history() {
    let setup = setup_with_receipts("chio-underwriting-decision-empty");

    let response = setup
        .client
        .get(format!(
            "{}/v1/reports/underwriting-decision",
            setup.base_url
        ))
        .query(&[("capabilityId", "cap-missing")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send underwriting decision request without history");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionReport =
        response.json().expect("parse underwriting decision report");
    assert_eq!(
        report.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::StepUp
    );
    assert!(report.findings.iter().any(|finding| {
        finding.reason
            == chio_core::underwriting::UnderwritingDecisionReasonCode::InsufficientReceiptHistory
    }));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_requires_anchor() {
    let setup = setup_with_receipts("chio-underwriting-decision-anchor");

    let response = setup
        .client
        .get(format!(
            "{}/v1/reports/underwriting-decision",
            setup.base_url
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send underwriting decision request without anchor");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse underwriting decision error response");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one anchor"));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_issue_requires_anchor() {
    let setup = setup_with_receipts("chio-underwriting-issue-anchor");

    let response = setup
        .client
        .post(format!(
            "{}/v1/underwriting/decisions/issue",
            setup.base_url
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .json(&serde_json::json!({
            "query": {
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send underwriting issue request without anchor");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse underwriting decision issue error response");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("at least one anchor"));

    let _ = std::fs::remove_dir_all(&setup.dir);
}

#[test]
fn test_underwriting_decision_links_failed_settlement_evidence() {
    let dir = unique_dir("chio-underwriting-failed-settlement");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-failed-settlement-1",
                "cap-failed-settlement-1",
                "subject-failed-settlement-1",
                "issuer-failed-settlement-1",
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(60),
                SettlementStatus::Failed,
                "USD",
                4_200,
                "USD",
                false,
                false,
            ))
            .expect("append failed settlement underwriting receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-failed-settlement-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/underwriting-decision"))
        .query(&[
            ("agentSubject", "subject-failed-settlement-1"),
            ("receiptLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting decision request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionReport =
        response.json().expect("parse underwriting decision report");
    let failed_settlement_finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.signal_reason
                == Some(chio_core::underwriting::UnderwritingReasonCode::FailedSettlementExposure)
        })
        .expect("failed settlement finding");
    assert_eq!(
        failed_settlement_finding.evidence_refs[0].kind,
        chio_core::underwriting::UnderwritingEvidenceKind::SettlementReconciliation
    );
    assert_eq!(
        failed_settlement_finding.evidence_refs[0].reference_id,
        "rc-failed-settlement-1"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_simulation_report_surfaces() {
    let dir = unique_dir("chio-underwriting-simulation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_file = dir.join("underwriting-policy.yaml");

    let subject_key = "subject-underwrite-sim-1";
    let issuer_key = "issuer-underwrite-sim-1";
    let base_timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        for day in 0..=14_u64 {
            store
                .append_chio_receipt(&make_underwriting_simulation_receipt(
                    &format!("rc-sim-{day}"),
                    "cap-sim-1",
                    subject_key,
                    issuer_key,
                    "ledger",
                    "transfer",
                    base_timestamp.saturating_sub(day * 86_400),
                    RuntimeAssuranceTier::Attested,
                ))
                .expect("append underwriting simulation receipt");
        }
    }

    let simulation_policy = chio_kernel::UnderwritingDecisionPolicy {
        version: "chio.underwriting.decision-policy.simulated-history-floor.v1".to_string(),
        minimum_receipt_history: 30,
        ..chio_kernel::UnderwritingDecisionPolicy::default()
    };
    std::fs::write(
        &policy_file,
        serde_yml::to_string(&simulation_policy).expect("serialize simulation policy"),
    )
    .expect("write simulation policy");

    let listen = reserve_listen_addr();
    let service_token = "underwriting-simulation-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .post(format!("{base_url}/v1/reports/underwriting-simulation"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 20
            },
            "policy": simulation_policy
        }))
        .send()
        .expect("send underwriting simulation request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingSimulationReport = response
        .json()
        .expect("parse underwriting simulation report");
    assert_eq!(report.schema, "chio.underwriting.simulation-report.v1");
    assert_eq!(
        report.default_evaluation.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::ReduceCeiling
    );
    assert_eq!(
        report.simulated_evaluation.outcome,
        chio_core::underwriting::UnderwritingDecisionOutcome::StepUp
    );
    assert!(report.delta.outcome_changed);
    assert!(report
        .delta
        .added_reasons
        .contains(&"insufficient_receipt_history".to_string()));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "underwriting-decision",
            "simulate",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "20",
            "--policy-file",
            policy_file.to_str().expect("policy path"),
        ])
        .output()
        .expect("run underwriting simulation CLI");
    assert!(
        cli_output.status.success(),
        "underwriting simulation CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_report: UnderwritingSimulationReport =
        serde_json::from_slice(&cli_output.stdout).expect("parse underwriting simulation CLI");
    assert_eq!(
        cli_report.simulated_evaluation.outcome,
        report.simulated_evaluation.outcome
    );
    assert_eq!(
        cli_report.delta.outcome_changed,
        report.delta.outcome_changed
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_issue_and_list_surfaces() {
    let dir = unique_dir("chio-underwriting-issue");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-issue-1";
    let issuer_key = "issuer-underwrite-issue-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-issue-1",
                "cap-issue-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
            ))
            .expect("append governed underwriting issue receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-issue-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let remote_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("send underwriting decision issue request");
    assert_eq!(remote_issue.status(), reqwest::StatusCode::OK);
    let remote_decision: SignedUnderwritingDecision = remote_issue
        .json()
        .expect("parse signed underwriting decision");
    assert!(remote_decision
        .verify_signature()
        .expect("verify signed underwriting decision"));
    assert_eq!(remote_decision.body.schema, "chio.underwriting.decision.v1");
    assert_eq!(
        remote_decision.body.review_state,
        chio_core::underwriting::UnderwritingReviewState::Approved
    );
    assert_eq!(
        remote_decision.body.budget.action,
        chio_core::underwriting::UnderwritingBudgetAction::Reduce
    );
    assert_eq!(
        remote_decision
            .body
            .premium
            .quoted_amount
            .as_ref()
            .map(|amount| amount.units),
        Some(168)
    );

    let remote_list = client
        .get(format!("{base_url}/v1/reports/underwriting-decisions"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send underwriting decision list request");
    assert_eq!(remote_list.status(), reqwest::StatusCode::OK);
    let list_report: UnderwritingDecisionListReport = remote_list
        .json()
        .expect("parse underwriting decision list");
    assert_eq!(list_report.summary.matching_decisions, 1);
    assert_eq!(list_report.summary.returned_decisions, 1);
    assert_eq!(list_report.summary.total_quoted_premium_units, 168);
    assert_eq!(
        list_report.summary.total_quoted_premium_currency.as_deref(),
        Some("USD")
    );
    assert_eq!(
        list_report
            .summary
            .quoted_premium_totals_by_currency
            .get("USD")
            .copied(),
        Some(168)
    );
    assert_eq!(
        list_report.decisions[0].decision.body.decision_id,
        remote_decision.body.decision_id
    );

    let cli_issue = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "trust",
            "underwriting-decision",
            "issue",
            "--agent-subject",
            subject_key,
            "--receipt-limit",
            "10",
            "--supersedes-decision-id",
            &remote_decision.body.decision_id,
        ])
        .output()
        .expect("run underwriting decision issue CLI");
    assert!(
        cli_issue.status.success(),
        "underwriting decision issue CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_issue.stdout),
        String::from_utf8_lossy(&cli_issue.stderr)
    );
    let cli_decision: SignedUnderwritingDecision =
        serde_json::from_slice(&cli_issue.stdout).expect("parse underwriting decision issue CLI");
    assert!(cli_decision
        .verify_signature()
        .expect("verify underwriting decision issue CLI signature"));

    let cli_list = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "trust",
            "underwriting-decision",
            "list",
            "--agent-subject",
            subject_key,
            "--limit",
            "10",
        ])
        .output()
        .expect("run underwriting decision list CLI");
    assert!(
        cli_list.status.success(),
        "underwriting decision list CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_list.stdout),
        String::from_utf8_lossy(&cli_list.stderr)
    );
    let cli_list_report: UnderwritingDecisionListReport =
        serde_json::from_slice(&cli_list.stdout).expect("parse underwriting decision list CLI");
    assert_eq!(cli_list_report.summary.matching_decisions, 2);
    assert!(cli_list_report
        .decisions
        .iter()
        .any(|row| row.decision.body.decision_id == cli_decision.body.decision_id));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_issue_with_mixed_currency_exposure_withholds_premium() {
    let dir = unique_dir("chio-underwriting-mixed-currency");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-mixed-1";
    let issuer_key = "issuer-underwrite-mixed-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-mixed-usd-1",
                "cap-mixed-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
                SettlementStatus::Settled,
                "USD",
                4_200,
                "USD",
                false,
                false,
            ))
            .expect("append USD governed receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-mixed-eur-1",
                "cap-mixed-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp.saturating_sub(1),
                SettlementStatus::Settled,
                "EUR",
                3_100,
                "EUR",
                false,
                false,
            ))
            .expect("append EUR governed receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-mixed-currency-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let issue_response = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue underwriting decision");
    assert_eq!(issue_response.status(), reqwest::StatusCode::OK);
    let decision: SignedUnderwritingDecision = issue_response
        .json()
        .expect("parse signed underwriting decision");
    assert_eq!(
        decision.body.premium.state,
        chio_core::underwriting::UnderwritingPremiumState::Withheld
    );
    assert!(decision.body.premium.quoted_amount.is_none());
    assert!(decision
        .body
        .premium
        .rationale
        .contains("multiple currencies"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_decision_list_partitions_premium_totals_by_currency() {
    let dir = unique_dir("chio-underwriting-premium-currencies");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-premium-usd-1",
                "cap-premium-usd-1",
                "subject-underwrite-usd-1",
                "issuer-underwrite-usd-1",
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(60),
                SettlementStatus::Settled,
                "USD",
                4_200,
                "USD",
                false,
                false,
            ))
            .expect("append USD receipt");
        store
            .append_chio_receipt(&make_governed_authorization_receipt_with_options(
                "rc-premium-eur-1",
                "cap-premium-eur-1",
                "subject-underwrite-eur-1",
                "issuer-underwrite-eur-1",
                "ledger",
                "transfer",
                unix_now_secs().saturating_sub(61),
                SettlementStatus::Settled,
                "EUR",
                3_100,
                "EUR",
                false,
                false,
            ))
            .expect("append EUR receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-premium-currency-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    for subject_key in ["subject-underwrite-usd-1", "subject-underwrite-eur-1"] {
        let response = client
            .post(format!("{base_url}/v1/underwriting/decisions/issue"))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            )
            .json(&serde_json::json!({
                "query": {
                    "agentSubject": subject_key,
                    "receiptLimit": 10
                }
            }))
            .send()
            .expect("issue underwriting decision");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    let list_response = client
        .get(format!("{base_url}/v1/reports/underwriting-decisions"))
        .query(&[("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list underwriting decisions");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionListReport = list_response
        .json()
        .expect("parse underwriting decision list");
    assert_eq!(report.summary.total_quoted_premium_units, 0);
    assert!(report.summary.total_quoted_premium_currency.is_none());
    assert_eq!(
        report
            .summary
            .quoted_premium_totals_by_currency
            .get("USD")
            .copied(),
        Some(105)
    );
    assert_eq!(
        report
            .summary
            .quoted_premium_totals_by_currency
            .get("EUR")
            .copied(),
        Some(78)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_appeal_and_supersession_lifecycle() {
    let dir = unique_dir("chio-underwriting-appeal");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-appeal-1";
    let issuer_key = "issuer-underwrite-appeal-1";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-appeal-1",
                "cap-appeal-1",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
            ))
            .expect("append governed underwriting appeal receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-appeal-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let initial_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue initial underwriting decision");
    assert_eq!(initial_issue.status(), reqwest::StatusCode::OK);
    let initial_decision: SignedUnderwritingDecision =
        initial_issue.json().expect("parse initial decision");

    let appeal_response = client
        .post(format!("{base_url}/v1/underwriting/appeals"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "decisionId": initial_decision.body.decision_id,
            "requestedBy": "ops-reviewer",
            "reason": "need superseding review"
        }))
        .send()
        .expect("create underwriting appeal");
    assert_eq!(appeal_response.status(), reqwest::StatusCode::OK);
    let appeal: UnderwritingAppealRecord =
        appeal_response.json().expect("parse underwriting appeal");
    assert_eq!(
        appeal.status,
        chio_core::underwriting::UnderwritingAppealStatus::Open
    );

    let superseding_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            },
            "supersedesDecisionId": initial_decision.body.decision_id
        }))
        .send()
        .expect("issue superseding underwriting decision");
    assert_eq!(superseding_issue.status(), reqwest::StatusCode::OK);
    let replacement_decision: SignedUnderwritingDecision = superseding_issue
        .json()
        .expect("parse superseding decision");

    let resolve_response = client
        .post(format!("{base_url}/v1/underwriting/appeals/resolve"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "appealId": appeal.appeal_id,
            "resolution": "accepted",
            "resolvedBy": "ops-reviewer",
            "replacementDecisionId": replacement_decision.body.decision_id
        }))
        .send()
        .expect("resolve underwriting appeal");
    assert_eq!(resolve_response.status(), reqwest::StatusCode::OK);
    let resolved_appeal: UnderwritingAppealRecord =
        resolve_response.json().expect("parse resolved appeal");
    assert_eq!(
        resolved_appeal.status,
        chio_core::underwriting::UnderwritingAppealStatus::Accepted
    );
    assert_eq!(
        resolved_appeal.replacement_decision_id.as_deref(),
        Some(replacement_decision.body.decision_id.as_str())
    );

    let second_resolve = client
        .post(format!("{base_url}/v1/underwriting/appeals/resolve"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "appealId": appeal.appeal_id,
            "resolution": "rejected",
            "resolvedBy": "ops-reviewer"
        }))
        .send()
        .expect("resolve underwriting appeal twice");
    assert_eq!(second_resolve.status(), reqwest::StatusCode::CONFLICT);

    let list_response = client
        .get(format!("{base_url}/v1/reports/underwriting-decisions"))
        .query(&[("agentSubject", subject_key), ("limit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("list underwriting decisions after appeal");
    assert_eq!(list_response.status(), reqwest::StatusCode::OK);
    let report: UnderwritingDecisionListReport = list_response
        .json()
        .expect("parse underwriting decision lifecycle list");
    assert_eq!(report.summary.matching_decisions, 2);
    let initial_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == initial_decision.body.decision_id)
        .expect("initial decision row");
    let replacement_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == replacement_decision.body.decision_id)
        .expect("replacement decision row");
    assert_eq!(
        initial_row.lifecycle_state,
        chio_core::underwriting::UnderwritingDecisionLifecycleState::Superseded
    );
    assert_eq!(
        replacement_row.lifecycle_state,
        chio_core::underwriting::UnderwritingDecisionLifecycleState::Active
    );
    assert_eq!(
        initial_row.latest_appeal_status,
        Some(chio_core::underwriting::UnderwritingAppealStatus::Accepted)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_underwriting_rejected_appeal_cannot_link_replacement_decision() {
    let dir = unique_dir("chio-underwriting-appeal-rejected-replacement");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_key = "subject-underwrite-appeal-2";
    let issuer_key = "issuer-underwrite-appeal-2";
    let timestamp = unix_now_secs().saturating_sub(60);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .append_chio_receipt(&make_governed_authorization_receipt(
                "rc-appeal-2",
                "cap-appeal-2",
                subject_key,
                issuer_key,
                "ledger",
                "transfer",
                timestamp,
            ))
            .expect("append governed underwriting appeal receipt");
    }

    let listen = reserve_listen_addr();
    let service_token = "underwriting-appeal-rejected-replacement-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = build_test_client();
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let initial_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            }
        }))
        .send()
        .expect("issue initial underwriting decision");
    assert_eq!(initial_issue.status(), reqwest::StatusCode::OK);
    let initial_decision: SignedUnderwritingDecision =
        initial_issue.json().expect("parse initial decision");

    let appeal_response = client
        .post(format!("{base_url}/v1/underwriting/appeals"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "decisionId": initial_decision.body.decision_id,
            "requestedBy": "ops-reviewer",
            "reason": "need superseding review"
        }))
        .send()
        .expect("create underwriting appeal");
    assert_eq!(appeal_response.status(), reqwest::StatusCode::OK);
    let appeal: UnderwritingAppealRecord =
        appeal_response.json().expect("parse underwriting appeal");

    let superseding_issue = client
        .post(format!("{base_url}/v1/underwriting/decisions/issue"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "query": {
                "agentSubject": subject_key,
                "receiptLimit": 10
            },
            "supersedesDecisionId": initial_decision.body.decision_id
        }))
        .send()
        .expect("issue superseding underwriting decision");
    assert_eq!(superseding_issue.status(), reqwest::StatusCode::OK);
    let replacement_decision: SignedUnderwritingDecision = superseding_issue
        .json()
        .expect("parse superseding decision");

    let resolve_response = client
        .post(format!("{base_url}/v1/underwriting/appeals/resolve"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .json(&serde_json::json!({
            "appealId": appeal.appeal_id,
            "resolution": "rejected",
            "resolvedBy": "ops-reviewer",
            "replacementDecisionId": replacement_decision.body.decision_id
        }))
        .send()
        .expect("resolve underwriting appeal with rejected replacement");
    assert_eq!(resolve_response.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = resolve_response
        .json()
        .expect("parse rejected appeal conflict");
    assert!(body["error"]
        .as_str()
        .expect("error string")
        .contains("may only be linked"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/receipts/query returns JSON (not HTML) even when SPA dist/ does not exist.
/// This verifies API routes take priority over the SPA catch-all.
#[test]
fn test_api_routes_not_shadowed_by_spa() {
    let setup = setup_with_receipts("chio-api-priority");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send API request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "API should return 200"
    );

    // The Content-Type must be application/json, not text/html.
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "API response Content-Type should be application/json, got: {content_type}"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}
