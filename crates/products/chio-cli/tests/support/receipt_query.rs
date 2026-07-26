#![allow(
    unused_imports,
    clippy::expect_used,
    clippy::too_many_arguments,
    clippy::unwrap_used
)]

mod budget_fixture;
pub(crate) use budget_fixture::seed_budget_exposure;

pub(crate) use super::receipt_query_capital_authority::*;
pub(crate) use super::receipt_query_helpers::*;

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::process::{Child, Command, Stdio};
pub(crate) use std::sync::{Mutex, MutexGuard, OnceLock};
pub(crate) use std::thread;
pub(crate) use std::time::Duration;
pub(crate) use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) use chio_core::appraisal::{
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
pub(crate) use chio_core::capability::{
    governance::{
        GovernedAutonomyTier, GovernedCallChainContext, GovernedCallChainProvenance,
        MeteredBillingQuote, MeteredSettlementMode,
    },
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
    workload_identity::WorkloadIdentity,
};
pub(crate) use chio_core::credit::{
    CapitalAllocationDecisionOutcome, CapitalAllocationDecisionReasonCode, CapitalBookSourceKind,
    CapitalExecutionInstructionAction, CapitalExecutionIntendedState,
    CapitalExecutionReconciledState, CreditBondLifecycleState, CreditLossLifecycleArtifact,
    CreditLossLifecycleEventKind, CreditLossLifecycleFinding, CreditLossLifecycleQuery,
    CreditLossLifecycleReasonCode, CreditLossLifecycleReport, CreditLossLifecycleSummary,
    CreditLossLifecycleSupportBoundary, CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA,
    CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA,
};
pub(crate) use chio_core::crypto::Keypair;
pub(crate) use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    economics::FinancialBudgetAuthorityReceiptMetadata,
    economics::FinancialBudgetAuthorizeReceiptMetadata,
    economics::FinancialBudgetHoldAuthorityMetadata,
    economics::FinancialBudgetTerminalReceiptMetadata, economics::FinancialReceiptMetadata,
    economics::SettlementStatus, governance::GovernedApprovalReceiptMetadata,
    governance::GovernedCommerceReceiptMetadata, governance::GovernedTransactionReceiptMetadata,
    governance::MeteredBillingReceiptMetadata, governance::RuntimeAssuranceReceiptMetadata,
    metadata::ReceiptAttributionMetadata,
};
pub(crate) use chio_kernel::{
    build_checkpoint, AuthorizationContextReport, BudgetStore, BudgetUsageRecord,
    CapabilitySnapshot, CreditBacktestReport, CreditBondListReport, CreditBondReport,
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
pub(crate) use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
pub(crate) use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
pub(crate) use reqwest::blocking::Client;
pub(crate) use rusqlite::Connection;

pub(crate) fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

pub(crate) fn build_test_client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(120))
        .build()
        .expect("build reqwest client")
}

pub(crate) const TEST_REPUTATION_RECEIPT_TARGET: u64 = 100;
pub(crate) const LARGE_RECEIPT_HISTORY_LEN: u64 = 128;
pub(crate) const CAPITAL_ALLOCATION_QUEUE_HISTORY_LEN: u64 = 240;

pub(crate) const TEST_KERNEL_SEED_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

pub(crate) fn test_kernel_keypair() -> Keypair {
    Keypair::from_seed_hex(TEST_KERNEL_SEED_HEX).expect("test kernel keypair")
}

pub(crate) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

pub(crate) fn tool_action(parameters: serde_json::Value) -> ToolCallAction {
    ToolCallAction::from_parameters(parameters).expect("hash tool action parameters")
}

pub(crate) fn sample_google_runtime_attestation() -> RuntimeAttestationEvidence {
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

pub(crate) fn sample_azure_runtime_attestation() -> RuntimeAttestationEvidence {
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

pub(crate) fn sample_aws_nitro_runtime_attestation() -> RuntimeAttestationEvidence {
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

pub(crate) fn sample_enterprise_runtime_attestation() -> RuntimeAttestationEvidence {
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

pub(crate) struct ServerGuard {
    pub(crate) child: Child,
    _service_lock: MutexGuard<'static, ()>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn trust_service_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn read_child_stderr(child: &mut Child) -> String {
    let Some(stderr) = child.stderr.take() else {
        return String::new();
    };
    let mut reader = std::io::BufReader::new(stderr);
    let mut output = String::new();
    let _ = std::io::Read::read_to_string(&mut reader, &mut output);
    output
}

pub(crate) fn write_test_reputation_policy(receipt_db_path: &Path) -> PathBuf {
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

pub(crate) fn trust_service_authority_seed_path(receipt_db_path: &Path) -> PathBuf {
    receipt_db_path.with_file_name("authority-seed.hex")
}

pub(crate) fn write_trust_service_authority_seed(receipt_db_path: &Path) -> PathBuf {
    let authority_seed_path = trust_service_authority_seed_path(receipt_db_path);
    std::fs::write(&authority_seed_path, test_kernel_keypair().seed_hex())
        .expect("write authority seed file");
    authority_seed_path
}

pub(crate) fn spawn_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
) -> ServerGuard {
    let service_lock = trust_service_test_lock();
    let policy_path = write_test_reputation_policy(receipt_db_path);
    let _ = authority_db_path;
    let authority_seed_path = write_trust_service_authority_seed(receipt_db_path);
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-seed-file",
            authority_seed_path
                .to_str()
                .expect("authority seed file path"),
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

pub(crate) fn spawn_trust_service_without_receipt_db(
    listen: std::net::SocketAddr,
    service_token: &str,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
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

pub(crate) fn wait_for_trust_service_result(
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

pub(crate) fn wait_for_trust_service(client: &Client, base_url: &str) {
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

pub(crate) fn assert_trust_service_auth_required(client: &Client, base_url: &str, path: &str) {
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

pub(crate) fn assert_trust_service_get_error(
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

pub(crate) fn record_test_credit_loss_event(
    receipt_db_path: &Path,
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

pub(crate) fn record_test_credit_loss_event_with_kind(
    receipt_db_path: &Path,
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

pub(crate) fn record_test_capability_snapshot(
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
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .expect("sign test capability");
    store
        .record_capability_snapshot(&token, None)
        .expect("record test capability snapshot");
}

pub(crate) fn make_receipt(
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
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            decision: Some(decision),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_financial_receipt(
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
    make_financial_receipt_signed_by(
        &Keypair::generate(),
        id,
        capability_id,
        subject_key,
        issuer_key,
        tool_server,
        tool_name,
        decision,
        timestamp,
        cost_charged,
        attempted_cost,
        root_budget_holder,
        delegation_depth,
    )
}

pub(crate) fn make_financial_receipt_signed_by(
    signing_key: &Keypair,
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
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            decision: Some(decision),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: signing_key.public_key(),
            bbs_projection_version: None,
        },
        signing_key,
    )
    .unwrap()
}

pub(crate) fn make_financial_receipt_with_budget_authority(
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_financial_receipt_with_settlement_status(
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_governed_financial_receipt_signed_by(
    signing_key: &Keypair,
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
                settlement_destination_ref: None,
            }),
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-risk-1".to_string(),
                approver_key: issuer_key.to_string(),
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: signing_key.public_key(),
            bbs_projection_version: None,
        },
        signing_key,
    )
    .unwrap()
}

pub(crate) fn make_governed_receipt(
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
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_governed_authorization_receipt_with_options(
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
pub(crate) fn make_governed_authorization_receipt_with_runtime_profile(
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
    let keypair = test_kernel_keypair();
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
                settlement_destination_ref: None,
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
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_governed_authorization_receipt(
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

pub(crate) fn make_credit_history_receipt(
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
    let keypair = test_kernel_keypair();
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
                settlement_destination_ref: None,
            }),
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: format!("approval-{id}"),
                approver_key: issuer_key.to_string(),
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_governed_authorization_receipt_without_runtime_assurance(
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
    let keypair = test_kernel_keypair();
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
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_underwriting_simulation_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    timestamp: u64,
    runtime_tier: RuntimeAssuranceTier,
) -> ChioReceipt {
    let keypair = test_kernel_keypair();
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
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_governed_x402_receipt(
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
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) fn make_governed_acp_receipt(
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
                settlement_destination_ref: None,
            }),
            metered_billing: None,
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-acp-ops-1".to_string(),
                approver_key: "approver-key-acp".to_string(),
                approval_artifact_digest: None,
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
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

pub(crate) struct TestSetup {
    pub(crate) dir: PathBuf,
    _receipt_db_path: PathBuf,
    _revocation_db_path: PathBuf,
    _authority_db_path: PathBuf,
    _budget_db_path: PathBuf,
    pub(crate) base_url: String,
    pub(crate) service_token: String,
    _service: ServerGuard,
    pub(crate) client: Client,
}

pub(crate) fn setup_with_receipts(prefix: &str) -> TestSetup {
    let dir = unique_dir(prefix);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");

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
