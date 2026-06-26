use super::*;
use std::ffi::OsString;
use std::path::Component;

const PROOF_DOCTOR_REPORT_SCHEMA: &str = "chio.proof.doctor-report.v1";
const PROOF_FIXTURE_ROOT_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-root-catalog.v1";
const PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA: &str = "chio.proof-room.receipt-evidence.v1";
const DOCKER_QUICKSTART_EVIDENCE_SCHEMA: &str = "chio.proof.docker-quickstart-evidence.v1";
const DOCKER_QUICKSTART_EVIDENCE_PATH: &str = "artifacts/release/docker-quickstart-evidence.json";
const DOCKER_QUICKSTART_TARGET: &str = "chio-proof-room-quickstart";
const DOCKER_QUICKSTART_DOCKERFILE: &str = "deploy/docker/Dockerfile";
const DOCKER_QUICKSTART_SERVER_BINARY: &str = "/usr/local/bin/chio-proof-room";
const DOCKER_QUICKSTART_BUNDLE_PATH: &str =
    "/opt/chio/fixtures/proof-room/first-run/single-call-authority/proof-room-bundle";
const DOCKER_QUICKSTART_DOCTOR_REPORT_PATH: &str = "/opt/chio/proof-doctor-report.json";
const DOCKER_QUICKSTART_EVIDENCE_SOURCE: &str =
    "scripts/check-chio-proof-room-docker-quickstart.sh";
const PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON";
const PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL";
const PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON: &str =
    "{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"latest_block_number\":12345701}";
const REQUIRED_DOCKER_ENDPOINTS: &[(&str, &str)] = &[
    ("/manifest.json", "chio.proof-room.bundle.v1"),
    (
        "/ui/proof-room-static/load-report.json",
        "chio.proof-room.verifier-report.v1",
    ),
    (
        "/proof-room-fixture-catalog.json",
        "chio.proof-room.fixture-catalog.v1",
    ),
    (
        "/proof-room-fixtures/minimal-passport-valid/verifier-report.json",
        "chio.transaction.verifier-report.v1",
    ),
    (
        "/proof-room-fixtures/minimal-passport-valid/transaction-passport.json",
        "passport-minimal-valid",
    ),
    (
        "/proof-room-fixtures/commerce-offline-psp/verifier-report.json",
        "chio.commerce.order-passport.v1",
    ),
    ("/?view=proof-room", "Chio"),
];

#[derive(Debug, serde::Serialize)]
struct ProofDoctorReport {
    schema: &'static str,
    scenario: &'static str,
    verdict: &'static str,
    check_count: usize,
    failed_count: usize,
    diagnostic_codes: Vec<String>,
    checks: Vec<ProofDoctorCheck>,
}

#[derive(Debug, serde::Serialize)]
struct ProofDoctorCheck {
    id: String,
    code: String,
    status: &'static str,
    path: String,
    message: String,
}

#[derive(serde::Deserialize)]
struct ProofPackageCatalog {
    schema: String,
    fixtures: Vec<ProofPackageFixture>,
}

#[derive(serde::Deserialize)]
struct ProofPackageFixture {
    id: String,
    kind: String,
    path: String,
}

#[derive(serde::Deserialize)]
struct ProofPackageNegativeCase {
    expected_failure_code: String,
    #[serde(default)]
    verifier_context: ProofPackageVerifierContext,
}

#[derive(Default, serde::Deserialize)]
struct ProofPackageVerifierContext {
    #[serde(default)]
    public_settlement_independent_chain_head: Option<PublicSettlementIndependentChainHeadContext>,
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum PublicSettlementIndependentChainHeadContext {
    Missing,
    BlockHashMismatch,
}

struct EnvVarOverride {
    name: &'static str,
    previous: Option<OsString>,
}

impl EnvVarOverride {
    fn remove(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::remove_var(name);
        Self { name, previous }
    }

    fn set(name: &'static str, value: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarOverride {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

impl ProofPackageVerifierContext {
    fn apply(&self) -> Vec<EnvVarOverride> {
        match self.public_settlement_independent_chain_head {
            Some(PublicSettlementIndependentChainHeadContext::Missing) => vec![
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV),
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV),
            ],
            Some(PublicSettlementIndependentChainHeadContext::BlockHashMismatch) => vec![
                EnvVarOverride::set(
                    PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV,
                    PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON,
                ),
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV),
            ],
            None => Vec::new(),
        }
    }
}

#[derive(serde::Deserialize)]
struct EnterpriseExportNegativeCase {
    schema: String,
    id: String,
    expected_failure_code: String,
}

impl ProofDoctorReport {
    fn new(scenario: &'static str, mut checks: Vec<ProofDoctorCheck>) -> Self {
        for check in &mut checks {
            check.code = proof_doctor_diagnostic_code(scenario, &check.id);
        }
        let check_count = checks.len();
        let failed_count = checks
            .iter()
            .filter(|check| check.status == "failed")
            .count();
        let diagnostic_codes = checks.iter().map(|check| check.code.clone()).collect();
        let verdict = if checks.iter().any(|check| check.status == "failed") {
            "failed"
        } else {
            "passed"
        };

        Self {
            schema: PROOF_DOCTOR_REPORT_SCHEMA,
            scenario,
            verdict,
            check_count,
            failed_count,
            diagnostic_codes,
            checks,
        }
    }

    fn failed(&self) -> bool {
        self.checks.iter().any(|check| check.status == "failed")
    }
}

fn proof_doctor_diagnostic_code(scenario: &str, check_id: &str) -> String {
    format!(
        "proof.doctor.{}.{}",
        proof_doctor_diagnostic_segment(scenario),
        proof_doctor_diagnostic_segment(check_id)
    )
}

fn proof_doctor_diagnostic_segment(value: &str) -> String {
    let mut segment = String::with_capacity(value.len());
    let mut previous_was_separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            segment.push(character.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator && !segment.is_empty() {
            segment.push('-');
            previous_was_separator = true;
        }
    }
    while segment.ends_with('-') {
        segment.pop();
    }
    if segment.is_empty() {
        "unknown".to_string()
    } else {
        segment
    }
}

struct TransactionPassportCheckSpec {
    id: &'static str,
    fixture: &'static str,
    expected_error: Option<&'static str>,
}

struct TransactionPassportScenarioSpec {
    scenario: ProofDoctorScenario,
    family: &'static str,
    checks: &'static [TransactionPassportCheckSpec],
}

enum WorkflowPreflightExpectation {
    Accepts,
    Rejects(&'static str),
}

struct WorkflowPreflightCheckSpec {
    id: &'static str,
    fixture: &'static str,
    expectation: WorkflowPreflightExpectation,
}

const COMMERCE_PAYMENTS_CHECKS: &[TransactionPassportCheckSpec] = &[
    TransactionPassportCheckSpec {
        id: "commerce_payment_offline_psp",
        fixture: "offline-psp-valid",
        expected_error: None,
    },
    TransactionPassportCheckSpec {
        id: "commerce_payment_wrong_merchant",
        fixture: "payment-wrong-merchant",
        expected_error: Some("payment merchant mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_expired_mandate",
        fixture: "expired-mandate",
        expected_error: Some("mandate expired before payment capture"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_payment_before_budget",
        fixture: "payment-before-budget",
        expected_error: Some("unknown commerce transition"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_quote_evidence_mismatch",
        fixture: "quote-evidence-mismatch",
        expected_error: Some("quote event missing quote evidence"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_open_dispute_completed",
        fixture: "open-dispute-completed",
        expected_error: Some("unresolved payment recovery state"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_fraud_declined",
        fixture: "fraud-declined",
        expected_error: Some("fraud outcome was not accepted"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_currency_mismatch",
        fixture: "currency-mismatch",
        expected_error: Some("payment amount or currency mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_payment_amount_mismatch",
        fixture: "payment-amount-mismatch",
        expected_error: Some("payment amount or currency mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "commerce_mandate_occurrence_limit",
        fixture: "mandate-occurrence-limit",
        expected_error: Some("mandate occurrence limit exceeded"),
    },
];

const RUNTIME_SECURITY_CHECKS: &[TransactionPassportCheckSpec] = &[
    TransactionPassportCheckSpec {
        id: "runtime_side_effecting_call",
        fixture: "valid-side-effecting-call",
        expected_error: None,
    },
    TransactionPassportCheckSpec {
        id: "runtime_missing_execution_lease",
        fixture: "missing-execution-lease",
        expected_error: Some("missing execution lease"),
    },
    TransactionPassportCheckSpec {
        id: "runtime_expired_execution_lease",
        fixture: "expired-execution-lease",
        expected_error: Some("execution lease expired before issuance"),
    },
    TransactionPassportCheckSpec {
        id: "runtime_advisory_used_as_authorization",
        fixture: "advisory-used-as-authorization",
        expected_error: Some("advisory evidence cannot authorize runtime execution"),
    },
    TransactionPassportCheckSpec {
        id: "runtime_ack_outside_lease",
        fixture: "ack-outside-lease",
        expected_error: Some("acknowledgement outside execution lease"),
    },
    TransactionPassportCheckSpec {
        id: "runtime_missing_terminal_receipt",
        fixture: "missing-terminal-receipt",
        expected_error: Some("missing terminal receipt for execution lease"),
    },
    TransactionPassportCheckSpec {
        id: "runtime_reused_nonce",
        fixture: "reused-nonce",
        expected_error: Some("reused nonce"),
    },
    TransactionPassportCheckSpec {
        id: "runtime_sandbox_mismatch",
        fixture: "sandbox-mismatch",
        expected_error: Some("sandbox tool binding mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "runtime_stale_revocation",
        fixture: "stale-revocation",
        expected_error: Some("revocation freshness stale"),
    },
];

const SWARM_AUTHORITY_CHECKS: &[TransactionPassportCheckSpec] = &[
    TransactionPassportCheckSpec {
        id: "swarm_recursive_delegation",
        fixture: "valid-recursive-delegation",
        expected_error: None,
    },
    TransactionPassportCheckSpec {
        id: "swarm_stale_continuation",
        fixture: "stale-continuation",
        expected_error: Some("swarm continuation token is stale"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_budget_allocations_exceed_pool",
        fixture: "budget-allocations-exceed-pool",
        expected_error: Some("swarm budget allocations exceed pool total"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_graph_cycle",
        fixture: "graph-cycle",
        expected_error: Some("swarm task graph cycle at task-child-a"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_join_parent_set_mismatch",
        fixture: "join-parent-set-mismatch",
        expected_error: Some("swarm join receipt parent set mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_replayed_continuation_nonce",
        fixture: "replayed-continuation-nonce",
        expected_error: Some("swarm continuation nonce replay"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_revoked_task",
        fixture: "revoked-task",
        expected_error: Some("swarm task is revoked"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_stale_route_plan",
        fixture: "stale-route-plan",
        expected_error: Some("swarm route-plan receipt is stale"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_route_plan_mismatch",
        fixture: "route-plan-mismatch",
        expected_error: Some("swarm route-plan selected route bridge mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "swarm_witness_child_scope_mismatch",
        fixture: "witness-child-scope-mismatch",
        expected_error: Some("swarm witness child scope mismatch"),
    },
];

const DISCLOSURE_LINEAGE_CHECKS: &[TransactionPassportCheckSpec] = &[
    TransactionPassportCheckSpec {
        id: "disclosure_lineage_valid_ledger",
        fixture: "valid-lineage-ledger",
        expected_error: None,
    },
    TransactionPassportCheckSpec {
        id: "disclosure_lineage_missing_ledger_entry",
        fixture: "missing-ledger-entry",
        expected_error: Some("disclosed field absent from leakage ledger"),
    },
    TransactionPassportCheckSpec {
        id: "disclosure_lineage_unknown_lineage_root",
        fixture: "unknown-lineage-root",
        expected_error: Some("unknown lineage root receipt"),
    },
];

const AGENT_WEB_INTEROP_CHECKS: &[TransactionPassportCheckSpec] = &[
    TransactionPassportCheckSpec {
        id: "agent_web_interop",
        fixture: "valid-webhook-cloudevents",
        expected_error: None,
    },
    TransactionPassportCheckSpec {
        id: "agent_web_external_digest_mismatch",
        fixture: "external-digest-mismatch",
        expected_error: Some("external subject digest mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_missing_required_signature",
        fixture: "missing-required-signature",
        expected_error: Some("missing external signature"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_cloudevents_specversion_mismatch",
        fixture: "cloudevents-specversion-mismatch",
        expected_error: Some("CloudEvents specversion mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_graphql_http_draft_version_missing",
        fixture: "graphql-http-draft-version-missing",
        expected_error: Some("GraphQL over HTTP version must be draft-labeled"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_graphql_errors_projected_as_success",
        fixture: "graphql-errors-projected-as-success",
        expected_error: Some("GraphQL response contains errors"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_mcp_authority_claim_not_limited",
        fixture: "mcp-authority-claim-not-limited",
        expected_error: Some(
            "missing Agent Web unsupported authority limitation: claim.external.mcp_tool_call_is_chio_authority",
        ),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_sidecar_claim_marked_native",
        fixture: "sidecar-claim-marked-native",
        expected_error: Some("sidecar claim presented as native external proof"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_unsupported_claim_not_limited",
        fixture: "unsupported-claim-not-limited",
        expected_error: Some("unsupported claim was not limited"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_x402_detached_from_order",
        fixture: "x402-detached-from-order",
        expected_error: Some("missing x402 order binding"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_external_subject_schema_mismatch",
        fixture: "external-subject-schema-mismatch",
        expected_error: Some("external subject schema mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_acp_client_unsupported_bridge_allowed",
        fixture: "acp-client-unsupported-bridge-allowed",
        expected_error: Some("unsupported ACP-Client bridge allowed"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_email_send_missing_message_digest",
        fixture: "email-send-missing-message-digest",
        expected_error: Some("missing email message digest"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_calendar_time_range_mismatch",
        fixture: "calendar-time-range-mismatch",
        expected_error: Some("Calendar time range changed after approval"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_slack_failed_provider_response",
        fixture: "slack-failed-provider-response",
        expected_error: Some("Slack response was not successful"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_kubernetes_admission_uid_mismatch",
        fixture: "kubernetes-admission-uid-mismatch",
        expected_error: Some("Kubernetes admission response UID mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_oci_tag_only_ref",
        fixture: "oci-tag-only-ref",
        expected_error: Some("OCI reference must be digest-pinned"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_slsa_unverified_provenance",
        fixture: "slsa-unverified-provenance",
        expected_error: Some("unsupported SLSA verification status"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_a2a_authority_claim_not_limited",
        fixture: "a2a-authority-claim-not-limited",
        expected_error: Some(
            "missing Agent Web unsupported authority limitation: claim.external.a2a_task_is_chio_authority",
        ),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_ap2_detached_from_order",
        fixture: "ap2-detached-from-order",
        expected_error: Some("missing ap2 order binding"),
    },
    TransactionPassportCheckSpec {
        id: "agent_web_vc_unbound_receipt",
        fixture: "vc-unbound-receipt",
        expected_error: Some("VC receipt ref is not bound"),
    },
];

const TRUST_MARKET_CHECKS: &[TransactionPassportCheckSpec] = &[
    TransactionPassportCheckSpec {
        id: "trust_market_context_valid",
        fixture: "valid-marketplace-context",
        expected_error: None,
    },
    TransactionPassportCheckSpec {
        id: "trust_market_guarantee_wrong_beneficiary",
        fixture: "guarantee-wrong-beneficiary",
        expected_error: Some("guarantee beneficiary mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_unsupported_guarantee_type",
        fixture: "unsupported-guarantee-type",
        expected_error: Some("guarantee type unsupported"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_unsupported_collateral_source",
        fixture: "unsupported-collateral-source",
        expected_error: Some("collateral source type unsupported"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_guarantee_without_backing",
        fixture: "guarantee-without-backing",
        expected_error: Some("guarantee backing missing"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_reputation_import_overweight",
        fixture: "reputation-import-overweight",
        expected_error: Some("reputation import local weight exceeds policy"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_required_unsupported_market_claim",
        fixture: "required-unsupported-market-claim",
        expected_error: Some("unsupported market claim cannot be required"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_score_recompute_mismatch",
        fixture: "score-recompute-mismatch",
        expected_error: Some("scorecard recompute mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_selected_provider_absent",
        fixture: "selected-provider-absent",
        expected_error: Some("selected provider absent from discovery snapshot"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_sla_wrong_order",
        fixture: "sla-wrong-order",
        expected_error: Some("SLA order mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_slash_authority_outside_jurisdiction",
        fixture: "slash-authority-outside-jurisdiction",
        expected_error: Some("slash authority not bound to jurisdiction"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_stale_discovery",
        fixture: "stale-discovery",
        expected_error: Some("discovery snapshot is stale"),
    },
    TransactionPassportCheckSpec {
        id: "trust_market_stale_reputation",
        fixture: "stale-reputation",
        expected_error: Some("scorecard component evidence is stale"),
    },
];

const PUBLIC_SETTLEMENT_CHECKS: &[TransactionPassportCheckSpec] = &[
    TransactionPassportCheckSpec {
        id: "public_settlement_offline_finality",
        fixture: "valid-offline-finality",
        expected_error: None,
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_wrong_chain_id",
        fixture: "wrong-chain-id",
        expected_error: Some("settlement chain id mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_finality_below_threshold",
        fixture: "finality-below-threshold",
        expected_error: Some("settlement finality below threshold"),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_observed_execution_outside_window",
        fixture: "observed-execution-outside-window",
        expected_error: Some(
            "observed execution timestamp falls outside dispatch execution window",
        ),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_missing_commerce_order_binding",
        fixture: "missing-commerce-order-binding",
        expected_error: Some("public_settlement.commerce_order_id"),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_order_evidence_mismatch",
        fixture: "order-evidence-mismatch",
        expected_error: Some("public settlement commerce order evidence mismatch"),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_missing_oracle_evidence",
        fixture: "missing-oracle-evidence",
        expected_error: Some("receipt requires oracle_evidence for FX-sensitive settlement paths"),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_refunded_posture_without_reversal",
        fixture: "refunded-posture-without-reversal",
        expected_error: Some("refunded dispute posture requires reversed or timed out settlement"),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_missing_independent_head",
        fixture: "missing-independent-head",
        expected_error: Some("public settlement independent head missing"),
    },
    TransactionPassportCheckSpec {
        id: "public_settlement_independent_head_block_hash_mismatch",
        fixture: "independent-head-block-hash-mismatch",
        expected_error: Some("public settlement independent head block hash mismatch"),
    },
];

const TRANSACTION_PASSPORT_SCENARIOS: &[TransactionPassportScenarioSpec] = &[
    TransactionPassportScenarioSpec {
        scenario: ProofDoctorScenario::AgentWebInterop,
        family: "agent-web",
        checks: AGENT_WEB_INTEROP_CHECKS,
    },
    TransactionPassportScenarioSpec {
        scenario: ProofDoctorScenario::CommercePayments,
        family: "commerce-payments",
        checks: COMMERCE_PAYMENTS_CHECKS,
    },
    TransactionPassportScenarioSpec {
        scenario: ProofDoctorScenario::DisclosureLineage,
        family: "disclosure-lineage",
        checks: DISCLOSURE_LINEAGE_CHECKS,
    },
    TransactionPassportScenarioSpec {
        scenario: ProofDoctorScenario::PublicSettlement,
        family: "public-settlement",
        checks: PUBLIC_SETTLEMENT_CHECKS,
    },
    TransactionPassportScenarioSpec {
        scenario: ProofDoctorScenario::RuntimeSecurity,
        family: "runtime-security",
        checks: RUNTIME_SECURITY_CHECKS,
    },
    TransactionPassportScenarioSpec {
        scenario: ProofDoctorScenario::SwarmAuthority,
        family: "swarm-authority",
        checks: SWARM_AUTHORITY_CHECKS,
    },
    TransactionPassportScenarioSpec {
        scenario: ProofDoctorScenario::TrustMarket,
        family: "trust-market",
        checks: TRUST_MARKET_CHECKS,
    },
];

const WORKFLOW_PREFLIGHT_CHECKS: &[WorkflowPreflightCheckSpec] = &[
    WorkflowPreflightCheckSpec {
        id: "workflow_preflight_valid_child_scope",
        fixture: "valid-child-scope",
        expectation: WorkflowPreflightExpectation::Accepts,
    },
    WorkflowPreflightCheckSpec {
        id: "workflow_broader_child_scope",
        fixture: "broader-child-scope",
        expectation: WorkflowPreflightExpectation::Rejects("payment.capture"),
    },
    WorkflowPreflightCheckSpec {
        id: "workflow_planning_artifact_claims_authority",
        fixture: "planning-artifact-claims-authority",
        expectation: WorkflowPreflightExpectation::Rejects("cannot satisfy live authority claims"),
    },
];

fn transaction_passport_fixture_checks(
    root: &Path,
    family: &str,
    specs: &[TransactionPassportCheckSpec],
) -> Vec<ProofDoctorCheck> {
    let family_root = root.join("fixtures/proof-room").join(family);
    specs
        .iter()
        .map(|spec| {
            let fixture_path = family_root.join(spec.fixture);
            match spec.expected_error {
                Some(expected_error) => {
                    check_transaction_passport_rejects(spec.id, &fixture_path, expected_error)
                }
                None => check_transaction_passport_verifies(spec.id, &fixture_path),
            }
        })
        .collect()
}

fn transaction_passport_report(
    root: &Path,
    scenario: ProofDoctorScenario,
    family: &str,
    specs: &[TransactionPassportCheckSpec],
) -> ProofDoctorReport {
    ProofDoctorReport::new(
        scenario.as_str(),
        transaction_passport_fixture_checks(root, family, specs),
    )
}

fn transaction_passport_scenario_report(
    root: &Path,
    scenario: ProofDoctorScenario,
) -> Option<ProofDoctorReport> {
    TRANSACTION_PASSPORT_SCENARIOS
        .iter()
        .find(|spec| spec.scenario == scenario)
        .map(|spec| transaction_passport_report(root, scenario, spec.family, spec.checks))
}

pub(super) fn run_proof_doctor(
    scenario: ProofDoctorScenario,
    root: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let root = match root {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let report = match transaction_passport_scenario_report(&root, scenario) {
        Some(report) => report,
        None => match scenario {
            ProofDoctorScenario::EnterpriseExport => enterprise_export_report(&root),
            ProofDoctorScenario::ProofPackage => proof_package_report(&root),
            ProofDoctorScenario::SingleCallAuthority => single_call_authority_report(&root),
            ProofDoctorScenario::WorkflowPreflight => workflow_preflight_report(&root),
            _ => ProofDoctorReport::new(
                scenario.as_str(),
                vec![failed(
                    "proof_doctor_scenario",
                    &root,
                    "transaction passport scenario is not registered".to_string(),
                )],
            ),
        },
    };
    write_proof_doctor_report(&report, json_output)?;
    if report.failed() {
        Err(CliError::cli_other_error(format!(
            "proof doctor: {} evidence failed",
            scenario.as_str()
        )))
    } else {
        Ok(())
    }
}

fn workflow_preflight_report(root: &Path) -> ProofDoctorReport {
    let workflow_root = root.join("fixtures/proof-room/workflow-preflight");
    let checks = WORKFLOW_PREFLIGHT_CHECKS
        .iter()
        .map(|spec| {
            let path = workflow_root.join(spec.fixture).join("preflight-plan.json");
            match spec.expectation {
                WorkflowPreflightExpectation::Accepts => {
                    check_workflow_preflight_accepts(spec.id, &path)
                }
                WorkflowPreflightExpectation::Rejects(expected_error) => {
                    check_workflow_preflight_rejects(spec.id, &path, expected_error)
                }
            }
        })
        .collect();

    ProofDoctorReport::new("workflow-preflight", checks)
}

fn proof_package_report(root: &Path) -> ProofDoctorReport {
    ProofDoctorReport::new("proof-package", proof_package_catalog_checks(root))
}

fn proof_package_catalog_checks(root: &Path) -> Vec<ProofDoctorCheck> {
    let catalog_path = root.join("fixtures/proof-room/catalog.json");
    let catalog = match read_proof_package_catalog(&catalog_path) {
        Ok(catalog) => catalog,
        Err(error) => return vec![failed("proof_fixture_catalog", &catalog_path, error)],
    };

    catalog
        .fixtures
        .iter()
        .map(|fixture| check_proof_package_catalog_fixture(root, fixture))
        .collect()
}

fn read_proof_package_catalog(path: &Path) -> Result<ProofPackageCatalog, String> {
    let value = read_json(path)?;
    let catalog: ProofPackageCatalog = serde_json::from_value(value)
        .map_err(|error| format!("invalid fixture catalog: {error}"))?;
    if catalog.schema != PROOF_FIXTURE_ROOT_CATALOG_SCHEMA {
        return Err(format!(
            "unsupported fixture catalog schema: {}",
            catalog.schema
        ));
    }
    Ok(catalog)
}

fn check_proof_package_catalog_fixture(
    root: &Path,
    fixture: &ProofPackageFixture,
) -> ProofDoctorCheck {
    let id = fixture_check_id(&fixture.id);
    let fixture_dir = match package_fixture_dir(root, fixture) {
        Ok(path) => path,
        Err(error) => return failed(id, root, error),
    };
    match fixture.kind.as_str() {
        "proof-room" => check_proof_room_bundle_with_id(
            id,
            &fixture_dir.join("proof-room-bundle/manifest.json"),
        ),
        "transaction-passport" => check_transaction_passport_verifies(id, &fixture_dir),
        "negative-transaction-passport" => match package_negative_expected_failure(root, fixture) {
            Ok(Some(expected_failure)) => {
                check_transaction_passport_rejects(id, &fixture_dir, &expected_failure)
            }
            Ok(None) => failed(
                id,
                &fixture_dir,
                "missing expected failure metadata".to_string(),
            ),
            Err(error) => failed(id, &fixture_dir, error),
        },
        "workflow-preflight" => check_workflow_preflight_fixture(id, &fixture_dir),
        "disclosure-crypto-context" => check_crypto_context_fixture(id, &fixture_dir),
        "negative-disclosure-crypto-context" => {
            check_crypto_context_negative_fixture(id, &fixture_dir, &fixture.id)
        }
        _ => failed(
            id,
            &fixture_dir,
            format!("unsupported proof fixture kind: {}", fixture.kind),
        ),
    }
}

fn fixture_check_id(fixture_id: &str) -> String {
    format!("fixture_{}", fixture_id.replace('-', "_"))
}

fn package_fixture_dir(root: &Path, fixture: &ProofPackageFixture) -> Result<PathBuf, String> {
    let path = Path::new(&fixture.path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !path.starts_with("fixtures/proof-room")
    {
        return Err(format!("unsafe proof fixture path: {}", fixture.path));
    }
    Ok(root.join(path))
}

fn package_negative_expected_failure(
    root: &Path,
    fixture: &ProofPackageFixture,
) -> Result<Option<String>, String> {
    let path = Path::new(&fixture.path);
    let relative = path
        .strip_prefix("fixtures/proof-room")
        .map_err(|_| format!("unsafe proof fixture path: {}", fixture.path))?;
    let Some(fixture_name) = relative.file_name().and_then(|name| name.to_str()) else {
        return Err(format!(
            "proof fixture path has no fixture name: {}",
            fixture.path
        ));
    };
    let Some(family) = relative.parent() else {
        return Ok(None);
    };
    let negative_case_path = root
        .join("fixtures/proof-room")
        .join(family)
        .join("negatives")
        .join(format!("{fixture_name}.json"));
    if !negative_case_path.is_file() {
        return Ok(None);
    }
    let value = read_json(&negative_case_path)?;
    let negative_case: ProofPackageNegativeCase = serde_json::from_value(value)
        .map_err(|error| format!("invalid negative fixture metadata: {error}"))?;
    Ok(Some(negative_case.expected_failure_code))
}

fn enterprise_export_report(root: &Path) -> ProofDoctorReport {
    let enterprise_root = root.join("fixtures/proof-room/enterprise-export");
    let valid = enterprise_root.join("valid-autonomous-commerce");
    let mut checks = vec![check_transaction_passport_verifies(
        "enterprise_export_autonomous_commerce",
        &valid,
    )];
    checks.extend(enterprise_export_negative_checks(&enterprise_root));

    ProofDoctorReport::new("enterprise-export", checks)
}

fn enterprise_export_negative_checks(enterprise_root: &Path) -> Vec<ProofDoctorCheck> {
    let negatives_root = enterprise_root.join("negatives");
    let entries = match fs::read_dir(&negatives_root) {
        Ok(entries) => entries,
        Err(error) => {
            return vec![failed(
                "enterprise_export_negative_fixtures",
                &negatives_root,
                format!("missing or unreadable enterprise negative fixtures: {error}"),
            )];
        }
    };

    let mut negative_paths = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return vec![failed(
                    "enterprise_export_negative_fixtures",
                    &negatives_root,
                    format!("unreadable enterprise negative fixture entry: {error}"),
                )];
            }
        };
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            negative_paths.push(path);
        }
    }
    negative_paths.sort();
    if negative_paths.is_empty() {
        return vec![failed(
            "enterprise_export_negative_fixtures",
            &negatives_root,
            "missing enterprise negative fixtures".to_string(),
        )];
    }

    negative_paths
        .into_iter()
        .map(|path| enterprise_export_negative_check(enterprise_root, &path))
        .collect()
}

fn enterprise_export_negative_check(enterprise_root: &Path, path: &Path) -> ProofDoctorCheck {
    let negative_case = match read_enterprise_export_negative_case(path) {
        Ok(negative_case) => negative_case,
        Err(error) => {
            return failed(
                "enterprise_export_negative_fixture",
                path,
                format!("invalid enterprise negative fixture metadata: {error}"),
            );
        }
    };
    let check_id = format!("enterprise_export_{}", negative_case.id.replace('-', "_"));
    if !is_safe_fixture_component(&negative_case.id) {
        return failed(
            check_id,
            path,
            format!(
                "unsafe enterprise negative fixture id: {}",
                negative_case.id
            ),
        );
    }
    check_transaction_passport_rejects(
        check_id,
        &enterprise_root.join(&negative_case.id),
        &negative_case.expected_failure_code,
    )
}

fn read_enterprise_export_negative_case(
    path: &Path,
) -> Result<EnterpriseExportNegativeCase, String> {
    let value = read_json(path)?;
    let negative_case: EnterpriseExportNegativeCase = serde_json::from_value(value)
        .map_err(|error| format!("invalid enterprise negative fixture metadata: {error}"))?;
    if negative_case.schema != "chio.enterprise-export.negative-fixture.v1" {
        return Err(format!(
            "unsupported enterprise negative fixture schema: {}",
            negative_case.schema
        ));
    }
    if negative_case.expected_failure_code.is_empty() {
        return Err("enterprise negative fixture missing expected failure code".to_string());
    }
    Ok(negative_case)
}

fn is_safe_fixture_component(component: &str) -> bool {
    !component.is_empty()
        && !component.contains('/')
        && !component.contains('\\')
        && std::path::Path::new(component)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn single_call_authority_report(root: &Path) -> ProofDoctorReport {
    let valid_passport =
        root.join("fixtures/proof-room/minimal-passport/valid/transaction-passport.json");
    let invalid_passport = root.join(
        "fixtures/proof-room/minimal-passport/invalid-policy-digest-mismatch/transaction-passport.json",
    );
    let first_run = root.join("fixtures/proof-room/first-run/single-call-authority");
    let allow_receipt = first_run.join("allow-receipt.json");
    let denial_receipt = first_run.join("denial-receipt.json");
    let verifier_report = first_run.join("verifier-report.json");
    let proof_room_bundle_manifest = first_run.join("proof-room-bundle/manifest.json");
    let command_log = first_run.join("command-log.json");
    let release_truth = first_run.join("release-truth.json");

    let checks = vec![
        check_valid_passport(&valid_passport),
        check_invalid_policy_digest(&invalid_passport),
        check_terminal_receipt("allow_receipt", &allow_receipt, "allowed_executed"),
        check_terminal_receipt("denial_receipt", &denial_receipt, "denied_guard_request"),
        check_verifier_report(&valid_passport, &verifier_report),
        check_proof_room_bundle(&proof_room_bundle_manifest),
        check_schema_file(
            "command_log",
            &command_log,
            "chio.proof.first-run.command-log.v1",
        ),
        check_schema_file(
            "release_truth",
            &release_truth,
            "chio.proof.release-truth.v1",
        ),
        check_docker_quickstart_evidence(&release_truth, &proof_room_bundle_manifest),
    ];

    ProofDoctorReport::new("single-call-authority", checks)
}

fn check_transaction_passport_verifies(id: impl Into<String>, dir: &Path) -> ProofDoctorCheck {
    let id = id.into();
    let path = dir.join("transaction-passport.json");
    match super::verify_transaction_passport_file(&path) {
        Ok(_) => passed(id, &path, "transaction passport verified"),
        Err(error) => failed(
            id,
            &path,
            format!("transaction passport failed verification: {error}"),
        ),
    }
}

fn check_transaction_passport_rejects(
    id: impl Into<String>,
    dir: &Path,
    expected_error: &str,
) -> ProofDoctorCheck {
    let id = id.into();
    let path = dir.join("transaction-passport.json");
    let env_overrides = match negative_verifier_context_for_fixture_dir(dir) {
        Ok(context) => context.apply(),
        Err(error) => return failed(id, dir, error),
    };
    let _env_overrides = env_overrides;
    match super::verify_transaction_passport_file(&path) {
        Ok(_) => failed(
            id,
            &path,
            "transaction passport unexpectedly verified".to_string(),
        ),
        Err(error) => {
            let error_message = error.to_string();
            let observed = semantic_negative_failure_code(&error_message);
            if error_message.contains(expected_error)
                || negative_failure_code_matches(&observed, expected_error)
            {
                passed(id, &path, "transaction passport rejected")
            } else {
                failed(
                    id,
                    &path,
                    format!(
                        "transaction passport failed for the wrong reason: expected {expected_error}; observed {observed}: {error}"
                    ),
                )
            }
        }
    }
}

fn negative_verifier_context_for_fixture_dir(
    dir: &Path,
) -> Result<ProofPackageVerifierContext, String> {
    let Some(fixture_name) = dir.file_name().and_then(|name| name.to_str()) else {
        return Ok(ProofPackageVerifierContext::default());
    };
    let Some(family_root) = dir.parent() else {
        return Ok(ProofPackageVerifierContext::default());
    };
    let metadata_path = family_root
        .join("negatives")
        .join(format!("{fixture_name}.json"));
    if !metadata_path.is_file() {
        return Ok(ProofPackageVerifierContext::default());
    }
    let value = read_json(&metadata_path)?;
    let negative_case: ProofPackageNegativeCase = serde_json::from_value(value)
        .map_err(|error| format!("invalid negative fixture metadata: {error}"))?;
    Ok(negative_case.verifier_context)
}

fn check_workflow_preflight_accepts(id: impl Into<String>, path: &Path) -> ProofDoctorCheck {
    let id = id.into();
    let plan = match read_workflow_preflight_plan(path) {
        Ok(plan) => plan,
        Err(error) => return failed(id, path, error),
    };
    match chio_workflow::evaluate_workflow_preflight(&plan) {
        Ok(report)
            if report.verdict == chio_workflow::WorkflowPreflightVerdict::Accepted
                && report.evidence_class == "planning"
                && report.live_authority_claims.is_empty() =>
        {
            passed(id, path, "workflow preflight accepted")
        }
        Ok(report) => failed(
            id,
            path,
            format!(
                "workflow preflight produced unexpected verdict: {:?}",
                report.verdict
            ),
        ),
        Err(error) => failed(id, path, format!("workflow preflight failed: {error}")),
    }
}

fn check_workflow_preflight_rejects(
    id: impl Into<String>,
    path: &Path,
    expected_error: &str,
) -> ProofDoctorCheck {
    let id = id.into();
    let plan = match read_workflow_preflight_plan(path) {
        Ok(plan) => plan,
        Err(error) => return failed(id, path, error),
    };
    match chio_workflow::evaluate_workflow_preflight(&plan) {
        Ok(report) if report.verdict == chio_workflow::WorkflowPreflightVerdict::Rejected => {
            let message = report
                .rejected_checks
                .iter()
                .map(|check| check.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            if message.contains(expected_error) {
                passed(id, path, "workflow preflight rejected")
            } else {
                failed(
                    id,
                    path,
                    format!(
                        "workflow preflight rejected for the wrong reason: expected {expected_error}, got {message}"
                    ),
                )
            }
        }
        Ok(_) => failed(
            id,
            path,
            "workflow preflight unexpectedly accepted".to_string(),
        ),
        Err(error) => failed(id, path, format!("workflow preflight failed: {error}")),
    }
}

fn check_workflow_preflight_fixture(id: impl Into<String>, dir: &Path) -> ProofDoctorCheck {
    let id = id.into();
    let path = dir.join("preflight-plan.json");
    if let Some(expected_error) = workflow_preflight_fixture_expected_error(&id) {
        return check_workflow_preflight_rejects(id, &path, expected_error);
    }
    let plan = match read_workflow_preflight_plan(&path) {
        Ok(plan) => plan,
        Err(error) => return failed(id, &path, error),
    };
    match chio_workflow::evaluate_workflow_preflight(&plan) {
        Ok(report)
            if report.verdict == chio_workflow::WorkflowPreflightVerdict::Accepted
                && report.evidence_class == "planning"
                && report.live_authority_claims.is_empty() =>
        {
            passed(id, &path, "workflow preflight accepted")
        }
        Ok(report) if report.verdict == chio_workflow::WorkflowPreflightVerdict::Rejected => {
            passed(id, &path, "workflow preflight rejected")
        }
        Ok(report) => failed(
            id,
            &path,
            format!(
                "workflow preflight produced unexpected verdict: {:?}",
                report.verdict
            ),
        ),
        Err(error) => failed(id, &path, format!("workflow preflight failed: {error}")),
    }
}

fn workflow_preflight_fixture_expected_error(id: &str) -> Option<&'static str> {
    match id {
        "fixture_workflow_preflight_broader_child_scope" => Some("outside parent scope"),
        "fixture_workflow_preflight_planning_artifact_claims_authority" => {
            Some("cannot satisfy live authority claims")
        }
        _ => None,
    }
}

fn check_crypto_context_fixture(id: impl Into<String>, dir: &Path) -> ProofDoctorCheck {
    let id = id.into();
    let path = dir.join("crypto-context-report.json");
    let context_path = dir.join("verification-context.json");
    let context_bytes = match fs::read(&context_path) {
        Ok(bytes) => bytes,
        Err(error) => return failed(id, &context_path, format!("missing or unreadable: {error}")),
    };
    let report_bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => return failed(id, &path, format!("missing or unreadable: {error}")),
    };
    let proof_path = dir.join("selective-disclosure-proof.json");
    let proof_bytes = match fs::read(&proof_path) {
        Ok(bytes) => bytes,
        Err(error) => return failed(id, &proof_path, format!("missing or unreadable: {error}")),
    };
    let profile_path = dir.join("verifier-privacy-profile.json");
    let profile_bytes = match fs::read(&profile_path) {
        Ok(bytes) => bytes,
        Err(error) => return failed(id, &profile_path, format!("missing or unreadable: {error}")),
    };
    let verified_report_bytes = match chio_proof_room::crypto_context_verified_report_bytes_with_bbs(
        &context_bytes,
        &report_bytes,
        &proof_bytes,
        &profile_bytes,
        &id,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return failed(
                id,
                &context_path,
                format!("crypto context check failed: {error}"),
            );
        }
    };
    let report: serde_json::Value = match serde_json::from_slice(&verified_report_bytes) {
        Ok(report) => report,
        Err(error) => return failed(id, &path, format!("invalid JSON: {error}")),
    };
    if report.get("schema").and_then(serde_json::Value::as_str)
        != Some("chio.disclosure.crypto-context-report.v1")
    {
        return failed(
            id,
            &path,
            "crypto context report schema mismatch".to_string(),
        );
    }
    if report.get("verdict").and_then(serde_json::Value::as_str) != Some("verified") {
        return failed(id, &path, "crypto context was not verified".to_string());
    }
    let Some(verified_claims) = report
        .get("verified_claims")
        .and_then(serde_json::Value::as_array)
    else {
        return failed(
            id,
            &path,
            "crypto context report missing verified claims".to_string(),
        );
    };
    let has_context_claim = verified_claims
        .iter()
        .any(|claim| claim.as_str() == Some("claim.disclosure.crypto_context_bound"));
    if !has_context_claim {
        return failed(
            id,
            &path,
            "crypto context report missing context claim".to_string(),
        );
    }
    passed(id, &path, "crypto context verified")
}

fn check_crypto_context_negative_fixture(
    id: impl Into<String>,
    dir: &Path,
    fixture_id: &str,
) -> ProofDoctorCheck {
    let id = id.into();
    let path = dir.join("verification-context.json");
    let context_bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => return failed(id, &path, format!("missing or unreadable: {error}")),
    };
    let proof_path = dir.join("selective-disclosure-proof.json");
    let proof_bytes = match fs::read(&proof_path) {
        Ok(bytes) => bytes,
        Err(error) => return failed(id, &proof_path, format!("missing or unreadable: {error}")),
    };
    let profile_path = dir.join("verifier-privacy-profile.json");
    let profile_bytes = match fs::read(&profile_path) {
        Ok(bytes) => bytes,
        Err(error) => return failed(id, &profile_path, format!("missing or unreadable: {error}")),
    };
    match chio_proof_room::crypto_context_rejected_report_bytes_with_bbs(
        &context_bytes,
        &proof_bytes,
        &profile_bytes,
        fixture_id,
    ) {
        Ok(report_bytes) => {
            let report: serde_json::Value = match serde_json::from_slice(&report_bytes) {
                Ok(report) => report,
                Err(error) => {
                    return failed(
                        id,
                        &path,
                        format!("crypto context rejection report invalid JSON: {error}"),
                    );
                }
            };
            if report.get("verdict").and_then(serde_json::Value::as_str) != Some("rejected") {
                return failed(
                    id,
                    &path,
                    "crypto context unexpectedly verified".to_string(),
                );
            }
            passed(id, &path, "crypto context rejected")
        }
        Err(error) => failed(id, &path, format!("crypto context check failed: {error}")),
    }
}

fn read_workflow_preflight_plan(
    path: &Path,
) -> Result<chio_workflow::WorkflowPreflightPlan, String> {
    let bytes = fs::read(path).map_err(|error| format!("missing or unreadable: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid JSON: {error}"))
}

fn check_valid_passport(path: &Path) -> ProofDoctorCheck {
    match super::verify_transaction_passport_file(path) {
        Ok(_) => passed("valid_minimal_passport", path, "valid passport verified"),
        Err(error) => failed(
            "valid_minimal_passport",
            path,
            format!("valid passport failed verification: {error}"),
        ),
    }
}

fn check_invalid_policy_digest(path: &Path) -> ProofDoctorCheck {
    match super::verify_transaction_passport_file(path) {
        Ok(_) => failed(
            "invalid_policy_digest_mismatch",
            path,
            "invalid passport unexpectedly verified".to_string(),
        ),
        Err(error)
            if error
                .to_string()
                .contains("verifier policy digest mismatch") =>
        {
            passed(
                "invalid_policy_digest_mismatch",
                path,
                "policy digest mismatch rejected",
            )
        }
        Err(error) => failed(
            "invalid_policy_digest_mismatch",
            path,
            format!("invalid passport failed for the wrong reason: {error}"),
        ),
    }
}

fn check_terminal_receipt(
    id: &'static str,
    path: &Path,
    expected_status: &str,
) -> ProofDoctorCheck {
    let value = match read_json(path) {
        Ok(value) => value,
        Err(error) => return failed(id, path, error),
    };
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some(PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA)
    {
        return failed(id, path, "receipt schema mismatch".to_string());
    }
    if value
        .get("terminal_status")
        .and_then(serde_json::Value::as_str)
        != Some(expected_status)
    {
        return failed(
            id,
            path,
            format!("terminal_status is not {expected_status}"),
        );
    }
    if value
        .get("policy_digest")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return failed(id, path, "missing policy_digest".to_string());
    }
    passed(id, path, "terminal receipt present")
}

fn check_verifier_report(valid_passport: &Path, path: &Path) -> ProofDoctorCheck {
    let expected = match super::verify_transaction_passport_file(valid_passport) {
        Ok(report) => report,
        Err(error) => {
            return failed(
                "verifier_report",
                path,
                format!("valid passport did not produce verifier report: {error}"),
            );
        }
    };
    let actual = match read_json(path) {
        Ok(value) => value,
        Err(error) => return failed("verifier_report", path, error),
    };
    if actual == expected {
        passed(
            "verifier_report",
            path,
            "verifier report matches CLI verifier output",
        )
    } else {
        failed(
            "verifier_report",
            path,
            "verifier report does not match CLI verifier output".to_string(),
        )
    }
}

fn check_proof_room_bundle(path: &Path) -> ProofDoctorCheck {
    check_proof_room_bundle_with_id("proof_room_bundle", path)
}

fn check_proof_room_bundle_with_id(id: impl Into<String>, path: &Path) -> ProofDoctorCheck {
    let id = id.into();
    match chio_proof_room::verify_proof_room_bundle(path) {
        Ok(()) => passed(id, path, "Proof Room bundle binds verifier report hash"),
        Err(error) => failed(id, path, error.to_string()),
    }
}

fn check_schema_file(id: &'static str, path: &Path, schema: &str) -> ProofDoctorCheck {
    let value = match read_json(path) {
        Ok(value) => value,
        Err(error) => return failed(id, path, error),
    };
    if value.get("schema").and_then(serde_json::Value::as_str) == Some(schema) {
        passed(id, path, "evidence file present")
    } else {
        failed(id, path, format!("schema is not {schema}"))
    }
}

fn check_docker_quickstart_evidence(
    release_truth_path: &Path,
    manifest_path: &Path,
) -> ProofDoctorCheck {
    let release_truth = match read_json(release_truth_path) {
        Ok(value) => value,
        Err(error) => return failed("docker_quickstart_evidence", release_truth_path, error),
    };
    let docker_quickstart_claimed = release_truth
        .get("truth")
        .and_then(|truth| truth.get("docker_quickstart"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !docker_quickstart_claimed {
        return passed(
            "docker_quickstart_evidence",
            manifest_path,
            "Docker quickstart is not claimed by release truth",
        );
    }

    let manifest = match read_json(manifest_path) {
        Ok(value) => value,
        Err(error) => return failed("docker_quickstart_evidence", manifest_path, error),
    };
    match verify_docker_quickstart_evidence(&manifest, manifest_path) {
        Ok(()) => passed(
            "docker_quickstart_evidence",
            manifest_path,
            "Docker quickstart release truth is backed by bundle evidence",
        ),
        Err(error) => failed("docker_quickstart_evidence", manifest_path, error),
    }
}

fn verify_docker_quickstart_evidence(
    manifest: &serde_json::Value,
    manifest_path: &Path,
) -> Result<(), String> {
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "release truth requires Docker quickstart evidence".to_string())?;
    let matches = artifacts
        .iter()
        .filter(|artifact| {
            artifact.get("schema").and_then(serde_json::Value::as_str)
                == Some(DOCKER_QUICKSTART_EVIDENCE_SCHEMA)
        })
        .collect::<Vec<_>>();
    let [artifact] = matches.as_slice() else {
        return Err("release truth requires Docker quickstart evidence".to_string());
    };
    if artifact.get("path").and_then(serde_json::Value::as_str)
        != Some(DOCKER_QUICKSTART_EVIDENCE_PATH)
    {
        return Err("Docker quickstart evidence path mismatch".to_string());
    }
    let expected_sha256 = artifact
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "Docker quickstart evidence digest missing".to_string())?;
    let bundle_dir = manifest_path
        .parent()
        .ok_or_else(|| "Proof Room bundle manifest has no parent".to_string())?;
    let evidence_path = resolve_bundle_artifact_path(bundle_dir, DOCKER_QUICKSTART_EVIDENCE_PATH)
        .map_err(|error| error.to_string())?;
    let evidence_bytes = fs::read(&evidence_path)
        .map_err(|error| format!("Docker quickstart evidence missing or unreadable: {error}"))?;
    let actual_sha256 = chio_core::sha256_hex(&evidence_bytes);
    if actual_sha256 != expected_sha256 {
        return Err("Docker quickstart evidence digest mismatch".to_string());
    }
    let evidence: serde_json::Value = serde_json::from_slice(&evidence_bytes)
        .map_err(|error| format!("Docker quickstart evidence invalid JSON: {error}"))?;
    if evidence.get("schema").and_then(serde_json::Value::as_str)
        != Some(DOCKER_QUICKSTART_EVIDENCE_SCHEMA)
    {
        return Err("Docker quickstart evidence schema mismatch".to_string());
    }
    if evidence.get("verdict").and_then(serde_json::Value::as_str) != Some("verified") {
        return Err("Docker quickstart evidence is not verified".to_string());
    }
    require_docker_quickstart_evidence_field(&evidence, "target", DOCKER_QUICKSTART_TARGET)?;
    require_docker_quickstart_evidence_field(
        &evidence,
        "dockerfile",
        DOCKER_QUICKSTART_DOCKERFILE,
    )?;
    require_docker_quickstart_evidence_field(
        &evidence,
        "server_binary",
        DOCKER_QUICKSTART_SERVER_BINARY,
    )?;
    require_docker_quickstart_evidence_field(
        &evidence,
        "bundle_path",
        DOCKER_QUICKSTART_BUNDLE_PATH,
    )?;
    require_docker_quickstart_evidence_field(
        &evidence,
        "doctor_report_path",
        DOCKER_QUICKSTART_DOCTOR_REPORT_PATH,
    )?;
    require_docker_quickstart_evidence_field(
        &evidence,
        "evidence_source",
        DOCKER_QUICKSTART_EVIDENCE_SOURCE,
    )?;
    let endpoints = evidence
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Docker quickstart evidence endpoints missing".to_string())?;
    for (path, expected) in REQUIRED_DOCKER_ENDPOINTS {
        let observed = endpoints.iter().any(|endpoint| {
            endpoint.get("path").and_then(serde_json::Value::as_str) == Some(*path)
                && endpoint.get("expected").and_then(serde_json::Value::as_str) == Some(*expected)
        });
        if !observed {
            return Err(format!(
                "Docker quickstart evidence endpoint missing: {path}"
            ));
        }
    }
    Ok(())
}

fn require_docker_quickstart_evidence_field(
    evidence: &serde_json::Value,
    field: &str,
    expected: &str,
) -> Result<(), String> {
    if evidence.get(field).and_then(serde_json::Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(format!("Docker quickstart evidence {field} mismatch"))
    }
}

fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = fs::read(path).map_err(|error| format!("missing or unreadable: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid JSON: {error}"))
}

fn passed(id: impl Into<String>, path: &Path, message: &str) -> ProofDoctorCheck {
    ProofDoctorCheck {
        id: id.into(),
        code: String::new(),
        status: "passed",
        path: path.to_string_lossy().into_owned(),
        message: message.to_string(),
    }
}

fn failed(id: impl Into<String>, path: &Path, message: String) -> ProofDoctorCheck {
    ProofDoctorCheck {
        id: id.into(),
        code: String::new(),
        status: "failed",
        path: path.to_string_lossy().into_owned(),
        message,
    }
}

fn write_proof_doctor_report(
    report: &ProofDoctorReport,
    json_output: bool,
) -> Result<(), CliError> {
    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, report)?;
        stdout.write_all(b"\n")?;
    } else {
        writeln!(stdout, "chio proof doctor {}", report.scenario)?;
        for check in &report.checks {
            writeln!(
                stdout,
                "  [{}] {}: {}",
                check.status, check.id, check.message
            )?;
        }
        writeln!(stdout, "verdict: {}", report.verdict)?;
    }
    Ok(())
}
