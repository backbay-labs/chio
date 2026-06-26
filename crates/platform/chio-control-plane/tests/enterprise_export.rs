use std::collections::BTreeMap;

use chio_core::Keypair;
use chio_test_support::prelude::*;
use serde_json::{json, Value};

use chio_control_plane::enterprise_export::{verify_enterprise_export, EnterpriseExportBundle};
use chio_control_plane::transaction_passport::TransactionPassport;

const CLAIM_DATA_GOVERNANCE_BOUND: &str = "claim.enterprise.data_governance_bound";
const CLAIM_EVIDENCE_EXPORT_DIGEST_BOUND: &str = "claim.enterprise.evidence_export_digest_bound";
const CLAIM_TELEMETRY_PROJECTION_BOUND: &str = "claim.enterprise.telemetry_projection_bound";
const CLAIM_EXPORT_APPROVAL_BOUND: &str = "claim.enterprise.export_approval_bound";
const CLAIM_CONTROL_MAP_BOUND: &str = "claim.enterprise.control_map_bound";
const TRANSACTION_PASSPORT_SIGNATURE_SEED: [u8; 32] = [7; 32];
const RISK_POLICY_ID: &str = "policy-enterprise-valid";

#[derive(Debug, Clone, Copy)]
enum EnterpriseCase {
    Valid,
    MissingApproval,
    ExportDigestMismatch,
    OverdisclosedPii,
    TelemetryDigestMismatch,
    ControlMapMissingGate,
    RiskMissingReserve,
    RiskCoverageSubjectMismatch,
    RiskDuplicateReserveReceiptId,
    RiskDoubleConsumedReserve,
    RiskMarketSlashFacilityReserve,
    RiskMarketSlashWithSanctionBridge,
    RiskMarketSlashMissingSanctionReserveLedger,
    RiskMarketSlashMissingJurisdiction,
    RiskOpenAppealReserveRelease,
    RiskOpenAppealClaimPayout,
    RiskOpenAppealMarketSlash,
    RiskOpenAppealWriteOff,
    RiskReverseSlashWithoutPriorPenalty,
    RiskReverseSlashExceedsPriorPenalty,
    RiskReverseSlashNetReconciled,
    RiskSettlementCounterpartyBound,
    RiskPayoutMatchedLifecycle,
    RiskSettlementCounterpartyMissing,
    RiskSettlementCounterpartyMismatch,
    RiskSettlementCounterpartyUnboundPayee,
    RiskReserveReleaseWithCounterparties,
    RiskClaimOutsideCoverage,
    RiskMultipleCoveredClaimPayouts,
    RiskDuplicateCoveredClaimId,
    RiskFacilityLifecycleMissingEvidence,
    RiskFacilityLifecycleMissingAuthority,
    RiskCoverageBoundWithoutLifecycle,
    RiskFacilityLifecycleMissingInitialGates,
    RiskCapitalAllocatableWithoutLifecycle,
    RiskClosedFacilityUnreconciledReserve,
    RiskInsuranceCopyExceedsActuarialEvidence,
    RiskExposureExceedsCapital,
    RiskCapitalAdequacyBreach,
    RiskActuarialBacktestBreach,
}

fn json_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).test_expect("test json serializes")
}

fn transaction_passport_keypair() -> Keypair {
    Keypair::from_seed(&TRANSACTION_PASSPORT_SIGNATURE_SEED)
}

fn sign_transaction_passport(passport: &mut TransactionPassport) {
    let keypair = transaction_passport_keypair();
    passport.issuer = format!("did:chio:{}", keypair.public_key().to_hex());
    passport.signature = String::new();
    passport.signature =
        chio_control_plane::transaction_passport::sign_transaction_passport(passport, &keypair)
            .test_expect("transaction passport signs");
}

fn approval_keypair() -> Keypair {
    Keypair::from_seed(&[61u8; 32])
}

fn risk_comptroller_keypair() -> Keypair {
    Keypair::from_seed(&[63u8; 32])
}

fn receipt_kernel_keypair() -> Keypair {
    Keypair::from_seed(&[23u8; 32])
}

fn approval_approver() -> String {
    format!("did:chio:{}", approval_keypair().public_key().to_hex())
}

fn signed_approval_case(value: Value) -> Value {
    signed_value_with_key(value, &approval_keypair())
}

fn signed_risk_comptroller_report(value: Value) -> Value {
    signed_value_with_key(value, &risk_comptroller_keypair())
}

fn signed_value_with_key(mut value: Value, keypair: &Keypair) -> Value {
    value
        .as_object_mut()
        .test_expect("signed artifact is an object")
        .remove("signature");
    let (signature, _) = keypair.sign_canonical(&value).test_expect("artifact signs");
    value["signature"] = Value::String(format!(
        "sig-ed25519:{}:{}",
        keypair.public_key().to_hex(),
        signature.to_hex()
    ));
    value
}

fn artifact_ref(role: &str, path: &str, bytes: &[u8]) -> Value {
    json!({
        "role": role,
        "path": path,
        "sha256": chio_core::sha256_hex(bytes)
    })
}

fn export_bundle_digest(artifacts: &[Value]) -> String {
    let artifact_list = artifacts.to_vec();
    let canonical = chio_core::canonical_json_bytes(&artifact_list)
        .test_expect("export artifacts canonicalize");
    chio_core::sha256_hex(&canonical)
}

fn capital_instructions_for_claim_payouts(reserve_ledger: &Value) -> Value {
    let entries = reserve_ledger
        .as_array()
        .test_expect("reserve ledger is an array");
    Value::Array(
        entries
            .iter()
            .filter(|entry| entry.get("lane").and_then(Value::as_str) == Some("claim_payout"))
            .map(|entry| {
                let entry_id = entry["entry_id"]
                    .as_str()
                    .test_expect("claim payout entry id");
                let claim_id = entry["claim_id"]
                    .as_str()
                    .test_expect("claim payout claim id");
                let reserve_ref = entry["reserve_ref"]
                    .as_str()
                    .test_expect("claim payout reserve ref");
                let currency = entry["currency"]
                    .as_str()
                    .test_expect("claim payout currency");
                let units = entry["units"].as_u64().test_expect("claim payout units");
                let settlement_ref = entry["settlement_ref"]
                    .as_str()
                    .test_expect("claim payout settlement ref");
                json!({
                    "instruction_id": format!("capital-instruction-{entry_id}"),
                    "reserve_entry_id": entry_id,
                    "order_id": "order-commerce-001",
                    "claim_id": claim_id,
                    "reserve_ref": reserve_ref,
                    "currency": currency,
                    "units": units,
                    "settlement_ref": settlement_ref,
                    "intended_action": "transfer_funds",
                    "source_kind": "facility_commitment",
                    "intended_state": "pending_execution",
                    "reconciled_state": "not_observed"
                })
            })
            .collect(),
    )
}

fn push_artifact(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut Vec<Value>,
    graph_role: &str,
    node_id: &str,
    schema: &str,
    path: &str,
    bytes: Vec<u8>,
) {
    let sha256 = chio_core::sha256_hex(&bytes);
    graph_nodes.push(json!({
        "id": node_id,
        "schema": schema,
        "path": path,
        "sha256": sha256,
        "role": graph_role
    }));
    artifacts.insert(path.to_string(), bytes);
}

fn normalize_graph_node_ids(graph_nodes: &mut [Value], graph_edges: &mut [Value]) {
    let mut node_id_map = BTreeMap::new();
    for node in graph_nodes {
        let old_id = node["id"]
            .as_str()
            .test_expect("graph node id exists")
            .to_string();
        let digest = node["sha256"]
            .as_str()
            .test_expect("graph node digest exists")
            .to_string();
        node["id"] = Value::String(digest.clone());
        node_id_map.insert(old_id, digest);
    }
    for edge in graph_edges {
        for field in ["from", "to"] {
            let Some(old_id) = edge[field].as_str() else {
                continue;
            };
            if let Some(new_id) = node_id_map.get(old_id) {
                edge[field] = Value::String(new_id.clone());
            }
        }
    }
}

fn push_ref_artifact_if_missing(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut Vec<Value>,
    graph_role: &str,
    node_id: &str,
    schema: &str,
) {
    if graph_nodes
        .iter()
        .any(|node| node.get("id").and_then(Value::as_str) == Some(node_id))
    {
        return;
    }
    let bytes = json_bytes(json!({
        "schema": schema,
        "id": node_id,
        "issued_at": "2026-06-10T00:00:00Z",
        "order_id": "order-commerce-001",
        "status": "verified"
    }));
    let path = format!("{node_id}.json");
    push_artifact(
        artifacts,
        graph_nodes,
        graph_role,
        node_id,
        schema,
        path.as_str(),
        bytes,
    );
}

fn push_reserve_ledger_ref_artifacts(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut Vec<Value>,
    reserve_ledger: &Value,
) {
    for entry in reserve_ledger
        .as_array()
        .test_expect("reserve ledger array")
    {
        let receipt_ref = entry["receipt_ref"]
            .as_str()
            .test_expect("reserve ledger receipt ref");
        push_ref_artifact_if_missing(
            artifacts,
            graph_nodes,
            "report",
            receipt_ref,
            "chio.receipt.v1",
        );
        let settlement_ref = entry["settlement_ref"]
            .as_str()
            .test_expect("reserve ledger settlement ref");
        push_ref_artifact_if_missing(
            artifacts,
            graph_nodes,
            "report",
            settlement_ref,
            "chio.enterprise.evidence-export-bundle.v1",
        );
    }
}

fn facility_lifecycle_from_start(mut transitions_after_reserve_held: Vec<Value>) -> Value {
    let mut transitions = vec![
        json!({
            "transition_id": "facility-transition-underwriting-ready",
            "policy_id": RISK_POLICY_ID,
            "from_state": "evidence_cold",
            "to_state": "underwriting_ready",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        }),
        json!({
            "transition_id": "facility-transition-facility-granted",
            "policy_id": RISK_POLICY_ID,
            "from_state": "underwriting_ready",
            "to_state": "facility_granted",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        }),
        json!({
            "transition_id": "facility-transition-reserve-held",
            "policy_id": RISK_POLICY_ID,
            "from_state": "facility_granted",
            "to_state": "reserve_held",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        }),
    ];
    transitions.append(&mut transitions_after_reserve_held);
    Value::Array(transitions)
}

fn enterprise_bundle(case: EnterpriseCase) -> EnterpriseExportBundle {
    let passport = TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-enterprise-valid".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        not_before: None,
        expires_at: None,
        issuer: "did:chio:66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
            .to_string(),
        evidence_graph_sha256: String::new(),
        evidence_graph_path: "evidence-graph.json".to_string(),
        claim_set_sha256: "0".repeat(64),
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: String::new(),
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: "0".repeat(128),
    };

    let mut artifacts = BTreeMap::new();
    let mut graph_nodes = Vec::new();

    let reserve_units: u64 = match case {
        EnterpriseCase::RiskMissingReserve => 0,
        _ => 1_200,
    };
    let capital_units: u64 = match case {
        EnterpriseCase::RiskExposureExceedsCapital => 4_000,
        EnterpriseCase::RiskCapitalAdequacyBreach => 5_500,
        _ => 10_000,
    };
    let coverage_subject = match case {
        EnterpriseCase::RiskCoverageSubjectMismatch => "did:chio:buyer-other",
        _ => "did:chio:buyer-enterprise",
    };
    let consumed_reserve_units: u64 = match case {
        EnterpriseCase::RiskReverseSlashNetReconciled => 400,
        EnterpriseCase::RiskDoubleConsumedReserve
        | EnterpriseCase::RiskMarketSlashFacilityReserve
        | EnterpriseCase::RiskMarketSlashWithSanctionBridge
        | EnterpriseCase::RiskMarketSlashMissingSanctionReserveLedger
        | EnterpriseCase::RiskMarketSlashMissingJurisdiction
        | EnterpriseCase::RiskOpenAppealReserveRelease
        | EnterpriseCase::RiskOpenAppealClaimPayout
        | EnterpriseCase::RiskOpenAppealMarketSlash
        | EnterpriseCase::RiskOpenAppealWriteOff
        | EnterpriseCase::RiskReverseSlashExceedsPriorPenalty
        | EnterpriseCase::RiskSettlementCounterpartyBound
        | EnterpriseCase::RiskPayoutMatchedLifecycle
        | EnterpriseCase::RiskSettlementCounterpartyMissing
        | EnterpriseCase::RiskSettlementCounterpartyMismatch
        | EnterpriseCase::RiskSettlementCounterpartyUnboundPayee
        | EnterpriseCase::RiskReserveReleaseWithCounterparties
        | EnterpriseCase::RiskClaimOutsideCoverage => 600,
        EnterpriseCase::RiskMultipleCoveredClaimPayouts => 1_200,
        _ => 0,
    };
    let payout_units: u64 = match case {
        EnterpriseCase::RiskMarketSlashFacilityReserve
        | EnterpriseCase::RiskMarketSlashWithSanctionBridge
        | EnterpriseCase::RiskMarketSlashMissingSanctionReserveLedger
        | EnterpriseCase::RiskMarketSlashMissingJurisdiction
        | EnterpriseCase::RiskOpenAppealReserveRelease
        | EnterpriseCase::RiskOpenAppealMarketSlash
        | EnterpriseCase::RiskOpenAppealWriteOff
        | EnterpriseCase::RiskReverseSlashExceedsPriorPenalty
        | EnterpriseCase::RiskReverseSlashNetReconciled
        | EnterpriseCase::RiskReserveReleaseWithCounterparties => 0,
        _ => consumed_reserve_units,
    };
    let reserve_ledger = match case {
        EnterpriseCase::RiskDoubleConsumedReserve => {
            json!([
                {
                    "entry_id": "claim-payout-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-double-consumed-payout",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:buyer-enterprise"
                },
                {
                    "entry_id": "reserve-release-enterprise-valid",
                    "receipt_ref": "risk-receipt-double-consumed-release",
                    "lane": "reserve_release",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskDuplicateReserveReceiptId => {
            json!([
                {
                    "entry_id": "hold-reserve-enterprise-valid-a",
                    "lane": "hold",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "receipt_ref": "risk-reserve-receipt-duplicate"
                },
                {
                    "entry_id": "hold-reserve-enterprise-valid-b",
                    "lane": "hold",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "receipt_ref": "risk-reserve-receipt-duplicate"
                }
            ])
        }
        EnterpriseCase::RiskMarketSlashFacilityReserve => {
            json!([
                {
                    "entry_id": "market-slash-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-market-slash-missing-bridge",
                    "lane": "market_slash",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskMarketSlashWithSanctionBridge
        | EnterpriseCase::RiskMarketSlashMissingSanctionReserveLedger
        | EnterpriseCase::RiskMarketSlashMissingJurisdiction
        | EnterpriseCase::RiskOpenAppealMarketSlash => {
            json!([
                {
                    "entry_id": "market-slash-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-market-slash-bridge",
                    "lane": "market_slash",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "sanction_bridge": {
                        "bridge_id": "sanction-bridge-enterprise-valid",
                        "authority_receipt_ref": "approval-case",
                        "evidence_ref": "data-governance-report",
                        "jurisdiction_ref": "jurisdiction-enterprise-valid",
                        "sanction_subject": "did:chio:buyer-enterprise",
                        "maximum_slash_units": 600
                    }
                }
            ])
        }
        EnterpriseCase::RiskOpenAppealReserveRelease => {
            json!([
                {
                    "entry_id": "reserve-release-enterprise-valid",
                    "receipt_ref": "risk-receipt-open-appeal-release",
                    "lane": "reserve_release",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskOpenAppealClaimPayout => {
            json!([
                {
                    "entry_id": "claim-payout-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-open-appeal-payout",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:buyer-enterprise"
                }
            ])
        }
        EnterpriseCase::RiskOpenAppealWriteOff => {
            json!([
                {
                    "entry_id": "write-off-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-open-appeal-write-off",
                    "lane": "write_off",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskReverseSlashWithoutPriorPenalty => {
            json!([
                {
                    "entry_id": "reverse-slash-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-reverse-slash",
                    "lane": "reverse_slash",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskReverseSlashExceedsPriorPenalty => {
            json!([
                {
                    "entry_id": "reserve-slash-enterprise-valid",
                    "receipt_ref": "risk-receipt-reserve-slash",
                    "lane": "reserve_slash",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                },
                {
                    "entry_id": "reverse-slash-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-reverse-slash",
                    "lane": "reverse_slash",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 700,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskReverseSlashNetReconciled => {
            json!([
                {
                    "entry_id": "reserve-slash-enterprise-valid",
                    "receipt_ref": "risk-receipt-reserve-slash",
                    "lane": "reserve_slash",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                },
                {
                    "entry_id": "reverse-slash-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-reverse-slash",
                    "lane": "reverse_slash",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 200,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskSettlementCounterpartyBound
        | EnterpriseCase::RiskPayoutMatchedLifecycle => {
            json!([
                {
                    "entry_id": "claim-payout-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-counterparty-bound",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:buyer-beneficiary"
                }
            ])
        }
        EnterpriseCase::RiskSettlementCounterpartyMissing => {
            json!([
                {
                    "entry_id": "claim-payout-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-counterparty-missing",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid"
                }
            ])
        }
        EnterpriseCase::RiskSettlementCounterpartyMismatch => {
            json!([
                {
                    "entry_id": "claim-payout-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-counterparty-mismatch",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:attacker"
                }
            ])
        }
        EnterpriseCase::RiskSettlementCounterpartyUnboundPayee => {
            json!([
                {
                    "entry_id": "claim-payout-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-counterparty-unbound-payee",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:attacker"
                }
            ])
        }
        EnterpriseCase::RiskReserveReleaseWithCounterparties => {
            json!([
                {
                    "entry_id": "reserve-release-enterprise-valid",
                    "receipt_ref": "risk-receipt-release-with-counterparties",
                    "lane": "reserve_release",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:buyer-enterprise"
                }
            ])
        }
        EnterpriseCase::RiskClaimOutsideCoverage => {
            json!([
                {
                    "entry_id": "claim-payout-outside-coverage",
                    "receipt_ref": "risk-receipt-claim-outside-coverage",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-outside-coverage",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:buyer-enterprise"
                }
            ])
        }
        EnterpriseCase::RiskMultipleCoveredClaimPayouts => {
            json!([
                {
                    "entry_id": "claim-payout-reserve-enterprise-valid",
                    "receipt_ref": "risk-receipt-claim-payout-valid",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:buyer-enterprise"
                },
                {
                    "entry_id": "claim-payout-reserve-enterprise-second",
                    "receipt_ref": "risk-receipt-claim-payout-second",
                    "lane": "claim_payout",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-second",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-second",
                    "payer_subject": "did:chio:buyer-enterprise",
                    "payee_subject": "did:chio:buyer-enterprise"
                }
            ])
        }
        _ => json!([]),
    };
    let sanction_reserve_ledger = match case {
        EnterpriseCase::RiskMarketSlashWithSanctionBridge
        | EnterpriseCase::RiskMarketSlashMissingJurisdiction
        | EnterpriseCase::RiskOpenAppealMarketSlash => {
            json!([
                {
                    "entry_id": "sanction-market-slash-enterprise-valid",
                    "bridge_id": "sanction-bridge-enterprise-valid",
                    "lane": "market_slash",
                    "receipt_ref": "risk-receipt-market-slash-bridge",
                    "reserve_ref": "reserve-enterprise-valid",
                    "claim_id": "claim-enterprise-valid",
                    "currency": "USD",
                    "units": 600,
                    "settlement_ref": "settlement-enterprise-valid",
                    "authority_receipt_ref": "approval-case",
                    "evidence_ref": "data-governance-report",
                    "jurisdiction_ref": "jurisdiction-enterprise-valid"
                }
            ])
        }
        _ => json!([]),
    };
    let appeals = match case {
        EnterpriseCase::RiskOpenAppealReserveRelease => json!([
            {
                "appeal_id": "appeal-enterprise-open",
                "claim_id": "claim-enterprise-valid",
                "status": "open",
                "blocks": [
                    "reserve_release",
                    "reserve_slash",
                    "facility_closure",
                    "write_off"
                ]
            }
        ]),
        EnterpriseCase::RiskOpenAppealClaimPayout => json!([
            {
                "appeal_id": "appeal-enterprise-open",
                "claim_id": "claim-enterprise-valid",
                "status": "open",
                "blocks": ["claim_payout"]
            }
        ]),
        EnterpriseCase::RiskOpenAppealMarketSlash => json!([
            {
                "appeal_id": "appeal-enterprise-open",
                "claim_id": "claim-enterprise-valid",
                "status": "open",
                "blocks": ["market_slash"]
            }
        ]),
        EnterpriseCase::RiskOpenAppealWriteOff => json!([
            {
                "appeal_id": "appeal-enterprise-open",
                "claim_id": "claim-enterprise-valid",
                "status": "open",
                "blocks": ["write_off"]
            }
        ]),
        _ => json!([]),
    };
    let facility_state = match case {
        EnterpriseCase::RiskPayoutMatchedLifecycle => "payout_matched",
        EnterpriseCase::RiskFacilityLifecycleMissingEvidence
        | EnterpriseCase::RiskFacilityLifecycleMissingAuthority => "settlement_matched",
        EnterpriseCase::RiskCoverageBoundWithoutLifecycle
        | EnterpriseCase::RiskFacilityLifecycleMissingInitialGates => "coverage_bound",
        EnterpriseCase::RiskCapitalAllocatableWithoutLifecycle => "capital_allocatable",
        EnterpriseCase::RiskClosedFacilityUnreconciledReserve => "closed",
        _ => "coverage_bound",
    };
    let facility_lifecycle = match case {
        EnterpriseCase::RiskPayoutMatchedLifecycle => facility_lifecycle_from_start(vec![
            json!({
                "transition_id": "facility-transition-coverage-bound",
                "policy_id": RISK_POLICY_ID,
                "from_state": "reserve_held",
                "to_state": "coverage_bound",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report"
            }),
            json!({
                "transition_id": "facility-transition-claim-open",
                "policy_id": RISK_POLICY_ID,
                "from_state": "coverage_bound",
                "to_state": "claim_open",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report"
            }),
            json!({
                "transition_id": "facility-transition-claim-decided",
                "policy_id": RISK_POLICY_ID,
                "from_state": "claim_open",
                "to_state": "claim_decided",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report"
            }),
            json!({
                "transition_id": "facility-transition-payout-matched",
                "policy_id": RISK_POLICY_ID,
                "from_state": "claim_decided",
                "to_state": "payout_matched",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report"
            }),
        ]),
        EnterpriseCase::RiskClosedFacilityUnreconciledReserve => {
            facility_lifecycle_from_start(vec![
                json!({
                    "transition_id": "facility-transition-coverage-bound",
                    "policy_id": RISK_POLICY_ID,
                    "from_state": "reserve_held",
                    "to_state": "coverage_bound",
                    "authority_receipt_ref": "approval-case",
                    "evidence_ref": "data-governance-report"
                }),
                json!({
                    "transition_id": "facility-transition-settlement-matched",
                    "policy_id": RISK_POLICY_ID,
                    "from_state": "coverage_bound",
                    "to_state": "settlement_matched",
                    "authority_receipt_ref": "approval-case",
                    "evidence_ref": "data-governance-report"
                }),
                json!({
                    "transition_id": "facility-transition-reserve-controlled",
                    "policy_id": RISK_POLICY_ID,
                    "from_state": "settlement_matched",
                    "to_state": "reserve_controlled",
                    "authority_receipt_ref": "approval-case",
                    "evidence_ref": "data-governance-report"
                }),
                json!({
                    "transition_id": "facility-transition-closed",
                    "policy_id": RISK_POLICY_ID,
                    "from_state": "reserve_controlled",
                    "to_state": "closed",
                    "authority_receipt_ref": "approval-case",
                    "evidence_ref": "data-governance-report"
                }),
            ])
        }
        EnterpriseCase::RiskFacilityLifecycleMissingInitialGates => json!([
            {
                "transition_id": "facility-transition-coverage-bound",
                "policy_id": RISK_POLICY_ID,
                "from_state": "reserve_held",
                "to_state": "coverage_bound",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report"
            }
        ]),
        EnterpriseCase::RiskFacilityLifecycleMissingEvidence
        | EnterpriseCase::RiskFacilityLifecycleMissingAuthority => {
            facility_lifecycle_from_start(vec![
                json!({
                    "transition_id": "facility-transition-coverage-bound",
                    "policy_id": RISK_POLICY_ID,
                    "from_state": "reserve_held",
                    "to_state": "coverage_bound",
                    "authority_receipt_ref": if matches!(
                        case,
                        EnterpriseCase::RiskFacilityLifecycleMissingAuthority
                    ) {
                        "missing-transition-authority"
                    } else {
                        "approval-case"
                    },
                    "evidence_ref": "data-governance-report"
                }),
                json!({
                    "transition_id": "facility-transition-settlement-matched",
                    "policy_id": RISK_POLICY_ID,
                    "from_state": "coverage_bound",
                    "to_state": "settlement_matched",
                    "authority_receipt_ref": "approval-case",
                    "evidence_ref": if matches!(
                        case,
                        EnterpriseCase::RiskFacilityLifecycleMissingEvidence
                    ) {
                        "missing-transition-evidence"
                    } else {
                        "data-governance-report"
                    }
                }),
            ])
        }
        EnterpriseCase::RiskCoverageBoundWithoutLifecycle
        | EnterpriseCase::RiskCapitalAllocatableWithoutLifecycle => json!([]),
        _ => facility_lifecycle_from_start(vec![json!({
            "transition_id": "facility-transition-coverage-bound",
            "policy_id": RISK_POLICY_ID,
            "from_state": "reserve_held",
            "to_state": "coverage_bound",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        })]),
    };
    let actuarial_supported_exposure_units = match case {
        EnterpriseCase::RiskInsuranceCopyExceedsActuarialEvidence => 6_000,
        _ => 5_000,
    };
    let insurance_maximum_coverage_units = match case {
        EnterpriseCase::RiskInsuranceCopyExceedsActuarialEvidence => 7_000,
        _ => 5_000,
    };
    let observed_loss_ratio_bps = match case {
        EnterpriseCase::RiskActuarialBacktestBreach => 2_600,
        _ => 1_800,
    };
    let covered_claim_ids = match case {
        EnterpriseCase::RiskDuplicateCoveredClaimId => {
            json!(["claim-enterprise-valid", "claim-enterprise-valid"])
        }
        EnterpriseCase::RiskMultipleCoveredClaimPayouts => {
            json!(["claim-enterprise-valid", "claim-enterprise-second"])
        }
        _ => json!(["claim-enterprise-valid"]),
    };
    let mut risk_report_value = json!({
        "schema": "chio.risk.comptroller-report.v1",
        "id": "risk-comptroller-enterprise-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "order_id": "order-commerce-001",
        "subject": "did:chio:buyer-enterprise",
        "verdict": "verified",
        "risk_state": "reconciled",
        "facility": {
            "facility_id": "facility-enterprise-valid",
            "policy_id": RISK_POLICY_ID,
            "state": facility_state,
            "capital_currency": "USD",
            "capital_units": capital_units,
            "reserve_currency": "USD",
            "reserve_units": reserve_units,
            "reserve_ref": "reserve-enterprise-valid"
        },
        "coverage": {
            "coverage_id": "coverage-enterprise-valid",
            "order_id": "order-commerce-001",
            "subject": coverage_subject,
            "covered_claim_ids": covered_claim_ids,
            "currency": "USD",
            "exposure_units": 5_000,
            "reserve_ref": "reserve-enterprise-valid",
            "status": "bound"
        },
        "premium": {
            "premium_id": "premium-enterprise-valid",
            "quote_ref": "data-governance-report",
            "coverage_id": "coverage-enterprise-valid",
            "order_id": "order-commerce-001",
            "subject": coverage_subject,
            "currency": "USD",
            "coverage_exposure_units": 5_000,
            "quoted_premium_units": 50,
            "bound_premium_units": 50,
            "collected_premium_units": 0,
            "status": "bound"
        },
        "capital_decomposition": {
            "decomposition_id": "capital-decomposition-enterprise-valid",
            "source_kind": "facility_commitment",
            "source_ref": "approval-case",
            "currency": "USD",
            "committed_units": capital_units,
            "held_units": reserve_units,
            "drawn_units": 0,
            "disbursed_units": payout_units,
            "impaired_units": 0,
            "available_units": capital_units.saturating_sub(reserve_units + payout_units)
        },
        "reconciliation": {
            "order_id": "order-commerce-001",
            "currency": "USD",
            "exposure_units": 5_000,
            "reserve_units": reserve_units,
            "consumed_reserve_units": consumed_reserve_units,
            "payout_units": payout_units,
            "settlement_units": payout_units,
            "status": "balanced"
        },
        "actuarial_evidence": {
            "model_ref": "actuarial-model-enterprise-valid",
            "evidence_ref": "data-governance-report",
            "currency": "USD",
            "supported_exposure_units": actuarial_supported_exposure_units,
            "confidence_level_bps": 9_500,
            "backtest": {
                "backtest_id": "actuarial-backtest-enterprise-valid",
                "window_start": "2026-03-10T00:00:00Z",
                "window_end": "2026-06-10T00:00:00Z",
                "sample_size": 120,
                "observed_loss_ratio_bps": observed_loss_ratio_bps,
                "maximum_loss_ratio_bps": 2_500,
                "status": "passed"
            }
        },
        "insurance_copy": {
            "copy_id": "insurance-copy-enterprise-valid",
            "actuarial_evidence_ref": "actuarial-model-enterprise-valid",
            "currency": "USD",
            "maximum_coverage_units": insurance_maximum_coverage_units,
            "coverage_statement": "coverage limited to supported exposure"
        },
        "reserve_ledger": reserve_ledger,
        "sanction_reserve_ledger": sanction_reserve_ledger,
        "capital_instructions": capital_instructions_for_claim_payouts(&reserve_ledger),
        "appeals": appeals,
        "facility_lifecycle": facility_lifecycle,
        "verified_claims": ["claim.risk.comptroller_report_bound"]
    });
    if matches!(
        case,
        EnterpriseCase::RiskSettlementCounterpartyBound
            | EnterpriseCase::RiskPayoutMatchedLifecycle
            | EnterpriseCase::RiskSettlementCounterpartyMismatch
    ) {
        risk_report_value["coverage"]["beneficiary_subject"] = json!("did:chio:buyer-beneficiary");
    }
    let risk_report = json_bytes(signed_risk_comptroller_report(risk_report_value));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "risk-comptroller-report",
        "risk-comptroller-report",
        "chio.risk.comptroller-report.v1",
        "risk-comptroller-report.json",
        risk_report.clone(),
    );
    push_reserve_ledger_ref_artifacts(&mut artifacts, &mut graph_nodes, &reserve_ledger);

    if matches!(
        case,
        EnterpriseCase::RiskMarketSlashWithSanctionBridge
            | EnterpriseCase::RiskMarketSlashMissingSanctionReserveLedger
            | EnterpriseCase::RiskOpenAppealMarketSlash
    ) {
        let jurisdiction = json_bytes(json!({
            "schema": "chio.risk.adjudication-jurisdiction-receipt.v1",
            "id": "jurisdiction-enterprise-valid",
            "issued_at": "2026-06-10T00:00:00Z",
            "jurisdiction_id": "jurisdiction-enterprise-valid",
            "order_id": "order-commerce-001",
            "policy_ref": "jurisdiction-policy-enterprise-valid",
            "covered_dispute_types": ["collateral_slash"],
            "adjudicator_subjects": ["did:chio:enterprise-adjudicator"],
            "appeal_authority_refs": ["did:chio:enterprise-appeal"],
            "slash_authority_refs": ["approval-case"],
            "remedy_limits": [
                {
                    "currency": "USD",
                    "maximum_remedy": 600
                }
            ],
            "evidence_rules_ref": "evidence-rules-enterprise-valid",
            "effective_window": {
                "start": "2026-06-10T00:00:00Z",
                "end": "2026-06-12T00:00:00Z"
            },
            "signature": "sig-jurisdiction-enterprise-valid"
        }));
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "adjudication-jurisdiction-receipt",
            "jurisdiction-enterprise-valid",
            "chio.risk.adjudication-jurisdiction-receipt.v1",
            "adjudication-jurisdiction-receipt.json",
            jurisdiction,
        );
    }

    let disclosure_capsule = json_bytes(json!({
        "schema": "chio.disclosure.crypto-context-report.v1",
        "id": "disclosure-report-enterprise-valid",
        "context_id": "crypto-context-buyer-auditor",
        "artifact_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "verdict": "verified",
        "evidence_class": "verifier_context",
        "cryptographic_proof_verified": true,
        "verified_claims": [
            "claim.disclosure.crypto_context_bound",
            "claim.disclosure.profile_context_policy_enforced"
        ],
        "rejected_checks": [],
        "disclosed_fields": ["capability_id", "id", "tool_name"]
    }));
    artifacts.insert(
        "disclosure-capsule.json".to_string(),
        disclosure_capsule.clone(),
    );

    let leakage_ledger = json_bytes(json!({
        "schema": "chio.enterprise.leakage-ledger.v1",
        "id": "leakage-ledger-enterprise-valid",
        "passport_id": passport.id,
        "disclosed_fields": ["capability_id", "id", "tool_name"],
        "redacted_fields": ["customer_email", "card_last4"]
    }));
    artifacts.insert("leakage-ledger.json".to_string(), leakage_ledger.clone());

    let pii_export_action = match case {
        EnterpriseCase::OverdisclosedPii => "disclosed",
        _ => "redacted",
    };
    let data_governance = json_bytes(json!({
        "schema": "chio.enterprise.data-governance-report.v1",
        "id": "data-governance-enterprise-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "risk_comptroller_report_ref": "risk-comptroller-enterprise-valid",
        "allowed_regions": ["US"],
        "observed_region": "US",
        "retention_class": "audit-365d",
        "legal_hold_status": "not_held",
        "redaction_profile_ref": "redaction-profile-enterprise-valid",
        "disclosure_capsule_ref": "disclosure-report-enterprise-valid",
        "leakage_ledger_ref": "leakage-ledger-enterprise-valid",
        "field_classifications": [
            {
                "field": "customer_email",
                "classification": "pii",
                "export_action": pii_export_action
            },
            {
                "field": "order_id",
                "classification": "business",
                "export_action": "disclosed"
            }
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "data-governance-report",
        "data-governance-report",
        "chio.enterprise.data-governance-report.v1",
        "data-governance-report.json",
        data_governance.clone(),
    );

    let passport_export = json_bytes(json!({
        "id": "transaction-passport-export-enterprise-valid",
        "artifact_kind": "transaction_passport_export",
        "schema_ref": "chio.transaction-passport.v1",
        "passport_id": passport.id,
        "evidence_graph_path": passport.evidence_graph_path,
        "verifier_policy_path": passport.verifier_policy_path,
        "redaction_profile_ref": "redaction-profile-enterprise-valid"
    }));
    let verifier_report_export = json_bytes(json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": "verifier-report-enterprise-valid",
        "passport_id": passport.id,
        "verdict": "verified",
        "verified_claims": [
            CLAIM_DATA_GOVERNANCE_BOUND,
            CLAIM_EVIDENCE_EXPORT_DIGEST_BOUND,
            CLAIM_TELEMETRY_PROJECTION_BOUND,
            CLAIM_EXPORT_APPROVAL_BOUND,
            CLAIM_CONTROL_MAP_BOUND
        ]
    }));
    let export_artifacts = vec![
        artifact_ref(
            "transaction_passport",
            "transaction-passport-export.json",
            &passport_export,
        ),
        artifact_ref(
            "verifier_report",
            "verifier-report-enterprise-valid.json",
            &verifier_report_export,
        ),
        artifact_ref(
            "risk_comptroller_report",
            "risk-comptroller-report.json",
            &risk_report,
        ),
        artifact_ref(
            "disclosure_capsule",
            "disclosure-capsule.json",
            &disclosure_capsule,
        ),
        artifact_ref("leakage_ledger", "leakage-ledger.json", &leakage_ledger),
        artifact_ref(
            "data_governance_report",
            "data-governance-report.json",
            &data_governance,
        ),
    ];
    let bundle_digest = match case {
        EnterpriseCase::ExportDigestMismatch => "f".repeat(64),
        _ => export_bundle_digest(&export_artifacts),
    };
    let approval_artifact = json_bytes(signed_approval_case(json!({
        "schema": "chio.enterprise.approval-case.v1",
        "id": "approval-case-enterprise-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "risk_comptroller_report_ref": "risk-comptroller-enterprise-valid",
        "evidence_export_bundle_digest": bundle_digest,
        "decision": "approved",
        "decision_subject": "evidence-export",
        "approvers": [approval_approver()],
        "required_quorum": 1,
        "expires_at": "2026-06-11T00:00:00Z"
    })));
    if !matches!(case, EnterpriseCase::MissingApproval) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "approval-case",
            "approval-case",
            "chio.enterprise.approval-case.v1",
            "approval-case.json",
            approval_artifact,
        );
    }
    let export_bundle = json_bytes(json!({
        "schema": "chio.enterprise.evidence-export-bundle.v1",
        "id": "evidence-export-enterprise-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "risk_comptroller_report_ref": "risk-comptroller-enterprise-valid",
        "approval_case_ref": "approval-case-enterprise-valid",
        "bundle_digest": bundle_digest,
        "artifacts": export_artifacts
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "evidence-export-bundle",
        "evidence-export-bundle",
        "chio.enterprise.evidence-export-bundle.v1",
        "evidence-export-bundle.json",
        export_bundle,
    );

    let telemetry = json_bytes(json!({
        "schema": "chio.enterprise.telemetry-projection.v1",
        "id": "telemetry-enterprise-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "risk_comptroller_report_ref": "risk-comptroller-enterprise-valid",
        "events": [
            {
                "event_id": "allow-event",
                "event_kind": "allow",
                "artifact_ref": "transaction-passport-export.json",
                "artifact_sha256": chio_core::sha256_hex(&passport_export)
            },
            {
                "event_id": "denied-guard-event",
                "event_kind": "denied_guard",
                "artifact_ref": "data-governance-report.json",
                "artifact_sha256": if matches!(case, EnterpriseCase::TelemetryDigestMismatch) {
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string()
                } else {
                    chio_core::sha256_hex(&data_governance)
                }
            },
            {
                "event_id": "risk-verifier-event",
                "event_kind": "risk_verifier",
                "artifact_ref": "risk-comptroller-report.json",
                "artifact_sha256": chio_core::sha256_hex(&risk_report)
            }
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "telemetry-projection",
        "telemetry-projection",
        "chio.enterprise.telemetry-projection.v1",
        "telemetry-projection.json",
        telemetry,
    );

    let gate_ref = match case {
        EnterpriseCase::ControlMapMissingGate => "missing-gate",
        _ => "data-governance-report",
    };
    let control_map = json_bytes(json!({
        "schema": "chio.enterprise.control-evidence-map.v1",
        "id": "control-map-enterprise-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "risk_comptroller_report_ref": "risk-comptroller-enterprise-valid",
        "controls": [
            {
                "control_id": "data-minimization",
                "control_family": "internal-proof",
                "claim_ref": CLAIM_DATA_GOVERNANCE_BOUND,
                "gate_ref": gate_ref
            },
            {
                "control_id": "sensitive-export-approval",
                "control_family": "internal-proof",
                "claim_ref": CLAIM_EXPORT_APPROVAL_BOUND,
                "gate_ref": "approval-case"
            }
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "control-evidence-map",
        "control-evidence-map",
        "chio.enterprise.control-evidence-map.v1",
        "control-evidence-map.json",
        control_map,
    );

    let verifier_policy = json_bytes(json!({
        "schema": "chio.transaction.verifier-policy.v1",
        "id": "enterprise-policy-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "required_claims": [
            CLAIM_DATA_GOVERNANCE_BOUND,
            CLAIM_EVIDENCE_EXPORT_DIGEST_BOUND,
            CLAIM_TELEMETRY_PROJECTION_BOUND,
            CLAIM_EXPORT_APPROVAL_BOUND,
            CLAIM_CONTROL_MAP_BOUND
        ],
        "omitted_claims": []
    }));
    let claim_set = json_bytes(json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "enterprise-claim-set-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "claims": [
            {
                "claim_id": CLAIM_DATA_GOVERNANCE_BOUND,
                "status": "verified",
                "required_evidence": ["data-governance-report.json"],
                "evidence_refs": ["data-governance-report.json"],
                "verifier_module": "chio-enterprise-export"
            }
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "verifier-policy",
        "enterprise-policy-valid",
        "chio.transaction.verifier-policy.v1",
        "verifier-policy.json",
        verifier_policy.clone(),
    );
    let claim_set_sha256 = chio_core::sha256_hex(&claim_set);
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "claim-set",
        "claim-set",
        "chio.transaction.claim-set.v1",
        "claim-set.json",
        claim_set,
    );

    let mut graph_edges = vec![
        json!({
            "from": "claim-set",
            "to": "enterprise-policy-valid",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "data-governance-report",
            "to": "risk-comptroller-report",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "telemetry-projection",
            "to": "risk-comptroller-report",
            "predicate": "projects-to",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "control-evidence-map",
            "to": "data-governance-report",
            "predicate": "reconciles",
            "evidence_class": "digest-bound-reference"
        }),
    ];
    if !matches!(case, EnterpriseCase::MissingApproval) {
        graph_edges.push(json!({
            "from": "evidence-export-bundle",
            "to": "approval-case",
            "predicate": "authorizes",
            "evidence_class": "chio-sidecar-proof"
        }));
    }
    if matches!(
        case,
        EnterpriseCase::RiskMarketSlashWithSanctionBridge
            | EnterpriseCase::RiskMarketSlashMissingSanctionReserveLedger
    ) {
        graph_edges.push(json!({
            "from": "approval-case",
            "to": "jurisdiction-enterprise-valid",
            "predicate": "binds",
            "evidence_class": "chio-sidecar-proof"
        }));
    }
    normalize_graph_node_ids(&mut graph_nodes, &mut graph_edges);
    let evidence_graph = json_bytes(json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "enterprise-evidence-graph-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "nodes": graph_nodes,
        "edges": graph_edges
    }));

    let mut passport = passport;
    passport.evidence_graph_sha256 = chio_core::sha256_hex(&evidence_graph);
    passport.claim_set_sha256 = claim_set_sha256;
    passport.verifier_policy_sha256 = chio_core::sha256_hex(&verifier_policy);
    sign_transaction_passport(&mut passport);
    artifacts.insert(
        "transaction-passport-export.json".to_string(),
        passport_export,
    );
    artifacts.insert(
        "verifier-report-enterprise-valid.json".to_string(),
        verifier_report_export,
    );

    EnterpriseExportBundle {
        passport,
        evidence_graph_bytes: evidence_graph,
        root_evidence_graph_bytes: None,
        verifier_policy_bytes: verifier_policy,
        artifacts,
        trusted_passport_signer_keys: vec![transaction_passport_keypair().public_key()],
        trusted_receipt_kernel_keys: vec![receipt_kernel_keypair().public_key()],
        trusted_approval_signer_keys: vec![approval_keypair().public_key()],
        trusted_risk_comptroller_signer_keys: vec![risk_comptroller_keypair().public_key()],
    }
}

fn with_graph_node_schema(
    mut bundle: EnterpriseExportBundle,
    node_id: &str,
    schema: &str,
) -> EnterpriseExportBundle {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("evidence graph parses");
    let nodes = graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes array");
    let node = nodes
        .iter_mut()
        .find(|node| {
            node.get("id").and_then(Value::as_str) == Some(node_id)
                || node.get("role").and_then(Value::as_str) == Some(node_id)
                || node
                    .get("path")
                    .and_then(Value::as_str)
                    .and_then(|path| std::path::Path::new(path).file_stem())
                    .and_then(std::ffi::OsStr::to_str)
                    == Some(node_id)
        })
        .test_expect("evidence graph node exists");
    node["schema"] = json!(schema);
    bundle.evidence_graph_bytes = json_bytes(graph);
    bundle.passport.evidence_graph_sha256 = chio_core::sha256_hex(&bundle.evidence_graph_bytes);
    sign_transaction_passport(&mut bundle.passport);
    bundle
}

#[test]
fn enterprise_export_accepts_valid_autonomous_commerce_fixture() {
    let bundle = enterprise_bundle(EnterpriseCase::Valid);

    let report = verify_enterprise_export(&bundle)
        .test_expect("valid enterprise export evidence should verify");

    assert_eq!(report.schema, "chio.transaction.verifier-report.v1");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.passport_id, "passport-enterprise-valid");
    assert_eq!(
        report.risk_comptroller_report_ref,
        "risk-comptroller-enterprise-valid"
    );
    assert!(report
        .verified_claims
        .contains(&CLAIM_DATA_GOVERNANCE_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_EVIDENCE_EXPORT_DIGEST_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_TELEMETRY_PROJECTION_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_EXPORT_APPROVAL_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_CONTROL_MAP_BOUND.to_string()));
}

#[test]
fn enterprise_export_rejects_missing_approval_case() {
    let bundle = enterprise_bundle(EnterpriseCase::MissingApproval);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("sensitive export without approval must fail");

    assert!(error.to_string().contains("missing approval case"));
}

#[test]
fn enterprise_export_rejects_export_bundle_digest_mismatch() {
    let bundle = enterprise_bundle(EnterpriseCase::ExportDigestMismatch);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("tampered export bundle digest must fail");

    assert!(error.to_string().contains("export bundle digest mismatch"));
}

#[test]
fn enterprise_export_rejects_pii_overdisclosure() {
    let bundle = enterprise_bundle(EnterpriseCase::OverdisclosedPii);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("PII field disclosed against governance policy must fail");

    assert!(error.to_string().contains("PII field was not redacted"));
}

#[test]
fn enterprise_export_rejects_telemetry_digest_mismatch() {
    let bundle = enterprise_bundle(EnterpriseCase::TelemetryDigestMismatch);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("telemetry digest mismatch must fail");

    assert!(error
        .to_string()
        .contains("telemetry artifact digest mismatch"));
}

#[test]
fn enterprise_export_rejects_control_map_missing_gate() {
    let bundle = enterprise_bundle(EnterpriseCase::ControlMapMissingGate);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("control map cannot cite a verifier gate that did not run");

    assert!(error.to_string().contains("control gate did not run"));
}

#[test]
fn enterprise_export_rejects_missing_risk_reserve_state() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskMissingReserve);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("risk report without reserve must fail");

    assert!(error.to_string().contains("risk reserve state missing"));
}

#[test]
fn enterprise_export_rejects_risk_coverage_subject_mismatch() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskCoverageSubjectMismatch);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk report with mismatched coverage subject must fail");

    assert!(error.to_string().contains("risk coverage subject mismatch"));
}

#[test]
fn enterprise_export_rejects_risk_double_consumed_reserve() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskDoubleConsumedReserve);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk report cannot pay and release the same reserve");

    assert!(error
        .to_string()
        .contains("risk reserve double consumption"));
}

#[test]
fn enterprise_export_rejects_duplicate_risk_reserve_receipt_id() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskDuplicateReserveReceiptId);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk reserve ledger receipt ids must be unique");

    assert!(error
        .to_string()
        .contains("risk reserve ledger duplicate receipt"));
}

#[test]
fn enterprise_export_rejects_market_slash_consuming_facility_reserve() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskMarketSlashFacilityReserve);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("market slash cannot consume facility reserve without sanction bridge");

    assert!(error
        .to_string()
        .contains("risk market slash requires sanction bridge"));
}

#[test]
fn enterprise_export_accepts_market_slash_with_sanction_bridge() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskMarketSlashWithSanctionBridge);

    let report = verify_enterprise_export(&bundle)
        .test_expect("sanction-bridged market slash should verify");

    assert_eq!(report.verdict, "verified");
    assert_eq!(
        report.risk_comptroller_report_ref,
        "risk-comptroller-enterprise-valid"
    );
}

#[test]
fn enterprise_export_rejects_market_slash_without_sanction_reserve_ledger() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskMarketSlashMissingSanctionReserveLedger);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("market slash must be backed by a sanction reserve ledger");

    assert!(error
        .to_string()
        .contains("risk sanction reserve ledger missing"));
}

#[test]
fn enterprise_export_rejects_market_slash_missing_jurisdiction_ref() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskMarketSlashMissingJurisdiction);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("market slash jurisdiction ref must resolve");

    assert!(error
        .to_string()
        .contains("risk market slash jurisdiction missing"));
}

#[test]
fn enterprise_export_rejects_open_appeal_reserve_release() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskOpenAppealReserveRelease);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("open appeal must block reserve release");

    assert!(error
        .to_string()
        .contains("risk open appeal blocks reserve action"));
}

#[test]
fn enterprise_export_rejects_open_appeal_claim_payout() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskOpenAppealClaimPayout);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("open appeal must block claim payout");

    assert!(error
        .to_string()
        .contains("risk open appeal blocks reserve action"));
}

#[test]
fn enterprise_export_rejects_open_appeal_market_slash() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskOpenAppealMarketSlash);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("open appeal must block market slash");

    assert!(error
        .to_string()
        .contains("risk open appeal blocks reserve action"));
}

#[test]
fn enterprise_export_rejects_open_appeal_write_off() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskOpenAppealWriteOff);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("open appeal must block write-off");

    assert!(error
        .to_string()
        .contains("risk open appeal blocks reserve action"));
}

#[test]
fn enterprise_export_rejects_reverse_slash_without_prior_penalty() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskReverseSlashWithoutPriorPenalty);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("reverse slash must reference a prior reserve slash");

    assert!(error
        .to_string()
        .contains("risk reverse slash missing prior reserve slash"));
}

#[test]
fn enterprise_export_rejects_reverse_slash_exceeding_prior_penalty() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskReverseSlashExceedsPriorPenalty);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("reverse slash cannot exceed the prior reserve slash");

    assert!(error
        .to_string()
        .contains("risk reverse slash exceeds prior reserve slash"));
}

#[test]
fn enterprise_export_accepts_reverse_slash_net_reconciliation() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskReverseSlashNetReconciled);

    let report =
        verify_enterprise_export(&bundle).test_expect("reverse slash should net reserve usage");

    assert_eq!(report.verdict, "verified");
    assert_eq!(
        report.risk_comptroller_report_ref,
        "risk-comptroller-enterprise-valid"
    );
}

#[test]
fn enterprise_export_accepts_risk_settlement_counterparty_bound_claim_payout() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskSettlementCounterpartyBound);

    let report = verify_enterprise_export(&bundle)
        .test_expect("counterparty-bound claim payout should verify");

    assert_eq!(report.verdict, "verified");
    assert_eq!(
        report.risk_comptroller_report_ref,
        "risk-comptroller-enterprise-valid"
    );
}

#[test]
fn enterprise_export_accepts_risk_payout_matched_lifecycle() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskPayoutMatchedLifecycle);

    let report = verify_enterprise_export(&bundle)
        .test_expect("claim payout lifecycle should replay to payout_matched");

    assert_eq!(report.verdict, "verified");
    assert_eq!(
        report.risk_comptroller_report_ref,
        "risk-comptroller-enterprise-valid"
    );
}

#[test]
fn enterprise_export_rejects_risk_claim_payout_without_counterparties() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskSettlementCounterpartyMissing);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk claim payout must bind payer and payee subjects");

    assert!(error
        .to_string()
        .contains("risk settlement counterparty mismatch"));
}

#[test]
fn enterprise_export_rejects_risk_settlement_counterparty_mismatch() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskSettlementCounterpartyMismatch);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk claim payout must settle to the coverage beneficiary");

    assert!(error
        .to_string()
        .contains("risk settlement counterparty mismatch"));
}

#[test]
fn enterprise_export_rejects_risk_settlement_counterparty_unbound_payee() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskSettlementCounterpartyUnboundPayee);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk claim payout payee must be coverage-bound");

    assert!(error
        .to_string()
        .contains("risk settlement counterparty mismatch"));
}

#[test]
fn enterprise_export_rejects_reserve_release_with_settlement_counterparties() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskReserveReleaseWithCounterparties);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("reserve release must not be presented as a payout lane");

    assert!(error
        .to_string()
        .contains("risk reserve ledger counterparty lane unsupported"));
}

#[test]
fn enterprise_export_rejects_risk_claim_outside_coverage() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskClaimOutsideCoverage);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk claim payout must be listed by coverage evidence");

    assert!(error.to_string().contains("risk claim outside coverage"));
}

#[test]
fn enterprise_export_accepts_multiple_covered_claim_payouts() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskMultipleCoveredClaimPayouts);

    let report = verify_enterprise_export(&bundle)
        .test_expect("risk reserve may pay multiple covered claims");

    assert_eq!(report.verdict, "verified");
    assert_eq!(
        report.risk_comptroller_report_ref,
        "risk-comptroller-enterprise-valid"
    );
}

#[test]
fn enterprise_export_rejects_duplicate_risk_coverage_claim_id() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskDuplicateCoveredClaimId);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk coverage claim scope must be unambiguous");

    assert!(error
        .to_string()
        .contains("risk coverage duplicate claim id"));
}

#[test]
fn enterprise_export_rejects_risk_facility_lifecycle_missing_evidence() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskFacilityLifecycleMissingEvidence);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk facility lifecycle transition evidence must be graph-bound");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle evidence missing"));
}

#[test]
fn enterprise_export_rejects_risk_facility_lifecycle_missing_authority() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskFacilityLifecycleMissingAuthority);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk facility lifecycle transition authority must be graph-bound");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle authority missing"));
}

#[test]
fn enterprise_export_rejects_risk_facility_lifecycle_authority_wrong_schema_kind() {
    let bundle = with_graph_node_schema(
        enterprise_bundle(EnterpriseCase::RiskPayoutMatchedLifecycle),
        "approval-case",
        "chio.enterprise.data-governance-report.v1",
    );

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk facility lifecycle authority must resolve to authority evidence");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle authority missing"));
}

#[test]
fn enterprise_export_rejects_risk_capital_allocatable_without_lifecycle_replay() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskCapitalAllocatableWithoutLifecycle);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("capital-allocatable risk facility must include lifecycle replay");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle replay missing"));
}

#[test]
fn enterprise_export_rejects_risk_coverage_bound_without_lifecycle_replay() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskCoverageBoundWithoutLifecycle);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("coverage-bound risk facility must include lifecycle replay");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle replay missing"));
}

#[test]
fn enterprise_export_rejects_risk_facility_lifecycle_missing_initial_gates() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskFacilityLifecycleMissingInitialGates);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk facility lifecycle must replay initial facility gates");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle replay gap"));
}

#[test]
fn enterprise_export_rejects_closed_risk_facility_with_unreconciled_reserve() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskClosedFacilityUnreconciledReserve);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("closed risk facility must reconcile its reserve");

    assert!(error
        .to_string()
        .contains("risk facility closure reserve unreconciled"));
}

#[test]
fn enterprise_export_rejects_risk_insurance_copy_exceeding_actuarial_support() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskInsuranceCopyExceedsActuarialEvidence);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk insurance copy cannot exceed actuarial support");

    assert!(error
        .to_string()
        .contains("risk insurance copy exceeds actuarial support"));
}

#[test]
fn enterprise_export_rejects_risk_exposure_exceeding_capital() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskExposureExceedsCapital);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("risk exposure must be capital-backed");

    assert!(error.to_string().contains("risk exposure exceeds capital"));
}

#[test]
fn enterprise_export_rejects_risk_capital_adequacy_breach() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskCapitalAdequacyBreach);

    let error = verify_enterprise_export(&bundle)
        .test_expect_err("risk capital must cover exposure plus held reserve");

    assert!(error.to_string().contains("risk capital adequacy breach"));
}

#[test]
fn enterprise_export_rejects_risk_actuarial_backtest_breach() {
    let bundle = enterprise_bundle(EnterpriseCase::RiskActuarialBacktestBreach);

    let error =
        verify_enterprise_export(&bundle).test_expect_err("risk actuarial backtest must pass");

    assert!(error.to_string().contains("risk actuarial backtest breach"));
}
