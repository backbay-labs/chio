use std::collections::BTreeMap;

use chio_core_types::Keypair;
use chio_test_support::prelude::*;
use serde_json::{json, Value};

use chio_transaction_passport::TransactionPassport;
use chio_trust_market_context::{verify_trust_market_context, TrustMarketBundle};

const CLAIM_DISCOVERY_BOUND: &str = "claim.trust_market.provider_discovery_bound";
const CLAIM_SELECTION_BOUND: &str = "claim.trust_market.provider_selection_bound";
const CLAIM_SCORECARD_BOUND: &str = "claim.trust_market.local_scorecard_bound";
const CLAIM_REPUTATION_IMPORT_BOUND: &str = "claim.trust_market.reputation_import_bound";
const CLAIM_SLA_BOUND: &str = "claim.trust_market.sla_commitment_bound";
const CLAIM_COLLATERAL_GUARANTEE_BOUND: &str = "claim.trust_market.collateral_guarantee_bound";
const CLAIM_JURISDICTION_BOUND: &str = "claim.trust_market.jurisdiction_bound";
const CLAIM_UNSUPPORTED_MARKET_LIMITED: &str =
    "claim.trust_market.unsupported_market_claims_limited";
const MARKET_AUTHORITY_SEED: [u8; 32] = [59; 32];
const TRANSACTION_PASSPORT_SIGNATURE_SEED: [u8; 32] = [7; 32];

#[derive(Debug, Clone, Copy)]
enum TrustMarketCase {
    Valid,
    SelectedProviderAbsent,
    StaleDiscovery,
    SelectionPredatesDiscovery,
    AmbiguousTopRank,
    LowerRankOverrideReceiptUnbound,
    LowerRankOverrideReceiptUnavailable,
    LowerRankOverrideReceiptUntrustedSigner,
    SelectionRankingMissingAvailableCandidate,
    SelectionRankingDuplicateProvider,
    SelectionRankingOrderMismatch,
    SelectionScorecardScoreMismatch,
    ScorecardStaleAtSelection,
    GlobalScorecardScope,
    ScoreRecomputeMismatch,
    ReputationImportOverweight,
    ScorecardPortableReputationOverweight,
    SlaWrongOrder,
    SlaPerformanceMetricMismatch,
    SlaPerformanceMissingCommittedMetric,
    SlaPerformanceTargetExceeded,
    CollateralUnsupportedSource,
    GuaranteeWithoutBacking,
    GuaranteeWrongBeneficiary,
    GuaranteeUnsupportedType,
    GuaranteeInvertedClaimWindow,
    GuaranteeEndsAfterSla,
    CollateralLockStartsAfterGuarantee,
    SlashAuthorityOutsideJurisdiction,
    RequiredUnsupportedMarketClaim,
    RiskReportRefUnbound,
    RiskComptrollerReportUnsigned,
    RiskDoubleConsumedReserve,
    RiskOpenAppealReserveRelease,
    RiskFacilityLifecycleReplayGap,
    RiskFacilityLifecycleReplayed,
    RiskFacilityLifecycleMissingEvidence,
    RiskFacilityLifecycleMissingEvidenceArtifact,
    RiskFacilityLifecycleUnsignedAuthorityEvidence,
    RiskReserveLedgerReceiptUntrustedSigner,
    RiskSettlementReceiptUntrustedSigner,
    RiskSanctionReserveLedgerReceiptUntrustedSigner,
    RiskSanctionAuthorityReceiptUntrustedSigner,
    RiskSanctionJurisdictionReceiptUntrustedSigner,
}

fn json_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).test_expect("test json serializes")
}

fn market_authority_keypair() -> Keypair {
    Keypair::from_seed(&MARKET_AUTHORITY_SEED)
}

fn untrusted_market_authority_keypair() -> Keypair {
    Keypair::from_seed(&[60; 32])
}

fn transaction_passport_keypair() -> Keypair {
    Keypair::from_seed(&TRANSACTION_PASSPORT_SIGNATURE_SEED)
}

fn sign_transaction_passport(passport: &mut TransactionPassport) {
    let keypair = transaction_passport_keypair();
    passport.issuer = format!("did:chio:{}", keypair.public_key().to_hex());
    passport.signature = String::new();
    passport.signature = chio_transaction_passport::sign_transaction_passport(passport, &keypair)
        .test_expect("transaction passport signs");
}

fn market_authority_key_hex() -> String {
    market_authority_keypair().public_key().to_hex()
}

fn signed_artifact_bytes_with_key(mut value: Value, keypair: &Keypair) -> Vec<u8> {
    let object = value
        .as_object_mut()
        .test_expect("signed market artifact is an object");
    object.remove("signature");
    let signature = keypair
        .sign_canonical(&value)
        .test_expect("market artifact signs")
        .0
        .to_hex();
    value["signature"] = Value::String(format!(
        "sig-ed25519:{}:{signature}",
        keypair.public_key().to_hex()
    ));
    json_bytes(value)
}

fn signed_market_artifact_bytes(value: Value) -> Vec<u8> {
    signed_artifact_bytes_with_key(value, &market_authority_keypair())
}

fn signed_receipt_artifact_bytes(receipt_id: &str, trusted: bool) -> Vec<u8> {
    let keypair = if trusted {
        market_authority_keypair()
    } else {
        untrusted_market_authority_keypair()
    };
    signed_artifact_bytes_with_key(
        json!({
            "schema": "chio.receipt.v1",
            "id": receipt_id,
            "receipt_id": receipt_id,
            "issued_at": "2026-06-10T00:00:00Z",
            "terminal_status": "allowed_executed"
        }),
        &keypair,
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
    let sha256 = chio_core_types::sha256_hex(&bytes);
    graph_nodes.push(json!({
        "id": node_id,
        "schema": schema,
        "path": path,
        "sha256": sha256,
        "role": graph_role
    }));
    artifacts.insert(path.to_string(), bytes);
}

fn push_receipt_artifact(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut Vec<Value>,
    receipt_id: &str,
    trusted: bool,
) {
    push_artifact(
        artifacts,
        graph_nodes,
        "receipt",
        receipt_id,
        "chio.receipt.v1",
        &format!("{receipt_id}.json"),
        signed_receipt_artifact_bytes(receipt_id, trusted),
    );
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

fn facility_lifecycle_for_state(final_state: &str, settlement_evidence_ref: &str) -> Value {
    const POLICY_ID: &str = "risk-policy-facility-market-valid";
    let mut transitions = vec![
        json!({
            "transition_id": "facility-transition-underwriting-ready",
            "policy_id": POLICY_ID,
            "from_state": "evidence_cold",
            "to_state": "underwriting_ready",
            "authority_receipt_ref": "guarantee-decision",
            "evidence_ref": "provider-selection-report"
        }),
        json!({
            "transition_id": "facility-transition-facility-granted",
            "policy_id": POLICY_ID,
            "from_state": "underwriting_ready",
            "to_state": "facility_granted",
            "authority_receipt_ref": "guarantee-decision",
            "evidence_ref": "provider-selection-report"
        }),
        json!({
            "transition_id": "facility-transition-reserve-held",
            "policy_id": POLICY_ID,
            "from_state": "facility_granted",
            "to_state": "reserve_held",
            "authority_receipt_ref": "guarantee-decision",
            "evidence_ref": "provider-selection-report"
        }),
        json!({
            "transition_id": "facility-transition-coverage-bound",
            "policy_id": POLICY_ID,
            "from_state": "reserve_held",
            "to_state": "coverage_bound",
            "authority_receipt_ref": "adjudication-jurisdiction-receipt",
            "evidence_ref": "collateral-position-report"
        }),
    ];
    if final_state == "settlement_matched" {
        transitions.push(json!({
            "transition_id": "facility-transition-settlement-matched",
            "policy_id": POLICY_ID,
            "from_state": "coverage_bound",
            "to_state": "settlement_matched",
            "authority_receipt_ref": "adjudication-jurisdiction-receipt",
            "evidence_ref": settlement_evidence_ref
        }));
    }
    Value::Array(transitions)
}

fn trust_market_bundle(case: TrustMarketCase) -> TrustMarketBundle {
    let passport = TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-trust-market-valid".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        not_before: None,
        expires_at: None,
        issuer: "did:chio:66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
            .to_string(),
        evidence_graph_sha256: String::new(),
        evidence_graph_path: "evidence-graph.json".to_string(),
        claim_set_sha256: String::new(),
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: String::new(),
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: "0".repeat(128),
    };

    let mut artifacts = BTreeMap::new();
    let mut graph_nodes = Vec::new();
    let provider_subject = "did:chio:provider-alpha";
    let absent_selected_provider = match case {
        TrustMarketCase::SelectedProviderAbsent => "did:chio:provider-missing",
        _ => provider_subject,
    };

    let discovery_valid_until = match case {
        TrustMarketCase::StaleDiscovery => "2026-06-09T00:00:00Z",
        _ => "2026-06-11T00:00:00Z",
    };
    let discovery = signed_market_artifact_bytes(json!({
        "schema": "chio.commerce.provider-discovery-snapshot.v1",
        "id": "discovery-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "order_id": "order-commerce-001",
        "order_intent_ref": "intent-commerce-001",
        "market_scope": "bounded-autonomous-commerce",
        "provider_candidates": [
            {
                "subject": provider_subject,
                "provider_passport_ref": "provider-passport-alpha",
                "service_manifest_ref": "service-manifest-alpha",
                "availability_ref": "availability-alpha",
                "pricing_surface_ref": "pricing-alpha",
                "jurisdiction_ref": "jurisdiction-trust-market-valid",
                "excluded": false
            },
            {
                "subject": "did:chio:provider-beta",
                "provider_passport_ref": "provider-passport-beta",
                "service_manifest_ref": "service-manifest-beta",
                "availability_ref": "availability-beta",
                "pricing_surface_ref": "pricing-beta",
                "jurisdiction_ref": "jurisdiction-trust-market-valid",
                "excluded": false
            }
        ],
        "freshness_window": {
            "valid_from": "2026-06-09T00:00:00Z",
            "valid_until": discovery_valid_until
        },
        "discovery_authority_ref": "did:chio:market-curator",
        "signature": "sig-discovery-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "provider-discovery-snapshot",
        "provider-discovery-snapshot",
        "chio.commerce.provider-discovery-snapshot.v1",
        "provider-discovery-snapshot.json",
        discovery,
    );

    let score_scope = match case {
        TrustMarketCase::GlobalScorecardScope => "global",
        _ => "local-policy",
    };
    let computed_score = match case {
        TrustMarketCase::ScoreRecomputeMismatch => 99,
        TrustMarketCase::ScorecardPortableReputationOverweight => 91,
        _ => 92,
    };
    let native_reputation_weight = match case {
        TrustMarketCase::ScorecardPortableReputationOverweight => 30,
        _ => 40,
    };
    let portable_reputation_weight = match case {
        TrustMarketCase::ScorecardPortableReputationOverweight => 40,
        _ => 30,
    };
    let scorecard_valid_until = match case {
        TrustMarketCase::ScorecardStaleAtSelection => "2026-06-10T01:00:00Z",
        _ => "2026-06-11T00:00:00Z",
    };
    let scorecard = signed_market_artifact_bytes(json!({
        "schema": "chio.trust.scorecard-snapshot.v1",
        "id": "scorecard-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "subject": provider_subject,
        "scope": score_scope,
        "verifier_policy_ref": "policy-trust-market-valid",
        "component_scores": [
            {
                "component": "native_reputation",
                "score": 92,
                "weight": native_reputation_weight,
                "evidence_ref": "reputation-native-alpha",
                "stale": false
            },
            {
                "component": "portable_reputation",
                "score": 88,
                "weight": portable_reputation_weight,
                "evidence_ref": "reputation-import-trust-market-valid",
                "stale": false
            },
            {
                "component": "sla_history",
                "score": 96,
                "weight": 30,
                "evidence_ref": "sla-performance-history-alpha",
                "stale": false
            }
        ],
        "issuer_trust_roots": ["did:chio:federation-root"],
        "reputation_snapshot_refs": ["reputation-native-alpha"],
        "portable_reputation_import_refs": ["reputation-import-trust-market-valid"],
        "sla_performance_refs": ["sla-performance-history-alpha"],
        "negative_event_refs": [],
        "freshness_window": {
            "valid_from": "2026-06-09T00:00:00Z",
            "valid_until": scorecard_valid_until
        },
        "score_floor": 0,
        "score_ceiling": 100,
        "computed_score": computed_score,
        "downgrade_reasons": [],
        "signature": "sig-scorecard-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "trust-scorecard-snapshot",
        "trust-scorecard-snapshot",
        "chio.trust.scorecard-snapshot.v1",
        "trust-scorecard-snapshot.json",
        scorecard,
    );

    let reputation_import = signed_market_artifact_bytes(json!({
        "schema": "chio.trust.reputation-import-report.v1",
        "id": "reputation-import-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "subject": provider_subject,
        "source_network": "federated-commerce-network",
        "issuer": "did:chio:federation-root",
        "issuer_trust_ref": "did:chio:federation-root",
        "source_reputation_ref": "external-reputation-alpha",
        "negative_event_refs": [],
        "subject_binding_ref": "subject-binding-alpha",
        "privacy_profile_ref": "privacy-profile-market-valid",
        "decay_policy_ref": "decay-policy-market-valid",
        "local_weight": if matches!(case, TrustMarketCase::ReputationImportOverweight) {
            31
        } else {
            30
        },
        "import_verdict": "accepted",
        "usage": "scoring_input",
        "signature": "sig-reputation-import-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "reputation-import-report",
        "reputation-import-report",
        "chio.trust.reputation-import-report.v1",
        "reputation-import-report.json",
        reputation_import,
    );

    let sla_order_id = match case {
        TrustMarketCase::SlaWrongOrder => "order-commerce-wrong",
        _ => "order-commerce-001",
    };
    let sla_metric_definitions = match case {
        TrustMarketCase::SlaPerformanceMissingCommittedMetric => json!([
            {
                "metric": "completion_time_minutes",
                "target": 30,
                "unit": "minutes"
            },
            {
                "metric": "handoff_count",
                "target": 2,
                "unit": "count"
            }
        ]),
        _ => json!([
            {
                "metric": "completion_time_minutes",
                "target": 30,
                "unit": "minutes"
            }
        ]),
    };
    let sla_commitment = signed_market_artifact_bytes(json!({
        "schema": "chio.commerce.sla-commitment.v1",
        "id": "sla-commitment-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "order_id": sla_order_id,
        "provider_subject": provider_subject,
        "buyer_subject": "did:chio:buyer-acme",
        "service_scope": "bounded-shopping-task",
        "metric_definitions": sla_metric_definitions,
        "measurement_policy_ref": "measurement-policy-market-valid",
        "effective_window": {
            "start": "2026-06-10T00:00:00Z",
            "end": "2026-06-11T00:00:00Z"
        },
        "exclusions_ref": "sla-exclusions-market-valid",
        "remedy_policy_ref": "remedy-policy-market-valid",
        "collateral_position_ref": "collateral-trust-market-valid",
        "guarantee_decision_ref": "guarantee-trust-market-valid",
        "signature": "sig-sla-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "sla-commitment",
        "sla-commitment",
        "chio.commerce.sla-commitment.v1",
        "sla-commitment.json",
        sla_commitment,
    );

    let sla_performance_metric = match case {
        TrustMarketCase::SlaPerformanceMetricMismatch => "availability_percent",
        _ => "completion_time_minutes",
    };
    let sla_performance_value = match case {
        TrustMarketCase::SlaPerformanceTargetExceeded => 45,
        _ => 18,
    };
    let sla_performance = signed_market_artifact_bytes(json!({
        "schema": "chio.commerce.sla-performance-report.v1",
        "id": "sla-performance-trust-market-valid",
        "issued_at": "2026-06-10T01:00:00Z",
        "performance_id": "sla-performance-trust-market-valid",
        "sla_ref": "sla-commitment-trust-market-valid",
        "order_id": "order-commerce-001",
        "provider_subject": provider_subject,
        "measurement_policy_ref": "measurement-policy-market-valid",
        "measurement_evidence_refs": ["fulfillment-measurement-valid"],
        "measured_at": "2026-06-10T01:00:00Z",
        "computed_metric_results": [
            {
                "metric": sla_performance_metric,
                "value": sla_performance_value,
                "unit": "minutes",
                "passed": true
            }
        ],
        "breach_verdict": "none",
        "remedy_ref": "",
        "dispute_ref": "",
        "signature": "sig-sla-performance-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "sla-performance-report",
        "sla-performance-report",
        "chio.commerce.sla-performance-report.v1",
        "sla-performance-report.json",
        sla_performance,
    );

    let uses_hold_receipt_refs = matches!(
        case,
        TrustMarketCase::RiskReserveLedgerReceiptUntrustedSigner
            | TrustMarketCase::RiskSettlementReceiptUntrustedSigner
    );
    let uses_sanction_receipt_refs = matches!(
        case,
        TrustMarketCase::RiskSanctionReserveLedgerReceiptUntrustedSigner
            | TrustMarketCase::RiskSanctionAuthorityReceiptUntrustedSigner
            | TrustMarketCase::RiskSanctionJurisdictionReceiptUntrustedSigner
    );
    let risk_consumed_units: u64 = match case {
        TrustMarketCase::RiskSanctionReserveLedgerReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionAuthorityReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionJurisdictionReceiptUntrustedSigner => 1,
        TrustMarketCase::RiskDoubleConsumedReserve
        | TrustMarketCase::RiskOpenAppealReserveRelease => 500,
        _ => 0,
    };
    let risk_payout_units: u64 = if uses_sanction_receipt_refs {
        0
    } else {
        risk_consumed_units
    };
    let risk_reserve_ledger = match case {
        TrustMarketCase::RiskDoubleConsumedReserve => json!([
            {
                "entry_id": "reserve-ledger-market-payout",
                "receipt_ref": "receipt-market-payout",
                "lane": "claim_payout",
                "reserve_ref": "reserve-market-valid",
                "claim_id": "claim-market-payout",
                "currency": "USD",
                "units": 250,
                "settlement_ref": "settlement-market-payout",
                "payer_subject": "did:chio:provider-alpha",
                "payee_subject": "did:chio:provider-alpha"
            },
            {
                "entry_id": "reserve-ledger-market-release",
                "receipt_ref": "receipt-market-release",
                "lane": "reserve_release",
                "reserve_ref": "reserve-market-valid",
                "claim_id": "claim-market-payout",
                "currency": "USD",
                "units": 250,
                "settlement_ref": "settlement-market-release"
            }
        ]),
        TrustMarketCase::RiskOpenAppealReserveRelease => json!([
            {
                "entry_id": "reserve-ledger-market-release",
                "receipt_ref": "receipt-market-release",
                "lane": "reserve_release",
                "reserve_ref": "reserve-market-valid",
                "claim_id": "claim-market-open",
                "currency": "USD",
                "units": 500,
                "settlement_ref": "settlement-market-release"
            }
        ]),
        TrustMarketCase::RiskReserveLedgerReceiptUntrustedSigner
        | TrustMarketCase::RiskSettlementReceiptUntrustedSigner => json!([
            {
                "entry_id": "reserve-ledger-market-hold",
                "receipt_ref": "receipt-market-hold",
                "lane": "hold",
                "reserve_ref": "reserve-market-valid",
                "claim_id": "claim-market-hold",
                "currency": "USD",
                "units": 1,
                "settlement_ref": "settlement-market-hold"
            }
        ]),
        TrustMarketCase::RiskSanctionReserveLedgerReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionAuthorityReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionJurisdictionReceiptUntrustedSigner => json!([
            {
                "entry_id": "reserve-ledger-market-slash",
                "receipt_ref": "receipt-market-slash",
                "lane": "market_slash",
                "reserve_ref": "reserve-market-valid",
                "claim_id": "claim-market-slash",
                "currency": "USD",
                "units": 1,
                "settlement_ref": "settlement-market-slash",
                "sanction_bridge": {
                    "bridge_id": "sanction-bridge-market-valid",
                    "authority_receipt_ref": "authority-market-slash",
                    "evidence_ref": "provider-selection-report",
                    "jurisdiction_ref": "jurisdiction-market-slash",
                    "sanction_subject": provider_subject,
                    "maximum_slash_units": 1
                }
            }
        ]),
        _ => json!([]),
    };
    let risk_sanction_reserve_ledger = match case {
        TrustMarketCase::RiskSanctionReserveLedgerReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionAuthorityReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionJurisdictionReceiptUntrustedSigner => json!([
            {
                "entry_id": "sanction-reserve-ledger-market-slash",
                "bridge_id": "sanction-bridge-market-valid",
                "lane": "market_slash",
                "receipt_ref": "receipt-market-slash",
                "reserve_ref": "reserve-market-valid",
                "claim_id": "claim-market-slash",
                "currency": "USD",
                "units": 1,
                "settlement_ref": "settlement-market-slash",
                "authority_receipt_ref": "authority-market-slash",
                "evidence_ref": "provider-selection-report",
                "jurisdiction_ref": "jurisdiction-market-slash"
            }
        ]),
        _ => json!([]),
    };
    let covered_claim_ids = match case {
        TrustMarketCase::RiskDoubleConsumedReserve => vec!["claim-market-payout"],
        TrustMarketCase::RiskOpenAppealReserveRelease => vec!["claim-market-open"],
        TrustMarketCase::RiskReserveLedgerReceiptUntrustedSigner
        | TrustMarketCase::RiskSettlementReceiptUntrustedSigner => vec!["claim-market-hold"],
        TrustMarketCase::RiskSanctionReserveLedgerReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionAuthorityReceiptUntrustedSigner
        | TrustMarketCase::RiskSanctionJurisdictionReceiptUntrustedSigner => {
            vec!["claim-market-slash"]
        }
        _ => Vec::new(),
    };
    let facility_state = match case {
        TrustMarketCase::RiskFacilityLifecycleReplayGap
        | TrustMarketCase::RiskFacilityLifecycleReplayed
        | TrustMarketCase::RiskFacilityLifecycleMissingEvidence
        | TrustMarketCase::RiskFacilityLifecycleMissingEvidenceArtifact
        | TrustMarketCase::RiskFacilityLifecycleUnsignedAuthorityEvidence => "settlement_matched",
        _ => "coverage_bound",
    };
    let mut risk_report_value = json!({
        "schema": "chio.risk.comptroller-report.v1",
        "id": "risk-comptroller-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "passport_id": passport.id,
        "order_id": "order-commerce-001",
        "subject": provider_subject,
        "verdict": "verified",
        "risk_state": "reconciled",
        "facility": {
            "facility_id": "facility-market-valid",
            "policy_id": "risk-policy-facility-market-valid",
            "state": facility_state,
            "capital_currency": "USD",
            "capital_units": 2000,
            "reserve_currency": "USD",
            "reserve_units": 500,
            "reserve_ref": "reserve-market-valid"
        },
        "coverage": {
            "coverage_id": "coverage-market-valid",
            "order_id": "order-commerce-001",
            "subject": provider_subject,
            "currency": "USD",
            "exposure_units": 1000,
            "reserve_ref": "reserve-market-valid",
            "status": "bound",
            "covered_claim_ids": covered_claim_ids
        },
        "premium": {
            "premium_id": "premium-market-valid",
            "quote_ref": "provider-selection-report",
            "coverage_id": "coverage-market-valid",
            "order_id": "order-commerce-001",
            "subject": provider_subject,
            "currency": "USD",
            "coverage_exposure_units": 1000,
            "quoted_premium_units": 10,
            "bound_premium_units": 10,
            "collected_premium_units": 0,
            "status": "bound"
        },
        "capital_decomposition": {
            "decomposition_id": "capital-decomposition-market-valid",
            "source_kind": "facility_commitment",
            "source_ref": "adjudication-jurisdiction-receipt",
            "currency": "USD",
            "committed_units": 2000,
            "held_units": 500,
            "drawn_units": 0,
            "disbursed_units": risk_consumed_units,
            "impaired_units": 0,
            "available_units": 2000_u64.saturating_sub(500 + risk_consumed_units)
        },
        "reconciliation": {
            "order_id": "order-commerce-001",
            "currency": "USD",
            "exposure_units": 1000,
            "reserve_units": 500,
            "consumed_reserve_units": risk_consumed_units,
            "payout_units": risk_payout_units,
            "settlement_units": risk_payout_units,
            "status": "balanced"
        },
        "actuarial_evidence": {
            "model_ref": "actuarial-model-market-valid",
            "evidence_ref": "provider-selection-report",
            "currency": "USD",
            "supported_exposure_units": 1000,
            "confidence_level_bps": 9500,
            "backtest": {
                "backtest_id": "actuarial-backtest-market-valid",
                "window_start": "2026-03-10T00:00:00Z",
                "window_end": "2026-06-10T00:00:00Z",
                "sample_size": 120,
                "observed_loss_ratio_bps": 1800,
                "maximum_loss_ratio_bps": 2500,
                "status": "passed"
            }
        },
        "insurance_copy": {
            "copy_id": "insurance-copy-market-valid",
            "actuarial_evidence_ref": "actuarial-model-market-valid",
            "currency": "USD",
            "maximum_coverage_units": 1000,
            "coverage_statement": "coverage limited to supported exposure"
        },
        "reserve_ledger": risk_reserve_ledger,
        "sanction_reserve_ledger": risk_sanction_reserve_ledger,
        "verified_claims": ["claim.risk.comptroller_report_bound"]
    });
    if matches!(case, TrustMarketCase::RiskOpenAppealReserveRelease) {
        risk_report_value["appeals"] = json!([
            {
                "appeal_id": "appeal-market-open",
                "claim_id": "claim-market-open",
                "status": "open",
                "blocks": ["reserve_release", "reserve_slash", "facility_closure"]
            }
        ]);
    }
    if !matches!(case, TrustMarketCase::RiskFacilityLifecycleReplayGap) {
        let settlement_evidence_ref = match case {
            TrustMarketCase::RiskFacilityLifecycleMissingEvidence
            | TrustMarketCase::RiskFacilityLifecycleMissingEvidenceArtifact => {
                "missing-risk-evidence"
            }
            _ => "guarantee-decision",
        };
        risk_report_value["facility_lifecycle"] =
            facility_lifecycle_for_state(facility_state, settlement_evidence_ref);
        if matches!(
            case,
            TrustMarketCase::RiskFacilityLifecycleUnsignedAuthorityEvidence
        ) {
            risk_report_value["facility_lifecycle"][0]["authority_receipt_ref"] =
                json!("unsigned-risk-authority");
        }
    }
    let risk_report = if matches!(case, TrustMarketCase::RiskComptrollerReportUnsigned) {
        json_bytes(risk_report_value)
    } else {
        signed_market_artifact_bytes(risk_report_value)
    };
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "risk-comptroller-report",
        "risk-comptroller-report",
        "chio.risk.comptroller-report.v1",
        "risk-comptroller-report.json",
        risk_report,
    );

    let collateral_slash_authority = "did:chio:slash-authority";
    let collateral_source_type = match case {
        TrustMarketCase::CollateralUnsupportedSource => "unsecured_note",
        _ => "bond",
    };
    let collateral_lock_start = match case {
        TrustMarketCase::CollateralLockStartsAfterGuarantee => "2026-06-11T00:00:00Z",
        _ => "2026-06-10T00:00:00Z",
    };
    let collateral = signed_market_artifact_bytes(json!({
        "schema": "chio.risk.collateral-position-report.v1",
        "id": "collateral-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "collateral_id": "collateral-trust-market-valid",
        "subject": provider_subject,
        "order_id": "order-commerce-001",
        "currency_or_asset": "USD",
        "amount": 1000,
        "source_type": collateral_source_type,
        "source_ref": "provider-bond-alpha",
        "lock_start": collateral_lock_start,
        "lock_expiry": "2026-06-12T00:00:00Z",
        "claim_priority": "sla-remedy",
        "slash_authority_ref": collateral_slash_authority,
        "release_policy_ref": "release-policy-market-valid",
        "consumed_amount_refs": [],
        "available_amount": 1000,
        "signature": "sig-collateral-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "collateral-position-report",
        "collateral-position-report",
        "chio.risk.collateral-position-report.v1",
        "collateral-position-report.json",
        collateral,
    );

    let guarantee_backing_refs = match case {
        TrustMarketCase::GuaranteeWithoutBacking => Vec::<&str>::new(),
        _ => vec!["collateral-trust-market-valid"],
    };
    let guarantee_beneficiary_subject = match case {
        TrustMarketCase::GuaranteeWrongBeneficiary => "did:chio:buyer-other",
        _ => "did:chio:buyer-acme",
    };
    let guarantee_type = match case {
        TrustMarketCase::GuaranteeUnsupportedType => "permissionless_liquidity_backstop",
        _ => "bounded_sla_remedy",
    };
    let guarantee_claim_window = match case {
        TrustMarketCase::GuaranteeInvertedClaimWindow => json!({
            "start": "2026-06-11T00:00:00Z",
            "end": "2026-06-10T00:00:00Z"
        }),
        TrustMarketCase::GuaranteeEndsAfterSla => json!({
            "start": "2026-06-10T00:00:00Z",
            "end": "2026-06-12T00:00:00Z"
        }),
        _ => json!({
            "start": "2026-06-10T00:00:00Z",
            "end": "2026-06-11T00:00:00Z"
        }),
    };
    let guarantee = signed_market_artifact_bytes(json!({
        "schema": "chio.risk.guarantee-decision.v1",
        "id": "guarantee-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "guarantee_id": "guarantee-trust-market-valid",
        "order_id": "order-commerce-001",
        "provider_subject": provider_subject,
        "beneficiary_subject": guarantee_beneficiary_subject,
        "guarantee_type": guarantee_type,
        "maximum_remedy": 500,
        "currency": "USD",
        "backing_refs": guarantee_backing_refs,
        "coverage_decision_ref": "coverage-decision-market-valid",
        "sla_commitment_ref": "sla-commitment-trust-market-valid",
        "claim_window": guarantee_claim_window,
        "exclusions_ref": "guarantee-exclusions-market-valid",
        "adjudication_jurisdiction_ref": "jurisdiction-trust-market-valid",
        "verdict": "backed",
        "signature": "sig-guarantee-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "guarantee-decision",
        "guarantee-decision",
        "chio.risk.guarantee-decision.v1",
        "guarantee-decision.json",
        guarantee,
    );
    if matches!(
        case,
        TrustMarketCase::RiskFacilityLifecycleUnsignedAuthorityEvidence
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "guarantee-decision",
            "unsigned-risk-authority",
            "chio.risk.guarantee-decision.v1",
            "unsigned-risk-authority.json",
            json_bytes(json!({
                "schema": "chio.risk.guarantee-decision.v1"
            })),
        );
    }

    let slash_authority_refs = match case {
        TrustMarketCase::SlashAuthorityOutsideJurisdiction => vec!["did:chio:other-authority"],
        _ => vec![collateral_slash_authority],
    };
    let jurisdiction = signed_market_artifact_bytes(json!({
        "schema": "chio.risk.adjudication-jurisdiction-receipt.v1",
        "id": "jurisdiction-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "jurisdiction_id": "jurisdiction-trust-market-valid",
        "order_id": "order-commerce-001",
        "policy_ref": "jurisdiction-policy-market-valid",
        "covered_dispute_types": ["sla_breach", "guarantee_claim", "collateral_slash"],
        "adjudicator_subjects": ["did:chio:market-adjudicator"],
        "appeal_authority_refs": ["did:chio:appeal-authority"],
        "slash_authority_refs": slash_authority_refs,
        "remedy_limits": [
            {
                "currency": "USD",
                "maximum_remedy": 500
            }
        ],
        "evidence_rules_ref": "evidence-rules-market-valid",
        "effective_window": {
            "start": "2026-06-10T00:00:00Z",
            "end": "2026-06-12T00:00:00Z"
        },
        "signature": "sig-jurisdiction-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "adjudication-jurisdiction-receipt",
        "adjudication-jurisdiction-receipt",
        "chio.risk.adjudication-jurisdiction-receipt.v1",
        "adjudication-jurisdiction-receipt.json",
        jurisdiction,
    );

    let risk_report_ref = match case {
        TrustMarketCase::RiskReportRefUnbound => "risk-comptroller-market-missing",
        _ => "risk-comptroller-market-valid",
    };
    let beta_rank = match case {
        TrustMarketCase::AmbiguousTopRank
        | TrustMarketCase::LowerRankOverrideReceiptUnbound
        | TrustMarketCase::LowerRankOverrideReceiptUnavailable
        | TrustMarketCase::LowerRankOverrideReceiptUntrustedSigner => 1,
        _ => 2,
    };
    let beta_total_score = match case {
        TrustMarketCase::SelectionRankingOrderMismatch => 99,
        TrustMarketCase::LowerRankOverrideReceiptUnavailable
        | TrustMarketCase::LowerRankOverrideReceiptUntrustedSigner => 99,
        _ => 81,
    };
    let selected_rank = match case {
        TrustMarketCase::LowerRankOverrideReceiptUnbound
        | TrustMarketCase::LowerRankOverrideReceiptUnavailable
        | TrustMarketCase::LowerRankOverrideReceiptUntrustedSigner => 2,
        _ => 1,
    };
    let override_receipt_ref = match case {
        TrustMarketCase::LowerRankOverrideReceiptUnbound => "selection-override-receipt-missing",
        TrustMarketCase::LowerRankOverrideReceiptUnavailable
        | TrustMarketCase::LowerRankOverrideReceiptUntrustedSigner => "selection-override-receipt",
        _ => "",
    };
    let selected_total_score = match case {
        TrustMarketCase::SelectionScorecardScoreMismatch => 91,
        TrustMarketCase::ScorecardPortableReputationOverweight => 91,
        _ => 92,
    };
    let selection_issued_at = match case {
        TrustMarketCase::ScorecardStaleAtSelection => "2026-06-10T02:00:00Z",
        TrustMarketCase::SelectionPredatesDiscovery => "2026-06-09T23:59:00Z",
        _ => "2026-06-10T00:00:00Z",
    };
    let ranking_results = match case {
        TrustMarketCase::SelectionRankingMissingAvailableCandidate => json!([
            {
                "provider_subject": absent_selected_provider,
                "rank": selected_rank,
                "total_score": selected_total_score
            }
        ]),
        TrustMarketCase::SelectionRankingDuplicateProvider => json!([
            {
                "provider_subject": absent_selected_provider,
                "rank": selected_rank,
                "total_score": selected_total_score
            },
            {
                "provider_subject": "did:chio:provider-beta",
                "rank": 2,
                "total_score": 81
            },
            {
                "provider_subject": "did:chio:provider-beta",
                "rank": 3,
                "total_score": 70
            }
        ]),
        _ => json!([
            {
                "provider_subject": absent_selected_provider,
                "rank": selected_rank,
                "total_score": selected_total_score
            },
            {
                "provider_subject": "did:chio:provider-beta",
                "rank": beta_rank,
                "total_score": beta_total_score
            }
        ]),
    };
    let selection = signed_market_artifact_bytes(json!({
        "schema": "chio.commerce.provider-selection-report.v1",
        "id": "selection-trust-market-valid",
        "issued_at": selection_issued_at,
        "passport_id": passport.id,
        "order_id": "order-commerce-001",
        "discovery_snapshot_ref": "discovery-trust-market-valid",
        "selected_provider_subject": absent_selected_provider,
        "ranking_policy_ref": "ranking-policy-market-valid",
        "scorecard_ref": "scorecard-trust-market-valid",
        "sla_commitment_ref": "sla-commitment-trust-market-valid",
        "price_quote_ref": "price-quote-alpha",
        "risk_report_ref": risk_report_ref,
        "override_receipt_ref": override_receipt_ref,
        "selection_reason_codes": ["highest_local_score", "sla_available"],
        "ranking_results": ranking_results,
        "rejected_candidate_summaries": [
            {
                "provider_subject": "did:chio:provider-beta",
                "reason_codes": ["lower_local_score"],
                "redacted_fields": ["customer_history"]
            }
        ],
        "signature": "sig-selection-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "provider-selection-report",
        "provider-selection-report",
        "chio.commerce.provider-selection-report.v1",
        "provider-selection-report.json",
        selection,
    );

    let policy_required_claims = match case {
        TrustMarketCase::RequiredUnsupportedMarketClaim => vec![
            CLAIM_DISCOVERY_BOUND,
            CLAIM_SELECTION_BOUND,
            CLAIM_SCORECARD_BOUND,
            CLAIM_REPUTATION_IMPORT_BOUND,
            CLAIM_SLA_BOUND,
            CLAIM_COLLATERAL_GUARANTEE_BOUND,
            CLAIM_JURISDICTION_BOUND,
            CLAIM_UNSUPPORTED_MARKET_LIMITED,
            "claim.market.permissionless_provider_marketplace_operated",
        ],
        _ => vec![
            CLAIM_DISCOVERY_BOUND,
            CLAIM_SELECTION_BOUND,
            CLAIM_SCORECARD_BOUND,
            CLAIM_REPUTATION_IMPORT_BOUND,
            CLAIM_SLA_BOUND,
            CLAIM_COLLATERAL_GUARANTEE_BOUND,
            CLAIM_JURISDICTION_BOUND,
            CLAIM_UNSUPPORTED_MARKET_LIMITED,
        ],
    };
    let claim_set_claims = policy_required_claims
        .iter()
        .map(|claim| {
            json!({
                "claim_id": claim,
                "status": "verified",
                "required_evidence": ["provider-selection-report.json"],
                "evidence_refs": ["provider-selection-report.json"],
                "verifier_module": "chio-trust-market-context"
            })
        })
        .collect::<Vec<_>>();
    let claim_set = json_bytes(json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "claim-set-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "claims": claim_set_claims
    }));
    let claim_set_sha256 = chio_core_types::sha256_hex(&claim_set);
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "claim-set",
        "claim-set",
        "chio.transaction.claim-set.v1",
        "claim-set.json",
        claim_set,
    );
    let verifier_policy = json_bytes(json!({
        "schema": "chio.transaction.verifier-policy.v1",
        "id": "policy-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "required_claims": policy_required_claims.clone(),
        "omitted_claims": [],
        "unsupported_claims": [
            "claim.market.permissionless_provider_marketplace_operated",
            "claim.market.global_trust_score_published",
            "claim.market.liquidity_pool_operated",
            "claim.market.underwriter_market_operated",
            "claim.market.slashing_court_operated"
        ],
        "max_reputation_import_weight": 30,
        "trusted_market_authority_keys": [market_authority_key_hex()]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "verifier-policy",
        "verifier-policy",
        "chio.transaction.verifier-policy.v1",
        "verifier-policy.json",
        verifier_policy.clone(),
    );

    if matches!(
        case,
        TrustMarketCase::RiskFacilityLifecycleMissingEvidenceArtifact
    ) {
        graph_nodes.push(json!({
            "id": "missing-risk-evidence",
            "schema": "chio.risk.guarantee-decision.v1",
            "path": "missing-risk-evidence.json",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "role": "guarantee-decision"
        }));
    }
    if matches!(case, TrustMarketCase::LowerRankOverrideReceiptUnavailable) {
        graph_nodes.push(json!({
            "id": "selection-override-receipt",
            "schema": "chio.receipt.v1",
            "path": "selection-override-receipt.json",
            "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "role": "receipt"
        }));
    }
    if matches!(
        case,
        TrustMarketCase::LowerRankOverrideReceiptUntrustedSigner
    ) {
        push_receipt_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "selection-override-receipt",
            false,
        );
    }
    if uses_hold_receipt_refs {
        push_receipt_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt-market-hold",
            !matches!(
                case,
                TrustMarketCase::RiskReserveLedgerReceiptUntrustedSigner
            ),
        );
        push_receipt_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "settlement-market-hold",
            !matches!(case, TrustMarketCase::RiskSettlementReceiptUntrustedSigner),
        );
    }
    if uses_sanction_receipt_refs {
        push_receipt_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt-market-slash",
            !matches!(
                case,
                TrustMarketCase::RiskSanctionReserveLedgerReceiptUntrustedSigner
            ),
        );
        push_receipt_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "settlement-market-slash",
            true,
        );
        push_receipt_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "authority-market-slash",
            !matches!(
                case,
                TrustMarketCase::RiskSanctionAuthorityReceiptUntrustedSigner
            ),
        );
        push_receipt_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "jurisdiction-market-slash",
            !matches!(
                case,
                TrustMarketCase::RiskSanctionJurisdictionReceiptUntrustedSigner
            ),
        );
    }

    let mut graph_edges = vec![
        json!({
            "from": "claim-set",
            "to": "verifier-policy",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "provider-discovery-snapshot",
            "to": "provider-selection-report",
            "predicate": "binds",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "provider-selection-report",
            "to": "sla-commitment",
            "predicate": "binds",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "provider-selection-report",
            "to": "risk-comptroller-report",
            "predicate": "binds",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "trust-scorecard-snapshot",
            "to": "reputation-import-report",
            "predicate": "derives",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "guarantee-decision",
            "to": "collateral-position-report",
            "predicate": "binds",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "guarantee-decision",
            "to": "adjudication-jurisdiction-receipt",
            "predicate": "binds",
            "evidence_class": "chio-sidecar-proof"
        }),
    ];
    normalize_graph_node_ids(&mut graph_nodes, &mut graph_edges);
    let evidence_graph = json_bytes(json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "evidence-graph-trust-market-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "nodes": graph_nodes,
        "edges": graph_edges
    }));

    let mut passport = TransactionPassport {
        evidence_graph_sha256: chio_core_types::sha256_hex(&evidence_graph),
        claim_set_sha256,
        verifier_policy_sha256: chio_core_types::sha256_hex(&verifier_policy),
        ..passport
    };
    sign_transaction_passport(&mut passport);

    TrustMarketBundle {
        passport,
        evidence_graph_bytes: evidence_graph,
        root_evidence_graph_bytes: None,
        verifier_policy_bytes: verifier_policy,
        artifacts,
        trusted_passport_signer_keys: vec![transaction_passport_keypair().public_key()],
        trusted_market_authority_keys: vec![market_authority_keypair().public_key()],
    }
}

fn trust_market_bundle_with_required_claim(claim: &str) -> TrustMarketBundle {
    let mut bundle = trust_market_bundle(TrustMarketCase::Valid);
    let mut policy: Value =
        serde_json::from_slice(&bundle.verifier_policy_bytes).test_expect("verifier policy parses");
    policy["required_claims"]
        .as_array_mut()
        .test_expect("required claims are an array")
        .push(Value::String(claim.to_string()));
    bundle.verifier_policy_bytes = json_bytes(policy);
    bundle.passport.verifier_policy_sha256 =
        chio_core_types::sha256_hex(&bundle.verifier_policy_bytes);
    sign_transaction_passport(&mut bundle.passport);
    bundle
}

fn update_trust_market_artifact(bundle: &mut TrustMarketBundle, path: &str, value: Value) {
    let bytes = json_bytes(value);
    let digest = chio_core_types::sha256_hex(&bytes);
    bundle.artifacts.insert(path.to_string(), bytes);

    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("evidence graph parses");
    let mut old_node_id = None;
    for node in graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes array")
    {
        if node["path"] == path {
            old_node_id = node.get("id").and_then(Value::as_str).map(str::to_string);
            node["id"] = Value::String(digest.clone());
            node["sha256"] = Value::String(digest.clone());
        }
    }
    if let Some(old_node_id) = old_node_id {
        for edge in graph["edges"]
            .as_array_mut()
            .test_expect("evidence graph edges array")
        {
            for field in ["from", "to"] {
                if edge[field].as_str() == Some(old_node_id.as_str()) {
                    edge[field] = Value::String(digest.clone());
                }
            }
        }
    }
    bundle.evidence_graph_bytes = json_bytes(graph);
    bundle.passport.evidence_graph_sha256 =
        chio_core_types::sha256_hex(&bundle.evidence_graph_bytes);
    sign_transaction_passport(&mut bundle.passport);
}

#[test]
fn trust_market_context_accepts_marketplace_fixture() {
    let report = verify_trust_market_context(&trust_market_bundle(TrustMarketCase::Valid))
        .test_expect("trust-market fixture verifies");

    assert_eq!(report.schema, "chio.transaction.verifier-report.v1");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.passport_id, "passport-trust-market-valid");
    assert_eq!(
        report.trust_market_sections.selected_provider_subject,
        "did:chio:provider-alpha"
    );
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| claim == CLAIM_UNSUPPORTED_MARKET_LIMITED));
    assert!(report
        .unsupported_claims
        .iter()
        .any(|claim| claim == "claim.market.global_trust_score_published"));
}

#[test]
fn trust_market_context_rejects_tampered_transaction_passport_signature() {
    let mut bundle = trust_market_bundle(TrustMarketCase::Valid);
    bundle.passport.signature = "00".repeat(64);

    let error = verify_trust_market_context(&bundle)
        .test_expect_err("trust-market verifier must reject a forged passport root");

    assert!(error
        .to_string()
        .contains("transaction passport signature invalid"));
}

#[test]
fn trust_market_rejects_policy_authority_without_external_root() {
    let mut bundle = trust_market_bundle(TrustMarketCase::Valid);
    bundle.trusted_market_authority_keys.clear();

    let error = verify_trust_market_context(&bundle)
        .test_expect_err("trust-market authority must be verifier-pinned");

    assert!(error
        .to_string()
        .contains("trusted market authority keys missing"));
}

#[test]
fn trust_market_rejects_policy_authority_not_pinned_by_verifier() {
    let mut bundle = trust_market_bundle(TrustMarketCase::Valid);
    bundle.trusted_market_authority_keys = vec![Keypair::from_seed(&[60; 32]).public_key()];

    let error = verify_trust_market_context(&bundle)
        .test_expect_err("bundle-local trust-market authority must not self-authorize");

    assert!(error
        .to_string()
        .contains("trusted market authority keys do not match verifier policy"));
}

#[test]
fn trust_market_rejects_tampered_provider_selection_signature() {
    let mut bundle = trust_market_bundle(TrustMarketCase::Valid);
    let mut selection: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("provider-selection-report.json")
            .test_expect("selection artifact exists"),
    )
    .test_expect("selection artifact parses");
    selection["signature"] = Value::String("sig-selection-attacker".to_string());
    update_trust_market_artifact(&mut bundle, "provider-selection-report.json", selection);

    let error = verify_trust_market_context(&bundle)
        .test_expect_err("tampered provider selection signature must fail");

    let message = error.to_string();
    assert!(
        message.contains("trust-market artifact signature invalid"),
        "{message}"
    );
}

#[test]
fn trust_market_context_ignores_non_trust_market_required_claims() {
    let bundle =
        trust_market_bundle_with_required_claim("claim.runtime.security_receipt_totality_bound");

    let report = verify_trust_market_context(&bundle)
        .test_expect("trust-market verifier should leave runtime claims to runtime verifier");

    assert_eq!(report.verdict, "verified");
    assert!(!report
        .verified_claims
        .contains(&"claim.runtime.security_receipt_totality_bound".to_string()));
}

#[test]
fn trust_market_rejects_selected_provider_absent_from_discovery() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SelectedProviderAbsent,
    ))
    .test_expect_err("missing selected provider fails");

    assert!(error
        .to_string()
        .contains("selected provider absent from discovery snapshot"));
}

#[test]
fn trust_market_rejects_ambiguous_top_rank_without_override() {
    let error =
        verify_trust_market_context(&trust_market_bundle(TrustMarketCase::AmbiguousTopRank))
            .test_expect_err("ambiguous top rank must fail without override");

    assert!(error
        .to_string()
        .contains("ranking result rank is ambiguous"));
}

#[test]
fn trust_market_rejects_lower_rank_selection_with_unbound_override_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::LowerRankOverrideReceiptUnbound,
    ))
    .test_expect_err("unbound selection override receipt must fail");

    assert!(error
        .to_string()
        .contains("selection override receipt missing"));
}

#[test]
fn trust_market_rejects_lower_rank_selection_with_unavailable_override_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::LowerRankOverrideReceiptUnavailable,
    ))
    .test_expect_err("selection override receipt artifact must be available");

    assert!(error
        .to_string()
        .contains("selection override receipt missing"));
}

#[test]
fn trust_market_rejects_lower_rank_selection_with_untrusted_override_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::LowerRankOverrideReceiptUntrustedSigner,
    ))
    .test_expect_err("selection override receipt must be signed by a trusted market key");

    assert!(error
        .to_string()
        .contains("selection override receipt missing"));
}

#[test]
fn trust_market_rejects_selection_scorecard_score_mismatch() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SelectionScorecardScoreMismatch,
    ))
    .test_expect_err("selection ranking score must match bound scorecard");

    assert!(error
        .to_string()
        .contains("selection scorecard score mismatch"));
}

#[test]
fn trust_market_rejects_ranking_missing_available_candidate() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SelectionRankingMissingAvailableCandidate,
    ))
    .test_expect_err("ranking must cover every available provider candidate");

    assert!(error
        .to_string()
        .contains("selection ranking missing available candidate"));
}

#[test]
fn trust_market_rejects_ranking_duplicate_provider() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SelectionRankingDuplicateProvider,
    ))
    .test_expect_err("ranking must not duplicate provider candidates");

    assert!(error
        .to_string()
        .contains("selection ranking duplicate provider"));
}

#[test]
fn trust_market_rejects_scorecard_stale_at_selection_time() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::ScorecardStaleAtSelection,
    ))
    .test_expect_err("selection must use a fresh scorecard");

    assert!(error
        .to_string()
        .contains("scorecard snapshot is stale at selection"));
}

#[test]
fn trust_market_rejects_ranking_order_mismatch() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SelectionRankingOrderMismatch,
    ))
    .test_expect_err("ranking order must match candidate scores");

    assert!(error
        .to_string()
        .contains("selection ranking order mismatch"));
}

#[test]
fn trust_market_rejects_stale_discovery_snapshot() {
    let error = verify_trust_market_context(&trust_market_bundle(TrustMarketCase::StaleDiscovery))
        .test_expect_err("stale discovery fails");

    assert!(error.to_string().contains("discovery snapshot is stale"));
}

#[test]
fn trust_market_rejects_selection_before_discovery_snapshot() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SelectionPredatesDiscovery,
    ))
    .test_expect_err("selection must not predate discovery");

    assert!(error
        .to_string()
        .contains("selection predates discovery snapshot"));
}

#[test]
fn trust_market_rejects_global_scorecard_scope() {
    let error =
        verify_trust_market_context(&trust_market_bundle(TrustMarketCase::GlobalScorecardScope))
            .test_expect_err("global scorecard fails");

    assert!(error
        .to_string()
        .contains("scorecard must be local-policy scoped"));
}

#[test]
fn trust_market_rejects_score_recompute_mismatch() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::ScoreRecomputeMismatch,
    ))
    .test_expect_err("score recompute mismatch fails");

    assert!(error.to_string().contains("scorecard recompute mismatch"));
}

#[test]
fn trust_market_rejects_reputation_import_overweight() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::ReputationImportOverweight,
    ))
    .test_expect_err("reputation import overweight fails");

    assert!(error
        .to_string()
        .contains("reputation import local weight exceeds policy"));
}

#[test]
fn trust_market_rejects_scorecard_portable_reputation_overweight() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::ScorecardPortableReputationOverweight,
    ))
    .test_expect_err("scorecard portable reputation weight must honor import limit");

    assert!(error
        .to_string()
        .contains("scorecard portable reputation weight exceeds import limit"));
}

#[test]
fn trust_market_rejects_sla_wrong_order() {
    let error = verify_trust_market_context(&trust_market_bundle(TrustMarketCase::SlaWrongOrder))
        .test_expect_err("wrong SLA order fails");

    assert!(error.to_string().contains("SLA order mismatch"));
}

#[test]
fn trust_market_rejects_sla_performance_metric_mismatch() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SlaPerformanceMetricMismatch,
    ))
    .test_expect_err("SLA performance must match committed metric definitions");

    assert!(error
        .to_string()
        .contains("SLA performance metric mismatch"));
}

#[test]
fn trust_market_rejects_missing_committed_sla_metric() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SlaPerformanceMissingCommittedMetric,
    ))
    .test_expect_err("SLA performance must cover every committed metric");

    assert!(error.to_string().contains("SLA performance metric missing"));
}

#[test]
fn trust_market_rejects_sla_performance_target_exceeded_even_if_report_passed() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SlaPerformanceTargetExceeded,
    ))
    .test_expect_err("SLA performance must be recomputed from committed target");

    assert!(error.to_string().contains("SLA metric target exceeded"));
}

#[test]
fn trust_market_rejects_unsupported_collateral_source_type() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::CollateralUnsupportedSource,
    ))
    .test_expect_err("unsupported collateral source type must fail");

    assert!(error
        .to_string()
        .contains("collateral source type unsupported"));
}

#[test]
fn trust_market_rejects_guarantee_without_backing() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::GuaranteeWithoutBacking,
    ))
    .test_expect_err("guarantee without backing fails");

    assert!(error.to_string().contains("guarantee backing missing"));
}

#[test]
fn trust_market_rejects_guarantee_wrong_beneficiary() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::GuaranteeWrongBeneficiary,
    ))
    .test_expect_err("guarantee beneficiary must match the SLA buyer");

    assert!(error.to_string().contains("guarantee beneficiary mismatch"));
}

#[test]
fn trust_market_rejects_unsupported_guarantee_type() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::GuaranteeUnsupportedType,
    ))
    .test_expect_err("unsupported guarantee type must fail");

    assert!(error.to_string().contains("guarantee type unsupported"));
}

#[test]
fn trust_market_rejects_inverted_guarantee_claim_window() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::GuaranteeInvertedClaimWindow,
    ))
    .test_expect_err("guarantee claim window must be ordered");

    assert!(error.to_string().contains("guarantee claim window invalid"));
}

#[test]
fn trust_market_rejects_guarantee_claim_window_after_sla() {
    let error =
        verify_trust_market_context(&trust_market_bundle(TrustMarketCase::GuaranteeEndsAfterSla))
            .test_expect_err("guarantee claim window must end inside the SLA");

    assert!(error
        .to_string()
        .contains("guarantee ends outside SLA window"));
}

#[test]
fn trust_market_rejects_collateral_lock_start_after_guarantee_start() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::CollateralLockStartsAfterGuarantee,
    ))
    .test_expect_err("collateral must be locked before the guarantee begins");

    assert!(error
        .to_string()
        .contains("collateral lock starts after guarantee claim window"));
}

#[test]
fn trust_market_rejects_slash_authority_outside_jurisdiction() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::SlashAuthorityOutsideJurisdiction,
    ))
    .test_expect_err("slash authority outside jurisdiction fails");

    assert!(error
        .to_string()
        .contains("slash authority not bound to jurisdiction"));
}

#[test]
fn trust_market_rejects_required_unsupported_market_claim() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RequiredUnsupportedMarketClaim,
    ))
    .test_expect_err("required unsupported market claim fails");

    assert!(error
        .to_string()
        .contains("unsupported market claim cannot be required"));
}

#[test]
fn trust_market_rejects_unbound_risk_report_ref() {
    let error =
        verify_trust_market_context(&trust_market_bundle(TrustMarketCase::RiskReportRefUnbound))
            .test_expect_err("unbound risk report ref fails");

    assert!(error
        .to_string()
        .contains("selection risk report ref mismatch"));
}

#[test]
fn trust_market_rejects_unsigned_risk_comptroller_report() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskComptrollerReportUnsigned,
    ))
    .test_expect_err("risk comptroller report must be signed by a trusted market key");

    assert!(error
        .to_string()
        .contains("trust-market artifact signature invalid"));
}

#[test]
fn trust_market_rejects_risk_double_consumed_reserve() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskDoubleConsumedReserve,
    ))
    .test_expect_err("trust-market risk report must reject double reserve consumption");

    assert!(error
        .to_string()
        .contains("risk reserve double consumption"));
}

#[test]
fn trust_market_rejects_open_appeal_reserve_release() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskOpenAppealReserveRelease,
    ))
    .test_expect_err("trust-market open appeal must block reserve release");

    assert!(error
        .to_string()
        .contains("risk open appeal blocks reserve action"));
}

#[test]
fn trust_market_rejects_facility_lifecycle_replay_gap() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskFacilityLifecycleReplayGap,
    ))
    .test_expect_err("later facility state without lifecycle replay should fail");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle replay missing"));
}

#[test]
fn trust_market_accepts_facility_lifecycle_replay() {
    let report = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskFacilityLifecycleReplayed,
    ))
    .test_expect("facility lifecycle replay should verify");

    assert_eq!(report.verdict, "verified");
    assert_eq!(
        report.trust_market_sections.risk_comptroller_report_ref,
        "risk-comptroller-market-valid"
    );
}

#[test]
fn trust_market_rejects_facility_lifecycle_missing_evidence() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskFacilityLifecycleMissingEvidence,
    ))
    .test_expect_err("trust-market lifecycle evidence must be graph-bound");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle evidence missing"));
}

#[test]
fn trust_market_rejects_unsigned_risk_lifecycle_authority_evidence() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskFacilityLifecycleUnsignedAuthorityEvidence,
    ))
    .test_expect_err("risk lifecycle authority evidence must be signed by a trusted key");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle authority missing"));
}

#[test]
fn trust_market_rejects_risk_evidence_ref_without_artifact() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskFacilityLifecycleMissingEvidenceArtifact,
    ))
    .test_expect_err("trust-market risk evidence refs must load their artifacts");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle evidence missing"));
}

#[test]
fn trust_market_rejects_untrusted_risk_reserve_ledger_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskReserveLedgerReceiptUntrustedSigner,
    ))
    .test_expect_err("risk reserve ledger receipt must be signed by a trusted market key");

    assert!(error
        .to_string()
        .contains("risk reserve ledger receipt missing"));
}

#[test]
fn trust_market_rejects_untrusted_risk_settlement_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskSettlementReceiptUntrustedSigner,
    ))
    .test_expect_err("risk settlement receipt must be signed by a trusted market key");

    assert!(error
        .to_string()
        .contains("risk reserve ledger settlement missing"));
}

#[test]
fn trust_market_rejects_untrusted_risk_sanction_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskSanctionReserveLedgerReceiptUntrustedSigner,
    ))
    .test_expect_err("risk sanction receipt must be signed by a trusted market key");
    let error = error.to_string();

    assert!(
        error.contains("risk reserve ledger receipt missing"),
        "{error}"
    );
}

#[test]
fn trust_market_rejects_untrusted_risk_sanction_authority_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskSanctionAuthorityReceiptUntrustedSigner,
    ))
    .test_expect_err("risk sanction authority receipt must be signed by a trusted market key");
    let error = error.to_string();

    assert!(
        error.contains("risk market slash sanction authority missing"),
        "{error}"
    );
}

#[test]
fn trust_market_rejects_untrusted_risk_sanction_jurisdiction_receipt() {
    let error = verify_trust_market_context(&trust_market_bundle(
        TrustMarketCase::RiskSanctionJurisdictionReceiptUntrustedSigner,
    ))
    .test_expect_err("risk sanction jurisdiction receipt must be signed by a trusted market key");
    let error = error.to_string();

    assert!(
        error.contains("risk market slash jurisdiction missing"),
        "{error}"
    );
}
