use std::path::PathBuf;

use chio_core_types::PublicKey;
use chio_risk_comptroller::{
    validate_risk_portfolio_reports, validate_risk_report, validate_signed_risk_report,
    RiskComptrollerReport,
};
use chio_test_support::prelude::*;
use chio_transaction_passport::TransactionPassport;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .and_then(|workspace| workspace.parent())
        .test_expect("workspace root is parent of crates/platform/chio-risk-comptroller")
        .to_path_buf()
}

fn read_fixture(relative_path: &str) -> Vec<u8> {
    std::fs::read(workspace_root().join(relative_path)).test_expect("fixture reads")
}

fn enterprise_passport(case_name: &str) -> TransactionPassport {
    let bytes = read_fixture(&format!(
        "fixtures/proof-room/enterprise-export/{case_name}/transaction-passport.json"
    ));
    serde_json::from_slice(&bytes).test_expect("passport parses")
}

fn enterprise_risk_report_value(case_name: &str) -> serde_json::Value {
    let bytes = read_fixture(&format!(
        "fixtures/proof-room/enterprise-export/{case_name}/risk-comptroller-report.json"
    ));
    serde_json::from_slice(&bytes).test_expect("risk report parses")
}

fn assert_risk_report_schema_accepts(report: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_slice(&read_fixture(
        "spec/schemas/chio-risk/v1/comptroller-report.schema.json",
    ))
    .test_expect("risk schema parses");
    let validator = jsonschema::validator_for(&schema).test_expect("risk schema compiles");
    let errors = validator
        .iter_errors(report)
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        errors.is_empty(),
        "risk comptroller schema rejected verified report:\n{errors}"
    );
}

fn risk_report_signer_key(report: &serde_json::Value) -> PublicKey {
    let signature = report["signature"]
        .as_str()
        .test_expect("risk report signature");
    let Some(signature_ref) = signature.strip_prefix("sig-ed25519:") else {
        panic!("risk report signature uses supported prefix");
    };
    let Some((public_key_hex, _)) = signature_ref.split_once(':') else {
        panic!("risk report signature includes public key");
    };
    PublicKey::from_hex(public_key_hex).test_expect("risk report signer key parses")
}

fn sanction_backed_market_slash_report_value() -> serde_json::Value {
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-risk-market-slash"]);
    report["appeals"][0]["claim_id"] = serde_json::json!("claim-risk-market-slash");
    report["appeals"][0]["status"] = serde_json::json!("resolved");
    report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(100);
    report["reconciliation"]["payout_units"] = serde_json::json!(0);
    report["reconciliation"]["settlement_units"] = serde_json::json!(0);
    report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "risk-ledger-market-slash",
            "receipt_ref": "approval-case",
            "lane": "market_slash",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "sanction_bridge": {
                "bridge_id": "sanction-bridge-risk-market-slash",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report",
                "jurisdiction_ref": "approval-case",
                "sanction_subject": "did:chio:buyer-enterprise",
                "maximum_slash_units": 100
            }
        }
    ]);
    report["sanction_reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "sanction-ledger-market-slash",
            "bridge_id": "sanction-bridge-risk-market-slash",
            "lane": "market_slash",
            "receipt_ref": "approval-case",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report",
            "jurisdiction_ref": "approval-case"
        }
    ]);
    report
}

fn set_claim_payout_capital_instruction(report: &mut serde_json::Value) {
    let entry = report["reserve_ledger"][0].clone();
    report["capital_instructions"] = serde_json::json!([
        {
            "instruction_id": "capital-instruction-claim-payout-enterprise-valid",
            "reserve_entry_id": entry["entry_id"],
            "order_id": report["order_id"],
            "claim_id": entry["claim_id"],
            "reserve_ref": entry["reserve_ref"],
            "currency": entry["currency"],
            "units": entry["units"],
            "settlement_ref": entry["settlement_ref"],
            "intended_action": "transfer_funds",
            "source_kind": "facility_commitment",
            "intended_state": "pending_execution",
            "reconciled_state": "not_observed"
        }
    ]);
    refresh_premium_binding(report);
    refresh_capital_decomposition(report);
}

fn refresh_premium_binding(report: &mut serde_json::Value) {
    let exposure_units = report["coverage"]["exposure_units"]
        .as_u64()
        .test_expect("coverage exposure units");
    let premium_units = exposure_units.div_ceil(100).max(1);
    report["premium"]["coverage_id"] = report["coverage"]["coverage_id"].clone();
    report["premium"]["order_id"] = report["order_id"].clone();
    report["premium"]["subject"] = report["coverage"]["subject"].clone();
    report["premium"]["currency"] = report["coverage"]["currency"].clone();
    report["premium"]["coverage_exposure_units"] = serde_json::json!(exposure_units);
    report["premium"]["quoted_premium_units"] = serde_json::json!(premium_units);
    report["premium"]["bound_premium_units"] = serde_json::json!(premium_units);
    if report["premium"]["status"].as_str() == Some("collected") {
        report["premium"]["collected_premium_units"] = serde_json::json!(premium_units);
    }
}

fn refresh_capital_decomposition(report: &mut serde_json::Value) {
    let committed_units = report["facility"]["capital_units"]
        .as_u64()
        .test_expect("facility capital units");
    let held_units = report["facility"]["reserve_units"]
        .as_u64()
        .test_expect("facility reserve units");
    let settlement_units = report["reconciliation"]["settlement_units"]
        .as_u64()
        .test_expect("settlement units");
    let payout_units = report["reconciliation"]["payout_units"]
        .as_u64()
        .test_expect("payout units");
    let drawn_units = if settlement_units == 0 {
        payout_units
    } else {
        0
    };
    let disbursed_units = settlement_units;
    let deductions = held_units
        .checked_add(drawn_units)
        .and_then(|units| units.checked_add(disbursed_units))
        .test_expect("capital deductions do not overflow");
    report["capital_decomposition"]["committed_units"] = serde_json::json!(committed_units);
    report["capital_decomposition"]["held_units"] = serde_json::json!(held_units);
    report["capital_decomposition"]["drawn_units"] = serde_json::json!(drawn_units);
    report["capital_decomposition"]["disbursed_units"] = serde_json::json!(disbursed_units);
    report["capital_decomposition"]["available_units"] =
        serde_json::json!(committed_units.saturating_sub(deductions));
}

#[test]
fn risk_comptroller_valid_fixture_passes() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let report_value = enterprise_risk_report_value("valid-autonomous-commerce");
    let report: RiskComptrollerReport =
        serde_json::from_value(report_value.clone()).test_expect("risk report reparses");

    validate_risk_report(&passport, &report).test_expect("risk report verifies");
    assert_risk_report_schema_accepts(&report_value);
    let projection = serde_json::json!({
        "risk_state": report_value["risk_state"],
        "facility_state": report_value["facility"]["state"],
        "coverage_status": report_value["coverage"]["status"],
        "premium_status": report_value["premium"]["status"],
        "reconciliation_status": report_value["reconciliation"]["status"],
        "capital_available_units": report_value["capital_decomposition"]["available_units"],
    });
    assert_eq!(
        projection,
        serde_json::json!({
            "risk_state": "reconciled",
            "facility_state": "settlement_matched",
            "coverage_status": "bound",
            "premium_status": "collected",
            "reconciliation_status": "balanced",
            "capital_available_units": 8800,
        })
    );
}

#[test]
fn signed_risk_report_rejects_untrusted_comptroller_signer() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let report_value = enterprise_risk_report_value("valid-autonomous-commerce");
    let untrusted_key =
        PublicKey::from_hex("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
            .test_expect("untrusted key parses");

    let error = validate_signed_risk_report(&passport, &report_value, &[untrusted_key])
        .test_expect_err("risk report signer must be pinned externally");

    assert!(error
        .to_string()
        .contains("risk comptroller report signer untrusted"));
}

#[test]
fn signed_risk_report_returns_report_after_signature_verification() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let report_value = enterprise_risk_report_value("valid-autonomous-commerce");
    let trusted_key = risk_report_signer_key(&report_value);

    let report = validate_signed_risk_report(&passport, &report_value, &[trusted_key])
        .test_expect("signed risk report verifies");

    assert_eq!(report.id, "risk-comptroller-enterprise-valid");
}

#[test]
fn report_rejects_bound_coverage_without_premium_binding() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let mut report_value = enterprise_risk_report_value("valid-autonomous-commerce");
    report_value
        .as_object_mut()
        .test_expect("risk report is object")
        .remove("premium");
    let report: RiskComptrollerReport =
        serde_json::from_value(report_value).test_expect("risk report reparses");

    let error = validate_risk_report(&passport, &report)
        .test_expect_err("bound coverage must cite premium binding");

    assert!(error.to_string().contains("risk premium binding missing"));
}

#[test]
fn report_rejects_bound_coverage_without_lifecycle_replay() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let mut report = enterprise_risk_report_value("valid-autonomous-commerce");
    report["facility"]["state"] = serde_json::json!("reserve_held");
    report["facility_lifecycle"] = serde_json::json!([]);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("bound coverage must replay lifecycle to coverage_bound");

    assert!(error
        .to_string()
        .contains("risk facility lifecycle replay missing"));
}

#[test]
fn report_rejects_facility_lifecycle_without_policy_binding() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let mut report = enterprise_risk_report_value("valid-autonomous-commerce");
    report["facility"]["policy_id"] = serde_json::json!("");
    for transition in report["facility_lifecycle"]
        .as_array_mut()
        .test_expect("facility lifecycle is array")
    {
        transition["policy_id"] = serde_json::json!("");
    }

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("facility lifecycle must bind a policy id");

    assert!(error.to_string().contains("facility_policy_id"));
}

#[test]
fn report_accepts_facility_lifecycle_independent_of_input_order() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let mut report = enterprise_risk_report_value("valid-autonomous-commerce");
    report["facility_lifecycle"]
        .as_array_mut()
        .test_expect("facility lifecycle is array")
        .rotate_left(2);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");

    validate_risk_report(&passport, &report)
        .test_expect("facility lifecycle replay must be order independent");
}

#[test]
fn report_rejects_inverted_actuarial_backtest_window() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let mut report = enterprise_risk_report_value("valid-autonomous-commerce");
    report["actuarial_evidence"]["backtest"]["window_start"] =
        serde_json::json!("2026-06-17T00:00:00Z");
    report["actuarial_evidence"]["backtest"]["window_end"] =
        serde_json::json!("2026-06-16T00:00:00Z");

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("risk actuarial backtest windows must be ordered");

    assert!(error
        .to_string()
        .contains("risk actuarial backtest window inverted"));
}

#[test]
fn report_rejects_insurance_copy_below_exposure() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let mut report = enterprise_risk_report_value("valid-autonomous-commerce");
    report["insurance_copy"]["maximum_coverage_units"] = serde_json::json!(1);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("insurance copy must cover the bound exposure");

    assert!(error
        .to_string()
        .contains("risk insurance copy undercovers exposure"));
}

#[test]
fn open_appeal_only_blocks_named_reserve_actions() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["blocks"] = serde_json::json!(["facility_closure"]);
    set_claim_payout_capital_instruction(&mut report);
    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");

    validate_risk_report(&passport, &report)
        .test_expect("facility-closure appeal must not block claim payout");
}

#[test]
fn report_rejects_claim_payout_without_capital_instruction() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["blocks"] = serde_json::json!(["facility_closure"]);
    set_claim_payout_capital_instruction(&mut report);
    report
        .as_object_mut()
        .test_expect("risk report is object")
        .remove("capital_instructions");

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("claim payout must bind a capital instruction");

    assert!(error
        .to_string()
        .contains("risk capital instruction missing"));
}

#[test]
fn report_rejects_preobserved_claim_payout_capital_instruction() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["blocks"] = serde_json::json!(["facility_closure"]);
    set_claim_payout_capital_instruction(&mut report);
    report["capital_instructions"][0]["reconciled_state"] = serde_json::json!("matched");
    report["capital_instructions"][0]["observed_execution_ref"] =
        serde_json::json!("claim-payout-wire-1");

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("claim payout instruction must be pre-observed");

    assert!(error
        .to_string()
        .contains("risk payout preobserved instruction"));
}

#[test]
fn portfolio_rejects_cross_report_reserve_double_consumption() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report_a = enterprise_risk_report_value("open-appeal-claim-payout");
    report_a["facility"]["capital_units"] = serde_json::json!(20_000);
    report_a["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report_a["appeals"][0]["status"] = serde_json::json!("resolved");
    set_claim_payout_capital_instruction(&mut report_a);

    let mut report_b = report_a.clone();
    report_b["id"] = serde_json::json!("risk-comptroller-enterprise-duplicate");
    report_b["order_id"] = serde_json::json!("order-commerce-duplicate");
    report_b["coverage"]["order_id"] = serde_json::json!("order-commerce-duplicate");
    report_b["reconciliation"]["order_id"] = serde_json::json!("order-commerce-duplicate");
    report_b["reserve_ledger"][0]["entry_id"] =
        serde_json::json!("claim-payout-reserve-enterprise-duplicate");
    report_b["reserve_ledger"][0]["receipt_ref"] =
        serde_json::json!("risk-receipt-open-appeal-payout-duplicate");
    set_claim_payout_capital_instruction(&mut report_b);

    let report_a: RiskComptrollerReport =
        serde_json::from_value(report_a).test_expect("first risk report reparses");
    let report_b: RiskComptrollerReport =
        serde_json::from_value(report_b).test_expect("second risk report reparses");
    validate_risk_report(&passport, &report_a).test_expect("first risk report is valid");
    validate_risk_report(&passport, &report_b).test_expect("second risk report is valid");

    let error = validate_risk_portfolio_reports(&[report_a, report_b])
        .test_expect_err("portfolio must reject reused reserve consumption");
    assert!(error
        .to_string()
        .contains("risk portfolio reserve double consumption"));
}

#[test]
fn portfolio_rejects_cross_report_duplicate_reserve_receipt_id() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report_a = enterprise_risk_report_value("open-appeal-claim-payout");
    report_a["facility"]["capital_units"] = serde_json::json!(20_000);
    report_a["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report_a["reconciliation"]["consumed_reserve_units"] = serde_json::json!(500);
    report_a["reconciliation"]["payout_units"] = serde_json::json!(500);
    report_a["reconciliation"]["settlement_units"] = serde_json::json!(500);
    report_a["reserve_ledger"][0]["units"] = serde_json::json!(500);
    report_a["appeals"][0]["status"] = serde_json::json!("resolved");
    set_claim_payout_capital_instruction(&mut report_a);

    let mut report_b = report_a.clone();
    report_b["id"] = serde_json::json!("risk-comptroller-enterprise-duplicate-receipt");
    report_b["order_id"] = serde_json::json!("order-commerce-duplicate-receipt");
    report_b["coverage"]["order_id"] = serde_json::json!("order-commerce-duplicate-receipt");
    report_b["coverage"]["covered_claim_ids"] =
        serde_json::json!(["claim-enterprise-duplicate-receipt"]);
    report_b["reconciliation"]["order_id"] = serde_json::json!("order-commerce-duplicate-receipt");
    report_b["reserve_ledger"][0]["entry_id"] =
        serde_json::json!("claim-payout-reserve-enterprise-duplicate-receipt");
    report_b["reserve_ledger"][0]["claim_id"] =
        serde_json::json!("claim-enterprise-duplicate-receipt");
    report_b["appeals"][0]["claim_id"] = serde_json::json!("claim-enterprise-duplicate-receipt");
    set_claim_payout_capital_instruction(&mut report_b);

    let report_a: RiskComptrollerReport =
        serde_json::from_value(report_a).test_expect("first risk report reparses");
    let report_b: RiskComptrollerReport =
        serde_json::from_value(report_b).test_expect("second risk report reparses");
    validate_risk_report(&passport, &report_a).test_expect("first risk report is valid");
    validate_risk_report(&passport, &report_b).test_expect("second risk report is valid");

    let error = validate_risk_portfolio_reports(&[report_a, report_b])
        .test_expect_err("portfolio must reject reused reserve receipt refs");
    assert!(error
        .to_string()
        .contains("risk portfolio reserve ledger duplicate receipt"));
}

#[test]
fn portfolio_rejects_shared_reserve_overconsumption_across_claims() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report_a = enterprise_risk_report_value("open-appeal-claim-payout");
    report_a["facility"]["capital_units"] = serde_json::json!(20_000);
    report_a["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report_a["reconciliation"]["consumed_reserve_units"] = serde_json::json!(700);
    report_a["reconciliation"]["payout_units"] = serde_json::json!(700);
    report_a["reconciliation"]["settlement_units"] = serde_json::json!(700);
    report_a["reserve_ledger"][0]["units"] = serde_json::json!(700);
    report_a["appeals"][0]["status"] = serde_json::json!("resolved");
    set_claim_payout_capital_instruction(&mut report_a);

    let mut report_b = report_a.clone();
    report_b["id"] = serde_json::json!("risk-comptroller-enterprise-secondary");
    report_b["order_id"] = serde_json::json!("order-commerce-secondary");
    report_b["coverage"]["order_id"] = serde_json::json!("order-commerce-secondary");
    report_b["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-secondary"]);
    report_b["reconciliation"]["order_id"] = serde_json::json!("order-commerce-secondary");
    report_b["reserve_ledger"][0]["entry_id"] =
        serde_json::json!("claim-payout-reserve-enterprise-secondary");
    report_b["reserve_ledger"][0]["receipt_ref"] =
        serde_json::json!("risk-receipt-open-appeal-payout-secondary");
    report_b["reserve_ledger"][0]["claim_id"] = serde_json::json!("claim-enterprise-secondary");
    report_b["appeals"][0]["claim_id"] = serde_json::json!("claim-enterprise-secondary");
    set_claim_payout_capital_instruction(&mut report_b);

    let report_a: RiskComptrollerReport =
        serde_json::from_value(report_a).test_expect("first risk report reparses");
    let report_b: RiskComptrollerReport =
        serde_json::from_value(report_b).test_expect("second risk report reparses");
    validate_risk_report(&passport, &report_a).test_expect("first risk report is valid");
    validate_risk_report(&passport, &report_b).test_expect("second risk report is valid");

    let error = validate_risk_portfolio_reports(&[report_a, report_b])
        .test_expect_err("portfolio must reject aggregate overuse of the same reserve");
    assert!(error
        .to_string()
        .contains("risk portfolio reserve overconsumed"));
}

#[test]
fn portfolio_counts_shared_facility_reserve_once_across_claims() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report_a = enterprise_risk_report_value("open-appeal-claim-payout");
    report_a["facility"]["capital_units"] = serde_json::json!(12_000);
    report_a["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report_a["reconciliation"]["consumed_reserve_units"] = serde_json::json!(500);
    report_a["reconciliation"]["payout_units"] = serde_json::json!(500);
    report_a["reconciliation"]["settlement_units"] = serde_json::json!(500);
    report_a["reserve_ledger"][0]["units"] = serde_json::json!(500);
    report_a["appeals"][0]["status"] = serde_json::json!("resolved");
    set_claim_payout_capital_instruction(&mut report_a);

    let mut report_b = report_a.clone();
    report_b["id"] = serde_json::json!("risk-comptroller-enterprise-second-covered-claim");
    report_b["order_id"] = serde_json::json!("order-commerce-second-covered-claim");
    report_b["coverage"]["order_id"] = serde_json::json!("order-commerce-second-covered-claim");
    report_b["coverage"]["covered_claim_ids"] =
        serde_json::json!(["claim-enterprise-second-covered-claim"]);
    report_b["reconciliation"]["order_id"] =
        serde_json::json!("order-commerce-second-covered-claim");
    report_b["reserve_ledger"][0]["entry_id"] =
        serde_json::json!("claim-payout-reserve-enterprise-second-covered-claim");
    report_b["reserve_ledger"][0]["receipt_ref"] =
        serde_json::json!("risk-receipt-second-covered-claim-payout");
    report_b["reserve_ledger"][0]["claim_id"] =
        serde_json::json!("claim-enterprise-second-covered-claim");
    report_b["appeals"][0]["claim_id"] = serde_json::json!("claim-enterprise-second-covered-claim");
    set_claim_payout_capital_instruction(&mut report_b);

    let report_a: RiskComptrollerReport =
        serde_json::from_value(report_a).test_expect("first risk report reparses");
    let report_b: RiskComptrollerReport =
        serde_json::from_value(report_b).test_expect("second risk report reparses");
    validate_risk_report(&passport, &report_a).test_expect("first risk report is valid");
    validate_risk_report(&passport, &report_b).test_expect("second risk report is valid");

    validate_risk_portfolio_reports(&[report_a, report_b])
        .test_expect("portfolio counts the shared facility reserve once");
}

#[test]
fn portfolio_rejects_same_reserve_ref_across_facilities() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report_a = enterprise_risk_report_value("open-appeal-claim-payout");
    report_a["facility"]["capital_units"] = serde_json::json!(20_000);
    report_a["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report_a["reconciliation"]["consumed_reserve_units"] = serde_json::json!(500);
    report_a["reconciliation"]["payout_units"] = serde_json::json!(500);
    report_a["reconciliation"]["settlement_units"] = serde_json::json!(500);
    report_a["reserve_ledger"][0]["units"] = serde_json::json!(500);
    report_a["appeals"][0]["status"] = serde_json::json!("resolved");
    set_claim_payout_capital_instruction(&mut report_a);

    let mut report_b = report_a.clone();
    report_b["id"] = serde_json::json!("risk-comptroller-enterprise-other-facility");
    report_b["order_id"] = serde_json::json!("order-commerce-other-facility");
    report_b["facility"]["facility_id"] = serde_json::json!("facility-enterprise-other");
    report_b["coverage"]["order_id"] = serde_json::json!("order-commerce-other-facility");
    report_b["coverage"]["covered_claim_ids"] =
        serde_json::json!(["claim-enterprise-other-facility"]);
    report_b["reconciliation"]["order_id"] = serde_json::json!("order-commerce-other-facility");
    report_b["reserve_ledger"][0]["entry_id"] =
        serde_json::json!("claim-payout-reserve-enterprise-other-facility");
    report_b["reserve_ledger"][0]["receipt_ref"] =
        serde_json::json!("risk-receipt-open-appeal-payout-other-facility");
    report_b["reserve_ledger"][0]["claim_id"] =
        serde_json::json!("claim-enterprise-other-facility");
    report_b["appeals"][0]["claim_id"] = serde_json::json!("claim-enterprise-other-facility");
    set_claim_payout_capital_instruction(&mut report_b);

    let report_a: RiskComptrollerReport =
        serde_json::from_value(report_a).test_expect("first risk report reparses");
    let report_b: RiskComptrollerReport =
        serde_json::from_value(report_b).test_expect("second risk report reparses");
    validate_risk_report(&passport, &report_a).test_expect("first risk report is valid");
    validate_risk_report(&passport, &report_b).test_expect("second risk report is valid");

    let error = validate_risk_portfolio_reports(&[report_a, report_b])
        .test_expect_err("portfolio must reject reserve refs shared across facilities");
    assert!(error
        .to_string()
        .contains("risk portfolio reserve facility mismatch"));
}

#[test]
fn report_rejects_unbound_sanction_reserve_ledger_entry() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = sanction_backed_market_slash_report_value();
    report["sanction_reserve_ledger"]
        .as_array_mut()
        .test_expect("sanction reserve ledger is array")
        .push(serde_json::json!({
            "entry_id": "sanction-ledger-market-slash-unbound",
            "bridge_id": "sanction-bridge-risk-market-slash-unbound",
            "lane": "market_slash",
            "receipt_ref": "approval-case-unbound",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report",
            "jurisdiction_ref": "approval-case"
        }));

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("every sanction reserve ledger entry must bind a market slash");

    assert!(error
        .to_string()
        .contains("risk sanction reserve ledger unbound entry"));
}

#[test]
fn report_rejects_duplicate_sanction_reserve_ledger_receipt() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = sanction_backed_market_slash_report_value();
    let mut duplicate_entry = report["sanction_reserve_ledger"][0].clone();
    duplicate_entry["entry_id"] = serde_json::json!("sanction-ledger-market-slash-duplicate");
    report["sanction_reserve_ledger"]
        .as_array_mut()
        .test_expect("sanction reserve ledger is array")
        .push(duplicate_entry);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("sanction reserve ledger receipts must not be reused");

    assert!(error
        .to_string()
        .contains("risk sanction reserve ledger duplicate receipt"));
}

#[test]
fn report_rejects_reused_sanction_bridge_across_market_slashes() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = sanction_backed_market_slash_report_value();
    report["coverage"]["covered_claim_ids"] = serde_json::json!([
        "claim-risk-market-slash",
        "claim-risk-market-slash-secondary"
    ]);
    report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(200);

    let mut second_market_slash = report["reserve_ledger"][0].clone();
    second_market_slash["entry_id"] = serde_json::json!("risk-ledger-market-slash-secondary");
    second_market_slash["receipt_ref"] = serde_json::json!("approval-case-secondary");
    second_market_slash["claim_id"] = serde_json::json!("claim-risk-market-slash-secondary");
    report["reserve_ledger"]
        .as_array_mut()
        .test_expect("reserve ledger is array")
        .push(second_market_slash);

    let mut second_sanction_entry = report["sanction_reserve_ledger"][0].clone();
    second_sanction_entry["entry_id"] = serde_json::json!("sanction-ledger-market-slash-secondary");
    second_sanction_entry["receipt_ref"] = serde_json::json!("approval-case-secondary");
    second_sanction_entry["claim_id"] = serde_json::json!("claim-risk-market-slash-secondary");
    report["sanction_reserve_ledger"]
        .as_array_mut()
        .test_expect("sanction reserve ledger is array")
        .push(second_sanction_entry);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("one sanction bridge must not back multiple market slashes");

    assert!(error.to_string().contains("risk sanction bridge duplicate"));
}

#[test]
fn report_rejects_reserve_slash_reported_as_claim_payout() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["status"] = serde_json::json!("resolved");
    report["reserve_ledger"][0]["lane"] = serde_json::json!("reserve_slash");
    let reserve_entry = report["reserve_ledger"][0]
        .as_object_mut()
        .test_expect("reserve ledger entry is object");
    reserve_entry.remove("payer_subject");
    reserve_entry.remove("payee_subject");
    report
        .as_object_mut()
        .test_expect("risk report is object")
        .remove("capital_instructions");

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("reserve slash cannot satisfy claim payout reconciliation");

    assert!(error.to_string().contains("risk payout ledger mismatch"));
}

#[test]
fn report_rejects_appeal_outside_coverage() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["claim_id"] = serde_json::json!("claim-enterprise-uncovered");
    set_claim_payout_capital_instruction(&mut report);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("risk appeals must be scoped to covered claims");

    assert!(error.to_string().contains("risk appeal outside coverage"));
}

#[test]
fn report_rejects_duplicate_appeal_id() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["status"] = serde_json::json!("resolved");
    set_claim_payout_capital_instruction(&mut report);
    let duplicate_appeal = report["appeals"][0].clone();
    report["appeals"]
        .as_array_mut()
        .test_expect("appeals is array")
        .push(duplicate_appeal);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("appeal ids must be unique within a risk report");

    assert!(error.to_string().contains("risk appeal duplicate id"));
}

#[test]
fn report_rejects_closed_facility_with_open_appeal() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["facility"]["state"] = serde_json::json!("closed");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["blocks"] = serde_json::json!(["facility_closure"]);
    report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(1200);
    report["reconciliation"]["payout_units"] = serde_json::json!(0);
    report["reconciliation"]["settlement_units"] = serde_json::json!(0);
    report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "claim-release-reserve-enterprise-valid",
            "receipt_ref": "risk-receipt-open-appeal-release",
            "lane": "reserve_release",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-enterprise-valid",
            "currency": "USD",
            "units": 1200,
            "settlement_ref": "settlement-enterprise-valid"
        }
    ]);
    report
        .as_object_mut()
        .test_expect("risk report is object")
        .remove("capital_instructions");
    report["facility_lifecycle"]
        .as_array_mut()
        .test_expect("facility lifecycle is array")
        .extend([
            serde_json::json!({
                "transition_id": "facility-transition-reserve-controlled",
                "policy_id": "risk-policy-enterprise-valid",
                "from_state": "settlement_matched",
                "to_state": "reserve_controlled",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "evidence-export-bundle"
            }),
            serde_json::json!({
                "transition_id": "facility-transition-closed",
                "policy_id": "risk-policy-enterprise-valid",
                "from_state": "reserve_controlled",
                "to_state": "closed",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "evidence-export-bundle"
            }),
        ]);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    let error = validate_risk_report(&passport, &report)
        .test_expect_err("facility closure must fail while a covered appeal blocks closure");

    assert!(error
        .to_string()
        .contains("risk open appeal blocks facility closure"));
}

#[test]
fn report_allows_closed_facility_when_open_appeal_blocks_different_action() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["facility"]["state"] = serde_json::json!("closed");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["blocks"] = serde_json::json!(["claim_payout"]);
    report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(1200);
    report["reconciliation"]["payout_units"] = serde_json::json!(0);
    report["reconciliation"]["settlement_units"] = serde_json::json!(0);
    report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "claim-release-reserve-enterprise-valid",
            "receipt_ref": "risk-receipt-open-appeal-release",
            "lane": "reserve_release",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-enterprise-valid",
            "currency": "USD",
            "units": 1200,
            "settlement_ref": "settlement-enterprise-valid"
        }
    ]);
    report
        .as_object_mut()
        .test_expect("risk report is object")
        .remove("capital_instructions");
    report["facility_lifecycle"]
        .as_array_mut()
        .test_expect("facility lifecycle is array")
        .extend([
            serde_json::json!({
                "transition_id": "facility-transition-reserve-controlled",
                "policy_id": "risk-policy-enterprise-valid",
                "from_state": "settlement_matched",
                "to_state": "reserve_controlled",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "evidence-export-bundle"
            }),
            serde_json::json!({
                "transition_id": "facility-transition-closed",
                "policy_id": "risk-policy-enterprise-valid",
                "from_state": "reserve_controlled",
                "to_state": "closed",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "evidence-export-bundle"
            }),
        ]);

    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");
    validate_risk_report(&passport, &report)
        .test_expect("non-closure appeal must not block facility closure");
}
