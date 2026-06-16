use std::path::PathBuf;

use chio_risk_comptroller::{
    validate_risk_portfolio_reports, validate_risk_report, RiskComptrollerReport,
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

#[test]
fn verified_enterprise_risk_report_matches_public_schema() {
    let passport = enterprise_passport("valid-autonomous-commerce");
    let report_value = enterprise_risk_report_value("valid-autonomous-commerce");
    let report: RiskComptrollerReport =
        serde_json::from_value(report_value.clone()).test_expect("risk report reparses");

    validate_risk_report(&passport, &report).test_expect("risk report verifies");
    assert_risk_report_schema_accepts(&report_value);
}

#[test]
fn open_appeal_only_blocks_named_reserve_actions() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report = enterprise_risk_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report["appeals"][0]["blocks"] = serde_json::json!(["facility_closure"]);
    let report: RiskComptrollerReport =
        serde_json::from_value(report).test_expect("risk report reparses");

    validate_risk_report(&passport, &report)
        .test_expect("facility-closure appeal must not block claim payout");
}

#[test]
fn portfolio_rejects_cross_report_reserve_double_consumption() {
    let passport = enterprise_passport("open-appeal-claim-payout");
    let mut report_a = enterprise_risk_report_value("open-appeal-claim-payout");
    report_a["facility"]["capital_units"] = serde_json::json!(20_000);
    report_a["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-enterprise-valid"]);
    report_a["appeals"][0]["status"] = serde_json::json!("resolved");

    let mut report_b = report_a.clone();
    report_b["id"] = serde_json::json!("risk-comptroller-enterprise-duplicate");
    report_b["order_id"] = serde_json::json!("order-commerce-duplicate");
    report_b["coverage"]["order_id"] = serde_json::json!("order-commerce-duplicate");
    report_b["reconciliation"]["order_id"] = serde_json::json!("order-commerce-duplicate");
    report_b["reserve_ledger"][0]["entry_id"] =
        serde_json::json!("claim-payout-reserve-enterprise-duplicate");
    report_b["reserve_ledger"][0]["receipt_ref"] =
        serde_json::json!("risk-receipt-open-appeal-payout-duplicate");

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
    report["facility_lifecycle"]
        .as_array_mut()
        .test_expect("facility lifecycle is array")
        .extend([
            serde_json::json!({
                "transition_id": "facility-transition-reserve-controlled",
                "from_state": "settlement_matched",
                "to_state": "reserve_controlled",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "evidence-export-bundle"
            }),
            serde_json::json!({
                "transition_id": "facility-transition-closed",
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
    report["facility_lifecycle"]
        .as_array_mut()
        .test_expect("facility lifecycle is array")
        .extend([
            serde_json::json!({
                "transition_id": "facility-transition-reserve-controlled",
                "from_state": "settlement_matched",
                "to_state": "reserve_controlled",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "evidence-export-bundle"
            }),
            serde_json::json!({
                "transition_id": "facility-transition-closed",
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
