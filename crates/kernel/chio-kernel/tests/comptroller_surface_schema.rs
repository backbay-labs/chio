use chio_credit::ExposureLedgerCurrencyPosition;
use chio_kernel::operator_report::{
    ComptrollerDecisionSummary, ComptrollerSurfaceReport, ComptrollerSurfaceSourceRefs,
    COMPTROLLER_SURFACE_REPORT_SCHEMA,
};
use chio_test_support::prelude::*;

const SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-comptroller/v1/surface-report.schema.json"
));

fn sample() -> ComptrollerSurfaceReport {
    ComptrollerSurfaceReport {
        schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
        generated_at: 1_700_000_000,
        filters: chio_kernel::operator_report::OperatorReportQuery::default(),
        exposure_positions: vec![ExposureLedgerCurrencyPosition {
            currency: "USD".to_string(),
            governed_max_exposure_units: 4200,
            reserved_units: 1000,
            settled_units: 200,
            pending_units: 100,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        }],
        decision_summary: ComptrollerDecisionSummary {
            allow_count: 1,
            deny_count: 1,
            cancelled_count: 0,
            incomplete_count: 0,
        },
        settlement_reconciliation: Default::default(),
        budget_utilization: Default::default(),
        source_refs: ComptrollerSurfaceSourceRefs::default(),
        execution_nonce_ref: None,
        hold_ref: None,
    }
}

fn schema_value() -> serde_json::Value {
    serde_json::from_str(SCHEMA_JSON).test_expect("schema parses")
}

#[test]
fn positive_sample_validates_against_published_schema() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).test_expect("compile schema");
    let instance = serde_json::to_value(sample()).test_expect("serialize sample");
    assert!(
        validator.is_valid(&instance),
        "serialized sample must satisfy the published schema"
    );
}

#[test]
fn extra_top_level_field_is_rejected() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).test_expect("compile schema");
    let mut instance = serde_json::to_value(sample()).test_expect("serialize sample");
    instance["unexpectedField"] = serde_json::json!("nope");
    assert!(
        !validator.is_valid(&instance),
        "additionalProperties:false must reject extra fields"
    );
}

#[test]
fn missing_required_field_is_rejected() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).test_expect("compile schema");
    let mut instance = serde_json::to_value(sample()).test_expect("serialize sample");
    instance
        .as_object_mut()
        .test_expect("object")
        .remove("exposurePositions");
    assert!(
        !validator.is_valid(&instance),
        "missing required field must be rejected"
    );
}

#[test]
fn wrong_schema_const_is_rejected() {
    let schema = schema_value();
    let validator = jsonschema::validator_for(&schema).test_expect("compile schema");
    let mut instance = serde_json::to_value(sample()).test_expect("serialize sample");
    instance["schema"] = serde_json::json!("chio.comptroller.surface-report.v9");
    assert!(
        !validator.is_valid(&instance),
        "wrong schema const must be rejected"
    );
}
