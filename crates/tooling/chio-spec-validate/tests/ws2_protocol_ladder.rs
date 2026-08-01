use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;

use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SIGNED_SCHEMAS: [&str; 6] = [
    "chio.credit.receivable-iou-envelope.v1",
    "chio.factor.assignment-acknowledgement.v1",
    "chio.factor.assignment-agreement.v1",
    "chio.factor.assignment-bind-authorization.v1",
    "chio.factor.assignment-not-applied.v1",
    "chio.obligation.status-proof.v1",
];

const UNSIGNED_SCHEMAS: [&str; 4] = [
    "chio.factor.assignment-offer.v1",
    "chio.factor.discount-quote.v1",
    "chio.factor.normalized-assignment-request.v1",
    "chio.factor.receivable-claim.v1",
];

fn spec(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../../spec/{name}"))
}

fn section<'a>(text: &'a str, start: &str, end: &str) -> TestResult<&'a str> {
    let section = text
        .split_once(start)
        .map(|(_, section)| section)
        .ok_or_else(|| io::Error::other(format!("missing section start: {start}")))?;
    section
        .split_once(end)
        .map(|(section, _)| section)
        .ok_or_else(|| io::Error::other(format!("missing section end: {end}")).into())
}

fn schema_bullets(text: &str) -> BTreeSet<&str> {
    text.lines()
        .filter_map(|line| line.strip_prefix("- `")?.strip_suffix('`'))
        .collect()
}

fn ladder_json(text: &str, key: &str, value: &str) -> TestResult<Value> {
    for block in text.split("```json").skip(1) {
        let Some((block, _)) = block.split_once("```") else {
            continue;
        };
        let parsed: Value = serde_json::from_str(block.trim())?;
        if parsed.get(key).and_then(Value::as_str) == Some(value) {
            return Ok(parsed);
        }
    }
    Err(io::Error::other(format!("missing ladder JSON where {key} is {value}")).into())
}

#[test]
fn protocol_names_the_exact_signed_and_unsigned_factoring_surfaces() -> TestResult {
    let protocol = std::fs::read_to_string(spec("PROTOCOL.md"))?;
    let factoring = section(
        &protocol,
        "The receivables-factoring contract registers",
        "Verified-outcome pricing registers",
    )?;
    let signed = section(
        factoring,
        "six signed artifact schemas:",
        "Their registry kinds",
    )?;
    let unsigned = section(
        factoring,
        "The following factoring schemas are unsigned canonical projections:",
        "They become evidence only",
    )?;

    assert_eq!(schema_bullets(signed), SIGNED_SCHEMAS.into_iter().collect());
    assert_eq!(
        schema_bullets(unsigned),
        UNSIGNED_SCHEMAS.into_iter().collect()
    );
    assert!(factoring.contains("MUST reject every unknown schema version"));
    assert!(factoring.contains("MUST NOT downgrade, reinterpret, or fall back"));
    for schema in [
        "chio.credit.iou-envelope.v1",
        "chio.credit.iou-envelope.v9",
        "chio.factor.assignment-agreement.v9",
    ] {
        assert!(!schema_bullets(signed).contains(schema));
    }
    Ok(())
}

#[test]
fn financial_ladder_pins_governed_actions_and_refuses_unknown_classes() -> TestResult {
    let path = spec("CHIO_LADDER.md");
    let ladder = std::fs::read_to_string(&path)?;
    let schema = ladder_json(
        &ladder,
        "$id",
        "chio.federation.governance-ladder-manifest.v1",
    )?;
    let mut manifest = ladder_json(
        &ladder,
        "manifest_id",
        "treasury.financial.ladder.2026-05-04",
    )?;
    let actions = manifest["action_classes"]
        .as_array()
        .ok_or_else(|| io::Error::other("financial ladder action_classes must be an array"))?;
    let matches: Vec<_> = actions
        .iter()
        .filter(|action| action["id"] == "factor.assignment_bind")
        .collect();
    let expected = json!({
        "id": "factor.assignment_bind",
        "title": "Receivable assignment binding",
        "mode": "receipt_backed",
        "destructive": true,
        "cross_org_visibility": "federated",
        "evidence_required": ["trust_activation", "workflow_receipt"],
        "co_sign": "bilateral_required",
        "consistency_model": "totally-ordered",
        "consistency_anchor": "hash-chain"
    });
    let refusal = json!("refuse");
    assert_eq!(matches, vec![&expected]);
    let fiscal_matches: Vec<_> = actions
        .iter()
        .filter(|action| action["id"] == "fiscal.amendment_activate")
        .collect();
    let expected_fiscal = json!({
        "id": "fiscal.amendment_activate",
        "title": "Fiscal amendment activation",
        "mode": "receipt_backed",
        "destructive": true,
        "cross_org_visibility": "private",
        "evidence_required": ["operator_report", "workflow_receipt", "external"],
        "co_sign": "none",
        "consistency_model": "totally-ordered",
        "consistency_anchor": "external-checkpoint"
    });
    assert_eq!(fiscal_matches, vec![&expected_fiscal]);
    assert_eq!(
        manifest.pointer("/ladder_refusal_policy/on_unknown_class"),
        Some(&refusal)
    );
    assert!(actions
        .iter()
        .all(|action| action["id"] != "factor.assignment_bind.v9"));

    manifest["signature"] = json!({
        "signer_key": "00",
        "alg": "ed25519",
        "value": "00"
    });
    chio_spec_validate::validate_value(&path, &schema, &path, &manifest)?;

    manifest["schema"] = json!("chio.federation.governance-ladder-manifest.v9");
    assert!(chio_spec_validate::validate_value(&path, &schema, &path, &manifest).is_err());
    Ok(())
}
