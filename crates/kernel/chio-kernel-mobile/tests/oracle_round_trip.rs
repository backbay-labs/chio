use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_kernel_mobile::sign_receipt_relaying_trusted_body;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
struct ReceiptFixture {
    platform: String,
    receipt_id: String,
    tenant_id: String,
    capability_id: String,
    tool_server: String,
    tool_name: String,
    actor_subject: String,
    timestamp_unix: u64,
    timestamp_iso: String,
    content_hash: String,
    policy_hash: String,
    guard_id: String,
    reason_code: String,
    checkpoint_id: String,
    kernel_seed_hex: String,
}

#[test]
fn ios_and_android_signed_receipts_round_trip_to_hosted_oracle() -> Result<(), Box<dyn Error>> {
    let fixture_dir = fixture_dir();
    let oracle_endpoint = load_oracle_endpoint(&fixture_dir.join("hosted-oracle.json"))?;
    let schema = load_json(&repo_root().join("spec/audit-log/export-schema.v1.json"))?;

    let mut accepted_platforms = BTreeSet::new();
    for fixture_name in ["ios-signed-receipt.json", "android-signed-receipt.json"] {
        let fixture: ReceiptFixture =
            serde_json::from_value(load_json(&fixture_dir.join(fixture_name))?)?;
        let receipt = sign_fixture_receipt(&fixture)?;
        let export_record = export_record_from_receipt(&fixture, &receipt);

        validate_export_schema_acceptance(&schema, &export_record)?;
        if !hosted_oracle_accepts(&oracle_endpoint, &receipt, &export_record)? {
            return Err(invalid_data("hosted oracle rejected mobile receipt").into());
        }
        accepted_platforms.insert(fixture.platform);
    }

    let expected = BTreeSet::from(["android".to_string(), "ios".to_string()]);
    assert_eq!(accepted_platforms, expected);
    Ok(())
}

fn sign_fixture_receipt(fixture: &ReceiptFixture) -> Result<ChioReceipt, Box<dyn Error>> {
    let keypair = Keypair::from_seed_hex(&fixture.kernel_seed_hex)?;
    let action = ToolCallAction::from_parameters(json!({
        "actor_subject": fixture.actor_subject,
        "mobile_platform": fixture.platform,
        "oracle_endpoint": "hosted-oracle-fixture",
    }))?;
    let body = ChioReceiptBody {
        id: fixture.receipt_id.clone(),
        timestamp: fixture.timestamp_unix,
        capability_id: fixture.capability_id.clone(),
        tool_server: fixture.tool_server.clone(),
        tool_name: fixture.tool_name.clone(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: fixture.content_hash.clone(),
        policy_hash: fixture.policy_hash.clone(),
        evidence: vec![],
        metadata: Some(json!({
            "actor_subject": fixture.actor_subject,
            "mobile_platform": fixture.platform,
        })),
        trust_level: TrustLevel::Mediated,
        tenant_id: Some(fixture.tenant_id.clone()),
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };

    // The oracle fixtures carry only `content_hash`, not the content preimage,
    // so they model the trusted-upstream-body relay seam (BAC-601). Route
    // through the explicit relay signer rather than the public WYSIWYS signer.
    let signed_json = sign_receipt_relaying_trusted_body(
        serde_json::to_string(&body)?,
        fixture.kernel_seed_hex.clone(),
    )?;
    let receipt: ChioReceipt = serde_json::from_str(&signed_json)?;
    if !receipt.verify_signature()? {
        return Err(invalid_data("mobile receipt signature did not verify").into());
    }
    if receipt.kernel_key != keypair.public_key() {
        return Err(invalid_data("receipt kernel key does not match attested key").into());
    }
    Ok(receipt)
}

fn export_record_from_receipt(fixture: &ReceiptFixture, receipt: &ChioReceipt) -> Value {
    json!({
        "schema_version": "chio.audit-log.export.v1",
        "receipt_id": receipt.id,
        "tenant_id": receipt.tenant_id.as_deref().unwrap_or("missing-tenant"),
        "capability_id": receipt.capability_id,
        "tool_id": format!("{}/{}", receipt.tool_server, receipt.tool_name),
        "decision": decision_name(&receipt.decision),
        "guard_id": fixture.guard_id,
        "reason_code": fixture.reason_code,
        "timestamp": fixture.timestamp_iso,
        "actor_subject": fixture.actor_subject,
        "redaction_status": "clean",
        "policy_hash": receipt.policy_hash,
        "checkpoint_id": fixture.checkpoint_id,
        "ocsf": {
            "schema_version": "1.3.0",
            "category_uid": 3,
            "class_uid": 3002,
            "class_name": "Authorization",
            "activity_name": "Authorize",
            "actor": {"uid": fixture.actor_subject},
            "resource": {"uid": receipt.capability_id},
        },
        "cef": {
            "version": "CEF:0",
            "device_vendor": "Backbay Labs",
            "device_product": "Chio",
            "signature_id": fixture.reason_code,
            "name": "Mobile receipt oracle verification",
            "severity": 3,
            "extension": {
                "rt": fixture.timestamp_iso,
                "msg": format!("{} mobile receipt accepted", fixture.platform),
                "cs1Label": "tenant_id",
                "cs1": fixture.tenant_id,
                "cs2Label": "receipt_id",
                "cs2": receipt.id,
                "cs3Label": "capability_id",
                "cs3": receipt.capability_id,
                "cs4Label": "checkpoint_id",
                "cs4": fixture.checkpoint_id,
            },
        },
    })
}

fn hosted_oracle_accepts(
    endpoint: &str,
    receipt: &ChioReceipt,
    export_record: &Value,
) -> Result<bool, Box<dyn Error>> {
    if endpoint != "https://hosted-oracle.fixture.chio.local/audit-log/v1/receipts" {
        return Err(invalid_data("unexpected hosted oracle endpoint").into());
    }
    if !receipt.verify_signature()? {
        return Ok(false);
    }
    Ok(
        export_record.get("receipt_id").and_then(Value::as_str) == Some(receipt.id.as_str())
            && export_record.get("tenant_id").and_then(Value::as_str)
                == receipt.tenant_id.as_deref()
            && export_record.get("decision").and_then(Value::as_str) == Some("allow"),
    )
}

fn validate_export_schema_acceptance(schema: &Value, record: &Value) -> Result<(), Box<dyn Error>> {
    if schema.get("title").and_then(Value::as_str) != Some("Chio Audit Log Export Schema v1") {
        return Err(invalid_data("unexpected export schema title").into());
    }

    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("schema required array missing"))?;
    for field in required {
        let field = field
            .as_str()
            .ok_or_else(|| invalid_data("schema required field was not a string"))?;
        if record.get(field).is_none() {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("export record missing required field {field}"),
            )
            .into());
        }
    }

    require_const(schema, "schema_version", record)?;
    require_const(schema, "ocsf.schema_version", record)?;
    require_const(schema, "ocsf.category_uid", record)?;
    require_const(schema, "ocsf.class_uid", record)?;
    require_const(schema, "ocsf.class_name", record)?;
    require_const(schema, "cef.version", record)?;
    require_const(schema, "cef.device_vendor", record)?;
    require_const(schema, "cef.device_product", record)?;

    let decision = record
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data("decision missing"))?;
    let allowed = schema
        .pointer("/properties/decision/enum")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data("decision enum missing"))?
        .iter()
        .any(|value| value.as_str() == Some(decision));
    if !allowed {
        return Err(invalid_data("decision not accepted by export schema").into());
    }

    Ok(())
}

fn require_const(schema: &Value, pointer_name: &str, record: &Value) -> Result<(), Box<dyn Error>> {
    let schema_pointer = format!(
        "/properties/{}/const",
        pointer_name.replace('.', "/properties/")
    );
    let record_pointer = format!("/{}", pointer_name.replace('.', "/"));
    let expected = schema.pointer(&schema_pointer).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("missing const {pointer_name}"),
        )
    })?;
    let actual = record.pointer(&record_pointer).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            format!("missing field {pointer_name}"),
        )
    })?;
    if expected != actual {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            format!("field {pointer_name} did not match schema const"),
        )
        .into());
    }
    Ok(())
}

fn decision_name(decision: &Option<Decision>) -> &'static str {
    match decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::Deny { .. }) => "deny",
        Some(Decision::Cancelled { .. }) => "cancelled",
        Some(Decision::Incomplete { .. }) => "incomplete",
        None => "none",
    }
}

fn load_oracle_endpoint(path: &Path) -> Result<String, Box<dyn Error>> {
    let value = load_json(path)?;
    let endpoint = value
        .get("endpoint_url")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data("hosted oracle endpoint_url missing"))?;
    Ok(endpoint.to_string())
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/receipts")
}

fn invalid_data(message: &str) -> IoError {
    IoError::new(ErrorKind::InvalidData, message.to_string())
}
