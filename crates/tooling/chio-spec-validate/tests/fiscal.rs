use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FISCAL_FIXTURES: [(&str, bool); 9] = [
    ("activation", true),
    ("approval", true),
    ("charter", true),
    ("consumer-readiness", true),
    ("continuity-checkpoint", true),
    ("genesis-policy", false),
    ("proposal-admission", true),
    ("proposal", true),
    ("schedule", true),
];

fn fiscal_schema_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/schemas/chio-fiscal/v1")
}

fn fiscal_paths(name: &str) -> (PathBuf, PathBuf) {
    let root = fiscal_schema_root();
    (
        root.join(format!("{name}.schema.json")),
        root.join(format!("fixtures/{name}.positive.json")),
    )
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn object_mut<'a>(value: &'a mut Value, label: &str) -> TestResult<&'a mut Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| io::Error::other(format!("{label} must be an object")).into())
}

fn unsupported_schema(body: &Map<String, Value>) -> TestResult<String> {
    let schema = body
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("fiscal fixture body must name its schema"))?;
    let prefix = schema
        .strip_suffix(".v1")
        .ok_or_else(|| io::Error::other("fiscal fixture schema must end in .v1"))?;
    Ok(format!("{prefix}.v2"))
}

fn tampered_signature(signature: &str) -> TestResult<String> {
    let last = signature
        .as_bytes()
        .last()
        .copied()
        .ok_or_else(|| io::Error::other("fiscal signature must not be empty"))?;
    let mut tampered = signature.to_owned();
    let last_index = tampered.len() - 1;
    tampered.replace_range(last_index.., if last == b'0' { "1" } else { "0" });
    Ok(tampered)
}

#[test]
fn fiscal_positive_fixtures_validate_against_published_schemas() -> TestResult {
    for (name, _) in FISCAL_FIXTURES {
        let (schema_path, fixture_path) = fiscal_paths(name);
        chio_spec_validate::validate(&schema_path, &fixture_path)?;
    }
    Ok(())
}

#[test]
fn fiscal_schemas_reject_unknown_versions_and_fields() -> TestResult {
    for (name, signed) in FISCAL_FIXTURES {
        let (schema_path, fixture_path) = fiscal_paths(name);
        let schema = read_json(&schema_path)?;

        let mut wrong_version = read_json(&fixture_path)?;
        let body = if signed {
            wrong_version
                .get_mut("body")
                .ok_or_else(|| io::Error::other("signed fiscal fixture must have a body"))?
        } else {
            &mut wrong_version
        };
        let body = object_mut(body, "fiscal fixture body")?;
        let schema_version = unsupported_schema(body)?;
        body.insert("schema".to_owned(), schema_version.into());
        assert!(
            chio_spec_validate::validate_value(
                &schema_path,
                &schema,
                &fixture_path,
                &wrong_version,
            )
            .is_err(),
            "{name} accepted an unsupported schema version"
        );

        let mut unknown_field = read_json(&fixture_path)?;
        object_mut(&mut unknown_field, "fiscal fixture")?
            .insert("unexpectedFiscalField".to_owned(), Value::Bool(true));
        assert!(
            chio_spec_validate::validate_value(
                &schema_path,
                &schema,
                &fixture_path,
                &unknown_field,
            )
            .is_err(),
            "{name} accepted an unknown root field"
        );
    }
    Ok(())
}

#[test]
fn fiscal_schema_validation_and_signature_verification_are_separate_gates() -> TestResult {
    for (name, signed) in FISCAL_FIXTURES {
        if !signed {
            continue;
        }
        let (schema_path, fixture_path) = fiscal_paths(name);
        let schema = read_json(&schema_path)?;
        let mut fixture = read_json(&fixture_path)?;
        let envelope = object_mut(&mut fixture, "signed fiscal fixture")?;
        let signature = envelope
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("signed fiscal fixture must have a signature"))?;
        let signature = tampered_signature(signature)?;
        envelope.insert("signature".to_owned(), signature.into());
        chio_spec_validate::validate_value(&schema_path, &schema, &fixture_path, &fixture)?;
    }
    Ok(())
}
