//! Eval-report bundle verification.
//!
//! The P3 verifier validates the bundle envelope, verifies local fixture
//! signatures, and checks every preserved receipt payload hash. Real cosign
//! and PGP verification stay fail-closed until the release lane supplies
//! external verifier tooling.

use serde_json::{Map, Value};

use crate::export::{sha256_hex, VERDICT_MATRIX_CORPUS_SHA256, VERDICT_MATRIX_SCENARIO_COUNT};
use crate::BUNDLE_SCHEMA_ID;

/// Successful bundle verification summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBundle {
    pub bundle_id: String,
    pub receipt_count: usize,
    pub signature_count: usize,
    pub corpus_sha256: String,
}

/// Fail-closed verifier errors.
#[derive(Debug)]
pub enum BundleError {
    Json(String),
    MissingField(&'static str),
    WrongType(&'static str),
    SchemaMismatch(String),
    CorpusMismatch(String),
    EmptyReceipts,
    EmptySignatures,
    UnsupportedSignatureKind(String),
    InvalidSignature(String),
    ReceiptHashMismatch(String),
    InvalidPartnerReview(String),
    Canonicalization(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(err) => write!(formatter, "invalid bundle json: {err}"),
            Self::MissingField(field) => write!(formatter, "missing bundle field: {field}"),
            Self::WrongType(field) => write!(formatter, "wrong bundle field type: {field}"),
            Self::SchemaMismatch(schema) => write!(formatter, "unsupported schema: {schema}"),
            Self::CorpusMismatch(detail) => write!(formatter, "corpus mismatch: {detail}"),
            Self::EmptyReceipts => write!(formatter, "bundle has no receipts"),
            Self::EmptySignatures => write!(formatter, "bundle has no signatures"),
            Self::UnsupportedSignatureKind(kind) => {
                write!(formatter, "unsupported signature kind: {kind}")
            }
            Self::InvalidSignature(key_id) => write!(formatter, "invalid signature for {key_id}"),
            Self::ReceiptHashMismatch(scenario_id) => {
                write!(formatter, "receipt hash mismatch for {scenario_id}")
            }
            Self::InvalidPartnerReview(detail) => {
                write!(formatter, "invalid partner review: {detail}")
            }
            Self::Canonicalization(err) => write!(formatter, "canonicalization failed: {err}"),
        }
    }
}

impl std::error::Error for BundleError {}

/// Verify an eval-report bundle JSON document.
pub fn verify_bundle(bundle_json: &str) -> Result<VerifiedBundle, BundleError> {
    let value: Value =
        serde_json::from_str(bundle_json).map_err(|err| BundleError::Json(err.to_string()))?;
    let object = value
        .as_object()
        .ok_or(BundleError::WrongType("bundle root"))?;

    let schema = str_field(object, "schema")?;
    if schema != BUNDLE_SCHEMA_ID {
        return Err(BundleError::SchemaMismatch(schema.to_owned()));
    }

    let bundle_id = str_field(object, "bundle_id")?.to_owned();
    verify_corpus(object)?;
    verify_receipts(object)?;
    verify_partner_review(object)?;
    verify_signatures(&value)?;

    let receipt_count = array_field(object, "receipts")?.len();
    let signature_count = array_field(object, "signatures")?.len();

    Ok(VerifiedBundle {
        bundle_id,
        receipt_count,
        signature_count,
        corpus_sha256: VERDICT_MATRIX_CORPUS_SHA256.to_owned(),
    })
}

fn verify_corpus(object: &Map<String, Value>) -> Result<(), BundleError> {
    let corpus = object_field(object, "corpus")?;
    let corpus_sha256 = str_field(corpus, "corpus_sha256")?;
    if corpus_sha256 != VERDICT_MATRIX_CORPUS_SHA256 {
        return Err(BundleError::CorpusMismatch(format!(
            "expected {VERDICT_MATRIX_CORPUS_SHA256}, got {corpus_sha256}"
        )));
    }

    let scenario_count = number_field(corpus, "scenario_count")?;
    if scenario_count != u64::from(VERDICT_MATRIX_SCENARIO_COUNT) {
        return Err(BundleError::CorpusMismatch(format!(
            "expected {VERDICT_MATRIX_SCENARIO_COUNT} scenarios, got {scenario_count}"
        )));
    }
    Ok(())
}

fn verify_receipts(object: &Map<String, Value>) -> Result<(), BundleError> {
    let receipts = array_field(object, "receipts")?;
    if receipts.is_empty() {
        return Err(BundleError::EmptyReceipts);
    }

    for receipt in receipts {
        let receipt_object = receipt
            .as_object()
            .ok_or(BundleError::WrongType("receipts[]"))?;
        let scenario_id = str_field(receipt_object, "scenario_id")?;
        let payload = str_field(receipt_object, "receipt_payload")?;
        let expected_hash = str_field(receipt_object, "receipt_sha256")?;
        let actual_hash = sha256_hex(payload.as_bytes());
        if actual_hash != expected_hash {
            return Err(BundleError::ReceiptHashMismatch(scenario_id.to_owned()));
        }
    }
    Ok(())
}

fn verify_partner_review(object: &Map<String, Value>) -> Result<(), BundleError> {
    let Some(value) = object.get("partner_review") else {
        return Ok(());
    };
    let review = value
        .as_object()
        .ok_or(BundleError::WrongType("partner_review"))?;
    str_field(review, "feedback_ref")?;
    str_field(review, "reviewer_role")?;
    let review_window_days = number_field(review, "review_window_days")?;
    if !(1..=7).contains(&review_window_days) {
        return Err(BundleError::InvalidPartnerReview(format!(
            "review_window_days must be 1-7, got {review_window_days}"
        )));
    }
    match str_field(review, "disposition")? {
        "accepted" | "accepted-with-notes" | "no-format-change" => Ok(()),
        other => Err(BundleError::InvalidPartnerReview(format!(
            "unsupported disposition {other}"
        ))),
    }
}

fn verify_signatures(value: &Value) -> Result<(), BundleError> {
    let object = value
        .as_object()
        .ok_or(BundleError::WrongType("bundle root"))?;
    let signatures = array_field(object, "signatures")?;
    if signatures.is_empty() {
        return Err(BundleError::EmptySignatures);
    }

    let canonical_payload = canonical_payload_without_signatures(value)?;
    let expected_signature = sha256_hex(canonical_payload.as_bytes());

    for signature in signatures {
        let signature_object = signature
            .as_object()
            .ok_or(BundleError::WrongType("signatures[]"))?;
        let kind = str_field(signature_object, "kind")?;
        let key_id = str_field(signature_object, "key_id")?;
        let signature_value = str_field(signature_object, "signature")?;
        let signed_payload = str_field(signature_object, "signed_payload")?;
        if signed_payload != "bundle_without_signatures:rfc8785" {
            return Err(BundleError::InvalidSignature(key_id.to_owned()));
        }
        match kind {
            "test-sha256" => {
                if signature_value != expected_signature {
                    return Err(BundleError::InvalidSignature(key_id.to_owned()));
                }
            }
            other => return Err(BundleError::UnsupportedSignatureKind(other.to_owned())),
        }
    }
    Ok(())
}

/// Return the deterministic local fixture signature for a bundle JSON value.
pub fn test_signature_for_bundle_json(bundle_json: &str) -> Result<String, BundleError> {
    let value: Value =
        serde_json::from_str(bundle_json).map_err(|err| BundleError::Json(err.to_string()))?;
    let canonical_payload = canonical_payload_without_signatures(&value)?;
    Ok(sha256_hex(canonical_payload.as_bytes()))
}

fn canonical_payload_without_signatures(value: &Value) -> Result<String, BundleError> {
    let mut payload = value.clone();
    let object = payload
        .as_object_mut()
        .ok_or(BundleError::WrongType("bundle root"))?;
    object.remove("signatures");
    canonicalize_json(&payload)
}

fn canonicalize_json(value: &Value) -> Result<String, BundleError> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(v) => Ok(if *v { "true" } else { "false" }.to_owned()),
        Value::Number(v) => Ok(v.to_string()),
        Value::String(v) => {
            serde_json::to_string(v).map_err(|err| BundleError::Canonicalization(err.to_string()))
        }
        Value::Array(values) => {
            let mut output = String::from("[");
            let mut first = true;
            for item in values {
                if first {
                    first = false;
                } else {
                    output.push(',');
                }
                output.push_str(&canonicalize_json(item)?);
            }
            output.push(']');
            Ok(output)
        }
        Value::Object(values) => {
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort();
            let mut output = String::from("{");
            let mut first = true;
            for key in keys {
                if first {
                    first = false;
                } else {
                    output.push(',');
                }
                let key_json = serde_json::to_string(key)
                    .map_err(|err| BundleError::Canonicalization(err.to_string()))?;
                output.push_str(&key_json);
                output.push(':');
                let value = values.get(key).ok_or(BundleError::Canonicalization(
                    "missing sorted key".to_owned(),
                ))?;
                output.push_str(&canonicalize_json(value)?);
            }
            output.push('}');
            Ok(output)
        }
    }
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Map<String, Value>, BundleError> {
    object
        .get(field)
        .ok_or(BundleError::MissingField(field))?
        .as_object()
        .ok_or(BundleError::WrongType(field))
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Vec<Value>, BundleError> {
    object
        .get(field)
        .ok_or(BundleError::MissingField(field))?
        .as_array()
        .ok_or(BundleError::WrongType(field))
}

fn str_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, BundleError> {
    object
        .get(field)
        .ok_or(BundleError::MissingField(field))?
        .as_str()
        .ok_or(BundleError::WrongType(field))
}

fn number_field(object: &Map<String, Value>, field: &'static str) -> Result<u64, BundleError> {
    object
        .get(field)
        .ok_or(BundleError::MissingField(field))?
        .as_u64()
        .ok_or(BundleError::WrongType(field))
}

#[cfg(test)]
mod tests {
    use super::{test_signature_for_bundle_json, verify_bundle, BundleError};
    use crate::export::{
        export_scenario_run, EvalRunMeta, EvalRunMetaParts, Receipt, ReceiptParts,
    };

    #[test]
    fn verifies_local_test_signature_and_receipt_hash() -> Result<(), BundleError> {
        let unsigned = unsigned_bundle_json()?;
        let signature = test_signature_for_bundle_json(&unsigned)?;
        let signed = unsigned.replace("\"SIGNATURE_PLACEHOLDER\"", &format!("\"{signature}\""));

        let verified = verify_bundle(&signed)?;

        assert_eq!(verified.bundle_id, "urn:chio:eval-bundle:verify-test");
        assert_eq!(verified.receipt_count, 1);
        assert_eq!(verified.signature_count, 1);
        Ok(())
    }

    #[test]
    fn rejects_unsupported_signature_kind() -> Result<(), BundleError> {
        let unsigned = unsigned_bundle_json()?;
        let signature = test_signature_for_bundle_json(&unsigned)?;
        let signed = unsigned
            .replace("\"SIGNATURE_PLACEHOLDER\"", &format!("\"{signature}\""))
            .replace("\"test-sha256\"", "\"sigstore-cosign\"");

        let err = verify_bundle(&signed).err();

        assert!(matches!(
            err,
            Some(BundleError::UnsupportedSignatureKind(kind)) if kind == "sigstore-cosign"
        ));
        Ok(())
    }

    #[test]
    fn rejects_partner_review_outside_d15_window() -> Result<(), BundleError> {
        let unsigned = unsigned_bundle_json()?;
        let signature = test_signature_for_bundle_json(&unsigned)?;
        let signed = unsigned
            .replace("\"SIGNATURE_PLACEHOLDER\"", &format!("\"{signature}\""))
            .replace("\"review_window_days\": 7", "\"review_window_days\": 30");

        let err = verify_bundle(&signed).err();

        assert!(matches!(
            err,
            Some(BundleError::InvalidPartnerReview(detail))
                if detail.contains("review_window_days")
        ));
        Ok(())
    }

    fn unsigned_bundle_json() -> Result<String, BundleError> {
        let receipt = Receipt::from_parts(ReceiptParts {
            scenario_id: "capability-subset-001-read-exact",
            category: "capability_subset",
            verdict: "allow",
            receipt_payload: "{\"scenario_id\":\"capability-subset-001-read-exact\"}",
            trace_id: "trace-001",
            sample_id: "sample-001",
        })
        .map_err(|err| BundleError::Canonicalization(err.to_string()))?;
        let meta = EvalRunMeta::from_parts(EvalRunMetaParts {
            bundle_id: "urn:chio:eval-bundle:verify-test",
            created_at: "2026-05-02T00:00:00Z",
            producer_commit: "verify-test",
            workflow_run_url: "local",
            run_id: "verify-test",
            partner: "METR",
            partner_slug: "metr",
            pipeline: "vivaria-trace-postprocess",
            pipeline_language: "python",
            model_under_eval: "partner-model",
            scorer_name: "tool-use-rubric",
            scorer_version: "v1",
        })
        .map_err(|err| BundleError::Canonicalization(err.to_string()))?;
        let bundle = export_scenario_run(&[receipt], meta);
        let entry = &bundle.receipts[0];
        Ok(format!(
            r#"{{
  "schema": "chio.eval-report.bundle.v1",
  "bundle_id": "{}",
  "created_at": "{}",
  "producer": {{
    "name": "{}",
    "repository": "{}",
    "commit": "{}",
    "workflow_run_url": "{}"
  }},
  "eval_run": {{
    "run_id": "{}",
    "partner": "{}",
    "partner_slug": "{}",
    "pipeline": "{}",
    "pipeline_language": "{}",
    "model_under_eval": "{}",
    "scorer_name": "{}",
    "scorer_version": "{}"
  }},
  "corpus": {{
    "name": "{}",
    "scenario_count": {},
    "corpus_sha256": "{}",
    "manifest_path": "{}"
  }},
  "receipts": [
    {{
      "scenario_id": "{}",
      "category": "{}",
      "verdict": "{}",
      "receipt_payload": {},
      "receipt_sha256": "{}",
      "evidence": {{
        "trace_id": "{}",
        "sample_id": "{}"
      }}
    }}
  ],
  "partner_review": {{
    "feedback_ref": "M02.P4 METR pair-run 2026-05-02",
    "review_window_days": 7,
    "reviewer_role": "partner technical reviewer",
    "disposition": "accepted-with-notes"
  }},
  "signatures": [
    {{
      "kind": "test-sha256",
      "key_id": "local-test",
      "signature": "SIGNATURE_PLACEHOLDER",
      "signed_payload": "bundle_without_signatures:rfc8785"
    }}
  ]
}}"#,
            bundle.bundle_id,
            bundle.created_at,
            bundle.producer.name,
            bundle.producer.repository,
            bundle.producer.commit,
            bundle.producer.workflow_run_url,
            bundle.eval_run.run_id,
            bundle.eval_run.partner,
            bundle.eval_run.partner_slug,
            bundle.eval_run.pipeline,
            bundle.eval_run.pipeline_language,
            bundle.eval_run.model_under_eval,
            bundle.eval_run.scorer_name,
            bundle.eval_run.scorer_version,
            bundle.corpus.name,
            bundle.corpus.scenario_count,
            bundle.corpus.corpus_sha256,
            bundle.corpus.manifest_path,
            entry.scenario_id,
            entry.category,
            entry.verdict,
            serde_json::to_string(&entry.receipt_payload)
                .map_err(|err| BundleError::Canonicalization(err.to_string()))?,
            entry.receipt_sha256,
            entry.evidence.trace_id,
            entry.evidence.sample_id
        ))
    }
}
