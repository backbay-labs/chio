//! Eval-report bundle verification.
//!
//! The verifier validates the bundle envelope, verifies local fixture
//! signatures, and checks every preserved receipt payload hash. Real cosign
//! and PGP verification stay fail-closed until the release lane supplies
//! external verifier tooling.

use chio_core_types::receipt::body::ChioReceipt;
use serde_json::{Map, Value};

use crate::export::{sha256_hex, VERDICT_MATRIX_CORPUS_SHA256, VERDICT_MATRIX_SCENARIO_COUNT};
use crate::BUNDLE_SCHEMA_ID;

const TEST_SIGNATURE_KIND: &str = "test-sha256";

const ROOT_FIELDS: &[&str] = &[
    "schema",
    "bundle_id",
    "created_at",
    "producer",
    "eval_run",
    "corpus",
    "receipts",
    "partner_review",
    "signatures",
];
const ROOT_REQUIRED_FIELDS: &[&str] = &[
    "schema",
    "bundle_id",
    "created_at",
    "producer",
    "eval_run",
    "corpus",
    "receipts",
    "signatures",
];
const PRODUCER_FIELDS: &[&str] = &["name", "repository", "commit", "workflow_run_url"];
const EVAL_RUN_FIELDS: &[&str] = &[
    "run_id",
    "partner",
    "partner_slug",
    "pipeline",
    "pipeline_language",
    "model_under_eval",
    "scorer_name",
    "scorer_version",
];
const CORPUS_FIELDS: &[&str] = &["name", "scenario_count", "corpus_sha256", "manifest_path"];
const RECEIPT_FIELDS: &[&str] = &[
    "scenario_id",
    "category",
    "verdict",
    "receipt_payload",
    "receipt_sha256",
    "evidence",
];
const EVIDENCE_FIELDS: &[&str] = &["trace_id", "sample_id"];
const PARTNER_REVIEW_FIELDS: &[&str] = &[
    "feedback_ref",
    "review_window_days",
    "reviewer_role",
    "disposition",
];
const SIGNATURE_FIELDS: &[&str] = &[
    "kind",
    "key_id",
    "signature",
    "certificate",
    "signed_payload",
];
const SIGNATURE_REQUIRED_FIELDS: &[&str] = &["kind", "key_id", "signature", "signed_payload"];

const LOCAL_TEST_RECEIPT_FIXTURE_HASHES: &[(&str, &str)] = &[
    (
        "capability-subset-001-read-exact",
        "2667e32d83f8f7db47b316f7f188e4dcd0a7d0414767122c54a043d076acb704",
    ),
    (
        "revocation-propagation-001-active-read",
        "f6db0dec41eb7b9873a4d0a14d26f7cb42c13dcfd22e04384bf1b20da67294c2",
    ),
    (
        "replay-verdict-001-fresh-read",
        "6e52db09a03b762233c5bf01e440bd0b9009f2c38527c43654a5090e852509f2",
    ),
];

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
    InvalidReceiptPayload(String),
    InvalidReceiptSignature(String),
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
            Self::InvalidReceiptPayload(scenario_id) => {
                write!(formatter, "invalid receipt payload for {scenario_id}")
            }
            Self::InvalidReceiptSignature(scenario_id) => {
                write!(
                    formatter,
                    "invalid embedded receipt signature for {scenario_id}"
                )
            }
            Self::InvalidPartnerReview(detail) => {
                write!(formatter, "invalid partner review: {detail}")
            }
            Self::Canonicalization(err) => write!(formatter, "canonicalization failed: {err}"),
        }
    }
}

impl std::error::Error for BundleError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerificationMode {
    Production,
    Fixture,
}

/// Verify an eval-report bundle JSON document.
pub fn verify_bundle(bundle_json: &str) -> Result<VerifiedBundle, BundleError> {
    verify_bundle_with_mode(bundle_json, VerificationMode::Production)
}

/// Verify a local eval-report fixture bundle JSON document.
///
/// This mode accepts the deterministic `test-sha256` outer signature and the
/// checked-in receipt fixtures. Use [`verify_bundle`] for production inputs.
pub fn verify_fixture_bundle(bundle_json: &str) -> Result<VerifiedBundle, BundleError> {
    verify_bundle_with_mode(bundle_json, VerificationMode::Fixture)
}

fn verify_bundle_with_mode(
    bundle_json: &str,
    mode: VerificationMode,
) -> Result<VerifiedBundle, BundleError> {
    let value: Value =
        serde_json::from_str(bundle_json).map_err(|err| BundleError::Json(err.to_string()))?;
    let object = value
        .as_object()
        .ok_or(BundleError::WrongType("bundle root"))?;

    let schema = str_field(object, "schema")?;
    if schema != BUNDLE_SCHEMA_ID {
        return Err(BundleError::SchemaMismatch(schema.to_owned()));
    }
    verify_schema_envelope(object)?;

    let bundle_id = str_field(object, "bundle_id")?.to_owned();
    verify_corpus(object)?;
    verify_receipts(object, mode)?;
    verify_partner_review(object)?;
    verify_signatures(&value, mode)?;

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

fn verify_receipts(object: &Map<String, Value>, mode: VerificationMode) -> Result<(), BundleError> {
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
        verify_receipt_payload(scenario_id, payload, mode)?;
    }
    Ok(())
}

fn verify_receipt_payload(
    scenario_id: &str,
    payload: &str,
    mode: VerificationMode,
) -> Result<(), BundleError> {
    match verify_chio_receipt_payload(scenario_id, payload) {
        Ok(()) => Ok(()),
        Err(err)
            if mode == VerificationMode::Fixture
                && is_allowed_local_fixture_receipt(scenario_id, payload) =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn verify_chio_receipt_payload(scenario_id: &str, payload: &str) -> Result<(), BundleError> {
    let receipt: ChioReceipt = serde_json::from_str(payload)
        .map_err(|_| BundleError::InvalidReceiptPayload(scenario_id.to_owned()))?;
    let is_valid = receipt
        .verify_signature()
        .map_err(|_| BundleError::InvalidReceiptSignature(scenario_id.to_owned()))?;
    if is_valid {
        Ok(())
    } else {
        Err(BundleError::InvalidReceiptSignature(scenario_id.to_owned()))
    }
}

fn is_allowed_local_fixture_receipt(scenario_id: &str, payload: &str) -> bool {
    let payload_hash = sha256_hex(payload.as_bytes());
    LOCAL_TEST_RECEIPT_FIXTURE_HASHES
        .iter()
        .any(|(fixture_id, fixture_hash)| {
            *fixture_id == scenario_id && *fixture_hash == payload_hash
        })
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

fn verify_signatures(value: &Value, mode: VerificationMode) -> Result<(), BundleError> {
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
            TEST_SIGNATURE_KIND if mode == VerificationMode::Fixture => {
                if signature_value != expected_signature {
                    return Err(BundleError::InvalidSignature(key_id.to_owned()));
                }
            }
            TEST_SIGNATURE_KIND => {
                return Err(BundleError::UnsupportedSignatureKind(kind.to_owned()));
            }
            other => return Err(BundleError::UnsupportedSignatureKind(other.to_owned())),
        }
    }
    Ok(())
}

fn verify_schema_envelope(object: &Map<String, Value>) -> Result<(), BundleError> {
    verify_allowed_fields("bundle root", object, ROOT_FIELDS)?;
    verify_required_fields(object, ROOT_REQUIRED_FIELDS)?;
    non_empty_str_field(object, "bundle_id", "bundle root.bundle_id")?;
    non_empty_str_field(object, "created_at", "bundle root.created_at")?;
    verify_producer_shape(object_field(object, "producer")?)?;
    verify_eval_run_shape(object_field(object, "eval_run")?)?;
    verify_corpus_shape(object_field(object, "corpus")?)?;
    verify_receipts_shape(array_field(object, "receipts")?)?;
    if let Some(partner_review) = object.get("partner_review") {
        let partner_review = partner_review
            .as_object()
            .ok_or(BundleError::WrongType("partner_review"))?;
        verify_partner_review_shape(partner_review)?;
    }
    verify_signatures_shape(array_field(object, "signatures")?)
}

fn verify_producer_shape(producer: &Map<String, Value>) -> Result<(), BundleError> {
    verify_allowed_fields("producer", producer, PRODUCER_FIELDS)?;
    verify_required_fields(producer, PRODUCER_FIELDS)?;
    for &field in PRODUCER_FIELDS {
        non_empty_str_field(producer, field, prefixed_field("producer", field))?;
    }
    Ok(())
}

fn verify_eval_run_shape(eval_run: &Map<String, Value>) -> Result<(), BundleError> {
    verify_allowed_fields("eval_run", eval_run, EVAL_RUN_FIELDS)?;
    verify_required_fields(eval_run, EVAL_RUN_FIELDS)?;
    for &field in EVAL_RUN_FIELDS {
        non_empty_str_field(eval_run, field, prefixed_field("eval_run", field))?;
    }
    enum_str_field(
        eval_run,
        "pipeline_language",
        "eval_run.pipeline_language",
        &["python", "go", "rust"],
    )?;
    Ok(())
}

fn verify_corpus_shape(corpus: &Map<String, Value>) -> Result<(), BundleError> {
    verify_allowed_fields("corpus", corpus, CORPUS_FIELDS)?;
    verify_required_fields(corpus, CORPUS_FIELDS)?;
    non_empty_str_field(corpus, "name", "corpus.name")?;
    number_field(corpus, "scenario_count")?;
    sha256_field(corpus, "corpus_sha256", "corpus.corpus_sha256")?;
    non_empty_str_field(corpus, "manifest_path", "corpus.manifest_path")?;
    Ok(())
}

fn verify_receipts_shape(receipts: &[Value]) -> Result<(), BundleError> {
    if receipts.is_empty() {
        return Err(BundleError::EmptyReceipts);
    }
    for receipt in receipts {
        let receipt = receipt
            .as_object()
            .ok_or(BundleError::WrongType("receipts[]"))?;
        verify_allowed_fields("receipts[]", receipt, RECEIPT_FIELDS)?;
        verify_required_fields(receipt, RECEIPT_FIELDS)?;
        non_empty_str_field(receipt, "scenario_id", "receipts[].scenario_id")?;
        non_empty_str_field(receipt, "category", "receipts[].category")?;
        enum_str_field(receipt, "verdict", "receipts[].verdict", &["allow", "deny"])?;
        non_empty_str_field(receipt, "receipt_payload", "receipts[].receipt_payload")?;
        sha256_field(receipt, "receipt_sha256", "receipts[].receipt_sha256")?;
        let evidence = object_field(receipt, "evidence")?;
        verify_allowed_fields("receipts[].evidence", evidence, EVIDENCE_FIELDS)?;
        verify_required_fields(evidence, EVIDENCE_FIELDS)?;
        non_empty_str_field(evidence, "trace_id", "receipts[].evidence.trace_id")?;
        non_empty_str_field(evidence, "sample_id", "receipts[].evidence.sample_id")?;
    }
    Ok(())
}

fn verify_partner_review_shape(review: &Map<String, Value>) -> Result<(), BundleError> {
    verify_allowed_fields("partner_review", review, PARTNER_REVIEW_FIELDS)?;
    verify_required_fields(review, PARTNER_REVIEW_FIELDS)?;
    non_empty_str_field(review, "feedback_ref", "partner_review.feedback_ref")?;
    number_field(review, "review_window_days")?;
    non_empty_str_field(review, "reviewer_role", "partner_review.reviewer_role")?;
    enum_str_field(
        review,
        "disposition",
        "partner_review.disposition",
        &["accepted", "accepted-with-notes", "no-format-change"],
    )?;
    Ok(())
}

fn verify_signatures_shape(signatures: &[Value]) -> Result<(), BundleError> {
    if signatures.is_empty() {
        return Err(BundleError::EmptySignatures);
    }
    for signature in signatures {
        let signature = signature
            .as_object()
            .ok_or(BundleError::WrongType("signatures[]"))?;
        verify_allowed_fields("signatures[]", signature, SIGNATURE_FIELDS)?;
        verify_required_fields(signature, SIGNATURE_REQUIRED_FIELDS)?;
        non_empty_str_field(signature, "kind", "signatures[].kind")?;
        non_empty_str_field(signature, "key_id", "signatures[].key_id")?;
        non_empty_str_field(signature, "signature", "signatures[].signature")?;
        non_empty_str_field(signature, "signed_payload", "signatures[].signed_payload")?;
        if signature.get("certificate").is_some() {
            str_field(signature, "certificate")?;
        }
    }
    Ok(())
}

fn verify_allowed_fields(
    context: &'static str,
    object: &Map<String, Value>,
    allowed: &[&str],
) -> Result<(), BundleError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(BundleError::SchemaMismatch(format!(
                "unexpected field in {context}: {key}"
            )));
        }
    }
    Ok(())
}

fn verify_required_fields(
    object: &Map<String, Value>,
    required: &[&'static str],
) -> Result<(), BundleError> {
    for field in required {
        if !object.contains_key(*field) {
            return Err(BundleError::MissingField(field));
        }
    }
    Ok(())
}

fn non_empty_str_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
    context: &'static str,
) -> Result<&'a str, BundleError> {
    let value = str_field(object, field)?;
    if value.trim().is_empty() {
        Err(BundleError::SchemaMismatch(format!(
            "{context} must not be empty"
        )))
    } else {
        Ok(value)
    }
}

fn enum_str_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
    context: &'static str,
    allowed: &[&str],
) -> Result<&'a str, BundleError> {
    let value = non_empty_str_field(object, field, context)?;
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(BundleError::SchemaMismatch(format!(
            "{context} has unsupported value {value}"
        )))
    }
}

fn sha256_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
    context: &'static str,
) -> Result<&'a str, BundleError> {
    let value = non_empty_str_field(object, field, context)?;
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value)
    } else {
        Err(BundleError::SchemaMismatch(format!(
            "{context} must be lowercase SHA-256 hex"
        )))
    }
}

fn prefixed_field(prefix: &'static str, field: &'static str) -> &'static str {
    match (prefix, field) {
        ("producer", "name") => "producer.name",
        ("producer", "repository") => "producer.repository",
        ("producer", "commit") => "producer.commit",
        ("producer", "workflow_run_url") => "producer.workflow_run_url",
        ("eval_run", "run_id") => "eval_run.run_id",
        ("eval_run", "partner") => "eval_run.partner",
        ("eval_run", "partner_slug") => "eval_run.partner_slug",
        ("eval_run", "pipeline") => "eval_run.pipeline",
        ("eval_run", "pipeline_language") => "eval_run.pipeline_language",
        ("eval_run", "model_under_eval") => "eval_run.model_under_eval",
        ("eval_run", "scorer_name") => "eval_run.scorer_name",
        ("eval_run", "scorer_version") => "eval_run.scorer_version",
        _ => field,
    }
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
    chio_core_types::canonicalize(&payload)
        .map_err(|err| BundleError::Canonicalization(err.to_string()))
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
    use super::{
        canonical_payload_without_signatures, test_signature_for_bundle_json, verify_bundle,
        verify_fixture_bundle, BundleError,
    };
    use crate::export::{
        export_scenario_run, EvalRunMeta, EvalRunMetaParts, Receipt, ReceiptParts,
    };
    use chio_core_types::crypto::Keypair;
    use chio_core_types::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        kinds::TrustLevel,
    };
    use serde_json::{json, Value};

    #[test]
    fn bundle_signature_payload_uses_core_rfc8785_canonicalization() -> Result<(), BundleError> {
        let bundle = json!({
            "signatures": [{"signature": "ignored"}],
            "bundle_id": "urn:chio:eval-bundle:unicode-order",
            "\u{e000}": 1,
            "\u{10437}": 2,
        });
        let mut expected = bundle.clone();
        expected
            .as_object_mut()
            .ok_or(BundleError::WrongType("bundle root"))?
            .remove("signatures");

        let canonical = canonical_payload_without_signatures(&bundle)?;
        let expected = chio_core_types::canonicalize(&expected)
            .map_err(|err| BundleError::Canonicalization(err.to_string()))?;

        assert_eq!(canonical, expected);
        let supplementary = canonical
            .find('\u{10437}')
            .ok_or(BundleError::Canonicalization(
                "missing supplementary key".to_owned(),
            ))?;
        let private_use = canonical
            .find('\u{e000}')
            .ok_or(BundleError::Canonicalization(
                "missing private-use key".to_owned(),
            ))?;
        assert!(supplementary < private_use);
        Ok(())
    }

    #[test]
    fn verifies_local_test_signature_and_receipt_hash() -> Result<(), BundleError> {
        let unsigned = unsigned_bundle_json()?;
        let signature = test_signature_for_bundle_json(&unsigned)?;
        let signed = unsigned.replace("\"SIGNATURE_PLACEHOLDER\"", &format!("\"{signature}\""));

        let verified = verify_fixture_bundle(&signed)?;

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

        let err = verify_fixture_bundle(&signed).err();

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

        let err = verify_fixture_bundle(&signed).err();

        assert!(matches!(
            err,
            Some(BundleError::InvalidPartnerReview(detail))
                if detail.contains("review_window_days")
        ));
        Ok(())
    }

    #[test]
    fn rejects_schema_forbidden_root_extension() -> Result<(), BundleError> {
        let signed = signed_bundle_with_mutation(|value| {
            value
                .as_object_mut()
                .ok_or(BundleError::WrongType("bundle root"))?
                .insert(
                    "attacker_claim".to_owned(),
                    Value::String("forged".to_owned()),
                );
            Ok(())
        })?;

        let err = verify_fixture_bundle(&signed).err();

        assert!(matches!(
            err,
            Some(BundleError::SchemaMismatch(detail))
                if detail.contains("bundle root") && detail.contains("attacker_claim")
        ));
        Ok(())
    }

    #[test]
    fn rejects_schema_forbidden_evidence_extension() -> Result<(), BundleError> {
        let signed = signed_bundle_with_mutation(|value| {
            let evidence = value
                .as_object_mut()
                .ok_or(BundleError::WrongType("bundle root"))?
                .get_mut("receipts")
                .and_then(Value::as_array_mut)
                .and_then(|receipts| receipts.first_mut())
                .and_then(Value::as_object_mut)
                .and_then(|receipt| receipt.get_mut("evidence"))
                .and_then(Value::as_object_mut)
                .ok_or(BundleError::WrongType("receipts[].evidence"))?;
            evidence.insert(
                "attacker_trace_url".to_owned(),
                Value::String("https://example.invalid/trace".to_owned()),
            );
            Ok(())
        })?;

        let err = verify_fixture_bundle(&signed).err();

        assert!(matches!(
            err,
            Some(BundleError::SchemaMismatch(detail))
                if detail.contains("receipts[].evidence")
                    && detail.contains("attacker_trace_url")
        ));
        Ok(())
    }

    #[test]
    fn rejects_invalid_pipeline_language_with_recomputed_signature() -> Result<(), BundleError> {
        let signed = signed_bundle_with_mutation(|value| {
            value
                .as_object_mut()
                .ok_or(BundleError::WrongType("bundle root"))?
                .get_mut("eval_run")
                .and_then(Value::as_object_mut)
                .ok_or(BundleError::WrongType("eval_run"))?
                .insert(
                    "pipeline_language".to_owned(),
                    Value::String("bash".to_owned()),
                );
            Ok(())
        })?;

        let err = verify_fixture_bundle(&signed).err();

        assert!(matches!(
            err,
            Some(BundleError::SchemaMismatch(detail))
                if detail.contains("eval_run.pipeline_language") && detail.contains("bash")
        ));
        Ok(())
    }

    #[test]
    fn rejects_whitespace_only_required_identity_fields_with_recomputed_signature(
    ) -> Result<(), BundleError> {
        let signed = signed_bundle_with_mutation(|value| {
            value
                .as_object_mut()
                .ok_or(BundleError::WrongType("bundle root"))?
                .get_mut("producer")
                .and_then(Value::as_object_mut)
                .ok_or(BundleError::WrongType("producer"))?
                .insert("name".to_owned(), Value::String("   ".to_owned()));
            Ok(())
        })?;
        let err = verify_fixture_bundle(&signed).err();
        assert!(matches!(
            err,
            Some(BundleError::SchemaMismatch(detail)) if detail.contains("producer.name")
        ));

        let signed = signed_bundle_with_mutation(|value| {
            value
                .as_object_mut()
                .ok_or(BundleError::WrongType("bundle root"))?
                .get_mut("eval_run")
                .and_then(Value::as_object_mut)
                .ok_or(BundleError::WrongType("eval_run"))?
                .insert("run_id".to_owned(), Value::String("\t".to_owned()));
            Ok(())
        })?;
        let err = verify_fixture_bundle(&signed).err();
        assert!(matches!(
            err,
            Some(BundleError::SchemaMismatch(detail)) if detail.contains("eval_run.run_id")
        ));

        let signed = signed_bundle_with_mutation(|value| {
            value
                .as_object_mut()
                .ok_or(BundleError::WrongType("bundle root"))?
                .get_mut("receipts")
                .and_then(Value::as_array_mut)
                .and_then(|receipts| receipts.first_mut())
                .and_then(Value::as_object_mut)
                .and_then(|receipt| receipt.get_mut("evidence"))
                .and_then(Value::as_object_mut)
                .ok_or(BundleError::WrongType("receipts[].evidence"))?
                .insert("trace_id".to_owned(), Value::String("\n".to_owned()));
            Ok(())
        })?;
        let err = verify_fixture_bundle(&signed).err();
        assert!(matches!(
            err,
            Some(BundleError::SchemaMismatch(detail))
                if detail.contains("receipts[].evidence.trace_id")
        ));
        Ok(())
    }

    #[test]
    fn rejects_recomputed_test_sha256_with_forged_receipt_payload() -> Result<(), BundleError> {
        let forged_payload =
            "{\"scenario_id\":\"capability-subset-001-read-exact\",\"verdict\":\"deny\"}";
        let signed = signed_bundle_with_receipt_payload(forged_payload)?;

        assert!(
            verify_fixture_bundle(&signed).is_err(),
            "recomputed test-sha256 signatures must not verify forged receipt payloads"
        );
        Ok(())
    }

    #[test]
    fn rejects_unsigned_receipt_payload() -> Result<(), BundleError> {
        let unsigned_payload = "{\"receipt_id\":\"unsigned-receipt\"}";
        let signed = signed_bundle_with_receipt_payload(unsigned_payload)?;

        assert!(
            verify_fixture_bundle(&signed).is_err(),
            "receipt payloads without an embedded Chio signature must not verify"
        );
        Ok(())
    }

    #[test]
    fn production_verifier_rejects_local_test_signature() -> Result<(), BundleError> {
        let receipt_payload = signed_chio_receipt_payload()?;
        let signed = signed_bundle_with_receipt_payload(&receipt_payload)?;

        let err = verify_bundle(&signed).err();

        assert!(matches!(
            err,
            Some(BundleError::UnsupportedSignatureKind(kind)) if kind == "test-sha256"
        ));
        Ok(())
    }

    fn signed_chio_receipt_payload() -> Result<String, BundleError> {
        let keypair = Keypair::from_seed(&[42u8; 32]);
        let action = ToolCallAction::from_parameters(json!({
            "scenario_id": "capability-subset-001-read-exact"
        }))
        .map_err(|err| BundleError::Canonicalization(err.to_string()))?;
        let body = ChioReceiptBody {
            id: "receipt-capability-subset-001-read-exact".to_owned(),
            timestamp: 1_777_680_000,
            capability_id: "capability-subset-001-read-exact".to_owned(),
            tool_server: "eval-fixture".to_owned(),
            tool_name: "read".to_owned(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: crate::export::sha256_hex(b"capability-subset-001-read-exact"),
            policy_hash: "policy-test".to_owned(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        };
        let receipt = ChioReceipt::sign(body, &keypair)
            .map_err(|err| BundleError::Canonicalization(err.to_string()))?;
        serde_json::to_string(&receipt)
            .map_err(|err| BundleError::Canonicalization(err.to_string()))
    }

    fn signed_bundle_with_mutation(
        mutate: impl FnOnce(&mut Value) -> Result<(), BundleError>,
    ) -> Result<String, BundleError> {
        let unsigned = unsigned_bundle_json()?;
        let mut value: Value =
            serde_json::from_str(&unsigned).map_err(|err| BundleError::Json(err.to_string()))?;
        mutate(&mut value)?;
        let unsigned = serde_json::to_string_pretty(&value)
            .map_err(|err| BundleError::Canonicalization(err.to_string()))?;
        let signature = test_signature_for_bundle_json(&unsigned)?;
        Ok(unsigned.replace(
            "\"signature\": \"SIGNATURE_PLACEHOLDER\"",
            &format!("\"signature\": \"{signature}\""),
        ))
    }

    fn signed_bundle_with_receipt_payload(payload: &str) -> Result<String, BundleError> {
        let unsigned = unsigned_bundle_json()?;
        let value = bundle_with_receipt_payload(&unsigned, payload)?;
        let unsigned = serde_json::to_string_pretty(&value)
            .map_err(|err| BundleError::Canonicalization(err.to_string()))?;
        let signature = test_signature_for_bundle_json(&unsigned)?;
        Ok(unsigned.replace(
            "\"signature\": \"SIGNATURE_PLACEHOLDER\"",
            &format!("\"signature\": \"{signature}\""),
        ))
    }

    fn bundle_with_receipt_payload(bundle_json: &str, payload: &str) -> Result<Value, BundleError> {
        let mut value: Value =
            serde_json::from_str(bundle_json).map_err(|err| BundleError::Json(err.to_string()))?;
        let object = value
            .as_object_mut()
            .ok_or(BundleError::WrongType("bundle root"))?;
        let receipts = object
            .get_mut("receipts")
            .and_then(Value::as_array_mut)
            .ok_or(BundleError::WrongType("receipts"))?;
        let receipt = receipts
            .first_mut()
            .and_then(Value::as_object_mut)
            .ok_or(BundleError::WrongType("receipts[]"))?;
        receipt.insert(
            "receipt_payload".to_owned(),
            Value::String(payload.to_owned()),
        );
        receipt.insert(
            "receipt_sha256".to_owned(),
            Value::String(crate::export::sha256_hex(payload.as_bytes())),
        );
        Ok(value)
    }

    fn unsigned_bundle_json() -> Result<String, BundleError> {
        let receipt = Receipt::from_parts(ReceiptParts {
            scenario_id: "capability-subset-001-read-exact",
            category: "capability_subset",
            verdict: "allow",
            receipt_payload: include_str!(
                "../tests/fixtures/capability-subset-001-read-exact.receipt.json"
            ),
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
    "feedback_ref": "METR pair-run 2026-05-02",
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
