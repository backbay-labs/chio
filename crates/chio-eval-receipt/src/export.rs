//! Unsigned eval-report bundle export helpers.
//!
//! Export intentionally stops before outer signature generation. The helper
//! preserves inner receipt payloads, hashes them for batch integrity checks,
//! and leaves `signatures` empty; schema and signature verification are
//! layered on separately.

use sha2::{Digest, Sha256};

use crate::BUNDLE_SCHEMA_ID;

/// Hash-pinned verdict-matrix corpus digest.
pub const VERDICT_MATRIX_CORPUS_SHA256: &str =
    "47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f";

/// The reference verifier consumes the 48-scenario verdict-matrix corpus.
pub const VERDICT_MATRIX_SCENARIO_COUNT: u16 = 48;

/// Manifest path for the corpus metadata.
pub const VERDICT_MATRIX_MANIFEST_PATH: &str =
    "crates/chio-conformance/verdict_matrix/manifest.toml";

const PRODUCER_REPOSITORY: &str = "https://github.com/backbay-labs/chio";
const CORPUS_NAME: &str = "chio-verdict-matrix";

/// Error returned by typed export input constructors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportError {
    /// A required field was empty or whitespace-only.
    EmptyField(&'static str),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(field) => write!(formatter, "required export field is empty: {field}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// Borrowed inputs for [`EvalRunMeta`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvalRunMetaParts<'a> {
    pub bundle_id: &'a str,
    pub created_at: &'a str,
    pub producer_commit: &'a str,
    pub workflow_run_url: &'a str,
    pub run_id: &'a str,
    pub partner: &'a str,
    pub partner_slug: &'a str,
    pub pipeline: &'a str,
    pub pipeline_language: &'a str,
    pub model_under_eval: &'a str,
    pub scorer_name: &'a str,
    pub scorer_version: &'a str,
}

/// Partner-facing eval-run metadata copied into a bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalRunMeta {
    pub bundle_id: String,
    pub created_at: String,
    pub producer_commit: String,
    pub workflow_run_url: String,
    pub run_id: String,
    pub partner: String,
    pub partner_slug: String,
    pub pipeline: String,
    pub pipeline_language: String,
    pub model_under_eval: String,
    pub scorer_name: String,
    pub scorer_version: String,
}

impl EvalRunMeta {
    /// Validate and own eval-run metadata.
    pub fn from_parts(parts: EvalRunMetaParts<'_>) -> Result<Self, ExportError> {
        Ok(Self {
            bundle_id: required("bundle_id", parts.bundle_id)?,
            created_at: required("created_at", parts.created_at)?,
            producer_commit: required("producer_commit", parts.producer_commit)?,
            workflow_run_url: required("workflow_run_url", parts.workflow_run_url)?,
            run_id: required("run_id", parts.run_id)?,
            partner: required("partner", parts.partner)?,
            partner_slug: required("partner_slug", parts.partner_slug)?,
            pipeline: required("pipeline", parts.pipeline)?,
            pipeline_language: required("pipeline_language", parts.pipeline_language)?,
            model_under_eval: required("model_under_eval", parts.model_under_eval)?,
            scorer_name: required("scorer_name", parts.scorer_name)?,
            scorer_version: required("scorer_version", parts.scorer_version)?,
        })
    }
}

/// Borrowed inputs for one wrapped scenario receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptParts<'a> {
    pub scenario_id: &'a str,
    pub category: &'a str,
    pub verdict: &'a str,
    pub receipt_payload: &'a str,
    pub trace_id: &'a str,
    pub sample_id: &'a str,
}

/// Preserved inner receipt payload plus scenario metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub scenario_id: String,
    pub category: String,
    pub verdict: String,
    pub receipt_payload: String,
    pub trace_id: String,
    pub sample_id: String,
}

impl Receipt {
    /// Validate and own a receipt wrapper input.
    pub fn from_parts(parts: ReceiptParts<'_>) -> Result<Self, ExportError> {
        Ok(Self {
            scenario_id: required("scenario_id", parts.scenario_id)?,
            category: required("category", parts.category)?,
            verdict: required("verdict", parts.verdict)?,
            receipt_payload: required("receipt_payload", parts.receipt_payload)?,
            trace_id: required("trace_id", parts.trace_id)?,
            sample_id: required("sample_id", parts.sample_id)?,
        })
    }

    fn to_entry(&self) -> ReceiptEntry {
        ReceiptEntry {
            scenario_id: self.scenario_id.clone(),
            category: self.category.clone(),
            verdict: self.verdict.clone(),
            receipt_payload: self.receipt_payload.clone(),
            receipt_sha256: sha256_hex(self.receipt_payload.as_bytes()),
            evidence: ReceiptEvidence {
                trace_id: self.trace_id.clone(),
                sample_id: self.sample_id.clone(),
            },
        }
    }
}

/// Producer provenance copied into an unsigned bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Producer {
    pub name: String,
    pub repository: String,
    pub commit: String,
    pub workflow_run_url: String,
}

/// Hash-pinned corpus metadata copied into an unsigned bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Corpus {
    pub name: String,
    pub scenario_count: u16,
    pub corpus_sha256: String,
    pub manifest_path: String,
}

/// Partner trace evidence attached to one receipt wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptEvidence {
    pub trace_id: String,
    pub sample_id: String,
}

/// One wrapped inner Chio receipt in an eval-report bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptEntry {
    pub scenario_id: String,
    pub category: String,
    pub verdict: String,
    pub receipt_payload: String,
    pub receipt_sha256: String,
    pub evidence: ReceiptEvidence,
}

/// Unsigned bundle shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bundle {
    pub schema: String,
    pub bundle_id: String,
    pub created_at: String,
    pub producer: Producer,
    pub eval_run: EvalRunMeta,
    pub corpus: Corpus,
    pub receipts: Vec<ReceiptEntry>,
    pub signatures: Vec<String>,
}

/// Produce an unsigned bundle from validated scenario receipts and run metadata.
pub fn export_scenario_run(receipts: &[Receipt], run_meta: EvalRunMeta) -> Bundle {
    let bundle_id = run_meta.bundle_id.clone();
    let created_at = run_meta.created_at.clone();
    let producer_commit = run_meta.producer_commit.clone();
    let workflow_run_url = run_meta.workflow_run_url.clone();
    let receipt_entries = receipts.iter().map(Receipt::to_entry).collect();

    Bundle {
        schema: BUNDLE_SCHEMA_ID.to_owned(),
        bundle_id,
        created_at,
        producer: Producer {
            name: "Chio".to_owned(),
            repository: PRODUCER_REPOSITORY.to_owned(),
            commit: producer_commit,
            workflow_run_url,
        },
        eval_run: run_meta,
        corpus: Corpus {
            name: CORPUS_NAME.to_owned(),
            scenario_count: VERDICT_MATRIX_SCENARIO_COUNT,
            corpus_sha256: VERDICT_MATRIX_CORPUS_SHA256.to_owned(),
            manifest_path: VERDICT_MATRIX_MANIFEST_PATH.to_owned(),
        },
        receipts: receipt_entries,
        signatures: Vec::new(),
    }
}

fn required(field: &'static str, value: &str) -> Result<String, ExportError> {
    if value.trim().is_empty() {
        Err(ExportError::EmptyField(field))
    } else {
        Ok(value.to_owned())
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        export_scenario_run, EvalRunMeta, EvalRunMetaParts, ExportError, Receipt, ReceiptParts,
        VERDICT_MATRIX_CORPUS_SHA256, VERDICT_MATRIX_SCENARIO_COUNT,
    };
    use crate::BUNDLE_SCHEMA_ID;

    #[test]
    fn export_preserves_receipt_payload_and_leaves_signatures_empty() -> Result<(), ExportError> {
        let run_meta = sample_meta()?;
        let receipt = Receipt::from_parts(ReceiptParts {
            scenario_id: "capability-subset-001-read-exact",
            category: "capability_subset",
            verdict: "allow",
            receipt_payload: "{\"receipt\":\"payload\"}",
            trace_id: "trace-001",
            sample_id: "sample-001",
        })?;

        let bundle = export_scenario_run(&[receipt], run_meta);

        assert_eq!(bundle.schema, BUNDLE_SCHEMA_ID);
        assert_eq!(bundle.corpus.scenario_count, VERDICT_MATRIX_SCENARIO_COUNT);
        assert_eq!(bundle.corpus.corpus_sha256, VERDICT_MATRIX_CORPUS_SHA256);
        assert!(bundle.signatures.is_empty());
        assert_eq!(bundle.receipts.len(), 1);
        assert_eq!(
            bundle.receipts[0].receipt_payload,
            "{\"receipt\":\"payload\"}"
        );
        assert_eq!(
            bundle.receipts[0].receipt_sha256,
            "65c76dd21a4fcd179b3e6d8eb777865ff426c566e2c89d6f637ae2c7c081e608"
        );
        Ok(())
    }

    #[test]
    fn metadata_constructor_rejects_empty_fields() {
        let result = EvalRunMeta::from_parts(EvalRunMetaParts {
            bundle_id: "bundle",
            created_at: "2026-05-02T00:00:00Z",
            producer_commit: "abc123",
            workflow_run_url: "local",
            run_id: "",
            partner: "METR",
            partner_slug: "metr",
            pipeline: "vivaria-trace-postprocess",
            pipeline_language: "python",
            model_under_eval: "model",
            scorer_name: "rubric",
            scorer_version: "v1",
        });

        assert_eq!(result, Err(ExportError::EmptyField("run_id")));
    }

    fn sample_meta() -> Result<EvalRunMeta, ExportError> {
        EvalRunMeta::from_parts(EvalRunMetaParts {
            bundle_id: "urn:chio:eval-bundle:metr:test",
            created_at: "2026-05-02T00:00:00Z",
            producer_commit: "abc123",
            workflow_run_url: "local",
            run_id: "metr-run-001",
            partner: "METR",
            partner_slug: "metr",
            pipeline: "vivaria-trace-postprocess",
            pipeline_language: "python",
            model_under_eval: "partner-model",
            scorer_name: "tool-use-rubric",
            scorer_version: "v1",
        })
    }
}
