//! Deterministic generator for the eval-report golden vector.

use std::fs;
use std::path::Path;

use chio_eval_receipt::{
    export_scenario_run, test_signature_for_bundle_json, EvalRunMeta, EvalRunMetaParts, Receipt,
    ReceiptParts,
};

use super::{display_path, freeze_vectors, workspace_root, XtaskError};

const VECTOR_PATH: &str = "tests/bindings/vectors/eval/v1.json";

pub fn run(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "eval-receipt-regen: unknown flag: {other}"
                )));
            }
        }
    }

    let workspace_root = workspace_root()?;
    let vector_path = workspace_root.join(VECTOR_PATH);
    let generated = generate_vector()?;

    if check_only {
        let existing = fs::read_to_string(&vector_path)
            .map_err(|err| XtaskError::Io(display_path(&vector_path), err))?;
        if existing != generated {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask eval-receipt-regen`",
                display_path(&vector_path)
            )));
        }
        freeze_vectors(vec!["--check".to_owned()])?;
        println!("{} in sync", display_path(&vector_path));
    } else {
        ensure_parent(&vector_path)?;
        fs::write(&vector_path, generated)
            .map_err(|err| XtaskError::Io(display_path(&vector_path), err))?;
        freeze_vectors(Vec::new())?;
        println!("wrote {}", display_path(&vector_path));
    }

    Ok(())
}

fn generate_vector() -> Result<String, XtaskError> {
    let receipts = vec![
        Receipt::from_parts(ReceiptParts {
            scenario_id: "capability-subset-001-read-exact",
            category: "capability_subset",
            verdict: "allow",
            receipt_payload: include_str!(
                "../../crates/chio-eval-receipt/tests/fixtures/capability-subset-001-read-exact.receipt.json"
            ),
            trace_id: "trace-capability-001",
            sample_id: "sample-capability-001",
        })
        .map_err(|err| XtaskError::Validation(err.to_string()))?,
        Receipt::from_parts(ReceiptParts {
            scenario_id: "revocation-propagation-001-active-read",
            category: "revocation_propagation",
            verdict: "allow",
            receipt_payload: include_str!(
                "../../crates/chio-eval-receipt/tests/fixtures/revocation-propagation-001-active-read.receipt.json"
            ),
            trace_id: "trace-revocation-001",
            sample_id: "sample-revocation-001",
        })
        .map_err(|err| XtaskError::Validation(err.to_string()))?,
        Receipt::from_parts(ReceiptParts {
            scenario_id: "replay-verdict-001-fresh-read",
            category: "replay_verdict",
            verdict: "allow",
            receipt_payload: include_str!(
                "../../crates/chio-eval-receipt/tests/fixtures/replay-verdict-001-fresh-read.receipt.json"
            ),
            trace_id: "trace-replay-001",
            sample_id: "sample-replay-001",
        })
        .map_err(|err| XtaskError::Validation(err.to_string()))?,
    ];
    let meta = EvalRunMeta::from_parts(EvalRunMetaParts {
        bundle_id: "urn:chio:eval-bundle:metr:golden-v1",
        created_at: "2026-05-02T00:00:00Z",
        producer_commit: "golden-v1",
        workflow_run_url: "local-eval-receipt-regen",
        run_id: "metr-golden-v1",
        partner: "METR",
        partner_slug: "metr",
        pipeline: "vivaria-trace-postprocess",
        pipeline_language: "python",
        model_under_eval: "partner-model",
        scorer_name: "tool-use-rubric",
        scorer_version: "v1",
    })
    .map_err(|err| XtaskError::Validation(err.to_string()))?;
    let bundle = export_scenario_run(&receipts, meta);
    let unsigned = render_bundle(&bundle, "SIGNATURE_PLACEHOLDER")?;
    let signature = test_signature_for_bundle_json(&unsigned)
        .map_err(|err| XtaskError::Validation(err.to_string()))?;
    render_bundle(&bundle, &signature)
}

fn render_bundle(
    bundle: &chio_eval_receipt::Bundle,
    signature: &str,
) -> Result<String, XtaskError> {
    let mut receipts_json = String::new();
    for (idx, entry) in bundle.receipts.iter().enumerate() {
        if idx > 0 {
            receipts_json.push_str(",\n");
        }
        let payload = serde_json::to_string(&entry.receipt_payload)
            .map_err(|err| XtaskError::Json("receipt_payload".to_owned(), err))?;
        receipts_json.push_str(&format!(
            r#"    {{
      "scenario_id": "{}",
      "category": "{}",
      "verdict": "{}",
      "receipt_payload": {},
      "receipt_sha256": "{}",
      "evidence": {{
        "trace_id": "{}",
        "sample_id": "{}"
      }}
    }}"#,
            entry.scenario_id,
            entry.category,
            entry.verdict,
            payload,
            entry.receipt_sha256,
            entry.evidence.trace_id,
            entry.evidence.sample_id
        ));
    }

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
{}
  ],
  "signatures": [
    {{
      "kind": "test-sha256",
      "key_id": "local-test",
      "signature": "{}",
      "signed_payload": "bundle_without_signatures:rfc8785"
    }}
  ]
}}
"#,
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
        receipts_json,
        signature
    ))
}

fn ensure_parent(path: &Path) -> Result<(), XtaskError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
    }
    Ok(())
}
