use chio_eval_receipt::{
    export_scenario_run, EvalRunMeta, EvalRunMetaParts, ExportError, Receipt, ReceiptParts,
    VERDICT_MATRIX_CORPUS_SHA256, VERDICT_MATRIX_SCENARIO_COUNT,
};

#[test]
fn exports_three_verdict_matrix_sample_receipts() -> Result<(), ExportError> {
    let receipts = vec![
        Receipt::from_parts(ReceiptParts {
            scenario_id: "capability-subset-001-read-exact",
            category: "capability_subset",
            verdict: "allow",
            receipt_payload: include_str!("fixtures/capability-subset-001-read-exact.receipt.json"),
            trace_id: "trace-capability-001",
            sample_id: "sample-capability-001",
        })?,
        Receipt::from_parts(ReceiptParts {
            scenario_id: "revocation-propagation-001-active-read",
            category: "revocation_propagation",
            verdict: "allow",
            receipt_payload: include_str!(
                "fixtures/revocation-propagation-001-active-read.receipt.json"
            ),
            trace_id: "trace-revocation-001",
            sample_id: "sample-revocation-001",
        })?,
        Receipt::from_parts(ReceiptParts {
            scenario_id: "replay-verdict-001-fresh-read",
            category: "replay_verdict",
            verdict: "allow",
            receipt_payload: include_str!("fixtures/replay-verdict-001-fresh-read.receipt.json"),
            trace_id: "trace-replay-001",
            sample_id: "sample-replay-001",
        })?,
    ];

    let bundle = export_scenario_run(&receipts, sample_meta()?);

    assert_eq!(bundle.bundle_id, "urn:chio:eval-bundle:metr:p2-roundtrip");
    assert_eq!(bundle.corpus.scenario_count, VERDICT_MATRIX_SCENARIO_COUNT);
    assert_eq!(bundle.corpus.corpus_sha256, VERDICT_MATRIX_CORPUS_SHA256);
    assert_eq!(bundle.eval_run.partner_slug, "metr");
    assert_eq!(bundle.eval_run.pipeline_language, "python");
    assert!(bundle.signatures.is_empty());
    assert_eq!(bundle.receipts.len(), 3);

    assert_receipt(&bundle.receipts[0], "capability-subset-001-read-exact");
    assert_receipt(
        &bundle.receipts[1],
        "revocation-propagation-001-active-read",
    );
    assert_receipt(&bundle.receipts[2], "replay-verdict-001-fresh-read");

    Ok(())
}

fn assert_receipt(receipt: &chio_eval_receipt::ReceiptEntry, scenario_id: &str) {
    assert_eq!(receipt.scenario_id, scenario_id);
    assert_eq!(receipt.receipt_sha256.len(), 64);
    assert!(receipt.receipt_payload.contains(scenario_id));
    assert!(!receipt.evidence.trace_id.is_empty());
    assert!(!receipt.evidence.sample_id.is_empty());
}

fn sample_meta() -> Result<EvalRunMeta, ExportError> {
    EvalRunMeta::from_parts(EvalRunMetaParts {
        bundle_id: "urn:chio:eval-bundle:metr:p2-roundtrip",
        created_at: "2026-05-02T00:00:00Z",
        producer_commit: "p2-test",
        workflow_run_url: "local-export-roundtrip",
        run_id: "metr-p2-roundtrip",
        partner: "METR",
        partner_slug: "metr",
        pipeline: "vivaria-trace-postprocess",
        pipeline_language: "python",
        model_under_eval: "partner-model",
        scorer_name: "tool-use-rubric",
        scorer_version: "v1",
    })
}
