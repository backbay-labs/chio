use chio_attest_buyer::runtime_evidence_manifest_from_json;

#[test]
fn runtime_evidence_manifest_from_json_rejects_manifest_without_artifacts() {
    let json = r#"{
        "schema": "chio.runtime.evidence-manifest.v1",
        "runId": "runtime-run:empty-manifest",
        "generatedAtUnixMs": 1766000000000,
        "workflowRunReportSha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "proofRegenerationReportSha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "entries": []
    }"#;

    let error = match runtime_evidence_manifest_from_json(json) {
        Ok(manifest) => panic!("empty runtime evidence manifest must be rejected: {manifest:?}"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "runtime_evidence_manifest_missing_entries");
}
