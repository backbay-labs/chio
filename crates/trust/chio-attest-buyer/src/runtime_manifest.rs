use crate::error::{json_error, BuyerAttestationError};
use crate::types::{RuntimeEvidenceManifest, RuntimeEvidenceManifestEntry};

// Round-trip the runtime evidence manifest through the historical type so
// that the historical crate's manifest invariants are honored even when
// callers obtain the manifest through Chio shapes.
pub fn runtime_evidence_manifest_from_json(
    json: &str,
) -> Result<RuntimeEvidenceManifest, BuyerAttestationError> {
    let historical: chio_runtime_core::RuntimeEvidenceManifest = serde_json::from_str(json)
        .map_err(|error| json_error("Chio runtime evidence manifest JSON", error))?;
    chio_runtime_core::validate_runtime_evidence_manifest(&historical)
        .map_err(BuyerAttestationError::from_runtime)?;
    Ok(RuntimeEvidenceManifest {
        schema: historical.schema,
        run_id: historical.run_id,
        generated_at_unix_ms: historical.generated_at_unix_ms,
        workflow_run_report_sha256: historical.workflow_run_report_sha256,
        proof_regeneration_report_sha256: historical.proof_regeneration_report_sha256,
        entries: historical
            .entries
            .into_iter()
            .map(|entry| RuntimeEvidenceManifestEntry {
                role: entry.role,
                path: entry.path,
                sha256: entry.sha256,
                byte_count: entry.byte_count,
            })
            .collect(),
    })
}
