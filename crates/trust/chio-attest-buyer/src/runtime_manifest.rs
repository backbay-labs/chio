use crate::error::{json_error, BuyerAttestationError};
use crate::types::{RuntimeEvidenceManifest, RuntimeEvidenceManifestEntry};

// Round-trip the runtime evidence manifest through the runtime-core type so
// that the runtime-core crate's manifest invariants are honored even when
// callers obtain the manifest through Chio shapes.
pub fn runtime_evidence_manifest_from_json(
    json: &str,
) -> Result<RuntimeEvidenceManifest, BuyerAttestationError> {
    let runtime_core: chio_runtime_core::RuntimeEvidenceManifest = serde_json::from_str(json)
        .map_err(|error| json_error("Chio runtime evidence manifest JSON", error))?;
    chio_runtime_core::validate_runtime_evidence_manifest(&runtime_core)
        .map_err(BuyerAttestationError::from_runtime)?;
    Ok(RuntimeEvidenceManifest {
        schema: runtime_core.schema,
        run_id: runtime_core.run_id,
        generated_at_unix_ms: runtime_core.generated_at_unix_ms,
        workflow_run_report_sha256: runtime_core.workflow_run_report_sha256,
        proof_regeneration_report_sha256: runtime_core.proof_regeneration_report_sha256,
        entries: runtime_core
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
