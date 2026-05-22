use serde::de::DeserializeOwned;

use crate::*;

use super::treaty_ref::TreatyEvidenceReference;

pub(super) fn load_treaty_artifact<S, T>(
    store: &S,
    evidence_kind: &str,
    reference: &TreatyEvidenceReference,
    missing_code: &'static str,
    mismatch_code: &'static str,
) -> Result<(T, String), ChioRuntimeError>
where
    S: RuntimeAdmissionStore,
    T: DeserializeOwned,
{
    let Some(record) = store.treaty_runtime_artifact(evidence_kind, &reference.evidence_id)? else {
        return rejected(
            missing_code,
            "cross-boundary request referenced treaty evidence that is not in the verifier-owned store",
        );
    };
    if record.artifact_sha256 != reference.artifact_sha256 {
        return rejected(
            mismatch_code,
            "cross-boundary request treaty evidence hash does not match verifier-owned store",
        );
    }
    let artifact_sha256 = record.artifact_sha256;
    let artifact: T = serde_json::from_value(record.raw_json)
        .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
    Ok((artifact, artifact_sha256))
}

pub(super) fn load_bilateral_invocation_artifact<S>(
    store: &S,
    reference: &TreatyEvidenceReference,
    missing_code: &'static str,
    mismatch_code: &'static str,
) -> Result<(BilateralInvocation, String), ChioRuntimeError>
where
    S: RuntimeAdmissionStore,
{
    let Some(record) =
        store.treaty_runtime_artifact("bilateral_invocation", &reference.evidence_id)?
    else {
        return rejected(
            missing_code,
            "cross-boundary request referenced treaty evidence that is not in the verifier-owned store",
        );
    };
    let invocation: BilateralInvocation = serde_json::from_value(record.raw_json)
        .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
    let artifact_sha256 = bilateral_invocation_binding_sha256(&invocation)?;
    if artifact_sha256 != reference.artifact_sha256 {
        return rejected(
            mismatch_code,
            "cross-boundary request bilateral invocation binding hash does not match verifier-owned store",
        );
    }
    Ok((invocation, artifact_sha256))
}
