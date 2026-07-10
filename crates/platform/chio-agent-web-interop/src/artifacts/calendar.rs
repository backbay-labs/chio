use chio_transaction_passport::TransactionPassportError;

use super::super::evidence::validate_sha256_hex;
use super::{
    claim_failed, required_json_bool, required_json_str, AgentWebProofEnvelope, ProjectionManifest,
};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("Calendar source version mismatch"));
    }
    if manifest.source_version != "v1" {
        return Err(claim_failed("unsupported Calendar source version"));
    }
    let provider_protocol = required_json_str(
        value,
        "provider_protocol",
        "missing Calendar provider protocol",
    )?;
    if provider_protocol != "google-calendar-api" {
        return Err(claim_failed("unsupported Calendar provider protocol"));
    }
    required_json_str(value, "event_id", "missing Calendar event id")?;
    let write_method = required_json_str(value, "write_method", "missing Calendar write method")?;
    if !matches!(write_method, "create" | "update" | "delete") {
        return Err(claim_failed("unsupported Calendar write method"));
    }
    for (field, message) in [
        ("calendar_id_digest", "missing Calendar id digest"),
        ("organizer_digest", "missing Calendar organizer digest"),
        ("time_range_digest", "missing Calendar time range digest"),
        (
            "approved_time_range_digest",
            "missing Calendar approved time range digest",
        ),
        ("recurrence_digest", "missing Calendar recurrence digest"),
        (
            "conferencing_link_digest",
            "missing Calendar conferencing link digest",
        ),
        (
            "oauth_scope_set_digest",
            "missing Calendar OAuth scope digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid Calendar digest: {field}")))?;
    }
    let time_range_digest = required_json_str(
        value,
        "time_range_digest",
        "missing Calendar time range digest",
    )?;
    let approved_time_range_digest = required_json_str(
        value,
        "approved_time_range_digest",
        "missing Calendar approved time range digest",
    )?;
    if matches!(write_method, "create" | "update")
        && time_range_digest != approved_time_range_digest
    {
        return Err(claim_failed("Calendar time range changed after approval"));
    }
    let attendee_digests = value
        .get("attendee_digest_list")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing Calendar attendee digests"))?;
    if attendee_digests.is_empty() {
        return Err(claim_failed("missing Calendar attendee digests"));
    }
    for attendee_digest in attendee_digests {
        let attendee_digest = attendee_digest
            .as_str()
            .ok_or_else(|| claim_failed("invalid Calendar attendee digest"))?;
        validate_sha256_hex(attendee_digest)
            .map_err(|_| claim_failed("invalid Calendar digest: attendee_digest_list"))?;
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing Calendar receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing Calendar receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid Calendar receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("Calendar receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing Calendar Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "Calendar action was not mediated by Chio receipt",
        ));
    }
    Ok(())
}
