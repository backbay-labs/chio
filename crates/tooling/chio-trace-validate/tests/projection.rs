mod support;

use chio_trace_validate::{
    decode_observations, project_revocation_trace, ActionCoverage, TraceError,
};

#[test]
fn projection_is_deterministic_and_counts_non_vacuous_actions() -> Result<(), TraceError> {
    let fixture = support::good_trace()?;
    let observations = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let first = project_revocation_trace(&observations)?;
    let second = project_revocation_trace(&observations)?;

    assert_eq!(first.itf_json(), second.itf_json());
    assert_eq!(
        first.action_coverage(),
        ActionCoverage {
            revoke: 1,
            evaluate: 2,
            post_revocation_evaluate: 1,
        }
    );
    assert_eq!(first.events().len(), 3);
    assert_eq!(first.authority_count(), 1);
    assert_eq!(first.capability_count(), 2);

    let itf: serde_json::Value = serde_json::from_slice(first.itf_json())?;
    let var_types = itf
        .get("#meta")
        .and_then(|metadata| metadata.get("varTypes"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| TraceError::InvalidInput("ITF is missing varTypes".to_string()))?;
    assert_eq!(
        var_types.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "clock",
            "depth",
            "pending",
            "receipt_log",
            "rev_epoch",
            "state"
        ]
    );
    Ok(())
}

#[test]
fn projection_rejects_a_receipt_with_an_invalid_signature() -> Result<(), TraceError> {
    let mut fixture = support::good_trace()?;
    fixture.tamper_last_receipt_tool_name()?;
    let observations = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let error = project_revocation_trace(&observations)
        .err()
        .ok_or_else(|| TraceError::InvalidInput("invalid receipt was projected".to_string()))?;

    assert!(error.to_string().contains("receipt signature"));
    Ok(())
}

#[test]
fn projection_rejects_a_signed_receipt_with_an_invalid_action_hash() -> Result<(), TraceError> {
    let fixture = support::invalid_action_hash_trace()?;
    let observations = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let error = project_revocation_trace(&observations)
        .err()
        .ok_or_else(|| TraceError::InvalidInput("invalid action hash was projected".to_string()))?;

    assert!(error.to_string().contains("action hash"));
    Ok(())
}
