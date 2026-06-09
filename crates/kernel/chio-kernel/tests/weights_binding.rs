use chio_kernel::weights_binding::{
    evaluate_weights_binding_with_loaded_hash, WeightsBindingError,
};
use chio_weights::card::{ModelCard, StringSet};
use chio_weights::error::WeightsError;
use chrono::{TimeZone, Utc};

fn issued_at() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 5, 2, 9, 0, 0) {
        chrono::LocalResult::Single(value) => value,
        _ => panic!("fixed timestamp fixture must construct"),
    }
}

fn model_card(weights_hash: &str) -> ModelCard {
    let issued = issued_at();
    match ModelCard::new(
        weights_hash,
        StringSet::new(["tool:read"]),
        StringSet::new(["tool:exec"]),
        "local-fixture",
        "https://issuer.example",
        issued,
        issued + chrono::Duration::days(30),
    ) {
        Ok(card) => card,
        Err(error) => panic!("model card fixture must construct: {error}"),
    }
}

fn binding_sets() -> (StringSet, StringSet) {
    (StringSet::new(["tool:read"]), StringSet::new(["tool:read"]))
}

#[test]
fn recomputed_loaded_hash_allows_matching_card() {
    let card = model_card("0000000000000000000000000000000000000000000000000000000000000001");
    let (scopes, tools) = binding_sets();
    let result = evaluate_weights_binding_with_loaded_hash(
        &card,
        Ok::<_, WeightsBindingError>(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        &scopes,
        &tools,
    );
    assert!(result.is_ok());
}

#[test]
fn recomputed_loaded_hash_rejects_spoofed_digest() {
    let card = model_card("0000000000000000000000000000000000000000000000000000000000000001");
    let (scopes, tools) = binding_sets();
    let err = match evaluate_weights_binding_with_loaded_hash(
        &card,
        Ok::<_, WeightsBindingError>(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        &scopes,
        &tools,
    ) {
        Ok(()) => panic!("spoofed digest must reject"),
        Err(err) => err,
    };
    assert!(matches!(err, WeightsError::CardMismatch { .. }));
}

#[test]
fn unavailable_loaded_weights_reject_fail_closed() {
    let card = model_card("0000000000000000000000000000000000000000000000000000000000000001");
    let (scopes, tools) = binding_sets();
    let err = match evaluate_weights_binding_with_loaded_hash(
        &card,
        Err::<String, _>("hosted provider did not expose loaded weights"),
        &scopes,
        &tools,
    ) {
        Ok(()) => panic!("unavailable loaded weights must reject"),
        Err(err) => err,
    };
    match err {
        WeightsError::SchemaRejected(message) => {
            assert!(message.contains("loaded weights unavailable"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
