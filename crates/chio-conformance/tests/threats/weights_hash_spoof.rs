// Threat test for threat ID `weights_hash_spoof` (Weights hash spoof).
//
// Surfaces: kernel_to_tool, native_chio.
//
// Owner: M05.P1.T3. The test exercises the loaded-weight recomputation
// contract added by M05.P1.T1/T2: a matching recomputed digest can bind,
// a spoofed digest rejects, and an unavailable loaded-weight surface
// rejects fail-closed.
//
// Coverage strategy: import production
// `chio_kernel::weights_binding::evaluate_weights_binding_with_loaded_hash`
// directly. Build a `ModelCard` whose declared weights hash matches the
// recomputed `loaded_weights_hash_of` digest, then drive the production
// function with three inputs: matching digest (Ok), spoofed digest
// (`WeightsError::CardMismatch`), and `LoadedWeightsUnavailable`
// (`WeightsError::SchemaRejected`). The two failure-path arms are the
// production deny branches that catch a spoofed weights hash.
//
// Revert-to-prove-it-fails recipe: flip the equality check inside
// `evaluate_weights_binding_with_loaded_hash` in
// `crates/chio-kernel/src/weights_binding.rs` (e.g. change `==` to
// `!=` or short-circuit to `Ok(())`). The spoofed-digest deny-arm
// assertion below fails because the production binding no longer
// rejects the mismatch between the card-declared and recomputed
// loaded-weights hashes.

use chio_core::{loaded_weights_hash_of, LoadedWeights, LoadedWeightsUnavailable};
use chio_kernel::weights_binding::evaluate_weights_binding_with_loaded_hash;
use chio_weights::card::{ModelCard, StringSet};
use chio_weights::error::WeightsError;
use chrono::{TimeZone, Utc};

fn issued_at() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 5, 2, 9, 30, 0) {
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
fn threat_weights_hash_spoof_is_covered() {
    // covers: weights_hash_spoof
    let loaded_weights = b"local-model-weights-v1".as_slice();
    let recomputed_hash = match loaded_weights.loaded_weights_hash() {
        Ok(hash) => hash,
        Err(error) => panic!("loaded-weight fixture must hash: {error}"),
    };
    assert_eq!(
        recomputed_hash,
        loaded_weights_hash_of(b"local-model-weights-v1")
    );

    let card = model_card(&recomputed_hash);
    let (scopes, tools) = binding_sets();
    let allow = evaluate_weights_binding_with_loaded_hash(
        &card,
        Ok::<_, LoadedWeightsUnavailable>(recomputed_hash.clone()),
        &scopes,
        &tools,
    );
    assert!(allow.is_ok());

    let spoofed = match evaluate_weights_binding_with_loaded_hash(
        &card,
        Ok::<_, LoadedWeightsUnavailable>(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        &scopes,
        &tools,
    ) {
        Ok(()) => panic!("spoofed loaded-weight digest must reject"),
        Err(error) => error,
    };
    assert!(matches!(spoofed, WeightsError::CardMismatch { .. }));

    let unavailable = LoadedWeightsUnavailable::new(
        "anthropic",
        "hosted API does not expose runtime loaded model bytes",
    );
    let unavailable_err = match evaluate_weights_binding_with_loaded_hash(
        &card,
        Err::<String, _>(unavailable),
        &scopes,
        &tools,
    ) {
        Ok(()) => panic!("unavailable loaded weights must reject"),
        Err(error) => error,
    };
    assert!(matches!(unavailable_err, WeightsError::SchemaRejected(_)));
}
