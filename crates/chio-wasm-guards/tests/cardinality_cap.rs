use chio_wasm_guards::{
    guard_id_label_from_digest, register_guard_metric_families,
    E_GUARD_METRIC_CARDINALITY_EXCEEDED, MAX_GUARD_METRIC_CARDINALITY,
};

fn digest_for(index: usize) -> String {
    format!("{index:012x}deadbeef")
}

#[test]
fn accepts_exactly_1024_distinct_guard_ids() {
    let mut registry = register_guard_metric_families();
    assert_eq!(registry.max_guards(), MAX_GUARD_METRIC_CARDINALITY);

    for index in 0..MAX_GUARD_METRIC_CARDINALITY {
        let digest = digest_for(index);
        let expected_guard_id = guard_id_label_from_digest(&digest);
        let guard_id = match registry.register_guard_digest(&digest) {
            Ok(guard_id) => guard_id,
            Err(err) => panic!("guard {index} unexpectedly failed registration: {err}"),
        };
        assert_eq!(guard_id, expected_guard_id);
    }

    assert_eq!(
        registry.registered_guard_count(),
        MAX_GUARD_METRIC_CARDINALITY
    );
}

#[test]
fn rejects_1025th_distinct_guard_id_with_structured_error() {
    let mut registry = register_guard_metric_families();
    for index in 0..MAX_GUARD_METRIC_CARDINALITY {
        let digest = digest_for(index);
        if let Err(err) = registry.register_guard_digest(&digest) {
            panic!("guard {index} unexpectedly failed registration: {err}");
        }
    }

    let overflow_digest = "ffffffffffffdeadbeef";
    let err = match registry.register_guard_digest(overflow_digest) {
        Ok(guard_id) => panic!("overflow guard registered as {guard_id}"),
        Err(err) => err,
    };

    assert_eq!(err.code(), E_GUARD_METRIC_CARDINALITY_EXCEEDED);
    assert_eq!(err.guard_id(), "ffffffffffff");
    assert_eq!(err.attempted(), MAX_GUARD_METRIC_CARDINALITY + 1);
    assert_eq!(err.limit(), MAX_GUARD_METRIC_CARDINALITY);
    assert_eq!(
        registry.registered_guard_count(),
        MAX_GUARD_METRIC_CARDINALITY
    );
}

#[test]
fn duplicate_guard_ids_do_not_consume_cardinality() {
    let mut registry = register_guard_metric_families();
    let digest = digest_for(7);

    for _ in 0..MAX_GUARD_METRIC_CARDINALITY + 1 {
        if let Err(err) = registry.register_guard_digest(&digest) {
            panic!("duplicate guard unexpectedly failed registration: {err}");
        }
    }

    assert_eq!(registry.registered_guard_count(), 1);
}

#[test]
fn custom_low_cap_uses_same_error_shape() {
    let mut registry = chio_wasm_guards::GuardMetricRegistry::with_max_guards(2);
    for index in 0..2 {
        let digest = digest_for(index);
        if let Err(err) = registry.register_guard_digest(&digest) {
            panic!("guard {index} unexpectedly failed registration: {err}");
        }
    }

    let err = match registry.register_guard_digest(&digest_for(2)) {
        Ok(guard_id) => panic!("overflow guard registered as {guard_id}"),
        Err(err) => err,
    };

    assert_eq!(err.code(), E_GUARD_METRIC_CARDINALITY_EXCEEDED);
    assert_eq!(err.attempted(), 3);
    assert_eq!(err.limit(), 2);
    assert_eq!(registry.registered_guard_count(), 2);
}
