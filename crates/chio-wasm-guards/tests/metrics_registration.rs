use chio_wasm_guards::{
    epoch_label, guard_id_label_from_digest, register_guard_metric_families,
    MetricFamilyDescriptor, MetricFamilyKind, EVAL_DURATION_BUCKETS_SECONDS,
    HOST_CALL_DURATION_BUCKETS_SECONDS, HOST_FN_LABEL_VALUES, LABEL_EPOCH, LABEL_GUARD_ID,
    LABEL_HOST_FN, LABEL_OUTCOME, LABEL_REASON_CLASS, LABEL_VERDICT, METRIC_CHIO_GUARD_DENY_TOTAL,
    METRIC_CHIO_GUARD_EVAL_DURATION_SECONDS, METRIC_CHIO_GUARD_FUEL_CONSUMED_TOTAL,
    METRIC_CHIO_GUARD_HOST_CALL_DURATION_SECONDS, METRIC_CHIO_GUARD_MODULE_BYTES,
    METRIC_CHIO_GUARD_RELOAD_TOTAL, METRIC_CHIO_GUARD_VERDICT_TOTAL, REASON_CLASS_LABEL_VALUES,
    RELOAD_OUTCOME_LABEL_VALUES, VERDICT_LABEL_VALUES,
};

fn family<'a>(families: &'a [MetricFamilyDescriptor], name: &str) -> &'a MetricFamilyDescriptor {
    match families.iter().find(|family| family.name == name) {
        Some(family) => family,
        None => panic!("missing metric family {name}"),
    }
}

#[test]
fn registers_exact_seven_metric_family_names() {
    let registry = register_guard_metric_families();
    let names = registry
        .families()
        .iter()
        .map(|family| family.name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            METRIC_CHIO_GUARD_EVAL_DURATION_SECONDS,
            METRIC_CHIO_GUARD_FUEL_CONSUMED_TOTAL,
            METRIC_CHIO_GUARD_VERDICT_TOTAL,
            METRIC_CHIO_GUARD_DENY_TOTAL,
            METRIC_CHIO_GUARD_RELOAD_TOTAL,
            METRIC_CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
            METRIC_CHIO_GUARD_MODULE_BYTES,
        ]
    );
}

#[test]
fn registers_locked_kinds_labels_units_and_buckets() {
    let registry = register_guard_metric_families();
    let families = registry.families();
    assert_eq!(families.len(), 7);

    let eval = family(families, METRIC_CHIO_GUARD_EVAL_DURATION_SECONDS);
    assert_eq!(eval.kind, MetricFamilyKind::Histogram);
    assert_eq!(eval.labels, &[LABEL_GUARD_ID, LABEL_VERDICT]);
    assert_eq!(eval.unit, Some("seconds"));
    assert_eq!(eval.buckets, EVAL_DURATION_BUCKETS_SECONDS);

    let fuel = family(families, METRIC_CHIO_GUARD_FUEL_CONSUMED_TOTAL);
    assert_eq!(fuel.kind, MetricFamilyKind::Counter);
    assert_eq!(fuel.labels, &[LABEL_GUARD_ID]);
    assert_eq!(fuel.unit, Some("fuel units"));
    assert!(fuel.buckets.is_empty());

    let verdict = family(families, METRIC_CHIO_GUARD_VERDICT_TOTAL);
    assert_eq!(verdict.kind, MetricFamilyKind::Counter);
    assert_eq!(verdict.labels, &[LABEL_GUARD_ID, LABEL_VERDICT]);
    assert_eq!(verdict.unit, Some("count"));
    assert!(verdict.buckets.is_empty());

    let deny = family(families, METRIC_CHIO_GUARD_DENY_TOTAL);
    assert_eq!(deny.kind, MetricFamilyKind::Counter);
    assert_eq!(deny.labels, &[LABEL_GUARD_ID, LABEL_REASON_CLASS]);
    assert_eq!(deny.unit, Some("count"));
    assert!(deny.buckets.is_empty());

    let reload = family(families, METRIC_CHIO_GUARD_RELOAD_TOTAL);
    assert_eq!(reload.kind, MetricFamilyKind::Counter);
    assert_eq!(reload.labels, &[LABEL_GUARD_ID, LABEL_OUTCOME]);
    assert_eq!(reload.unit, Some("count"));
    assert!(reload.buckets.is_empty());

    let host_call = family(families, METRIC_CHIO_GUARD_HOST_CALL_DURATION_SECONDS);
    assert_eq!(host_call.kind, MetricFamilyKind::Histogram);
    assert_eq!(host_call.labels, &[LABEL_GUARD_ID, LABEL_HOST_FN]);
    assert_eq!(host_call.unit, Some("seconds"));
    assert_eq!(host_call.buckets, HOST_CALL_DURATION_BUCKETS_SECONDS);

    let module_bytes = family(families, METRIC_CHIO_GUARD_MODULE_BYTES);
    assert_eq!(module_bytes.kind, MetricFamilyKind::Gauge);
    assert_eq!(module_bytes.labels, &[LABEL_GUARD_ID, LABEL_EPOCH]);
    assert_eq!(module_bytes.unit, Some("bytes"));
    assert!(module_bytes.buckets.is_empty());
}

#[test]
fn exposes_normative_label_value_sets() {
    assert_eq!(VERDICT_LABEL_VALUES, &["allow", "deny", "rewrite", "error"]);
    assert_eq!(
        REASON_CLASS_LABEL_VALUES,
        &[
            "policy",
            "pii",
            "secret",
            "prompt_injection",
            "oversize",
            "fuel",
            "trap",
        ]
    );
    assert_eq!(
        HOST_FN_LABEL_VALUES,
        &["log", "get_config", "get_time_unix_secs", "fetch_blob"]
    );
    assert_eq!(
        RELOAD_OUTCOME_LABEL_VALUES,
        &["applied", "canary_failed", "rolled_back"]
    );
}

#[test]
fn renders_guard_and_epoch_labels() {
    assert_eq!(
        guard_id_label_from_digest("abcdef1234567890fedcba"),
        "abcdef123456"
    );
    assert_eq!(
        guard_id_label_from_digest("sha256:abcdef1234567890fedcba"),
        "abcdef123456"
    );
    assert_eq!(guard_id_label_from_digest("short"), "short");
    assert_eq!(epoch_label(42), "42");
}
