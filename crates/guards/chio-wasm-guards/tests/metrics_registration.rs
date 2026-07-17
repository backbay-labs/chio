use chio_metrics_spec::{descriptor_for, MetricDescriptor, MetricKind};
use chio_wasm_guards::{
    epoch_label, guard_id_label_from_digest, register_guard_metric_families,
    register_guard_pool_metric_families, GuardPoolMetrics, MetricFamilyDescriptor,
    MetricFamilyKind, EVAL_DURATION_BUCKETS_SECONDS, GUARD_POOL_METRIC_FAMILIES,
    HOST_CALL_DURATION_BUCKETS_SECONDS, HOST_FN_LABEL_VALUES, LABEL_EPOCH, LABEL_GUARD_ID,
    LABEL_HOST_FN, LABEL_OUTCOME, LABEL_REASON, LABEL_REASON_CLASS, LABEL_TENANT_ID, LABEL_VERDICT,
    METRIC_CHIO_GUARD_DENY_TOTAL, METRIC_CHIO_GUARD_EVAL_DURATION_SECONDS,
    METRIC_CHIO_GUARD_FUEL_CONSUMED_TOTAL, METRIC_CHIO_GUARD_HOST_CALL_DURATION_SECONDS,
    METRIC_CHIO_GUARD_MODULE_BYTES, METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL,
    METRIC_CHIO_GUARD_POOL_EVICT_TOTAL, METRIC_CHIO_GUARD_POOL_WARM_SIZE,
    METRIC_CHIO_GUARD_RELOAD_TOTAL, METRIC_CHIO_GUARD_VERDICT_TOTAL,
    METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL, METRIC_CHIO_OTEL_SINK_DROP_TOTAL,
    METRIC_CHIO_SIGNING_QUEUE_BLOCK_TOTAL, OVERFLOW_TENANT_ID, REASON_CLASS_LABEL_VALUES,
    RELOAD_OUTCOME_LABEL_VALUES, RUNTIME_METRIC_FAMILIES, VERDICT_LABEL_VALUES,
};

fn family<'a>(families: &'a [MetricFamilyDescriptor], name: &str) -> &'a MetricFamilyDescriptor {
    match families.iter().find(|family| family.name == name) {
        Some(family) => family,
        None => panic!("missing metric family {name}"),
    }
}

fn spec_family(name: &str) -> &'static MetricDescriptor {
    match descriptor_for(name) {
        Some(descriptor) => descriptor,
        None => panic!("missing workspace metric descriptor {name}"),
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
fn runtime_metric_descriptors_lock_counter_names_and_units() {
    let names = RUNTIME_METRIC_FAMILIES
        .iter()
        .map(|family| family.name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            METRIC_CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
            METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL,
            METRIC_CHIO_OTEL_SINK_DROP_TOTAL,
        ]
    );

    for name in names {
        let descriptor = family(RUNTIME_METRIC_FAMILIES, name);
        assert_eq!(descriptor.kind, MetricFamilyKind::Counter);
        assert_eq!(descriptor.unit, Some("count"));
        assert!(descriptor.buckets.is_empty());
    }

    // The signing family carries the `reason` label so the exported descriptor
    // matches the workspace descriptor and the kernel renderer, which emit
    // chio_signing_queue_block_total{reason="..."}.
    let signing = family(
        RUNTIME_METRIC_FAMILIES,
        METRIC_CHIO_SIGNING_QUEUE_BLOCK_TOTAL,
    );
    assert_eq!(signing.labels, &[LABEL_REASON]);
    // The OTEL-drop families remain unlabeled.
    let otel_ingress = family(RUNTIME_METRIC_FAMILIES, METRIC_CHIO_OTEL_INGRESS_DROP_TOTAL);
    assert!(otel_ingress.labels.is_empty());
    let otel_sink = family(RUNTIME_METRIC_FAMILIES, METRIC_CHIO_OTEL_SINK_DROP_TOTAL);
    assert!(otel_sink.labels.is_empty());
}

#[test]
fn pool_metric_descriptors_lock_names_labels_and_units() {
    let registry = register_guard_pool_metric_families();
    let names = registry
        .families()
        .iter()
        .map(|family| family.name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL,
            METRIC_CHIO_GUARD_POOL_WARM_SIZE,
            METRIC_CHIO_GUARD_POOL_EVICT_TOTAL,
        ]
    );
    assert_eq!(registry.families(), GUARD_POOL_METRIC_FAMILIES);

    let checkout = family(registry.families(), METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL);
    assert_eq!(checkout.kind, MetricFamilyKind::Counter);
    assert_eq!(checkout.labels, &[LABEL_GUARD_ID, LABEL_TENANT_ID]);
    assert_eq!(checkout.unit, Some("count"));
    assert!(checkout.buckets.is_empty());

    let warm = family(registry.families(), METRIC_CHIO_GUARD_POOL_WARM_SIZE);
    assert_eq!(warm.kind, MetricFamilyKind::Gauge);
    assert_eq!(warm.labels, &[LABEL_GUARD_ID, LABEL_TENANT_ID]);
    assert_eq!(warm.unit, Some("instances"));
    assert!(warm.buckets.is_empty());

    let evict = family(registry.families(), METRIC_CHIO_GUARD_POOL_EVICT_TOTAL);
    assert_eq!(evict.kind, MetricFamilyKind::Counter);
    assert_eq!(evict.labels, &[LABEL_GUARD_ID, LABEL_TENANT_ID]);
    assert_eq!(evict.unit, Some("count"));
    assert!(evict.buckets.is_empty());
}

#[test]
fn pool_metric_exports_match_workspace_registry() {
    for (name, kind) in [
        (METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL, MetricKind::Counter),
        (METRIC_CHIO_GUARD_POOL_WARM_SIZE, MetricKind::Gauge),
        (METRIC_CHIO_GUARD_POOL_EVICT_TOTAL, MetricKind::Counter),
    ] {
        let descriptor = spec_family(name);
        assert_eq!(descriptor.kind, kind);
        assert_eq!(descriptor.labels, &[LABEL_GUARD_ID, LABEL_TENANT_ID]);
    }
}

#[test]
fn guard_pool_metrics_cap_tenant_cardinality() {
    let mut metrics = GuardPoolMetrics::with_max_tenants(2);
    metrics.record_checkout("tenant-a");
    metrics.set_warm_size("tenant-a", 1);
    metrics.record_checkout("tenant-b");
    metrics.record_checkout("tenant-c");
    metrics.record_evict("tenant-c");

    let tenant_a = match metrics.snapshot("tenant-a") {
        Some(snapshot) => snapshot,
        None => panic!("tenant-a metrics should be registered"),
    };
    assert_eq!(tenant_a.checkout_total, 1);
    assert_eq!(tenant_a.warm_size, 1);
    assert_eq!(tenant_a.evict_total, 0);
    assert_eq!(metrics.registered_tenant_count(), 2);

    let overflow = metrics.overflow_snapshot();
    assert_eq!(overflow.checkout_total, 1);
    assert_eq!(overflow.evict_total, 1);
    assert!(metrics.snapshot(OVERFLOW_TENANT_ID).is_some());
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
            "malformed",
            "other",
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
