use chio_kernel::{
    guard_metrics_endpoint, render_guard_metrics_prometheus, PrometheusMetricKind,
    GUARD_METRICS_PATH, GUARD_METRIC_FAMILIES, PROMETHEUS_TEXT_CONTENT_TYPE,
};

#[test]
fn metrics_endpoint_serves_prometheus_text() {
    let response = match guard_metrics_endpoint(GUARD_METRICS_PATH) {
        Some(response) => response,
        None => panic!("metrics endpoint did not handle /metrics"),
    };

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, PROMETHEUS_TEXT_CONTENT_TYPE);
    assert!(response
        .body
        .contains("# HELP chio_guard_eval_duration_seconds"));
    assert!(response
        .body
        .contains("# TYPE chio_guard_eval_duration_seconds histogram"));
}

#[test]
fn metrics_endpoint_ignores_other_paths() {
    assert!(guard_metrics_endpoint("/healthz").is_none());
}

#[test]
fn scrape_contains_all_seven_guard_metric_families() {
    let body = render_guard_metrics_prometheus();
    let names = [
        "chio_guard_eval_duration_seconds",
        "chio_guard_fuel_consumed_total",
        "chio_guard_verdict_total",
        "chio_guard_deny_total",
        "chio_guard_reload_total",
        "chio_guard_host_call_duration_seconds",
        "chio_guard_module_bytes",
    ];

    for name in names {
        assert!(
            body.contains(&format!("# HELP {name} ")),
            "missing HELP for {name}"
        );
        assert!(
            body.contains(&format!("# TYPE {name} ")),
            "missing TYPE for {name}"
        );
    }
}

#[test]
fn descriptors_lock_kinds_labels_and_buckets() {
    assert_eq!(GUARD_METRIC_FAMILIES.len(), 7);

    let eval = match GUARD_METRIC_FAMILIES
        .iter()
        .find(|family| family.name == "chio_guard_eval_duration_seconds")
    {
        Some(family) => family,
        None => panic!("missing eval duration family"),
    };
    assert_eq!(eval.kind, PrometheusMetricKind::Histogram);
    assert_eq!(eval.labels, &["guard_id", "verdict"]);
    assert_eq!(
        eval.buckets,
        &[
            "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5",
            "1.0",
        ]
    );

    let host = match GUARD_METRIC_FAMILIES
        .iter()
        .find(|family| family.name == "chio_guard_host_call_duration_seconds")
    {
        Some(family) => family,
        None => panic!("missing host call duration family"),
    };
    assert_eq!(host.kind, PrometheusMetricKind::Histogram);
    assert_eq!(host.labels, &["guard_id", "host_fn"]);
    assert_eq!(
        host.buckets,
        &["0.00001", "0.00005", "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1",]
    );
}

#[test]
fn scrape_renders_histogram_buckets_with_locked_bounds() {
    let body = render_guard_metrics_prometheus();

    assert!(body.contains(
        "chio_guard_eval_duration_seconds_bucket{guard_id=\"\",verdict=\"\",le=\"1.0\"} 0"
    ));
    assert!(body.contains(
        "chio_guard_host_call_duration_seconds_bucket{guard_id=\"\",host_fn=\"\",le=\"0.00001\"} 0"
    ));
    assert!(body.contains(
        "chio_guard_host_call_duration_seconds_bucket{guard_id=\"\",host_fn=\"\",le=\"+Inf\"} 0"
    ));
}

#[test]
fn scrape_renders_counter_and_gauge_samples() {
    let body = render_guard_metrics_prometheus();

    for sample in [
        "chio_guard_fuel_consumed_total{guard_id=\"\"} 0",
        "chio_guard_verdict_total{guard_id=\"\",verdict=\"\"} 0",
        "chio_guard_deny_total{guard_id=\"\",reason_class=\"\"} 0",
        "chio_guard_reload_total{guard_id=\"\",outcome=\"\"} 0",
        "chio_guard_module_bytes{guard_id=\"\",epoch=\"\"} 0",
    ] {
        assert!(body.contains(sample), "missing sample {sample}");
    }
}
