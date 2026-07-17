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
fn guard_metrics_report_driven_counts() {
    use chio_metrics_spec::runtime::families;
    families::GUARD_VERDICT.incr(&["driven-guard", "allow"]);
    families::GUARD_VERDICT.incr(&["driven-guard", "deny"]);
    families::GUARD_DENY.incr(&["driven-guard", "blocking"]);
    families::GUARD_EVAL_DURATION.observe(&["driven-guard", "allow"], 0.002);

    let body = render_guard_metrics_prometheus();
    assert!(
        body.contains("chio_guard_verdict_total{guard_id=\"driven-guard\",verdict=\"allow\"} 1"),
        "{body}"
    );
    assert!(
        body.contains("chio_guard_verdict_total{guard_id=\"driven-guard\",verdict=\"deny\"} 1"),
        "{body}"
    );
    assert!(
        body.contains(
            "chio_guard_deny_total{guard_id=\"driven-guard\",reason_class=\"blocking\"} 1"
        ),
        "{body}"
    );
    assert!(
        body.contains(
            "chio_guard_eval_duration_seconds_count{guard_id=\"driven-guard\",verdict=\"allow\"} 1"
        ),
        "{body}"
    );
    // No family renders a hardcoded empty-label zero placeholder.
    assert!(
        !body.contains("guard_id=\"\""),
        "no empty-label placeholder: {body}"
    );
}

#[test]
fn signing_block_counter_reports_reason_label() {
    use chio_metrics_spec::runtime::families;
    families::SIGNING_QUEUE_BLOCK.incr(&["byte_budget"]);
    let body = render_guard_metrics_prometheus();
    assert!(
        body.contains("chio_signing_queue_block_total{reason=\"byte_budget\"}"),
        "signing family must render the reason label: {body}"
    );
    // No unlabeled placeholder line is rendered.
    assert!(
        !body.contains("chio_signing_queue_block_total{} 0\n"),
        "{body}"
    );
}

#[test]
fn watchdog_gauges_render_from_health_report() {
    use chio_kernel::receipt_store::{ReceiptStoreHealthReport, ReceiptWriterCounters};
    let report = ReceiptStoreHealthReport {
        healthy: true,
        writer: ReceiptWriterCounters {
            last_commit_unix_ms: Some(1_000_000),
            ..Default::default()
        },
        writer_liveness: "healthy".to_string(),
        latest_committed_entry_seq: 50,
        latest_checkpoint_seq: Some(4),
        latest_checkpointed_entry_seq: 40,
        uncheckpointed_start_seq: Some(41),
        uncheckpointed_end_seq: Some(50),
        checkpoint_error: None,
        db_size_bytes: None,
        retention_watermark_entry_seq: None,
        retention_error: None,
        ..Default::default()
    };
    // Checkpoint staleness is based on checkpoint PROGRESS, not write-commit
    // freshness. The first sample seeds the staleness clock at 0; a later sample
    // with the SAME checkpointed seq and a still-pending backlog reports the
    // elapsed staleness, even though the write commit timestamp stayed fresh
    // (writes keep committing while checkpointing stalls). A last-commit-based
    // gauge would have read ~0 here.
    chio_kernel::record_receipt_health_gauges(&report, 1_000_000);
    chio_kernel::record_receipt_health_gauges(&report, 1_030_000); // +30s, checkpoint seq unchanged
    let body = chio_kernel::render_guard_metrics_prometheus();
    assert!(
        body.contains("chio_receipt_uncheckpointed_seq_range 9"),
        "{body}"
    ); // 50-41
    assert!(
        body.contains("chio_receipt_seconds_since_last_checkpoint 30"),
        "checkpoint staleness must grow while the checkpoint high-water mark stalls: {body}"
    );
}

#[test]
fn metrics_endpoint_serves_prometheus_body() {
    let response = match guard_metrics_endpoint(GUARD_METRICS_PATH) {
        Some(response) => response,
        None => panic!("metrics path serves"),
    };
    assert_eq!(response.status, 200);
    assert!(response
        .body
        .contains("# TYPE chio_guard_verdict_total counter"));
    assert!(response
        .body
        .contains("# TYPE chio_signing_queue_block_total counter"));
}
