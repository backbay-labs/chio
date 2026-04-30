//! Cold-start and steady-state diagnostic latency benches.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//!
//! Targets the success-criteria contract: cold-start p99 < 200 ms and
//! steady-state diagnostic latency p99 < 50 ms on a 1k-line
//! `chio.yaml`. The benches measure the diagnostic provider directly
//! (no LSP wire encoding) so the numbers reflect engine cost, not
//! transport.

use chio_lsp::diagnostics;
use chio_lsp::DocumentLanguage;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tower_lsp::lsp_types::Url;

fn synthesize_chio_yaml(lines: usize) -> String {
    let mut body = String::with_capacity(lines * 32);
    body.push_str("version: 1\n");
    body.push_str("policy: ./policy.yaml\n");
    body.push_str("scopes:\n");
    for i in 0..lines.saturating_sub(2) {
        body.push_str(&format!("  - urn:chio:scope:tool.read.{i:04}\n"));
    }
    body
}

fn bench_cold_start(c: &mut Criterion) {
    let body = synthesize_chio_yaml(1024);
    let uri = Url::parse("file:///proj/chio.yaml").expect("valid url");
    c.bench_function("diagnostics_cold_start_1k_lines", |b| {
        b.iter(|| {
            let diags = diagnostics::validate(
                DocumentLanguage::ChioYaml,
                black_box(&uri),
                black_box(&body),
            );
            black_box(diags);
        });
    });
}

fn bench_steady_state(c: &mut Criterion) {
    let body = synthesize_chio_yaml(1024);
    let uri = Url::parse("file:///proj/chio.yaml").expect("valid url");
    // Warm: discard the first run's results.
    let _ = diagnostics::validate(DocumentLanguage::ChioYaml, &uri, &body);
    c.bench_function("diagnostics_steady_state_1k_lines", |b| {
        b.iter(|| {
            let diags = diagnostics::validate(
                DocumentLanguage::ChioYaml,
                black_box(&uri),
                black_box(&body),
            );
            black_box(diags);
        });
    });
}

criterion_group!(benches, bench_cold_start, bench_steady_state);
criterion_main!(benches);
