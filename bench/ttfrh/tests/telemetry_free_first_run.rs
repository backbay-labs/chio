//! Integration test for the telemetry-free first-run sentinel.
//!
//! Asserts that:
//!
//! 1. The embedded allowlist still matches the on-disk manifest at
//!    `bench/ttfrh/sentinel/allowlist.toml`.
//! 2. Every template defaults to an empty per-template allowlist (zero
//!    unsanctioned outbound hosts on first run).
//! 3. A simulated capture stream containing only loopback hostnames
//!    passes the sentinel.
//! 4. A simulated capture stream containing one third-party hostname
//!    fails the sentinel and surfaces the offending host name.
//!
//! The test ships the gate command:
//!
//! ```text
//! cargo test -p ttfrh-bench --test telemetry_free_first_run
//! ```

#![forbid(unsafe_code)]

use ttfrh_bench::network_sentinel::{Allowlist, SentinelReport};
use ttfrh_bench::TemplateRunner;

const MANIFEST: &str = include_str!("../sentinel/allowlist.toml");

#[test]
fn embedded_allowlist_matches_on_disk_manifest() {
    let allowlist = Allowlist::embedded();
    assert!(
        allowlist.matches_manifest(MANIFEST),
        "embedded allowlist drifted from sentinel/allowlist.toml",
    );
}

#[test]
fn every_template_defaults_to_zero_outbound_hosts() {
    let allowlist = Allowlist::embedded();
    for template in TemplateRunner::ALL {
        match allowlist.template_hosts(template) {
            Some(hosts) => assert!(
                hosts.is_empty(),
                "{} default allowlist must be empty (telemetry-free)",
                template
            ),
            None => panic!("{} missing allowlist entry", template),
        }
    }
}

#[test]
fn loopback_only_capture_passes_for_each_template() {
    let allowlist = Allowlist::embedded();
    // IPv6 addresses must use the bracketed `[host]:port` form so the
    // sentinel can unambiguously separate the host from the port. The bare
    // form `::1:8787` is itself a valid IPv6 literal and is preserved.
    let capture = ["127.0.0.1:3000", "localhost:8000", "[::1]:8787"];
    for template in TemplateRunner::ALL {
        let report =
            SentinelReport::parse_capture_lines(template, &allowlist, capture.iter().copied());
        assert!(
            report.passed(),
            "{} should pass loopback-only capture: offending = {:?}",
            template,
            report.offending,
        );
    }
}

#[test]
fn unsanctioned_host_fails_the_gate() {
    let allowlist = Allowlist::embedded();
    let capture = ["telemetry.example.com:443", "127.0.0.1:3000"];
    for template in TemplateRunner::ALL {
        let report =
            SentinelReport::parse_capture_lines(template, &allowlist, capture.iter().copied());
        assert!(
            !report.passed(),
            "{} should fail when telemetry.example.com is captured",
            template
        );
        assert!(
            report.offending.contains("telemetry.example.com"),
            "{} report must surface the offending host",
            template
        );
    }
}
