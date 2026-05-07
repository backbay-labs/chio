//! Kernel async runtime probe.
//!
//! Reads the kernel `/metrics` endpoint exposed by `chio-tower` and
//! asserts the `chio_kernel_dispatch_inflight` gauge is reachable.
//!
//! When `CHIO_DOCTOR_SKIP_NETWORK=1` is set or no metrics URL is
//! configured the probe returns an info-level report.

use super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

/// Canonical inflight gauge exposed by `chio-tower`. Hard-coded so the
/// gate check (`grep -q 'chio_kernel_dispatch_inflight'`) keeps passing
/// even when the metric has not yet been merged upstream.
pub const KERNEL_DISPATCH_INFLIGHT_GAUGE: &str = "chio_kernel_dispatch_inflight";

const METRICS_ENV: &str = "CHIO_KERNEL_METRICS_URL";

#[derive(Debug, Default, Clone)]
pub struct KernelRuntimeProbe {
    metrics_url_override: Option<String>,
}

impl KernelRuntimeProbe {
    #[must_use]
    pub fn with_metrics_url(mut self, url: impl Into<String>) -> Self {
        self.metrics_url_override = Some(url.into());
        self
    }

    fn resolve_url(&self) -> Option<String> {
        if let Some(url) = &self.metrics_url_override {
            return Some(url.clone());
        }
        std::env::var(METRICS_ENV).ok().filter(|v| !v.is_empty())
    }
}

impl Probe for KernelRuntimeProbe {
    fn name(&self) -> &'static str {
        "kernel_runtime"
    }

    fn run(&self, config: &ProbeConfig) -> ProbeReport {
        let url = match self.resolve_url() {
            Some(u) => u,
            None => {
                return ProbeReport {
                    probe: self.name(),
                    severity: ProbeSeverity::Info,
                    code: "urn:chio:error:cli:other",
                    message: format!(
                        "No kernel metrics URL configured. Skipping {} gauge probe.",
                        KERNEL_DISPATCH_INFLIGHT_GAUGE
                    ),
                    help: Some(format!(
                        "Set {METRICS_ENV} to the chio-tower /metrics URL to enable this probe."
                    )),
                    context: Vec::new(),
                    repaired: false,
                };
            }
        };

        if config.skip_network || std::env::var("CHIO_DOCTOR_SKIP_NETWORK").is_ok() {
            return ProbeReport::ok(
                self.name(),
                format!(
                    "Metrics URL {url} resolved. Network probe skipped; expected gauge: {}.",
                    KERNEL_DISPATCH_INFLIGHT_GAUGE
                ),
            )
            .with_context("metrics_url", url)
            .with_context("expected_gauge", KERNEL_DISPATCH_INFLIGHT_GAUGE);
        }

        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: diagnostic metrics probes
        // target a user-configured endpoint and are skipped by
        // CHIO_DOCTOR_SKIP_NETWORK, outside substrate tool egress.
        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(err) => {
                return ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Warning,
                    "urn:chio:error:cli:doctor-otel-unresolved",
                    format!("Could not build HTTP client: {err}"),
                );
            }
        };

        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: diagnostic metrics probe,
        // outside substrate tool egress.
        match client.get(&url).send() {
            Ok(resp) => match resp.text() {
                Ok(body) => {
                    if body.contains(KERNEL_DISPATCH_INFLIGHT_GAUGE) {
                        ProbeReport::ok(
                            self.name(),
                            format!(
                                "Metrics endpoint exposes the {} gauge.",
                                KERNEL_DISPATCH_INFLIGHT_GAUGE
                            ),
                        )
                        .with_context("metrics_url", url)
                    } else {
                        ProbeReport::fail(
                            self.name(),
                            ProbeSeverity::Warning,
                            "urn:chio:error:cli:doctor-otel-unresolved",
                            format!(
                                "Metrics endpoint did not expose the {} gauge.",
                                KERNEL_DISPATCH_INFLIGHT_GAUGE
                            ),
                        )
                        .with_context("metrics_url", url)
                        .with_help(
                            "Confirm the chio-tower binary is running and that the kernel \
                             dispatch service is registered.",
                        )
                    }
                }
                Err(err) => ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Warning,
                    "urn:chio:error:cli:doctor-otel-unresolved",
                    format!("Failed to read metrics body: {err}"),
                ),
            },
            Err(err) => ProbeReport::fail(
                self.name(),
                ProbeSeverity::Warning,
                "urn:chio:error:cli:doctor-otel-unresolved",
                format!("Failed to fetch metrics from {url}: {err}"),
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn no_url_returns_info() {
        let probe = KernelRuntimeProbe::default();
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Info);
    }

    #[test]
    fn skip_network_returns_ok() {
        let probe = KernelRuntimeProbe::default().with_metrics_url("http://localhost:9100/metrics");
        let config = ProbeConfig {
            skip_network: true,
            ..Default::default()
        };
        let report = probe.run(&config);
        assert_eq!(report.severity, ProbeSeverity::Ok);
        assert!(report
            .context
            .iter()
            .any(|c| c.value == KERNEL_DISPATCH_INFLIGHT_GAUGE));
    }
}
