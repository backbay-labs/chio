//! `chio doctor` probe implementations.
//!
//! The doctor subcommand wires a small ordered set of probes that
//! diagnose common DX failure modes (toolchain mismatch, OCI registry
//! reachability, cosign freshness, OTEL endpoint resolution, kernel
//! runtime metrics presence, and `chio.yaml` schema validity). Each
//! probe reports a single `ProbeReport`; the
//! runner aggregates the reports and derives an exit code from the
//! worst observed severity.
//!
//! Probe substrates:
//!
//! - `oci`: `chio-guard-registry` is the OCI substrate.
//! - `cosign`: `chio-attest-verify` is the cosign verifier.
//! - `otel`: `chio-otel-receipt-exporter` defines the OTLP endpoint shape.
//! - `kernel_runtime`: `chio-tower` exposes `/metrics` and the
//!   `chio_kernel_dispatch_inflight` gauge.
//! - `chio_yaml`: `spec/schemas/chio-wire/v1/` schemas anchor the schema
//!   check.
//!
//! Test-injection helpers (`with_root`, `with_endpoint`, ...) are
//! exercised by the per-probe integration tests under
//! `crates/chio-cli/tests/doctor_*`. The binary path itself drives the
//! public `Probe` trait, so the helpers can look unused under
//! `--bin chio`; the per-module dead-code allow is the targeted fix.
#![allow(dead_code)]

pub mod chio_yaml;
pub mod cosign;
pub mod kernel_runtime;
pub mod oci;
pub mod otel;
pub mod probe;
pub mod toolchain;

pub use chio_yaml::ChioYamlProbe;
pub use cosign::CosignProbe;
pub use kernel_runtime::KernelRuntimeProbe;
pub use oci::OciProbe;
pub use otel::OtelProbe;
pub use probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};
pub use toolchain::ToolchainProbe;

use serde::Serialize;

/// Result of a full doctor run. Aggregates individual probe reports and
/// surfaces the worst observed severity.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorRun {
    pub reports: Vec<ProbeReport>,
    pub worst: ProbeSeverity,
}

impl DoctorRun {
    /// Numeric exit code derived from `worst`.
    ///
    /// - `Ok` / `Info`: 0
    /// - `Warning`: 0 (non-blocking)
    /// - `Error`: 1
    /// - `Fatal`: 2
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self.worst {
            ProbeSeverity::Ok | ProbeSeverity::Info | ProbeSeverity::Warning => 0,
            ProbeSeverity::Error => 1,
            ProbeSeverity::Fatal => 2,
        }
    }
}

/// Ordered runner over a set of probes.
pub struct DoctorRunner {
    probes: Vec<Box<dyn Probe>>,
    config: ProbeConfig,
}

impl DoctorRunner {
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            probes: Vec::new(),
            config,
        }
    }

    #[must_use]
    pub fn with_probe(mut self, probe: Box<dyn Probe>) -> Self {
        self.probes.push(probe);
        self
    }

    /// Build the standard probe set in the canonical order: toolchain,
    /// OCI, cosign, OTEL, kernel runtime, chio.yaml.
    #[must_use]
    pub fn standard(config: ProbeConfig) -> Self {
        Self::new(config)
            .with_probe(Box::new(ToolchainProbe::default()))
            .with_probe(Box::new(OciProbe::default()))
            .with_probe(Box::new(CosignProbe::default()))
            .with_probe(Box::new(OtelProbe::default()))
            .with_probe(Box::new(KernelRuntimeProbe::default()))
            .with_probe(Box::new(ChioYamlProbe::default()))
    }

    pub fn run(&self) -> DoctorRun {
        let mut reports = Vec::with_capacity(self.probes.len());
        let mut worst = ProbeSeverity::Ok;
        for probe in &self.probes {
            let report = probe.run(&self.config);
            if report.severity > worst {
                worst = report.severity;
            }
            reports.push(report);
        }
        DoctorRun { reports, worst }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubProbe {
        name: &'static str,
        outcome: ProbeReport,
    }

    impl Probe for StubProbe {
        fn name(&self) -> &'static str {
            self.name
        }
        fn run(&self, _config: &ProbeConfig) -> ProbeReport {
            self.outcome.clone()
        }
    }

    #[test]
    fn worst_severity_drives_exit_code() {
        let runner = DoctorRunner::new(ProbeConfig::default())
            .with_probe(Box::new(StubProbe {
                name: "a",
                outcome: ProbeReport::ok("a", "ok"),
            }))
            .with_probe(Box::new(StubProbe {
                name: "b",
                outcome: ProbeReport::fail(
                    "b",
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:doctor-probe-failed",
                    "boom",
                ),
            }));
        let run = runner.run();
        assert_eq!(run.reports.len(), 2);
        assert_eq!(run.worst, ProbeSeverity::Error);
        assert_eq!(run.exit_code(), 1);
    }

    #[test]
    fn warnings_do_not_drive_non_zero_exit() {
        let runner = DoctorRunner::new(ProbeConfig::default()).with_probe(Box::new(StubProbe {
            name: "warn",
            outcome: ProbeReport::fail(
                "warn",
                ProbeSeverity::Warning,
                "urn:chio:error:cli:doctor-oci-unreachable",
                "soft",
            ),
        }));
        let run = runner.run();
        assert_eq!(run.exit_code(), 0);
        assert_eq!(run.worst, ProbeSeverity::Warning);
    }
}
