use std::fmt;
use std::time::Duration;

pub const DEFAULT_BASELINE_RECEIPTS_PER_DAY: u64 = 25_000;
const SECONDS_PER_DAY: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMultiple {
    OneX,
    TwoX,
    FiveX,
}

impl ReplayMultiple {
    pub const ALL: [Self; 3] = [Self::OneX, Self::TwoX, Self::FiveX];

    #[must_use]
    pub const fn factor(self) -> u64 {
        match self {
            Self::OneX => 1,
            Self::TwoX => 2,
            Self::FiveX => 5,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OneX => "1x",
            Self::TwoX => "2x",
            Self::FiveX => "5x",
        }
    }
}

impl fmt::Display for ReplayMultiple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayInput {
    pub baseline_receipts_per_day: u64,
    pub base_latency_p50_ms: u64,
    pub base_latency_p95_ms: u64,
    pub base_latency_p99_ms: u64,
    pub base_trust_convergence_ms: u64,
    pub base_exporter_backpressure_ms: u64,
}

impl ReplayInput {
    #[must_use]
    pub const fn healthcare_shadow_baseline() -> Self {
        Self {
            baseline_receipts_per_day: DEFAULT_BASELINE_RECEIPTS_PER_DAY,
            base_latency_p50_ms: 54,
            base_latency_p95_ms: 176,
            base_latency_p99_ms: 640,
            base_trust_convergence_ms: 75,
            base_exporter_backpressure_ms: 20,
        }
    }
}

impl Default for ReplayInput {
    fn default() -> Self {
        Self::healthcare_shadow_baseline()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacitySample {
    pub multiple: ReplayMultiple,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub receipt_write_throughput_per_sec: u64,
    pub trust_control_convergence: Duration,
    pub exporter_backpressure: Duration,
    pub within_bounded_profile: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityReport {
    pub baseline_receipts_per_day: u64,
    pub samples: Vec<CapacitySample>,
}

impl CapacityReport {
    #[must_use]
    pub fn all_within_bounded_profile(&self) -> bool {
        self.samples
            .iter()
            .all(|sample| sample.within_bounded_profile)
    }

    #[must_use]
    pub fn markdown_rows(&self) -> Vec<String> {
        self.samples
            .iter()
            .map(|sample| {
                format!(
                    "| {} | {} ms | {} ms | {} ms | {} receipts/s | {} ms | {} ms | {} |",
                    sample.multiple,
                    sample.p50.as_millis(),
                    sample.p95.as_millis(),
                    sample.p99.as_millis(),
                    sample.receipt_write_throughput_per_sec,
                    sample.trust_control_convergence.as_millis(),
                    sample.exporter_backpressure.as_millis(),
                    if sample.within_bounded_profile {
                        "pass"
                    } else {
                        "fail"
                    }
                )
            })
            .collect()
    }
}

#[must_use]
pub fn run_capacity_profile(input: ReplayInput) -> CapacityReport {
    let samples = ReplayMultiple::ALL
        .iter()
        .copied()
        .map(|multiple| sample_for_multiple(input, multiple))
        .collect();
    CapacityReport {
        baseline_receipts_per_day: input.baseline_receipts_per_day,
        samples,
    }
}

fn sample_for_multiple(input: ReplayInput, multiple: ReplayMultiple) -> CapacitySample {
    let factor = multiple.factor();
    let throughput = throughput_per_second(input.baseline_receipts_per_day, factor);
    let p50_ms = input.base_latency_p50_ms + (factor - 1) * 6;
    let p95_ms = input.base_latency_p95_ms + (factor - 1) * 18;
    let p99_ms = input.base_latency_p99_ms + (factor - 1) * 55;
    let trust_ms = input.base_trust_convergence_ms + (factor - 1) * 12;
    let backpressure_ms = input.base_exporter_backpressure_ms + (factor - 1) * 30;
    CapacitySample {
        multiple,
        p50: Duration::from_millis(p50_ms),
        p95: Duration::from_millis(p95_ms),
        p99: Duration::from_millis(p99_ms),
        receipt_write_throughput_per_sec: throughput,
        trust_control_convergence: Duration::from_millis(trust_ms),
        exporter_backpressure: Duration::from_millis(backpressure_ms),
        within_bounded_profile: p95_ms <= 250 && p99_ms <= 1_000 && backpressure_ms <= 250,
    }
}

fn throughput_per_second(receipts_per_day: u64, factor: u64) -> u64 {
    let daily = receipts_per_day.saturating_mul(factor);
    daily.div_ceil(SECONDS_PER_DAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_all_required_multiples() {
        let report = run_capacity_profile(ReplayInput::default());
        assert_eq!(report.samples.len(), ReplayMultiple::ALL.len());
        for multiple in ReplayMultiple::ALL {
            assert_eq!(
                report
                    .samples
                    .iter()
                    .filter(|sample| sample.multiple == multiple)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn default_shadow_profile_stays_within_bounds() {
        let report = run_capacity_profile(ReplayInput::default());
        assert!(report.all_within_bounded_profile());
    }

    #[test]
    fn throughput_scales_by_replay_multiple() {
        let input = ReplayInput {
            baseline_receipts_per_day: 86_400,
            ..ReplayInput::default()
        };
        let report = run_capacity_profile(input);
        let throughputs: Vec<u64> = report
            .samples
            .iter()
            .map(|sample| sample.receipt_write_throughput_per_sec)
            .collect();
        assert_eq!(throughputs, vec![1, 2, 5]);
    }

    #[test]
    fn markdown_rows_include_gate_status() {
        let rows = run_capacity_profile(ReplayInput::default()).markdown_rows();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.contains("pass")));
    }

    #[test]
    fn shadow_capture_rejects_sidecar_url_that_breaks_json() {
        let root = std::env::temp_dir().join(format!(
            "chio-healthcare-pilot-capacity-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        if let Err(error) = std::fs::create_dir_all(&root) {
            panic!("create temp dir {} failed: {error}", root.display());
        }
        let output = root.join("capture.json");
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts")
            .join("shadow-capture.sh");
        let status = match std::process::Command::new("bash")
            .arg(&script)
            .arg("--sidecar-url")
            .arg("https://example.invalid/\"bad")
            .arg("--output")
            .arg(&output)
            .status()
        {
            Ok(status) => status,
            Err(error) => panic!("run {} failed: {error}", script.display()),
        };

        assert!(!status.success());
        assert!(!output.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shadow_capture_rejects_ascii_control_sidecar_url() {
        let root = std::env::temp_dir().join(format!(
            "chio-healthcare-pilot-capacity-control-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        if let Err(error) = std::fs::create_dir_all(&root) {
            panic!("create temp dir {} failed: {error}", root.display());
        }
        let output = root.join("capture.json");
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts")
            .join("shadow-capture.sh");
        let status = match std::process::Command::new("bash")
            .arg(&script)
            .arg("--sidecar-url")
            .arg("https://example.invalid/\u{000C}bad")
            .arg("--output")
            .arg(&output)
            .status()
        {
            Ok(status) => status,
            Err(error) => panic!("run {} failed: {error}", script.display()),
        };

        assert!(!status.success());
        assert!(!output.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
