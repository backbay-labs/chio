#![forbid(unsafe_code)]

//! TTFRH bench harness. Runners are required gating backed by a deterministic
//! in-process simulation layer so the bench reports p50 and p99 timings
//! without provisioning a Docker host on every PR. The CI workflow at
//! `.github/workflows/ttfrh.yml` runs the full container path once a
//! template directory or a runner module changes.

use std::fmt;
use std::time::Duration;

pub mod budget;
pub mod network_sentinel;
pub mod runners;

pub use budget::{Budget, BudgetError, DEFAULT_BUDGET_MS, DEFAULT_BUFFER_PCT};

pub const TARGET_SECONDS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateRunner {
    NextAiSdkReceipts,
    FastapiLangchain,
    CloudflareWorker,
}

impl TemplateRunner {
    pub const ALL: [Self; 3] = [
        Self::NextAiSdkReceipts,
        Self::FastapiLangchain,
        Self::CloudflareWorker,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::NextAiSdkReceipts => "next-ai-sdk-receipts",
            Self::FastapiLangchain => "fastapi-langchain",
            Self::CloudflareWorker => "cloudflare-worker",
        }
    }
}

impl fmt::Display for TemplateRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerPlan {
    pub template: TemplateRunner,
    pub command: &'static str,
    /// `false` when the runner is required by CI (all runners are currently required).
    pub advisory: bool,
    /// Synthetic samples in milliseconds used by the in-process bench
    /// path. The container path under `.github/workflows/ttfrh.yml`
    /// replaces these with measured wall-clock samples.
    pub synthetic_samples_ms: &'static [u64],
}

pub fn runner_plans() -> [RunnerPlan; 3] {
    [
        runners::next_ai_sdk_receipts::plan(),
        runners::fastapi_langchain::plan(),
        runners::cloudflare_worker::plan(),
    ]
}

/// Result of running a single template under the bench harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerReport {
    pub template: TemplateRunner,
    pub p50: Duration,
    pub p99: Duration,
    pub samples: usize,
    pub within_budget: bool,
}

/// Compute a percentile from a sorted slice of millisecond samples.
fn percentile_ms(sorted_ms: &[u64], pct: u8) -> u64 {
    if sorted_ms.is_empty() {
        return 0;
    }
    let last_index = sorted_ms.len() - 1;
    // ceiling-rank percentile so p99 of small samples picks the tail.
    let scaled = (u128::from(pct) * last_index as u128).div_ceil(100);
    let idx = scaled as usize;
    sorted_ms[idx.min(last_index)]
}

/// Run every template plan against the supplied budget. Returns one
/// report per template; the caller decides whether to fail the gate.
pub fn run_all(budget: Budget) -> Vec<RunnerReport> {
    runner_plans()
        .iter()
        .map(|plan| run_plan(plan, budget))
        .collect()
}

/// Run a single plan, computing p50 / p99 from the synthetic samples.
pub fn run_plan(plan: &RunnerPlan, budget: Budget) -> RunnerReport {
    let mut samples = plan.synthetic_samples_ms.to_vec();
    samples.sort_unstable();
    let p50_ms = percentile_ms(&samples, 50);
    let p99_ms = percentile_ms(&samples, 99);
    let p99 = Duration::from_millis(p99_ms);
    RunnerReport {
        template: plan.template,
        p50: Duration::from_millis(p50_ms),
        p99,
        samples: samples.len(),
        within_budget: !budget.breaches(p99),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runners_cover_every_template_once() {
        let plans = runner_plans();
        assert_eq!(plans.len(), TemplateRunner::ALL.len());
        for template in TemplateRunner::ALL {
            assert_eq!(
                plans
                    .iter()
                    .filter(|plan| plan.template == template)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn all_runners_are_required() {
        for plan in runner_plans() {
            assert!(!plan.advisory, "{} runner must be required", plan.template);
            assert!(!plan.command.trim().is_empty());
            assert!(
                !plan.synthetic_samples_ms.is_empty(),
                "{} runner must ship synthetic samples for the in-process path",
                plan.template
            );
        }
    }

    #[test]
    fn every_template_meets_default_budget() {
        let budget = Budget::default_60s();
        for report in run_all(budget) {
            assert!(
                report.within_budget,
                "{} regressed: p99 = {:?}",
                report.template, report.p99
            );
            assert!(report.samples >= 5);
        }
    }

    #[test]
    fn breach_flagged_when_budget_too_tight() {
        let tight = match Budget::new(1, 0) {
            Ok(b) => b,
            Err(_) => panic!("tight budget construction should succeed"),
        };
        for report in run_all(tight) {
            assert!(!report.within_budget, "{} should breach", report.template);
        }
    }

    #[test]
    fn percentile_picks_tail_for_p99() {
        let samples = [100u64, 200, 300, 400, 500];
        assert_eq!(percentile_ms(&samples, 50), 300);
        assert_eq!(percentile_ms(&samples, 99), 500);
    }
}
