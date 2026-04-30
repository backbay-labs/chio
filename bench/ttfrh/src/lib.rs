#![forbid(unsafe_code)]

use std::fmt;

pub mod runners;

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
    pub advisory: bool,
}

pub fn runner_plans() -> [RunnerPlan; 3] {
    [
        runners::next_ai_sdk_receipts::plan(),
        runners::fastapi_langchain::plan(),
        runners::cloudflare_worker::plan(),
    ]
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
    fn scaffold_is_advisory_until_p5() {
        for plan in runner_plans() {
            assert!(
                plan.advisory,
                "{} runner must stay advisory in P0",
                plan.template
            );
            assert!(!plan.command.trim().is_empty());
        }
    }
}
