use crate::{RunnerPlan, TemplateRunner};

// Synthetic samples (milliseconds) from the reference 4-core Linux runner.
// The container lane in `.github/workflows/ttfrh.yml` overwrites these with
// live samples.
const SAMPLES_MS: &[u64] = &[42_100, 44_300, 45_900, 47_500, 49_800];

pub fn plan() -> RunnerPlan {
    RunnerPlan {
        template: TemplateRunner::NextAiSdkReceipts,
        command: "npx create-chio-app next-ai-sdk-receipts && cd next-ai-sdk-receipts && bun install --frozen-lockfile && bun run build",
        advisory: false,
        synthetic_samples_ms: SAMPLES_MS,
    }
}
