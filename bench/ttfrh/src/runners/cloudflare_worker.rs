use crate::{RunnerPlan, TemplateRunner};

// Synthetic samples (milliseconds) from the reference 4-core Linux runner.
// The container lane in `.github/workflows/ttfrh.yml` overwrites these with
// live samples.
const SAMPLES_MS: &[u64] = &[35_900, 39_400, 41_700, 43_500, 45_200];

pub fn plan() -> RunnerPlan {
    RunnerPlan {
        template: TemplateRunner::CloudflareWorker,
        command: "npx create-chio-app cloudflare-worker && cd cloudflare-worker && bun install --frozen-lockfile && bun run build",
        advisory: false,
        synthetic_samples_ms: SAMPLES_MS,
    }
}
