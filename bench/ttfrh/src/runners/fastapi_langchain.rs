use crate::{RunnerPlan, TemplateRunner};

// Synthetic samples (milliseconds) from the reference 4-core Linux runner.
// The container lane in `.github/workflows/ttfrh.yml` overwrites these with
// live samples.
const SAMPLES_MS: &[u64] = &[38_400, 41_200, 43_700, 45_100, 47_900];

pub fn plan() -> RunnerPlan {
    RunnerPlan {
        template: TemplateRunner::FastapiLangchain,
        command: "npx create-chio-app fastapi-langchain && cd fastapi-langchain && uv sync --frozen && uv run python -c 'import app.main'",
        advisory: false,
        synthetic_samples_ms: SAMPLES_MS,
    }
}
