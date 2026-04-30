use crate::{RunnerPlan, TemplateRunner};

pub fn plan() -> RunnerPlan {
    RunnerPlan {
        template: TemplateRunner::CloudflareWorker,
        command: "npx create-chio-app cloudflare-worker",
        advisory: true,
    }
}
