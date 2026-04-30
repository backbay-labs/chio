use crate::{RunnerPlan, TemplateRunner};

pub fn plan() -> RunnerPlan {
    RunnerPlan {
        template: TemplateRunner::NextAiSdkReceipts,
        command: "npx create-chio-app next-ai-sdk-receipts",
        advisory: true,
    }
}
