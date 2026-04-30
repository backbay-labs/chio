use crate::{RunnerPlan, TemplateRunner};

pub fn plan() -> RunnerPlan {
    RunnerPlan {
        template: TemplateRunner::FastapiLangchain,
        command: "npx create-chio-app fastapi-langchain",
        advisory: true,
    }
}
