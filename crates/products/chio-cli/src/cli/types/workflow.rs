use super::*;

#[derive(Subcommand)]
pub(crate) enum WorkflowCommands {
    /// Validate a read-only workflow preflight plan.
    Preflight {
        /// Path to a chio.workflow.preflight-plan.v1 JSON artifact.
        #[arg(long, value_name = "PATH")]
        plan: PathBuf,
    },
}
