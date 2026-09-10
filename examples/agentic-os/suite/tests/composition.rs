use anyhow::Result;
use chio_agent_os_shared::{Application, Run};
#[tokio::test]
async fn composed_chapters_publish_the_exact_candidate_after_joint_compute() -> Result<()> {
    let app = chio_suite::Suite;
    let input = app.sample();
    let run = Run::create(
        &std::env::temp_dir().join("chio-suite-tests"),
        app.name(),
        &input,
    )?;
    let output = chio_suite::compose(input, run, env!("CARGO_BIN_EXE_chio-suite").into()).await?;
    assert_eq!(output["published"], true);
    assert_eq!(output["cooperative"]["effects"], 1);
    assert_eq!(
        output["factory"]["candidate_sha256"],
        output["publication"]["candidate_sha256"]
    );
    Ok(())
}
