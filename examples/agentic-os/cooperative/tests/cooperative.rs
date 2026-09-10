use anyhow::Result;
use chio_agent_os_shared::{json, Application, Run};
#[tokio::test]
async fn independent_member_policy_controls_an_exact_once_useful_effect() -> Result<()> {
    let app = chio_cooperative::Cooperative;
    let input = app.sample();
    let root = std::env::temp_dir().join("chio-cooperative-tests");
    let run = Run::create(&root, app.name(), &input)?;
    let result = chio_cooperative::execute_bilateral(
        input.clone(),
        run,
        env!("CARGO_BIN_EXE_chio-cooperative").into(),
    )
    .await?;
    assert_eq!(result["computation"]["output"]["mean"], 24.0);
    assert_eq!(result["effects"], 1);
    let mut denied = input;
    denied["member_budget"] = json!(2);
    let run = Run::create(&root, app.name(), &denied)?;
    let result = chio_cooperative::execute_bilateral(
        denied,
        run,
        env!("CARGO_BIN_EXE_chio-cooperative").into(),
    )
    .await?;
    assert_eq!(result["status"], "denied");
    assert_eq!(result["effects"], 0);
    Ok(())
}
