use anyhow::Result;
use chio_agent_os_shared::{Application, Run};
#[tokio::test]
async fn real_venue_delivers_a_repair_and_retains_the_purchase_terminal() -> Result<()> {
    let app = chio_cognition_marketplace::Marketplace;
    let input = app.sample();
    let run = Run::create(
        &std::env::temp_dir().join("chio-market-tests"),
        app.name(),
        &input,
    )?;
    let result = app.execute(input, run).await?;
    assert_eq!(result["status"], "completed");
    assert_eq!(result["customer"]["before"]["passed"], false);
    assert_eq!(result["customer"]["after"]["passed"], true);
    assert_eq!(result["denials"]["tampered_proof"]["refused"], true);
    assert_eq!(result["purchase"]["purchase"]["settlement"], "captured");
    Ok(())
}
