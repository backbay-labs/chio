use anyhow::Result;
use chio_agent_os_shared::{Application, Run};
use chio_research_swarm::Research;
#[tokio::test]
async fn actual_receiver_decay_changes_assignment_and_authority_still_controls_work() -> Result<()>
{
    let app = Research;
    let root = std::env::temp_dir().join("chio-research-tests");
    let input = app.sample();
    let run = Run::create(&root, app.name(), &input)?;
    let first = app.execute(input.clone(), run).await?;
    assert_eq!(first["order"][0], "contradiction");
    assert_eq!(first["adaptive"]["duplicate_executions"], 0);
    assert_eq!(first["adaptive"]["retained_after_reopen"], true);
    assert_eq!(first["denials"]["replay"]["accepted"], false);
    assert_eq!(first["denials"]["tampered"]["accepted"], false);
    assert_eq!(first["denials"]["scarcity"]["accepted"], false);
    let mut aged = input;
    aged["query_after_seconds"] = serde_json::json!(600);
    aged["remove_worker"] = serde_json::json!("reproduce");
    aged["exercise_denials"] = serde_json::json!(false);
    let run = Run::create(&root, app.name(), &aged)?;
    let second = app.execute(aged, run).await?;
    assert_eq!(second["order"][0], "reproduce");
    assert!(second["adaptive"]["refused"].as_u64().unwrap_or(0) > 0);
    assert!(second["adaptive"]["completed"].as_u64().unwrap_or(0) < 4);
    Ok(())
}
