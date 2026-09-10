use anyhow::Result;
use chio_agent_os_shared::{Application, Run};
#[tokio::test]
async fn three_processes_execute_and_enforce_membership_on_real_connections() -> Result<()> {
    let app = chio_personal_network::Personal;
    let input = app.sample();
    let run = Run::create(
        &std::env::temp_dir().join("chio-personal-tests"),
        app.name(),
        &input,
    )?;
    let result = chio_personal_network::run_network(
        input,
        run,
        env!("CARGO_BIN_EXE_chio-personal-network").into(),
    )
    .await?;
    assert_eq!(result["computation"]["output"]["mean"], 20.0);
    assert_eq!(result["observation_delivery"]["accepted"], true);
    assert_eq!(
        result["lifecycle"]["existing_connection_after_removal"]["accepted"],
        false
    );
    let pids = result["nodes"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No nodes"))?
        .iter()
        .map(|v| v["pid"].as_u64())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(pids.len(), 3);
    Ok(())
}
