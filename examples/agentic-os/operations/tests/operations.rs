use anyhow::Result;
use chio_agent_os_shared::{json, Application, Run};
#[tokio::test]
async fn actual_process_death_keeps_uncertain_work_and_stale_claims_closed() -> Result<()> {
    let app = chio_operations::Operations;
    for exercise in [
        "worker-crash-before-dispatch",
        "host-crash-during-report",
        "cancel-running-report",
        "expired-authority",
    ] {
        let mut input = app.sample();
        input["exercise"] = json!(exercise);
        let run = Run::create(
            &std::env::temp_dir().join("chio-operations-tests"),
            app.name(),
            &input,
        )?;
        let output =
            chio_operations::exercise(input, run, env!("CARGO_BIN_EXE_chio-operations").into())
                .await?;
        assert_eq!(output["published"], false);
        assert_eq!(output["identity_retained"], true);
        assert!(output["stale_worker"]["http_status"].as_u64().unwrap_or(0) >= 400);
    }
    Ok(())
}

#[tokio::test]
async fn operation_controls_reuse_the_fleet_and_network_boundaries() -> Result<()> {
    let app = chio_operations::Operations;
    for exercise in ["lost-acknowledgement", "budget-exhaustion", "peer-removal"] {
        let mut input = app.sample();
        input["exercise"] = json!(exercise);
        let run = Run::create(
            &std::env::temp_dir().join("chio-operations-controls"),
            app.name(),
            &input,
        )?;
        let output = chio_operations::exercise(
            input,
            run.clone(),
            env!("CARGO_BIN_EXE_chio-operations").into(),
        )
        .await?;
        run.finish(&Ok(output.clone()))?;
        assert!(Run::capture(&run.directory()?.parent().unwrap(), &run.id()?).is_ok());
        match exercise {
            "peer-removal" => assert_eq!(
                output["network"]["lifecycle"]["removed_peer_tool_call_refused"],
                true
            ),
            "budget-exhaustion" => {
                assert!(output["fleet"]["accounting"]["spent"].as_u64().unwrap() <= 30)
            }
            _ => assert!(output["fleet"]["reconciliations"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())),
        }
    }
    Ok(())
}
