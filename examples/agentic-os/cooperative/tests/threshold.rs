use anyhow::Result;
use chio_agent_os_shared::{json, Application, Run};
#[tokio::test]
async fn distributed_dkg_authorizes_registered_settlement_and_preserves_exactly_one_debit(
) -> Result<()> {
    for (budget, expected) in [(8, "completed"), (2, "denied")] {
        let app = chio_cooperative::Cooperative;
        let mut input = app.sample();
        input["mode"] = json!("threshold");
        input["member_budget"] = json!(budget);
        let run = Run::create(
            &std::env::temp_dir().join("chio-threshold-tests"),
            "cooperative",
            &input,
        )?;
        let output = chio_cooperative::threshold::execute(
            input,
            run,
            env!("CARGO_BIN_EXE_chio-cooperative").into(),
        )
        .await?;
        assert_eq!(output["status"], expected);
        if expected == "completed" {
            assert_eq!(output["computation"]["output"]["mean"], 24.0);
            assert_eq!(output["state"]["credits"]["research"], 96);
            assert_eq!(output["state"]["completed_computations"], 1);
            assert!(output["denials"]["replay_after_restart"]["output"].is_null());
        } else {
            assert_eq!(output["state"]["credits"]["research"], 100);
            assert_eq!(output["state"]["completed_computations"], 0);
        }
    }
    Ok(())
}
