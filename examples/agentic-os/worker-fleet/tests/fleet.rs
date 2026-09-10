use chio_agent_os_shared::{json, Application, Run};
use chio_worker_fleet::{run_fleet, Fleet};
#[tokio::test]
async fn competing_processes_share_spending_and_reconcile_after_restart() -> anyhow::Result<()> {
    let app = Fleet;
    let input = app.sample();
    let run = Run::create(
        &std::env::temp_dir().join("chio-fleet-tests"),
        app.name(),
        &input,
    )?;
    let result = run_fleet(
        input,
        run.clone(),
        env!("CARGO_BIN_EXE_chio-worker-fleet").into(),
    )
    .await?;
    assert_eq!(result["accounting"]["spent"], 40);
    assert_eq!(result["accounting"]["available"], 10);
    assert_eq!(result["accounting"], result["after_restart"]);
    let jobs = result["jobs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing jobs"))?;
    assert_eq!(jobs.iter().filter(|j| j["state"] == "completed").count(), 2);
    assert_eq!(jobs.iter().filter(|j| j["state"] == "refused").count(), 2);
    let mut pids = std::collections::BTreeSet::new();
    for worker in result["workers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing workers"))?
    {
        assert!(pids.insert(worker["pid"].as_u64()));
    }
    assert_eq!(pids.len(), 3);
    let reportdir = run.directory()?.join("fleet/reports");
    for job in jobs {
        let id = job["operation_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing ID"))?;
        assert_eq!(
            reportdir.join(format!("{id}.json")).exists(),
            job["state"] == "completed"
        );
    }
    Ok(())
}
#[tokio::test]
async fn queued_cancellation_has_no_report_and_no_receipt() -> anyhow::Result<()> {
    let app = Fleet;
    let mut input = app.sample();
    input["sections"] = json!(["summary", "terms"]);
    input["cancel_index"] = json!(0);
    input["allowance"] = json!(40);
    input["lose_ack_index"] = json!(null);
    let run = Run::create(
        &std::env::temp_dir().join("chio-fleet-tests"),
        app.name(),
        &input,
    )?;
    let result = run_fleet(
        input,
        run.clone(),
        env!("CARGO_BIN_EXE_chio-worker-fleet").into(),
    )
    .await?;
    assert_eq!(result["accounting"]["spent"], 20);
    assert_eq!(result["jobs"][0]["state"], "cancelled_before_dispatch");
    assert!(result["jobs"][0]["outcome"]["receipt_id"].is_null());
    Ok(())
}
