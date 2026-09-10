use anyhow::{Context, Result};
use chio_agent_os_shared::{async_trait, host::private_directory, json, Application, Run, Value};
use chio_worker_fleet::{process, server::Config, snapshot, Fleet};
use std::{collections::BTreeMap, path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};
pub struct Operations;
#[async_trait]
impl Application for Operations {
    fn name(&self) -> &'static str {
        "operations"
    }
    fn title(&self) -> &'static str {
        "Recover an operating system without guessing its effects"
    }
    fn description(&self) -> &'static str {
        "Stop real workers and hosts, inspect their retained authority and effects, and reconcile before deciding what can safely run again."
    }
    fn sample(&self) -> Value {
        json!({"exercise":"host-crash-during-report","document":Fleet.sample()["document"]})
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        exercise(input, run, std::env::current_exe()?).await
    }
}
pub async fn exercise(input: Value, run: Run, executable: PathBuf) -> Result<Value> {
    let exercise = input["exercise"]
        .as_str()
        .context("Select a recovery exercise")?;
    if ["lost-acknowledgement", "budget-exhaustion"].contains(&exercise) {
        let mut request = Fleet.sample();
        request["document"] = input["document"].clone();
        if exercise == "budget-exhaustion" {
            request["allowance"] = json!(30);
        }
        let child = Run::create(&run.directory()?.join("fleet-runs"), Fleet.name(), &request)?;
        let result = chio_worker_fleet::run_fleet(request, child.clone(), executable).await;
        child.finish(&result)?;
        let output = result?;
        run.emit(
            "operations.fleet",
            "operator",
            "Actual fleet restart followed by effect reconciliation",
            child.snapshot()?,
        )?;
        return Ok(json!({"exercise":exercise,"fleet":output}));
    }
    if exercise == "peer-removal" {
        let app = chio_personal_network::Personal;
        let mut request = app.sample();
        request["document"] = input["document"].clone();
        let child = Run::create(&run.directory()?.join("network-runs"), app.name(), &request)?;
        let result = chio_personal_network::run_network(request, child.clone(), executable).await;
        child.finish(&result)?;
        let output = result?;
        run.emit(
            "operations.network",
            "operator",
            "Live peer removal and restoration across node processes",
            child.snapshot()?,
        )?;
        return Ok(json!({"exercise":exercise,"network":output}));
    }
    anyhow::ensure!(
        [
            "worker-crash-before-dispatch",
            "host-crash-during-report",
            "cancel-running-report",
            "expired-authority"
        ]
        .contains(&exercise),
        "Choose a documented recovery exercise"
    );
    let root = run.directory()?.join("service");
    private_directory(&root)?;
    let config = Config {
        directory: root.clone(),
        input: json!({
            "document":input["document"],
            "sections":[
                "summary"
            ],
            "allowance":40,
            "capability_ttl_seconds":if exercise=="expired-authority" {
                2
            }else{
                900
            }
        }),
        workers: BTreeMap::from([("report-worker".into(), uuid::Uuid::new_v4().to_string())]),
        admin: uuid::Uuid::new_v4().to_string(),
    };
    let key = config
        .workers
        .get("report-worker")
        .context("Missing worker credential")?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let (mut host, ready) = process(&config, &executable).await?;
    let url = ready["url"].as_str().context("No host URL")?;
    let mut worker = Command::new(&executable)
        .arg("--worker")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = worker.stdin.take().context("Worker input missing")?;
    stdin
        .write_all(
            serde_json::to_string(
                &json!({"url":url,"key":key,"id":"report-worker","hold_after_claim":true}),
            )?
            .as_bytes(),
        )
        .await?;
    stdin.shutdown().await?;
    drop(stdin);
    let mut lines =
        BufReader::new(worker.stdout.take().context("Worker readiness missing")?).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line())
        .await??
        .context("Worker stopped before claiming")?;
    let claim: Value = serde_json::from_str(&line)?;
    let id = claim["job"]["operation_id"]
        .as_str()
        .context("Missing operation")?
        .to_owned();
    run.emit(
        "operations.claimed",
        "report-worker",
        "Independent worker retained its job claim",
        json!({"pid":claim["pid"],"operation_id":id}),
    )?;
    let mut in_flight = None;
    if ["host-crash-during-report", "cancel-running-report"].contains(&exercise) {
        let request = client
            .post(format!("{url}/execute"))
            .bearer_auth(key)
            .json(&json!({"operation_id":id,"claim":claim["job"]["claim"]}));
        in_flight = Some(tokio::spawn(async move { request.send().await }));
        let partial = root.join("reports").join(format!("{id}.partial.json"));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !partial.exists() {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "The tool did not reach its first retained partial result"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        run.emit(
            "operations.effect_started",
            "report-host",
            "The governed report has written partial output",
            serde_json::from_slice(&std::fs::read(partial)?)?,
        )?;
    }
    if exercise == "expired-authority" {
        tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
        let expired: Value = client
            .post(format!("{url}/execute"))
            .bearer_auth(key)
            .json(&json!({"operation_id":id,"claim":claim["job"]["claim"]}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        anyhow::ensure!(
            expired["allowed"] == false && expired["output"].is_null(),
            "Expired authority reached the report tool"
        );
        run.emit(
            "operations.expired",
            "report-host",
            "Expired authority was refused before handler entry",
            expired,
        )?;
    }
    let before = snapshot(&client, url, &config.admin).await?;
    if exercise == "cancel-running-report" {
        client
            .post(format!("{url}/cancel/{id}"))
            .bearer_auth(&config.admin)
            .send()
            .await?
            .error_for_status()?;
        if let Some(task) = in_flight.take() {
            let _ = task.await?;
        }
        run.emit(
            "operations.cancelled",
            "operator",
            "Requested cancellation while the tool was running",
            json!({"operation_id":id}),
        )?;
    }
    worker.kill().await?;
    worker.wait().await?;
    host.kill().await?;
    host.wait().await?;
    if let Some(task) = in_flight {
        let _ = task.await?;
    }
    run.emit("operations.processes_stopped","operator","Worker and authoritative host processes have stopped",json!({"worker_pid":claim["pid"],"host_pid":ready["pid"],"crash_point":exercise,"accounting":before["accounting"]}))?;
    let (mut replacement, restarted) = process(&config, &executable).await?;
    let url = restarted["url"].as_str().context("No replacement URL")?;
    let recovered = snapshot(&client, url, &config.admin).await?;
    let stale = client
        .post(format!("{url}/execute"))
        .bearer_auth(key)
        .json(&json!({"operation_id":id,"claim":claim["job"]["claim"]}))
        .send()
        .await?;
    let stale_status = stale.status();
    let stale_body: Value = stale.json().await?;
    anyhow::ensure!(
        !stale_status.is_success(),
        "A stale worker claim was accepted after restart"
    );
    let resolution: Value = client
        .post(format!("{url}/reconcile/{id}"))
        .bearer_auth(&config.admin)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let final_state = snapshot(&client, url, &config.admin).await?;
    anyhow::ensure!(
        !root.join("reports").join(format!("{id}.json")).exists(),
        "Interrupted report unexpectedly published"
    );
    anyhow::ensure!(
        ready["kernel_key"] == restarted["kernel_key"],
        "Restart replaced the trusted host identity"
    );
    if exercise != "cancel-running-report" {
        anyhow::ensure!(
            before["accounting"] == recovered["accounting"],
            "Crash recovery reset retained admission accounting"
        );
    }
    run.emit(
        "operations.reconciled",
        "operator",
        "Retained state refused the stale worker and left incomplete work unresolved",
        json!({
            "restarted_pid":restarted["pid"],
            "operation_id":id,
            "stale_request":stale_body,
            "resolution":resolution,
            "accounting":final_state["accounting"]
        }),
    )?;
    replacement.kill().await?;
    replacement.wait().await?;
    Ok(json!({
        "exercise":exercise,
        "operation_id":id,
        "before":before["accounting"],
        "after":final_state["accounting"],
        "resolution":resolution,
        "stale_worker":{
            "http_status":stale_status.as_u16(),
            "response":stale_body
        },
        "published":false,
        "identity_retained":true,
        "recovery":"No automatic retry: the adapter has no completed effect to return. Inspect partial output and retained admission before explicitly scheduling replacement work."
    }))
}
