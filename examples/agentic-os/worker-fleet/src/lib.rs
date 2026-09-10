pub mod report;
pub mod server;
use anyhow::{Context, Result};
use chio_agent_os_shared::{
    async_trait,
    host::{text, write_json},
    json, Application, Run, Value,
};
use std::{collections::BTreeMap, path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

pub struct Fleet;
#[async_trait]
impl Application for Fleet {
    fn name(&self) -> &'static str {
        "worker-fleet"
    }
    fn title(&self) -> &'static str {
        "One allowance. Many workers."
    }
    fn description(&self) -> &'static str {
        "Independent worker processes compete for report jobs through one authoritative host. Retain spending and reconcile lost acknowledgements."
    }
    fn sample(&self) -> Value {
        json!({"document":"# Release readiness\n\nThe team must retain receipts and operation IDs.\n\n- [ ] Review the exact release candidate\n- [ ] Verify recovery after a missing response\n\nRead https://chio.computer/docs for the full guide.","sections":["summary","terms","actions","links"],"concurrency":3,"allowance":50,"lose_ack_index":0,"restart":true})
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        run_fleet(input, run, std::env::current_exe()?).await
    }
}

pub async fn process(config: &server::Config, executable: &PathBuf) -> Result<(Child, Value)> {
    let configfile = config.directory.join("service-config.json");
    write_json(&configfile, &json!(config))?;
    let mut child = Command::new(executable)
        .arg("--host")
        .arg(&configfile)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().context("Host has no readiness pipe")?;
    let mut lines = BufReader::new(stdout).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
        .await??
        .context("Host stopped before readiness")?;
    Ok((child, serde_json::from_str(&line)?))
}
pub async fn snapshot(client: &reqwest::Client, url: &str, key: &str) -> Result<Value> {
    Ok(client
        .get(format!("{url}/snapshot"))
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
fn copy_events(run: &Run, capture: &Value, next: &mut usize) -> Result<()> {
    let events = capture["events"]
        .as_array()
        .context("Host returned no event stream")?;
    for event in events.iter().skip(*next) {
        let mut data = event["data"].clone();
        data["source_run_id"] = capture["id"].clone();
        run.emit(
            event["kind"].as_str().context("Missing event kind")?,
            event["actor"].as_str().context("Missing actor")?,
            event["title"].as_str().context("Missing event title")?,
            data,
        )?;
    }
    *next = events.len();
    Ok(())
}
pub async fn run_fleet(input: Value, run: Run, executable: PathBuf) -> Result<Value> {
    text(&input, "document", 64_000)?;
    let sections = input["sections"].as_array().context("Choose sections")?;
    anyhow::ensure!(
        !sections.is_empty()
            && sections.len() <= 8
            && sections
                .iter()
                .all(|s| ["summary", "terms", "actions", "links"]
                    .contains(&s.as_str().unwrap_or(""))),
        "Choose 1 to 8 supported report sections"
    );
    let concurrency = input["concurrency"].as_u64().unwrap_or(3);
    anyhow::ensure!((1..=4).contains(&concurrency), "Concurrency must be 1 to 4");
    let allowance = input["allowance"].as_u64().unwrap_or(50);
    anyhow::ensure!(
        (1..=160).contains(&allowance),
        "Allowance must be 1 to 160 local credits"
    );
    let workers: BTreeMap<String, String> = (0..concurrency)
        .map(|i| {
            (
                format!("worker-{}", i + 1),
                uuid::Uuid::new_v4().to_string(),
            )
        })
        .collect();
    let directory = run.directory()?.join("fleet");
    chio_agent_os_shared::host::private_directory(&directory)?;
    let config = server::Config {
        directory,
        input: input.clone(),
        workers: workers.clone(),
        admin: uuid::Uuid::new_v4().to_string(),
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let (mut host, ready) = process(&config, &executable).await?;
    let mut url = ready["url"].as_str().context("Host has no URL")?.to_owned();
    run.emit(
        "fleet.started",
        "operator",
        "Started the authoritative host",
        json!({
            "pid":ready["pid"],
            "kernel_key":ready["kernel_key"],
            "workers":workers.keys().collect::<Vec<_>>(),
            "allowance":allowance,
            "transport":"HTTP over loopback; separate OS processes"
        }),
    )?;
    let initial = snapshot(&client, &url, &config.admin).await?;
    if let Some(index) = input["cancel_index"].as_u64() {
        let id = initial["jobs"][index as usize]["operation_id"]
            .as_str()
            .context("Cancel index is outside the queue")?;
        client
            .post(format!("{url}/cancel/{id}"))
            .bearer_auth(&config.admin)
            .send()
            .await?
            .error_for_status()?;
        run.emit(
            "fleet.cancelled",
            "operator",
            "Cancelled a queued job before kernel dispatch",
            json!({"operation_id":id,"receipt_id":null}),
        )?;
    }
    let mut children = Vec::new();
    for (id, key) in &workers {
        let mut worker = Command::new(&executable)
            .arg("--worker")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = worker
            .stdin
            .take()
            .context("Worker has no configuration pipe")?;
        stdin
            .write_all(serde_json::to_string(&json!({"url":url,"key":key,"id":id}))?.as_bytes())
            .await?;
        stdin.shutdown().await?;
        run.emit(
            "fleet.worker_started",
            id,
            "Worker connected to its host",
            json!({"pid":worker.id()}),
        )?;
        children.push(worker);
    }
    let mut next = 0;
    let mut last;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "Fleet timed out; inspect its retained operation records"
        );
        last = snapshot(&client, &url, &config.admin).await?;
        copy_events(&run, &last["capture"], &mut next)?;
        let mut done = true;
        for child in &mut children {
            if child.try_wait()?.is_none() {
                done = false;
            }
        }
        if done {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let mut worker_results = Vec::new();
    for child in children {
        let output = child.wait_with_output().await?;
        anyhow::ensure!(output.status.success(), "A worker process failed");
        worker_results.push(serde_json::from_slice::<Value>(&output.stdout)?);
    }
    // Resolve lost acknowledgements only after the requested host death and restart.
    let before = last["accounting"].clone();
    let mut after = Value::Null;
    if input["restart"] == true {
        host.kill().await?;
        host.wait().await?;
        run.emit(
            "fleet.host_stopped",
            "operator",
            "Stopped the host before reconciliation",
            json!({"pid":ready["pid"],"accounting":before,"reconciled":false}),
        )?;
        let (replacement, restarted) = process(&config, &executable).await?;
        host = replacement;
        url = restarted["url"]
            .as_str()
            .context("Restarted host has no URL")?
            .to_owned();
        last = snapshot(&client, &url, &config.admin).await?;
        after = last["accounting"].clone();
        anyhow::ensure!(
            before == after && ready["kernel_key"] == restarted["kernel_key"],
            "Restart changed authoritative accounting or identity"
        );
        next = 0;
        run.emit("fleet.host_restarted", "operator", "Restart retained the original allowance and report records",
            json!({"old_pid":ready["pid"],"new_pid":restarted["pid"],"accounting":after,"kernel_key":restarted["kernel_key"]}))?;
    }
    let mut reconciliations = Vec::new();
    for job in last["jobs"].as_array().context("Missing jobs")? {
        let id = job["operation_id"]
            .as_str()
            .context("Missing operation ID")?;
        let resolved: Value = client
            .post(format!("{url}/reconcile/{id}"))
            .bearer_auth(&config.admin)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        reconciliations.push(json!({"operation_id":id,"resolution":resolved,"after_host_restart":input["restart"]==true}));
    }
    last = snapshot(&client, &url, &config.admin).await?;
    copy_events(&run, &last["capture"], &mut next)?;
    host.kill().await?;
    host.wait().await?;
    Ok(json!({
        "jobs":last["jobs"],
        "accounting":before,
        "after_restart":after,
        "reconciliations":reconciliations,
        "workers":worker_results,
        "kernel_key":ready["kernel_key"]
    }))
}
pub async fn worker() -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut input = Vec::new();
    tokio::io::stdin()
        .take(4096)
        .read_to_end(&mut input)
        .await?;
    let config: Value = serde_json::from_slice(&input)?;
    let url = config["url"].as_str().context("Worker has no host")?;
    let key = config["key"].as_str().context("Worker has no credential")?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let mut outcomes = Vec::new();
    loop {
        let claim: Value = client
            .post(format!("{url}/claim"))
            .bearer_auth(key)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if claim["job"].is_null() {
            break;
        }
        let job = &claim["job"];
        if config["hold_after_claim"] == true {
            use std::io::Write;
            println!(
                "{}",
                json!({"worker":config["id"],"pid":std::process::id(),"job":job})
            );
            std::io::stdout().flush()?;
            std::future::pending::<()>().await;
        }
        let response = client
            .post(format!("{url}/execute"))
            .bearer_auth(key)
            .json(&json!({"operation_id":job["operation_id"],"claim":job["claim"]}))
            .send()
            .await?;
        let status = response.status().as_u16();
        let response: Value = response.json().await?;
        outcomes.push(
            json!({"operation_id":job["operation_id"],"http_status":status,"response":response}),
        );
    }
    println!(
        "{}",
        json!({"worker":config["id"],"pid":std::process::id(),"outcomes":outcomes})
    );
    Ok(())
}
