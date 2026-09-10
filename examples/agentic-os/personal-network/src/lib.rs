pub mod directory;
pub mod joint;
pub mod node;
pub mod wire;
use anyhow::{Context, Result};
use chio_agent_os_shared::{
    async_trait,
    events::now_ms,
    graph::digest,
    host::{private_directory, text, write_json},
    json, Application, Run, Value,
};
use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
use directory::Enrollment;
use std::{collections::BTreeMap, path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
};
pub struct Personal;
pub struct Process {
    pub child: Child,
    pub config: node::Config,
    pub enrollment: Enrollment,
}
impl Process {
    pub async fn start(config: node::Config, executable: &PathBuf) -> Result<Self> {
        private_directory(&config.root)?;
        let path = config.root.join("node-config.json");
        write_json(&path, &json!(config))?;
        let mut child = Command::new(executable)
            .arg("--node")
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut lines = BufReader::new(
            child
                .stdout
                .take()
                .context("Node has no readiness stream")?,
        )
        .lines();
        let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
            .await??
            .context("Node stopped before announcing its address")?;
        let enrollment = serde_json::from_str(&line)?;
        Ok(Self {
            child,
            config,
            enrollment,
        })
    }
    pub async fn post(&self, path: &str, input: Value) -> Result<Value> {
        let response = reqwest::Client::new()
            .post(format!("{}{path}", self.enrollment.http_url))
            .bearer_auth(&self.config.admin_token)
            .json(&input)
            .timeout(std::time::Duration::from_secs(25))
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        anyhow::ensure!(
            status.is_success(),
            "Node request {path} failed ({status}): {text}"
        );
        Ok(serde_json::from_str(&text)?)
    }
    pub async fn status(&self) -> Result<Value> {
        Ok(reqwest::Client::new()
            .get(format!("{}/status", self.enrollment.http_url))
            .timeout(std::time::Duration::from_secs(25))
            .bearer_auth(&self.config.admin_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn stop(&mut self) -> Result<()> {
        self.child.kill().await?;
        let _ = self.child.wait().await?;
        Ok(())
    }
}
#[async_trait]
impl Application for Personal {
    fn name(&self) -> &'static str {
        "personal-network"
    }
    fn title(&self) -> &'static str {
        "An assistant with independently governed nodes"
    }
    fn description(&self) -> &'static str {
        "A coordinator queries private knowledge, calls a bounded compute service, and delivers signed observations over Iroh."
    }
    fn sample(&self) -> Value {
        json!({
            "question":"What should survive a restart, and how do we handle a missing acknowledgement?",
            "document":"# Private recovery notes\nRetain operation IDs, signed receipts, and budget balances across a host restart.\nA missing acknowledgement requires checking the operation record before another attempt.\n",
            "values":[
                14,
                18,
                22,
                26
            ],
            "exercise_lifecycle":true,
            "relay":false
        })
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        run_network(input, run, std::env::current_exe()?).await
    }
}
pub async fn run_network(input: Value, run: Run, executable: PathBuf) -> Result<Value> {
    let question = text(&input, "question", 2000)?;
    let document = text(&input, "document", 64_000)?;
    let root = run.directory()?;
    let issuer = directory::key(&root.join("directory-owner.key"))?;
    let mut nodes = Vec::new();
    for role in ["coordinator", "knowledge", "compute"] {
        nodes.push(
            Process::start(
                node::Config {
                    root: root.join(role),
                    role: role.into(),
                    directory_issuer: issuer.public_key(),
                    joint_policy: None,
                    admin_token: uuid::Uuid::new_v4().to_string(),
                    http_bind: "127.0.0.1:0".into(),
                    http_public_url: None,
                    relay: input["relay"] == true,
                    document: if role == "knowledge" {
                        document.into()
                    } else {
                        String::new()
                    },
                },
                &executable,
            )
            .await?,
        );
    }
    let entries = nodes
        .iter()
        .map(|n| n.enrollment.entry.clone())
        .collect::<Vec<_>>();
    let mut bundles = BTreeMap::<String, TransportDirectoryBundleDocument>::new();
    for node in &nodes {
        let bundle = directory::bundle(
            &issuer,
            &node.enrollment.entry.kernel_id,
            entries.clone(),
            1,
            None,
            now_ms() + 300_000,
        )?;
        node.post("/directory", json!(bundle)).await?;
        bundles.insert(node.config.role.clone(), bundle);
    }
    run.emit(
        "network.ready",
        "operator",
        "Started and enrolled three independent node processes",
        json!({
            "nodes":nodes.iter().map(|n|&n.enrollment).collect::<Vec<_>>(),
            "protocols":{
                "tool_calls":"HTTP with passport-signed requests and per-node Chio capabilities",
                "observations":"Chio Iroh directed-batch lane over QUIC"
            }
        }),
    )?;
    let coordinator = &nodes[0];
    let knowledge = &nodes[1];
    let compute = &nodes[2];
    let knowledge_cap = knowledge
        .post(
            "/grant",
            json!({"peer":coordinator.enrollment.entry.kernel_id}),
        )
        .await?;
    let compute_cap = compute
        .post(
            "/grant",
            json!({"peer":coordinator.enrollment.entry.kernel_id}),
        )
        .await?;
    let retrieved = coordinator
        .post(
            "/dispatch",
            json!({
                "peer":knowledge.enrollment,
                "capability":knowledge_cap["capability"],
                "tool":"retrieve",
                "arguments":{
                    "question":question
                }
            }),
        )
        .await?;
    anyhow::ensure!(
        retrieved["allowed"] == true && !retrieved["output"].is_null(),
        "Knowledge retrieval did not finish"
    );
    let computed = coordinator
        .post(
            "/dispatch",
            json!({
                "peer":compute.enrollment,
                "capability":compute_cap["capability"],
                "tool":"statistics",
                "arguments":{
                    "values":input["values"]
                }
            }),
        )
        .await?;
    anyhow::ensure!(
        computed["allowed"] == true && !computed["output"].is_null(),
        "Compute task did not finish"
    );
    let wire = coordinator
        .post(
            "/wire",
            json!({
                "peer":knowledge.enrollment,
                "observation":{
                    "task":"statistics",
                    "receipt_id":computed["receipt_id"],
                    "result_sha256":digest(&computed["output"])?
                }
            }),
        )
        .await?;
    anyhow::ensure!(
        wire["accepted"] == true,
        "Knowledge node refused the signed task observation"
    );
    let mut lifecycle = json!({});
    if input["exercise_lifecycle"] == true {
        let outsider = Process::start(
            node::Config {
                root: root.join("unknown"),
                role: "coordinator".into(),
                directory_issuer: issuer.public_key(),
                joint_policy: None,
                admin_token: uuid::Uuid::new_v4().to_string(),
                http_bind: "127.0.0.1:0".into(),
                http_public_url: None,
                relay: false,
                document: String::new(),
            },
            &executable,
        )
        .await?;
        let mut outsider_peers = entries.clone();
        outsider_peers.push(outsider.enrollment.entry.clone());
        outsider
            .post(
                "/directory",
                json!(directory::bundle(
                    &issuer,
                    &outsider.enrollment.entry.kernel_id,
                    outsider_peers,
                    1,
                    None,
                    now_ms() + 300_000
                )?),
            )
            .await?;
        let before = knowledge.status().await?;
        let unknown = outsider
            .post(
                "/wire",
                json!({"peer":knowledge.enrollment,"observation":{"attempt":"unknown peer"}}),
            )
            .await;
        anyhow::ensure!(
            unknown.is_err(),
            "Unknown peer reached the observation receiver"
        );
        coordinator
            .post("/hold", json!({"peer":knowledge.enrollment}))
            .await?;
        let old = bundles
            .get("knowledge")
            .context("Knowledge directory missing")?;
        let mut removed = entries.clone();
        for peer in &mut removed {
            if peer.kernel_id == coordinator.enrollment.entry.kernel_id {
                peer.removed = true;
            }
        }
        let successor = directory::bundle(
            &issuer,
            &knowledge.enrollment.entry.kernel_id,
            removed,
            2,
            Some(digest(&old.body)?),
            now_ms() + 300_000,
        )?;
        knowledge.post("/directory", json!(successor)).await?;
        let existing = coordinator
            .post(
                "/held-send",
                json!({"recipient":knowledge.enrollment.entry.kernel_id}),
            )
            .await?;
        anyhow::ensure!(
            existing["accepted"] == false,
            "Removed peer delivered on an existing connection"
        );
        let fresh = coordinator
            .post(
                "/wire",
                json!({"peer":knowledge.enrollment,"observation":{"attempt":"removed"}}),
            )
            .await;
        anyhow::ensure!(
            fresh.is_err(),
            "Removed peer opened a new accepted observation connection"
        );
        let removed_call = coordinator
            .post(
                "/dispatch",
                json!({
                    "peer":knowledge.enrollment,
                    "capability":knowledge_cap["capability"],
                    "tool":"retrieve",
                    "arguments":{
                        "question":question
                    }
                }),
            )
            .await;
        anyhow::ensure!(
            removed_call.is_err(),
            "Removed peer reached a protected tool handler"
        );
        anyhow::ensure!(
            knowledge.status().await?["effects"] == before["effects"],
            "Membership denial changed protected handler count"
        );
        let rollback = knowledge.post("/directory", json!(old)).await;
        anyhow::ensure!(rollback.is_err(), "A rolled-back directory was installed");
        let expired = directory::bundle(
            &issuer,
            &knowledge.enrollment.entry.kernel_id,
            entries.clone(),
            3,
            Some(digest(&successor.body)?),
            now_ms().saturating_sub(1),
        )?;
        let expired = knowledge.post("/directory", json!(expired)).await;
        anyhow::ensure!(expired.is_err(), "An expired directory was installed");
        let rejoin = directory::bundle(
            &issuer,
            &knowledge.enrollment.entry.kernel_id,
            entries.clone(),
            3,
            Some(digest(&successor.body)?),
            now_ms() + 300_000,
        )?;
        knowledge.post("/directory", json!(rejoin)).await?;
        let reconnected = coordinator
            .post(
                "/wire",
                json!({
                    "peer":knowledge.enrollment,
                    "observation":{
                        "task":"reconnection",
                        "status":"new signed directory admitted the coordinator"
                    }
                }),
            )
            .await?;
        anyhow::ensure!(
            reconnected["accepted"] == true,
            "A restored peer failed to reconnect"
        );
        lifecycle = json!({
            "unknown_peer_refused":true,
            "new_connection_after_removal_refused":true,
            "existing_connection_after_removal":existing,
            "removed_peer_tool_call_refused":true,
            "rollback_refused":true,
            "expired_directory_refused":true,
            "reconnected":reconnected
        });
    }
    let mut captures = Vec::new();
    for node in &nodes {
        let capture = node.status().await?;
        for event in capture["run"]["events"]
            .as_array()
            .context("Node event stream missing")?
        {
            let mut data = event["data"].clone();
            data["source_run_id"] = capture["run"]["id"].clone();
            run.emit(
                event["kind"].as_str().context("Event kind missing")?,
                event["actor"].as_str().context("Event actor missing")?,
                event["title"].as_str().context("Event title missing")?,
                data,
            )?;
        }
        captures.push(capture);
    }
    if input["exercise_lifecycle"] == true {
        // Stop and restart an actual compute process, using its retained identity and accounting.
        let old_compute = nodes[2].enrollment.clone();
        let config = nodes[2].config.clone();
        nodes[2].stop().await?;
        let offline = nodes[0]
            .post(
                "/dispatch",
                json!({
                    "peer":old_compute,
                    "capability":compute_cap["capability"],
                    "tool":"statistics",
                    "arguments":{
                        "values":input["values"]
                    }
                }),
            )
            .await;
        anyhow::ensure!(
            offline.is_err(),
            "Offline node returned an invented completed result"
        );
        let restored = Process::start(config, &executable).await?;
        anyhow::ensure!(
            restored.enrollment.kernel_key == old_compute.kernel_key
                && restored.enrollment.entry == old_compute.entry,
            "Restart changed the node's retained identity"
        );
        let recovered = nodes[0]
            .post(
                "/dispatch",
                json!({
                    "peer":restored.enrollment,
                    "capability":compute_cap["capability"],
                    "tool":"statistics",
                    "arguments":{
                        "values":input["values"]
                    }
                }),
            )
            .await?;
        anyhow::ensure!(
            recovered["allowed"] == true,
            "Restart failed to preserve the original grant"
        );
        lifecycle["offline_call_unresolved"] = json!(true);
        lifecycle["restarted_with_same_identity"] = json!(true);
        lifecycle["new_task_after_restart"] = recovered;
    }
    Ok(json!({
        "question":question,
        "knowledge":retrieved,
        "computation":computed,
        "observation_delivery":wire,
        "lifecycle":lifecycle,
        "nodes":captures,
        "protocols":{
            "task_calls":"Passport-authenticated HTTP into each node's kernel",
            "observations":"Iroh federation lane with receiver-owned signature, treaty, replay, and scarcity checks"
        },
        "topology":"Three independent processes; the coordinator holds no worker-node signing keys"
    }))
}
