use anyhow::{Context, Result};
use chio_megastart::workshop::{projection, setup::Setup, workspace};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

struct Host {
    root: PathBuf,
    child: tokio::process::Child,
    base: String,
    token: String,
    client: reqwest::Client,
}
impl Host {
    async fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!("chio-workshop-host-{}", Uuid::new_v4()));
        workspace::create(&root, Setup::reference())?;
        Self::open(root).await
    }
    async fn open(root: PathBuf) -> Result<Self> {
        Self::open_with_path(root, None).await
    }
    async fn open_with_path(root: PathBuf, path: Option<&str>) -> Result<Self> {
        let descriptor = root.join("connections/console.json");
        if descriptor.exists() {
            std::fs::remove_file(&descriptor)?;
        }
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_megastart"));
        if let Some(path) = path {
            command.env("PATH", path);
        }
        let child = command
            .args(["workshop", "--no-open", "--workspace"])
            .arg(&root)
            .env("MEGASTART_CONNECTIONS", root.join("agent-connections"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let connection = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if descriptor.is_file() {
                    return chio_megastart::read::<Value>(&descriptor);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        Ok(Self {
            root,
            child,
            base: connection["endpoint"]
                .as_str()
                .context("Endpoint missing")?
                .into(),
            token: connection["token"]
                .as_str()
                .context("Token missing")?
                .into(),
            client: reqwest::Client::new(),
        })
    }
    async fn get(&self, path: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}/api/workshop/v1/{path}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?;
        let status = response.status();
        let result: Value = response.json().await?;
        anyhow::ensure!(status.is_success(), "GET {path}: {status} {result}");
        Ok(result)
    }
    async fn state(&self) -> Result<Value> {
        self.get("state").await
    }
    fn request(state: &Value, command: Value) -> Value {
        json!({"schema_version":1,"request_id":Uuid::new_v4(),"workspace_id":state["workspace"]["id"],"mission_id":state["mission"]["id"].as_str(),"expected":{"host_epoch":state["host"]["epoch"],"mission_input_identity":state["mission"]["input_identity"].as_str(),"candidate_digest":command["candidate_digest"].as_str()},"command":command})
    }
    async fn post(&self, request: &Value) -> Result<(u16, Value)> {
        let response = self
            .client
            .post(format!("{}/api/workshop/v1/commands", self.base))
            .bearer_auth(&self.token)
            .json(request)
            .send()
            .await?;
        let status = response.status().as_u16();
        Ok((status, response.json().await?))
    }
    async fn command(&self, request: &Value) -> Result<Value> {
        let (status, accepted) = self.post(request).await?;
        anyhow::ensure!(status == 202, "{status}: {accepted}");
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let observation = self
                    .get(&format!(
                        "commands/{}",
                        request["request_id"].as_str().context("Request missing")?
                    ))
                    .await?;
                if !["accepted", "running"].contains(&observation["status"].as_str().unwrap_or(""))
                {
                    anyhow::ensure!(observation["status"] == "succeeded", "{observation}");
                    return Ok::<_, anyhow::Error>(observation);
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await?
    }
    async fn stop(&mut self) -> Result<()> {
        self.child.kill().await?;
        self.child.wait().await?;
        Ok(())
    }
}
fn tree(root: &Path) -> Result<Value> {
    fn walk(
        root: &Path,
        path: &Path,
        items: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(root, &path, items)?
            } else {
                items.insert(
                    path.strip_prefix(root)?.display().to_string(),
                    chio_megastart::digest(&std::fs::read(&path)?)?,
                );
            }
        }
        Ok(())
    }
    let mut items = std::collections::BTreeMap::new();
    walk(root, root, &mut items)?;
    Ok(json!(items))
}
fn fixture(name: &str, state: &Value) -> Result<()> {
    if let Some(root) = std::env::var_os("CHIO_WORKSHOP_TEST_FIXTURES") {
        let root = PathBuf::from(root);
        std::fs::create_dir_all(&root)?;
        std::fs::write(
            root.join(format!("{name}.json")),
            serde_json::to_vec_pretty(state)?,
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn actual_host_runs_publishes_and_retains_a_sixth_check_in_a_fresh_mission() -> Result<()> {
    let mut host = Host::new().await?;
    // Simulate a stop after durable IDs were saved but before preparation.
    let pending_id = Uuid::new_v4();
    let mut manifest = workspace::load(&host.root)?;
    manifest.pending = Some(workspace::Entry {
        id: pending_id,
        label: "Moving average".into(),
        parent_id: None,
        recipe: None,
        revision_id: Uuid::new_v4(),
    });
    chio_agent_os_shared::runtime::files::replace(
        &host.root.join("workspace.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    let draft = host.state().await?;
    assert!(draft["mission"].is_null());
    assert!(workspace::load(&host.root)?.missions.is_empty());
    fixture("draft", &draft)?;
    let init = Host::request(
        &draft,
        json!({"type":"initialize","setup":Setup::reference()}),
    );
    host.command(&init).await?;
    let ready = host.state().await?;
    assert_eq!(ready["mission"]["phase"], "ready");
    fixture("ready", &ready)?;
    let baseline = ready["mission"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        baseline,
        pending_id.to_string(),
        "preparation replaced its durable mission identity"
    );
    let run = Host::request(&ready, json!({"type":"run"}));
    // Losing this first response does not lose the host-owned operation.
    assert_eq!(host.post(&run).await?.0, 202);
    let repeated = host.command(&run).await?;
    assert_eq!(repeated["request_id"], run["request_id"]);
    let done = host.state().await?;
    assert_eq!(done["mission"]["phase"], "awaiting_review");
    assert!(done["mission"]["publication"].is_null());
    assert_eq!(done["mission"]["tests"]["status"], "passed");
    assert_eq!(
        done["mission"]["tests"]["checks"].as_array().unwrap().len(),
        5
    );
    fixture("review", &done)?;
    let source = host
        .get(&format!("artifacts/candidate?mission={baseline}"))
        .await?;
    assert_eq!(
        source["artifact"]["digest"],
        done["mission"]["proposal"]["candidate_digest"]
    );
    assert_eq!(
        chio_megastart::digest(&source["content"])?,
        source["artifact"]["digest"]
    );
    let incorrect = Host::request(
        &done,
        json!({"type":"approve","candidate_digest":"f".repeat(64)}),
    );
    let (status, rejected) = host.post(&incorrect).await?;
    assert_eq!(status, 409);
    assert_eq!(rejected["error"]["code"], "CANDIDATE_CHANGED");
    let approve = Host::request(
        &done,
        json!({"type":"approve","candidate_digest":done["mission"]["proposal"]["candidate_digest"]}),
    );
    host.command(&approve).await?;
    let published = host.state().await?;
    assert_eq!(published["mission"]["phase"], "published");
    fixture("published", &published)?;
    let baseline_path = host.root.join("missions").join(&baseline);
    let original = tree(&baseline_path)?;
    let revision = Host::request(
        &published,
        json!({"type":"create_revision","recipe":"singleton-window-v1"}),
    );
    let created = host.command(&revision).await?;
    let child = created["result_mission_id"].as_str().unwrap().to_owned();
    assert_ne!(child, baseline);
    // Simulate the mission directory reaching disk before the manifest commit.
    let mut interrupted = workspace::load(&host.root)?;
    let prepared = interrupted.missions.pop().unwrap();
    assert_eq!(prepared.id.to_string(), child);
    interrupted.pending = Some(prepared);
    interrupted.selected_mission_id = Some(Uuid::parse_str(&baseline)?);
    let prepared_path = host.root.join("missions").join(&child);
    let prepared_bytes = tree(&prepared_path)?;
    chio_agent_os_shared::runtime::files::replace(
        &host.root.join("workspace.json"),
        &serde_json::to_vec_pretty(&interrupted)?,
    )?;
    assert_eq!(
        workspace::create_revision(&host.root, Uuid::parse_str(&baseline)?)?.to_string(),
        child
    );
    assert_eq!(
        tree(&prepared_path)?,
        prepared_bytes,
        "recovery replaced prepared authority or mission data"
    );
    let child_ready = host.state().await?;
    assert_eq!(child_ready["mission"]["id"], child);
    assert_ne!(
        child_ready["mission"]["harness_digest"],
        published["mission"]["harness_digest"]
    );
    assert_eq!(
        child_ready["mission"]["source_digest"],
        published["mission"]["source_digest"]
    );
    let repeat = host.command(&revision).await?;
    assert_eq!(repeat["result_mission_id"], child);
    // A new explicit request for the same recipe also opens the existing child.
    let repeat_intent = Host::request(
        &published,
        json!({"type":"create_revision","recipe":"singleton-window-v1"}),
    );
    assert_eq!(
        host.command(&repeat_intent).await?["result_mission_id"],
        child
    );
    host.command(&Host::request(&child_ready, json!({"type":"run"})))
        .await?;
    let six = host.state().await?;
    assert_eq!(six["mission"]["tests"]["status"], "passed");
    let checks = six["mission"]["tests"]["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 6);
    assert!(checks
        .iter()
        .any(|check| check["name"] == "singleton_window_preserves_value"
            && check["status"] == "passed"));
    assert_eq!(
        tree(&baseline_path)?,
        original,
        "the parent mission changed"
    );
    fixture("child-review", &six)?;
    let events = host
        .get(&format!("events?mission={baseline}&after=0"))
        .await?;
    assert!(events["events"].as_array().unwrap().len() > 6);
    let context = host.get(&format!("state?mission={baseline}")).await?;
    assert_eq!(context["mission"]["phase"], "published");
    assert_eq!(workspace::load(&host.root)?.missions.len(), 2);
    let epoch = six["host"]["epoch"].clone();
    let root = host.root.clone();
    host.stop().await?;
    let mut reopened = Host::open(root.clone()).await?;
    let after = reopened.state().await?;
    assert_ne!(after["host"]["epoch"], epoch);
    assert_eq!(after["mission"]["id"], child);
    assert_eq!(
        reopened.command(&revision).await?["result_mission_id"],
        child
    );
    let stale = Host::request(&six, json!({"type":"run"}));
    assert_eq!(
        reopened.post(&stale).await?.1["error"]["code"],
        "STALE_CONTEXT"
    );
    reopened.stop().await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn authentication_ids_and_command_conflicts_fail_before_effects() -> Result<()> {
    let mut host = Host::new().await?;
    let url = format!("{}/api/workshop/v1/state", host.base);
    assert_eq!(host.client.get(&url).send().await?.status(), 401);
    assert_eq!(
        host.client
            .get(&url)
            .bearer_auth(&host.token)
            .header("Origin", "https://chio.computer")
            .send()
            .await?
            .status(),
        403
    );
    assert_eq!(
        host.client
            .get(&url)
            .bearer_auth(&host.token)
            .header("Host", "untrusted.invalid")
            .send()
            .await?
            .status(),
        403
    );
    for endpoint in ["state", "events", "artifacts/original"] {
        let response = host
            .client
            .get(format!(
                "{}/api/workshop/v1/{endpoint}?mission={}",
                host.base,
                Uuid::new_v4()
            ))
            .bearer_auth(&host.token)
            .send()
            .await?;
        assert_eq!(response.status(), 404);
        assert_eq!(
            response.json::<Value>().await?["error"]["code"],
            "MISSION_UNAVAILABLE"
        );
    }
    let state = host.state().await?;
    let request = Host::request(
        &state,
        json!({"type":"initialize","setup":Setup::reference()}),
    );
    let mut injected = request.clone();
    injected["command"]["project"] = json!("/tmp/arbitrary");
    assert_eq!(host.post(&injected).await?.0, 400);
    let mut unsupported = request.clone();
    unsupported["schema_version"] = json!(2);
    assert_eq!(
        host.post(&unsupported).await?.1["error"]["code"],
        "UNSUPPORTED_VERSION"
    );
    assert!(workspace::load(&host.root)?.missions.is_empty());
    host.command(&request).await?;
    let ready = host.state().await?;
    let path = workspace::mission_path(
        &host.root,
        &workspace::load(&host.root)?,
        Uuid::parse_str(ready["mission"]["id"].as_str().unwrap())?,
    )?;
    // Both browser tabs and the legacy console share the same mutation gate.
    let lease = workspace::lock(&path, "host.lock")?;
    let run = Host::request(&ready, json!({"type":"run"}));
    let first = host.post(&run).await?;
    assert_eq!(first.0, 202);
    // A process lease may cause a fast failure; in that case a second explicit
    // request can be accepted, but the mission's existing host lock still wins.
    let second = host
        .post(&Host::request(&ready, json!({"type":"run"})))
        .await?;
    assert!([202, 409].contains(&second.0));
    // Wait for both accepted attempts to resolve before the reopen assertion.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if chio_megastart::workshop::commands::active(&host.root)?.is_null() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    drop(lease);
    assert_eq!(
        host.state().await?["mission"]["phase"],
        "ready",
        "a competing runner altered the mission"
    );
    let mut conflict = request.clone();
    conflict["command"] = json!({"type":"run"});
    assert_eq!(
        host.post(&conflict).await?.1["error"]["code"],
        "REQUEST_ID_CONFLICT"
    );
    let second = tokio::process::Command::new(env!("CARGO_BIN_EXE_megastart"))
        .args(["workshop", "--no-open", "--workspace"])
        .arg(&host.root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?;
    assert!(
        second.success(),
        "the existing verified host should be reused"
    );
    assert!(
        host.child.try_wait()?.is_none(),
        "reopen stopped the original host"
    );
    host.stop().await?;
    std::fs::remove_dir_all(&host.root)?;
    Ok(())
}

#[tokio::test]
async fn missing_tools_and_storage_permissions_block_effects() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("chio-workshop-readiness-{}", Uuid::new_v4()));
    workspace::create(&root, Setup::reference())?;
    let mut host = Host::open_with_path(root, Some("")).await?;
    let state = host.state().await?;
    let checks = state["readiness"].as_array().context("Missing readiness")?;
    assert!(checks
        .iter()
        .any(|c| c["id"] == "compiler" && c["status"] == "missing"));
    let request = Host::request(
        &state,
        json!({"type":"initialize","setup":Setup::reference()}),
    );
    assert_eq!(
        host.post(&request).await?.1["error"]["code"],
        "DEPENDENCY_MISSING"
    );
    assert!(workspace::load(&host.root)?.missions.is_empty());
    assert!(workspace::load(&host.root)?.pending.is_none());
    std::fs::set_permissions(&host.root, std::fs::Permissions::from_mode(0o500))?;
    let state_result = host.state().await;
    let rejected_result = host.post(&request).await;
    // Restore permissions even if a request failed so the isolated fixture can be removed.
    std::fs::set_permissions(&host.root, std::fs::Permissions::from_mode(0o700))?;
    let state = state_result?;
    assert!(state["readiness"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["id"] == "storage" && c["status"] == "missing"));
    assert_eq!(rejected_result?.1["error"]["code"], "STORAGE_ERROR");
    assert!(workspace::load(&host.root)?.missions.is_empty());
    host.stop().await?;
    std::fs::remove_dir_all(&host.root)?;

    #[cfg(feature = "native-agents")]
    {
        let root =
            std::env::temp_dir().join(format!("chio-workshop-native-readiness-{}", Uuid::new_v4()));
        workspace::create(&root, Setup::decode("sf1.native.codex.codex.codex")?)?;
        let mut host = Host::open_with_path(root, Some("")).await?;
        let state = host.state().await?;
        let checks = state["readiness"].as_array().context("Missing readiness")?;
        for id in ["prepare-node", "prepare-npm", "prepare-git", "agent-codex"] {
            assert!(
                checks
                    .iter()
                    .any(|c| c["id"] == id && c["status"] == "missing"),
                "Missing {id} prerequisite"
            );
        }
        let request = Host::request(&state, json!({"type":"prepare_agent","agent":"codex"}));
        assert_eq!(
            host.post(&request).await?.1["error"]["code"],
            "DEPENDENCY_MISSING"
        );
        assert!(!host.root.join("agent-connections").exists());
        host.stop().await?;
        std::fs::remove_dir_all(&host.root)?;
    }
    Ok(())
}

#[test]
fn normalization_never_invents_passing_named_checks() {
    let good = json!({"passed":true,"result":{"success":true,"stdout":"running 1 test\ntest one ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"}});
    assert_eq!(
        projection::normalize_tests(&good, Value::Null, "h")["status"],
        "passed"
    );
    let unknown = json!({"passed":true,"result":{"success":true,"stdout":"everything is fine"}});
    assert_eq!(
        projection::normalize_tests(&unknown, Value::Null, "h")["status"],
        "unknown"
    );
    let compile = json!({"passed":false,"compiler":{"success":false,"stderr":"syntax error"}});
    assert_eq!(
        projection::normalize_tests(&compile, Value::Null, "h")["status"],
        "compile_failed"
    );
    let failure = json!({"passed":false,"result":{"success":false,"stdout":"test one ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"}});
    assert_eq!(
        projection::normalize_tests(&failure, Value::Null, "h")["status"],
        "failed"
    );
    let runner = json!({"passed":false,"result":{"success":false,"stdout":""}});
    assert_eq!(
        projection::normalize_tests(&runner, Value::Null, "h")["status"],
        "runner_failed"
    );
}

#[tokio::test]
async fn actual_compiler_and_test_failures_remain_distinct() -> Result<()> {
    let root = std::env::temp_dir().join(format!("chio-workshop-failure-{}", Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("tests.rs"), "this is not Rust;")?;
    let compile = chio_megastart::operations::tests(&root, false).await?;
    let projected = projection::normalize_tests(&compile, Value::Null, "compile-fixture");
    assert_eq!(projected["status"], "compile_failed");
    assert!(projected["checks"].as_array().unwrap().is_empty());
    std::fs::write(
        root.join("tests.rs"),
        "#[test] fn intentional_regression() { assert_eq!(2, 3); }\n",
    )?;
    let failed = chio_megastart::operations::tests(&root, false).await?;
    let projected = projection::normalize_tests(&failed, Value::Null, "failure-fixture");
    assert_eq!(projected["status"], "failed");
    assert_eq!(projected["checks"][0]["name"], "intentional_regression");
    assert_eq!(projected["checks"][0]["status"], "failed");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
