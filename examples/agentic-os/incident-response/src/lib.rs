pub mod organization;
use anyhow::{Context, Result};
use chio_agent_os_shared::{
    async_trait,
    host::{private_directory, text, write_json},
    json, Application, Run, Value,
};
use organization::{Config, Peer};
use std::{path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
};
pub struct Incident;
#[async_trait]
impl Application for Incident {
    fn name(&self) -> &'static str {
        "incident-response"
    }
    fn title(&self) -> &'static str {
        "Three organizations resolve an incident"
    }
    fn description(&self) -> &'static str {
        "Customer telemetry, provider configuration, and specialist diagnosis converge on one exact repair. The provider approves it; a separate health check decides whether the incident closes."
    }
    fn sample(&self) -> Value {
        json!({
            "customer_records":"request-01 eu-west failed\nrequest-02 eu-west failed",
            "approve_repair":true,
            "backend_failed":false,
            "exercise_denials":true
        })
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        resolve(input, run, std::env::current_exe()?).await
    }
}
struct Organization {
    _child: Child,
    config: Config,
    peer: Peer,
}
impl Organization {
    async fn start(config: Config, executable: &PathBuf) -> Result<Self> {
        private_directory(&config.root)?;
        let path = config.root.join("organization.json");
        write_json(&path, &json!(config))?;
        let mut child = Command::new(executable)
            .arg("--organization")
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
                .context("Organization readiness stream unavailable")?,
        )
        .lines();
        let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
            .await??
            .context("Organization stopped before becoming ready")?;
        Ok(Self {
            _child: child,
            config,
            peer: serde_json::from_str(&line)?,
        })
    }
    async fn post(&self, path: &str, input: Value) -> Result<Value> {
        let response = reqwest::Client::new()
            .post(format!("{}{path}", self.peer.url))
            .bearer_auth(&self.config.admin)
            .json(&input)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        anyhow::ensure!(
            status.is_success(),
            "Organization {} {path} returned {status}: {text}",
            self.config.role
        );
        Ok(serde_json::from_str(&text)?)
    }
    async fn status(&self) -> Result<Value> {
        Ok(reqwest::Client::new()
            .get(format!("{}/status", self.peer.url))
            .bearer_auth(&self.config.admin)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    async fn grant(&self, tool: &str) -> Result<Value> {
        Ok(self
            .post("/grant", json!({"peer":"customer","tool":tool}))
            .await?["capability"]
            .clone())
    }
    async fn prepare(&self, capability: &Value, tool: &str, arguments: Value) -> Result<Value> {
        self.post(
            "/prepare",
            json!({"capability":capability,"tool":tool,"arguments":arguments}),
        )
        .await
    }
    async fn dispatch(&self, peer: &str, request: Value) -> Result<Value> {
        self.post("/dispatch", json!({"peer":peer,"request":request}))
            .await
    }
    async fn call(&self, peer: &str, cap: &Value, tool: &str, args: Value) -> Result<Value> {
        let request = self.prepare(cap, tool, args).await?;
        self.dispatch(peer, request).await
    }
}
pub async fn resolve(input: Value, run: Run, executable: PathBuf) -> Result<Value> {
    let customer_raw = text(&input, "customer_records", 16_000)?;
    let root = run.directory()?;
    let mut organizations = Vec::new();
    for role in ["customer", "provider", "specialist"] {
        organizations.push(
            Organization::start(
                Config {
                    root: root.join(role),
                    role: role.into(),
                    admin: uuid::Uuid::new_v4().to_string(),
                    customer_raw: if role == "customer" {
                        customer_raw.into()
                    } else {
                        String::new()
                    },
                    backend_failed: input["backend_failed"] == true,
                },
                &executable,
            )
            .await?,
        );
    }
    let peers = organizations
        .iter()
        .map(|o| o.peer.clone())
        .collect::<Vec<_>>();
    for organization in &organizations {
        organization.post("/peers", json!(peers)).await?;
    }
    let customer = &organizations[0];
    let provider = &organizations[1];
    let specialist = &organizations[2];
    run.emit(
        "incident.organizations",
        "coordinator",
        "Three independently governed organization processes are ready",
        json!({"organizations":peers}),
    )?;
    let telemetry_cap = customer.grant("telemetry").await?;
    let inspect_cap = provider.grant("inspect").await?;
    let diagnose_cap = specialist.grant("diagnose").await?;
    let repair_cap = provider.grant("repair").await?;
    let telemetry = customer
        .call("customer", &telemetry_cap, "telemetry", json!({}))
        .await?;
    let inspection = customer
        .call("provider", &inspect_cap, "inspect", json!({}))
        .await?;
    anyhow::ensure!(
        telemetry["allowed"] == true && inspection["allowed"] == true,
        "Incident evidence was refused"
    );
    // Construct the specialist disclosure explicitly. Raw customer records never enter its request.
    let disclosure = json!({
        "telemetry":{
            "service":telemetry["output"][
                "service"
            ],
            "region":telemetry["output"][
                "region"
            ],
            "http_status":telemetry["output"][
                "http_status"
            ]
        },
        "configuration":inspection["output"][
            "configuration"
        ],
        "configuration_sha256":inspection["output"][
            "configuration_sha256"
        ]
    });
    run.emit("incident.disclosure","customer","Share the observed failure and inspected configuration",json!({"disclosure":disclosure,"source_receipts":[telemetry["receipt_id"],inspection["receipt_id"]]}))?;
    let diagnosis = customer
        .call("specialist", &diagnose_cap, "diagnose", disclosure.clone())
        .await?;
    anyhow::ensure!(
        diagnosis["allowed"] == true && !diagnosis["output"].is_null(),
        "Specialist could not derive a bounded remediation"
    );
    let proposal = diagnosis["output"]["proposal"].clone();
    let mut denials = json!({});
    if input["exercise_denials"] == true {
        let unapproved = customer
            .call("provider", &repair_cap, "repair", proposal.clone())
            .await?;
        let mut excessive = proposal.clone();
        excessive["rule_id"] = json!("all-regional-rules");
        let excessive_request = customer.prepare(&repair_cap, "repair", excessive).await?;
        let excessive_approval = provider.post("/approve", excessive_request).await;
        let revoked_cap = provider.grant("repair").await?;
        provider
            .post("/revoke", json!({"capability_id":revoked_cap["id"]}))
            .await?;
        let mut revoked_request = customer
            .prepare(&revoked_cap, "repair", proposal.clone())
            .await?;
        revoked_request["approval_token"] =
            provider.post("/approve", revoked_request.clone()).await?["approval_token"].clone();
        let revoked = customer.dispatch("provider", revoked_request).await?;
        anyhow::ensure!(
            unapproved["allowed"] == false
                && revoked["allowed"] == false
                && excessive_approval.is_err()
                && provider.status().await?["repairs"] == 0,
            "A refused repair produced a protected change"
        );
        denials = json!({
            "missing_approval":unapproved,
            "excessive_scope":excessive_approval.err().map(|e|e.to_string()),
            "revoked_capability":revoked,
            "repairs_after_refusals":0
        });
        run.emit(
            "incident.refused",
            "provider",
            "Missing approval, expanded scope, and revoked authority produced no repair",
            denials.clone(),
        )?;
    }
    let mut repair = Value::Null;
    if input["approve_repair"] == true {
        let mut request = customer
            .prepare(&repair_cap, "repair", proposal.clone())
            .await?;
        let approved = provider.post("/approve", request.clone()).await?;
        request["approval_token"] = approved["approval_token"].clone();
        run.emit(
            "incident.approved",
            "provider",
            "Approve only this rule and configuration version",
            json!({"proposal":proposal,"approval":approved["approval_token"]}),
        )?;
        repair = customer.dispatch("provider", request).await?;
        anyhow::ensure!(
            repair["allowed"] == true && repair["output"]["changed"] == true,
            "Approved repair did not change the provider service"
        );
    }
    // A successful mutation receipt is insufficient. Exercise the service again through customer telemetry.
    let postcheck = customer
        .call("customer", &telemetry_cap, "telemetry", json!({}))
        .await?;
    let healthy = postcheck["allowed"] == true && postcheck["output"]["http_status"] == 200;
    let status = if healthy {
        "resolved"
    } else if input["approve_repair"] != true {
        "awaiting_approval"
    } else {
        "open"
    };
    let mut snapshots = Vec::new();
    for organization in &organizations {
        snapshots.push(organization.status().await?);
    }
    run.emit(
        "incident.postcheck",
        "customer",
        if healthy {
            "Service accepted the request; close the incident"
        } else {
            "The service is still unhealthy; retain the open incident"
        },
        json!({"status":status,"postcheck":postcheck}),
    )?;
    Ok(json!({
        "status":status,
        "organizations":peers,
        "disclosure":disclosure,
        "diagnosis":diagnosis,
        "proposal":proposal,
        "repair":repair,
        "postcheck":postcheck,
        "denials":denials,
        "organization_records":snapshots,
        "resolved":healthy,
        "customer_material_sent_to_specialist":false
    }))
}
