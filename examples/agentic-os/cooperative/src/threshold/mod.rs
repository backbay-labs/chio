mod anchors;
pub mod authority;
pub mod member;
use anyhow::{Context, Result};
use chio_agent_os_shared::{
    graph::digest,
    host::{private_directory, write_json},
    json, Run, Value,
};
use chio_federation::frost::*;
use chio_federation_authority::{aggregate_frost_authorization, build_frost_signing_package};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
};
const SCOPE: &str = "cooperative.research.local-credits.v1";
fn now() -> u64 {
    chio_agent_os_shared::events::now_ms() / 1000
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settlement {
    pub operation_id: String,
    pub values: Vec<f64>,
    pub units: u64,
}
impl Settlement {
    fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.operation_id)?;
        anyhow::ensure!(
            !self.values.is_empty()
                && self.values.len() <= 100
                && self.values.iter().all(|v| v.is_finite() && v.abs() < 1e12)
                && self.units == self.values.len() as u64,
            "A computation needs 1 to 100 finite samples and exactly one local credit per sample"
        );
        Ok(())
    }
}
fn action(s: &Settlement) -> Result<FrostActionPreimageV1> {
    s.validate()?;
    Ok(FrostActionPreimageV1::SettleCommitment(
        FrostSettleCommitmentActionV1 {
            schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA.into(),
            settlement_body_digest: digest(s)?,
            payer_id: "research-account".into(),
            payee_id: "compute-owner".into(),
            amount_base_units: s.units.to_string(),
            asset_id: "research.local-credit".into(),
            operation_id: s.operation_id.clone(),
            rail_idempotency_key: format!("research:{}", s.operation_id),
            resource_version: 1,
            resource_fence: 1,
        },
    ))
}
fn body(
    roster: &FrostRosterV1,
    action: &FrostActionPreimageV1,
    issued: u64,
    expires: u64,
) -> Result<FrostAuthorizationBodyV1> {
    let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
        .context("Settlement action is not registered")?;
    let FrostActionPreimageV1::SettleCommitment(action_fields) = action else {
        anyhow::bail!("Only registered settlement commitments are accepted")
    };
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.into(),
        authorization_id: String::new(),
        domain: FrostAuthorizationDomain::SettleCommitment,
        ladder_action_class: registration.ladder_action_class.into(),
        ladder_contract_digest: registration.ladder_contract_digest()?,
        quorum_n: registration.quorum_n,
        quorum_m: registration.quorum_m,
        quorum_scope: registration.quorum_scope.into(),
        scope_id: roster.scope_id.clone(),
        resource_id: action_fields.operation_id.clone(),
        resource_version: 1,
        resource_fence: 1,
        action_digest: action.action_digest()?,
        roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        issued_at: issued,
        expires_at: expires,
    };
    body.authorization_id = body.recompute_authorization_id()?;
    body.validate()?;
    Ok(body)
}
struct Process {
    child: Child,
    url: String,
    admin: String,
    ready: Value,
}
impl Process {
    async fn start(executable: &PathBuf, flag: &str, path: PathBuf, config: Value) -> Result<Self> {
        private_directory(path.parent().context("Configuration needs a directory")?)?;
        write_json(&path, &config)?;
        let mut child = Command::new(executable)
            .arg(flag)
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut lines =
            BufReader::new(child.stdout.take().context("No process readiness stream")?).lines();
        let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
            .await??
            .context("Process stopped before ready")?;
        let ready: Value = serde_json::from_str(&line)?;
        Ok(Self {
            child,
            url: ready["url"].as_str().context("No process URL")?.into(),
            admin: config["admin"]
                .as_str()
                .context("No private administrator credential")?
                .into(),
            ready,
        })
    }
    async fn post(&self, path: &str, input: Value) -> Result<Value> {
        let response = reqwest::Client::new()
            .post(format!("{}{path}", self.url))
            .bearer_auth(&self.admin)
            .json(&input)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::ensure!(
            status.is_success(),
            "Request {path} was refused ({status}): {body}"
        );
        Ok(serde_json::from_str(&body)?)
    }
    async fn status(&self) -> Result<Value> {
        Ok(reqwest::Client::new()
            .get(format!("{}/status", self.url))
            .bearer_auth(&self.admin)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
pub async fn execute(input: Value, run: Run, executable: PathBuf) -> Result<Value> {
    let values: Vec<f64> = serde_json::from_value(input["values"].clone())?;
    let settlement = Settlement {
        units: values.len() as u64,
        values,
        operation_id: uuid::Uuid::new_v4().to_string(),
    };
    settlement.validate()?;
    let budget = input["member_budget"]
        .as_u64()
        .context("Choose a member budget")?;
    anyhow::ensure!(
        budget <= 100,
        "The member budget is at most 100 local credits"
    );
    let root = run.directory()?.join("threshold");
    private_directory(&root)?;
    let mut members = Vec::new();
    for index in 1..=3 {
        let id = format!("operator-{index}");
        let config = member::Config {
            root: root.join(&id),
            id: id.clone(),
            admin: uuid::Uuid::new_v4().to_string(),
            budget: if index == 1 { 100 } else { budget },
            accept: if index == 1 {
                true
            } else {
                input["member_accepts"] != false
            },
        };
        members.push(
            Process::start(
                &executable,
                "--threshold-member",
                root.join(&id).join("config.json"),
                json!(config),
            )
            .await?,
        );
    }
    let peers = members.iter().map(|p| p.ready.clone()).collect::<Vec<_>>();
    let mut first = Vec::new();
    for member in &members {
        first.push(member.post("/begin", json!(peers)).await?);
    }
    let mut receipts = Vec::new();
    for member in &members {
        receipts.extend(
            member
                .post("/advance", json!(first))
                .await?
                .as_array()
                .context("No public DKG receipts")?
                .clone(),
        );
    }
    let mut completed = Vec::new();
    for member in &members {
        completed.push(member.post("/complete", json!(receipts)).await?);
    }
    anyhow::ensure!(
        completed.windows(2).all(|p| p[0] == p[1]),
        "Members disagree about the DKG group or public transcript"
    );
    let config = authority::Config {
        root: root.join("compute-owner"),
        admin: uuid::Uuid::new_v4().to_string(),
    };
    let config_path = root.join("compute-owner/config.json");
    let mut owner = Process::start(
        &executable,
        "--threshold-authority",
        config_path.clone(),
        json!(config),
    )
    .await?;
    let roster: FrostRosterV1 =
        serde_json::from_value(owner.post("/install", completed[0].clone()).await?)?;
    for member in &members {
        member.post("/roster", json!(roster)).await?;
    }
    run.emit("cooperative.threshold.ceremony","members","Three members complete recipient-scoped distributed key generation",json!({"members":peers,"public_transcript":receipts,"ceremony":completed[0],"roster":roster,"authority":owner.ready}))?;
    let action = action(&settlement)?;
    let body = body(&roster, &action, now().saturating_sub(1), now() + 90)?;
    let proposal = json!({"settlement":settlement,"body":body});
    let mut commitments = BTreeMap::new();
    let mut decisions = Vec::new();
    for member in &members {
        let result = member.post("/prepare", proposal.clone()).await;
        match result {
            Ok(value) => {
                commitments.insert(
                    value["participant_id"]
                        .as_str()
                        .context("No signer identity")?
                        .to_owned(),
                    hex::decode(value["commitment"].as_str().context("No commitment")?)?,
                );
                decisions.push(json!({"member":member.ready["id"],"accepted":true}));
            }
            Err(error) => decisions.push(
                json!({"member":member.ready["id"],"accepted":false,"reason":error.to_string()}),
            ),
        }
    }
    run.emit(
        "cooperative.threshold.decisions",
        "members",
        "Independent policies inspect the exact computation and credit transfer",
        json!({"proposal":proposal,"decisions":decisions,"threshold":2}),
    )?;
    if commitments.len() < 2 {
        let state = owner.status().await?;
        anyhow::ensure!(
            state["completed_computations"] == 0,
            "Insufficient approval produced a computation"
        );
        return Ok(json!({
            "mode":"threshold",
            "status":"denied",
            "decisions":decisions,
            "settlement":settlement,
            "state":state,
            "roster":roster
        }));
    }
    let package = build_frost_signing_package(&body, &roster, &commitments)?;
    let mut shares = BTreeMap::new();
    for id in package.participant_ids() {
        let member = members
            .iter()
            .find(|m| m.ready["id"] == *id)
            .context("Signer process absent")?;
        let value=member.post("/sign",json!({"settlement":settlement,"body":body,"signing_package":hex::encode(package.bytes())})).await?;
        shares.insert(
            id.clone(),
            hex::decode(value["share"].as_str().context("No signature share")?)?,
        );
    }
    let proof = aggregate_frost_authorization(&body, &roster, package.bytes(), &shares)?;
    let mut denials = json!({});
    if input["exercise_denials"] == true {
        let one = commitments
            .iter()
            .take(1)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        anyhow::ensure!(
            build_frost_signing_package(&body, &roster, &one).is_err(),
            "A single member constructed a threshold signing package"
        );
        let unanchored = owner
            .post("/execute", json!({"settlement":settlement,"proof":proof}))
            .await?;
        anyhow::ensure!(
            unanchored["output"].is_null() && owner.status().await?["completed_computations"] == 0,
            "An unanchored authorization reached the credit rail"
        );
        denials["unanchored"] = unanchored;
    }
    owner.post("/complete", json!(proof)).await?;
    if input["exercise_denials"] == true {
        let mut changed = settlement.clone();
        changed.values[0] += 1.;
        let tampered = owner
            .post("/execute", json!({"settlement":changed,"proof":proof}))
            .await?;
        anyhow::ensure!(
            tampered["output"].is_null() && owner.status().await?["completed_computations"] == 0,
            "Changed computation reached the credit rail"
        );
        denials["changed_values"] = tampered;
    }
    let computation = owner
        .post("/execute", json!({"settlement":settlement,"proof":proof}))
        .await?;
    anyhow::ensure!(
        !computation["output"].is_null() && owner.status().await?["completed_computations"] == 1,
        "Threshold-authorized computation did not settle exactly once"
    );
    let state_before = owner.status().await?;
    let signer = owner.ready["kernel"].clone();
    if input["exercise_denials"] == true {
        owner.child.kill().await?;
        let _ = owner.child.wait().await?;
        owner = Process::start(
            &executable,
            "--threshold-authority",
            config_path,
            json!(config),
        )
        .await?;
        let replay = owner
            .post("/execute", json!({"settlement":settlement,"proof":proof}))
            .await?;
        anyhow::ensure!(
            replay["output"].is_null()
                && owner.status().await? == state_before
                && owner.ready["kernel"] == signer,
            "Owner restart permitted repeat spending or lost authority"
        );
        denials["replay_after_restart"] = replay;
    }
    run.emit(
        "cooperative.threshold.completed",
        "compute-owner",
        "The registered settlement funded one retained computation",
        json!({"computation":computation,"state":state_before,"proof":proof}),
    )?;
    Ok(json!({
        "mode":"threshold",
        "status":"completed",
        "settlement":settlement,
        "action":action,
        "proof":proof,
        "roster":roster,
        "decisions":decisions,
        "members":peers,
        "computation":computation,
        "state":state_before,
        "denials":denials,
        "custody":"Each member received only its two inbound private DKG packages; public receipts bind the complete transcript",
        "authority_topology":"Independent member processes; one retained compute-owner authority and local credit ledger"
    }))
}
