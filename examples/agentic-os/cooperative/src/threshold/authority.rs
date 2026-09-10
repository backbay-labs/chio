use super::{action, anchors::Anchors, now, Settlement};
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chio_agent_os_shared::{
    host::{grant, Host},
    json, Run, Value,
};
use chio_core::{capability::scope::ChioScope, crypto::Keypair};
use chio_federation::frost::*;
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub root: PathBuf,
    pub admin: String,
}
struct Compute(Arc<Anchors>);
#[async_trait::async_trait]
impl ToolServerConnection for Compute {
    fn server_id(&self) -> &str {
        "cooperative"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["settle_and_compute".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        input: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.execute(input)
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}
impl Compute {
    fn execute(&self, input: Value) -> Result<Value> {
        let settlement: Settlement = serde_json::from_value(input["settlement"].clone())?;
        settlement.validate()?;
        let proof: FrostAuthorizationV1 = serde_json::from_value(input["proof"].clone())?;
        let action = action(&settlement)?;
        let digest = action.action_digest()?;
        let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
            .context("Settlement is not registered")?;
        let contract = registration.ladder_contract_digest()?;
        let expected = ExpectedFrostAuthorization {
            domain: FrostAuthorizationDomain::SettleCommitment,
            ladder_action_class: registration.ladder_action_class,
            ladder_contract_digest: &contract,
            scope_id: super::SCOPE,
            resource_id: &settlement.operation_id,
            resource_version: 1,
            resource_fence: 1,
            action_digest: &digest,
        };
        verify_for_execution(
            &proof,
            &expected,
            &self.0.active()?,
            &*self.0,
            &*self.0,
            &self.0.trust()?,
            now(),
        )?;
        // The local credit transfer and its useful deterministic computation commit together.
        let mut db = self
            .0
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Settlement store lock failed"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM settlements WHERE id=?1",
            [&settlement.operation_id],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            count == 0,
            "This operation already settled; inspect the retained result instead of spending again"
        );
        let raw: String = tx.query_row("SELECT body FROM records WHERE id='credits'", [], |r| {
            r.get(0)
        })?;
        let mut credits: Value = serde_json::from_str(&raw)?;
        let available = credits["research"]
            .as_u64()
            .context("Invalid payer balance")?;
        anyhow::ensure!(
            available >= settlement.units,
            "The research account has insufficient local credits"
        );
        let mean = settlement.values.iter().sum::<f64>() / (settlement.values.len() as f64);
        let output = json!({
            "mean":mean,
            "samples":settlement.values.len(),
            "operation_id":settlement.operation_id,
            "local_credits_transferred":settlement.units,
            "action_digest":digest,
            "authorization_id":proof.body.authorization_id
        });
        credits["research"] = json!(available - settlement.units);
        credits["compute"] = json!(
            credits["compute"]
                .as_u64()
                .context("Invalid recipient balance")?
                + settlement.units
        );
        tx.execute(
            "UPDATE records SET body=?1 WHERE id='credits'",
            [serde_json::to_string(&credits)?],
        )?;
        tx.execute(
            "INSERT INTO settlements(id,action_digest,result) VALUES(?1,?2,?3)",
            rusqlite::params![
                settlement.operation_id,
                digest,
                serde_json::to_string(&output)?
            ],
        )?;
        tx.commit()?;
        Ok(output)
    }
}
struct Node {
    config: Config,
    anchors: Arc<Anchors>,
    host: Host,
    run: Run,
    cap: chio_core::capability::token::CapabilityToken,
}
type Api = std::result::Result<Json<Value>, (StatusCode, String)>;
fn error(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}
fn admin(node: &Node, h: &HeaderMap) -> Result<()> {
    anyhow::ensure!(
        h.get("authorization").and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {}", node.config.admin)),
        "Compute-owner administration requires authentication"
    );
    Ok(())
}
async fn install(State(node): State<Arc<Node>>, h: HeaderMap, Json(input): Json<Value>) -> Api {
    admin(&node, &h).map_err(error)?;
    Ok(Json(json!(node.anchors.install(&input).map_err(error)?)))
}
async fn complete(
    State(node): State<Arc<Node>>,
    h: HeaderMap,
    Json(proof): Json<FrostAuthorizationV1>,
) -> Api {
    admin(&node, &h).map_err(error)?;
    node.anchors.complete(&proof).map_err(error)?;
    Ok(Json(json!({"anchored":true})))
}
async fn execute(State(node): State<Arc<Node>>, h: HeaderMap, Json(input): Json<Value>) -> Api {
    admin(&node, &h).map_err(error)?;
    let result = node
        .host
        .call(
            &node.run,
            "research-operator",
            &node.cap,
            "cooperative",
            "settle_and_compute",
            input,
        )
        .await
        .map_err(error)?;
    Ok(Json(json!({
        "allowed":result.allowed,
        "output":result.output,
        "reason":result.reason,
        "receipt_id":result.receipt_id,
        "run":node.run.snapshot().map_err(error)?
    })))
}
async fn status(State(node): State<Arc<Node>>, h: HeaderMap) -> Api {
    admin(&node, &h).map_err(error)?;
    Ok(Json(node.anchors.state().map_err(error)?))
}
pub async fn serve(config: Config) -> Result<()> {
    let anchors = Arc::new(Anchors::open(&config.root.join("authority"))?);
    let host = Host::open(
        &config.root.join("kernel"),
        "cooperative-local-credit-settlement-v1",
        vec![Box::new(Compute(anchors.clone()))],
    )?;
    let caller = Keypair::generate();
    let cap = host.kernel.issue_capability(
        &caller.public_key(),
        ChioScope {
            grants: vec![grant("cooperative", "settle_and_compute", 10)],
            ..Default::default()
        },
        300,
    )?;
    let run = Run::create(
        &config.root.join("runs"),
        "threshold-compute-owner",
        &json!({"action":"settle.commitment"}),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    println!(
        "{}",
        json!({"url":format!("http://{}",listener.local_addr()?),"kernel":host.signer,"anchor_key":anchors.key.public_key(),"pid":std::process::id()})
    );
    let router = Router::new()
        .route("/install", post(install))
        .route("/complete", post(complete))
        .route("/execute", post(execute))
        .route("/status", get(status))
        .layer(DefaultBodyLimit::max(512_000))
        .with_state(Arc::new(Node {
            config,
            anchors,
            host,
            run,
            cap,
        }));
    axum::serve(listener, router).await?;
    Ok(())
}
