//! Each organization owns its own issuer, tools, approval, and retained receipts.
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chio_agent_os_shared::{
    events::now_ms,
    graph::digest,
    host::{grant, private_directory, request, write_json, Host},
    json, Run, Value,
};
use chio_core::{
    capability::{
        governance::GovernedTransactionIntent,
        scope::{ChioScope, Constraint},
        token::CapabilityToken,
    },
    crypto::{Keypair, PublicKey, Signature},
};
use chio_kernel::{KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub root: PathBuf,
    pub role: String,
    pub admin: String,
    pub customer_raw: String,
    pub backend_failed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Peer {
    pub role: String,
    pub url: String,
    pub passport: PublicKey,
    pub kernel: PublicKey,
    pub pid: u32,
}
#[derive(Serialize, Deserialize)]
struct SignedCall {
    sender: PublicKey,
    issued_at_ms: u64,
    request: ToolCallRequest,
    signature: Signature,
}
fn preimage(sender: &PublicKey, issued: u64, request: &ToolCallRequest) -> Result<Vec<u8>> {
    let mut bytes = b"chio.incident.http-request.v1\0".to_vec();
    bytes.extend(chio_core::canonical_json_bytes(
        &json!({"sender":sender,"issued_at_ms":issued,"request":request}),
    )?);
    Ok(bytes)
}
struct Tools {
    config: Config,
    peers: Mutex<BTreeMap<String, Peer>>,
    service: Mutex<Value>,
    repairs: AtomicUsize,
}
struct Adapter(Arc<Tools>);
#[async_trait::async_trait]
impl ToolServerConnection for Adapter {
    fn server_id(&self) -> &str {
        "incident"
    }
    fn tool_names(&self) -> Vec<String> {
        match self.0.config.role.as_str() {
            "customer" => vec!["telemetry".into()],
            "specialist" => vec!["diagnose".into()],
            _ => vec!["inspect".into(), "repair".into()],
        }
    }
    async fn invoke(
        &self,
        tool: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0
            .invoke(tool, args)
            .await
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}
impl Tools {
    async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
        match (self.config.role.as_str(), tool) {
            ("customer", "telemetry") => {
                let peer = self
                    .peers
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Peer lock failed"))?
                    .get("provider")
                    .cloned()
                    .context("Provider is not enrolled")?;
                let response = reqwest::Client::new()
                    .get(format!("{}/service", peer.url))
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await?;
                let status = response.status().as_u16();
                Ok(json!({
                    "service":"inference-gateway",
                    "region":"eu-west",
                    "http_status":status,
                    "observed_at_ms":now_ms(),
                    "customer_records":self.config.customer_raw.lines().count(),
                    "raw_customer_material_shared":false
                }))
            }
            ("provider", "inspect") => {
                let service = self
                    .service
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Service lock failed"))?;
                Ok(json!({"configuration":*service,"configuration_sha256":digest(&*service)?}))
            }
            ("specialist", "diagnose") => {
                anyhow::ensure!(
                    args["telemetry"]["http_status"] == 403
                        && args["configuration"]["rule_enabled"] == true,
                    "This evidence does not support the bounded rule repair"
                );
                Ok(json!({
                    "explanation":"The observed EU request is refused while the regional restriction is active.",
                    "proposal":{
                        "service":"inference-gateway",
                        "rule_id":"geo-restrict-v42",
                        "action":"disable_rule",
                        "configuration_sha256":args["configuration_sha256"]
                    },
                    "shared_input_sha256":digest(&args)?
                }))
            }
            ("provider", "repair") => {
                let mut service = self
                    .service
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Service lock failed"))?;
                let expected = json!({
                    "service":"inference-gateway",
                    "rule_id":"geo-restrict-v42",
                    "action":"disable_rule",
                    "configuration_sha256":digest(&*service)?
                });
                anyhow::ensure!(args==expected,"Repair is outside the provider's exact service, rule, action, or configuration version");
                anyhow::ensure!(
                    service["rule_enabled"] == true,
                    "The rule is already disabled; reconcile the existing repair"
                );
                let mut next = service.clone();
                next["rule_enabled"] = json!(false);
                next["version"] = json!(service["version"].as_u64().unwrap_or(0) + 1);
                write_json(&self.config.root.join("service.json"), &next)?;
                *service = next.clone();
                self.repairs.fetch_add(1, Ordering::SeqCst);
                Ok(
                    json!({"changed":true,"configuration":next,"configuration_sha256":digest(&next)?}),
                )
            }
            _ => anyhow::bail!("This organization does not expose that tool"),
        }
    }
}
struct Node {
    config: Config,
    passport: Keypair,
    host: Host,
    tools: Arc<Tools>,
    run: Run,
}
type Api = std::result::Result<Json<Value>, (StatusCode, String)>;
fn error(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}
fn admin(node: &Node, headers: &HeaderMap) -> Result<()> {
    anyhow::ensure!(
        headers.get("authorization").and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {}", node.config.admin)),
        "Organization administrator authentication required"
    );
    Ok(())
}
fn selected(node: &Node, role: &str) -> Result<Peer> {
    node.tools
        .peers
        .lock()
        .map_err(|_| anyhow::anyhow!("Peer lock failed"))?
        .get(role)
        .cloned()
        .context("Organization is not enrolled")
}
fn validate(node: &Node, call: &SignedCall) -> Result<()> {
    anyhow::ensure!(
        node.tools
            .peers
            .lock()
            .map_err(|_| anyhow::anyhow!("Peer lock failed"))?
            .values()
            .any(|p| p.passport == call.sender),
        "Caller organization is not admitted"
    );
    anyhow::ensure!(
        now_ms().abs_diff(call.issued_at_ms) <= 30_000
            && call.sender == call.request.capability.subject
            && call.sender.verify_strict(
                &preimage(&call.sender, call.issued_at_ms, &call.request)?,
                &call.signature
            ),
        "Caller signature, freshness, or capability subject is invalid"
    );
    if call.request.tool_name == "repair" {
        anyhow::ensure!(
            call.request
                .governed_intent
                .as_ref()
                .and_then(|i| i.context.as_ref())
                .and_then(|c| c.get("arguments_sha256"))
                == Some(&json!(digest(&call.request.arguments)?)),
            "Repair arguments differ from the governed intent"
        );
    }
    Ok(())
}
async fn peers(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(peers): Json<Vec<Peer>>,
) -> Api {
    admin(&node, &headers).map_err(error)?;
    if peers.len() > 3 {
        return Err(error("At most three incident organizations"));
    }
    *node
        .tools
        .peers
        .lock()
        .map_err(|_| error("Peer lock failed"))? =
        peers.into_iter().map(|p| (p.role.clone(), p)).collect();
    Ok(Json(json!({"enrolled":true})))
}
async fn grant_to(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Api {
    admin(&node, &headers).map_err(error)?;
    let peer = selected(
        &node,
        input["peer"]
            .as_str()
            .ok_or_else(|| error("Choose a peer"))?,
    )
    .map_err(error)?;
    let tool = input["tool"]
        .as_str()
        .ok_or_else(|| error("Choose a tool"))?;
    let tools = Adapter(node.tools.clone()).tool_names();
    if !tools.iter().any(|t| t == tool) {
        return Err(error("This organization does not own the requested tool"));
    }
    let mut scope = grant("incident", tool, 8);
    if tool == "repair" {
        scope.constraints = vec![
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove { threshold_units: 0 },
        ];
    }
    let cap = node
        .host
        .kernel
        .issue_capability(
            &peer.passport,
            ChioScope {
                grants: vec![scope],
                ..Default::default()
            },
            120,
        )
        .map_err(error)?;
    Ok(Json(json!({"capability":cap})))
}
async fn prepare(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Api {
    admin(&node, &headers).map_err(error)?;
    let cap: CapabilityToken =
        serde_json::from_value(input["capability"].clone()).map_err(error)?;
    if cap.subject != node.passport.public_key() {
        return Err(error("Capability was not issued to this organization"));
    }
    let tool = input["tool"]
        .as_str()
        .ok_or_else(|| error("Choose a tool"))?;
    let mut call = request(&cap, "incident", tool, input["arguments"].clone());
    if tool == "repair" {
        call.governed_intent=Some(GovernedTransactionIntent{id:call.request_id.clone(),server_id:"incident".into(),tool_name:"repair".into(),purpose:"Disable only geo-restrict-v42 on inference-gateway at the inspected configuration version".into(),max_amount:None,commerce:None,metered_billing:None,runtime_attestation:None,call_chain:None,autonomy:None,context:Some(json!({"arguments_sha256":digest(&call.arguments).map_err(error)?})),body:Default::default()});
    }
    Ok(Json(json!(call)))
}
async fn approve(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(call): Json<ToolCallRequest>,
) -> Api {
    admin(&node, &headers).map_err(error)?;
    if node.config.role != "provider" || call.tool_name != "repair" {
        return Err(error("Only the provider may approve this remediation"));
    }
    let service = node
        .tools
        .service
        .lock()
        .map_err(|_| error("Service lock failed"))?;
    let expected = json!({
        "service":"inference-gateway",
        "rule_id":"geo-restrict-v42",
        "action":"disable_rule",
        "configuration_sha256":digest(&*service).map_err(error)?
    });
    if call.arguments != expected {
        return Err(error(
            "Approval requires the exact current remediation proposal",
        ));
    }
    Ok(Json(
        json!({"approval_token":node.host.approve(&call,true,call.capability.expires_at).map_err(error)?}),
    ))
}
async fn invoke(State(node): State<Arc<Node>>, Json(call): Json<SignedCall>) -> Api {
    validate(&node, &call).map_err(error)?;
    let result = node
        .host
        .call_controlled(
            &node.run,
            &call.sender.to_hex(),
            call.request,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .map_err(error)?;
    let snapshot = node.run.snapshot().map_err(error)?;
    let event = snapshot["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .rev()
                .find(|event| event["data"]["receipt_id"] == result.receipt_id)
        })
        .map(|e| e["data"].clone())
        .unwrap_or(Value::Null);
    Ok(Json(
        json!({"allowed":result.allowed,"output":result.output,"receipt_id":result.receipt_id,"evidence":event}),
    ))
}
async fn dispatch(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Api {
    admin(&node, &headers).map_err(error)?;
    let peer = selected(
        &node,
        input["peer"]
            .as_str()
            .ok_or_else(|| error("Choose a peer"))?,
    )
    .map_err(error)?;
    let call: ToolCallRequest = serde_json::from_value(input["request"].clone()).map_err(error)?;
    if call.capability.subject != node.passport.public_key() {
        return Err(error("Caller does not own this capability"));
    }
    let now = now_ms();
    let sender = node.passport.public_key();
    let signature = node
        .passport
        .sign(&preimage(&sender, now, &call).map_err(error)?);
    let signed = SignedCall {
        sender,
        issued_at_ms: now,
        request: call,
        signature,
    };
    let response = reqwest::Client::new()
        .post(format!("{}/invoke", peer.url))
        .json(&signed)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(error)?;
    if !response.status().is_success() {
        return Err(error(response.text().await.map_err(error)?));
    }
    let value: Value = response.json().await.map_err(error)?;
    let receipt: chio_core::receipt::body::ChioReceipt =
        serde_json::from_value(value["evidence"]["receipt"].clone()).map_err(error)?;
    if receipt.kernel_key != peer.kernel
        || !receipt.verify_signature().map_err(error)?
        || value["receipt_id"] != receipt.id
    {
        return Err(error(
            "The remote receipt is not from the selected organization",
        ));
    }
    Ok(Json(value))
}
async fn revoke(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Api {
    admin(&node, &headers).map_err(error)?;
    node.host
        .kernel
        .revoke_capability(
            &input["capability_id"]
                .as_str()
                .ok_or_else(|| error("Provide capability_id"))?
                .to_owned(),
        )
        .map_err(error)?;
    Ok(Json(json!({"revoked":true})))
}
async fn status(State(node): State<Arc<Node>>, headers: HeaderMap) -> Api {
    admin(&node, &headers).map_err(error)?;
    Ok(Json(json!({
        "role":node.config.role,
        "pid":std::process::id(),
        "repairs":node.tools.repairs.load(Ordering::SeqCst),
        "run":node.run.snapshot().map_err(error)?
    })))
}
async fn service(State(node): State<Arc<Node>>) -> (StatusCode, Json<Value>) {
    if node.config.role != "provider" {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"No service on this host"})),
        );
    }
    let Ok(config) = node.tools.service.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Service state unavailable"})),
        );
    };
    if config["rule_enabled"] == true {
        (
            StatusCode::FORBIDDEN,
            Json(json!({"service":"inference-gateway","error":"region_denied","region":"eu-west"})),
        )
    } else if config["backend_failed"] == true {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"service":"inference-gateway","error":"backend_unavailable"})),
        )
    } else {
        (
            StatusCode::OK,
            Json(json!({
                "service":"inference-gateway",
                "region":"eu-west",
                "answer":"The supplied service accepted and completed the request"
            })),
        )
    }
}
pub async fn serve(config: Config) -> Result<()> {
    private_directory(&config.root)?;
    let keyfile = config.root.join("passport.key");
    let passport = if keyfile.exists() {
        Keypair::from_seed_hex(std::fs::read_to_string(&keyfile)?.trim())?
    } else {
        let key = Keypair::generate();
        write_json(
            &config.root.join("passport-public.json"),
            &json!(key.public_key()),
        )?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options.open(&keyfile)?;
        file.write_all(key.seed_hex().as_bytes())?;
        file.sync_all()?;
        key
    };
    let servicefile = config.root.join("service.json");
    let initial_service: Value = if servicefile.exists() {
        serde_json::from_slice(&std::fs::read(servicefile)?)?
    } else {
        let value = json!({
            "service":"inference-gateway",
            "rule_id":"geo-restrict-v42",
            "rule_enabled":true,
            "backend_failed":config.backend_failed,
            "version":1
        });
        write_json(&servicefile, &value)?;
        value
    };
    let tools = Arc::new(Tools {
        config: config.clone(),
        peers: Mutex::new(BTreeMap::new()),
        service: Mutex::new(initial_service),
        repairs: AtomicUsize::new(0),
    });
    let host = Host::open(
        &config.root.join("kernel"),
        "incident-organization-policy-v1",
        vec![Box::new(Adapter(tools.clone()))],
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let peer = Peer {
        role: config.role.clone(),
        url: format!("http://{}", listener.local_addr()?),
        passport: passport.public_key(),
        kernel: host.signer.clone(),
        pid: std::process::id(),
    };
    let run = Run::create(
        &config.root.join("runs"),
        "incident-organization",
        &json!({"role":config.role}),
    )?;
    let node = Arc::new(Node {
        config,
        passport,
        host,
        tools,
        run,
    });
    let router = Router::new()
        .route("/peers", post(peers))
        .route("/grant", post(grant_to))
        .route("/prepare", post(prepare))
        .route("/approve", post(approve))
        .route("/invoke", post(invoke))
        .route("/dispatch", post(dispatch))
        .route("/revoke", post(revoke))
        .route("/status", get(status))
        .route("/service", get(service))
        .layer(DefaultBodyLimit::max(128_000))
        .with_state(node);
    println!("{}", serde_json::to_string(&peer)?);
    axum::serve(listener, router).await?;
    Ok(())
}
