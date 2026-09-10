use crate::directory::{Directory, Enrollment};
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chio_agent_os_shared::{
    async_trait,
    events::now_ms,
    host::{grant, request, Host},
    json, Run, Value,
};
use chio_core::{
    capability::{scope::ChioScope, token::CapabilityToken},
    crypto::{Keypair, PublicKey, Signature},
};
use chio_federation_transport_iroh::{
    identity::*,
    lanes::pheromone::{deliver_batch_over_iroh, ALPN_PHEROMONE_BATCH},
};
use chio_kernel::{KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use iroh::{endpoint::presets, protocol::Router as IrohRouter, Endpoint, RelayMode, SecretKey};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub root: PathBuf,
    pub role: String,
    pub directory_issuer: PublicKey,
    #[serde(default)]
    pub joint_policy: Option<crate::joint::Policy>,
    pub admin_token: String,
    pub http_bind: String,
    #[serde(default)]
    pub http_public_url: Option<String>,
    pub relay: bool,
    pub document: String,
}
#[derive(Serialize, Deserialize)]
struct SignedRequest {
    sender: String,
    issued_at_ms: u64,
    request: ToolCallRequest,
    signature: Signature,
}
fn request_preimage(sender: &str, issued: u64, request: &ToolCallRequest) -> Result<Vec<u8>> {
    let mut bytes = b"chio.personal.http-tool-request.v1\0".to_vec();
    bytes.extend(chio_core::canonical_json_bytes(
        &json!({"sender":sender,"issued_at_ms":issued,"request":request}),
    )?);
    Ok(bytes)
}
struct Tools {
    local: String,
    gate: chio_federation_transport_iroh::admission::DirectoryGate,
    joint_policy: Option<crate::joint::Policy>,
    root: PathBuf,
    role: String,
    document: String,
    effects: AtomicUsize,
}
struct ToolAdapter(Arc<Tools>);
#[async_trait]
impl ToolServerConnection for ToolAdapter {
    fn server_id(&self) -> &str {
        "personal"
    }
    fn tool_names(&self) -> Vec<String> {
        vec![if self.0.role == "knowledge" {
            "retrieve"
        } else {
            "statistics"
        }
        .into()]
    }
    fn tool_is_read_only(&self, _: &str) -> bool {
        self.0.joint_policy.is_none()
    }
    async fn invoke(
        &self,
        tool: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.0
            .execute(tool, args)
            .map_err(|e| KernelError::ToolServerError(e.to_string()))
    }
}
impl Tools {
    fn execute(&self, tool: &str, args: Value) -> Result<Value> {
        let output = match tool {
            "retrieve" if self.role == "knowledge" => {
                let query = args["question"]
                    .as_str()
                    .context("Provide a question")?
                    .to_lowercase();
                let terms = query
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|s| s.len() > 3)
                    .collect::<Vec<_>>();
                let mut passages = Vec::new();
                let mut start = 0;
                for line in self.document.split_inclusive('\n') {
                    if terms.iter().any(|term| line.to_lowercase().contains(term)) {
                        passages.push(json!({
                            "text":line,
                            "byte_range":[
                                start,
                                start+line.len()
                            ],
                            "source_sha256":chio_core::sha256_hex(self.document.as_bytes())
                        }));
                    }
                    start += line.len();
                }
                json!({"passages":passages,"source_sha256":chio_core::sha256_hex(self.document.as_bytes()),"owner":self.role})
            }
            "statistics" if self.role == "compute" => {
                let values = args["values"]
                    .as_array()
                    .context("Provide numeric values")?
                    .iter()
                    .map(|value| value.as_f64().context("Values must be numbers"))
                    .collect::<Result<Vec<_>>>()?;
                anyhow::ensure!(
                    !values.is_empty()
                        && values.len() <= 1000
                        && values.iter().all(|n| n.is_finite()),
                    "Use 1 to 1000 finite values"
                );
                let mean = values.iter().sum::<f64>() / values.len() as f64;
                anyhow::ensure!(
                    mean.is_finite(),
                    "The supplied values overflow the calculation"
                );
                let approval = if let Some(policy) = &self.joint_policy {
                    let proof = crate::joint::verify(&args, &self.local, policy, &self.gate)?;
                    let consumed = self
                        .root
                        .join(format!("joint-{}.consumed", proof.action.nonce));
                    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&consumed)
                        .context("This joint action was already attempted; inspect its retained result before another proposal")?;
                    use std::io::Write;
                    file.write_all(chio_agent_os_shared::graph::digest(&proof.action)?.as_bytes())?;
                    file.sync_all()?;
                    Some(proof)
                } else {
                    None
                };
                let result = json!({
                    "count":values.len(),
                    "mean":mean,
                    "minimum":values.iter().copied().fold(f64::INFINITY,
                    f64::min),
                    "maximum":values.iter().copied().fold(f64::NEG_INFINITY,
                    f64::max)
                });
                if let Some(proof) = approval {
                    chio_agent_os_shared::host::write_json(
                        &self
                            .root
                            .join(format!("joint-{}.result.json", proof.action.nonce)),
                        &json!({"action_sha256":chio_agent_os_shared::graph::digest(&proof.action)?,"output":result}),
                    )?;
                }
                result
            }
            _ => anyhow::bail!("This node does not own that tool"),
        };
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(output)
    }
}

struct Node {
    config: Config,
    local: String,
    passport: Keypair,
    directory: Directory,
    endpoint: Endpoint,
    host: Host,
    tools: Arc<Tools>,
    run: Run,
    held: tokio::sync::Mutex<Option<iroh::endpoint::Connection>>,
}
fn error(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}
fn admin(node: &Node, headers: &HeaderMap) -> Result<()> {
    anyhow::ensure!(
        headers.get("authorization").and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {}", node.config.admin_token)),
        "Administrative authentication required"
    );
    Ok(())
}
async fn update(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(bundle): Json<TransportDirectoryBundleDocument>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    let version = node.directory.update(bundle).map_err(error)?;
    node.run
        .emit(
            "directory.updated",
            &node.local,
            "Installed a signed directory successor",
            json!({"version":version}),
        )
        .map_err(error)?;
    Ok(Json(
        json!({"version":version,"body_sha256":node.directory.gate.current_body_sha256()}),
    ))
}
async fn status(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    Ok(Json(json!({
        "pid":std::process::id(),
        "effects":node.tools.effects.load(Ordering::SeqCst),
        "version":node.directory.gate.current_version(),
        "kernel":node.host.signer,
        "run":node.run.snapshot().map_err(error)?
    })))
}
async fn issue(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    node.directory.live().map_err(error)?;
    let directory = node.directory.gate.directory();
    let peer = input["peer"]
        .as_str()
        .ok_or_else(|| error("Choose a peer"))?;
    let public = directory
        .resolve_passport_key(peer)
        .ok_or_else(|| error("Peer is not admitted"))?;
    let tool = if node.config.role == "knowledge" {
        "retrieve"
    } else {
        "statistics"
    };
    let cap = node
        .host
        .kernel
        .issue_capability(
            public,
            ChioScope {
                grants: vec![grant("personal", tool, 8)],
                ..Default::default()
            },
            300,
        )
        .map_err(error)?;
    Ok(Json(json!({"capability":cap})))
}
async fn invoke(
    State(node): State<Arc<Node>>,
    Json(call): Json<SignedRequest>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    node.directory.live().map_err(error)?;
    let directory = node.directory.gate.directory();
    let sender = directory
        .resolve_passport_key(&call.sender)
        .ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                "Caller is not in this node's current directory".into(),
            )
        })?;
    if now_ms().abs_diff(call.issued_at_ms) > 30_000
        || *sender != call.request.capability.subject
        || !sender.verify_strict(
            &request_preimage(&call.sender, call.issued_at_ms, &call.request).map_err(error)?,
            &call.signature,
        )
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "The caller signature, freshness, or capability subject is invalid".into(),
        ));
    }
    let result = node
        .host
        .call_controlled(
            &node.run,
            &call.sender,
            call.request,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .map_err(error)?;
    let snapshot = node.run.snapshot().map_err(error)?;
    let receipt = snapshot["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .rev()
                .find(|event| event["data"]["receipt_id"] == result.receipt_id)
        })
        .map(|event| event["data"]["receipt"].clone())
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "allowed":result.allowed,
        "output":result.output,
        "receipt_id":result.receipt_id,
        "receipt":receipt,
        "trusted_kernel":node.host.signer,
        "pid":std::process::id()
    })))
}
async fn dispatch(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    node.directory.live().map_err(error)?;
    let peer: Enrollment = serde_json::from_value(input["peer"].clone()).map_err(error)?;
    let directory = node.directory.gate.directory();
    if directory.resolve_transport_endpoint(&peer.entry.kernel_id)
        != Some(peer.entry.transport_endpoint_id)
    {
        return Err(error("Peer is not in the current directory"));
    }
    let cap: CapabilityToken =
        serde_json::from_value(input["capability"].clone()).map_err(error)?;
    let tool = input["tool"]
        .as_str()
        .ok_or_else(|| error("Choose a tool"))?;
    let call = request(&cap, "personal", tool, input["arguments"].clone());
    let issued = now_ms();
    let signature = node
        .passport
        .sign(&request_preimage(&node.local, issued, &call).map_err(error)?);
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/tools", peer.http_url))
        .json(&SignedRequest {
            sender: node.local.clone(),
            issued_at_ms: issued,
            request: call,
            signature,
        })
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(error)?;
    let status = response.status();
    if !status.is_success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Peer refused or could not finish the call: {}",
                response.text().await.map_err(error)?
            ),
        ));
    }
    let result: Value = response.json().await.map_err(error)?;
    // Verify the original receipt against the explicitly selected host key.
    let receipt: chio_core::receipt::body::ChioReceipt =
        serde_json::from_value(result["receipt"].clone()).map_err(error)?;
    if receipt.kernel_key != peer.kernel_key || !receipt.verify_signature().map_err(error)? {
        return Err(error("Remote result carried an untrusted receipt"));
    }
    node.run
        .emit(
            "network.tool-result",
            &node.local,
            "Received a governed tool result over signed HTTP",
            result.clone(),
        )
        .map_err(error)?;
    Ok(Json(result))
}
async fn wire(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    let peer: Enrollment = serde_json::from_value(input["peer"].clone()).map_err(error)?;
    let batch = crate::wire::batch(
        &node.passport,
        &node.local,
        &peer.entry.kernel_id,
        input["observation"].clone(),
    )
    .map_err(error)?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        deliver_batch_over_iroh(&node.endpoint, peer.address, &batch),
    )
    .await
    .map_err(error)?
    .map_err(error)?;
    Ok(Json(json!({
        "accepted":result.accepted,
        "report":serde_json::from_slice::<Value>(&result.report_json).map_err(error)?,
        "transport":"Iroh directed pheromone batch"
    })))
}
async fn hold(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    let peer: Enrollment = serde_json::from_value(input["peer"].clone()).map_err(error)?;
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        node.endpoint.connect(peer.address, ALPN_PHEROMONE_BATCH),
    )
    .await
    .map_err(error)?
    .map_err(error)?;
    *node.held.lock().await = Some(connection);
    Ok(Json(json!({"connected":true})))
}
async fn held_send(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    let connection = node
        .held
        .lock()
        .await
        .take()
        .ok_or_else(|| error("No retained connection"))?;
    let recipient = input["recipient"]
        .as_str()
        .ok_or_else(|| error("Choose the recipient"))?;
    let batch = crate::wire::batch(
        &node.passport,
        &node.local,
        recipient,
        json!({"late":"after membership removal"}),
    )
    .map_err(error)?;
    let operation = async {
        let (mut send, mut recv) = connection.open_bi().await?;
        let bytes = chio_core::canonical_json_bytes(&batch)?;
        send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
        send.write_all(&bytes).await?;
        send.finish()?;
        let reply = recv.read_to_end(128_000).await?;
        Ok::<_, anyhow::Error>(reply)
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), operation).await;
    connection.close(0u32.into(), b"lifecycle check complete");
    let accepted = matches!(&result, Ok(Ok(_)));
    let detail = match result {
        Ok(Ok(bytes)) => format!("Received {} bytes", bytes.len()),
        Ok(Err(e)) => e.to_string(),
        Err(e) => e.to_string(),
    };
    Ok(Json(json!({
        "accepted":accepted,
        "detail":detail,
        "boundary":"A connection opened before removal attempted its first batch after removal"
    })))
}
async fn cosign(
    State(node): State<Arc<Node>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    admin(&node, &headers).map_err(error)?;
    let peer: Enrollment = serde_json::from_value(input["peer"].clone()).map_err(error)?;
    let action: crate::joint::Action =
        serde_json::from_value(input["action"].clone()).map_err(error)?;
    let policy = node
        .config
        .joint_policy
        .as_ref()
        .ok_or_else(|| error("This node has no joint signing policy"))?;
    let proof = crate::joint::cosign(
        node.endpoint.clone(),
        &node.directory.gate,
        &node.local,
        &node.passport,
        policy,
        &peer,
        action,
    )
    .await
    .map_err(error)?;
    node.run
        .emit(
            "cooperative.cosigned",
            &node.local,
            "Both members authorized the exact computation",
            json!(proof),
        )
        .map_err(error)?;
    Ok(Json(json!(proof)))
}

pub async fn serve(config: Config) -> Result<()> {
    chio_agent_os_shared::host::private_directory(&config.root)?;
    let passport = crate::directory::key(&config.root.join("passport.key"))?;
    let transport = crate::directory::key(&config.root.join("transport.key"))?;
    let local = format!("did:chio:{}", passport.public_key().to_hex());
    let directory = Directory::open(
        &config.root.join("membership"),
        config.directory_issuer.clone(),
        local.clone(),
    )?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&transport.seed_bytes()))
        .relay_mode(if config.relay {
            RelayMode::Default
        } else {
            RelayMode::Disabled
        })
        .bind_addr((std::net::Ipv4Addr::UNSPECIFIED, 0))?
        .hooks(directory.gate.clone())
        .bind()
        .await?;
    let run = Run::create(
        &config.root.join("runs"),
        "personal-network-node",
        &json!({"role":config.role,"kernel_id":local,"relay":config.relay}),
    )?;
    let tools = Arc::new(Tools {
        local: local.clone(),
        gate: directory.gate.clone(),
        joint_policy: config.joint_policy.clone(),
        root: config.root.clone(),
        role: config.role.clone(),
        document: config.document.clone(),
        effects: AtomicUsize::new(0),
    });
    let host = Host::open(
        &config.root.join("host"),
        "personal-directory-and-capability-v1",
        vec![Box::new(ToolAdapter(tools.clone()))],
    )?;
    let listener = tokio::net::TcpListener::bind(&config.http_bind).await?;
    let socket = listener.local_addr()?;
    let address = if config.relay {
        tokio::time::timeout(std::time::Duration::from_secs(25), endpoint.online())
            .await
            .context("Iroh relay did not become available within 25 seconds")?;
        endpoint.addr()
    } else {
        iroh::EndpointAddr::new(endpoint.id()).with_ip_addr(
            (
                std::net::Ipv4Addr::LOCALHOST,
                endpoint
                    .bound_sockets()
                    .first()
                    .context("Transport has no socket")?
                    .port(),
            )
                .into(),
        )
    };
    let enrollment = Enrollment {
        entry: TransportDirectoryEntry {
            kernel_id: local.clone(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: endpoint.id(),
            passport_endorsement: passport
                .sign(&transport_endorsement_preimage(&local, &endpoint.id())),
            revocation_signers: vec![],
            removed: false,
        },
        address,
        http_url: if let Some(url) = &config.http_public_url {
            let parsed = reqwest::Url::parse(url)?;
            anyhow::ensure!(
                parsed.scheme() == "https"
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                    && parsed.query().is_none()
                    && parsed.fragment().is_none()
                    && parsed.path() == "/",
                "A public tool URL must be an HTTPS origin without credentials"
            );
            url.trim_end_matches('/').to_owned()
        } else {
            format!("http://{socket}")
        },
        pid: std::process::id(),
        kernel_key: host.signer.clone(),
    };
    let handler = crate::wire::handler(
        &config.root,
        local.clone(),
        directory.gate.clone(),
        run.clone(),
    )?;
    let joint_handler = crate::joint::handler(
        local.clone(),
        passport.clone(),
        directory.gate.clone(),
        config.joint_policy.clone(),
    );
    let router = IrohRouter::builder(endpoint.clone())
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .accept(
            chio_federation_transport_iroh::lanes::bilateral::ALPN_BILATERAL,
            joint_handler,
        )
        .spawn();
    let node = Arc::new(Node {
        config,
        local,
        passport,
        directory,
        endpoint,
        host,
        tools,
        run,
        held: tokio::sync::Mutex::new(None),
    });
    let expiry = node.clone();
    let watchdog = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if expiry.directory.gate.current_expires_at_unix_ms() <= now_ms() {
                expiry
                    .directory
                    .gate
                    .swap(Arc::new(VerifiedDirectory::empty_deny_all()));
            }
        }
    });
    let app = Router::new()
        .route("/directory", post(update))
        .route("/status", get(status))
        .route("/grant", post(issue))
        .route("/tools", post(invoke))
        .route("/dispatch", post(dispatch))
        .route("/wire", post(wire))
        .route("/cosign", post(cosign))
        .route("/hold", post(hold))
        .route("/held-send", post(held_send))
        .layer(axum::extract::DefaultBodyLimit::max(200_000))
        .with_state(node);
    println!("{}", serde_json::to_string(&enrollment)?);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    watchdog.abort();
    router.shutdown().await?;
    Ok(())
}
