//! Four independently persisted kernel hosts for a delegated work order.
//! Network input never chooses a subprocess, executable, file path or issuer.
use anyhow::{bail, ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Path as RoutePath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chio_core::{
    capability::{
        attenuation::scope_hash,
        delegated_token::{issue_delegated_capability, DelegatedCapabilityRequest},
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    crypto::Keypair,
    receipt::metadata::GuardEvidence,
};
use chio_kernel::{
    ChioKernel, Guard, GuardContext, GuardDecision, KernelConfig, KernelError, ToolCallOutput,
    ToolCallRequest, ToolServerConnection,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn read(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
fn write(path: &Path, value: &Value) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}
fn directory(path: &Path) -> Result<()> {
    std::fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn scope(tools: &[(&str, &str)], calls: u32, delegable: bool) -> ChioScope {
    ChioScope {
        grants: tools
            .iter()
            .map(|(server, tool)| ToolGrant {
                server_id: (*server).into(),
                tool_name: (*tool).into(),
                operations: if delegable {
                    vec![Operation::Invoke, Operation::Delegate]
                } else {
                    vec![Operation::Invoke]
                },
                constraints: vec![],
                max_invocations: Some(calls),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            })
            .collect(),
        ..Default::default()
    }
}
const TOOLS: &[(&str, &str)] = &[
    ("atlas", "quote"),
    ("atlas", "buy_report"),
    ("atlas", "reserve"),
    ("atlas", "settle"),
    ("atlas", "refund"),
    ("atlas", "status"),
    ("atlas", "recover"),
    ("proofworks", "review"),
    ("cipherworks", "review"),
    ("meridian", "admit"),
    ("meridian", "audit"),
];
fn prepare(path: &Path) -> Result<()> {
    directory(path)?;
    let issuer = Keypair::generate();
    let owner = Keypair::generate();
    let provider = Keypair::generate();
    let specialist = Keypair::generate();
    let buyer = Keypair::generate();
    let auditor = Keypair::generate();
    let issued = now()?;
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: uuid::Uuid::new_v4().to_string(),
            issuer: issuer.public_key(),
            subject: owner.public_key(),
            scope: scope(TOOLS, 200, true),
            issued_at: issued,
            expires_at: issued + 3600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let delegate = |parent: &CapabilityToken,
                    holder: &Keypair,
                    subject: &Keypair,
                    tools: &[(&str, &str)],
                    calls,
                    share,
                    delegable|
     -> Result<CapabilityToken> {
        Ok(issue_delegated_capability(
            parent,
            DelegatedCapabilityRequest {
                id: uuid::Uuid::new_v4().to_string(),
                subject: subject.public_key(),
                scope: scope(tools, calls, delegable),
                issued_at: issued,
                expires_at: issued + 1800,
                budget_share_bps: Some(share),
                nonce: *uuid::Uuid::new_v4().as_bytes(),
            },
            holder,
            &issuer,
        )?
        .0)
    };
    let provider_cap = delegate(
        &root,
        &owner,
        &provider,
        &[("proofworks", "review"), ("cipherworks", "review")],
        30,
        6000,
        true,
    )?;
    let specialist_cap = delegate(
        &provider_cap,
        &provider,
        &specialist,
        &[("cipherworks", "review")],
        20,
        2500,
        false,
    )?;
    let buyer_cap = delegate(
        &root,
        &owner,
        &buyer,
        &TOOLS
            .iter()
            .copied()
            .filter(|(s, _)| *s == "atlas" || *s == "meridian")
            .collect::<Vec<_>>(),
        60,
        3000,
        false,
    )?;
    let auditor_cap = delegate(
        &root,
        &owner,
        &auditor,
        &[("meridian", "audit")],
        20,
        1000,
        false,
    )?;
    directory(&path.join("operator"))?;
    directory(&path.join("credentials"))?;
    write(
        &path.join("operator/issuer.json"),
        &json!({"seed":issuer.seed_hex()}),
    )?;
    for (name, key, cap) in [
        ("buyer", &buyer, &buyer_cap),
        ("provider", &provider, &provider_cap),
        ("specialist", &specialist, &specialist_cap),
        ("auditor", &auditor, &auditor_cap),
    ] {
        write(
            &path.join(format!("credentials/{name}.json")),
            &json!({"seed":key.seed_hex(),"capability":cap}),
        )?;
    }
    write(
        &path.join("capabilities.json"),
        &json!({"root":root,"provider":provider_cap,"specialist":specialist_cap,"buyer":buyer_cap,"auditor":auditor_cap}),
    )?;
    for name in ["atlas", "proofworks", "cipherworks", "meridian"] {
        let host = path.join(name);
        directory(&host)?;
        let runtime =
            chio_control_plane::DurableAdmissionRuntime::open(&host.join("admission.db"))?;
        let admin_token = Keypair::generate().seed_hex();
        write(
            &host.join("config.json"),
            &json!({"name":name,"issuer":issuer.public_key(),"root":root,"parents":[root,provider_cap],"admin_token":admin_token,"record_token":Keypair::generate().seed_hex(),"trusted_kernel":runtime.kernel_keypair().public_key()}),
        )?;
        write(
            &path.join(format!("operator/{name}.json")),
            &json!({"token":admin_token}),
        )?;
    }
    println!("Created four durable hosts in {}", path.display());
    Ok(())
}

#[derive(Clone)]
struct Domain {
    name: String,
    directory: PathBuf,
    python: PathBuf,
    script: PathBuf,
}
impl Domain {
    fn run(&self, phase: &str, tool: &str, input: &Value) -> Result<Value> {
        let mut process = Command::new(&self.python)
            .arg(&self.script)
            .arg(phase)
            .arg(&self.directory)
            .arg(tool)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        process
            .stdin
            .take()
            .context("Missing domain stdin")?
            .write_all(&serde_json::to_vec(input)?)?;
        // Small bounded responses; pipes are drained concurrently so tool output
        // cannot deadlock the host. A stalled domain process is terminated.
        let stdout = process.stdout.take().context("Missing stdout")?;
        let stderr = process.stderr.take().context("Missing stderr")?;
        let drain = |stream: Box<dyn std::io::Read + Send>| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                std::io::Read::take(stream, 1_048_577)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
            })
        };
        let output = drain(Box::new(stdout));
        let error = drain(Box::new(stderr));
        let start = Instant::now();
        let status = loop {
            if let Some(status) = process.try_wait()? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(60) {
                process.kill()?;
                process.wait()?;
                bail!("Domain operation exceeded 60 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let output = output
            .join()
            .map_err(|_| anyhow::anyhow!("Domain stdout reader failed"))??;
        let error = error
            .join()
            .map_err(|_| anyhow::anyhow!("Domain stderr reader failed"))??;
        ensure!(
            output.len() <= 1_048_576 && error.len() <= 1_048_576,
            "Domain response exceeded its bound"
        );
        ensure!(
            status.success(),
            "Domain operation failed: {}",
            String::from_utf8_lossy(&error)
        );
        Ok(serde_json::from_slice(&output)?)
    }
}
impl Guard for Domain {
    fn name(&self) -> &str {
        "WorkOrderPolicy"
    }
    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let result = self
            .run(
                "check",
                &ctx.request.tool_name,
                &json!({"request":ctx.request}),
            )
            .map_err(|e| KernelError::GuardDenied(e.to_string()))?;
        let allowed = result["allowed"] == true;
        let evidence = vec![GuardEvidence {
            guard_name: self.name().into(),
            verdict: allowed,
            details: Some(result.to_string()),
        }];
        Ok(if allowed {
            GuardDecision::allow_with_evidence(evidence)
        } else {
            GuardDecision::deny(evidence)
        })
    }
}
#[async_trait::async_trait]
impl ToolServerConnection for Domain {
    fn server_id(&self) -> &str {
        &self.name
    }
    fn tool_names(&self) -> Vec<String> {
        TOOLS
            .iter()
            .filter(|(s, _)| *s == self.name)
            .map(|(_, t)| (*t).into())
            .collect()
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        matches!(tool, "status" | "audit")
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.run("execute", tool, &arguments)
            .map_err(|e| KernelError::RequestIncomplete(e.to_string()))
    }
}
struct App {
    kernel: Mutex<ChioKernel>,
    name: String,
    admin_token: String,
    record_token: String,
    directory: PathBuf,
}
async fn call(
    State(app): State<Arc<App>>,
    Json(input): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let request: ToolCallRequest =
        serde_json::from_value(input).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if request.server_id.as_str() != app.name {
        return Err((StatusCode::BAD_REQUEST, "Wrong host audience".into()));
    }
    let output = tokio::task::spawn_blocking(move || -> Result<Value> {
        let kernel = app.kernel.lock().map_err(|_| anyhow::anyhow!("Host state unavailable"))?;
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        let output = match response.output { Some(ToolCallOutput::Value(value)) => value, None => Value::Null, Some(ToolCallOutput::Stream(_)) => bail!("Expected a bounded work-order result") };
        let result = json!({"receipt":response.receipt,"output":output,"reason":response.reason,"terminal_state":response.terminal_state});
        let records = app.directory.join("records");
        std::fs::create_dir_all(&records)?;
        // The receipt ID is content-addressed and unique to this signed result.
        let record = json!({"request":request,"result":result});
        write(&records.join(format!("{}.json", response.receipt.id)), &record)?;
        Ok(result)
    }).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR,e.to_string()))?
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE,e.to_string()))?;
    Ok(Json(output))
}
async fn record(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        != Some(app.record_token.as_str())
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Auditor record credential required".into(),
        ));
    }
    if id.len() != 64
        || !id
            .bytes()
            .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Expected a receipt content ID".into(),
        ));
    }
    read(&app.directory.join("records").join(format!("{id}.json")))
        .map(Json)
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "No retained operation has this receipt ID".into(),
            )
        })
}
async fn revoke(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        != Some(app.admin_token.as_str())
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Operator credential required".into(),
        ));
    }
    let id = input["capability_id"]
        .as_str()
        .filter(|s| s.len() <= 256)
        .ok_or((StatusCode::BAD_REQUEST, "Capability ID required".into()))?;
    app.kernel
        .lock()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "State unavailable".into()))?
        .revoke_capability(&id.to_string())
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    Ok(Json(json!({"revoked":id})))
}
async fn serve(directory: &Path, python: &Path, script: &Path) -> Result<()> {
    ensure!(
        python.is_absolute() && python.is_file(),
        "Python must be an absolute interpreter entrypoint"
    );
    let config = read(&directory.join("config.json"))?;
    let name = config["name"]
        .as_str()
        .context("Host name required")?
        .to_string();
    let root: CapabilityToken = serde_json::from_value(config["root"].clone())?;
    ensure!(
        root.verify_signature()?,
        "Invalid configured authority root"
    );
    let authority =
        chio_control_plane::DurableAdmissionRuntime::open(&directory.join("admission.db"))?;
    let signer = authority.kernel_keypair();
    ensure!(
        serde_json::to_value(signer.public_key())? == config["trusted_kernel"],
        "Kernel identity changed"
    );
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer,
        ca_public_keys: vec![root.issuer.clone()],
        max_delegation_depth: 8,
        policy_hash: chio_core::sha256_hex(&std::fs::read(script)?),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    let store = chio_store_sqlite::SqliteReceiptStore::open(directory.join("receipts.db"))?;
    for parent in config["parents"]
        .as_array()
        .context("Configured parent snapshots required")?
    {
        let token: CapabilityToken = serde_json::from_value(parent.clone())?;
        ensure!(
            token.issuer == root.issuer && token.verify_signature()?,
            "Untrusted parent snapshot"
        );
        store.record_capability_snapshot(
            &token,
            token
                .delegation_chain
                .last()
                .map(|link| link.capability_id.as_str()),
        )?;
    }
    kernel.set_receipt_store(Box::new(store))?;
    kernel.configure_durable_admission(
        chio_kernel::admission_operation::DurableAdmissionMode::All,
        false,
    )?;
    authority.attach(&mut kernel)?;
    kernel.set_capability_trust_root(root.issuer, scope_hash(&root.scope)?);
    for parent in config["parents"]
        .as_array()
        .context("Parent snapshots required")?
    {
        let token: CapabilityToken = serde_json::from_value(parent.clone())?;
        kernel
            .register_budget_parent(token.id, token.budget_share_bps.unwrap_or(10000))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    let domain = Domain {
        name: name.clone(),
        directory: directory.canonicalize()?,
        // Keep the virtual environment entrypoint: resolving its symlink
        // selects the base interpreter and silently discards installed packages.
        python: python.to_path_buf(),
        script: script.canonicalize()?,
    };
    kernel.add_guard(Box::new(domain.clone()));
    kernel.register_tool_server(Box::new(domain));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let app = Arc::new(App {
        kernel: Mutex::new(kernel),
        directory: directory.to_path_buf(),
        record_token: config["record_token"]
            .as_str()
            .context("Record credential missing")?
            .into(),
        name,
        admin_token: config["admin_token"]
            .as_str()
            .context("Operator credential missing")?
            .into(),
    });
    let router = Router::new()
        .route("/call", post(call))
        .route("/admin/revoke", post(revoke))
        .route("/records/{id}", get(record))
        .route("/healthz", get(|| async { "ready" }))
        .layer(DefaultBodyLimit::max(2_097_152))
        .with_state(app);
    write(
        &directory.join("server.json"),
        &json!({"endpoint":endpoint,"trusted_kernel":config["trusted_kernel"]}),
    )?;
    axum::serve(listener, router).await?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("prepare") if args.len()==3 => prepare(Path::new(&args[2])),
        Some("serve") if args.len()==5 => serve(Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4])).await,
        _ => bail!("Usage: web3-work-order prepare NEW_DIRECTORY | serve HOST_DIRECTORY PYTHON DOMAIN_SCRIPT"),
    }
}
