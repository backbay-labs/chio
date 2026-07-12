use super::*;
use chio_api_protect::DEFAULT_UPSTREAM_REQUEST_TIMEOUT;
use std::time::Duration;

pub(crate) fn cmd_run(
    policy_path: &Path,
    command: &[String],
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        "loaded policy"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    opt_in_ephemeral_revocation_for_local_session(&mut kernel, revocation_db_path, control_url);
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps.clone())?;

    info!(
        capability_count = initial_caps.len(),
        agent_id = %session_agent_id,
        "issued initial capabilities to agent"
    );

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| CliError::cli_other_error("empty command".to_string()))?;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::cli_io_error("failed to open child stdin".to_string()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::cli_io_error("failed to open child stdout".to_string()))?;

    let mut transport = ChioTransport::new(child_stdout, child_stdin);

    let init_msg = KernelMessage::CapabilityList {
        capabilities: initial_caps.clone(),
    };
    transport.send(&init_msg)?;
    kernel.activate_session(&session_id)?;

    info!("sent initial capabilities to agent, entering message loop");

    let mut stats = SessionStats::default();

    loop {
        let agent_msg = match transport.recv() {
            Ok(msg) => msg,
            Err(TransportError::ConnectionClosed) => {
                debug!("agent closed connection");
                break;
            }
            Err(e) => {
                warn!(error = %e, "transport read error");
                break;
            }
        };

        let kernel_msgs = handle_agent_message(
            &mut kernel,
            &agent_msg,
            &session_id,
            &session_agent_id,
            &mut stats,
        );

        let mut write_failed = false;
        for kernel_msg in kernel_msgs {
            if let Err(e) = transport.send(&kernel_msg) {
                warn!(error = %e, "transport write error");
                write_failed = true;
                break;
            }
        }
        if write_failed {
            break;
        }
    }

    if let Err(e) = kernel.begin_draining_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to mark session draining");
    }

    if let Err(e) = kernel.close_session(&session_id) {
        warn!(error = %e, session_id = %session_id, "failed to close session");
    }

    let status = child.wait()?;
    print_summary(&stats, status.code(), json_output);

    if status.success() {
        Ok(())
    } else {
        let code = status.code().unwrap_or(1);
        Err(CliError::transport_error(format!(
            "agent exited with code {code}"
        )))
    }
}

/// Whether a `--receipt-store` value opens a SQLite database that lives only in
/// memory for the life of the process. A non-UTF-8 path is always a real
/// filesystem path, so it is never in-memory; otherwise the shared
/// [`chio_store_sqlite::is_in_memory_sqlite_path`] classifier decides, keeping a
/// single source of truth for what counts as a non-durable receipt database
/// across the boot gate, the store-wiring path, and this sidecar.
fn is_in_memory_sqlite_path(path: &Path) -> bool {
    path.to_str()
        .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
}

/// Refuse to boot without a durable receipt store unless the operator has
/// explicitly opted into ephemeral receipts, and warn when the sidecar cannot
/// deliver its audit guarantee. A durable audit log is the product's core
/// promise; a missing `--receipt-store` or an in-memory SQLite path should fail
/// loudly at startup rather than run and silently lose every receipt on restart.
fn require_durable_or_ephemeral_optin(
    receipt_store: Option<&Path>,
    allow_ephemeral_receipts: bool,
    authority_seed_path: Option<&Path>,
) -> Result<(), CliError> {
    // A durable receipt store is a real filesystem path. A missing path and
    // SQLite's in-memory sentinels are equally ephemeral (both lose the audit
    // log on restart), so both require the explicit ephemeral opt-in.
    let ephemeral_receipts = receipt_store.is_none_or(is_in_memory_sqlite_path);

    if ephemeral_receipts && !allow_ephemeral_receipts {
        return Err(CliError::cli_other_error(
            "refusing to start without durable receipts: pass --receipt-store <path> for a \
             durable audit log on a filesystem path, or --allow-ephemeral-receipts to run with \
             in-memory receipts that are lost on every restart"
                .to_string(),
        ));
    }
    if ephemeral_receipts {
        tracing::warn!(
            target: "chio::sidecar",
            "running with in-memory receipts (--allow-ephemeral-receipts): audit evidence is lost on every restart"
        );
    }
    if authority_seed_path.is_none() {
        tracing::warn!(
            target: "chio::sidecar",
            "no --authority-seed-file: a fresh signer is generated per boot, so receipts signed before a restart are unverifiable"
        );
    }
    Ok(())
}

/// A one-shot `chio run` or `chio check` invocation issues fresh capabilities,
/// evaluates within a single process lifetime, and exits, so revocation state
/// never needs to survive a restart. Such a session keeps its revocation set in
/// an in-memory store unless the operator wires a durable `--revocation-db` or a
/// remote control plane, and this explicitly accepts that ephemeral store so the
/// kernel's revocation-durability gate does not deny dispatch. A configured
/// durable backend satisfies the gate on its own, so this only ever relaxes the
/// genuinely in-memory case (an in-memory SQLite path counts as no durable
/// backend, mirroring the receipt-store durability check).
///
/// Long-running servers must NOT use this: a persistent edge accepts requests
/// across capability releases and restarts, so it requires a durable revocation
/// backend or an explicit `allow_ephemeral_revocation_store` opt-in in policy
/// (see [`build_mcp_edge_kernel`]).
pub(crate) fn opt_in_ephemeral_revocation_for_local_session(
    kernel: &mut ChioKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
) {
    let durable_backend = revocation_db_path.is_some_and(|path| !is_in_memory_sqlite_path(path))
        || control_url.is_some();
    if !durable_backend {
        kernel.opt_in_ephemeral_revocation_store();
    }
}

/// Durable store and authority paths for the long-running MCP edge kernel.
pub(crate) struct McpEdgeStores<'a> {
    pub receipt_db_path: Option<&'a Path>,
    pub revocation_db_path: Option<&'a Path>,
    pub authority_seed_path: Option<&'a Path>,
    pub authority_db_path: Option<&'a Path>,
    pub budget_db_path: Option<&'a Path>,
    pub control_url: Option<&'a str>,
    pub control_token: Option<&'a str>,
}

/// Build the kernel that backs the long-running `chio mcp serve` edge.
///
/// Unlike the one-shot `chio run` / `chio check` sessions, the MCP edge outlives
/// many capability releases and is expected to survive restarts (operators wire
/// it with a durable `--receipt-db`). It therefore never auto-opts into an
/// ephemeral revocation store: revocation durability must come from a
/// `--revocation-db`, a control plane, or an explicit
/// `allow_ephemeral_revocation_store` in policy. When none is present the
/// kernel's revocation-durability gate denies dispatch, which is the intended
/// fail-closed behavior for a server that would otherwise keep accepting a token
/// it had already revoked before a restart.
pub(crate) fn build_mcp_edge_kernel(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    stores: &McpEdgeStores<'_>,
) -> Result<ChioKernel, CliError> {
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
    let mut kernel = build_kernel(loaded_policy, kernel_kp);
    configure_receipt_store(
        &mut kernel,
        stores.receipt_db_path,
        stores.control_url,
        stores.control_token,
    )?;
    configure_revocation_store(
        &mut kernel,
        stores.revocation_db_path,
        stores.control_url,
        stores.control_token,
    )?;
    configure_capability_authority(
        &mut kernel,
        kernel_kp,
        stores.authority_seed_path,
        stores.authority_db_path,
        stores.receipt_db_path,
        stores.budget_db_path,
        stores.control_url,
        stores.control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(
        &mut kernel,
        stores.budget_db_path,
        stores.control_url,
        stores.control_token,
    )?;
    Ok(kernel)
}

/// The receipt-store path to hand the proxy as a durable backend, or `None` when
/// the configured path only opens an in-memory database. The boot gate already
/// forces an explicit ephemeral opt-in for in-memory paths; passing such a path
/// on as `receipt_db` would make the proxy open in-memory stores yet advertise a
/// durable receipt backend, so it is mapped to the same no-store path an operator
/// gets from `--allow-ephemeral-receipts` without a `--receipt-store`.
fn durable_receipt_db_path(receipt_store: Option<&Path>) -> Option<&Path> {
    receipt_store.filter(|path| !is_in_memory_sqlite_path(path))
}

pub(crate) fn cmd_api_protect(
    upstream: &str,
    spec_path: Option<&Path>,
    listen_addr: &str,
    receipt_store: Option<&Path>,
    authority_seed_path: Option<&Path>,
    allow_ephemeral_receipts: bool,
    upstream_timeout_secs: Option<u64>,
) -> Result<(), CliError> {
    require_durable_or_ephemeral_optin(receipt_store, allow_ephemeral_receipts, authority_seed_path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::transport_error(format!("failed to start async runtime: {error}"))
        })?;

    runtime.block_on(async move {
        let sidecar_control_token = std::env::var("CHIO_SIDECAR_CONTROL_TOKEN")
            .ok()
            .or_else(|| std::env::var("CHIO_API_PROTECT_CONTROL_TOKEN").ok())
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        let signer_seed_hex = authority_seed_path
            .map(load_or_create_authority_keypair)
            .transpose()?
            .map(|keypair| keypair.seed_hex());
        let trusted_capability_issuers = parse_trusted_capability_issuers_from_env()?;
        let config = ProtectConfig {
            upstream: upstream.to_string(),
            spec_content: None,
            spec_path: spec_path.map(|path| path.display().to_string()),
            listen_addr: listen_addr.to_string(),
            receipt_db: durable_receipt_db_path(receipt_store).map(|path| path.display().to_string()),
            // The boot gate above already required an explicit opt-in when the
            // receipt store is missing or in-memory, so mirror the operator's
            // choice into the proxy's own durable-by-default gate.
            allow_ephemeral_receipts,
            sidecar_control_token,
            signer_seed_hex,
            trusted_capability_issuers,
            upstream_request_timeout: upstream_timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_UPSTREAM_REQUEST_TIMEOUT),
        };
        ProtectProxy::new(config).run().await.map_err(|error| {
            CliError::transport_error(format!("failed to start chio api protect: {error}"))
        })
    })
}

/// Empty OpenAPI spec used by `chio start` so the proxy can build the
/// route table without an upstream OpenAPI source. The catch-all
/// `/{*path}` proxy route still mounts; it just has no upstream to
/// forward to (pointing at `http://127.0.0.1:1`), so non-`/chio/*` and
/// non-`/v1/*` requests will fail loud at the egress contract instead
/// of silently succeeding. This is the intended behaviour for the
/// sidecar-only deployment shape.
pub(crate) const CHIO_START_SIDECAR_OPENAPI_SPEC: &str = r#"openapi: 3.1.0
info:
  title: chio-start-sidecar
  version: 0.0.0
paths: {}
"#;

pub(crate) const CHIO_START_NO_UPSTREAM_URL: &str = "http://127.0.0.1:1";

pub(crate) fn cmd_start(
    listen_addr: &str,
    receipt_store: Option<&Path>,
    authority_seed_path: Option<&Path>,
    allow_ephemeral_receipts: bool,
    print_config: bool,
) -> Result<(), CliError> {
    require_durable_or_ephemeral_optin(receipt_store, allow_ephemeral_receipts, authority_seed_path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::transport_error(format!("failed to start async runtime: {error}"))
        })?;

    runtime.block_on(async move {
        let sidecar_control_token = std::env::var("CHIO_SIDECAR_CONTROL_TOKEN")
            .ok()
            .or_else(|| std::env::var("CHIO_API_PROTECT_CONTROL_TOKEN").ok())
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());
        let signer_seed_hex = authority_seed_path
            .map(load_or_create_authority_keypair)
            .transpose()?
            .map(|keypair| keypair.seed_hex());
        let trusted_capability_issuers = parse_trusted_capability_issuers_from_env()?;
        let config = ProtectConfig {
            // The chio-start shape never proxies upstream traffic; the
            // catch-all route exists only because the underlying axum
            // router shape is shared with `chio api protect`. Pointing
            // at port 1 ensures any caller that hits the catch-all
            // path gets a fast, loud failure rather than a subtle
            // forward.
            upstream: CHIO_START_NO_UPSTREAM_URL.to_string(),
            spec_content: Some(CHIO_START_SIDECAR_OPENAPI_SPEC.to_string()),
            spec_path: None,
            listen_addr: listen_addr.to_string(),
            receipt_db: durable_receipt_db_path(receipt_store).map(|path| path.display().to_string()),
            // The boot gate above already required an explicit opt-in when the
            // receipt store is missing or in-memory, so mirror the operator's
            // choice into the proxy's own durable-by-default gate.
            allow_ephemeral_receipts,
            sidecar_control_token,
            signer_seed_hex,
            trusted_capability_issuers,
            // The chio-start shape never proxies upstream, so the hop ceiling is
            // moot; keep the default so the serve site's drain window is unchanged.
            upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        };

        ProtectProxy::new(config)
            .run_with_observer(move |bound_addr| {
                let base_url = format!("http://{bound_addr}");
                println!("chio sidecar listening on {base_url}");
                println!(
                    "  routes: /chio/* (health, evaluate, verify), /v1/capabilities/{{,mint,validate,attenuate,release}}, /v1/evaluate, /v1/receipts{{,/verify}}, /approvals/*"
                );
                if print_config {
                    println!();
                    println!("# chio-hermes quickstart -- copy into your shell:");
                    println!("export CHIO_SIDECAR_URL={base_url}");
                    println!("# then mint a capability:");
                    println!("#   hermes chio issue --description \"default backbay capability\" --json | jq -r .id");
                    println!("# and export it:");
                    println!("#   export CHIO_CAPABILITY_ID=<id-from-issue>");
                }
            })
            .await
            .map_err(|error| {
                CliError::transport_error(format!("failed to start chio sidecar: {error}"))
            })
    })
}

pub(crate) fn parse_trusted_capability_issuers_from_env(
) -> Result<Vec<chio_core::PublicKey>, CliError> {
    let mut issuers = Vec::new();

    if let Ok(single_issuer) = std::env::var("CHIO_TRUSTED_ISSUER_KEY") {
        let single_issuer = single_issuer.trim();
        if !single_issuer.is_empty() {
            issuers.push(
                chio_core::PublicKey::from_hex(single_issuer).map_err(|error| {
                    CliError::transport_error(format!(
                        "failed to parse CHIO_TRUSTED_ISSUER_KEY as a public key: {error}"
                    ))
                })?,
            );
        }
    }

    if let Ok(multiple_issuers) = std::env::var("CHIO_TRUSTED_ISSUER_KEYS") {
        for issuer in multiple_issuers
            .split(',')
            .map(str::trim)
            .filter(|issuer| !issuer.is_empty())
        {
            let parsed = chio_core::PublicKey::from_hex(issuer).map_err(|error| {
                CliError::transport_error(format!(
                    "failed to parse CHIO_TRUSTED_ISSUER_KEYS entry as a public key: {error}"
                ))
            })?;
            if !issuers.contains(&parsed) {
                issuers.push(parsed);
            }
        }
    }

    Ok(issuers)
}

pub(crate) fn cmd_check(
    policy_path: &Path,
    mode: CheckMode,
    tool: &str,
    params_str: &str,
    server: &str,
    output_fixture: Option<&Path>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    let check_output = validate_check_mode(&loaded_policy, mode, output_fixture)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();

    let kernel_kp = Keypair::generate();
    let mut kernel = build_kernel(loaded_policy, &kernel_kp);
    configure_receipt_store(&mut kernel, receipt_db_path, control_url, control_token)?;
    configure_revocation_store(&mut kernel, revocation_db_path, control_url, control_token)?;
    opt_in_ephemeral_revocation_for_local_session(&mut kernel, revocation_db_path, control_url);
    configure_capability_authority(
        &mut kernel,
        &kernel_kp,
        authority_seed_path,
        authority_db_path,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    configure_budget_store(&mut kernel, budget_db_path, control_url, control_token)?;

    kernel.register_tool_server(Box::new(CheckToolServer {
        id: server.to_string(),
        output: check_output,
    }));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let session_agent_id = agent_pk.to_hex();
    let params: serde_json::Value = serde_json::from_str(params_str)?;
    let initial_caps = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;
    let cap = match select_capability_for_request(&initial_caps, tool, server, &params) {
        Some(capability) => capability,
        None => kernel
            .issue_capability(&agent_pk, ChioScope::default(), 300)
            .map_err(|error| {
                CliError::transport_error(format!(
                    "failed to issue fallback empty capability: {error}"
                ))
            })?,
    };
    let session_id = kernel.open_session(session_agent_id.clone(), initial_caps)?;
    kernel.activate_session(&session_id)?;

    let context = OperationContext::new(
        session_id.clone(),
        RequestId::new("check-001"),
        session_agent_id,
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        arguments: params.clone(),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
                extra_metadata: None,
    }));

    let response = match kernel.evaluate_session_operation(&context, &operation)? {
        SessionOperationResponse::ToolCall(response) => response,
        SessionOperationResponse::RootList { .. }
        | SessionOperationResponse::ResourceList { .. }
        | SessionOperationResponse::ResourceRead { .. }
        | SessionOperationResponse::ResourceReadDenied { .. }
        | SessionOperationResponse::ResourceTemplateList { .. }
        | SessionOperationResponse::PromptList { .. }
        | SessionOperationResponse::PromptGet { .. }
        | SessionOperationResponse::Completion { .. }
        | SessionOperationResponse::CapabilityList { .. }
        | SessionOperationResponse::Heartbeat => {
            return Err(CliError::transport_error(
                "unexpected non-tool response while evaluating check command".to_string(),
            ));
        }
    };

    kernel.begin_draining_session(&session_id)?;
    kernel.close_session(&session_id)?;

    let verdict_str = verdict_label(response.verdict);

    if json_output {
        let output = serde_json::json!({
            "verdict": verdict_str,
            "tool": tool,
            "server": server,
            "params": params,
            "reason": response.reason,
            "receipt_id": response.receipt.id,
            "policy_hash": policy_identity.runtime_hash,
            "policy_source_hash": policy_identity.source_hash,
            "check_mode": mode.as_str(),
            "output_fixture": output_fixture.is_some(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("verdict:    {verdict_str}");
        println!("tool:       {tool}");
        println!("server:     {server}");
        if let Some(reason) = &response.reason {
            println!("reason:     {reason}");
        }
        println!("receipt_id: {}", response.receipt.id);
        println!("policy:     {}", policy_identity.runtime_hash);
        println!("source:     {}", policy_identity.source_hash);
        println!("mode:       {}", mode.as_str());
        println!("fixture:    {}", output_fixture.is_some());
    }

    match response.verdict {
        chio_kernel::Verdict::Allow => Ok(()),
        chio_kernel::Verdict::Deny => {
            std::process::exit(2);
        }
        chio_kernel::Verdict::PendingApproval => {
            // Treat approval-pending as a soft deny from the CLI
            // perspective; the orchestrator can resume once the
            // human has approved out-of-band.
            std::process::exit(3);
        }
    }
}

fn validate_check_mode(
    loaded_policy: &policy::LoadedPolicy,
    mode: CheckMode,
    output_fixture: Option<&Path>,
) -> Result<Option<serde_json::Value>, CliError> {
    match mode {
        CheckMode::Preflight => {
            if output_fixture.is_some() {
                return Err(CliError::cli_other_error(
                    "--output-fixture requires --mode full".to_string(),
                ));
            }
            if !loaded_policy.post_invocation_pipeline.is_empty() {
                return Err(CliError::cli_other_error(
                    "chio check preflight cannot evaluate post-output guards; use --mode full --output-fixture <JSON> so output-sensitive policy is evaluated against explicit fixture output".to_string(),
                ));
            }
            Ok(None)
        }
        CheckMode::Full => {
            let Some(output_fixture) = output_fixture else {
                return Err(CliError::cli_other_error(
                    "chio check --mode full requires --output-fixture <JSON>; use --mode preflight for admission-only checks".to_string(),
                ));
            };
            load_check_output_fixture(output_fixture).map(Some)
        }
    }
}

fn load_check_output_fixture(path: &Path) -> Result<serde_json::Value, CliError> {
    let content = fs::read_to_string(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read check output fixture {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse check output fixture {} as JSON: {error}",
            path.display()
        ))
    })
}

struct CheckToolServer {
    id: String,
    output: Option<serde_json::Value>,
}

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CheckToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        Ok(self.output.clone().unwrap_or_else(|| {
            serde_json::json!({
                "check_probe": true,
                "tool": tool_name,
                "arguments": arguments,
            })
        }))
    }
}

pub(crate) fn verdict_label(verdict: chio_kernel::Verdict) -> &'static str {
    match verdict {
        chio_kernel::Verdict::Allow => "ALLOW",
        chio_kernel::Verdict::Deny => "DENY",
        chio_kernel::Verdict::PendingApproval => "PENDING_APPROVAL",
    }
}

pub(crate) fn cmd_mcp_serve(
    policy_path: Option<&Path>,
    preset: Option<&str>,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    // Resolve `--preset` to a materialized YAML on disk so the rest
    // of the plumbing can use `load_policy` unchanged. Keeping the
    // preset on disk also keeps the source_policy_hash deterministic
    // across runs so receipt verification continues to work.
    let materialized_preset = match (policy_path, preset) {
        (Some(_), None) => None,
        (None, Some(name)) => {
            let preset = policies::McpPreset::from_name(name).ok_or_else(|| {
                CliError::cli_other_error(format!("unknown --preset {name:?} (known: code-agent)"))
            })?;
            Some(preset.materialize_to_temp()?)
        }
        (Some(_), Some(_)) => {
            // clap's `conflicts_with` should prevent this, but we
            // guard defensively in case the CLI wiring ever drifts.
            return Err(CliError::cli_other_error(
                "--policy and --preset are mutually exclusive".to_string(),
            ));
        }
        (None, None) => {
            return Err(CliError::cli_other_error(
                "either --policy <path> or --preset <name> is required".to_string(),
            ));
        }
    };

    let resolved_policy_path: &Path = match (policy_path, &materialized_preset) {
        (Some(p), _) => p,
        (None, Some(m)) => m.path(),
        _ => unreachable!("policy path resolution validated above"),
    };

    let loaded_policy = load_policy(resolved_policy_path)?;
    let policy_identity = loaded_policy.identity.clone();
    let default_capabilities = loaded_policy.default_capabilities.clone();

    info!(
        policy_path = %resolved_policy_path.display(),
        preset = preset.unwrap_or(""),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %policy_identity.source_hash,
        runtime_policy_hash = %policy_identity.runtime_hash,
        server_id = server_id,
        "loaded policy for MCP edge"
    );

    let kernel_kp = Keypair::generate();
    let mut kernel = build_mcp_edge_kernel(
        loaded_policy,
        &kernel_kp,
        &McpEdgeStores {
            receipt_db_path,
            revocation_db_path,
            authority_seed_path,
            authority_db_path,
            budget_db_path,
            control_url,
            control_token,
        },
    )?;

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::cli_other_error("empty MCP server command".to_string()))?;
    let wrapped_arg_refs = wrapped_args.iter().map(String::as_str).collect::<Vec<_>>();

    let manifest_public_key = manifest_public_key
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
    let adapted_server = AdaptedMcpServer::from_command(
        wrapped_cmd,
        &wrapped_arg_refs,
        McpAdapterConfig {
            server_id: server_id.to_string(),
            server_name: server_name.unwrap_or(server_id).to_string(),
            server_version: server_version
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            public_key: manifest_public_key,
        },
    )?;
    let upstream_notification_source = adapted_server.notification_source();
    let upstream_capabilities = adapted_server.upstream_capabilities();
    let manifest = adapted_server.manifest_clone();
    if let Some(resource_provider) = adapted_server.resource_provider() {
        kernel.register_resource_provider(Box::new(resource_provider));
    }
    if let Some(prompt_provider) = adapted_server.prompt_provider() {
        kernel.register_prompt_provider(Box::new(prompt_provider));
    }
    kernel.register_tool_server(Box::new(adapted_server));

    let agent_kp = Keypair::generate();
    let agent_pk = agent_kp.public_key();
    let agent_id = agent_pk.to_hex();
    let capabilities = issue_default_capabilities(&kernel, &agent_pk, &default_capabilities)?;

    info!(
        capability_count = capabilities.len(),
        upstream_resources = upstream_capabilities.resources_supported,
        upstream_prompts = upstream_capabilities.prompts_supported,
        upstream_completions = upstream_capabilities.completions_supported,
        wrapped_command = wrapped_cmd,
        "initialized MCP edge session"
    );

    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            page_size,
            tools_list_changed: tools_list_changed || upstream_capabilities.tools_list_changed,
            completion_enabled: Some(upstream_capabilities.completions_supported),
            resources_subscribe: upstream_capabilities.resources_subscribe,
            resources_list_changed: upstream_capabilities.resources_list_changed,
            prompts_list_changed: upstream_capabilities.prompts_list_changed,
            logging_enabled: true,
        },
        kernel,
        agent_id,
        capabilities,
        vec![manifest],
    )?;
    edge.attach_upstream_transport(upstream_notification_source);

    edge.serve_stdio(std::io::BufReader::new(std::io::stdin()), std::io::stdout())?;
    Ok(())
}

pub(crate) fn cmd_mcp_serve_http(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    manifest_public_key: Option<&str>,
    page_size: usize,
    tools_list_changed: bool,
    shared_hosted_owner: bool,
    listen: SocketAddr,
    auth_token: Option<&str>,
    auth_jwt_public_key: Option<&str>,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_introspection_client_id: Option<&str>,
    auth_introspection_client_secret: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_server_seed_file: Option<&Path>,
    identity_federation_seed_file: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    auth_jwt_issuer: Option<&str>,
    auth_jwt_audience: Option<&str>,
    admin_token: Option<&str>,
    public_base_url: Option<&str>,
    auth_servers: &[String],
    auth_authorization_endpoint: Option<&str>,
    auth_token_endpoint: Option<&str>,
    auth_registration_endpoint: Option<&str>,
    auth_jwks_uri: Option<&str>,
    auth_scopes: &[String],
    auth_subject: &str,
    auth_code_ttl_secs: u64,
    auth_access_token_ttl_secs: u64,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    session_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let loaded_policy = load_policy(policy_path)?;
    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %loaded_policy.identity.source_hash,
        runtime_policy_hash = %loaded_policy.identity.runtime_hash,
        server_id = server_id,
        listen_addr = %listen,
        "loaded policy for remote MCP edge"
    );

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::cli_other_error("empty MCP server command".to_string()))?;

    let auth_token = optional_secret_with_env_fallback(auth_token, "CHIO_MCP_AUTH_TOKEN");
    let admin_token = optional_secret_with_env_fallback(admin_token, "CHIO_MCP_ADMIN_TOKEN");
    let egress_contract = remote_mcp_auth_egress_contract(
        server_id,
        auth_jwt_discovery_url,
        auth_introspection_url,
        auth_jwt_provider_profile,
        auth_jwt_issuer,
        auth_jwks_uri,
    )?;

    remote_mcp::serve_http(remote_mcp::RemoteServeHttpConfig {
        listen,
        auth_token,
        auth_jwt_public_key: auth_jwt_public_key.map(ToOwned::to_owned),
        auth_jwt_discovery_url: auth_jwt_discovery_url.map(ToOwned::to_owned),
        auth_introspection_url: auth_introspection_url.map(ToOwned::to_owned),
        auth_introspection_client_id: auth_introspection_client_id.map(ToOwned::to_owned),
        auth_introspection_client_secret: auth_introspection_client_secret.map(ToOwned::to_owned),
        auth_jwt_provider_profile,
        auth_server_seed_path: auth_server_seed_file.map(Path::to_path_buf),
        identity_federation_seed_path: identity_federation_seed_file.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        auth_jwt_issuer: auth_jwt_issuer.map(ToOwned::to_owned),
        auth_jwt_audience: auth_jwt_audience.map(ToOwned::to_owned),
        admin_token,
        control_url: control_url.map(ToOwned::to_owned),
        control_token: control_token.map(ToOwned::to_owned),
        public_base_url: public_base_url.map(ToOwned::to_owned),
        auth_servers: auth_servers.to_vec(),
        auth_authorization_endpoint: auth_authorization_endpoint.map(ToOwned::to_owned),
        auth_token_endpoint: auth_token_endpoint.map(ToOwned::to_owned),
        auth_registration_endpoint: auth_registration_endpoint.map(ToOwned::to_owned),
        auth_jwks_uri: auth_jwks_uri.map(ToOwned::to_owned),
        auth_scopes: auth_scopes.to_vec(),
        auth_subject: auth_subject.to_string(),
        auth_code_ttl_secs,
        auth_access_token_ttl_secs,
        receipt_db_path: receipt_db_path.map(std::path::Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(std::path::Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(std::path::Path::to_path_buf),
        authority_db_path: authority_db_path.map(std::path::Path::to_path_buf),
        budget_db_path: budget_db_path.map(std::path::Path::to_path_buf),
        session_db_path: session_db_path.map(std::path::Path::to_path_buf),
        policy_path: policy_path.to_path_buf(),
        server_id: server_id.to_string(),
        server_name: server_name.unwrap_or(server_id).to_string(),
        server_version: server_version
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        manifest_public_key: manifest_public_key.map(ToOwned::to_owned),
        page_size,
        tools_list_changed,
        shared_hosted_owner,
        wrapped_command: wrapped_cmd.clone(),
        wrapped_args: wrapped_args.to_vec(),
        egress_contract,
    })
}

pub(crate) fn remote_mcp_auth_egress_contract(
    server_id: &str,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_jwt_issuer: Option<&str>,
    auth_jwks_uri: Option<&str>,
) -> Result<Option<chio_egress_contract::HttpEgressContract>, CliError> {
    let mut urls = Vec::new();
    urls.extend(auth_jwt_discovery_url);
    urls.extend(auth_introspection_url);
    urls.extend(auth_jwks_uri);
    if auth_jwt_provider_profile.is_some() || auth_jwt_discovery_url.is_some() {
        urls.extend(auth_jwt_issuer);
    }
    if urls.is_empty() {
        return Ok(None);
    }

    let mut allowed_schemes = std::collections::BTreeSet::new();
    let mut allowed_authority_set = std::collections::BTreeSet::new();
    let mut deny_loopback = true;
    let mut deny_link_local = true;
    let mut deny_ipv6_ula = true;

    for raw_url in urls {
        let parsed = url::Url::parse(raw_url).map_err(|error| {
            CliError::cli_other_error(format!(
                "remote MCP auth egress URL `{raw_url}` is invalid: {error}"
            ))
        })?;
        allowed_schemes.insert(parsed.scheme().to_ascii_lowercase());
        allowed_authority_set.insert(cli_normalized_url_authority(&parsed)?);

        if let Some(host) = parsed.host() {
            match host {
                url::Host::Domain(domain) => {
                    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                    if matches!(normalized.as_str(), "localhost" | "localhost.localdomain") {
                        deny_loopback = false;
                    }
                }
                url::Host::Ipv4(address) => {
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if address.is_link_local() {
                        deny_link_local = false;
                    }
                }
                url::Host::Ipv6(address) => {
                    if let Some(mapped) = address.to_ipv4_mapped() {
                        if mapped.is_loopback() {
                            deny_loopback = false;
                        }
                        if mapped.is_link_local() {
                            deny_link_local = false;
                        }
                    }
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if is_cli_ipv6_unicast_link_local(&address) {
                        deny_link_local = false;
                    }
                    if is_cli_ipv6_unique_local(&address) {
                        deny_ipv6_ula = false;
                    }
                }
            }
        }
    }

    let contract = chio_egress_contract::HttpEgressContract {
        tenant_egress_namespace: format!("remote-mcp-auth:{server_id}"),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback,
        deny_link_local,
        deny_ipv6_ula,
        max_redirect_chain: 3,
        max_response_bytes: 1024 * 1024,
    };
    contract.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress contract is invalid: {error}"
        ))
    })?;
    Ok(Some(contract))
}

pub(crate) fn cli_normalized_url_authority(url: &url::Url) -> Result<String, CliError> {
    let host = url.host_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress URL `{url}` is missing an authority"
        ))
    })?;
    let host = match url.host() {
        Some(url::Host::Ipv6(_)) => format!("[{}]", host.to_ascii_lowercase()),
        Some(url::Host::Domain(_)) => host.trim_end_matches('.').to_ascii_lowercase(),
        _ => host.to_ascii_lowercase(),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

pub(crate) fn is_cli_ipv6_unicast_link_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

pub(crate) fn is_cli_ipv6_unique_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

pub(crate) fn optional_secret_with_env_fallback(
    value: Option<&str>,
    fallback_env: &str,
) -> Option<String> {
    value.map(ToOwned::to_owned).or_else(|| {
        std::env::var(fallback_env)
            .ok()
            .filter(|value| !value.is_empty())
    })
}

pub(crate) fn require_revocation_db_path(
    revocation_db_path: Option<&Path>,
) -> Result<&Path, CliError> {
    revocation_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "trust commands require --revocation-db <path> so persisted trust state is explicit"
                .to_string(),
        )
    })
}

pub(crate) fn require_receipt_db_path(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "shared evidence commands require --receipt-db <path> when --control-url is not set"
                .to_string(),
        )
    })
}

pub(crate) fn cmd_trust_serve(
    listen: SocketAddr,
    service_token: &str,
    tenant_read_tokens: &[String],
    policy_path: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    federation_policies_file: Option<&Path>,
    scim_lifecycle_file: Option<&Path>,
    verifier_policies_file: Option<&Path>,
    verifier_challenge_db: Option<&Path>,
    passport_statuses_file: Option<&Path>,
    passport_issuance_offers_file: Option<&Path>,
    certification_registry_file: Option<&Path>,
    certification_discovery_file: Option<&Path>,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    advertise_url: Option<&str>,
    allow_local_peer_urls: bool,
    certification_public_metadata_ttl_seconds: u64,
    peer_urls: &[String],
    cluster_sync_interval_ms: u64,
) -> Result<(), CliError> {
    if service_token.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "trust serve requires a non-empty --service-token".to_string(),
        ));
    }
    let tenant_read_tokens = parse_tenant_read_tokens(tenant_read_tokens)?;
    if let Some((tenant_id, _)) = tenant_read_tokens
        .iter()
        .find(|(_, token)| token.as_str() == service_token)
    {
        return Err(CliError::cli_other_error(format!(
            "--tenant-read-token for tenant {tenant_id} must not equal --service-token"
        )));
    }
    let (issuance_policy, runtime_assurance_policy) = policy_path
        .map(load_policy)
        .transpose()?
        .map(|loaded| (loaded.issuance_policy, loaded.runtime_assurance_policy))
        .unwrap_or((None, None));
    trust_control::serve(trust_control::TrustServiceConfig {
        listen,
        service_token: service_token.to_string(),
        tenant_read_tokens,
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(Path::to_path_buf),
        authority_db_path: authority_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        federation_policies_file: federation_policies_file.map(Path::to_path_buf),
        scim_lifecycle_file: scim_lifecycle_file.map(Path::to_path_buf),
        verifier_policies_file: verifier_policies_file.map(Path::to_path_buf),
        verifier_challenge_db_path: verifier_challenge_db.map(Path::to_path_buf),
        passport_statuses_file: passport_statuses_file.map(Path::to_path_buf),
        passport_issuance_offers_file: passport_issuance_offers_file.map(Path::to_path_buf),
        certification_registry_file: certification_registry_file.map(Path::to_path_buf),
        certification_discovery_file: certification_discovery_file.map(Path::to_path_buf),
        issuance_policy,
        runtime_assurance_policy,
        advertise_url: advertise_url.map(ToOwned::to_owned),
        allow_local_peer_urls,
        certification_public_metadata_ttl_seconds,
        peer_urls: peer_urls.to_vec(),
        cluster_sync_interval: std::time::Duration::from_millis(cluster_sync_interval_ms.max(50)),
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
    })
}

pub(crate) fn parse_tenant_read_tokens(
    specs: &[String],
) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    let mut parsed = std::collections::BTreeMap::new();
    for spec in specs {
        let (tenant, token) = spec.split_once('=').ok_or_else(|| {
            CliError::cli_other_error("--tenant-read-token must use tenant=token form".to_string())
        })?;
        if tenant.trim() != tenant || token.trim() != token {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must not contain surrounding whitespace"
                    .to_string(),
            ));
        }
        if tenant.chars().any(char::is_control) || token.chars().any(char::is_control) {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must not contain control characters"
                    .to_string(),
            ));
        }
        if tenant.is_empty() || token.is_empty() {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must be non-empty".to_string(),
            ));
        }
        if parsed
            .insert(tenant.to_string(), token.to_string())
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "duplicate --tenant-read-token for tenant {tenant}"
            )));
        }
    }
    Ok(parsed)
}

pub(crate) fn cmd_trust_revoke(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (newly_revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::service_runtime::client::build_client(url, token)?
            .revoke_capability(capability_id)?;
        (response.newly_revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.revoke(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": true,
            "newly_revoked": newly_revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       true");
        println!("newly_revoked: {newly_revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

pub(crate) fn cmd_trust_status(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::service_runtime::client::build_client(url, token)?
            .list_revocations(&trust_control::RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            })?;
        let revoked = response.revoked.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "trust-control revocation response omitted revoked status for {capability_id}"
            ))
        })?;
        (revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.is_revoked(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       {revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

#[cfg(test)]
mod runtime_local_error_domain_tests {
    use super::*;

    fn must_err<T: std::fmt::Debug>(result: Result<T, CliError>, context: &str) -> CliError {
        match result {
            Ok(value) => panic!("{context}: expected error, got {value:?}"),
            Err(error) => error,
        }
    }

    fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected_code);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    #[test]
    fn missing_local_receipt_db_uses_cli_domain() {
        let error = must_err(
            require_receipt_db_path(None),
            "missing receipt db should fail closed",
        );

        assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
    }

    #[test]
    fn in_memory_receipt_store_is_refused_without_ephemeral_optin() {
        for sentinel in [
            ":memory:",
            "file::memory:",
            "file:audit?mode=memory&cache=shared",
        ] {
            let error = must_err(
                require_durable_or_ephemeral_optin(Some(Path::new(sentinel)), false, None),
                "an in-memory receipt store must fail closed without --allow-ephemeral-receipts",
            );
            let message = error.to_string();
            assert!(
                message.contains("without durable receipts"),
                "unexpected error for {sentinel}: {message}"
            );
        }
    }

    #[test]
    fn in_memory_receipt_store_boots_only_with_the_ephemeral_optin() {
        assert!(
            require_durable_or_ephemeral_optin(Some(Path::new(":memory:")), true, None).is_ok(),
            "an in-memory receipt store is allowed once ephemeral receipts are opted into"
        );
    }

    #[test]
    fn durable_receipt_path_boots_without_the_ephemeral_optin() {
        assert!(
            require_durable_or_ephemeral_optin(
                Some(Path::new("/var/lib/chio/receipts.db")),
                false,
                None,
            )
            .is_ok(),
            "a filesystem receipt path is durable and needs no ephemeral opt-in"
        );
    }

    #[test]
    fn in_memory_receipt_store_is_not_carried_through_as_durable() {
        // An in-memory path that cleared the boot gate must not reach the proxy
        // as a receipt_db, or the proxy opens in-memory stores yet reports a
        // durable receipt backend. It collapses to the no-store ephemeral path.
        for sentinel in [
            ":memory:",
            "file::memory:",
            "file:audit?mode=memory&cache=shared",
        ] {
            assert!(
                durable_receipt_db_path(Some(Path::new(sentinel))).is_none(),
                "in-memory path {sentinel} must not be treated as a durable receipt_db"
            );
        }
        assert!(durable_receipt_db_path(None).is_none());
        assert_eq!(
            durable_receipt_db_path(Some(Path::new("/var/lib/chio/receipts.db"))),
            Some(Path::new("/var/lib/chio/receipts.db")),
            "a filesystem path is a durable receipt_db and passes through"
        );
    }

    #[test]
    fn partial_credit_loss_lifecycle_amount_uses_cli_domain() {
        let error = must_err(
            crate::runtime_trust_reports::build_credit_loss_lifecycle_query(
                "bond-1",
                "delinquency",
                Some(100),
                None,
            ),
            "partial amount flags should fail closed",
        );

        assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
    }

    #[test]
    fn tenant_read_token_mapping_rejects_surrounding_whitespace() {
        for spec in [" tenant-a=read-token", "tenant-a=read-token "] {
            let error = must_err(
                parse_tenant_read_tokens(&[spec.to_string()]),
                "tenant token mapping with surrounding whitespace should fail closed",
            );

            let message = error.to_string();
            assert!(
                message.contains("surrounding whitespace"),
                "unexpected tenant token validation error for {spec}: {message}"
            );
        }
    }

    #[test]
    fn tenant_read_token_mapping_rejects_control_characters() {
        for spec in ["tenant-\na=read-token", "tenant-a=read\u{7f}token"] {
            let error = must_err(
                parse_tenant_read_tokens(&[spec.to_string()]),
                "tenant token mapping with control characters should fail closed",
            );

            let message = error.to_string();
            assert!(
                message.contains("control characters"),
                "unexpected tenant token validation error for {spec:?}: {message}"
            );
        }
    }

    #[test]
    fn remote_mcp_auth_contract_is_derived_from_external_auth_urls() {
        let contract = remote_mcp_auth_egress_contract(
            "edge-a",
            Some("https://id.example.com/.well-known/openid-configuration"),
            Some("https://auth.example.com/oauth2/introspect"),
            None,
            Some("https://issuer.example.com/oauth2/default"),
            Some("https://keys.example.com/jwks.json"),
        )
        .expect("contract builds")
        .expect("external auth creates contract");

        assert_eq!(contract.tenant_egress_namespace, "remote-mcp-auth:edge-a");
        assert!(contract.allowed_schemes.contains("https"));
        assert!(contract.allowed_authority_set.contains("id.example.com"));
        assert!(contract.allowed_authority_set.contains("auth.example.com"));
        assert!(contract
            .allowed_authority_set
            .contains("issuer.example.com"));
        assert!(contract.allowed_authority_set.contains("keys.example.com"));
        assert!(contract.deny_loopback);
    }

    #[test]
    fn remote_mcp_auth_contract_permits_explicit_loopback_auth_url() {
        let contract = remote_mcp_auth_egress_contract(
            "edge-local",
            None,
            Some("http://127.0.0.1:18080/introspect"),
            None,
            None,
            None,
        )
        .expect("contract builds")
        .expect("loopback auth creates contract");

        assert!(contract.allowed_schemes.contains("http"));
        assert!(contract.allowed_authority_set.contains("127.0.0.1:18080"));
        assert!(!contract.deny_loopback);
    }
}
