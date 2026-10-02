//! Managed worker endpoints share the application's durable admission owner.
use anyhow::{Context, Result};
use chio_agent_os_shared::{host::grant, runtime::files};
use chio_control_plane::DurableAdmissionRuntime;
use chio_core::{
    capability::{
        attenuation::{
            compute_attenuation_witness, delegate, scope_hash, Attenuation, AttenuationProof,
        },
        scope::{ChioScope, Constraint, Operation},
        token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody},
    },
    crypto::Keypair,
    delegation_receipt::ScopeAttenuation,
};
use chio_mcp_remote::{serve_http_bound, BoundSessionAuthority, RemoteServeHttpConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub const TOOLS: [&str; 4] = [
    "read_text_file",
    "write_file",
    "edit_file",
    "list_directory",
];
pub const WORKERS: [&str; 6] = [
    "research-0",
    "research-1",
    "implementation-0",
    "implementation-1",
    "review-0",
    "review-1",
];

#[derive(Serialize, Deserialize)]
struct Grants {
    root: CapabilityToken,
    workers: BTreeMap<String, CapabilityToken>,
}

fn worker(
    root: &CapabilityToken,
    owner: &Keypair,
    issuer: &Keypair,
    name: &str,
) -> Result<CapabilityToken> {
    let subject = Keypair::generate().public_key();
    let mut scope = root.scope.clone();
    let mut steps = Vec::new();
    for grant in &mut scope.grants {
        grant.operations = vec![Operation::Invoke];
        steps.push(Attenuation::RemoveOperation {
            server_id: "fs".into(),
            tool_name: grant.tool_name.clone(),
            operation: Operation::Delegate,
        });
        let prefix = if matches!(grant.tool_name.as_str(), "write_file" | "edit_file") {
            format!("/workspace/outputs/{name}")
        } else {
            "/workspace".into()
        };
        let constraint = Constraint::ArgumentPathPrefix {
            pointer: "/path".into(),
            prefix,
        };
        grant.constraints.push(constraint.clone());
        steps.push(Attenuation::AddConstraint {
            server_id: "fs".into(),
            tool_name: grant.tool_name.clone(),
            constraint,
        });
    }
    let now = chio_agent_os_shared::events::now_ms() / 1000;
    let delegated = delegate(
        root,
        &scope,
        owner,
        &subject,
        ScopeAttenuation {
            steps,
            child_expires_at: Some(root.expires_at),
            budget_share_bps: Some(1_000),
        },
        now,
        *uuid::Uuid::new_v4().as_bytes(),
    )?;
    Ok(CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: uuid::Uuid::new_v4().to_string(),
                issuer: issuer.public_key(),
                subject,
                scope: scope.clone(),
                issued_at: now,
                expires_at: root.expires_at,
                delegation_chain: delegated.complete_chain(),
                aggregate_invocation_budget: root.aggregate_invocation_budget.clone(),
            },
            caveats: vec![],
            scope_attenuations: delegated.attenuation.steps,
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&root.scope)?,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&root.scope, &scope)?,
            },
            budget_share_bps: Some(1_000),
        },
        issuer,
    )?)
}

/// Internal checkpoint entrypoint. Public onboarding uses the operator console.
/// Reopening keeps original grants and refuses expiry; it never resets usage.
pub async fn checkpoint(
    directory: &Path,
    project: &Path,
    first_port: u16,
    allowance: u32,
) -> Result<()> {
    anyhow::ensure!(
        (1024..=65_529).contains(&first_port),
        "Invalid worker port range"
    );
    anyhow::ensure!(
        (1..=1000).contains(&allowance),
        "Invalid invocation allowance"
    );
    let fresh = !directory.exists();
    files::private_directory(directory)?;
    let directory = directory.canonicalize()?;
    let lease = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("host.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lease)
        .context("Another process owns these worker endpoints")?;
    let resource = directory.join("resource");
    if fresh {
        for sub in ["source", "outputs", "handoffs"] {
            files::private_directory(&resource.join(sub))?;
        }
        for name in ["lib.rs", "tests.rs"] {
            files::create(
                &resource.join("source").join(name),
                files::read_text(&project.join(name), 64_000)?.as_bytes(),
            )?;
        }
        for name in WORKERS {
            files::private_directory(&resource.join("outputs").join(name))?;
        }
        files::create(&directory.join("policy.yaml"), b"kernel:\n  max_capability_ttl: 86400\n  delegation_depth_limit: 1\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools: []\n")?;
    }
    let admission = Arc::new(DurableAdmissionRuntime::open(
        &directory.join("admission.db"),
    )?);
    let issuer = admission.kernel_keypair();
    let authority_path = directory.join("authority.json");
    let grants: Grants = if fresh {
        let owner = Keypair::generate();
        let now = chio_agent_os_shared::events::now_ms() / 1000;
        let mut tools = Vec::new();
        for name in TOOLS {
            let mut tool = grant("fs", name, 64);
            tool.operations.push(Operation::Delegate);
            tools.push(tool);
        }
        let root = CapabilityToken::sign_aggregate_family_root(
            CapabilityTokenBody {
                id: uuid::Uuid::new_v4().to_string(),
                issuer: issuer.public_key(),
                subject: owner.public_key(),
                scope: ChioScope {
                    grants: tools,
                    ..Default::default()
                },
                issued_at: now,
                expires_at: now + 86_400,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            allowance,
            &issuer,
        )?;
        let mut workers = BTreeMap::new();
        for name in WORKERS {
            workers.insert(name.into(), worker(&root, &owner, &issuer, name)?);
        }
        let grants = Grants { root, workers };
        crate::retain(&authority_path, &grants)?;
        grants
    } else {
        crate::read(&authority_path).context("Retained authority missing; refusing replacement")?
    };
    let budget = grants
        .root
        .aggregate_invocation_budget
        .as_ref()
        .context("Family allowance missing")?;
    anyhow::ensure!(
        budget.max_invocations == allowance,
        "Retained allowance differs; refusing replacement"
    );
    let mut services = tokio::task::JoinSet::new();
    for (index, name) in WORKERS.iter().enumerate() {
        let state = directory.join(name);
        files::private_directory(&state)?;
        let operator_path = state.join("operator.json");
        let operator = if fresh {
            let value = json!({"agentToken":Keypair::generate().seed_hex(),"adminToken":Keypair::generate().seed_hex(),"port":first_port + index as u16,"signer":issuer.public_key().to_hex(),"worker":name,"capability":grants.workers[*name].id,"family":grants.root.id});
            crate::retain(&operator_path, &value)?;
            value
        } else {
            crate::read(&operator_path)?
        };
        anyhow::ensure!(
            operator["port"] == first_port + index as u16,
            "Retained worker port differs"
        );
        let config = config(&directory, &state, &resource, &operator)?;
        let authority = BoundSessionAuthority::new(
            grants.root.clone(),
            grants.workers[*name].clone(),
            admission.clone(),
        )?;
        services.spawn(async move { serve_http_bound(config, authority).await });
    }
    println!(
        "native worker endpoints: {first_port}..{}; one retained family; {allowance} shared calls",
        first_port + 5
    );
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        stopped = services.join_next() => { anyhow::bail!("Worker endpoint stopped: {stopped:?}"); }
    }
    services.shutdown().await;
    drop(lease);
    Ok(())
}

fn config(
    directory: &Path,
    state: &Path,
    resource: &Path,
    operator: &serde_json::Value,
) -> Result<RemoteServeHttpConfig> {
    let token = |name: &str| {
        operator[name]
            .as_str()
            .map(str::to_owned)
            .context("Operator credential missing")
    };
    let port = operator["port"].as_u64().context("Worker port missing")?;
    Ok(RemoteServeHttpConfig {
        listen: format!("127.0.0.1:{port}").parse()?,
        auth_token: Some(token("agentToken")?),
        admin_token: Some(token("adminToken")?),
        auth_jwt_public_key: None,
        auth_jwt_discovery_url: None,
        auth_introspection_url: None,
        auth_introspection_client_id: None,
        auth_introspection_client_secret: None,
        auth_jwt_provider_profile: None,
        auth_server_seed_path: None,
        identity_federation_seed_path: None,
        enterprise_providers_file: None,
        auth_jwt_issuer: None,
        auth_jwt_audience: None,
        control_url: None,
        control_token: None,
        public_base_url: None,
        auth_servers: vec![],
        auth_authorization_endpoint: None,
        auth_token_endpoint: None,
        auth_registration_endpoint: None,
        auth_jwks_uri: None,
        auth_scopes: vec![],
        auth_subject: "mission-worker".into(),
        auth_code_ttl_secs: 300,
        auth_access_token_ttl_secs: 900,
        receipt_db_path: Some(directory.join("receipts.db")),
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        budget_db_path: None,
        session_db_path: Some(state.join("sessions.db")),
        policy_path: directory.join("policy.yaml"),
        server_id: "fs".into(),
        server_name: "Megastart workspace".into(),
        server_version: "1".into(),
        manifest_public_key: None,
        page_size: 50,
        tools_list_changed: false,
        shared_hosted_owner: true,
        wrapped_command: std::env::current_exe()?
            .to_str()
            .context("Executable path is not UTF-8")?
            .into(),
        wrapped_args: vec![
            "native-resource".into(),
            resource
                .to_str()
                .context("Resource path is not UTF-8")?
                .into(),
        ],
        egress_contract: None,
    })
}

/// The mission and its remote sessions borrow one admission owner. Dropping the
/// returned set cancels the endpoints; the application retains every journal.
pub async fn start_mission(
    mission: &crate::mission::Mission,
) -> Result<tokio::task::JoinSet<Result<(), chio_mcp_remote::CliError>>> {
    let selected = mission
        .config
        .native
        .as_ref()
        .context("Native configuration missing")?;
    let directory = mission.directory.join("native");
    let fresh = !directory.exists();
    files::private_directory(&directory)?;
    let resource = directory.join("resource");
    if fresh {
        for sub in ["source", "outputs", "handoffs"] {
            files::private_directory(&resource.join(sub))?;
        }
        for name in ["lib.rs", "tests.rs"] {
            files::create(
                &resource.join("source").join(name),
                files::read_text(&mission.directory.join("source").join(name), 64_000)?.as_bytes(),
            )?;
        }
        for name in WORKERS {
            files::private_directory(&resource.join("outputs").join(name))?;
        }
        files::create(&directory.join("policy.yaml"), b"kernel:\n  max_capability_ttl: 86400\n  delegation_depth_limit: 1\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools: []\n")?;
    }
    let mut services = tokio::task::JoinSet::new();
    for (index, name) in WORKERS.iter().enumerate() {
        let state = directory.join(name);
        files::private_directory(&state)?;
        let path = state.join("operator.json");
        let operator: serde_json::Value = if fresh {
            let value = json!({"agentToken":Keypair::generate().seed_hex(),"adminToken":Keypair::generate().seed_hex(),"port":selected.first_port + index as u16,"signer":mission.host.signer.to_hex(),"worker":name,"capability":mission.authority.workers[*name].id,"family":mission.authority.root.id});
            crate::retain(&path, &value)?;
            value
        } else {
            crate::read(&path)?
        };
        anyhow::ensure!(
            operator["port"] == selected.first_port + index as u16
                && operator["capability"] == mission.authority.workers[*name].id
                && operator["family"] == mission.authority.root.id,
            "Retained native endpoint authority changed"
        );
        let mut config = config(&directory, &state, &resource, &operator)?;
        config.receipt_db_path = Some(mission.directory.join("kernel/receipts.db"));
        let authority = BoundSessionAuthority::new(
            mission.authority.root.clone(),
            mission.authority.workers[*name].clone(),
            mission.host.admission.clone(),
        )?;
        services.spawn(async move { serve_http_bound(config, authority).await });
    }
    // Readiness is observed from actual listening sockets, not a fixed delay.
    for offset in 0..6 {
        let address = (std::net::Ipv4Addr::LOCALHOST, selected.first_port + offset);
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if let Some(stopped) = services.try_join_next() {
                    anyhow::bail!("Native endpoint stopped: {stopped:?}");
                }
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    return Ok(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .context("Native endpoint did not become ready")??;
    }
    Ok(services)
}
