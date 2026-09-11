use chio_core::{
    capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::CapabilityToken,
    },
    crypto::Keypair,
};
use chio_kernel::{
    ChioKernel, KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::ToolManifest;
use std::path::Path;

pub struct Host {
    pub kernel: ChioKernel,
    pub capability: CapabilityToken,
    pub manifest: ToolManifest,
}

pub fn boot(directory: &Path) -> anyhow::Result<Host> {
    let authority_bytes = std::fs::read("authority.json")?;
    let config: serde_json::Value = serde_json::from_slice(&authority_bytes)?;
    let fields = config
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Authority must be an object"))?;
    anyhow::ensure!(
        fields.keys().all(
            |key| ["schema", "tool", "max_invocations", "lifetime_seconds"].contains(&key.as_str())
        ),
        "Unknown authority field"
    );
    anyhow::ensure!(
        config["schema"] == "document-tools.authority.v1",
        "Unknown authority schema"
    );
    anyhow::ensure!(
        config["tool"] == crate::service::TOOL,
        "This host grants only count_words"
    );
    let call_limit = config["max_invocations"]
        .as_u64()
        .filter(|v| (1..=50).contains(v))
        .ok_or_else(|| anyhow::anyhow!("max_invocations must be an integer from 1 to 50"))?
        as u32;
    let lifetime = config["lifetime_seconds"]
        .as_u64()
        .filter(|v| (1..=3600).contains(v))
        .ok_or_else(|| anyhow::anyhow!("lifetime_seconds must be an integer from 1 to 3600"))?;
    // A new application run gets a fresh session. Refuse to reuse its directory.
    std::fs::create_dir(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::write(directory.join("authority.json"), &authority_bytes)?;
    let authority =
        chio_control_plane::DurableAdmissionRuntime::open(&directory.join("admission.db"))?;
    let keypair = authority.kernel_keypair();
    // The host chooses this key before any receipt exists.
    std::fs::write(
        directory.join("kernel-public-key.txt"),
        keypair.public_key().to_hex(),
    )?;
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 3,
        policy_hash: chio_core::sha256_hex(&authority_bytes),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.set_receipt_store(Box::new(chio_store_sqlite::SqliteReceiptStore::open(
        directory.join("receipts.db"),
    )?))?;
    authority.attach(&mut kernel)?;
    let service_key = Keypair::generate();
    let manifest = crate::service::manifest(service_key.public_key().to_hex());
    let signed = chio_manifest::sign_manifest(&manifest, &service_key)?;
    chio_manifest::verify_manifest(&signed, &service_key.public_key())?;
    std::fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec_pretty(&signed)?,
    )?;
    kernel.register_tool_server(Box::new(crate::service::DocumentTools));
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: crate::service::SERVER.into(),
                tool_name: crate::service::TOOL.into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: Some(call_limit),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        lifetime,
    )?;
    std::fs::write(
        directory.join("capability.json"),
        serde_json::to_vec_pretty(&capability)?,
    )?;
    Ok(Host {
        kernel,
        capability,
        manifest,
    })
}
