# Unified Configuration

Status: **Partially shipped -- see caveats below**
Authors: Chio core team
Normative spec: `spec/CONFIGURATION.md`

> **Status note (amended April 2026)**: This document was originally written
> as the design rationale for a unified `chio.yaml` configuration system.
> **Parts of this document are aspirational and do not match the current
> implementation.** Specifically:
>
> - The nested `adapters.mcp/a2a/acp` schema described here is NOT the
>   shipped schema. The current loader uses flat Vec sections. See
>   `crates/platform/chio-config/src/schema.rs` for the actual schema.
> - `kernel.keypair` is NOT shipped. The current field is `kernel.signing_key`.
> - `chio start --config chio.yaml` does NOT exist. The CLI uses per-command
>   `--config` flags on individual subcommands.
>
> For the current, normative config contract, read `spec/CONFIGURATION.md`.
> This document is retained as a non-normative companion for design context
> and migration history. Do not copy-paste examples from this doc without
> checking them against the normative spec.

## 1. Problem Statement

Chio supports three protocol adapters -- MCP, A2A, and ACP-Client -- each with its own
configuration type, builder API, and field naming conventions:

- `McpAdapterConfig` -- `server_id`, `server_name`, `server_version`, `public_key`
- `A2aAdapterConfig` -- `agent_card_url`, `public_key`, `timeout`, OAuth credentials,
  mTLS identity, partner policy, task registry
- `AcpProxyConfig` -- `agent_command`, `agent_args`, `agent_env`, `public_key`,
  `server_id`, `allowed_path_prefixes`, `allowed_commands`

A deployment that uses all three protocols requires constructing each config
independently, managing separate keypair references, and wiring guards and
receipt storage ad-hoc. The kernel's own `KernelConfig` adds yet another
keypair, policy hash, sampling flags, and checkpoint tuning.

This fragmentation is the number one developer experience barrier for new
deployments. One file should configure everything for the common case while
remaining honest about trust-boundary complexity in larger deployments.

## 2. Design Goals

1. **Single file** -- one `chio.yaml` describes the kernel, all adapters, edges,
   receipts, and logging.
2. **Environment variable interpolation** -- `${VAR}` syntax for secrets and
   per-environment values.
3. **Default shared key management** -- one keypair path for local and
   single-operator deployments, with a clear upgrade path to richer key
   hierarchies for hosted or federated environments.
4. **Protocol-specific sections** -- MCP, A2A, and ACP-Client each get their own
   subsection for protocol-specific fields.
5. **Fail-fast validation** -- the config is fully validated at parse time.
   Missing fields, duplicate IDs, and broken references are caught before any
   adapter starts.
6. **Backward compatibility** -- existing programmatic builder APIs continue to
   work. The unified file is an alternative entry point, not a replacement.

## 3. File Format

YAML. Nested structures (auth blocks, partner policies, exporter lists) are more
readable in YAML than in TOML's table syntax. The file is named `chio.yaml` by
convention and, in the proposed runtime flow, would be loaded via
`chio start --config chio.yaml`.

### Full Annotated Example

```yaml
# chio.yaml -- unified Chio configuration

kernel:
  # Path to an Ed25519 keypair file (PEM or raw 64-byte seed+pubkey).
  # Used by the kernel for signing receipts and issuing capabilities.
  # All adapters derive their public_key from this keypair automatically.
  keypair: ./keys/chio-kernel.ed25519

  # SHA-256 hash of the active guard policy file, or the path to the
  # policy file (the loader computes the hash).
  policy: ./policies/default.hush

  # Ordered list of guard names to evaluate on every tool call.
  guards:
    - forbidden-path
    - shell-command
    - secret-leak
    - velocity

  # Trusted CA public keys (hex-encoded Ed25519). Capabilities signed
  # by these keys are accepted without further verification.
  ca_public_keys: []

  max_delegation_depth: 5
  allow_sampling: true
  allow_sampling_tool_use: false
  allow_elicitation: true

  # Streaming limits
  max_stream_duration_secs: 300
  max_stream_total_bytes: 268435456  # 256 MiB

  # Merkle checkpoint interval (0 = disabled)
  checkpoint_batch_size: 100
  require_web3_evidence: false

adapters:
  mcp:
    - id: mcp-filesystem
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
      name: "Filesystem Tools"
      version: "1.0.0"

    - id: mcp-github
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-github"]
      env:
        GITHUB_TOKEN: "${GITHUB_TOKEN}"

  a2a:
    - id: a2a-research-agent
      agent_card_url: "https://research.internal/.well-known/agent-card.json"
      timeout_secs: 30
      version: "0.1.0"
      auth:
        type: oauth2
        client_id: "${A2A_CLIENT_ID}"
        client_secret: "${A2A_CLIENT_SECRET}"
        scopes: ["search", "summarize"]
      partner_policy:
        partner_id: research-team
        required_skills: ["search", "summarize"]
        required_tenant: null
      task_registry: ./registries/research-tasks.json

    - id: a2a-internal-agent
      agent_card_url: "https://internal.corp/.well-known/agent-card.json"
      timeout_secs: 10
      auth:
        type: bearer
        token: "${INTERNAL_BEARER_TOKEN}"

  acp:
    - id: acp-coding-agent
      command: "./agents/coding-agent"
      args: ["--model", "claude-opus-4-6"]
      env:
        ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"
      allowed_paths:
        - /workspace/src
        - /workspace/tests
      allowed_commands:
        - cargo
        - npm
        - git

edges:
  mcp:
    - id: mcp-edge-primary
      expose_from: ["mcp-filesystem", "mcp-github", "a2a-research-agent"]
      bind: "127.0.0.1:8080"
      server_name: "Chio MCP Edge"
      server_version: "1.0.0"

  a2a:
    - id: a2a-edge-primary
      expose_from: ["mcp-filesystem", "mcp-github"]
      agent_name: "Chio A2A Edge"
      bind: "0.0.0.0:8081"
      security_schemes: ["bearer"]

  acp:
    - id: acp-edge-primary
      expose_from: ["mcp-filesystem"]
      agent_name: "Chio ACP-Client Edge"
      advertised_capabilities:
        streaming: true
        permissions: true

receipts:
  store: sqlite://./data/receipts.db
  retention:
    retention_days: 90
    max_size_bytes: 10737418240  # 10 GiB
    archive_path: ./data/receipts-archive.sqlite3
  exporters:
    - type: splunk
      endpoint: "https://splunk.internal:8088"
      token: "${SPLUNK_HEC_TOKEN}"
    - type: elasticsearch
      endpoint: "https://es.internal:9200"

logging:
  level: info
  format: json
```

## 4. Configuration Structs

All structs use `serde::Deserialize` with `#[serde(deny_unknown_fields)]` so
that typos and unsupported fields fail at parse time rather than silently being
ignored.

```rust
use std::collections::HashMap;
use std::path::PathBuf;
use serde::Deserialize;

/// Root of the unified configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioConfig {
    pub kernel: KernelSection,
    #[serde(default)]
    pub adapters: AdaptersSection,
    #[serde(default)]
    pub edges: EdgesSection,
    #[serde(default)]
    pub receipts: Option<ReceiptsSection>,
    #[serde(default)]
    pub logging: Option<LoggingSection>,
}

// -- Kernel --

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelSection {
    /// Path to the Ed25519 keypair file.
    pub keypair: PathBuf,
    /// Path to the policy file (hash computed at load time).
    pub policy: Option<PathBuf>,
    /// Ordered guard names.
    #[serde(default)]
    pub guards: Vec<String>,
    /// Trusted CA public keys (hex-encoded).
    #[serde(default)]
    pub ca_public_keys: Vec<String>,
    #[serde(default = "default_max_delegation_depth")]
    pub max_delegation_depth: u32,
    #[serde(default = "default_true")]
    pub allow_sampling: bool,
    #[serde(default)]
    pub allow_sampling_tool_use: bool,
    #[serde(default = "default_true")]
    pub allow_elicitation: bool,
    #[serde(default = "default_max_stream_duration")]
    pub max_stream_duration_secs: u64,
    #[serde(default = "default_max_stream_bytes")]
    pub max_stream_total_bytes: u64,
    #[serde(default = "default_checkpoint_batch")]
    pub checkpoint_batch_size: u64,
    #[serde(default)]
    pub require_web3_evidence: bool,
}

// -- Adapters --

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptersSection {
    #[serde(default)]
    pub mcp: Vec<McpAdapterEntry>,
    #[serde(default)]
    pub a2a: Vec<A2aAdapterEntry>,
    #[serde(default)]
    pub acp: Vec<AcpAdapterEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAdapterEntry {
    pub id: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_version")]
    pub version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aAdapterEntry {
    pub id: String,
    pub agent_card_url: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub auth: Option<A2aAuthConfig>,
    #[serde(default)]
    pub tls: Option<A2aTlsConfig>,
    #[serde(default)]
    pub partner_policy: Option<A2aPartnerPolicyEntry>,
    #[serde(default)]
    pub task_registry: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum A2aAuthConfig {
    #[serde(rename = "oauth2")]
    OAuth2 {
        client_id: String,
        client_secret: String,
        #[serde(default)]
        scopes: Vec<String>,
        #[serde(default)]
        token_endpoint: Option<String>,
    },
    #[serde(rename = "bearer")]
    Bearer { token: String },
    #[serde(rename = "basic")]
    Basic { username: String, password: String },
    #[serde(rename = "api_key_header")]
    ApiKeyHeader { header_name: String, value: String },
    #[serde(rename = "api_key_query")]
    ApiKeyQuery { param_name: String, value: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aTlsConfig {
    #[serde(default)]
    pub root_ca_pem: Option<PathBuf>,
    #[serde(default)]
    pub client_cert_pem: Option<PathBuf>,
    #[serde(default)]
    pub client_key_pem: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aPartnerPolicyEntry {
    pub partner_id: String,
    #[serde(default)]
    pub required_skills: Vec<String>,
    #[serde(default)]
    pub required_tenant: Option<String>,
    #[serde(default)]
    pub required_security_scheme_names: Vec<String>,
    #[serde(default)]
    pub allowed_interface_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpAdapterEntry {
    pub id: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub allowed_commands: Vec<String>,
}

// -- Edges --

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgesSection {
    #[serde(default)]
    pub mcp: Vec<McpEdgeEntry>,
    #[serde(default)]
    pub a2a: Vec<A2aEdgeEntry>,
    #[serde(default)]
    pub acp: Vec<AcpEdgeEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpEdgeEntry {
    pub id: String,
    /// Adapter IDs whose tools this edge exposes.
    pub expose_from: Vec<String>,
    /// Socket address to bind (e.g., "127.0.0.1:8080").
    pub bind: String,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub server_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aEdgeEntry {
    pub id: String,
    /// Adapter IDs whose tools this edge exposes as A2A skills.
    pub expose_from: Vec<String>,
    /// Agent name advertised in the A2A Agent Card.
    pub agent_name: String,
    /// Socket address to bind (e.g., "0.0.0.0:8081").
    pub bind: String,
    /// Security schemes for inbound A2A requests.
    #[serde(default)]
    pub security_schemes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpEdgeEntry {
    pub id: String,
    /// Adapter IDs whose tools this edge exposes as ACP-Client capabilities.
    pub expose_from: Vec<String>,
    /// Agent name reported in ACP-Client `initialize` response.
    pub agent_name: String,
    /// Capabilities advertised to ACP-Client editors.
    #[serde(default)]
    pub advertised_capabilities: AcpEdgeCapabilities,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpEdgeCapabilities {
    #[serde(default)]
    pub streaming: bool,
    #[serde(default)]
    pub permissions: bool,
}

// -- Receipts --

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptsSection {
    /// SQLite connection string for the receipt store.
    pub store: String,
    #[serde(default)]
    pub retention: Option<RetentionEntry>,
    #[serde(default)]
    pub exporters: Vec<ExporterEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionEntry {
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
    #[serde(default = "default_max_size_bytes")]
    pub max_size_bytes: u64,
    pub archive_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExporterEntry {
    #[serde(rename = "type")]
    pub exporter_type: String,
    pub endpoint: String,
    #[serde(default)]
    pub token: Option<String>,
}

// -- Logging --

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}
```

## 5. Environment Variable Resolution

Any string value in the YAML file may contain `${VAR_NAME}` references. The
loader resolves these after YAML parsing but before serde deserialization of
typed fields.

### Resolution rules

| Pattern | Behavior |
|---------|----------|
| `${VAR}` | Replace with the value of environment variable `VAR`. Error if unset. |
| `${VAR:-default}` | Replace with `VAR` if set, otherwise use `default`. |
| `$$` | Literal `$` (escape hatch). |

### Implementation sketch

```rust
fn resolve_env_vars(raw: &str) -> Result<String, ConfigError> {
    let re = regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")
        .expect("static regex");
    let mut errors = Vec::new();
    let resolved = re.replace_all(raw, |caps: &regex::Captures| {
        let var_name = &caps[1];
        match std::env::var(var_name) {
            Ok(val) => val,
            Err(_) => match caps.get(2) {
                Some(default) => default.as_str().to_string(),
                None => {
                    errors.push(var_name.to_string());
                    String::new()
                }
            },
        }
    });
    if errors.is_empty() {
        Ok(resolved.replace("$$", "$"))
    } else {
        Err(ConfigError::MissingEnvVars(errors))
    }
}
```

Environment variables are resolved in string-typed fields only. Non-string
fields (integers, booleans) cannot contain variable references.

## 6. Key Management

The `kernel.keypair` path points to a single Ed25519 keypair file. This keypair
is the kernel's signing identity and is used for:

- Signing receipts
- Issuing capability tokens
- Generating the `public_key` field for all adapter manifests

This single-keypair model is the **default local profile**, not the entire Chio
trust model. Production hosted deployments may separate trust roots, kernel
signers, capability-authority keys, checkpoint publishers, and verifier trust
bundles. See `TRUST-MODEL-AND-KEY-MANAGEMENT.md` for the broader model.

### Keypair loading

1. Read the file at `kernel.keypair` (resolved relative to the config file's
   parent directory).
2. Detect format: PEM (`-----BEGIN PRIVATE KEY-----`) or raw 64-byte
   seed-plus-public-key.
3. Validate that the public key derived from the seed matches the trailing 32
   bytes (for raw format) or the embedded public key (for PEM).
4. On failure, return `ConfigError::InvalidKeypair` with a descriptive message.

### Per-adapter public key

Adapters do not declare their own `public_key` in the unified config. The
loader extracts the public key from the loaded keypair and injects it into
each adapter's programmatic config struct automatically:

```rust
let keypair = load_keypair(&config.kernel.keypair)?;
let public_key_hex = keypair.public_key().to_hex();

// Injected into McpAdapterConfig, A2aAdapterConfig, AcpProxyConfig
```

If a deployment requires distinct keys per adapter, customer-managed HSM
signing, or separate verifier trust roots, it should use the programmatic
builder API or a future extended runtime config profile instead of assuming the
single-key default here.

## 7. Validation Rules

Validation runs immediately after parsing and environment variable resolution.
Any failure aborts startup with a clear error message.

### ID uniqueness

All `id` fields across all adapter sections share a single namespace. Duplicate
IDs are rejected:

```
Error: duplicate adapter id "mcp-filesystem" (appears in adapters.mcp[0] and adapters.mcp[2])
```

### Edge reference integrity

Every ID in an edge's `expose_from` list must match a declared adapter ID:

```
Error: edges.mcp[0].expose_from references unknown adapter "mcp-typo"
```

### Required fields per protocol

| Protocol | Required fields |
|----------|----------------|
| MCP | `id`, `command` |
| A2A | `id`, `agent_card_url` |
| ACP-Client | `id`, `command` |

### Auth completeness

A2A entries with `auth.type: oauth2` must include both `client_id` and
`client_secret`. Bearer auth must include `token`. Incomplete auth blocks are
rejected at parse time (enforced by serde's `deny_unknown_fields` and required
field declarations on the enum variants).

### Path existence

The loader checks that `kernel.keypair` and `kernel.policy` (when set) point to
existing files. Adapter `command` paths are validated only when they are
absolute paths or begin with `./`. Bare command names (e.g., `npx`) are assumed
to be on `$PATH` and are not checked.

### Guard names

Each name in `kernel.guards` is checked against the set of guards registered in
the guard registry at startup. Unrecognized guard names produce a warning (not
an error) to allow forward compatibility when new guards are added in newer
versions.

## 8. CLI Integration

Proposed CLI integration:

```
chio start --config chio.yaml
```

Status note: `chio start` is not a current command in the repo. The shipped CLI
today exposes `chio mcp serve`, `chio mcp serve-http`, `chio run`, and related
trust/receipt commands. This section specifies the intended future entry point.

### Startup sequence

1. Parse `chio.yaml` and resolve environment variables.
2. Run validation (Section 7).
3. Load the keypair from `kernel.keypair`.
4. Initialize the receipt store from `receipts.store`.
5. Build the guard pipeline from `kernel.guards`.
6. For each MCP adapter entry: spawn the subprocess, perform the MCP
   `initialize` handshake, generate the Chio manifest.
7. For each A2A adapter entry: fetch the agent card, validate partner policy,
   build the transport.
8. For each ACP-Client adapter entry: build the proxy config with the declared
   allowed paths and commands.
9. Register all adapters with the kernel.
10. For each MCP edge entry: resolve `expose_from` IDs to tool server
    connections, bind the edge to the declared address.
11. For each A2A edge entry: resolve `expose_from` IDs, generate Agent Card
    with advertised skills and security schemes, bind the HTTP endpoint.
12. For each ACP-Client edge entry: resolve `expose_from` IDs, build the ACP-Client agent
    with advertised capabilities, prepare stdio transport.
13. Start the receipt exporters.
14. Log the startup summary and begin serving.

### Minimal config

A valid config requires only the kernel section and at least one adapter:

```yaml
kernel:
  keypair: ./keys/dev.ed25519

adapters:
  mcp:
    - id: fs
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-filesystem", "."]
```

## 9. Migration from Individual Configs

The unified config file is an alternative to the programmatic builder API. Both
paths produce the same runtime objects. Teams can adopt the unified file
incrementally.

### Programmatic API remains unchanged

Existing code that constructs `McpAdapterConfig`, `A2aAdapterConfig`, or
`AcpProxyConfig` via builders continues to work without modification:

```rust
// This still works. Nothing changes for programmatic users.
let mcp_config = McpAdapterConfig {
    server_id: "mcp-fs".into(),
    server_name: "Filesystem".into(),
    server_version: "1.0.0".into(),
    public_key: keypair.public_key().to_hex(),
};
let adapter = McpAdapter::from_command("npx", &["-y", "server-fs"], mcp_config)?;
```

### Conversion layer

The `chio-config` crate provides `From` implementations that convert unified
config entries into the existing per-adapter config types:

```rust
impl ChioConfig {
    /// Convert the parsed unified config into the runtime objects
    /// the kernel and adapters expect.
    pub fn into_runtime(self) -> Result<ChioRuntime, ConfigError> {
        let keypair = load_keypair(&self.kernel.keypair)?;
        let public_key_hex = keypair.public_key().to_hex();

        let mcp_adapters: Vec<McpAdapterConfig> = self.adapters.mcp
            .iter()
            .map(|entry| McpAdapterConfig {
                server_id: entry.id.clone().into(),
                server_name: entry.name.clone()
                    .unwrap_or_else(|| entry.id.clone()),
                server_version: entry.version.clone(),
                public_key: public_key_hex.clone(),
            })
            .collect();

        let a2a_adapters: Vec<A2aAdapterConfig> = self.adapters.a2a
            .iter()
            .map(|entry| {
                let mut config = A2aAdapterConfig::new(
                    &entry.agent_card_url,
                    &public_key_hex,
                )
                .with_timeout(Duration::from_secs(entry.timeout_secs))
                .with_server_id(&entry.id)
                .with_server_version(&entry.version);

                if let Some(auth) = &entry.auth {
                    config = apply_a2a_auth(config, auth);
                }
                if let Some(policy) = &entry.partner_policy {
                    config = config.with_partner_policy(
                        policy.clone().into()
                    );
                }
                config
            })
            .collect();

        let acp_proxies: Vec<AcpProxyConfig> = self.adapters.acp
            .iter()
            .map(|entry| {
                let mut config = AcpProxyConfig::new(
                    &entry.command,
                    &public_key_hex,
                )
                .with_server_id(&entry.id)
                .with_agent_args(entry.args.clone());

                for path in &entry.allowed_paths {
                    config = config.with_allowed_path_prefix(path);
                }
                for cmd in &entry.allowed_commands {
                    config = config.with_allowed_command(cmd);
                }
                config
            })
            .collect();

        // ... build KernelConfig, edges, receipt store, exporters ...
        Ok(ChioRuntime { keypair, mcp_adapters, a2a_adapters, acp_proxies, /* ... */ })
    }
}
```

### Hybrid mode

A deployment can load a base config from `chio.yaml` and then programmatically
add or override adapters before starting the kernel:

```rust
let mut runtime = ChioConfig::load("chio.yaml")?.into_runtime()?;

// Add an adapter not in the YAML file
runtime.register_mcp_adapter(my_custom_adapter);

runtime.start()?;
```

This lets teams keep stable infrastructure in the YAML file while varying
per-environment adapters in code.
