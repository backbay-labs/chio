use super::*;

#[derive(Subcommand)]
pub(crate) enum ChioFederationCommands {
    /// Produce local federation authority artifacts for offline verification.
    Authority {
        #[command(subcommand)]
        command: ChioAuthorityCommands,
    },

    /// Verify treaty-bound cross-kernel provenance artifacts.
    Treaty {
        #[command(subcommand)]
        command: ChioTreatyCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioAttestCommands {
    /// Package, verify, and explain buyer-facing attestation evidence.
    Buyer {
        #[command(subcommand)]
        command: ChioBuyerCommands,
    },

    /// Verify Sigstore-backed supply-chain attestations.
    SupplyChain {
        #[command(subcommand)]
        command: ChioSupplyChainCommands,
    },

    /// Verify runtime quote evidence.
    RuntimeQuote {
        #[command(subcommand)]
        command: ChioRuntimeQuoteCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioBuyerCommands {
    /// Build a buyer review packet from a local runtime output directory.
    Packet {
        /// Runtime output directory containing buyer review artifacts.
        #[arg(long = "run-output", value_name = "DIR")]
        run_output: PathBuf,

        /// Output path for buyer attestation review packet JSON.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },

    /// Verify a buyer review package against verifier-owned inputs.
    Verify {
        /// Buyer attestation review package JSON.
        #[arg(long = "package", value_name = "PATH")]
        package: PathBuf,

        /// Verifier-owned trust bundle JSON.
        #[arg(long = "trust-bundle", value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Verifier context JSON.
        #[arg(long, value_name = "PATH")]
        context: PathBuf,

        /// Output path for buyer attestation review report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify a Chio attest proof package directly.
    VerifyProof {
        /// Chio attest proof package JSON.
        #[arg(long = "package", value_name = "PATH")]
        package: PathBuf,

        /// Verifier-owned trust bundle JSON.
        #[arg(long = "trust-bundle", value_name = "PATH")]
        trust_bundle: PathBuf,

        /// Verifier context JSON.
        #[arg(long, value_name = "PATH")]
        context: PathBuf,

        /// Output path for verifier report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Verify a hash-only buyer packet as unresolved unless full DSSE review hydrates it.
    VerifyPacket {
        /// Buyer attestation packet JSON.
        #[arg(long, value_name = "PATH")]
        packet: PathBuf,

        /// Receipt lineage statement JSON.
        #[arg(long = "lineage-statement", value_name = "PATH")]
        lineage_statement: PathBuf,

        /// Cross-kernel continuation JSON.
        #[arg(long, value_name = "PATH")]
        continuation: PathBuf,

        /// Cross-boundary admission report JSON.
        #[arg(long = "admission-report", value_name = "PATH")]
        admission_report: PathBuf,

        /// Bilateral invocation JSON.
        #[arg(long = "bilateral-invocation", value_name = "PATH")]
        bilateral_invocation: PathBuf,

        /// Output path for buyer attestation verification report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,
    },

    /// Render a buyer review report as JSON or plain text.
    Explain {
        /// Buyer attestation review report JSON.
        #[arg(long, value_name = "PATH")]
        report: PathBuf,

        /// Explanation format.
        #[arg(long, value_parser = ["json", "text"], default_value = "text")]
        format: String,

        /// Output path for explanation.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioSupplyChainCommands {
    /// Verify a Sigstore bundle against the artifact bytes and expected identity.
    Verify {
        /// Artifact bytes covered by the Sigstore bundle.
        #[arg(long, value_name = "PATH")]
        artifact: PathBuf,

        /// Sigstore bundle JSON.
        #[arg(long, value_name = "PATH")]
        bundle: PathBuf,

        /// Fulcio certificate identity SAN regex expected on the signing cert.
        #[arg(long = "issuer-san-regex", value_name = "REGEX")]
        issuer_san_regex: String,

        /// Fulcio certificate OIDC issuer expected on the signing cert.
        #[arg(long = "issuer-oidc", value_name = "URL")]
        issuer_oidc: String,

        /// Optional output path for a verification report. Defaults to stdout.
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChioRuntimeQuoteCommands {
    /// Verify runtime quote evidence through chio-attest-verify.
    Verify {
        /// Kernel signing public key in Chio canonical text form.
        #[arg(long = "kernel-public-key", value_name = "KEY")]
        kernel_public_key: String,

        /// Receipt root as 64 lowercase hex characters.
        #[arg(long = "receipt-root", value_name = "HEX")]
        receipt_root: String,

        /// Optional observed runtime quote report-data bytes for diagnostic comparison.
        #[arg(long = "report-data", value_name = "HEX")]
        report_data: Option<String>,

        /// TEE backend that produced the quote.
        #[arg(
            long = "tee-kind",
            value_name = "KIND",
            value_parser = ["intel-tdx", "amd-sev-snp", "aws-nitro"]
        )]
        tee_kind: Option<String>,

        /// Raw quote bytes to verify.
        #[arg(long, value_name = "PATH")]
        quote: Option<PathBuf>,

        /// Backend collateral JSON used to verify the quote.
        #[arg(long, value_name = "PATH")]
        collateral: Option<PathBuf>,

        /// Optional output path for a verification report. Defaults to stdout.
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
    },
}

/// Sub-subcommands for `chio arena`.
#[derive(clap::Subcommand)]
pub(crate) enum ArenaCommands {
    /// Run a scenario file and write an arena bundle under target/arena/.
    Run {
        /// Path to the scenario TOML file.
        scenario: PathBuf,
        /// Override the bundle output root (default `target/arena/`).
        #[arg(long, value_name = "DIR")]
        output_root: Option<PathBuf>,
        /// Emit the run summary as JSON on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Replay a previously emitted arena bundle by scenario id.
    ///
    /// Resolves `target/arena/<scenario-id>/` and delegates to the
    /// `chio replay` engine. Use `--bundle-dir` to point at a non-default
    /// bundle location.
    Replay {
        /// Scenario id to replay.
        scenario_id: String,
        /// Override the bundle output root.
        #[arg(long, value_name = "DIR")]
        output_root: Option<PathBuf>,
        /// Resolved bundle directory (overrides `--output-root` plus id).
        #[arg(long, value_name = "DIR")]
        bundle_dir: Option<PathBuf>,
        /// Emit the resolved bundle metadata as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the co-evolution loop for a scenario seed.
    Evolve {
        /// Path to the seed scenario TOML file.
        seed: PathBuf,
        /// Number of generations to run (the bounded-budget gate clamps).
        #[arg(long, default_value_t = 5)]
        generations: u32,
        /// Maximum wall-clock budget in seconds.
        #[arg(long, default_value_t = 1800)]
        wall_seconds: u64,
        /// Override the leaderboard output root (default `target/arena/`).
        #[arg(long, value_name = "DIR")]
        output_root: Option<PathBuf>,
        /// Emit the evolve summary as JSON on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Settle subcommands. Currently exposes a single `status` surface;
/// further verbs (e.g. `clear`, `replay`) can attach here without
/// breaking the `chio settle status` contract.
#[derive(Subcommand)]
pub(crate) enum SettleCommands {
    /// Show pending IOU envelopes, settled receipts, and dead-lettered
    /// settlements for the local store.
    Status {
        /// Path to the chio-store-sqlite database. Defaults to
        /// `--receipt-db` when omitted, which is the same store every
        /// other receipt-aware subcommand reads.
        #[arg(long, value_name = "PATH")]
        store: Option<PathBuf>,

        /// Emit a structured JSON report on stdout instead of the
        /// human-readable text summary.
        #[arg(long)]
        json: bool,
    },
}

/// `chio lineage` subcommands. Surfaces three verbs that the underlying
/// library and tests share.
#[derive(Subcommand)]
pub(crate) enum LineageCommands {
    /// Walk forward or reverse from a seed node id over a lineage JSON dump.
    Query {
        /// Path to the lineage JSON dump (the same format the static
        /// viewer at `docs/demo/lineage` reads).
        #[arg(long, value_name = "PATH")]
        graph: PathBuf,
        /// Seed node ids. Repeatable.
        #[arg(long = "seed", value_name = "ID")]
        seeds: Vec<String>,
        /// Walk direction. `forward` walks downstream edges; `reverse`
        /// walks upstream.
        #[arg(long, default_value = "forward")]
        direction: String,
        /// Maximum recursion depth. Defaults to 20 (matches the
        /// recursive-CTE bound documented on `chio-store-sqlite::lineage_cte`).
        #[arg(long, default_value_t = 20)]
        depth_limit: u32,
        /// Maximum row count.
        #[arg(long, default_value_t = 10_000)]
        row_limit: u32,
        /// Emit a JSON report instead of a TTY summary.
        #[arg(long)]
        json: bool,
    },
    /// Symmetric edge diff between two lineage JSON dumps.
    Diff {
        #[arg(long, value_name = "LABEL")]
        left_label: String,
        #[arg(long, value_name = "PATH")]
        left: PathBuf,
        #[arg(long, value_name = "LABEL")]
        right_label: String,
        #[arg(long, value_name = "PATH")]
        right: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List pinned-frontier artifacts in a directory.
    Roots {
        #[arg(long, value_name = "PATH")]
        dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

/// Conformance harness commands.
#[derive(Subcommand)]
pub(crate) enum ConformanceCommands {
    /// Execute conformance scenarios against a peer language adapter.
    Run {
        /// Peer language adapter to exercise (`js`, `python`, `go`, `cpp`, or `all`).
        #[arg(long)]
        peer: String,

        /// Optional report format. Pass `json` to emit machine-readable JSON
        /// summarising the run; omit to print a human-readable summary.
        #[arg(long)]
        report: Option<String>,

        /// Optional scenario id filter. When set, only scenarios with this id
        /// are surfaced in the printed/written report; the underlying harness
        /// still executes the full corpus.
        #[arg(long)]
        scenario: Option<String>,

        /// Optional output file. When provided, the report is written to this
        /// path; otherwise the report is printed to stdout.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Explicit peer executable to run. Valid only with a single
        /// `--peer` language, and used by release smoke tests after
        /// `fetch-peers` downloads a pinned artifact.
        #[arg(long, value_name = "PATH")]
        peer_binary: Option<PathBuf>,
    },

    /// Download pre-built peer-language adapter binaries pinned in
    /// `crates/tooling/chio-conformance/peers.lock.toml`.
    FetchPeers {
        /// Verify the lockfile shape only; do not download anything.
        #[arg(long)]
        check: bool,

        /// Output directory for fetched binaries.
        #[arg(long, default_value = "./.chio-peers")]
        out: PathBuf,

        /// Optional language filter (`python`, `js`, `go`, `cpp`).
        #[arg(long)]
        language: Option<String>,

        /// Allow a selection whose matching peers are all `published = false`.
        /// This is only for pre-release workflows that validate lockfile shape
        /// before release assets exist; normal fetches fail closed.
        #[arg(long)]
        allow_unpublished_only: bool,

        /// Optional explicit path to `peers.lock.toml`. When omitted the
        /// CLI consults `$CHIO_PEERS_LOCK`, the XDG config dir, the
        /// in-repo path, and the cwd in that order.
        #[arg(long)]
        lockfile: Option<PathBuf>,
    },
}

/// Guard development lifecycle commands.
#[derive(Subcommand)]
pub(crate) enum GuardCommands {
    /// Scaffold a new guard project with Cargo.toml, src/lib.rs, and guard-manifest.yaml.
    New {
        /// Name of the guard project to create.
        name: String,
    },

    /// Compile the guard in the current directory to wasm32-unknown-unknown.
    Build,

    /// Inspect a compiled .wasm guard binary and print exports, ABI compatibility, and memory config.
    Inspect {
        /// Path to the .wasm file to inspect.
        path: PathBuf,
    },

    /// Run YAML test fixtures against a compiled .wasm guard.
    Test {
        /// Path to the .wasm file to test.
        #[arg(long)]
        wasm: PathBuf,
        /// Glob or paths to YAML fixture files.
        fixtures: Vec<PathBuf>,
        /// Fuel limit per fixture evaluation (default: 1_000_000).
        #[arg(long, default_value = "1000000")]
        fuel_limit: u64,
    },

    /// Benchmark a compiled .wasm guard for fuel consumption and latency.
    Bench {
        /// Path to the .wasm file to benchmark.
        path: PathBuf,
        /// Number of iterations (default: 100).
        #[arg(long, default_value = "100")]
        iterations: u32,
        /// Fuel limit per evaluation (default: 1_000_000).
        #[arg(long, default_value = "1000000")]
        fuel_limit: u64,
    },

    /// Package a guard project into a distributable .arcguard archive.
    Pack,

    /// Publish a guard project as a three-layer OCI artifact.
    Publish {
        /// Guard project directory containing guard-manifest.yaml.
        project: PathBuf,
        /// Tag-addressed OCI destination, for example oci://ghcr.io/chio/tool-gate:v1.
        #[arg(long = "ref")]
        reference: String,
        /// WIT file to publish as the first layer.
        #[arg(long, default_value = "wit/chio-guard/world.wit")]
        wit: PathBuf,
        /// Ed25519 signer public key as ed25519:<base64>. If omitted, guard-manifest.yaml is used.
        #[arg(long)]
        signer_public_key: Option<String>,
        /// Optional Sigstore signer subject annotation.
        #[arg(long)]
        signer_subject: Option<String>,
        /// Runtime fuel limit recorded in the config blob.
        #[arg(long, default_value_t = 5_000_000)]
        fuel_limit: u64,
        /// Runtime memory limit in bytes recorded in the config blob.
        #[arg(long, default_value_t = 16_777_216)]
        memory_limit_bytes: u64,
        /// Epoch seed recorded in the config blob.
        #[arg(long)]
        epoch_id_seed: String,
        /// Registry username for HTTP basic auth.
        #[arg(long)]
        username: Option<String>,
        /// Registry password or token for HTTP basic auth.
        /// Prefer `CHIO_GUARD_REGISTRY_PASSWORD` env over the argv form so
        /// the secret does not leak via `ps` / `/proc/<pid>/cmdline`.
        #[arg(
            long,
            requires = "username",
            env = "CHIO_GUARD_REGISTRY_PASSWORD",
            hide_env_values = true
        )]
        password: Option<String>,
        /// Registry host allowed to use HTTP instead of HTTPS.
        #[arg(long = "allow-http-registry")]
        allow_http_registry: Vec<String>,
    },

    /// Pull a digest-pinned guard OCI artifact into the local content-addressed cache.
    Pull {
        /// Digest-pinned OCI source, for example oci://ghcr.io/chio/tool-gate@sha256:<digest>.
        #[arg(long = "ref")]
        reference: String,
        /// Registry username for HTTP basic auth.
        #[arg(long)]
        username: Option<String>,
        /// Registry password or token for HTTP basic auth.
        /// Prefer `CHIO_GUARD_REGISTRY_PASSWORD` env over the argv form so
        /// the secret does not leak via `ps` / `/proc/<pid>/cmdline`.
        #[arg(
            long,
            requires = "username",
            env = "CHIO_GUARD_REGISTRY_PASSWORD",
            hide_env_values = true
        )]
        password: Option<String>,
        /// Registry host allowed to use HTTP instead of HTTPS.
        #[arg(long = "allow-http-registry")]
        allow_http_registry: Vec<String>,
        /// Optional Sigstore bundle JSON to cache alongside the pulled artifact.
        #[arg(long = "sigstore-bundle", value_name = "PATH")]
        sigstore_bundle: Option<PathBuf>,
        /// Fulcio certificate identity SAN regex required for Sigstore cache admission.
        #[arg(long = "sigstore-identity-regex", value_name = "REGEX")]
        sigstore_identity_regex: Option<String>,
        /// OIDC issuer expected on the Sigstore certificate.
        #[arg(long = "sigstore-oidc-issuer", value_name = "URL")]
        sigstore_oidc_issuer: Option<String>,
    },

    /// Manage the local guard digest blocklist.
    Blocklist {
        #[command(subcommand)]
        command: GuardBlocklistCommands,
    },

    /// Install a .arcguard archive to the guard directory.
    Install {
        /// Path to the .arcguard archive file.
        path: PathBuf,
        /// Target directory to extract into (default: ./guards/).
        #[arg(long, default_value = "guards")]
        target_dir: PathBuf,
    },

    /// Sign a .wasm guard binary and write a `.wasm.sig` sidecar.
    Sign {
        /// Path to the `.wasm` file to sign.
        wasm: PathBuf,
        /// Path to a file containing a hex-encoded 32-byte Ed25519 signing seed.
        #[arg(long)]
        key: PathBuf,
        /// Module name to embed in the signed envelope (matches `guard-manifest.yaml`).
        #[arg(long)]
        name: String,
        /// Module version to embed in the signed envelope.
        #[arg(long)]
        version: String,
    },

    /// Verify the `.wasm.sig` sidecar for a .wasm guard binary (exits 0 on success).
    Verify {
        /// Path to the `.wasm` file to verify.
        wasm: PathBuf,
    },

    /// Marketplace surface: list, info, install priced guards.
    Market {
        #[command(subcommand)]
        command: GuardMarketCommands,
    },
}

/// Subcommands under `chio guard market`.
#[derive(Subcommand)]
pub(crate) enum GuardMarketCommands {
    /// List guards visible to the tenant under the tenant's reputation
    /// tier.
    List {
        /// Path to the marketplace catalog JSON file.
        #[arg(long, value_name = "PATH")]
        catalog: PathBuf,
        /// Tenant identifier surfaced in audit-trail output.
        #[arg(long, value_name = "ID", default_value = "default")]
        tenant: String,
        /// Tenant reputation tier (`tier0`/`tier1`/`tier2`/`tier3`).
        #[arg(long, value_name = "TIER", default_value = "tier0")]
        tier: String,
        /// Currency the tenant pays in (ISO 4217).
        #[arg(long, value_name = "CCY", default_value = "USD")]
        currency: String,
        /// Emit a stable JSON report on stdout instead of a TTY table.
        #[arg(long)]
        json: bool,
    },
    /// Show price, reputation floor, cosign status, recent settlements.
    Info {
        /// Path to the marketplace catalog JSON file.
        #[arg(long, value_name = "PATH")]
        catalog: PathBuf,
        /// Digest-pinned guard reference.
        #[arg(long = "ref", value_name = "OCI_REF")]
        reference: String,
        /// Tenant identifier surfaced in audit-trail output.
        #[arg(long, value_name = "ID", default_value = "default")]
        tenant: String,
        /// Tenant reputation tier.
        #[arg(long, value_name = "TIER", default_value = "tier0")]
        tier: String,
        /// Tenant currency.
        #[arg(long, value_name = "CCY", default_value = "USD")]
        currency: String,
        /// Treat the publisher as revoked by the revocation oracle.
        #[arg(long)]
        publisher_revoked: bool,
        /// Emit a stable JSON report on stdout instead of plain text.
        #[arg(long)]
        json: bool,
    },
    /// Bind a pulled guard to the tenant bundle and registered price.
    /// Idempotent on replay.
    Install {
        /// Path to the marketplace catalog JSON file.
        #[arg(long, value_name = "PATH")]
        catalog: PathBuf,
        /// Path to the tenant bundle directory (created if missing).
        #[arg(long, value_name = "DIR")]
        bundle_dir: PathBuf,
        /// Digest-pinned guard reference to install.
        #[arg(long = "ref", value_name = "OCI_REF")]
        reference: String,
        /// Tenant identifier.
        #[arg(long, value_name = "ID", default_value = "default")]
        tenant: String,
        /// Tenant reputation tier.
        #[arg(long, value_name = "TIER", default_value = "tier0")]
        tier: String,
        /// Tenant currency.
        #[arg(long, value_name = "CCY", default_value = "USD")]
        currency: String,
        /// Treat the publisher as revoked by the revocation oracle.
        #[arg(long)]
        publisher_revoked: bool,
        /// Emit a stable JSON record on stdout.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum GuardBlocklistCommands {
    /// Remove a digest from the local guard blocklist.
    Remove {
        /// Digest to remove, as sha256:<64-hex> or bare 64-hex.
        digest: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum McpCommands {
    /// Wrap a stdio MCP server with verdict gating and emit IDE configs.
    ///
    /// Spawns the wrapped server, gates each
    /// `tools/call` through the manifest scaffold, and (when
    /// `--emit-config` is set) prints a paste-ready blob for Cursor /
    /// Claude Desktop / Continue / Zed.
    Wrap(McpWrapArgs),

    /// Wrap an MCP server subprocess and expose a secured MCP edge over stdio.
    Serve {
        /// Path to the policy YAML file. Mutually exclusive with `--preset`.
        #[arg(long, conflicts_with = "preset")]
        policy: Option<PathBuf>,

        /// Bundled policy preset to use instead of `--policy`.
        ///
        /// Available presets:
        /// * `code-agent` -- zero-config policy for coding agents
        ///   (Claude Code, Cursor, MCP filesystem/git/shell servers).
        ///   Allows safe file reads, denies `.env` / `.git/**` /
        ///   `.ssh/**` writes, denies `git push --force`.
        #[arg(long)]
        preset: Option<String>,

        /// Server ID to assign to the wrapped MCP server inside Chio.
        #[arg(long, default_value = "mcp")]
        server_id: String,

        /// Human-readable name for the wrapped MCP server.
        #[arg(long)]
        server_name: Option<String>,

        /// Version string for the wrapped MCP server.
        #[arg(long)]
        server_version: Option<String>,

        /// Override the public key embedded in the synthetic manifest.
        #[arg(long)]
        manifest_public_key: Option<String>,

        /// Page size for paginated `tools/list` responses.
        #[arg(long, default_value_t = 50)]
        page_size: usize,

        /// Whether the edge should advertise `notifications/tools/list_changed`.
        #[arg(long, default_value_t = false)]
        tools_list_changed: bool,

        /// The wrapped MCP server command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Wrap an MCP server subprocess and expose a secured MCP edge over Streamable HTTP.
    ServeHttp {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: PathBuf,

        /// Server ID to assign to the wrapped MCP server inside Chio.
        #[arg(long)]
        server_id: String,

        /// Human-readable name for the wrapped MCP server.
        #[arg(long)]
        server_name: Option<String>,

        /// Version string for the wrapped MCP server.
        #[arg(long)]
        server_version: Option<String>,

        /// Override the public key embedded in the synthetic manifest.
        #[arg(long)]
        manifest_public_key: Option<String>,

        /// Page size for paginated `tools/list` responses.
        #[arg(long, default_value_t = 50)]
        page_size: usize,

        /// Whether the edge should advertise `notifications/tools/list_changed`.
        #[arg(long, default_value_t = false)]
        tools_list_changed: bool,

        /// Use one shared wrapped MCP subprocess for all remote sessions.
        #[arg(long, default_value_t = false)]
        shared_hosted_owner: bool,

        /// Socket address to bind the remote MCP edge to.
        #[arg(long, default_value = "127.0.0.1:8931")]
        listen: SocketAddr,

        /// Static bearer token required for remote MCP session admission.
        /// Prefer `CHIO_AUTH_TOKEN` env over the argv form so the bearer
        /// does not leak via `ps` / `/proc/<pid>/cmdline`.
        #[arg(long, env = "CHIO_AUTH_TOKEN", hide_env_values = true)]
        auth_token: Option<String>,

        /// Public key used to verify externally issued JWT bearer tokens.
        #[arg(long)]
        auth_jwt_public_key: Option<String>,

        /// OIDC discovery URL used to resolve issuer metadata and JWT JWKS keys.
        #[arg(long)]
        auth_jwt_discovery_url: Option<String>,

        /// OAuth2 token introspection endpoint used to validate opaque bearer tokens.
        #[arg(long)]
        auth_introspection_url: Option<String>,

        /// Client ID used when calling the token introspection endpoint.
        #[arg(long)]
        auth_introspection_client_id: Option<String>,

        /// Client secret used when calling the token introspection endpoint.
        /// Prefer `CHIO_MCP_AUTH_INTROSPECTION_CLIENT_SECRET` env over the argv
        /// form so the secret does not leak via `ps` / `/proc/<pid>/cmdline`.
        #[arg(
            long,
            env = "CHIO_MCP_AUTH_INTROSPECTION_CLIENT_SECRET",
            hide_env_values = true
        )]
        auth_introspection_client_secret: Option<String>,

        /// Optional provider profile used for principal mapping and default OIDC discovery behavior.
        #[arg(long, value_enum)]
        auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,

        /// Local auth-server signing seed file. When set, `serve-http` can issue JWTs itself.
        #[arg(long)]
        auth_server_seed_file: Option<PathBuf>,

        /// Persistent seed file used to derive stable Chio subjects from authenticated OAuth bearer principals.
        #[arg(long)]
        identity_federation_seed_file: Option<PathBuf>,

        /// Optional file-backed enterprise provider registry shared with trust-control.
        #[arg(long)]
        enterprise_providers_file: Option<PathBuf>,

        /// Expected bearer-token issuer for remote MCP session admission.
        #[arg(long)]
        auth_jwt_issuer: Option<String>,

        /// Expected bearer-token audience for remote MCP session admission.
        #[arg(long)]
        auth_jwt_audience: Option<String>,

        /// Optional static bearer token for remote admin APIs.
        /// Prefer `CHIO_ADMIN_TOKEN` env over the argv form so the bearer
        /// does not leak via `ps` / `/proc/<pid>/cmdline`.
        #[arg(long, env = "CHIO_ADMIN_TOKEN", hide_env_values = true)]
        admin_token: Option<String>,

        /// Public base URL used when constructing protected-resource metadata URLs.
        #[arg(long)]
        public_base_url: Option<String>,

        /// Authorization server URL advertised via protected-resource metadata.
        #[arg(long = "auth-server")]
        auth_servers: Vec<String>,

        /// OAuth authorization endpoint advertised in colocated auth-server metadata.
        #[arg(long)]
        auth_authorization_endpoint: Option<String>,

        /// OAuth token endpoint advertised in colocated auth-server metadata.
        #[arg(long)]
        auth_token_endpoint: Option<String>,

        /// Optional dynamic client registration endpoint advertised in auth-server metadata.
        #[arg(long)]
        auth_registration_endpoint: Option<String>,

        /// Optional JWKS URI advertised in auth-server metadata.
        #[arg(long)]
        auth_jwks_uri: Option<String>,

        /// Scope hint advertised in protected-resource challenges and metadata.
        #[arg(long = "auth-scope")]
        auth_scopes: Vec<String>,

        /// Subject to embed in locally issued auth-server access tokens.
        #[arg(long, default_value = "operator")]
        auth_subject: String,

        /// Authorization-code lifetime for the hosted auth server.
        #[arg(long, default_value_t = 300)]
        auth_code_ttl_secs: u64,

        /// Access-token lifetime for the hosted auth server.
        #[arg(long, default_value_t = 600)]
        auth_access_token_ttl_secs: u64,

        /// The wrapped MCP server command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ApiCommands {
    /// Start the Chio HTTP sidecar/reverse proxy.
    Protect {
        /// Upstream base URL to proxy to.
        #[arg(long)]
        upstream: String,

        /// Optional local OpenAPI spec path. Auto-discovered when omitted.
        #[arg(long)]
        spec: Option<PathBuf>,

        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:9090")]
        listen: String,

        /// Optional SQLite receipt store path.
        #[arg(long = "receipt-store")]
        receipt_store: Option<PathBuf>,

        /// Wall-clock ceiling in seconds on a single upstream hop, including
        /// reading the full response. Raise it for upstreams with legitimately
        /// slow calls or large bounded responses. Defaults to 20 seconds.
        #[arg(long = "upstream-timeout-secs")]
        upstream_timeout_secs: Option<u64>,
    },
}
