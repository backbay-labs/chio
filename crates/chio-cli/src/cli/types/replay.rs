use super::*;

/// Arguments for the `chio replay` subcommand.
#[derive(clap::Args)]
pub struct ReplayArgs {
    /// Path to a receipt-log directory or NDJSON stream.
    /// Required when no sub-subcommand is supplied.
    pub log: Option<PathBuf>,

    /// Treat `log` as a tee NDJSON stream. When omitted, the reader
    /// auto-detects the input shape (directory vs. NDJSON file).
    #[arg(long)]
    pub from_tee: bool,

    /// Ed25519 tenant public-key file required when `--from-tee` is used.
    /// Raw 32-byte and 64-lowercase-hex files are accepted.
    #[arg(long, value_name = "PATH")]
    pub tenant_pubkey: Option<PathBuf>,

    /// Trusted kernel public-key file required for receipt-log replay.
    /// Raw 32-byte Ed25519 and algorithm-aware hex files are accepted.
    #[arg(long, value_name = "PATH")]
    pub trusted_kernel_pubkey: Option<PathBuf>,

    /// Assert the recomputed Merkle root matches this hex string.
    #[arg(long, value_name = "HEX")]
    pub expect_root: Option<String>,

    /// Emit a structured JSON report on stdout (instead of human text).
    #[arg(long)]
    pub json: bool,

    /// (Restricted) Convert a TEE capture into a replay fixture directory.
    /// Requires the local `chio:tee/bless@1` capability gate.
    #[arg(long)]
    pub bless: bool,

    /// Destination fixture directory for `--bless`.
    #[arg(long, value_name = "FIXTURE-DIR", requires = "bless")]
    pub into: Option<PathBuf>,

    /// Optional sub-subcommand. Currently the only variant is
    /// `traffic`, which validates an NDJSON `chio-tee-frame.v1` capture.
    #[command(subcommand)]
    pub command: Option<ReplaySubcommand>,
}

/// Sub-subcommands under `chio replay`.
#[derive(clap::Subcommand)]
pub enum ReplaySubcommand {
    /// Validate or re-execute an NDJSON `chio-tee-frame.v1` capture.
    /// Supply `--against <policy-ref>` to re-execute against a policy with
    /// namespaced replay receipts (`replay:<run_id>:<frame_id>`).
    Traffic(TrafficArgs),
}

/// Arguments for `chio replay traffic`.
#[derive(clap::Args)]
pub struct TrafficArgs {
    /// Path to an NDJSON file containing one `chio-tee-frame.v1` per
    /// line.
    #[arg(long, value_name = "NDJSON")]
    pub from: PathBuf,

    /// Pinned schema name. Defaults to `chio-tee-frame.v1`. The on-the-wire
    /// `schema_version` field is the literal `"1"`; this flag lets callers
    /// pin the schema name for diagnostic clarity. Frames whose
    /// `schema_version` does not match the pinned literal are rejected
    /// regardless of this value.
    #[arg(long, default_value = "chio-tee-frame.v1")]
    pub schema: String,

    /// Optional path to an Ed25519 tenant public-key file (32 raw bytes
    /// or 64 lowercase-hex characters). When supplied, every frame's
    /// `tenant_sig` is verified against this key; mismatches fail
    /// closed. When omitted, the verifier is skipped (frames are still
    /// schema-validated).
    #[arg(long, value_name = "PATH")]
    pub tenant_pubkey: Option<PathBuf>,

    /// Emit a structured JSON report on stdout instead of human text.
    #[arg(long)]
    pub json: bool,

    /// Re-execute every frame against this policy reference.
    ///
    /// Three accepted shapes:
    ///
    /// 1. `<64-lower-hex>` or `sha256:<64-lower-hex>` -- manifest hash.
    ///    Requires manifest registry (not yet wired); surfaces
    ///    `NotResolvable` until then.
    /// 2. `<name>@<semver>` or `version:<name>@<semver>` -- package
    ///    coordinate. Same: `NotResolvable` until package registry lands.
    /// 3. Any other shape (or `path:<file>`) -- workspace-local YAML
    ///    policy file. Fully resolvable now.
    ///
    /// Replay receipts are namespaced `replay:<run_id>:<frame_id>` to
    /// prevent collisions with production receipts.
    #[arg(long, value_name = "POLICY-REF")]
    pub against: Option<String>,

    /// Optional caller-supplied replay run-id. When omitted a fresh
    /// random UUID-v4 is generated per invocation. Useful for
    /// deterministic fixture generation in tests; format is
    /// `[A-Za-z0-9_-]+` (token-shaped so the resulting
    /// `replay:<run_id>:<frame_id>` ids stay grep-friendly).
    #[arg(long, value_name = "ID")]
    pub run_id: Option<String>,
}

