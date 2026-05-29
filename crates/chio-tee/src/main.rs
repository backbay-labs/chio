//! `chio-tee` shadow-runner binary.
//!
//! Subcommands:
//!
//! - `--help` / `--version`: read-only introspection, safe for image smoke
//!   tests.
//! - `run`: resolve the operating mode, load the tenant signing key, open the
//!   capture file under `${CHIO_TEE_RUNTIME_DIR}/captures/<run_id>.ndjson`,
//!   install the SIGUSR1 hot-toggle, and drain `Observation` envelopes from
//!   stdin through the shadow runner.
//!
//! The binary fails closed: any configuration, key-load, capture, or
//! enforce-mode error exits non-zero with a diagnostic on stderr.

use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use chio_core::crypto::Keypair;
use chio_store_sqlite::{SqliteEncryptedBlobStore, TenantId, TenantKey};
use chio_tee::{
    load_env_mode, load_tenant_manifest_mode, load_toml_mode, resolve_toml_path, ModeInputs,
    ResolvedMode, RunnerConfig, ShadowRunner, TEE_VERSION,
};

/// Env var naming the runtime directory; captures land under `<dir>/captures/`.
const ENV_RUNTIME_DIR: &str = "CHIO_TEE_RUNTIME_DIR";
/// Env var carrying the tenant signing-key seed as 64 hex chars, or
/// `generate` to mint an ephemeral dev key.
const ENV_TENANT_KEY: &str = "CHIO_TEE_TENANT_KEY";
/// Env var pointing at a file whose contents are the 64-hex tenant seed.
const ENV_TENANT_KEY_FILE: &str = "CHIO_TEE_TENANT_KEY_FILE";
/// Env var naming the tenant the captured blobs are encrypted under.
const ENV_TENANT_ID: &str = "CHIO_TEE_TENANT_ID";
/// Env var pinning the deployment tee id.
const ENV_TEE_ID: &str = "CHIO_TEE_ID";
/// Env var naming the capture run id (defaults to a timestamped value).
const ENV_RUN_ID: &str = "CHIO_TEE_RUN_ID";
/// Env var arming the `--paranoid` redactor heuristic when set to `1`/`true`.
const ENV_PARANOID: &str = "CHIO_TEE_PARANOID";
/// Env var providing a 32-byte (64-hex) tenant at-rest encryption key.
const ENV_TENANT_AT_REST_KEY: &str = "CHIO_TEE_TENANT_AT_REST_KEY";
/// Optional env var pointing at a persistent SQLite blob store; absent => an
/// in-memory store (redacted blobs are transient, frames still persist).
const ENV_BLOB_STORE: &str = "CHIO_TEE_BLOB_STORE";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {
            eprintln!("chio-tee: missing command (try `chio-tee --help`)");
            ExitCode::from(2)
        }
        Some("-h" | "--help") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!("chio-tee {TEE_VERSION}");
            ExitCode::SUCCESS
        }
        Some("run") => match run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("chio-tee run failed (fail-closed): {error}");
                ExitCode::from(1)
            }
        },
        Some(other) => {
            eprintln!("chio-tee: unknown command {other:?} (try `chio-tee --help`)");
            ExitCode::from(2)
        }
    }
}

/// Execute the `run` subcommand. Returns a boxed error so every failure path
/// fails closed with a diagnostic.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = resolve_mode()?;
    let runtime_dir = runtime_dir()?;
    let run_id = std::env::var(ENV_RUN_ID).unwrap_or_else(|_| default_run_id());
    let keypair = load_tenant_keypair()?;

    let tenant_id =
        TenantId::new(std::env::var(ENV_TENANT_ID).unwrap_or_else(|_| "tenant-local".to_string()));
    let tenant_at_rest_key = load_at_rest_key()?;
    let mut config = RunnerConfig::new(tenant_id, tenant_at_rest_key)
        .with_paranoid(is_truthy(&std::env::var(ENV_PARANOID).unwrap_or_default()));
    if let Ok(tee_id) = std::env::var(ENV_TEE_ID) {
        config = config.with_tee_id(tee_id);
    }

    let store = match std::env::var(ENV_BLOB_STORE) {
        Ok(path) if !path.trim().is_empty() => SqliteEncryptedBlobStore::open(PathBuf::from(path))?,
        _ => SqliteEncryptedBlobStore::open_in_memory()?,
    };

    let runner =
        ShadowRunner::from_store(config, resolved.mode, keypair, store, &runtime_dir, &run_id)?;

    // tee.mode_resolved: surface the resolved mode and which layer won.
    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "tee.mode_resolved mode={} source={} capture={}",
        resolved.mode,
        resolved.source.as_str(),
        runner.capture_path().display(),
    )?;
    drop(stderr);

    // Install the SIGUSR1 hot-toggle on Unix: downgrade is unconditional,
    // upgrade requires a capability token read from
    // `${CHIO_TEE_RUNTIME_DIR}/mode-request`.
    #[cfg(unix)]
    let _signal_handle = install_mode_toggle(&runner, &runtime_dir)?;

    // Drain observations from stdin. EOF ends the run cleanly.
    let summary = runner.run(BufReader::new(std::io::stdin().lock()))?;
    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "tee.run_complete observed={} captured={}",
        summary.observed, summary.captured,
    )?;
    Ok(())
}

/// Resolve the operating mode from env > toml > tenant manifest > default.
fn resolve_mode() -> Result<ResolvedMode, Box<dyn std::error::Error>> {
    let env = load_env_mode()?;
    let toml = load_toml_mode(&resolve_toml_path())?;
    let tenant_manifest = match std::env::var("CHIO_TEE_TENANT_MANIFEST") {
        Ok(path) if !path.trim().is_empty() => load_tenant_manifest_mode(&PathBuf::from(path))?,
        _ => None,
    };
    Ok(ResolvedMode::resolve(ModeInputs {
        env,
        toml,
        tenant_manifest,
    }))
}

/// Resolve the runtime directory, requiring it to be set so captures have a
/// home. Fail-closed if unset.
fn runtime_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    match std::env::var(ENV_RUNTIME_DIR) {
        Ok(dir) if !dir.trim().is_empty() => Ok(PathBuf::from(dir)),
        _ => Err(format!("{ENV_RUNTIME_DIR} must be set to the tee runtime directory").into()),
    }
}

/// Load the tenant signing keypair from `CHIO_TEE_TENANT_KEY`
/// (64-hex seed or `generate`) or `CHIO_TEE_TENANT_KEY_FILE`.
fn load_tenant_keypair() -> Result<Keypair, Box<dyn std::error::Error>> {
    if let Ok(value) = std::env::var(ENV_TENANT_KEY) {
        let trimmed = value.trim();
        if trimmed == "generate" {
            return Ok(Keypair::generate());
        }
        if !trimmed.is_empty() {
            return Ok(Keypair::from_seed_hex(trimmed)?);
        }
    }
    if let Ok(path) = std::env::var(ENV_TENANT_KEY_FILE) {
        let contents = std::fs::read_to_string(&path)
            .map_err(|error| format!("failed to read {ENV_TENANT_KEY_FILE} ({path}): {error}"))?;
        return Ok(Keypair::from_seed_hex(contents.trim())?);
    }
    Err(format!(
        "tenant signing key required: set {ENV_TENANT_KEY} (64-hex seed or `generate`) or {ENV_TENANT_KEY_FILE}"
    )
    .into())
}

/// Load the tenant at-rest encryption key (64 hex chars). Defaults to a
/// zeroed key only when the blob store is in-memory and no key is supplied;
/// a persistent store requires an explicit key.
fn load_at_rest_key() -> Result<TenantKey, Box<dyn std::error::Error>> {
    match std::env::var(ENV_TENANT_AT_REST_KEY) {
        Ok(value) if !value.trim().is_empty() => {
            let bytes = decode_hex_32(value.trim())?;
            Ok(TenantKey::from_bytes(bytes))
        }
        _ => {
            if let Ok(path) = std::env::var(ENV_BLOB_STORE) {
                if !path.trim().is_empty() {
                    return Err(format!(
                        "{ENV_TENANT_AT_REST_KEY} (64-hex) is required when {ENV_BLOB_STORE} names a persistent store"
                    )
                    .into());
                }
            }
            Ok(TenantKey::from_bytes([0u8; 32]))
        }
    }
}

/// Decode exactly 32 bytes from a 64-char hex string.
fn decode_hex_32(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("at-rest key must be 64 hex chars (32 bytes)".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("invalid hex digit in at-rest key".into()),
    }
}

/// Build a timestamped run id when one is not pinned. Uses the wall clock
/// millis so concurrent runs in one runtime dir do not collide.
fn default_run_id() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("run-{millis}")
}

fn is_truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "yes" | "on")
}

/// Install the SIGUSR1 mode-toggle handler. The handler reads
/// `${runtime_dir}/mode-request` (a mode tag plus optional capability token on
/// the next line) and applies the transition through the shared mode cell.
#[cfg(unix)]
fn install_mode_toggle(
    runner: &ShadowRunner,
    runtime_dir: &std::path::Path,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use std::str::FromStr;

    use chio_tee::{config::install_sigusr1_handler, Mode};

    let mode_state = runner.mode_state();
    let request_path = runtime_dir.join("mode-request");
    install_sigusr1_handler(move || {
        let Ok(contents) = std::fs::read_to_string(&request_path) else {
            return;
        };
        let mut lines = contents.lines();
        let Some(tag) = lines.next() else {
            return;
        };
        let Ok(target) = Mode::from_str(tag.trim()) else {
            return;
        };
        let capability = lines.next().map(str::trim).filter(|s| !s.is_empty());
        // Downgrades are unconditional; upgrades require a non-empty token.
        let _ = mode_state.transition(target, capability);
    })
}

fn print_help() {
    println!(
        "chio-tee {TEE_VERSION}\n\
         \n\
         Usage: chio-tee <command>\n\
         \n\
         Commands:\n\
         \x20 run            Capture observed kernel decisions into signed replay frames.\n\
         \x20 -h, --help     Show this help.\n\
         \x20 -V, --version  Show the version.\n\
         \n\
         `chio-tee run` resolves the operating mode (env > toml > tenant\n\
         manifest > verdict-only default), loads the tenant signing key, and\n\
         drains newline-delimited Observation envelopes from stdin. Each\n\
         observation is redacted (fail-closed), its redacted blobs are\n\
         persisted encrypted, and a tenant-signed chio-tee-frame.v1 record is\n\
         appended to ${{CHIO_TEE_RUNTIME_DIR}}/captures/<run_id>.ndjson.\n\
         \n\
         Environment:\n\
         \x20 CHIO_TEE_MODE             verdict-only | shadow | enforce\n\
         \x20 CHIO_TEE_CONFIG           sidecar TOML path ([tee] mode = ...)\n\
         \x20 CHIO_TEE_RUNTIME_DIR      required; capture + signal files live here\n\
         \x20 CHIO_TEE_TENANT_KEY       64-hex Ed25519 seed, or `generate`\n\
         \x20 CHIO_TEE_TENANT_KEY_FILE  file holding the 64-hex seed\n\
         \x20 CHIO_TEE_TENANT_AT_REST_KEY 64-hex at-rest blob key (required for persistent store)\n\
         \x20 CHIO_TEE_BLOB_STORE       persistent SQLite path (default: in-memory)\n\
         \x20 CHIO_TEE_TENANT_ID        tenant id for blob encryption\n\
         \x20 CHIO_TEE_ID               deployment tee id\n\
         \x20 CHIO_TEE_RUN_ID           capture run id (default: run-<millis>)\n\
         \x20 CHIO_TEE_PARANOID         1/true to arm the zero-match redactor refusal"
    );
}
