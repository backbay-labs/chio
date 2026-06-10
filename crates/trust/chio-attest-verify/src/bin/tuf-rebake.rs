use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot;
use tokio::fs;
use tough::{ExpirationEnforcement, RepositoryLoader, TargetName};
use url::Url;

const DEFAULT_METADATA_URL: &str = "https://tuf-repo-cdn.sigstore.dev";
const DEFAULT_TARGETS_URL: &str = "https://tuf-repo-cdn.sigstore.dev/targets";
const ROOT_JSON: &str = "root.json";
const TRUSTED_ROOT_JSON: &str = "trusted_root.json";

type DynError = Box<dyn Error + Send + Sync>;
type Result<T> = std::result::Result<T, DynError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Check,
    Write,
}

#[derive(Debug)]
struct Config {
    mode: Mode,
    root_dir: PathBuf,
    metadata_url: String,
    targets_url: String,
}

#[derive(Debug)]
struct RebakedRoot {
    root_json: Vec<u8>,
    trusted_root_json: Vec<u8>,
    root_version: u64,
    trusted_root_sha256: String,
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("tuf-rebake: {error}");
        process::exit(1);
    }
}

fn main_result() -> Result<()> {
    let config = Config::parse(env::args_os().skip(1))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config))
}

impl Config {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let mut mode = None;
        let mut root_dir = default_root_dir()?;
        let mut metadata_url = DEFAULT_METADATA_URL.to_string();
        let mut targets_url = DEFAULT_TARGETS_URL.to_string();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--check") => mode = Some(set_mode(mode, Mode::Check)?),
                Some("--write") => mode = Some(set_mode(mode, Mode::Write)?),
                Some("--root-dir") => {
                    let value = args
                        .next()
                        .ok_or_else(|| invalid_input("--root-dir requires a path argument"))?;
                    root_dir = PathBuf::from(value);
                }
                Some("--metadata-url") => {
                    metadata_url = next_string_arg(&mut args, "--metadata-url")?;
                }
                Some("--targets-url") => {
                    targets_url = next_string_arg(&mut args, "--targets-url")?;
                }
                Some("--help") | Some("-h") => {
                    print_usage();
                    process::exit(0);
                }
                Some(other) => {
                    return Err(invalid_input(format!("unknown argument `{other}`")).into());
                }
                None => {
                    return Err(
                        invalid_input(format!("argument is not valid UTF-8: {arg:?}")).into(),
                    );
                }
            }
        }

        Ok(Self {
            mode: mode.unwrap_or(Mode::Check),
            root_dir,
            metadata_url,
            targets_url,
        })
    }
}

async fn run(config: Config) -> Result<()> {
    let current_root_path = config.root_dir.join(ROOT_JSON);
    let current_trusted_root_path = config.root_dir.join(TRUSTED_ROOT_JSON);
    let current_root = read_required(&current_root_path).await?;
    let current_trusted_root = read_required(&current_trusted_root_path).await?;

    validate_existing_inputs(&current_root, &current_trusted_root)?;

    let rebaked = rebake(&config, &current_root).await?;
    match config.mode {
        Mode::Check => check_current(
            &current_root,
            &current_trusted_root,
            &rebaked,
            &current_root_path,
            &current_trusted_root_path,
        )?,
        Mode::Write => {
            write_if_changed(&current_root_path, &current_root, &rebaked.root_json).await?;
            write_if_changed(
                &current_trusted_root_path,
                &current_trusted_root,
                &rebaked.trusted_root_json,
            )
            .await?;
        }
    }

    println!(
        "tuf-rebake: verified Sigstore root version {} trusted_root sha256 {}",
        rebaked.root_version, rebaked.trusted_root_sha256
    );
    Ok(())
}

async fn rebake(config: &Config, trusted_root: &[u8]) -> Result<RebakedRoot> {
    let metadata_base = Url::parse(&config.metadata_url)?;
    let targets_base = Url::parse(&config.targets_url)?;
    let work_dir = unique_temp_dir()?;
    let metadata_dir = work_dir.join("metadata");
    fs::create_dir_all(&metadata_dir).await?;

    let repository = RepositoryLoader::new(&trusted_root, metadata_base, targets_base)
        .datastore(&metadata_dir)
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .load()
        .await?;

    repository.cache_metadata(&metadata_dir, true).await?;
    let root_version = repository.root().signed.version.get();
    let root_json = read_required(&metadata_dir.join(format!("{root_version}.root.json"))).await?;
    let trusted_root_json = read_verified_target(&repository, TRUSTED_ROOT_JSON).await?;
    validate_rebaked_outputs(&root_json, &trusted_root_json)?;

    let rebaked = RebakedRoot {
        root_version: tuf_root_version(&root_json)?,
        trusted_root_sha256: sha256_hex(&trusted_root_json),
        root_json,
        trusted_root_json,
    };

    if let Err(error) = fs::remove_dir_all(&work_dir).await {
        eprintln!(
            "tuf-rebake: warning: failed to remove temp dir {}: {error}",
            work_dir.display()
        );
    }

    Ok(rebaked)
}

async fn read_verified_target(repository: &tough::Repository, name: &str) -> Result<Vec<u8>> {
    let target_name = TargetName::new(name)?;
    let Some(mut stream) = repository.read_target(&target_name).await? else {
        return Err(invalid_data(format!("TUF target `{name}` is not listed")).into());
    };

    let mut data = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        data.extend_from_slice(&chunk);
    }

    Ok(data)
}

fn check_current(
    current_root: &[u8],
    current_trusted_root: &[u8],
    rebaked: &RebakedRoot,
    current_root_path: &Path,
    current_trusted_root_path: &Path,
) -> Result<()> {
    let mut stale = Vec::new();
    if current_root != rebaked.root_json {
        stale.push(current_root_path.display().to_string());
    }
    if current_trusted_root != rebaked.trusted_root_json {
        stale.push(current_trusted_root_path.display().to_string());
    }
    if stale.is_empty() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "embedded Sigstore trust-root material is stale: {}. Run `scripts/tuf-rebake.sh --write` and commit the refreshed files.",
        stale.join(", ")
    ))
    .into())
}

async fn write_if_changed(path: &Path, old: &[u8], new: &[u8]) -> Result<()> {
    if old == new {
        return Ok(());
    }

    let tmp_path = path.with_extension(format!("json.tmp.{}", process::id()));
    fs::write(&tmp_path, new).await?;
    fs::rename(&tmp_path, path).await?;
    println!("tuf-rebake: updated {}", path.display());
    Ok(())
}

fn validate_existing_inputs(root_json: &[u8], trusted_root_json: &[u8]) -> Result<()> {
    let root_version = tuf_root_version(root_json)?;
    if root_version == 0 {
        return Err(invalid_data("root.json version must be non-zero").into());
    }
    validate_sigstore_trusted_root(trusted_root_json)
}

fn validate_rebaked_outputs(root_json: &[u8], trusted_root_json: &[u8]) -> Result<()> {
    let root_version = tuf_root_version(root_json)?;
    if root_version == 0 {
        return Err(invalid_data("rebaked root.json version must be non-zero").into());
    }
    validate_sigstore_trusted_root(trusted_root_json)
}

fn validate_sigstore_trusted_root(trusted_root_json: &[u8]) -> Result<()> {
    let trust_root = SigstoreTrustRoot::from_trusted_root_json_unchecked(trusted_root_json)?;
    let fulcio_count = trust_root.fulcio_certs()?.len();
    let rekor_count = trust_root.rekor_keys()?.len();
    let ctfe_count = trust_root.ctfe_keys()?.len();

    if fulcio_count == 0 {
        return Err(invalid_data("trusted_root.json has no Fulcio certificates").into());
    }
    if rekor_count == 0 {
        return Err(invalid_data("trusted_root.json has no Rekor keys").into());
    }
    if ctfe_count == 0 {
        return Err(invalid_data("trusted_root.json has no CTFE keys").into());
    }

    Ok(())
}

fn tuf_root_version(root_json: &[u8]) -> Result<u64> {
    let value: serde_json::Value = serde_json::from_slice(root_json)?;
    value
        .pointer("/signed/version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid_data("root.json is missing signed.version").into())
}

async fn read_required(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "required file `{}` is not readable: {error}",
                path.display()
            ),
        )
        .into()
    })
}

fn default_root_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sigstore-root"))
}

fn unique_temp_dir() -> Result<PathBuf> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = env::temp_dir().join(format!("chio-tuf-rebake-{}-{timestamp}", process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn next_string_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    let value = args
        .next()
        .ok_or_else(|| invalid_input(format!("{name} requires a value")))?;
    value
        .into_string()
        .map_err(|value| invalid_input(format!("{name} is not valid UTF-8: {value:?}")).into())
}

fn set_mode(current: Option<Mode>, requested: Mode) -> Result<Mode> {
    if current.is_some() {
        return Err(invalid_input("pass only one of --check or --write").into());
    }
    Ok(requested)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn print_usage() {
    println!(
        "Usage: tuf-rebake [--check|--write] [--root-dir PATH] [--metadata-url URL] [--targets-url URL]"
    );
}
