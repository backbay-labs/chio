use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chio_control_plane::trust_control::finding_hosted_profile::FindingHostedProfile;
use chio_core_types::canonical_json_bytes_from_str;
use chio_finding_hosted_edge::{
    serve_hosted_market_loopback_with_shutdown, HostedAuthenticator, HostedHttpServerConfig,
    HostedHttpServerState,
};
use chio_finding_market_store_postgres::{HostedPostgresConfig, PostgresFindingMarketStore};
use clap::Parser;
use nix::libc;
use zeroize::Zeroizing;

const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "chio-finding-market-server")]
#[command(about = "Serve the authenticated PostgreSQL cognition market")]
struct Args {
    #[arg(long)]
    profile: PathBuf,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum ServerError {
    #[error("hosted server profile is invalid")]
    Profile,
    #[error("hosted server secret is unavailable")]
    Secret,
    #[error("hosted server database is unavailable")]
    Database,
    #[error("hosted server authentication boundary is invalid")]
    Authentication,
    #[error("hosted server listener is unavailable")]
    Listener,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), ServerError> {
    let profile: FindingHostedProfile = read_profile(&args.profile)?;
    profile.validate().map_err(|_| ServerError::Profile)?;
    if !profile.listen.ip().is_loopback() {
        return Err(ServerError::Profile);
    }
    let trusted_proxy = profile
        .load_trusted_proxy()
        .map_err(|_| ServerError::Authentication)?
        .ok_or(ServerError::Authentication)?;
    let database_url = Zeroizing::new(
        std::env::var(&profile.database.runtime_url_env).map_err(|_| ServerError::Secret)?,
    );
    let max_jobs =
        i64::try_from(profile.database.max_jobs_per_tenant).map_err(|_| ServerError::Profile)?;
    let database_config = HostedPostgresConfig::new(database_url.to_string())
        .and_then(|config| config.with_ca_certificate(&profile.database.ca_certificate_path))
        .and_then(|config| config.with_max_connections(profile.database.max_connections))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(
                profile.database.acquire_timeout_millis,
            ))
        })
        .and_then(|config| config.with_max_jobs_per_tenant(max_jobs))
        .map_err(|_| ServerError::Profile)?;
    let store = Arc::new(
        PostgresFindingMarketStore::connect(&database_config)
            .await
            .map_err(|_| ServerError::Database)?,
    );
    let authenticator = Arc::new(
        HostedAuthenticator::new(
            profile
                .authenticator_config()
                .map_err(|_| ServerError::Authentication)?,
            store.clone(),
            Arc::new(
                profile
                    .load_api_key_pepper()
                    .map_err(|_| ServerError::Authentication)?,
            ),
        )
        .map_err(|_| ServerError::Authentication)?,
    );
    let state = HostedHttpServerState::new(
        HostedHttpServerConfig {
            public_endpoint: profile.public_endpoint.clone(),
            maximum_body_bytes: MAX_HTTP_BODY_BYTES,
        },
        authenticator,
        store,
        Arc::new(trusted_proxy),
    )
    .map_err(|_| ServerError::Authentication)?;
    let listener = tokio::net::TcpListener::bind(profile.listen)
        .await
        .map_err(|_| ServerError::Listener)?;
    serve_hosted_market_loopback_with_shutdown(listener, state, shutdown_signal())
        .await
        .map_err(|_| ServerError::Listener)
}

#[cfg(unix)]
async fn shutdown_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if result.is_err() {
                        let _ = terminate.recv().await;
                    }
                }
                _ = terminate.recv() => {}
            }
        }
        Err(_) => {
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn read_profile<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ServerError> {
    if !path.is_absolute() {
        return Err(ServerError::Profile);
    }
    let (mut file, metadata) = open_private_regular(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_PROFILE_BYTES {
        return Err(ServerError::Profile);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ServerError::Profile)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ServerError::Profile)?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| ServerError::Profile)?;
    if bytes_len != metadata.len() || bytes_len > MAX_PROFILE_BYTES {
        return Err(ServerError::Profile);
    }
    let raw = std::str::from_utf8(&bytes).map_err(|_| ServerError::Profile)?;
    if canonical_json_bytes_from_str(raw).map_err(|_| ServerError::Profile)? != bytes {
        return Err(ServerError::Profile);
    }
    serde_json::from_slice(&bytes).map_err(|_| ServerError::Profile)
}

fn open_private_regular(path: &Path) -> Result<(File, Metadata), ServerError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| ServerError::Profile)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.mode() & 0o077 != 0
        || before.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(ServerError::Profile);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ServerError::Profile)?;
    let after = file.metadata().map_err(|_| ServerError::Profile)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_file()
        || after.mode() & 0o077 != 0
        || after.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(ServerError::Profile);
    }
    Ok((file, after))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use super::*;

    fn private_file(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap_or_else(|error| panic!("test file create failed: {error}"));
        file.write_all(bytes)
            .unwrap_or_else(|error| panic!("test file write failed: {error}"));
    }

    #[test]
    fn profile_reader_rejects_relative_paths_before_io() {
        assert!(matches!(
            read_profile::<serde_json::Value>(Path::new("profile.json")),
            Err(ServerError::Profile)
        ));
    }

    #[test]
    fn public_errors_do_not_expose_dependency_details() {
        assert_eq!(
            ServerError::Database.to_string(),
            "hosted server database is unavailable"
        );
        assert!(!ServerError::Secret.to_string().contains("environment"));
    }

    #[test]
    fn profile_reader_requires_private_canonical_regular_file() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("test directory create failed: {error}"));
        let profile = directory.path().join("profile.json");
        private_file(&profile, b"{}");
        assert_eq!(
            read_profile::<serde_json::Value>(&profile)
                .unwrap_or_else(|error| panic!("private profile read failed: {error}")),
            serde_json::json!({})
        );
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|error| panic!("test permissions failed: {error}"));
        assert!(matches!(
            read_profile::<serde_json::Value>(&profile),
            Err(ServerError::Profile)
        ));
    }

    #[test]
    fn profile_reader_rejects_symlink_and_oversized_input() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("test directory create failed: {error}"));
        let target = directory.path().join("target.json");
        private_file(&target, b"{}");
        let link = directory.path().join("profile.json");
        std::os::unix::fs::symlink(&target, &link)
            .unwrap_or_else(|error| panic!("test symlink failed: {error}"));
        assert!(matches!(
            read_profile::<serde_json::Value>(&link),
            Err(ServerError::Profile)
        ));

        let oversized = directory.path().join("oversized.json");
        private_file(&oversized, b"{");
        OpenOptions::new()
            .write(true)
            .open(&oversized)
            .and_then(|file| file.set_len(MAX_PROFILE_BYTES + 1))
            .unwrap_or_else(|error| panic!("test sparse file failed: {error}"));
        assert!(matches!(
            read_profile::<serde_json::Value>(&oversized),
            Err(ServerError::Profile)
        ));
    }
}
