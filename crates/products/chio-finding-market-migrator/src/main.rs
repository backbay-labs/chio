use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use chio_finding_market_store_postgres::{HostedPostgresConfig, PostgresFindingMarketMigrator};
use clap::Parser;

const MAX_DATABASE_URL_BYTES: usize = 16 * 1024;

#[derive(Debug, Parser)]
#[command(name = "chio-finding-market-migrate")]
#[command(about = "Apply immutable hosted cognition-market PostgreSQL migrations")]
struct Args {
    /// Environment variable containing the migration-only PostgreSQL URL.
    #[arg(long, default_value = "CHIO_FINDING_MARKET_MIGRATOR_DATABASE_URL")]
    database_url_env: String,
    /// Absolute path to the trusted PostgreSQL certificate authority.
    #[arg(long)]
    ca_certificate: PathBuf,
    /// Maximum time to wait for the single migration connection.
    #[arg(long, default_value_t = 5_000)]
    acquire_timeout_millis: u64,
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

async fn run(args: Args) -> Result<(), &'static str> {
    if args.database_url_env.is_empty()
        || args.database_url_env.len() > 256
        || !args
            .database_url_env
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || !args.ca_certificate.is_absolute()
        || !(100..=30_000).contains(&args.acquire_timeout_millis)
    {
        return Err("finding_market_migrator_arguments_invalid");
    }
    let database_url = std::env::var(&args.database_url_env)
        .map_err(|_| "finding_market_migrator_secret_missing")?;
    if database_url.is_empty()
        || database_url.len() > MAX_DATABASE_URL_BYTES
        || database_url.chars().any(char::is_control)
    {
        return Err("finding_market_migrator_secret_invalid");
    }
    let config = HostedPostgresConfig::new(database_url)
        .and_then(|config| config.with_ca_certificate(args.ca_certificate))
        .and_then(|config| config.with_max_connections(1))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(args.acquire_timeout_millis))
        })
        .map_err(|_| "finding_market_migrator_configuration_invalid")?;
    let migrator = PostgresFindingMarketMigrator::connect(&config)
        .await
        .map_err(|_| "finding_market_migrator_connection_failed")?;
    migrator
        .migrate()
        .await
        .map_err(|_| "finding_market_migration_failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_environment_name_is_strict() {
        let args = Args {
            database_url_env: "lowercase".to_owned(),
            ca_certificate: PathBuf::from("/tmp/ca.pem"),
            acquire_timeout_millis: 5_000,
        };
        assert!(args
            .database_url_env
            .bytes()
            .any(|byte| !byte.is_ascii_uppercase() && !byte.is_ascii_digit() && byte != b'_'));
    }
}
