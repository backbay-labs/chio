use super::*;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_control_plane::trust_control::finding_operator_profile::{
    FindingOperatorBuyerProfile, FindingOperatorPaths, FindingOperatorProfile,
    FindingOperatorSecretSeeds, FindingOperatorSellerProfile, FINDING_OPERATOR_PROFILE_SCHEMA,
};
use chio_control_plane::trust_control::finding_operator_purchase::{
    FindingOperatorPurchaseExecutor, FindingOperatorPurchaseStorage,
};
use chio_control_plane::trust_control::finding_operator_status::FindingOperatorAuthorityStatusResolver;
use chio_control_plane::trust_control::{
    FindingAuthorityPin, FindingMarketConfig, FindingPoolPin, FindingStatusOperatorPin,
    FindingStatusServiceBond, TrustServiceConfig, VenueLedgerRailObserver,
    FINDING_STATUS_OPERATOR_ROLE,
};
use chio_core::{canonical_json_bytes, sha256_hex, Keypair};
use chio_store_sqlite::{
    SqliteAuthorityStore, SqliteFindingOperatorBundleStore,
    SqliteFindingOperatorPaymentAdapter, SqliteFindingPayloadStore, SqliteReceiptStore, TenantId,
    TenantKey,
};

const PROFILE_FILE: &str = "operator-profile.json";
const PROFILE_MAX_BYTES: usize = 1024 * 1024;
const ROLE_WINDOW_SECS: u64 = 10 * 365 * 24 * 60 * 60;

struct GeneratedRoles {
    venue: Keypair,
    listing: Keypair,
    governance_root: Keypair,
    authority_status: Keypair,
    verifier_report: Keypair,
    collateral: Keypair,
    purchase: Keypair,
    failed_delivery: Keypair,
    challenge_evaluator: Keypair,
    venue_finalization: Keypair,
    market_penalty: Keypair,
    settlement_observer: Keypair,
    anchor_publisher: Keypair,
    audit_authority: Keypair,
    audit_randomness_witness: Keypair,
    status_feed_operator: Keypair,
    fee_schedule_operator: Keypair,
    kernel: Keypair,
}

impl GeneratedRoles {
    fn generate() -> Self {
        Self {
            venue: Keypair::generate(),
            listing: Keypair::generate(),
            governance_root: Keypair::generate(),
            authority_status: Keypair::generate(),
            verifier_report: Keypair::generate(),
            collateral: Keypair::generate(),
            purchase: Keypair::generate(),
            failed_delivery: Keypair::generate(),
            challenge_evaluator: Keypair::generate(),
            venue_finalization: Keypair::generate(),
            market_penalty: Keypair::generate(),
            settlement_observer: Keypair::generate(),
            anchor_publisher: Keypair::generate(),
            audit_authority: Keypair::generate(),
            audit_randomness_witness: Keypair::generate(),
            status_feed_operator: Keypair::generate(),
            fee_schedule_operator: Keypair::generate(),
            kernel: Keypair::generate(),
        }
    }

    fn secrets(&self) -> FindingOperatorSecretSeeds {
        FindingOperatorSecretSeeds {
            venue: self.venue.seed_hex(),
            listing: self.listing.seed_hex(),
            governance_root: self.governance_root.seed_hex(),
            authority_status: self.authority_status.seed_hex(),
            verifier_report: self.verifier_report.seed_hex(),
            collateral: self.collateral.seed_hex(),
            purchase: self.purchase.seed_hex(),
            failed_delivery: self.failed_delivery.seed_hex(),
            challenge_evaluator: self.challenge_evaluator.seed_hex(),
            venue_finalization: self.venue_finalization.seed_hex(),
            market_penalty: self.market_penalty.seed_hex(),
            settlement_observer: self.settlement_observer.seed_hex(),
            anchor_publisher: self.anchor_publisher.seed_hex(),
            audit_authority: self.audit_authority.seed_hex(),
            audit_randomness_witness: self.audit_randomness_witness.seed_hex(),
            status_feed_operator: self.status_feed_operator.seed_hex(),
            fee_schedule_operator: self.fee_schedule_operator.seed_hex(),
            kernel: self.kernel.seed_hex(),
        }
    }
}

pub(super) fn cmd_finding_operator_init(
    directory: &Path,
    listen: SocketAddr,
    buyer_principal: &str,
    buyer_payout: &str,
    seller_principal: &str,
    seller_payout: &str,
    json_output: bool,
) -> Result<(), CliError> {
    set_operator_umask();
    create_secure_directory(directory)?;
    let profile_path = directory.join(PROFILE_FILE);
    if profile_path.exists() {
        return Err(CliError::cli_other_error(format!(
            "operator profile already exists at {}",
            profile_path.display()
        )));
    }
    for child in ["locks", "packages", "reports"] {
        create_secure_directory(&directory.join(child))?;
    }

    let now = unix_time()?;
    let valid_from = now.saturating_sub(60);
    let valid_until = now
        .checked_add(ROLE_WINDOW_SECS)
        .ok_or_else(|| CliError::cli_other_error("operator role window overflowed".to_owned()))?;
    let roles = GeneratedRoles::generate();
    let pin = |label: &str, keypair: &Keypair| FindingAuthorityPin {
        authority_id: format!("local-{label}"),
        key_hex: keypair.public_key().to_hex(),
        key_epoch: 1,
        valid_from,
        valid_until,
        revocation_status_ref: format!("local/revocations/{label}"),
    };
    let status_feed_id = "finding-status/local-cognition-market".to_owned();
    let status_authority = pin("status-feed-operator", &roles.status_feed_operator);
    let market = FindingMarketConfig {
        venue_id: "local-cognition-market".to_owned(),
        venue: pin("venue", &roles.venue),
        listing: pin("listing", &roles.listing),
        governance_root: pin("governance-root", &roles.governance_root),
        authority_status: pin("authority-status", &roles.authority_status),
        verifier_report: pin("verifier-report", &roles.verifier_report),
        collateral: pin("collateral", &roles.collateral),
        purchase: pin("purchase", &roles.purchase),
        failed_delivery: pin("failed-delivery", &roles.failed_delivery),
        challenge_evaluator: pin("challenge-evaluator", &roles.challenge_evaluator),
        venue_finalization: pin("venue-finalization", &roles.venue_finalization),
        market_penalty: pin("market-penalty", &roles.market_penalty),
        settlement_observer: pin("settlement-observer", &roles.settlement_observer),
        anchor_publisher: pin("anchor-publisher", &roles.anchor_publisher),
        max_snapshot_age_secs: 3_600,
        settlement_finality_requirement: chio_settle::FindingFinalityRequirement::Confirmations {
            min_depth: 1,
        },
        audit_authority: pin("audit-authority", &roles.audit_authority),
        audit_randomness_witness: pin(
            "audit-randomness-witness",
            &roles.audit_randomness_witness,
        ),
        audit_pool: FindingPoolPin {
            principal_id: "pool:local-audit".to_owned(),
            rail_destination: "rail:venue-ledger:local-audit".to_owned(),
            currency: "USD".to_owned(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolPin {
            principal_id: "pool:local-challenge-administration".to_owned(),
            rail_destination: "rail:venue-ledger:local-challenge-administration".to_owned(),
            currency: "USD".to_owned(),
            authority_epoch: 1,
        },
        community_fund_destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_owned(),
        status_feed_operator_ref: status_feed_id.clone(),
        status_feed_operator: FindingStatusOperatorPin {
            feed_id: status_feed_id,
            role: FINDING_STATUS_OPERATOR_ROLE.to_owned(),
            authority: status_authority,
            rotation_policy_ref: "local/rotation/status-feed".to_owned(),
            authorization_sha256: sha256_hex(b"local-cognition-market-status-authorization-v1"),
            revoked_from: None,
        },
        status_feed_service_bond: FindingStatusServiceBond {
            bond_id: "local-status-service-bond".to_owned(),
            feed_id: "finding-status/local-cognition-market".to_owned(),
            operator_id: "local-status-feed-operator".to_owned(),
            locked_units: 1_000,
            currency: "USD".to_owned(),
            valid_from,
            valid_until,
            inclusion_sla_secs: 3_600,
            missed_inclusion_slash_units: 100,
            equivocation_slash_units: 1_000,
            evidence_sha256: sha256_hex(b"local-cognition-market-status-bond-v1"),
        },
        status_max_epoch_age_secs: 300,
        fee_schedule_operator_keys: vec![roles.fee_schedule_operator.public_key().to_hex()],
    };
    let buyer_key = Keypair::generate();
    let profile = FindingOperatorProfile {
        schema: FINDING_OPERATOR_PROFILE_SCHEMA.to_owned(),
        listen,
        service_token: random_token("service"),
        paths: FindingOperatorPaths {
            authority_database: "authority.db".to_owned(),
            authority_lock_root: "locks".to_owned(),
            operator_database: "operator.db".to_owned(),
            receipt_database: "receipts.db".to_owned(),
            packages_directory: "packages".to_owned(),
            reports_directory: "reports".to_owned(),
        },
        market,
        secrets: roles.secrets(),
        payload_key_hex: Keypair::generate().seed_hex(),
        buyers: vec![FindingOperatorBuyerProfile {
            principal_id: buyer_principal.to_owned(),
            bearer_token: random_token("buyer"),
            signing_seed: buyer_key.seed_hex(),
            payout_destination: buyer_payout.to_owned(),
        }],
        sellers: vec![FindingOperatorSellerProfile {
            principal_id: seller_principal.to_owned(),
            bearer_token: random_token("seller"),
            signing_seed: roles.listing.seed_hex(),
            payout_destination: seller_payout.to_owned(),
        }],
    };
    profile
        .validate()
        .map_err(CliError::cli_other_error)?;
    let profile_bytes = canonical_json_bytes(&profile)?;
    write_secret_new(&profile_path, &profile_bytes)?;

    let paths = ResolvedOperatorPaths::new(directory, &profile.paths);
    SqliteAuthorityStore::provision(&paths.authority_database, &paths.authority_lock_root)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    initialize_operator_database(&paths.operator_database)?;
    SqliteReceiptStore::open(&paths.receipt_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;

    let output = serde_json::json!({
        "profile": profile_path,
        "listen": profile.listen,
        "buyerPrincipal": buyer_principal,
        "sellerPrincipal": seller_principal,
        "schema": FINDING_OPERATOR_PROFILE_SCHEMA,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("profile:         {}", profile_path.display());
        println!("listen:          http://{}", profile.listen);
        println!("buyer_principal: {}", terminal_safe(buyer_principal));
        println!("seller_principal: {}", terminal_safe(seller_principal));
        println!("credentials:     retained in the mode-0600 profile");
    }
    Ok(())
}

pub(super) fn cmd_finding_operator_serve(profile_path: &Path) -> Result<(), CliError> {
    set_operator_umask();
    let (profile, root) = load_profile(profile_path)?;
    let paths = ResolvedOperatorPaths::new(&root, &profile.paths);
    let authority = Arc::new(
        SqliteAuthorityStore::open_serving(
            &paths.authority_database,
            &paths.authority_lock_root,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let resolver = Arc::new(
        FindingOperatorAuthorityStatusResolver::new(
            profile.market.authority_status.clone(),
            profile
                .authority_status_key()
                .map_err(CliError::cli_other_error)?,
        )
        .map_err(CliError::cli_other_error)?,
    );
    let executor = Arc::new(
        FindingOperatorPurchaseExecutor::new(
            FindingOperatorPurchaseStorage {
                authority: authority.clone(),
                operator_db_path: paths.operator_database.clone(),
                receipt_db_path: paths.receipt_database.clone(),
                payload_tenant_id: TenantId::new("cognition-market-pilot"),
                payload_key: TenantKey::from_bytes(
                    profile
                        .payload_key_bytes()
                        .map_err(CliError::cli_other_error)?,
                ),
            },
            profile.market.clone(),
            resolver.clone(),
            profile.purchase_keys().map_err(CliError::cli_other_error)?,
            profile
                .buyer_credentials()
                .map_err(CliError::cli_other_error)?,
            &profile.service_token,
        )
        .map_err(CliError::cli_other_error)?,
    );
    let config = trust_config(&profile, &paths);
    chio_control_plane::trust_control::serve_with_finding_purchase_runtime(
        config,
        authority,
        executor,
        Arc::new(VenueLedgerRailObserver),
        resolver,
    )
}

pub(super) fn cmd_finding_operator_tick(
    profile_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    set_operator_umask();
    let (profile, root) = load_profile(profile_path)?;
    let paths = ResolvedOperatorPaths::new(&root, &profile.paths);
    let bundles = SqliteFindingOperatorBundleStore::open(&paths.operator_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let payments = SqliteFindingOperatorPaymentAdapter::open(&paths.operator_database)
        .map_err(CliError::cli_other_error)?;
    let report = serde_json::json!({
        "schema": "chio.finding.operator-tick.v1",
        "bundleCount": bundles.bundle_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "terminalCount": bundles.terminal_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "captureCount": payments.capture_count().map_err(CliError::cli_other_error)?,
        "reconciledJobs": 0,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("bundles:         {}", report["bundleCount"]);
        println!("terminals:       {}", report["terminalCount"]);
        println!("captures:        {}", report["captureCount"]);
        println!("reconciled_jobs: 0");
    }
    Ok(())
}

pub(super) struct ResolvedOperatorPaths {
    pub(super) authority_database: PathBuf,
    pub(super) authority_lock_root: PathBuf,
    pub(super) operator_database: PathBuf,
    pub(super) receipt_database: PathBuf,
    pub(super) packages_directory: PathBuf,
    pub(super) reports_directory: PathBuf,
}

impl ResolvedOperatorPaths {
    pub(super) fn new(root: &Path, paths: &FindingOperatorPaths) -> Self {
        Self {
            authority_database: root.join(&paths.authority_database),
            authority_lock_root: root.join(&paths.authority_lock_root),
            operator_database: root.join(&paths.operator_database),
            receipt_database: root.join(&paths.receipt_database),
            packages_directory: root.join(&paths.packages_directory),
            reports_directory: root.join(&paths.reports_directory),
        }
    }
}

fn trust_config(
    profile: &FindingOperatorProfile,
    paths: &ResolvedOperatorPaths,
) -> TrustServiceConfig {
    TrustServiceConfig {
        listen: profile.listen,
        service_token: profile.service_token.clone(),
        tenant_read_tokens: BTreeMap::new(),
        receipt_db_path: None,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        budget_db_path: None,
        joint_authority_db_path: Some(paths.authority_database.clone()),
        fiscal_runtime: None,
        enterprise_providers_file: None,
        federation_policies_file: None,
        scim_lifecycle_file: None,
        verifier_policies_file: None,
        verifier_challenge_db_path: None,
        passport_statuses_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: Some(format!("http://{}", profile.listen)),
        allow_local_peer_urls: true,
        certification_public_metadata_ttl_seconds: 300,
        peer_urls: Vec::new(),
        cluster_sync_interval: Duration::from_millis(250),
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: Some(profile.market.clone()),
    }
}

pub(super) fn load_profile(path: &Path) -> Result<(FindingOperatorProfile, PathBuf), CliError> {
    require_secret_file(path)?;
    let raw = fs::read(path)?;
    if raw.is_empty() || raw.len() > PROFILE_MAX_BYTES {
        return Err(CliError::cli_other_error(
            "operator profile is empty or exceeds its size bound".to_owned(),
        ));
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| CliError::cli_other_error("operator profile is not UTF-8".to_owned()))?;
    let strict = chio_core::canonical::canonical_json_bytes_from_str(text)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if strict != raw {
        return Err(CliError::cli_other_error(
            "operator profile is not strict canonical JSON".to_owned(),
        ));
    }
    let profile: FindingOperatorProfile = serde_json::from_slice(&raw)?;
    if canonical_json_bytes(&profile)? != raw {
        return Err(CliError::cli_other_error(
            "operator profile typed serialization is not byte-stable".to_owned(),
        ));
    }
    profile.validate().map_err(CliError::cli_other_error)?;
    let root = path
        .parent()
        .ok_or_else(|| CliError::cli_other_error("operator profile has no parent".to_owned()))?
        .to_path_buf();
    Ok((profile, root))
}

fn initialize_operator_database(path: &Path) -> Result<(), CliError> {
    SqliteFindingOperatorBundleStore::open(path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    SqliteFindingPayloadStore::open(path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    SqliteFindingOperatorPaymentAdapter::open(path).map_err(CliError::cli_other_error)?;
    Ok(())
}

fn random_token(label: &str) -> String {
    format!("{label}_{}", Keypair::generate().seed_hex())
}

fn unix_time() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn create_secure_directory(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::cli_other_error(format!(
                "{} is not a directory",
                path.display()
            )));
        }
    } else {
        fs::create_dir(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_secret_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write as _;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn require_secret_file(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::cli_other_error(
            "operator profile must be a regular non-symlink file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::cli_other_error(
                "operator profile must not grant group or other permissions".to_owned(),
            ));
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(CliError::cli_other_error(
                "operator profile is not owned by the current user".to_owned(),
            ));
        }
    }
    Ok(())
}

fn set_operator_umask() {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
}
