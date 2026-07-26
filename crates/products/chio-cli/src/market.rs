//! `chio guard market {list,info,install}` CLI subcommands.
//!
//! The marketplace surface reuses the `chio-guard-registry` pull path
//! for fetching artifacts. Listing and info read from a local
//! marketplace catalog file ("the catalog") that records, for each
//! guard ref, the manifest fields (`GuardPrice`, `ReputationTier`) plus
//! a recent settlement summary emitted by the settlement observer.
//!
//! The catalog format is a JSON array of [`MarketCatalogEntry`] under the
//! path resolved by `chio guard market --catalog <PATH>`. This module reads
//! the catalog; populating it (for example by walking the OCI registry and
//! indexing manifests) is out of scope here.
//!
//! Three contracts the marketplace preserves:
//!
//! - Discovery is gated by tenant reputation tier; publication is gated
//!   by the cosign bundle path. Tier gating filters output but never
//!   weakens cosign verification.
//! - `install` consults the revocation oracle by way of the
//!   underwriting credit-limit helper; `publisher_revoked = true`
//!   denies regardless of tier.
//! - Re-installing the same ref is idempotent.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chio_appraisal::{
    MarketplaceBasePrice, MarketplaceInvocationPrice, MarketplacePricingContext,
    MarketplacePricingError, MarketplaceReputationTier,
};
use chio_control_plane::trust_control::TrustControlClient;
use chio_guard_registry::{GuardPrice, MARKETPLACE_BLOCK_KEY};
use chio_reputation::{ReputationTier, satisfies_floor};
use chio_underwriting::{
    MarketplaceCreditLimitDecision, MarketplaceCreditLimitRequest, MarketplaceLimitTier,
};
use serde::{Deserialize, Serialize};

/// Schema string emitted on the wire for the JSON output of
/// `chio guard market list`.
pub const MARKET_LIST_REPORT_SCHEMA: &str = "chio.market.list-report.v1";

/// Schema string emitted on the wire for `chio guard market info` JSON.
pub const MARKET_INFO_REPORT_SCHEMA: &str = "chio.market.info-report.v1";

/// Schema string emitted on the wire for `chio guard market install` JSON.
pub const MARKET_INSTALL_REPORT_SCHEMA: &str = "chio.market.install-report.v1";

/// One entry in the local marketplace catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketCatalogEntry {
    /// Digest-pinned OCI ref, for example
    /// `oci://ghcr.io/chio/pii-mask@sha256:...`.
    pub reference: String,
    /// Human-readable name shown in the TTY table.
    pub name: String,
    /// Manifest base price (per the manifest marketplace block).
    pub price: GuardPrice,
    /// Reputation floor required to discover this guard.
    pub reputation_floor: ReputationTier,
    /// Cosign bundle status surfaced for `info`. Pre-rendered as a
    /// short verdict string so the catalog stays decoupled from
    /// chio-attest-verify.
    #[serde(default)]
    pub cosign_status: String,
    /// Recent settlement summary count for the tenant, surfaced by
    /// `info`. Zero when there have been no settlements yet.
    #[serde(default)]
    pub recent_settlement_count: u64,
}

/// Tenant context the marketplace consumes for filtering, pricing, and
/// limit evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketTenantContext {
    /// Tenant identifier surfaced in audit-trail JSON.
    pub tenant_id: String,
    /// Tenant's effective reputation tier.
    pub tier: ReputationTier,
    /// Currency the tenant pays in. ISO 4217.
    pub currency: String,
}

/// Local installation record persisted by `chio guard market install`.
///
/// The record binds a tenant bundle entry to a (reference, price,
/// applied_tier) triple so the kernel-level pricing machinery can
/// charge per-invocation prices for guards in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketInstallRecord {
    /// Schema tag.
    pub schema: String,
    /// Reference that was installed.
    pub reference: String,
    /// Tenant who installed it.
    pub tenant_id: String,
    /// Per-invocation price registered for this guard at install time.
    pub registered_price_units: u64,
    /// Currency for the registered price.
    pub registered_price_currency: String,
    /// Reputation tier applied at install time.
    pub applied_tier: ReputationTier,
    /// Approved credit ceiling for this tenant in minor units.
    pub credit_limit_units: u64,
    /// Currency for the credit limit.
    pub credit_limit_currency: String,
    /// Whether the install was a fresh write or a no-op idempotent
    /// re-install. The CLI surfaces this in JSON output so callers
    /// can assert idempotence.
    pub idempotent_replay: bool,
}

/// Errors raised by the market subcommands.
#[derive(Debug, thiserror::Error)]
pub enum MarketError {
    #[error("market catalog read failed: {0}")]
    CatalogIo(String),
    #[error("market catalog parse failed: {0}")]
    CatalogParse(String),
    #[error("install record write failed: {0}")]
    InstallIo(String),
    #[error("install record parse failed: {0}")]
    InstallRecordParse(String),
    #[error("install record serialize failed: {0}")]
    InstallSerialize(String),
    #[error("guard reference not present in catalog: {0}")]
    UnknownReference(String),
    #[error("install denied: {0}")]
    InstallDenied(String),
    #[error("marketplace pricing failed: {0}")]
    Pricing(String),
    #[error("fiscal marketplace evaluation failed: {0}")]
    Fiscal(String),
}

trait FiscalMarketplaceRuntime {
    fn invocation_price(
        &self,
        base: &MarketplaceBasePrice,
        context: &MarketplacePricingContext,
    ) -> Result<MarketplaceInvocationPrice, MarketError>;

    fn credit_limit(
        &self,
        request: &MarketplaceCreditLimitRequest,
    ) -> Result<MarketplaceCreditLimitDecision, MarketError>;
}

impl FiscalMarketplaceRuntime for TrustControlClient {
    fn invocation_price(
        &self,
        base: &MarketplaceBasePrice,
        context: &MarketplacePricingContext,
    ) -> Result<MarketplaceInvocationPrice, MarketError> {
        self.fiscal_marketplace_price(base, context)
            .map_err(|error| MarketError::Fiscal(error.to_string()))
    }

    fn credit_limit(
        &self,
        request: &MarketplaceCreditLimitRequest,
    ) -> Result<MarketplaceCreditLimitDecision, MarketError> {
        self.fiscal_marketplace_credit_limit(request)
            .map_err(|error| MarketError::Fiscal(error.to_string()))
    }
}

fn read_catalog(path: &Path) -> Result<Vec<MarketCatalogEntry>, MarketError> {
    let bytes = fs::read(path).map_err(|err| MarketError::CatalogIo(err.to_string()))?;
    let entries: Vec<MarketCatalogEntry> =
        serde_json::from_slice(&bytes).map_err(|err| MarketError::CatalogParse(err.to_string()))?;
    Ok(entries)
}

fn tier_to_pricing(tier: ReputationTier) -> MarketplaceReputationTier {
    match tier {
        ReputationTier::Tier0 => MarketplaceReputationTier::Tier0,
        ReputationTier::Tier1 => MarketplaceReputationTier::Tier1,
        ReputationTier::Tier2 => MarketplaceReputationTier::Tier2,
        ReputationTier::Tier3 => MarketplaceReputationTier::Tier3,
    }
}

fn tier_to_limit(tier: ReputationTier) -> MarketplaceLimitTier {
    match tier {
        ReputationTier::Tier0 => MarketplaceLimitTier::Tier0,
        ReputationTier::Tier1 => MarketplaceLimitTier::Tier1,
        ReputationTier::Tier2 => MarketplaceLimitTier::Tier2,
        ReputationTier::Tier3 => MarketplaceLimitTier::Tier3,
    }
}

fn marketplace_price_for_tenant(
    price: &GuardPrice,
    tenant: &MarketTenantContext,
    fiscal: &dyn FiscalMarketplaceRuntime,
) -> Result<MarketplaceInvocationPrice, MarketError> {
    let base = MarketplaceBasePrice::try_new(price.units, price.currency.clone())?;
    let context =
        MarketplacePricingContext::try_new(&tenant.tenant_id, tier_to_pricing(tenant.tier))?;
    fiscal.invocation_price(&base, &context)
}

impl From<MarketplacePricingError> for MarketError {
    fn from(error: MarketplacePricingError) -> Self {
        Self::Pricing(error.to_string())
    }
}

/// Output of [`market_list`]: stable, sorted, machine-readable view of
/// the visible catalog plus per-entry effective price for the tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketListReport {
    pub schema: String,
    pub tenant_id: String,
    pub tenant_tier: ReputationTier,
    pub entries: Vec<MarketListEntry>,
}

/// One row of [`MarketListReport`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketListEntry {
    pub reference: String,
    pub name: String,
    pub effective_price_units: u64,
    pub currency: String,
    pub reputation_floor: ReputationTier,
}

/// Filter the catalog by tenant reputation tier and emit a stable,
/// sorted list view.
pub fn market_list(
    catalog_path: &Path,
    tenant: &MarketTenantContext,
    fiscal: &TrustControlClient,
) -> Result<MarketListReport, MarketError> {
    market_list_with_fiscal(catalog_path, tenant, fiscal)
}

fn market_list_with_fiscal(
    catalog_path: &Path,
    tenant: &MarketTenantContext,
    fiscal: &dyn FiscalMarketplaceRuntime,
) -> Result<MarketListReport, MarketError> {
    let entries = read_catalog(catalog_path)?;
    let mut visible: Vec<MarketListEntry> = entries
        .into_iter()
        .filter(|entry| satisfies_floor(tenant.tier, entry.reputation_floor))
        .map(|entry| {
            let price = marketplace_price_for_tenant(&entry.price, tenant, fiscal)?;
            Ok(MarketListEntry {
                reference: entry.reference,
                name: entry.name,
                effective_price_units: price.units,
                currency: price.currency,
                reputation_floor: entry.reputation_floor,
            })
        })
        .collect::<Result<Vec<_>, MarketError>>()?;
    visible.sort_by(|a, b| a.reference.cmp(&b.reference));

    Ok(MarketListReport {
        schema: MARKET_LIST_REPORT_SCHEMA.to_owned(),
        tenant_id: tenant.tenant_id.clone(),
        tenant_tier: tenant.tier,
        entries: visible,
    })
}

/// Output of [`market_info`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketInfoReport {
    pub schema: String,
    pub reference: String,
    pub name: String,
    pub effective_price_units: u64,
    pub currency: String,
    pub reputation_floor: ReputationTier,
    pub cosign_status: String,
    pub recent_settlement_count: u64,
    pub credit_limit_units: u64,
    pub credit_limit_currency: String,
}

/// Show the current marketplace state for one digest-pinned reference.
///
/// Discovery is gated by tenant reputation tier. A tenant whose tier is
/// below `entry.reputation_floor` MUST NOT see metadata for the guard,
/// matching the visibility gate enforced by `market_list` and
/// `market_install`. The function returns `MarketError::UnknownReference`
/// (not a tier-specific error) so the failure mode is byte-identical to
/// the entry not being present in the catalog. This preserves the
/// undiscoverable contract: a low-tier tenant cannot use `info` to
/// confirm or deny the existence of a guard above their floor.
pub fn market_info(
    catalog_path: &Path,
    tenant: &MarketTenantContext,
    reference: &str,
    publisher_revoked: bool,
    fiscal: &TrustControlClient,
) -> Result<MarketInfoReport, MarketError> {
    market_info_with_fiscal(catalog_path, tenant, reference, publisher_revoked, fiscal)
}

fn market_info_with_fiscal(
    catalog_path: &Path,
    tenant: &MarketTenantContext,
    reference: &str,
    publisher_revoked: bool,
    fiscal: &dyn FiscalMarketplaceRuntime,
) -> Result<MarketInfoReport, MarketError> {
    let entries = read_catalog(catalog_path)?;
    let entry = entries
        .into_iter()
        .find(|entry| {
            entry.reference == reference && satisfies_floor(tenant.tier, entry.reputation_floor)
        })
        .ok_or_else(|| MarketError::UnknownReference(reference.to_owned()))?;

    let price = marketplace_price_for_tenant(&entry.price, tenant, fiscal)?;

    let limit = fiscal.credit_limit(&MarketplaceCreditLimitRequest {
        tenant_id: tenant.tenant_id.clone(),
        reputation_tier: tier_to_limit(tenant.tier),
        currency: tenant.currency.clone(),
        publisher_revoked,
    })?;

    Ok(MarketInfoReport {
        schema: MARKET_INFO_REPORT_SCHEMA.to_owned(),
        reference: entry.reference,
        name: entry.name,
        effective_price_units: price.units,
        currency: price.currency,
        reputation_floor: entry.reputation_floor,
        cosign_status: entry.cosign_status,
        recent_settlement_count: entry.recent_settlement_count,
        credit_limit_units: limit.limit_units,
        credit_limit_currency: limit.currency,
    })
}

/// Bind a pulled guard to the tenant bundle and registered price.
///
/// Idempotent: invoking install twice with the same `(tenant, reference)`
/// produces a record byte-identical to the first invocation, modulo the
/// `idempotent_replay` flag flipping to `true` on the second call.
pub fn market_install(
    catalog_path: &Path,
    bundle_dir: &Path,
    tenant: &MarketTenantContext,
    reference: &str,
    publisher_revoked: bool,
    fiscal: &TrustControlClient,
) -> Result<MarketInstallRecord, MarketError> {
    market_install_with_fiscal(
        catalog_path,
        bundle_dir,
        tenant,
        reference,
        publisher_revoked,
        fiscal,
    )
}

fn market_install_with_fiscal(
    catalog_path: &Path,
    bundle_dir: &Path,
    tenant: &MarketTenantContext,
    reference: &str,
    publisher_revoked: bool,
    fiscal: &dyn FiscalMarketplaceRuntime,
) -> Result<MarketInstallRecord, MarketError> {
    let entries = read_catalog(catalog_path)?;
    let entry = entries
        .into_iter()
        .find(|entry| entry.reference == reference)
        .ok_or_else(|| MarketError::UnknownReference(reference.to_owned()))?;

    if !satisfies_floor(tenant.tier, entry.reputation_floor) {
        return Err(MarketError::InstallDenied(format!(
            "tenant tier {:?} below required floor {:?}",
            tenant.tier, entry.reputation_floor
        )));
    }

    let price = marketplace_price_for_tenant(&entry.price, tenant, fiscal)?;

    let limit = fiscal.credit_limit(&MarketplaceCreditLimitRequest {
        tenant_id: tenant.tenant_id.clone(),
        reputation_tier: tier_to_limit(tenant.tier),
        currency: tenant.currency.clone(),
        publisher_revoked,
    })?;
    if limit.limit_units == 0 {
        return Err(MarketError::InstallDenied(format!(
            "credit limit denied: {}",
            limit.reason
        )));
    }

    fs::create_dir_all(bundle_dir).map_err(|err| MarketError::InstallIo(err.to_string()))?;
    let install_path = install_record_path(bundle_dir, &tenant.tenant_id, reference);

    let record = MarketInstallRecord {
        schema: MARKET_INSTALL_REPORT_SCHEMA.to_owned(),
        reference: entry.reference,
        tenant_id: tenant.tenant_id.clone(),
        registered_price_units: price.units,
        registered_price_currency: price.currency.clone(),
        applied_tier: tenant.tier,
        credit_limit_units: limit.limit_units,
        credit_limit_currency: limit.currency,
        idempotent_replay: false,
    };

    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|err| MarketError::InstallSerialize(err.to_string()))?;
    let mut tmp = tempfile_in(bundle_dir).map_err(|err| MarketError::InstallIo(err.to_string()))?;
    tmp.write_all(&bytes)
        .map_err(|err| MarketError::InstallIo(err.to_string()))?;
    if !tmp
        .persist_new(&install_path)
        .map_err(|err| MarketError::InstallIo(err.to_string()))?
    {
        let mut existing = read_install_record(&install_path)?;
        existing.idempotent_replay = true;
        return Ok(existing);
    }

    Ok(record)
}

fn read_install_record(path: &Path) -> Result<MarketInstallRecord, MarketError> {
    let bytes = fs::read(path).map_err(|err| MarketError::InstallIo(err.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|err| MarketError::InstallRecordParse(err.to_string()))
}

/// Build a non-lossy, traversal-safe filename for an install record.
///
/// `tenant_id` and `reference` are both untrusted from the perspective
/// of this function (`market_install` is `pub`, so callers outside the
/// CLI can supply arbitrary `MarketTenantContext` values). To keep the
/// resulting path inside `bundle_dir` regardless of input, both fields
/// are lowercase-hex-encoded against their SHA-256 digest, and a stable
/// human-readable prefix derived from each field is included for
/// operator legibility. Two distinct inputs cannot produce the same
/// filename (collision resistance is inherited from SHA-256), and the
/// alphabet is restricted to `[0-9a-f._-]` so no path separator,
/// `..` segment, or shell-special byte can appear in the result. The
/// pretty prefix is bounded to 32 bytes per field and is only present
/// to aid grep-driven triage; the digest carries the full identity.
fn install_record_path(bundle_dir: &Path, tenant_id: &str, reference: &str) -> PathBuf {
    use sha2::{Digest, Sha256};

    let tenant_digest = hex::encode(Sha256::digest(tenant_id.as_bytes()));
    let reference_digest = hex::encode(Sha256::digest(reference.as_bytes()));

    let tenant_prefix = sanitize_prefix(tenant_id, 32);
    let reference_prefix = sanitize_prefix(reference, 32);

    let name =
        format!("{tenant_prefix}-{tenant_digest}.{reference_prefix}-{reference_digest}.json");
    bundle_dir.join(name)
}

/// Render a leading slice of `input` using a restricted, traversal-safe
/// alphabet (`[0-9a-z-]`), truncated to `max_len`. Any other byte
/// (including `.` and `_`) is mapped to `-` to keep the result free of
/// `.`, `..`, and path separators while remaining a valid filename
/// component on every platform. The result is never empty: missing or
/// empty inputs collapse to `-`. Used as the human-readable prefix of
/// `install_record_path`; the SHA-256 digest carries the canonical
/// identity, so prefix lossiness is fine and explicitly does not need
/// to be reversible.
fn sanitize_prefix(input: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(max_len);
    for ch in input.chars() {
        if out.len() >= max_len {
            break;
        }
        match ch {
            'a'..='z' | '0'..='9' | '-' => out.push(ch),
            'A'..='Z' => out.push(ch.to_ascii_lowercase()),
            _ => out.push('-'),
        }
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

fn tempfile_in(dir: &Path) -> std::io::Result<TempPersist> {
    let mut path = dir.to_path_buf();
    path.push(format!(".market-install-{}.tmp", uuid_like()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    Ok(TempPersist { file, path })
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:032x}")
}

struct TempPersist {
    file: fs::File,
    path: PathBuf,
}

impl TempPersist {
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.file.write_all(bytes)?;
        self.file.sync_all()?;
        Ok(())
    }

    fn persist_new(self, dest: &Path) -> std::io::Result<bool> {
        drop(self.file);
        match fs::hard_link(&self.path, dest) {
            Ok(()) => {
                fs::remove_file(&self.path)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&self.path);
                Ok(false)
            }
            Err(error) => {
                let _ = fs::remove_file(&self.path);
                Err(error)
            }
        }
    }
}

/// Render a `MarketListReport` as a TTY-friendly text table.
#[must_use]
pub fn render_list_table(report: &MarketListReport) -> String {
    let mut output = String::new();
    output.push_str("REFERENCE\tNAME\tPRICE\tFLOOR\n");
    for entry in &report.entries {
        let row = format!(
            "{}\t{}\t{} {}\t{}\n",
            entry.reference,
            entry.name,
            entry.effective_price_units,
            entry.currency,
            entry.reputation_floor.as_str()
        );
        output.push_str(&row);
    }
    output
}

/// Render a `MarketInfoReport` as a TTY-friendly text view.
#[must_use]
pub fn render_info_text(report: &MarketInfoReport) -> String {
    let mut lines = BTreeMap::new();
    lines.insert("reference", report.reference.clone());
    lines.insert("name", report.name.clone());
    lines.insert(
        "effective_price",
        format!("{} {}", report.effective_price_units, report.currency),
    );
    lines.insert(
        "reputation_floor",
        report.reputation_floor.as_str().to_owned(),
    );
    lines.insert("cosign_status", report.cosign_status.clone());
    lines.insert(
        "recent_settlement_count",
        report.recent_settlement_count.to_string(),
    );
    lines.insert(
        "credit_limit",
        format!(
            "{} {}",
            report.credit_limit_units, report.credit_limit_currency
        ),
    );
    let mut output = String::new();
    for (key, value) in lines {
        output.push_str(&format!("{key}: {value}\n"));
    }
    output
}

/// Re-export of [`MARKETPLACE_BLOCK_KEY`] from the registry crate.
pub const fn _marketplace_block_key_link() -> &'static str {
    MARKETPLACE_BLOCK_KEY
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct BootstrapFiscal;

    impl FiscalMarketplaceRuntime for BootstrapFiscal {
        fn invocation_price(
            &self,
            base: &MarketplaceBasePrice,
            context: &MarketplacePricingContext,
        ) -> Result<MarketplaceInvocationPrice, MarketError> {
            chio_appraisal::compute_checked_marketplace_invocation_price(base, context)
                .map_err(MarketError::from)
        }

        fn credit_limit(
            &self,
            request: &MarketplaceCreditLimitRequest,
        ) -> Result<MarketplaceCreditLimitDecision, MarketError> {
            Ok(chio_underwriting::compute_marketplace_credit_limit(request))
        }
    }

    fn write_catalog(dir: &Path, entries: &[MarketCatalogEntry]) -> PathBuf {
        let path = dir.join("catalog.json");
        let bytes = serde_json::to_vec_pretty(entries).expect("serialize catalog");
        fs::write(&path, bytes).expect("write catalog");
        path
    }

    fn fixture_entries() -> Vec<MarketCatalogEntry> {
        vec![
            MarketCatalogEntry {
                reference:
                    "oci://ghcr.io/chio/pii-mask@sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_owned(),
                name: "pii-mask".to_owned(),
                price: GuardPrice::new(1_000, "USD"),
                reputation_floor: ReputationTier::Tier0,
                cosign_status: "verified".to_owned(),
                recent_settlement_count: 0,
            },
            MarketCatalogEntry {
                reference:
                    "oci://ghcr.io/chio/exfil-blocker@sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
                name: "exfil-blocker".to_owned(),
                price: GuardPrice::new(500, "USD"),
                reputation_floor: ReputationTier::Tier2,
                cosign_status: "verified".to_owned(),
                recent_settlement_count: 0,
            },
        ]
    }

    fn tenant_ctx(tier: ReputationTier) -> MarketTenantContext {
        MarketTenantContext {
            tenant_id: "tenant-a".to_owned(),
            tier,
            currency: "USD".to_owned(),
        }
    }

    #[test]
    fn list_filters_by_reputation_tier() {
        let dir = tempdir().expect("tmpdir");
        let path = write_catalog(dir.path(), &fixture_entries());
        let report = market_list_with_fiscal(
            &path,
            &tenant_ctx(ReputationTier::Tier0),
            &BootstrapFiscal,
        )
        .expect("list runs");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].name, "pii-mask");
    }

    #[test]
    fn list_includes_higher_floor_for_higher_tier() {
        let dir = tempdir().expect("tmpdir");
        let path = write_catalog(dir.path(), &fixture_entries());
        let report = market_list_with_fiscal(
            &path,
            &tenant_ctx(ReputationTier::Tier3),
            &BootstrapFiscal,
        )
        .expect("list runs");
        assert_eq!(report.entries.len(), 2);
        // Sorted lexically by reference.
        assert!(report.entries[0].reference < report.entries[1].reference);
    }

    #[test]
    fn info_emits_effective_price_and_credit_limit() {
        let dir = tempdir().expect("tmpdir");
        let path = write_catalog(dir.path(), &fixture_entries());
        let report = market_info_with_fiscal(
            &path,
            &tenant_ctx(ReputationTier::Tier1),
            "oci://ghcr.io/chio/pii-mask@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            false,
            &BootstrapFiscal,
        )
        .expect("info runs");
        // Tier1 -> 5% discount, 1000 -> 950.
        assert_eq!(report.effective_price_units, 950);
        assert_eq!(report.credit_limit_units, 50_000);
        assert_eq!(report.cosign_status, "verified");
    }

    #[test]
    fn info_unknown_reference_errors() {
        let dir = tempdir().expect("tmpdir");
        let path = write_catalog(dir.path(), &fixture_entries());
        let result = market_info_with_fiscal(
            &path,
            &tenant_ctx(ReputationTier::Tier1),
            "oci://ghcr.io/chio/missing@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            false,
            &BootstrapFiscal,
        );
        assert!(matches!(result, Err(MarketError::UnknownReference(_))));
    }

    #[test]
    fn catalog_pricing_rejects_non_canonical_currency() {
        let dir = tempdir().expect("tmpdir");
        let mut entries = fixture_entries();
        entries[0].price.currency = "usd".to_owned();
        let path = write_catalog(dir.path(), &entries);
        let bundle = dir.path().join("bundle");
        let tenant = tenant_ctx(ReputationTier::Tier1);
        let reference = entries[0].reference.clone();

        let list_result = market_list_with_fiscal(&path, &tenant, &BootstrapFiscal);
        assert!(matches!(list_result, Err(MarketError::Pricing(_))));

        let install_result = market_install_with_fiscal(
            &path,
            &bundle,
            &tenant,
            &reference,
            false,
            &BootstrapFiscal,
        );
        assert!(matches!(install_result, Err(MarketError::Pricing(_))));
        assert!(
            !bundle.exists(),
            "install must fail before writing bundle records for malformed catalog prices"
        );
    }

    #[test]
    fn install_is_idempotent_on_replay() {
        let dir = tempdir().expect("tmpdir");
        let catalog = write_catalog(dir.path(), &fixture_entries());
        let bundle = dir.path().join("bundle");
        let tenant = tenant_ctx(ReputationTier::Tier1);
        let reference = "oci://ghcr.io/chio/pii-mask@sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let first = market_install_with_fiscal(
            &catalog,
            &bundle,
            &tenant,
            reference,
            false,
            &BootstrapFiscal,
        )
        .expect("install runs");
        assert!(!first.idempotent_replay);
        assert_eq!(first.registered_price_units, 950);
        assert_eq!(first.credit_limit_units, 50_000);

        let second = market_install_with_fiscal(
            &catalog,
            &bundle,
            &tenant,
            reference,
            false,
            &BootstrapFiscal,
        )
        .expect("re-install runs");
        assert!(second.idempotent_replay);
        assert_eq!(second.registered_price_units, first.registered_price_units);
    }

    #[test]
    fn install_replay_does_not_rewrite_existing_record() {
        let dir = tempdir().expect("tmpdir");
        let catalog = write_catalog(dir.path(), &fixture_entries());
        let bundle = dir.path().join("bundle");
        let tenant = tenant_ctx(ReputationTier::Tier1);
        let reference = "oci://ghcr.io/chio/pii-mask@sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let first = market_install_with_fiscal(
            &catalog,
            &bundle,
            &tenant,
            reference,
            false,
            &BootstrapFiscal,
        )
        .expect("install runs");
        assert!(!first.idempotent_replay);
        let path = install_record_path(&bundle, &tenant.tenant_id, reference);
        let original_bytes = fs::read(&path).expect("read install record");

        let second = market_install_with_fiscal(
            &catalog,
            &bundle,
            &tenant,
            reference,
            false,
            &BootstrapFiscal,
        )
        .expect("re-install runs");
        assert!(second.idempotent_replay);
        let replay_bytes = fs::read(&path).expect("read replayed install record");
        assert_eq!(
            original_bytes, replay_bytes,
            "idempotent replay must not rewrite the existing install record"
        );
    }

    #[test]
    fn install_denied_below_floor() {
        let dir = tempdir().expect("tmpdir");
        let catalog = write_catalog(dir.path(), &fixture_entries());
        let bundle = dir.path().join("bundle");
        let tenant = tenant_ctx(ReputationTier::Tier0);
        let reference = "oci://ghcr.io/chio/exfil-blocker@sha256:2222222222222222222222222222222222222222222222222222222222222222";

        let result = market_install_with_fiscal(
            &catalog,
            &bundle,
            &tenant,
            reference,
            false,
            &BootstrapFiscal,
        );
        assert!(matches!(result, Err(MarketError::InstallDenied(_))));
    }

    #[test]
    fn install_denied_when_publisher_revoked() {
        let dir = tempdir().expect("tmpdir");
        let catalog = write_catalog(dir.path(), &fixture_entries());
        let bundle = dir.path().join("bundle");
        let tenant = tenant_ctx(ReputationTier::Tier3);
        let reference = "oci://ghcr.io/chio/exfil-blocker@sha256:2222222222222222222222222222222222222222222222222222222222222222";

        let result = market_install_with_fiscal(
            &catalog,
            &bundle,
            &tenant,
            reference,
            true,
            &BootstrapFiscal,
        );
        assert!(matches!(result, Err(MarketError::InstallDenied(_))));
    }

    #[test]
    fn info_below_floor_returns_unknown_reference() {
        // market_info must enforce the reputation floor so a low-tier
        // tenant cannot retrieve metadata for an above-floor guard.
        // The error is UnknownReference, matching the contract that
        // the entry is undiscoverable for this tenant.
        let dir = tempdir().expect("tmpdir");
        let path = write_catalog(dir.path(), &fixture_entries());
        let result = market_info_with_fiscal(
            &path,
            &tenant_ctx(ReputationTier::Tier0),
            "oci://ghcr.io/chio/exfil-blocker@sha256:2222222222222222222222222222222222222222222222222222222222222222",
            false,
            &BootstrapFiscal,
        );
        assert!(matches!(result, Err(MarketError::UnknownReference(_))));
    }

    #[test]
    fn install_record_path_distinguishes_punctuation_variants() {
        // References differing only by punctuation must NOT collide
        // on the install-record path: the digest-keyed scheme is
        // collision-free where a `_`-replacement scheme would be lossy.
        let dir = tempdir().expect("tmpdir");
        let bundle = dir.path().join("bundle");
        let a = install_record_path(&bundle, "tenant", "guard-foo");
        let b = install_record_path(&bundle, "tenant", "guard_foo");
        assert_ne!(a, b);
    }

    #[test]
    fn install_record_path_traversal_inputs_stay_in_bundle_dir() {
        // tenant_id is untrusted because market_install is `pub`.
        // A tenant_id containing path separators or `..` segments
        // must NOT resolve outside `bundle_dir`.
        let dir = tempdir().expect("tmpdir");
        let bundle = dir.path().join("bundle");
        let evil_tenant = "../../etc/passwd";
        let evil_reference = "../../../boot.ini";
        let path = install_record_path(&bundle, evil_tenant, evil_reference);
        let parent = path.parent().expect("install path has parent");
        assert_eq!(
            parent, bundle,
            "install path escaped bundle_dir: {path:?} (parent={parent:?})"
        );
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("filename utf8");
        assert!(!filename.contains('/'));
        assert!(!filename.contains('\\'));
        assert!(!filename.contains(".."));
    }

    #[test]
    fn install_record_path_is_deterministic() {
        let dir = tempdir().expect("tmpdir");
        let bundle = dir.path().join("bundle");
        let a = install_record_path(&bundle, "tenant", "ref");
        let b = install_record_path(&bundle, "tenant", "ref");
        assert_eq!(a, b);
    }
}
