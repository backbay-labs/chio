use super::*;
use super::output::{write_bytes, write_pretty_json_line};

fn fiscal_marketplace_client(
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<chio_control_plane::trust_control::TrustControlClient, CliError> {
    let url = control_url.ok_or_else(|| {
        CliError::cli_other_error(
            "guard market requires --control-url so fiscal policy is resolved by the trusted runtime"
                .to_owned(),
        )
    })?;
    let token = require_control_token(control_token)?;
    chio_control_plane::trust_control::service_runtime::client::build_client(url, token)
}

pub(crate) fn parse_market_tier(value: &str) -> Result<chio_reputation::ReputationTier, CliError> {
    match value {
        "tier0" | "tier_0" => Ok(chio_reputation::ReputationTier::Tier0),
        "tier1" | "tier_1" => Ok(chio_reputation::ReputationTier::Tier1),
        "tier2" | "tier_2" => Ok(chio_reputation::ReputationTier::Tier2),
        "tier3" | "tier_3" => Ok(chio_reputation::ReputationTier::Tier3),
        other => Err(CliError::Other(format!(
            "unknown reputation tier '{other}'; expected tier0..tier3"
        ))),
    }
}

pub(crate) fn cmd_market_list(
    catalog: &Path,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    json: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = crate::market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let fiscal = fiscal_marketplace_client(control_url, control_token)?;
    let report = crate::market::market_list(catalog, &context, &fiscal)
        .map_err(|err| CliError::Other(format!("market list: {err}")))?;
    let mut stdout = std::io::stdout();
    if json {
        write_pretty_json_line(&mut stdout, &report, "market list")?;
    } else {
        let table = crate::market::render_list_table(&report);
        write_bytes(&mut stdout, table.as_bytes(), "market list")?;
    }
    Ok(())
}

pub(crate) fn cmd_market_info(
    catalog: &Path,
    reference: &str,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    publisher_revoked: bool,
    json: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = crate::market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let fiscal = fiscal_marketplace_client(control_url, control_token)?;
    let report =
        crate::market::market_info(catalog, &context, reference, publisher_revoked, &fiscal)
            .map_err(|err| CliError::Other(format!("market info: {err}")))?;
    let mut stdout = std::io::stdout();
    if json {
        write_pretty_json_line(&mut stdout, &report, "market info")?;
    } else {
        let text = crate::market::render_info_text(&report);
        write_bytes(&mut stdout, text.as_bytes(), "market info")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_market_install(
    catalog: &Path,
    bundle_dir: &Path,
    reference: &str,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    publisher_revoked: bool,
    json: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = crate::market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let fiscal = fiscal_marketplace_client(control_url, control_token)?;
    let record = crate::market::market_install(
        catalog,
        bundle_dir,
        &context,
        reference,
        publisher_revoked,
        &fiscal,
    )
    .map_err(|err| CliError::Other(format!("market install: {err}")))?;
    let mut stdout = std::io::stdout();
    if json {
        write_pretty_json_line(&mut stdout, &record, "market install")?;
    } else {
        let line = format!(
            "installed {} for tenant {} at {} {} (limit {} {})\n",
            record.reference,
            record.tenant_id,
            record.registered_price_units,
            record.registered_price_currency,
            record.credit_limit_units,
            record.credit_limit_currency,
        );
        write_bytes(&mut stdout, line.as_bytes(), "market install")?;
    }
    Ok(())
}
