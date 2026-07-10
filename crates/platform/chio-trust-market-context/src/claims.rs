pub(super) const CLAIM_DISCOVERY_BOUND: &str = "claim.trust_market.provider_discovery_bound";
pub(super) const CLAIM_SELECTION_BOUND: &str = "claim.trust_market.provider_selection_bound";
pub(super) const CLAIM_SCORECARD_BOUND: &str = "claim.trust_market.local_scorecard_bound";
pub(super) const CLAIM_REPUTATION_IMPORT_BOUND: &str = "claim.trust_market.reputation_import_bound";
pub(super) const CLAIM_SLA_BOUND: &str = "claim.trust_market.sla_commitment_bound";
pub(super) const CLAIM_COLLATERAL_GUARANTEE_BOUND: &str =
    "claim.trust_market.collateral_guarantee_bound";
pub(super) const CLAIM_JURISDICTION_BOUND: &str = "claim.trust_market.jurisdiction_bound";
pub(super) const CLAIM_UNSUPPORTED_MARKET_LIMITED: &str =
    "claim.trust_market.unsupported_market_claims_limited";
pub(super) const CLAIM_RISK_COMPTROLLER_REPORT_BOUND: &str = "claim.risk.comptroller_report_bound";

const BLOCKED_MARKET_CLAIMS: &[&str] = &[
    "claim.market.permissionless_provider_marketplace_operated",
    "claim.market.global_trust_score_published",
    "claim.market.liquidity_pool_operated",
    "claim.market.risk_syndication_operated",
    "claim.market.underwriter_market_operated",
    "claim.market.autonomous_guarantee_product_sold",
    "claim.market.slashing_court_operated",
];

pub(super) fn blocked_market_claim(claim: &str) -> bool {
    BLOCKED_MARKET_CLAIMS.contains(&claim)
}

pub(super) fn push_claim_once(verified_claims: &mut Vec<String>, claim: &str) {
    if !verified_claims.iter().any(|verified| verified == claim) {
        verified_claims.push(claim.to_string());
    }
}
