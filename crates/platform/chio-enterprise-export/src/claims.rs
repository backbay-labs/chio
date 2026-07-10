pub(super) const CLAIM_DATA_GOVERNANCE_BOUND: &str = "claim.enterprise.data_governance_bound";
pub(super) const CLAIM_EVIDENCE_EXPORT_DIGEST_BOUND: &str =
    "claim.enterprise.evidence_export_digest_bound";
pub(super) const CLAIM_TELEMETRY_PROJECTION_BOUND: &str =
    "claim.enterprise.telemetry_projection_bound";
pub(super) const CLAIM_EXPORT_APPROVAL_BOUND: &str = "claim.enterprise.export_approval_bound";
pub(super) const CLAIM_CONTROL_MAP_BOUND: &str = "claim.enterprise.control_map_bound";
pub(super) const CLAIM_RISK_COMPTROLLER_REPORT_BOUND: &str = "claim.risk.comptroller_report_bound";

pub(super) fn push_claim_once(verified_claims: &mut Vec<String>, claim: &str) {
    if !verified_claims.iter().any(|verified| verified == claim) {
        verified_claims.push(claim.to_string());
    }
}
