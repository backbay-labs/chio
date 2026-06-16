pub(super) const CLAIM_EXECUTION_LEASE_VALID: &str = "claim.runtime.execution_lease_valid";
pub(super) const CLAIM_NONCE_FRESH: &str = "claim.runtime.nonce_fresh";
pub(super) const CLAIM_REVOCATION_FRESH: &str = "claim.runtime.revocation_fresh_at_dispatch";
pub(super) const CLAIM_SANDBOX_MATCHED: &str = "claim.runtime.sandbox_attestation_matched";
pub(super) const CLAIM_TOOL_ACK_BOUND: &str = "claim.runtime.tool_server_ack_bound";
pub(super) const CLAIM_RECEIPT_TOTALITY: &str = "claim.runtime.receipt_totality_complete";
pub(super) const CLAIM_ADVISORY_NOT_AUTHORIZATION: &str =
    "claim.runtime.advisory_not_used_as_authorization";

pub(super) fn push_claim_once(verified_claims: &mut Vec<String>, claim: &str) {
    if !verified_claims.iter().any(|verified| verified == claim) {
        verified_claims.push(claim.to_string());
    }
}
