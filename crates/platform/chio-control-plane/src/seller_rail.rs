// Seller-to-rail resolver for the EIP-3009 off-chain lane.
//
// The kernel `SimPaymentAdapter` stays rail-agnostic. EVM-rail bridging lives
// here, at the control-plane layer: the operator config declares which
// (seller, token_symbol) pair maps to which on-chain rail, and this module
// resolves that mapping. No custody, no broadcast.

use chio_settle::RailBinding;

/// One entry in the operator-configured seller-to-rail table.
#[derive(Debug, Clone)]
pub struct SellerRailEntry {
    /// Seller identifier (matches `GovernedCommerceContext.seller`).
    pub seller: String,
    /// Token symbol this entry applies to (compared case-insensitively).
    pub token_symbol: String,
    /// Resolved EVM rail parameters for this seller and token.
    pub rail: RailBinding,
}

/// Operator config holding the full set of seller-to-rail mappings.
#[derive(Debug, Clone, Default)]
pub struct SellerRailConfig {
    pub entries: Vec<SellerRailEntry>,
}

/// Look up the rail for a (seller, token_symbol) pair from operator config.
///
/// Returns `None` when no matching entry is found, treating a missing rail as
/// an unconfigured lane rather than an error (the caller decides whether to
/// deny or fall through to a different payment path).
pub fn resolve_seller_rail<'a>(
    config: &'a SellerRailConfig,
    seller: &str,
    token_symbol: &str,
) -> Option<&'a RailBinding> {
    config
        .entries
        .iter()
        .find(|entry| {
            entry.seller == seller
                && entry
                    .token_symbol
                    .trim()
                    .eq_ignore_ascii_case(token_symbol.trim())
        })
        .map(|entry| &entry.rail)
}

/// Derive a deterministic sim pseudo-broadcast reference from an EIP-712
/// authorization digest.
///
/// The sim lane never broadcasts on-chain. This function derives a stable,
/// short reference from the digest so the kernel `SimPaymentAdapter` can
/// carry a traceable identifier without touching any EVM node.
pub fn sim_pseudo_ref_from_digest(authorization_digest: &str) -> String {
    let hex = authorization_digest.trim_start_matches("0x");
    format!("sim-eip3009-{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    };
    use chio_core::crypto::Keypair;
    use chio_settle::{
        approval_binding_from_governed, prepare_transfer_with_authorization, Eip3009Domain,
        InMemoryEip3009NonceStore, TransferWithAuthorizationInput,
    };
    use chio_test_support::prelude::*;

    const TEST_CHAIN_ID: u64 = 8453;
    const TEST_TOKEN_CONTRACT: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const TEST_PAYEE: &str = "0x1000000000000000000000000000000000000002";
    /// `issued_at` of the test token; used as `valid_after` for the test authorization.
    const TEST_ISSUED_AT: u64 = 1_744_000_000;
    const TEST_EXPIRES_AT: u64 = 1_744_000_600;
    /// A `now` strictly inside `(TEST_ISSUED_AT, TEST_EXPIRES_AT)`.
    const TEST_NOW: u64 = 1_744_000_300;

    fn test_rail() -> RailBinding {
        RailBinding {
            chain_id: TEST_CHAIN_ID,
            token_contract: TEST_TOKEN_CONTRACT.to_string(),
            payee_address: TEST_PAYEE.to_string(),
            token_decimals: 6,
            token_symbol: "USDC".to_string(),
        }
    }

    fn test_approval_token() -> GovernedApprovalToken {
        let kp = Keypair::generate();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "seller-rail-test-1".to_string(),
                approver: kp.public_key(),
                subject: kp.public_key(),
                governed_intent_hash: "test-intent-hash".to_string(),
                request_id: "req-seller-rail-1".to_string(),
                threshold_proposal_hash: None,
                issued_at: TEST_ISSUED_AT,
                expires_at: TEST_EXPIRES_AT,
                decision: GovernedApprovalDecision::Approved,
            },
            &kp,
        )
        .test_unwrap()
    }

    #[test]
    fn resolve_seller_rail_finds_matching_entry() {
        let config = SellerRailConfig {
            entries: vec![SellerRailEntry {
                seller: "seller-abc".to_string(),
                token_symbol: "USDC".to_string(),
                rail: test_rail(),
            }],
        };
        let rail = resolve_seller_rail(&config, "seller-abc", "USDC");
        assert!(rail.is_some(), "matching entry must be found");
        assert_eq!(rail.test_unwrap().chain_id, TEST_CHAIN_ID);
    }

    #[test]
    fn resolve_seller_rail_is_case_insensitive_for_token_symbol() {
        let config = SellerRailConfig {
            entries: vec![SellerRailEntry {
                seller: "seller-abc".to_string(),
                token_symbol: "USDC".to_string(),
                rail: test_rail(),
            }],
        };
        assert!(resolve_seller_rail(&config, "seller-abc", "usdc").is_some());
        assert!(resolve_seller_rail(&config, "seller-abc", "USDC").is_some());
        assert!(resolve_seller_rail(&config, "seller-abc", "EURC").is_none());
        assert!(resolve_seller_rail(&config, "unknown-seller", "USDC").is_none());
    }

    #[test]
    fn pseudo_ref_derives_from_authorization_digest() {
        let digest_a = "0xaabbccdd1122334455667788aabbccdd1122334455667788aabbccdd11223344";
        let digest_b = "0x9900112233445566778899001122334455667788990011223344556677889900";
        let ref_a = sim_pseudo_ref_from_digest(digest_a);
        let ref_b = sim_pseudo_ref_from_digest(digest_b);
        assert_eq!(ref_a, sim_pseudo_ref_from_digest(digest_a));
        assert_ne!(ref_a, ref_b);
        assert!(
            ref_a.contains("aabbccdd"),
            "pseudo ref must contain the authorization_digest content, got: {ref_a}"
        );
    }

    /// Verifies the complete end-to-end sim flow: resolve rail -> binding ->
    /// prepare EIP-712 digest -> derive pseudo ref from that actual digest.
    /// This ensures the sim ref is bound to the real authorization parameters
    /// (nonce, from, validity window, amount, payee) rather than a narrower
    /// subset.
    #[test]
    fn sim_ref_derives_from_actual_authorization_digest() {
        let token = test_approval_token();
        let rail = test_rail();
        let amount_minor_units: u128 = 1_000_000;

        let binding =
            approval_binding_from_governed(&token, &rail, amount_minor_units, token.expires_at)
                .test_unwrap();

        let domain = Eip3009Domain {
            name: "USD Coin".to_string(),
            version: "2".to_string(),
            chain_id: rail.chain_id,
            verifying_contract: rail.token_contract.clone(),
        };
        let authorization = TransferWithAuthorizationInput {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: rail.payee_address.clone(),
            value_minor_units: amount_minor_units,
            valid_after: TEST_ISSUED_AT,
            valid_before: TEST_EXPIRES_AT,
            nonce: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        };

        let prepared = prepare_transfer_with_authorization(
            domain,
            authorization,
            &binding,
            TEST_NOW,
            &InMemoryEip3009NonceStore::new(),
        )
        .test_unwrap();

        let sim_ref = sim_pseudo_ref_from_digest(&prepared.authorization_digest);
        assert!(
            sim_ref.starts_with("sim-eip3009-"),
            "sim pseudo ref must carry the sim-eip3009 prefix, got: {sim_ref}"
        );
        // The ref must be stable for the same inputs.
        assert_eq!(
            sim_ref,
            sim_pseudo_ref_from_digest(&prepared.authorization_digest),
            "sim pseudo ref must be deterministic"
        );
        // The EIP-712 digest must be present and non-empty.
        assert!(
            !prepared.authorization_digest.is_empty(),
            "authorization_digest must be non-empty"
        );
    }
}
