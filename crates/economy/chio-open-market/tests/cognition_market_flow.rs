//! Spec-shaped coverage for the proposed agent cognition market
//! (research spike, branch `research/cognition-market`).
//!
//! Companion documents:
//! - `docs/research/agent-cognition-market.md` (design memo)
//! - `docs/adr/ADR-0017-cognition-market-finding-artifacts.md`
//!
//! Two of these tests pass today and demonstrate that the buy leg and the
//! elicitation ceiling need no new marketplace machinery. The `#[ignore]`d
//! test specifies the desired end-to-end reveal flow and names the seams
//! that do not exist yet; run it with `cargo test -- --ignored` to see the
//! first missing seam. Nothing here is production wiring.

use chio_open_market::{
    bidding::{BidRequest, RequestedScope, BID_REQUEST_SCHEMA},
    capability::scope::MonetaryAmount,
};

/// Stub shapes mirroring the interface sketches in the memo (section 6.1).
/// They live in this test file on purpose: the production types do not
/// exist yet, and this spike must not add public API surface. Fields and
/// variants exist to specify the artifact shape, so dead-code analysis is
/// silenced for the module.
#[allow(dead_code)]
mod finding_stubs {
    pub const FINDING_SCHEMA_V1: &str = "chio.finding.v1";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FindingOutcomeClass {
        /// "Doing X fails / has no effect": the negative result.
        NullResult,
        /// "This change makes the committed check pass": the verified fix.
        VerifiedFix,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FindingGuaranteeClass {
        /// Claim re-checkable by deterministic re-execution of the
        /// committed descriptor (the coding-agent wedge).
        DeterministicReplay,
        /// Execution, cost, and output digest attested by mediated
        /// receipts; claim semantics not re-checkable.
        MeteredAttested,
    }

    #[derive(Debug, Clone)]
    pub struct FindingDescriptor {
        pub topic: String,
        pub context_sha256: String,
        pub outcome_class: FindingOutcomeClass,
    }

    #[derive(Debug, Clone)]
    pub struct Finding {
        pub schema: String,
        pub finding_id: String,
        pub descriptor: FindingDescriptor,
        pub guarantee_class: FindingGuaranteeClass,
        /// Commitment to the sealed payload; served bytes must hash to
        /// this or the delivery receipt must not exist.
        pub payload_sha256: String,
        pub evidence_receipt_ids: Vec<String>,
        pub evidence_cost_units: u64,
        pub bond_ref: String,
        pub status_feed_ref: String,
    }

    /// Delivery proof the reveal step must produce: a kernel receipt whose
    /// `content_hash` equals the finding's committed `payload_sha256`.
    /// Today no tool contract enforces that equality, so this stub can
    /// only report the seam as missing.
    pub fn mediated_reveal_delivery_receipt(_finding: &Finding) -> Option<String> {
        None
    }

    /// Elicitation ceiling from memo section 6.6: the counterfactual the
    /// platform can actually meter (re-derivation quote) discounted by the
    /// planner-owned priors, hard-capped by the purchasing allocation.
    /// Deterministic and implementable today; kept here as spec.
    pub struct FindingBidBasis {
        pub rederivation_quote_units: u64,
        pub would_have_run_bps: u16,
        pub sibling_redundancy_bps: u16,
        pub guarantee_class_bps: u16,
        pub budget_remaining_units: u64,
    }

    pub fn finding_bid_ceiling(basis: &FindingBidBasis) -> u64 {
        const BPS: u128 = 10_000;
        let would = u128::from(basis.would_have_run_bps.min(10_000));
        let keep = BPS - u128::from(basis.sibling_redundancy_bps.min(10_000));
        let class = u128::from(basis.guarantee_class_bps.min(10_000));
        let discounted =
            u128::from(basis.rederivation_quote_units) * would / BPS * keep / BPS * class / BPS;
        u64::try_from(discounted)
            .unwrap_or(u64::MAX)
            .min(basis.budget_remaining_units)
    }
}

use finding_stubs::{
    finding_bid_ceiling, mediated_reveal_delivery_receipt, Finding, FindingBidBasis,
    FindingDescriptor, FindingGuaranteeClass, FindingOutcomeClass, FINDING_SCHEMA_V1,
};

fn sealed_negative_result() -> Finding {
    Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: "finding-dead-end-0001".to_string(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#flaky-suite-investigation".to_string(),
            context_sha256: "a".repeat(64),
            outcome_class: FindingOutcomeClass::NullResult,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: "b".repeat(64),
        evidence_receipt_ids: vec!["receipt-0001".to_string(), "receipt-0002".to_string()],
        evidence_cost_units: 4_200,
        bond_ref: "bond-req-listing-slashable-01".to_string(),
        status_feed_ref: "finding-status-feed-01".to_string(),
    }
}

/// Passes today: buying a finding reuses the existing marketplace bid
/// shape unchanged. The listing id points at a finding listing instead of
/// a tool listing; the bid itself needs zero new fields.
#[test]
fn finding_purchase_reuses_marketplace_bid_shape() {
    let bid = BidRequest {
        schema: BID_REQUEST_SCHEMA.to_string(),
        agent_id: "buyer-agent-7".to_string(),
        listing_id: "listing-finding-dead-end-0001".to_string(),
        max_price_per_call: MonetaryAmount {
            units: 900,
            currency: "USD".to_string(),
        },
        window_seconds: 3_600,
        requested_scope: RequestedScope {
            server_id: "finding-server.seller.example".to_string(),
            tool_name: "read_finding".to_string(),
            max_invocations: Some(1),
            capability_scope_prefix: "finding/".to_string(),
        },
        issued_at: 1_760_000_000,
    };
    assert!(bid.validate().is_ok());
}

/// Passes today: the elicitation ceiling is deterministic, monotone in the
/// re-derivation quote, and hard-capped by the purchasing allocation. It
/// makes no claim about the finding's true value.
#[test]
fn finding_bid_ceiling_is_bounded_and_budget_capped() {
    let mut basis = FindingBidBasis {
        rederivation_quote_units: 4_200,
        would_have_run_bps: 6_000,
        sibling_redundancy_bps: 2_500,
        guarantee_class_bps: 10_000,
        budget_remaining_units: 10_000,
    };
    let ceiling = finding_bid_ceiling(&basis);
    // 4200 x 0.60 x 0.75 x 1.00 = 1890.
    assert_eq!(ceiling, 1_890);
    assert!(ceiling <= basis.rederivation_quote_units);

    basis.budget_remaining_units = 500;
    assert_eq!(finding_bid_ceiling(&basis), 500);

    basis.would_have_run_bps = 0;
    assert_eq!(finding_bid_ceiling(&basis), 0);
}

/// Specifies the desired end-to-end flow (memo section 6.2). Ignored
/// because the reveal seam does not exist yet; the panic below names the
/// first missing piece in dependency order.
#[test]
#[ignore = "specifies the unimplemented cognition-market reveal flow; see docs/research/agent-cognition-market.md section 6.2"]
fn cognition_market_reveal_flow_spec() {
    let finding = sealed_negative_result();

    // 1. Commit: the finding artifact carries the payload commitment and
    //    the metered evidence refs a buyer verifies before bidding.
    assert_eq!(finding.schema, FINDING_SCHEMA_V1);
    assert!(!finding.evidence_receipt_ids.is_empty());

    // 2. Bid/accept: covered by `finding_purchase_reuses_marketplace_bid_shape`.

    // 3. Escrow: MustPrepay hold (small amounts) or ChioEscrow terms
    //    (large amounts) with release/refund as the only terminal states.

    // 4. Reveal = delivery proof. MISSING SEAMS, in dependency order:
    //    a. a `read_finding` tool contract that refuses to sign a delivery
    //       receipt unless receipt.content_hash == finding.payload_sha256;
    //    b. escrow release wired from that receipt's Merkle inclusion;
    //    c. a `FabricatedFindingEvidence` abuse class + replay challenge
    //       decision rule feeding the existing sanction/slash gate;
    //    d. a finding-status feed (revocation-oracle pattern) checked for
    //       non-inclusion at purchase time.
    let delivery = mediated_reveal_delivery_receipt(&finding);
    let receipt_id = match delivery {
        Some(receipt_id) => receipt_id,
        None => panic!(
            "missing seam (a): no governed read_finding tool contract binds \
             receipt content_hash to the committed payload_sha256"
        ),
    };

    // 5. Post-reveal: the delivery receipt anchors the dispute window and
    //    the challenge evidence chain.
    assert!(!receipt_id.is_empty());
}
