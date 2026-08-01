use chio_open_market::finding_bid_policy::{
    finding_bid_ceiling, FindingBidCeilingError, FindingBidCeilingInput,
};
use chio_test_support::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    valid_cases: Vec<ValidCase>,
}

#[derive(Deserialize)]
struct ValidCase {
    id: String,
    input: FindingBidCeilingInput,
    #[serde(rename = "expectedCeiling")]
    expected_ceiling: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../../tests/bindings/fixtures/cognition-market-finding-bid-ceiling-v1.json"
    ))
    .test_expect("parse finding bid ceiling vectors")
}

fn basic() -> FindingBidCeilingInput {
    fixture()
        .valid_cases
        .into_iter()
        .next()
        .test_expect("basic vector")
        .input
}

#[test]
fn finding_bid_ceiling_rust_matches_shared_sdk_goldens() {
    for case in fixture().valid_cases {
        assert_eq!(
            finding_bid_ceiling(&case.input).test_expect(&case.id),
            case.expected_ceiling,
            "{}",
            case.id
        );
    }
}

#[test]
fn finding_bid_ceiling_rejects_noncanonical_bounds_and_overflow() {
    for value in ["", "01", "+1", "-1", "1.0", "NaN"] {
        let mut input = basic();
        input.estimate.units = value.to_string();
        assert!(matches!(
            finding_bid_ceiling(&input),
            Err(FindingBidCeilingError::InvalidDecimal { .. })
        ));
    }

    let mut input = basic();
    input.estimate.units = "18446744073709551616".to_string();
    assert!(matches!(
        finding_bid_ceiling(&input),
        Err(FindingBidCeilingError::U64Overflow { .. })
    ));

    let mut input = basic();
    input.policy.would_have_run_bps = "10001".to_string();
    assert!(matches!(
        finding_bid_ceiling(&input),
        Err(FindingBidCeilingError::BasisPointsOutOfRange { .. })
    ));
}

#[test]
fn finding_bid_ceiling_rejects_currency_provenance_staleness_and_substitution() {
    let mut currency = basic();
    currency.policy.currency = "EUR".to_string();
    assert_eq!(
        finding_bid_ceiling(&currency),
        Err(FindingBidCeilingError::CurrencyMismatch)
    );

    let mut provenance = basic();
    provenance.estimate.provenance = "operator_assertion_v1".to_string();
    assert_eq!(
        finding_bid_ceiling(&provenance),
        Err(FindingBidCeilingError::ProvenanceUnsupported)
    );

    let mut stale = basic();
    stale.now_unix_ms = stale.estimate.valid_until_unix_ms.clone();
    assert_eq!(
        finding_bid_ceiling(&stale),
        Err(FindingBidCeilingError::StaleEstimate)
    );

    let mut source = basic();
    source.expected_source_sha256 = "0".repeat(64);
    assert_eq!(
        finding_bid_ceiling(&source),
        Err(FindingBidCeilingError::SourceSubstituted)
    );

    let mut context = basic();
    context.expected_context_sha256 = "0".repeat(64);
    assert_eq!(
        finding_bid_ceiling(&context),
        Err(FindingBidCeilingError::ContextSubstituted)
    );

    let mut replay = basic();
    replay.expected_replay_recipe_sha256 = "0".repeat(64);
    assert_eq!(
        finding_bid_ceiling(&replay),
        Err(FindingBidCeilingError::ReplayRecipeSubstituted)
    );
}
