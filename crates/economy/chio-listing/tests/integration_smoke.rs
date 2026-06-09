use chio_listing::{GenericListingBoundary, GenericListingSearchPolicy};

#[test]
fn listing_defaults_validate() {
    assert!(GenericListingBoundary::default().validate().is_ok());
    assert!(GenericListingSearchPolicy::default().validate().is_ok());
}
