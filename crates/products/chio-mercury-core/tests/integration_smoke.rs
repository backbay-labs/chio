use chio_mercury_core::{
    sample_mercury_bundle_manifest, sample_mercury_receipt_metadata,
    MERCURY_BUNDLE_MANIFEST_SCHEMA, MERCURY_RECEIPT_METADATA_SCHEMA,
};

#[test]
fn mercury_public_fixtures_produce_schema_shaped_artifacts() {
    let metadata = sample_mercury_receipt_metadata();
    let bundle = sample_mercury_bundle_manifest();

    assert_eq!(metadata.schema, MERCURY_RECEIPT_METADATA_SCHEMA);
    assert_eq!(bundle.schema, MERCURY_BUNDLE_MANIFEST_SCHEMA);
    assert!(!bundle.artifacts.is_empty());
}
