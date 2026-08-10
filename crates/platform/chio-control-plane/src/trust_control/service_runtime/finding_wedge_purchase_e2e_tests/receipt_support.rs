fn matched_delivery_metadata(content_hash: &str) -> Result<serde_json::Value, AnyError> {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        DELIVERY_CONTRACT_METADATA_KEY.to_string(),
        serde_json::to_value(DeliveryContract {
            schema: DELIVERY_CONTRACT_SCHEMA.to_string(),
            expected_digest: content_hash.to_string(),
            observed_digest: content_hash.to_string(),
            result: DeliveryResult::Matched,
        })?,
    );
    Ok(serde_json::Value::Object(metadata))
}
