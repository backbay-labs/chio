use chio_bedrock_control_plane::{
    batch_meter_usage, marketplace_sdk_client_type_names, meter_usage, EntitlementError,
    EntitlementRecord, EntitlementStore, MeteringApi, MeteringBatch, MeteringError, MeteringUsage,
};

fn record() -> EntitlementRecord {
    EntitlementRecord {
        customer_identifier: "customer-123".to_string(),
        product_code: "prod-abc".to_string(),
        dimension: "bedrock_receipt_overage".to_string(),
        expires_at_epoch_secs: 1_900_000_000,
        active: true,
    }
}

fn usage(receipt_id: &str) -> MeteringUsage {
    MeteringUsage {
        customer_identifier: "customer-123".to_string(),
        product_code: "prod-abc".to_string(),
        dimension: "bedrock_receipt_overage".to_string(),
        quantity: 1,
        timestamp_epoch_secs: 1_710_000_200,
        receipt_id: receipt_id.to_string(),
    }
}

#[test]
fn entitlement_and_metering_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = EntitlementStore::default();
    store.insert(record())?;

    let decision = store.check(
        "customer-123",
        "prod-abc",
        "bedrock_receipt_overage",
        1_710_000_000,
    )?;
    assert_eq!(decision.product_code, "prod-abc");

    let event = meter_usage(&store, usage("rcpt-a"), 1_710_000_000)?;
    assert_eq!(event.api, MeteringApi::MeterUsage);
    assert_eq!(event.receipt_id, "rcpt-a");

    let batch = batch_meter_usage(
        &store,
        MeteringBatch {
            records: vec![usage("rcpt-b"), usage("rcpt-c")],
        },
        1_710_000_000,
    )?;
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].api, MeteringApi::BatchMeterUsage);

    let sdk_types = marketplace_sdk_client_type_names();
    assert!(sdk_types
        .entitlement_client
        .contains("aws_sdk_marketplaceentitlement"));
    assert!(sdk_types
        .metering_client
        .contains("aws_sdk_marketplacemetering"));

    Ok(())
}

#[test]
fn entitlement_and_metering_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = EntitlementStore::default();
    store.insert(EntitlementRecord {
        active: false,
        ..record()
    })?;

    let entitlement_error = store
        .check(
            "customer-123",
            "prod-abc",
            "bedrock_receipt_overage",
            1_710_000_000,
        )
        .err();
    assert_eq!(
        entitlement_error,
        Some(EntitlementError::InactiveEntitlement)
    );

    let metering_error = meter_usage(&store, usage("rcpt-denied"), 1_710_000_000).err();
    assert_eq!(
        metering_error,
        Some(MeteringError::Entitlement(
            EntitlementError::InactiveEntitlement
        ))
    );

    let mut active_store = EntitlementStore::default();
    active_store.insert(record())?;
    let zero_quantity = MeteringUsage {
        quantity: 0,
        ..usage("rcpt-zero")
    };
    assert_eq!(
        meter_usage(&active_store, zero_quantity, 1_710_000_000).err(),
        Some(MeteringError::QuantityMustBePositive)
    );

    let mut padded_store = EntitlementStore::default();
    let padded_error = padded_store
        .insert(EntitlementRecord {
            customer_identifier: " customer-123".to_string(),
            ..record()
        })
        .err();
    assert_eq!(
        padded_error,
        Some(EntitlementError::MissingCustomerIdentifier)
    );

    Ok(())
}
