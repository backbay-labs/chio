use chio_bedrock_control_plane::{
    meter_usage, EntitlementError, EntitlementRecord, EntitlementStore, MeteringApi, MeteringError,
    MeteringUsage,
};

const QUICK_LAUNCH_TEMPLATE: &str = include_str!("../cloudformation/quick-launch.yaml");
const CUSTOMER_ID: &str = "customer-post-listing";
const PRODUCT_CODE: &str = "prod-chio-bedrock";
const DIMENSION: &str = "bedrock_receipt_overage";
const NOW_EPOCH_SECS: u64 = 1_777_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReceiptBillingAction {
    BaseQuotaOnly { receipt_id: String },
    MeterOverage(MeteringUsage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptQuotaTracker {
    base_quota: u32,
    issued: u32,
}

impl ReceiptQuotaTracker {
    fn new(base_quota: u32) -> Self {
        Self {
            base_quota,
            issued: 0,
        }
    }

    fn issue_receipt(
        &mut self,
        entitlements: &EntitlementStore,
        receipt_id: &str,
    ) -> Result<ReceiptBillingAction, EntitlementError> {
        entitlements.check(CUSTOMER_ID, PRODUCT_CODE, DIMENSION, NOW_EPOCH_SECS)?;
        self.issued += 1;

        if self.issued <= self.base_quota {
            return Ok(ReceiptBillingAction::BaseQuotaOnly {
                receipt_id: receipt_id.to_string(),
            });
        }

        Ok(ReceiptBillingAction::MeterOverage(MeteringUsage {
            customer_identifier: CUSTOMER_ID.to_string(),
            product_code: PRODUCT_CODE.to_string(),
            dimension: DIMENSION.to_string(),
            quantity: 1,
            timestamp_epoch_secs: NOW_EPOCH_SECS,
            receipt_id: receipt_id.to_string(),
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CustomerErrorEnvelope {
    urn: &'static str,
    status: &'static str,
    message: String,
}

fn customer_error_envelope(error: MeteringError) -> CustomerErrorEnvelope {
    CustomerErrorEnvelope {
        urn: "urn:chio:error:aws-bedrock:marketplace-entitlement-denied",
        status: "denied",
        message: error.to_string(),
    }
}

fn active_entitlements() -> Result<EntitlementStore, EntitlementError> {
    let mut store = EntitlementStore::default();
    store.insert(EntitlementRecord {
        customer_identifier: CUSTOMER_ID.to_string(),
        product_code: PRODUCT_CODE.to_string(),
        dimension: DIMENSION.to_string(),
        expires_at_epoch_secs: NOW_EPOCH_SECS + 86_400,
        active: true,
    })?;
    Ok(store)
}

fn smoke_error(message: &'static str) -> Box<dyn std::error::Error> {
    std::io::Error::other(message).into()
}

#[test]
fn post_listing_customer_shape_onboarding_smoke() -> Result<(), Box<dyn std::error::Error>> {
    assert!(QUICK_LAUNCH_TEMPLATE.contains("ChioBedrockIntegrationRole"));
    assert!(QUICK_LAUNCH_TEMPLATE.contains("ChioControlPlaneEndpoint"));
    assert!(QUICK_LAUNCH_TEMPLATE.contains("ChioTenantId"));
    assert!(QUICK_LAUNCH_TEMPLATE.contains("ChioSellerAccountPrincipalArn"));
    assert!(QUICK_LAUNCH_TEMPLATE.contains("bedrock:InvokeModel"));

    let entitlements = active_entitlements()?;
    let decision = entitlements.check(CUSTOMER_ID, PRODUCT_CODE, DIMENSION, NOW_EPOCH_SECS)?;
    assert_eq!(decision.customer_identifier, CUSTOMER_ID);
    assert_eq!(decision.product_code, PRODUCT_CODE);

    let mut quota = ReceiptQuotaTracker::new(1);
    let first_receipt = quota.issue_receipt(&entitlements, "rcpt-base-0001")?;
    assert_eq!(
        first_receipt,
        ReceiptBillingAction::BaseQuotaOnly {
            receipt_id: "rcpt-base-0001".to_string()
        }
    );

    let second_receipt = quota.issue_receipt(&entitlements, "rcpt-overage-0002")?;
    let metering_event = if let ReceiptBillingAction::MeterOverage(usage) = second_receipt {
        meter_usage(&entitlements, usage, NOW_EPOCH_SECS)?
    } else {
        return Err(smoke_error(
            "second receipt did not produce metered overage",
        ));
    };
    assert_eq!(metering_event.api, MeteringApi::MeterUsage);
    assert_eq!(metering_event.receipt_id, "rcpt-overage-0002");
    assert_eq!(metering_event.quantity, 1);

    let denied = meter_usage(
        &EntitlementStore::default(),
        MeteringUsage {
            customer_identifier: CUSTOMER_ID.to_string(),
            product_code: PRODUCT_CODE.to_string(),
            dimension: DIMENSION.to_string(),
            quantity: 1,
            timestamp_epoch_secs: NOW_EPOCH_SECS,
            receipt_id: "rcpt-denied-0003".to_string(),
        },
        NOW_EPOCH_SECS,
    )
    .err();
    let envelope = if let Some(error) = denied {
        customer_error_envelope(error)
    } else {
        return Err(smoke_error(
            "forced failure path unexpectedly allowed metering",
        ));
    };
    assert!(envelope.urn.starts_with("urn:chio:error:"));
    assert_eq!(envelope.status, "denied");
    assert!(envelope.message.contains("entitlement"));

    Ok(())
}
