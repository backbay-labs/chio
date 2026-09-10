#![allow(clippy::unwrap_used)]
use chio_manifest::{OpenAiManifestError, PricingModel, ToolGovernance, ToolManifest, ToolPricing};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn declarations() -> BTreeMap<String, ToolGovernance> {
    BTreeMap::from([(
        "get_customer_orders".into(),
        ToolGovernance {
            has_side_effects: false,
            pricing: None,
        },
    )])
}
fn tool() -> Value {
    json!({"type":"function", "function":{"name":"get_customer_orders", "description":"Read one customer's orders", "parameters":{"type":"object","properties":{"customer_id":{"type":"string"}},"required":["customer_id"],"additionalProperties":false},"strict":true}})
}
fn import(
    tools: &[Value],
    governance: &BTreeMap<String, ToolGovernance>,
) -> Result<ToolManifest, OpenAiManifestError> {
    ToolManifest::from_openai_tools("orders", "test-public-key", "1.0.0", tools, governance)
}

#[test]
fn preserves_provider_schema_and_explicit_governance_for_both_dialects() {
    let nested = tool();
    let mut flat = nested["function"].clone();
    flat["type"] = json!("function");
    for definition in [nested, flat] {
        let function = definition.get("function").unwrap_or(&definition);
        let mut governance = declarations();
        governance
            .get_mut("get_customer_orders")
            .unwrap()
            .has_side_effects = true;
        let manifest = import(std::slice::from_ref(&definition), &governance).unwrap();
        assert_eq!(manifest.tools[0].input_schema, function["parameters"]);
        assert!(manifest.tools[0].has_side_effects);
        assert!(manifest.tools[0].pricing.is_none());
        assert_eq!(manifest.server_id.as_str(), "orders");
    }
}

#[test]
fn refuses_missing_or_misspelled_declarations_and_duplicate_tools() {
    assert!(matches!(
        import(&[tool()], &BTreeMap::new()),
        Err(OpenAiManifestError::MissingGovernance(_))
    ));
    let mut governance = declarations();
    governance.insert(
        "typo".into(),
        ToolGovernance {
            has_side_effects: false,
            pricing: None,
        },
    );
    assert!(matches!(
        import(&[tool()], &governance),
        Err(OpenAiManifestError::UnknownGovernance(_))
    ));
    assert!(import(&[tool(), tool()], &declarations()).is_err());
}

#[test]
fn refuses_native_tools_malformed_schema_and_invalid_pricing() {
    assert!(import(&[json!({"type":"web_search"})], &declarations()).is_err());
    let mut malformed = tool();
    malformed["function"]["parameters"] = json!(null);
    assert!(import(&[malformed], &declarations()).is_err());
    let mut governance = declarations();
    governance.get_mut("get_customer_orders").unwrap().pricing = Some(ToolPricing {
        pricing_model: PricingModel::PerInvocation,
        base_price: None,
        unit_price: None,
        billing_unit: None,
    });
    assert!(import(&[tool()], &governance).is_err());
    assert!(import(&[], &BTreeMap::new()).is_err());
}

#[test]
fn preserves_explicit_metering_declaration() {
    let pricing: ToolPricing = serde_json::from_value(
        json!({"pricing_model":"flat","base_price":{"units":25,"currency":"USD"}}),
    )
    .unwrap();
    let expected = serde_json::to_value(&pricing).unwrap();
    let governance = BTreeMap::from([(
        "get_customer_orders".into(),
        ToolGovernance {
            has_side_effects: false,
            pricing: Some(pricing),
        },
    )]);
    let manifest = import(&[tool()], &governance).unwrap();
    assert_eq!(
        serde_json::to_value(&manifest.tools[0].pricing).unwrap(),
        expected
    );
}
