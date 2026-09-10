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
    malformed["function"]["parameters"] = json!(42);
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
fn optional_fields_accept_omitted_null_empty_and_populated_forms() {
    for nested in [false, true] {
        for value in [
            None,
            Some(Value::Null),
            Some(json!({})),
            Some(json!({"type":"object","properties":{"id":{"type":"string"}}})),
        ] {
            let mut function = json!({"name":"get_customer_orders"});
            if let Some(value) = &value {
                function["parameters"] = value.clone();
            }
            let expected = value
                .filter(|v| !v.is_null())
                .unwrap_or_else(|| json!({"type":"object","properties":{}}));
            let definition = if nested {
                json!({"type":"function","function":function})
            } else {
                function["type"] = json!("function");
                function
            };
            assert_eq!(
                import(&[definition], &declarations()).unwrap().tools[0].input_schema,
                expected
            );
        }
        for value in [
            None,
            Some(Value::Null),
            Some(json!("")),
            Some(json!("Read orders")),
        ] {
            let mut function = json!({"name":"get_customer_orders"});
            if let Some(value) = &value {
                function["description"] = value.clone();
            }
            let expected = value
                .as_ref()
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let definition = if nested {
                json!({"type":"function","function":function})
            } else {
                function["type"] = json!("function");
                function
            };
            assert_eq!(
                import(&[definition], &declarations()).unwrap().tools[0].description,
                expected
            );
        }
    }
}

#[test]
fn rejects_malformed_schemas_at_the_root_and_in_nested_keywords() {
    for schema in [
        json!({"type":"not-a-json-schema-type"}),
        json!({"type":"object","properties":42}),
        json!({"type":"object","required":"city"}),
        json!({"type":"object","properties":{"city":{"type":"not-a-json-schema-type"}}}),
        json!({"allOf":[{"required":[42]}]}),
        json!({"$schema":"https://example.invalid/custom-meta"}),
    ] {
        for field in ["parameters", "output_schema"] {
            let mut definition = json!({"type":"function","name":"get_customer_orders"});
            definition[field] = schema.clone();
            assert!(
                matches!(import(&[definition], &declarations()), Err(OpenAiManifestError::InvalidSchema { field: actual, .. }) if actual == field)
            );
        }
    }
}

#[test]
fn preserves_optional_responses_output_schemas_without_rewriting_references() {
    for value in [
        None,
        Some(Value::Null),
        Some(json!({})),
        Some(
            json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"orders":{"type":"array","items":{"$ref":"https://example.invalid/order.json"}}}}),
        ),
    ] {
        let mut definition = json!({"type":"function","name":"get_customer_orders"});
        if let Some(value) = &value {
            definition["output_schema"] = value.clone();
        }
        let expected = value.filter(|v| !v.is_null());
        assert_eq!(
            import(&[definition], &declarations()).unwrap().tools[0].output_schema,
            expected
        );
    }
}

#[test]
fn malformed_optional_fields_are_not_treated_as_absent() {
    for (field, value) in [
        ("description", json!(42)),
        ("parameters", json!([])),
        ("output_schema", json!("object")),
    ] {
        let mut definition = json!({"type":"function","name":"get_customer_orders"});
        definition[field] = value;
        assert!(import(&[definition], &declarations()).is_err());
    }
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
