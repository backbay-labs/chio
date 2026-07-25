#![allow(
    clippy::clone_on_copy,
    clippy::derivable_impls,
    clippy::enum_variant_names,
    clippy::expect_used,
    clippy::large_enum_variant,
    clippy::unwrap_used
)]

use std::{fs, path::PathBuf};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

#[allow(dead_code)]
#[path = "../src/_generated/chio_wire_v1.rs"]
mod generated;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn round_trip<T>(instance: Value) -> Result<Value, serde_json::Error>
where
    T: DeserializeOwned + Serialize,
{
    serde_json::from_value::<T>(instance).and_then(serde_json::to_value)
}

fn generated_instance(schema_file: &str, instance: Value) -> Value {
    if schema_file == "agent/active-response-governed-intent.schema.json" {
        json!({
            "id": "intent-1",
            "server_id": "chio.control-plane.active-response",
            "tool_name": "execute_response_plan",
            "purpose": "containment",
            "body": { "kind": "active_response_plan", "value": instance }
        })
    } else {
        instance
    }
}

fn parse_generated(schema_file: &str, instance: Value) -> Result<Value, serde_json::Error> {
    match schema_file {
        "capability/token.schema.json" => {
            round_trip::<generated::agent_tool_call_request::ChioCapabilityToken>(instance)
        }
        "capability/aggregate-invocation-budget.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioAggregateInvocationBudget,
        >(instance),
        "capability/threshold-approval-proposal.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioThresholdApprovalProposal,
        >(instance),
        "capability/governed-approval-token.schema.json" => {
            round_trip::<generated::agent_tool_call_request::ChioGovernedApprovalToken>(instance)
        }
        "agent/active-response-governed-intent.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioGovernedTransactionIntent,
        >(instance),
        "kernel/combined-capture-metadata.schema.json" => round_trip::<
            generated::kernel_combined_capture_metadata::ChioCombinedAdmissionCaptureMetadata,
        >(instance),
        "capability/supplemental-authorization.schema.json" => round_trip::<
            generated::agent_tool_call_request::ChioOpaqueSupplementalAuthorization,
        >(instance),
        other => panic!("unmapped protocol-primitives fixture schema: {other}"),
    }
}

#[test]
fn generated_rust_shapes_parse_reject_and_round_trip_shared_fixtures() {
    let corpus: Value = serde_json::from_str(
        &fs::read_to_string(
            repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json"),
        )
        .expect("protocol-primitives fixture corpus exists"),
    )
    .expect("protocol-primitives fixture corpus parses");

    for case in corpus["cases"]
        .as_array()
        .expect("fixture cases are an array")
    {
        let schema_file = case["schema_file"]
            .as_str()
            .expect("fixture schema_file is a string");
        let instance = generated_instance(schema_file, case["instance"].clone());
        let result = parse_generated(schema_file, instance.clone());
        let valid = case["valid"].as_bool().expect("fixture valid is a boolean");
        assert_eq!(
            result.is_ok(),
            valid,
            "generated Rust fixture result mismatch for {}",
            case["name"].as_str().expect("fixture name is a string")
        );
        if valid {
            assert_eq!(
                chio_core_types::canonical_json_bytes(&result.expect("valid fixture parsed"))
                    .expect("round trip canonicalizes"),
                chio_core_types::canonical_json_bytes(&instance).expect("fixture canonicalizes"),
                "generated Rust round trip changed canonical bytes for {}",
                case["name"].as_str().expect("fixture name is a string")
            );
        }
    }
}
