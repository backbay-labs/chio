use chio_runtime::{
    ChioRuntimeAdmissionHook, ChioRuntimeError, InMemoryRuntimeAdmissionStore,
    RuntimeAdmissionProfile, CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA,
};

#[test]
fn runtime_facade_exposes_chio_trust_floor_schema_and_runtime_types() {
    assert_eq!(
        CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA,
        "chio.runtime.trust-floor-state.v1"
    );

    fn accepts_profile(_profile: Option<RuntimeAdmissionProfile>) {}
    fn accepts_error(_error: Option<ChioRuntimeError>) {}

    accepts_profile(None);
    accepts_error(None);
}

#[test]
fn runtime_error_boundary_is_chio_owned() {
    let error_type = std::any::type_name::<ChioRuntimeError>();
    assert_eq!(error_type, "chio_runtime::ChioRuntimeError");
}

#[test]
fn runtime_admission_hook_boundary_is_chio_owned() {
    fn accepts_hook(_hook: Option<ChioRuntimeAdmissionHook<InMemoryRuntimeAdmissionStore>>) {}

    accepts_hook(None);

    let hook_type =
        std::any::type_name::<ChioRuntimeAdmissionHook<InMemoryRuntimeAdmissionStore>>();
    assert!(hook_type.starts_with("chio_runtime::ChioRuntimeAdmissionHook<"));
    assert_eq!(
        std::any::type_name::<InMemoryRuntimeAdmissionStore>(),
        "chio_runtime::InMemoryRuntimeAdmissionStore"
    );
}

#[test]
fn runtime_boundary_does_not_wildcard_reexport_historical_core() {
    let lib = include_str!("../src/lib.rs");

    assert!(!lib.contains("pub use chio_runtime_core::*"));
}

#[test]
fn runtime_cli_helper_parsers_return_chio_errors() {
    let admission_error = match chio_runtime::runtime_admission_profile_from_json("{") {
        Ok(_) => panic!("invalid runtime admission profile JSON should fail"),
        Err(error) => error,
    };
    assert_eq!(
        std::any::type_name_of_val(&admission_error),
        "chio_runtime::ChioRuntimeError"
    );
    assert_eq!(admission_error.code(), "runtime_admission_json");

    let orchestration_error = match chio_runtime::runtime_orchestration_profile_from_json("{") {
        Ok(_) => panic!("invalid runtime orchestration profile JSON should fail"),
        Err(error) => error,
    };
    assert_eq!(
        std::any::type_name_of_val(&orchestration_error),
        "chio_runtime::ChioRuntimeError"
    );
    assert_eq!(orchestration_error.code(), "runtime_admission_json");
}

#[test]
fn runtime_cli_hash_helpers_return_chio_error_results() {
    fn accepts_peer_weights_hash_helper(
        _helper: fn(
            &chio_runtime::RuntimePeerWeights,
        ) -> Result<String, chio_runtime::ChioRuntimeError>,
    ) {
    }

    fn accepts_orchestration_profile_hash_helper(
        _helper: fn(
            &chio_runtime::RuntimeOrchestrationProfile,
        ) -> Result<String, chio_runtime::ChioRuntimeError>,
    ) {
    }

    accepts_peer_weights_hash_helper(chio_runtime::runtime_peer_weights_sha256);
    accepts_orchestration_profile_hash_helper(chio_runtime::runtime_orchestration_profile_sha256);
}

#[test]
fn runtime_provider_bindings_from_json_revalidates_public_payloads(
) -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{
        "schema": "chio.runtime.provider-bindings.v1",
        "bindings": [
            {
                "providerId": "provider-vendor-b",
                "localKernelId": "kernel.vendor-b",
                "serverId": "vendor-ledger",
                "toolName": "close_account",
                "discoveryAllowed": false
            },
            {
                "providerId": "provider-vendor-b",
                "localKernelId": "kernel.vendor-b",
                "serverId": "vendor-ledger-backup",
                "toolName": "close_account",
                "discoveryAllowed": false
            }
        ]
    }"#;

    let error = match chio_runtime::runtime_provider_bindings_from_json(json) {
        Ok(_) => {
            return Err(std::io::Error::other("duplicate provider binding accepted").into());
        }
        Err(error) => error,
    };
    assert_eq!(error.code(), "runtime_provider_duplicate_id");
    assert_eq!(
        std::any::type_name_of_val(&error),
        "chio_runtime::ChioRuntimeError"
    );
    Ok(())
}

#[test]
fn runtime_cli_helper_reexports_are_not_historical_error_reexports() {
    let lib = include_str!("../src/lib.rs");
    for helper in [
        "runtime_admission_profile_from_json",
        "runtime_admission_bundle_from_json",
        "runtime_request_binding_from_json",
        "runtime_orchestration_profile_from_json",
        "runtime_run_contract_from_json",
        "runtime_supervisor_profile_from_json",
        "runtime_artifact_retention_profile_from_json",
        "runtime_provider_bindings_from_json",
        "runtime_peer_weights_sha256",
        "runtime_orchestration_profile_sha256",
        "runtime_run_contract_sha256",
        "evaluate_runtime_admission",
        "build_runtime_orchestration_plan",
    ] {
        assert!(
            !lib.contains(&format!("    {helper},")),
            "{helper} must be wrapped by chio-runtime instead of direct-reexported"
        );
    }
}

#[test]
fn runtime_admission_store_boundary_is_chio_owned() {
    let lib = include_str!("../src/lib.rs");
    for symbol in [
        "pub use chio_runtime_core::{",
        "T: chio_runtime_core::RuntimeAdmissionStore",
        "T: chio_runtime_core::RuntimeTrustFloorStore",
    ] {
        assert!(
            !lib.contains(symbol),
            "{symbol} must not appear in the Chio runtime public boundary"
        );
    }

    for symbol in [
        "pub struct ChioRuntimeAdmissionInput",
        "pub trait ChioRuntimeAdmissionStore",
        "pub trait ChioRuntimeTrustFloorStore",
        "pub struct InMemoryRuntimeAdmissionStore",
        "pub struct JsonRuntimeAdmissionStore",
        "pub struct JsonRuntimeTrustFloorStateStore",
        "pub struct LayeredRuntimeAdmissionStore",
        "pub struct SqliteRuntimeOrchestrationStore",
    ] {
        assert!(
            lib.contains(symbol),
            "chio-runtime facade must expose {symbol}"
        );
    }

    assert!(
        !lib.contains("S: chio_runtime_core::RuntimeAdmissionStore"),
        "ChioRuntimeAdmissionHook must be bounded by the Chio-owned store trait"
    );
}

#[test]
fn runtime_public_store_wrappers_are_debuggable() {
    fn assert_debug<T: std::fmt::Debug>() {}

    assert_debug::<chio_runtime::InMemoryRuntimeAdmissionStore>();
    assert_debug::<chio_runtime::JsonRuntimeAdmissionStore>();
    assert_debug::<chio_runtime::JsonRuntimeTrustFloorStateStore>();
    assert_debug::<chio_runtime::LayeredRuntimeAdmissionStore<'static>>();
    assert_debug::<chio_runtime::SqliteRuntimeOrchestrationStore>();
}
