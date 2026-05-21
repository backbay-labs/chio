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
}

#[test]
fn runtime_boundary_does_not_wildcard_reexport_historical_core() {
    let lib = include_str!("../src/lib.rs");

    assert!(!lib.contains("pub use chio_chiodos_runtime::*"));
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
    let Some(reexport_start) = lib.find("pub use chio_chiodos_runtime::{") else {
        panic!("runtime facade must keep an explicit historical reexport block");
    };
    let reexport_tail = &lib[reexport_start..];
    let Some(reexport_end) = reexport_tail.find("};") else {
        panic!("runtime facade historical reexport block must terminate");
    };
    let reexport_block = &reexport_tail[..reexport_end];
    let exported_symbols = reexport_block
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|symbol| !symbol.is_empty())
        .collect::<Vec<_>>();

    for symbol in [
        "RuntimeAdmissionInput",
        "RuntimeAdmissionStore",
        "RuntimeTrustFloorStore",
    ] {
        assert!(
            !exported_symbols.contains(&symbol),
            "{symbol} must be Chio-owned in chio-runtime, not reexported from the historical runtime crate"
        );
    }

    for symbol in [
        "pub struct ChioRuntimeAdmissionInput",
        "pub trait ChioRuntimeAdmissionStore",
        "pub trait ChioRuntimeTrustFloorStore",
    ] {
        assert!(
            lib.contains(symbol),
            "chio-runtime facade must expose {symbol}"
        );
    }

    assert!(
        !lib.contains("S: chio_chiodos_runtime::RuntimeAdmissionStore"),
        "ChioRuntimeAdmissionHook must be bounded by the Chio-owned store trait"
    );
}
