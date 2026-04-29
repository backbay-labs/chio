// C++ peer P0 conformance gate.
//
// Wave 1 decision 5 locks the C++ peer P0 surface to `mcp_core` and `auth` only.
// `chio-extensions`, `tasks`, `nested_callbacks`, and `notifications` are
// explicitly deferred to a follow-on milestone and are NOT exercised here. If
// you need to extend the C++ peer's coverage, file a follow-on ticket and add
// a separate integration test rather than expanding this one (its purpose is
// to be the immutable P0 gate).
//
// The C++ peer is the conformance-peer binary built from
// `packages/sdk/chio-cpp` via CMake; that binary links against
// `crates/chio-cpp-kernel-ffi` (the C ABI surface for the Chio offline
// kernel). Driving the binary therefore exercises the FFI end-to-end.
//
// This test is gated behind the `CHIO_CPP_LIVE_CONFORMANCE` environment
// variable for the same reason as the per-area `*_cpp_live.rs` tests: the
// toolchain (cmake, libcurl, a recent python3 with chio-sdk-python) is not
// always available on every dev workstation or CI runner, and the harness
// also needs to spawn the chio binary plus the local OAuth fixtures. When
// the variable is unset (the default), the test prints a skip notice and
// returns success so `cargo test -p chio-conformance --test cpp_peer_p0`
// passes uniformly.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use chio_conformance::{run_conformance_harness, ConformanceAuthMode};

// P0 scenarios for the C++ peer (Wave 1 decision 5). Keep these lists in
// lockstep with `tests/conformance/scenarios/{mcp_core,auth}/` and the
// per-area `mcp_core_cpp_live.rs` / `auth_cpp_live.rs` assertions.
const MCP_CORE_P0_SCENARIOS: &[&str] = &[
    "initialize",
    "tools-list",
    "tools-call-simple-text",
    "resources-list",
    "prompts-list",
];

const AUTH_P0_SCENARIOS: &[&str] = &[
    "auth-unauthorized-challenge",
    "auth-protected-resource-metadata",
    "auth-authorization-server-metadata",
    "auth-code-initialize",
    "auth-token-exchange-initialize",
];

// Areas explicitly deferred to a follow-on milestone (Wave 1 decision 5).
// Listed here so a future reader can grep and confirm the deferral is still
// the intent before expanding the gate.
const DEFERRED_AREAS: &[&str] = &[
    "chio-extensions",
    "tasks",
    "nested_callbacks",
    "notifications",
];

#[test]
fn cpp_peer_p0_mcp_core_and_auth_pass() {
    if common::skip_cpp_live_conformance_unless_enabled() {
        eprintln!(
            "cpp_peer_p0: deferred areas (not asserted in P0): {}",
            DEFERRED_AREAS.join(", ")
        );
        return;
    }

    if !common::command_available("cmake") || !common::python3_supports_chio_sdk() {
        eprintln!(
            "cpp_peer_p0: required toolchain unavailable (cmake or python3>=3.11 with chio-sdk-python); skipping"
        );
        return;
    }

    // mcp_core scenarios: static-bearer auth.
    let mcp_core_options = common::cpp_options("mcp_core", ConformanceAuthMode::StaticBearer);
    let mcp_core_summary =
        run_conformance_harness(&mcp_core_options).expect("run mcp_core conformance harness");
    let mcp_core_results =
        std::fs::read_to_string(mcp_core_summary.results_dir.join("cpp-remote-http.json"))
            .expect("read mcp_core cpp results");

    for scenario in MCP_CORE_P0_SCENARIOS {
        assert!(
            common::scenario_passed(&mcp_core_results, scenario),
            "C++ peer must pass P0 mcp_core scenario `{scenario}`; results: {mcp_core_results}"
        );
    }

    // auth scenarios: local OAuth.
    let auth_options = common::cpp_options("auth", ConformanceAuthMode::LocalOAuth);
    let auth_summary =
        run_conformance_harness(&auth_options).expect("run auth conformance harness");
    let auth_results =
        std::fs::read_to_string(auth_summary.results_dir.join("cpp-remote-http.json"))
            .expect("read auth cpp results");

    for scenario in AUTH_P0_SCENARIOS {
        assert!(
            common::scenario_passed(&auth_results, scenario),
            "C++ peer must pass P0 auth scenario `{scenario}`; results: {auth_results}"
        );
    }
}

// Compile-time guard: deferred areas live on disk but are intentionally not
// driven through the C++ peer in P0. If a deferred-area scenarios directory
// disappears, that is a signal that the follow-on milestone has begun and the
// P0 gate should be revisited.
#[test]
fn deferred_areas_still_present_on_disk() {
    let repo_root = chio_conformance::default_repo_root();
    for area in DEFERRED_AREAS {
        let area_dir = repo_root.join(format!("tests/conformance/scenarios/{area}"));
        assert!(
            area_dir.exists(),
            "deferred scenario area `{area}` missing at {}; \
             if the follow-on milestone has started, update cpp_peer_p0.rs to cover it",
            area_dir.display()
        );
    }
}
