use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("repo root should resolve: {error}"))
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn line_count(relative: &str) -> usize {
    read_repo_file(relative).lines().count()
}

#[test]
fn runtime_entrypoints_remain_decomposed_and_reexported() {
    // Remote MCP now lives in chio-mcp-remote; chio-hosted-mcp is a compatibility shell.
    let cli_types = read_repo_file("crates/chio-cli/src/cli/types.rs");
    assert!(
        cli_types.contains("pub use chio_mcp_remote as remote_mcp;"),
        "chio-cli cli/types.rs must keep re-exporting the remote MCP crate",
    );
    let main = read_repo_file("crates/chio-cli/src/main.rs");
    assert!(
        !main.contains("mod remote_mcp;"),
        "chio-cli main must not inline the remote MCP runtime shell",
    );
    assert!(
        !main.contains("mod trust_control;"),
        "chio-cli main must not inline the trust-control runtime shell",
    );

    // The pre-refactor crate-extraction pattern (#[path = "../../chio-cli/..."]
    // splice from chio-hosted-mcp/chio-control-plane) was replaced by direct
    // re-exports once chio-mcp-remote became a first-class workspace member.
    // The current invariant is that chio-cli no longer inlines remote_mcp;
    // ownership lives in chio-mcp-remote.
    let hosted_lib = read_repo_file("crates/chio-hosted-mcp/src/lib.rs");
    assert!(
        hosted_lib.contains("pub use chio_mcp_remote::{serve_http, RemoteServeHttpConfig};"),
        "chio-hosted-mcp must remain a compatibility re-export of chio-mcp-remote",
    );

    let control_plane_lib = read_repo_file("crates/chio-control-plane/src/lib.rs");
    assert!(
        control_plane_lib.contains("#[path = \"../../chio-cli/src/trust_control.rs\"]"),
        "chio-control-plane must remain the runtime owner of trust_control.rs",
    );
    assert!(
        control_plane_lib.contains("#[path = \"../../chio-cli/src/federation_policy.rs\"]"),
        "chio-control-plane must keep the extracted federation policy boundary",
    );
    assert!(
        control_plane_lib.contains("#[path = \"../../chio-cli/src/scim_lifecycle.rs\"]"),
        "chio-control-plane must keep the extracted scim lifecycle boundary",
    );

    assert!(
        repo_root()
            .join("crates/chio-mcp-remote/src/remote_mcp/admin.rs")
            .exists(),
        "remote_mcp admin boundary file must exist",
    );
    assert!(
        !repo_root()
            .join("crates/chio-cli/src/remote_mcp.rs")
            .exists(),
        "remote_mcp ownership must live in chio-mcp-remote, not be inlined in chio-cli",
    );

    let trust_control = read_repo_file("crates/chio-cli/src/trust_control.rs");
    assert!(
        trust_control.contains("#[path = \"trust_control/health.rs\"]"),
        "trust_control.rs must keep its health boundary extracted",
    );
    assert!(
        repo_root()
            .join("crates/chio-cli/src/trust_control/health.rs")
            .exists(),
        "trust_control health boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/chio-cli/src/federation_policy.rs")
            .exists(),
        "trust_control federation policy boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/chio-cli/src/scim_lifecycle.rs")
            .exists(),
        "trust_control scim lifecycle boundary file must exist",
    );

    let edge_runtime = read_repo_file("crates/chio-mcp-edge/src/runtime.rs");
    assert!(
        edge_runtime.contains("#[path = \"runtime/protocol.rs\"]"),
        "chio-mcp-edge runtime must keep protocol helpers extracted",
    );
    assert!(
        repo_root()
            .join("crates/chio-mcp-edge/src/runtime/protocol.rs")
            .exists(),
        "chio-mcp-edge protocol helper file must exist",
    );

    let kernel = read_repo_file("crates/chio-kernel/src/lib.rs");
    assert!(
        kernel.contains("mod receipt_support;"),
        "chio-kernel must keep receipt support extracted",
    );
    assert!(
        kernel.contains("mod request_matching;"),
        "chio-kernel must keep request matching extracted",
    );
    assert!(
        repo_root()
            .join("crates/chio-kernel/src/receipt_support.rs")
            .exists(),
        "chio-kernel receipt support file must exist",
    );
    assert!(
        repo_root()
            .join("crates/chio-kernel/src/request_matching.rs")
            .exists(),
        "chio-kernel request matching file must exist",
    );

    assert!(
        line_count("crates/chio-mcp-remote/src/remote_mcp/http_service.rs") <= 2600,
        "remote_mcp http_service.rs regrew past the phase-180 ceiling",
    );
    assert!(
        line_count("crates/chio-cli/src/trust_control.rs") <= 21500,
        "trust_control.rs regrew past the phase-180 ceiling",
    );
    assert!(
        line_count("crates/chio-mcp-edge/src/runtime.rs") <= 6600,
        "chio-mcp-edge runtime.rs regrew past the phase-180 ceiling",
    );
    assert!(
        line_count("crates/chio-kernel/src/lib.rs") <= 11800,
        "chio-kernel lib.rs regrew past the phase-180 ceiling",
    );
}

#[test]
fn runtime_boundary_map_is_present() {
    let doc = read_repo_file("docs/architecture/CHIO_RUNTIME_BOUNDARIES.md");
    assert!(doc.contains("crates/chio-mcp-remote/src/remote_mcp/admin.rs"));
    assert!(doc.contains("trust_control/health.rs"));
    assert!(doc.contains("federation_policy.rs"));
    assert!(doc.contains("scim_lifecycle.rs"));
    assert!(doc.contains("runtime/protocol.rs"));
    assert!(doc.contains("receipt_support.rs"));
    assert!(doc.contains("request_matching.rs"));
}
