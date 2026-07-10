use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
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
    // Remote MCP lives in chio-mcp-remote; chio-hosted-mcp is a compatibility shell.
    let main = read_repo_file("crates/products/chio-cli/src/main.rs");
    assert!(
        main.contains("pub use chio_mcp_remote as remote_mcp;"),
        "chio-cli main.rs must keep re-exporting the remote MCP crate",
    );
    assert!(
        !main.contains("mod remote_mcp;"),
        "chio-cli main must not inline the remote MCP runtime shell",
    );
    assert!(
        !main.contains("mod trust_control;"),
        "chio-cli main must not inline the trust-control runtime shell",
    );

    // chio-cli must not inline the remote_mcp module; ownership lives in chio-mcp-remote.
    let hosted_lib = read_repo_file("crates/protocol/chio-hosted-mcp/src/lib.rs");
    assert!(
        hosted_lib.contains("pub use chio_mcp_remote::{serve_http, RemoteServeHttpConfig};"),
        "chio-hosted-mcp must remain a compatibility re-export of chio-mcp-remote",
    );

    let control_plane_lib = read_repo_file("crates/platform/chio-control-plane/src/lib.rs");
    assert!(
        !control_plane_lib.contains("../../../products/chio-cli/src/"),
        "chio-control-plane must own its trust-control sources directly, not reach into chio-cli/src",
    );
    assert!(
        control_plane_lib.contains("pub mod trust_control;"),
        "chio-control-plane must own trust_control as a direct module",
    );
    assert!(
        control_plane_lib.contains("pub mod federation_policy;"),
        "chio-control-plane must own federation_policy as a direct module",
    );
    assert!(
        control_plane_lib.contains("pub mod scim_lifecycle;"),
        "chio-control-plane must own scim_lifecycle as a direct module",
    );

    assert!(
        repo_root()
            .join("crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs")
            .exists(),
        "remote_mcp admin boundary file must exist",
    );
    assert!(
        !repo_root()
            .join("crates/products/chio-cli/src/remote_mcp.rs")
            .exists(),
        "remote_mcp ownership must live in chio-mcp-remote, not be inlined in chio-cli",
    );

    let trust_control = read_repo_file("crates/platform/chio-control-plane/src/trust_control.rs");
    assert!(
        trust_control.contains("#[path = \"trust_control/health.rs\"]"),
        "trust_control.rs must keep its health boundary extracted",
    );
    assert!(
        repo_root()
            .join("crates/platform/chio-control-plane/src/trust_control/health.rs")
            .exists(),
        "trust_control health boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/platform/chio-control-plane/src/federation_policy.rs")
            .exists(),
        "trust_control federation policy boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/platform/chio-control-plane/src/scim_lifecycle.rs")
            .exists(),
        "trust_control scim lifecycle boundary file must exist",
    );

    let edge_runtime = read_repo_file("crates/protocol/chio-mcp-edge/src/runtime.rs");
    assert!(
        edge_runtime.contains("#[path = \"runtime/protocol.rs\"]"),
        "chio-mcp-edge runtime must keep protocol helpers extracted",
    );
    assert!(
        repo_root()
            .join("crates/protocol/chio-mcp-edge/src/runtime/protocol.rs")
            .exists(),
        "chio-mcp-edge protocol helper file must exist",
    );

    let kernel = read_repo_file("crates/kernel/chio-kernel/src/lib.rs");
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
            .join("crates/kernel/chio-kernel/src/receipt_support/mod.rs")
            .exists(),
        "chio-kernel receipt support facade file must exist",
    );
    assert!(
        repo_root()
            .join("crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs")
            .exists(),
        "chio-kernel receipt metadata boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/kernel/chio-kernel/src/receipt_support/receipt_content.rs")
            .exists(),
        "chio-kernel receipt content boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/kernel/chio-kernel/src/receipt_support/receipt_scopes.rs")
            .exists(),
        "chio-kernel receipt scopes boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/kernel/chio-kernel/src/receipt_support/receipt_building.rs")
            .exists(),
        "chio-kernel receipt building boundary file must exist",
    );
    assert!(
        repo_root()
            .join("crates/kernel/chio-kernel/src/request_matching.rs")
            .exists(),
        "chio-kernel request matching file must exist",
    );

    assert!(
        line_count("crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs") <= 2600,
        "remote_mcp http_service.rs exceeded its 2600-line ceiling",
    );
    assert!(
        line_count("crates/platform/chio-control-plane/src/trust_control.rs") <= 21500,
        "trust_control.rs exceeded its 21500-line ceiling",
    );
    assert!(
        line_count("crates/protocol/chio-mcp-edge/src/runtime.rs") <= 6600,
        "chio-mcp-edge runtime.rs exceeded its 6600-line ceiling",
    );
    assert!(
        line_count("crates/kernel/chio-kernel/src/lib.rs") <= 11800,
        "chio-kernel lib.rs exceeded its 11800-line ceiling",
    );
}

#[test]
fn runtime_boundary_map_is_present() {
    let doc = read_repo_file("docs/architecture/CHIO_RUNTIME_BOUNDARIES.md");
    assert!(doc.contains("crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs"));
    assert!(doc.contains("trust_control/health.rs"));
    assert!(doc.contains("federation_policy.rs"));
    assert!(doc.contains("scim_lifecycle.rs"));
    assert!(doc.contains("runtime/protocol.rs"));
    assert!(doc.contains("receipt_support/mod.rs"));
    assert!(doc.contains("receipt_support/receipt_metadata.rs"));
    assert!(doc.contains("request_matching.rs"));
}
