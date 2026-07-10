#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeEdgeMatrix {
    schema: String,
    id: String,
    finding_ids: Vec<String>,
    edges: Vec<RuntimeEdgeRow>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeEdgeRow {
    surface: String,
    crate_name: String,
    source_path: String,
    test_name: String,
    entrypoint: String,
    expected: RuntimeEdgeExpected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeEdgeExpected {
    runtime_admission_before_dispatch: bool,
    deny_receipt_emitted: bool,
    downstream_dispatch_count_zero: bool,
    route_metadata_bound: bool,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf())
}

fn matrix_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("runtime_edges")
}

fn load_matrices() -> Result<Vec<RuntimeEdgeMatrix>, Box<dyn Error>> {
    let mut matrices = Vec::new();
    for entry in fs::read_dir(matrix_dir())? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path)?;
        matrices.push(serde_json::from_slice::<RuntimeEdgeMatrix>(&bytes)?);
    }
    matrices.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(matrices)
}

#[test]
fn r_t03_runtime_edge_matrix_points_to_real_admission_tests() -> Result<(), Box<dyn Error>> {
    let matrices = load_matrices()?;
    assert!(
        !matrices.is_empty(),
        "runtime edge matrix must not be empty"
    );

    let mut surfaces = BTreeSet::new();
    let mut crates = BTreeSet::new();
    let root = repo_root();
    for matrix in matrices {
        assert_eq!(matrix.schema, "chio.runtime-edge-conformance.v1");
        let finding_ids = matrix
            .finding_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert!(finding_ids.contains("R-T03-09"));
        assert!(finding_ids.contains("R-T03-14"));
        assert!(finding_ids.contains("R-T03-21"));
        assert!(
            !matrix.edges.is_empty(),
            "{} must list runtime edges",
            matrix.id
        );

        for edge in matrix.edges {
            assert!(
                edge.expected.runtime_admission_before_dispatch,
                "{} must prove runtime admission runs before dispatch",
                edge.surface
            );
            assert!(
                edge.expected.deny_receipt_emitted,
                "{} must emit a deny receipt",
                edge.surface
            );
            assert!(
                edge.expected.downstream_dispatch_count_zero,
                "{} must prove downstream dispatch did not run",
                edge.surface
            );
            if edge.expected.route_metadata_bound {
                assert!(
                    edge.entrypoint.contains("tools/call")
                        || edge.entrypoint.contains("function_call"),
                    "{} route binding must name the routed entrypoint",
                    edge.surface
                );
            }

            let source_path = root.join(&edge.source_path);
            let source = fs::read_to_string(&source_path)?;
            let test_signature = format!("fn {}(", edge.test_name);
            assert!(
                source.contains(&test_signature),
                "{} must reference a real source test in {}",
                edge.surface,
                edge.source_path
            );
            surfaces.insert(edge.surface);
            crates.insert(edge.crate_name);
        }
    }

    assert_eq!(
        surfaces,
        BTreeSet::from([
            "a2a_adapter_deferred_get_task".to_string(),
            "a2a_adapter_send_message".to_string(),
            "a2a_edge_deferred_task_get".to_string(),
            "acp_edge_stream_resume".to_string(),
            "mcp_tools_call_route_metadata".to_string(),
            "openai_function_call".to_string(),
            "openapi_bridge_invocation".to_string(),
        ])
    );
    assert_eq!(
        crates,
        BTreeSet::from([
            "chio-a2a-adapter".to_string(),
            "chio-a2a-edge".to_string(),
            "chio-acp-edge".to_string(),
            "chio-mcp-edge".to_string(),
            "chio-openai-adapter".to_string(),
            "chio-openapi-mcp-bridge".to_string(),
        ])
    );
    Ok(())
}
