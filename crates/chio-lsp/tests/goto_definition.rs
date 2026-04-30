//! P4.T5 go-to-definition integration test.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;

use chio_lsp::definition::definition;
use chio_lsp::DocumentLanguage;
use tower_lsp::lsp_types::{Position, Url};

#[test]
fn local_reference_resolves_to_first_occurrence_in_document() {
    let text = "\
scopes:
  - urn:chio:scope:tool.read
capabilities:
  - urn:chio:scope:tool.read
";
    let uri = Url::parse("file:///proj/chio.yaml").unwrap();
    // Cursor on the second occurrence (line 3 is the second list).
    let pos = Position::new(3, 12);
    let loc = definition(DocumentLanguage::ChioYaml, &uri, text, pos).expect("definition resolves");
    assert_eq!(loc.uri, uri);
    // First occurrence is on line index 1.
    assert_eq!(loc.range.start.line, 1);
}

#[test]
fn manifest_pointer_resolves_to_external_file() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("tools.chio-manifest.yaml");
    {
        let mut f = std::fs::File::create(&manifest_path).unwrap();
        writeln!(
            f,
            "tools:\n  - id: search\n    grants:\n      - urn:chio:guard:rate-limiter"
        )
        .unwrap();
    }
    let chio_yaml_path = dir.path().join("chio.yaml");
    let text = format!(
        "version: 1\nmanifest: {}\nguards:\n  - urn:chio:guard:rate-limiter\n",
        manifest_path.file_name().unwrap().to_str().unwrap()
    );
    {
        let mut f = std::fs::File::create(&chio_yaml_path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }
    let uri = Url::from_file_path(&chio_yaml_path).unwrap();
    // Cursor on the guard URN in the chio.yaml `guards:` list.
    let pos = Position::new(3, 12);
    let loc = definition(DocumentLanguage::ChioYaml, &uri, &text, pos)
        .expect("definition resolves to manifest");
    assert_eq!(loc.uri, Url::from_file_path(&manifest_path).unwrap());
}

#[test]
fn cursor_off_urn_returns_none() {
    let text = "version: 1\n";
    let uri = Url::parse("file:///proj/chio.yaml").unwrap();
    let loc = definition(DocumentLanguage::ChioYaml, &uri, text, Position::new(0, 0));
    assert!(loc.is_none());
}

#[test]
fn error_urn_is_not_a_definition_target() {
    let text = "code: urn:chio:error:capability:expired\n";
    let uri = Url::parse("file:///proj/chio.yaml").unwrap();
    let pos = Position::new(0, 30);
    let loc = definition(DocumentLanguage::ChioYaml, &uri, text, pos);
    assert!(
        loc.is_none(),
        "error URNs are not definition targets in P4.T5"
    );
}
