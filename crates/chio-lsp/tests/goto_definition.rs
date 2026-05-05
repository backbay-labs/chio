//! Go-to-definition integration test.
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
    // The resolver canonicalises the manifest path so it stays inside
    // the document directory; compare against the canonical sibling.
    let canonical_manifest = std::fs::canonicalize(&manifest_path).unwrap();
    assert_eq!(loc.uri, Url::from_file_path(&canonical_manifest).unwrap());
}

#[test]
fn manifest_pointer_rejects_absolute_path() {
    // Hostile chio.yaml that points the LSP server at a file outside
    // the document directory must not be followed. The resolver may
    // still find an in-document match for the URN; what matters is
    // that the returned Location does NOT reference the absolute path.
    let dir = tempfile::tempdir().unwrap();
    let chio_yaml_path = dir.path().join("chio.yaml");
    let text = "version: 1\nmanifest: /etc/passwd\nguards:\n  - urn:chio:guard:rate-limiter\n";
    {
        let mut f = std::fs::File::create(&chio_yaml_path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }
    let uri = Url::from_file_path(&chio_yaml_path).unwrap();
    let pos = Position::new(3, 12);
    let loc = definition(DocumentLanguage::ChioYaml, &uri, text, pos);
    if let Some(loc) = loc {
        assert_ne!(
            loc.uri.path(),
            "/etc/passwd",
            "absolute manifest paths must not be followed"
        );
    }
}

#[test]
fn manifest_pointer_rejects_parent_traversal() {
    // A `..` traversal must not escape the document directory. The
    // resolver may fall back to the in-document URN match.
    let dir = tempfile::tempdir().unwrap();
    let chio_yaml_path = dir.path().join("chio.yaml");
    let text = "version: 1\nmanifest: ../escape.chio-manifest.yaml\nguards:\n  - urn:chio:guard:rate-limiter\n";
    {
        let mut f = std::fs::File::create(&chio_yaml_path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }
    let uri = Url::from_file_path(&chio_yaml_path).unwrap();
    let pos = Position::new(3, 12);
    let loc = definition(DocumentLanguage::ChioYaml, &uri, text, pos);
    if let Some(loc) = loc {
        // The resolved file URI must remain inside the document
        // directory (or be the document itself). Both sides are
        // canonicalised so macOS `/var` -> `/private/var` indirection
        // does not produce a false positive.
        let dir_canonical = std::fs::canonicalize(dir.path()).unwrap();
        let loc_path = loc.uri.to_file_path().unwrap();
        let loc_canonical = std::fs::canonicalize(&loc_path).unwrap_or_else(|_| loc_path.clone());
        assert!(
            loc_canonical.starts_with(&dir_canonical),
            "parent traversal escaped document directory: {loc_canonical:?}"
        );
    }
}

#[test]
fn manifest_pointer_rejects_non_manifest_filename() {
    // Files that do not match the manifest naming pattern must not be
    // read by the LSP server even when they sit in the document
    // directory.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("secrets.txt");
    {
        let mut f = std::fs::File::create(&target).unwrap();
        writeln!(f, "urn:chio:guard:rate-limiter").unwrap();
    }
    let chio_yaml_path = dir.path().join("chio.yaml");
    let text = "version: 1\nmanifest: secrets.txt\nguards:\n  - urn:chio:guard:rate-limiter\n";
    {
        let mut f = std::fs::File::create(&chio_yaml_path).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }
    let uri = Url::from_file_path(&chio_yaml_path).unwrap();
    let pos = Position::new(3, 12);
    let loc = definition(DocumentLanguage::ChioYaml, &uri, text, pos);
    if let Some(loc) = loc {
        let target_canonical = std::fs::canonicalize(&target).unwrap();
        let loc_path = loc.uri.to_file_path().unwrap();
        assert_ne!(
            loc_path, target_canonical,
            "non-manifest filename must not be opened by the LSP server"
        );
    }
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
