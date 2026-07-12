use std::fs;
use std::path::Path;

const GENERATED_HEADER: &str = "DO NOT EDIT - regenerate via 'cargo xtask codegen rust'";

#[test]
fn generated_rust_sources_have_the_regeneration_header() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/_generated");
    let mut seen = 0usize;
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        assert!(
            source
                .lines()
                .take(16)
                .any(|line| line.contains(GENERATED_HEADER)),
            "{} is missing its generated-source header",
            path.display()
        );
        seen += 1;
    }
    assert!(seen > 0, "generated source directory is empty");
    Ok(())
}
