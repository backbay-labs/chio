#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CrossSurfaceFixture {
    schema: String,
    id: String,
    surface: String,
    negative_class: String,
    expected: CrossSurfaceExpected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CrossSurfaceExpected {
    verdict: String,
    deny_receipt_emitted: bool,
    lineage_class: String,
    revocation_propagates: bool,
    budget_enforced: bool,
    no_adapter_bypass: bool,
    signed_negative_conformance: bool,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("cross_surface")
}

fn load_fixtures() -> Result<Vec<CrossSurfaceFixture>, Box<dyn Error>> {
    let mut fixtures = Vec::new();
    for entry in fs::read_dir(fixtures_dir())? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path)?;
        let fixture = serde_json::from_slice::<CrossSurfaceFixture>(&bytes)?;
        fixtures.push(fixture);
    }
    fixtures.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(fixtures)
}

#[test]
fn t2_1_cross_surface_negative_fixtures_cover_all_advertised_surfaces() -> Result<(), Box<dyn Error>>
{
    let fixtures = load_fixtures()?;
    assert!(
        !fixtures.is_empty(),
        "T2.1 cross-surface fixture directory must not be empty"
    );

    let mut surfaces = BTreeSet::new();
    for fixture in &fixtures {
        assert_eq!(fixture.schema, "chio.cross_surface_conformance.negative.v1");
        assert_eq!(fixture.negative_class, "adapter_bypass_denied");
        assert_eq!(fixture.expected.verdict, "deny");
        assert!(
            fixture.expected.deny_receipt_emitted,
            "{} must emit a deny receipt",
            fixture.id
        );
        assert_eq!(fixture.expected.lineage_class, "preserved");
        assert!(
            fixture.expected.revocation_propagates,
            "{} must propagate revocation",
            fixture.id
        );
        assert!(
            fixture.expected.budget_enforced,
            "{} must enforce budget",
            fixture.id
        );
        assert!(
            fixture.expected.no_adapter_bypass,
            "{} must deny adapter bypass",
            fixture.id
        );
        assert!(
            fixture.expected.signed_negative_conformance,
            "{} must be a signed negative conformance fixture",
            fixture.id
        );
        surfaces.insert(fixture.surface.as_str());
    }

    let required = BTreeSet::from(["a2a_http_edge", "hosted_native_http", "mcp_wrapped"]);
    assert_eq!(surfaces, required);
    Ok(())
}
