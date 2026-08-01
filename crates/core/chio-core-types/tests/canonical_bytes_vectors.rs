#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core_types::CanonicalBytes;
use serde::Deserialize;
use serde_json::Value;

const CANONICAL_VECTOR_CORPUS: &str =
    include_str!("../../../../tests/bindings/vectors/canonical/v1.json");
const EXPECTED_CASE_COUNT: usize = 23;

#[derive(Debug, Deserialize)]
struct Corpus {
    cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    id: String,
    input_json: String,
    canonical_json: String,
}

#[test]
fn canonical_bytes_match_checked_in_vectors() -> Result<(), Box<dyn std::error::Error>> {
    let corpus: Corpus = serde_json::from_str(CANONICAL_VECTOR_CORPUS)?;

    assert_eq!(
        corpus.cases.len(),
        EXPECTED_CASE_COUNT,
        "canonical vector corpus size changed"
    );

    for case in &corpus.cases {
        let input: Value = serde_json::from_str(&case.input_json)?;
        let canonical = CanonicalBytes::from_value(&input)?;

        assert_eq!(
            canonical.as_bytes(),
            case.canonical_json.as_bytes(),
            "canonical bytes drifted for vector {}",
            case.id
        );
    }

    Ok(())
}
