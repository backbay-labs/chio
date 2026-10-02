use chio_megastart::workshop::setup::Setup;
use serde_json::Value;

#[test]
fn setup_codec_matches_shared_fixtures() -> anyhow::Result<()> {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/workshop-setups.json"))?;
    for valid in fixture["valid"].as_array().unwrap() {
        let code = valid["code"].as_str().unwrap();
        let decoded = Setup::decode(code)?;
        assert_eq!(serde_json::to_value(&decoded)?, valid["setup"]);
        assert_eq!(decoded.encode()?, code);
    }
    for invalid in fixture["invalid"].as_array().unwrap() {
        assert!(
            Setup::decode(invalid.as_str().unwrap()).is_err(),
            "accepted {invalid}"
        );
    }
    Ok(())
}

#[test]
fn recorded_sources_use_the_same_digest_scheme() -> anyhow::Result<()> {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/workshop-recording.json"))?;
    for run in fixture["runs"].as_array().unwrap() {
        for (source, key) in [
            (&fixture["original"], "source_sha256"),
            (&run["candidate"], "candidate_sha256"),
            (&run["testSource"], "tests_sha256"),
        ] {
            assert_eq!(chio_megastart::digest(source)?, run["identity"][key]);
        }
    }
    Ok(())
}
