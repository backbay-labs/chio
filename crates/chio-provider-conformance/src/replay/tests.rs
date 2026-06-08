use super::*;

#[test]
fn fixture_paths_for_dir_filters_ndjson_and_sorts() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "chio-provider-conformance-paths-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    fs::write(root.join("b.ndjson"), "{}\n")?;
    fs::write(root.join("a.ndjson"), "{}\n")?;
    fs::write(root.join("notes.txt"), "ignored\n")?;

    let paths = fixture_paths_for_dir(root.clone())?;

    assert_eq!(paths, vec![root.join("a.ndjson"), root.join("b.ndjson")]);
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn load_fixture_rejects_empty_fixture_id() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "chio-provider-conformance-empty-id-{}.ndjson",
        std::process::id()
    ));
    fs::write(
        &path,
        format!(
            r#"{{"schema":"{CAPTURE_SCHEMA}","fixture_id":"","direction":"upstream_request","provider":"openai","payload":{{}}}}"#
        ),
    )?;

    let error = match load_fixture(&path) {
        Ok(_) => {
            let _ = fs::remove_file(&path);
            panic!("empty fixture_id must fail closed");
        }
        Err(error) => error,
    };

    fs::remove_file(&path)?;
    assert!(error.to_string().contains("fixture_id was empty"));
    Ok(())
}

#[test]
fn load_fixture_rejects_spaced_fixture_id() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "chio-provider-conformance-spaced-id-{}.ndjson",
        std::process::id()
    ));
    fs::write(
        &path,
        format!(
            r#"{{"schema":"{CAPTURE_SCHEMA}","fixture_id":" spaced ","direction":"upstream_request","provider":"openai","payload":{{}}}}"#
        ),
    )?;

    let error = match load_fixture(&path) {
        Ok(_) => {
            let _ = fs::remove_file(&path);
            panic!("spaced fixture_id must fail closed");
        }
        Err(error) => error,
    };

    fs::remove_file(&path)?;
    assert!(
        error
            .to_string()
            .contains("fixture_id had surrounding whitespace"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn load_fixture_rejects_fixture_id_that_does_not_match_filename(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "chio-provider-conformance-id-drift-{}.ndjson",
        std::process::id()
    ));
    fs::write(
        &path,
        format!(
            r#"{{"schema":"{CAPTURE_SCHEMA}","fixture_id":"different_fixture","direction":"upstream_request","provider":"openai","payload":{{}}}}"#
        ),
    )?;

    let error = match load_fixture(&path) {
        Ok(_) => {
            let _ = fs::remove_file(&path);
            panic!("fixture_id must be bound to the filename stem");
        }
        Err(error) => error,
    };

    fs::remove_file(&path)?;
    assert!(
        error
            .to_string()
            .contains("fixture_id did not match filename"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn load_fixture_rejects_provider_drift_within_file() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "chio-provider-conformance-provider-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    let path = root.join("provider_drift.ndjson");
    fs::write(
        &path,
        format!(
            r#"{{"schema":"{CAPTURE_SCHEMA}","fixture_id":"provider_drift","direction":"upstream_request","provider":"openai","payload":{{}}}}
{{"schema":"{CAPTURE_SCHEMA}","fixture_id":"provider_drift","direction":"upstream_response","provider":"anthropic","payload":{{}}}}
"#
        ),
    )?;

    let error = match load_fixture(&path) {
        Ok(_) => {
            let _ = fs::remove_dir_all(&root);
            panic!("provider drift must fail closed");
        }
        Err(error) => error,
    };

    fs::remove_dir_all(&root)?;
    assert!(
        error
            .to_string()
            .contains("provider changed within one NDJSON file"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn required_field_rejects_surrounding_whitespace() {
    let error = match required_field(
        Path::new("fixture.ndjson"),
        Some(" call_1 "),
        "invocation_id",
    ) {
        Ok(_) => panic!("spaced invocation_id must fail closed"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("invocation_id had surrounding whitespace"),
        "unexpected error: {error}"
    );
}
