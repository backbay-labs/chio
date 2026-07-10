use super::*;

#[test]
fn resolve_schema_path_rejects_prefix_traversal() {
    let temp = match TempDir::new("xtask-schema-resolve") {
        Ok(temp) => temp,
        Err(err) => panic!("failed to create temp dir: {err}"),
    };
    let schemas_root = temp.path().join("schemas");
    if let Err(err) = fs::create_dir_all(&schemas_root) {
        panic!("failed to create schemas dir: {err}");
    }
    let outside_schema = temp.path().join("outside.schema.json");
    if let Err(err) = fs::write(&outside_schema, "{}") {
        panic!("failed to write outside schema: {err}");
    }

    let uri = format!("{SCHEMA_URI_PREFIX}../outside");
    let index = SchemaIndex::new();

    assert!(resolve_schema_path(&uri, &index, &schemas_root).is_none());
}

#[test]
fn collect_scenario_files_rejects_missing_directory() {
    let temp = match TempDir::new("xtask-scenarios-missing") {
        Ok(temp) => temp,
        Err(err) => panic!("failed to create temp dir: {err}"),
    };
    let missing = temp.path().join("scenarios");

    let error = collect_scenario_files(&missing).unwrap_err();

    assert!(format!("{error}").contains("scenarios directory is missing"));
}

#[test]
fn build_schema_index_rejects_missing_root() {
    let temp = match TempDir::new("xtask-schemas-missing") {
        Ok(temp) => temp,
        Err(err) => panic!("failed to create temp dir: {err}"),
    };
    let missing = temp.path().join("schemas");

    let error = build_schema_index(&missing).unwrap_err();

    assert!(format!("{error}").contains("schema root is missing"));
}

#[test]
fn pascal_case_handles_kebab_and_snake() {
    assert_eq!(pascal_case("trust-control"), "TrustControl");
    assert_eq!(pascal_case("tool_call_request"), "ToolCallRequest");
    assert_eq!(pascal_case("agent"), "Agent");
    assert_eq!(pascal_case("inclusion-proof"), "InclusionProof");
}

#[test]
fn pascal_case_passes_through_pascal_input() {
    // Already-PascalCase input is preserved (no separators to split on).
    assert_eq!(pascal_case("Capability"), "Capability");
}

#[test]
fn ts_namespace_name_derives_group_and_stem() {
    let p = Path::new("spec/schemas/chio-wire/v1/capability/grant.schema.json");
    assert_eq!(ts_namespace_name(p).as_deref(), Some("Capability_Grant"));
    let p = Path::new("spec/schemas/chio-wire/v1/trust-control/lease.schema.json");
    assert_eq!(ts_namespace_name(p).as_deref(), Some("TrustControl_Lease"));
    let p = Path::new("spec/schemas/chio-wire/v1/jsonrpc/request.schema.json");
    assert_eq!(ts_namespace_name(p).as_deref(), Some("Jsonrpc_Request"));
}

#[test]
fn ts_namespace_name_rejects_non_schema_paths() {
    assert!(ts_namespace_name(Path::new("/tmp/foo.txt")).is_none());
}

#[test]
fn ts_header_includes_pin_and_sha() {
    let header = ts_header("deadbeef");
    assert!(header.contains("DO NOT EDIT"));
    assert!(header.contains("cargo xtask codegen --lang ts"));
    assert!(header.contains("json-schema-to-typescript 15.0.4"));
    assert!(header.contains("Schema SHA: deadbeef"));
    assert!(header.contains("/* eslint-disable */"));
}

#[test]
fn normalize_ts_chunk_strips_trailing_newlines() {
    assert_eq!(normalize_ts_chunk("hello\n\n\n"), "hello");
    assert_eq!(normalize_ts_chunk("multi\nline\n"), "multi\nline");
}

#[test]
fn codegen_argv_round_trips_positional_and_flag() {
    // The clap dispatch builds the exact argv `run_codegen` parses.
    use crate::cli::{CodegenArgs, Lang};
    use crate::dispatch::codegen_argv;
    let pos = CodegenArgs {
        lang_positional: Some(Lang::Rust),
        lang_flag: None,
        check: true,
    };
    match codegen_argv(&pos) {
        Ok(argv) => assert_eq!(argv, vec!["rust".to_string(), "--check".to_string()]),
        Err(err) => panic!("positional form must parse, got: {err}"),
    }
    let flag = CodegenArgs {
        lang_positional: None,
        lang_flag: Some(Lang::Python),
        check: false,
    };
    match codegen_argv(&flag) {
        Ok(argv) => assert_eq!(argv, vec!["--lang".to_string(), "python".to_string()]),
        Err(err) => panic!("flag form must parse, got: {err}"),
    }
}

#[test]
fn codegen_argv_rejects_language_given_twice() {
    // `codegen rust --lang python` supplies the language twice; the dispatch
    // rejects this rather than silently keeping the positional and dropping the
    // flag.
    use crate::cli::{CodegenArgs, Lang};
    use crate::dispatch::codegen_argv;
    use crate::XtaskError;
    let both = CodegenArgs {
        lang_positional: Some(Lang::Rust),
        lang_flag: Some(Lang::Python),
        check: false,
    };
    match codegen_argv(&both) {
        Err(XtaskError::Usage(msg)) => {
            assert!(
                msg.contains("given twice") && msg.contains("rust") && msg.contains("python"),
                "got: {msg}"
            );
        }
        other => panic!("expected Usage error for duplicate language, got {other:?}"),
    }
}
