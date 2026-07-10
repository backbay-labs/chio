use std::fs;
use std::path::Path;

use chio_guard_registry::GUARD_WIT_WORLD;
use chio_wasm_guards::abi::{GuardRequest, GuardVerdict};
use sha2::{Digest, Sha256};

use crate::CliError;

use super::*;
use super::build::pack_from_dir;
use super::formatting::{format_duration_us, format_number, mean_u64, percentile};
use super::new::{sanitize_package_name, MANIFEST_YAML_TEMPLATE};
use super::publish::guard_publish_preflight;
use super::verify::{check_verdict, FixtureResult, TestFixture};


    #[test]
    fn sanitize_package_name_normalizes_input() {
        assert_eq!(sanitize_package_name("my-guard"), "my-guard");
        assert_eq!(sanitize_package_name("My Guard"), "my-guard");
        assert_eq!(sanitize_package_name("UPPER_CASE"), "upper-case");
        assert_eq!(sanitize_package_name("___"), "chio-guard");
        assert_eq!(sanitize_package_name("a--b"), "a-b");
    }

    fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected_code);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    fn must_cli_err<T>(result: Result<T, CliError>, context: &str) -> CliError {
        match result {
            Ok(_) => panic!("{context}: expected error"),
            Err(err) => err,
        }
    }

    #[test]
    fn cmd_guard_new_creates_project_directory() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("test-guard");
        let project_name = project_path.to_str().unwrap();

        cmd_guard_new(project_name).unwrap();

        // Check files exist
        assert!(project_path.join("Cargo.toml").exists());
        assert!(project_path.join("src/lib.rs").exists());
        assert!(project_path.join("guard-manifest.yaml").exists());

        // Check Cargo.toml content
        let cargo = fs::read_to_string(project_path.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("name = \"test-guard\""));
        assert!(cargo.contains("crate-type = [\"cdylib\"]"));
        assert!(cargo.contains("chio-guard-sdk = \"0.1\""));
        assert!(cargo.contains("chio-guard-sdk-macros = \"0.1\""));
        assert!(cargo.contains("unwrap_used = \"deny\""));

        // Check src/lib.rs content
        let lib_rs = fs::read_to_string(project_path.join("src/lib.rs")).unwrap();
        assert!(lib_rs.contains("#[chio_guard]"));
        assert!(lib_rs.contains("fn evaluate(req: GuardRequest) -> GuardVerdict"));
        assert!(lib_rs.contains("unimplemented guard - deny by default"));

        // Check guard-manifest.yaml content
        let manifest = fs::read_to_string(project_path.join("guard-manifest.yaml")).unwrap();
        assert!(manifest.contains("name: test-guard"));
        assert!(manifest.contains("abi_version: \"1\""));
        assert!(manifest.contains("wasm_sha256: \"TODO:"));
        assert!(manifest.contains("test_guard.wasm"));
    }

    #[test]
    fn cmd_guard_new_refuses_non_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("existing-guard");
        fs::create_dir_all(&project_path).unwrap();
        fs::write(project_path.join("some-file.txt"), "content").unwrap();

        let result = cmd_guard_new(project_path.to_str().unwrap());
        let err = must_cli_err(result, "scaffold into non-empty directory");
        assert_registry_error(&err, "urn:chio:error:guard:denied", "guard");
        let msg = err.to_string();
        assert!(msg.contains("refusing to scaffold"), "{msg}");
    }

    fn write_publish_manifest(project_dir: &Path, wasm_path: &str, wasm_sha256: &str) {
        let manifest_content = format!(
            "name: test-guard\n\
             version: \"0.1.0\"\n\
             abi_version: \"1\"\n\
             wit_world: {GUARD_WIT_WORLD}\n\
             wasm_path: \"{wasm_path}\"\n\
             wasm_sha256: \"{wasm_sha256}\"\n"
        );
        fs::write(project_dir.join("guard-manifest.yaml"), manifest_content).unwrap();
    }

    #[test]
    fn guard_publish_preflight_rejects_scaffold_sha_before_missing_wasm() {
        let project_dir = tempfile::tempdir().unwrap();
        let scaffold_sha = MANIFEST_YAML_TEMPLATE
            .lines()
            .find_map(|line| line.strip_prefix("wasm_sha256: \""))
            .and_then(|value| value.strip_suffix('"'))
            .unwrap();
        write_publish_manifest(project_dir.path(), "missing.wasm", scaffold_sha);

        let err = must_cli_err(
            guard_publish_preflight(project_dir.path()),
            "publish preflight with scaffold hash",
        );
        assert_registry_error(&err, "urn:chio:error:guard:denied", "guard");
        let msg = err.to_string();
        assert!(msg.contains("wasm_sha256 must be lowercase hex"), "{msg}");
        assert!(
            !msg.contains("failed to read"),
            "scaffold hash must fail before missing-WASM IO: {msg}"
        );
    }

    #[test]
    fn guard_publish_preflight_rejects_non_hex_sha_before_missing_wasm() {
        let project_dir = tempfile::tempdir().unwrap();
        write_publish_manifest(project_dir.path(), "missing.wasm", "abcxyz");

        let err = must_cli_err(
            guard_publish_preflight(project_dir.path()),
            "publish preflight with non-hex hash",
        );
        assert_registry_error(&err, "urn:chio:error:guard:denied", "guard");
        let msg = err.to_string();
        assert!(msg.contains("wasm_sha256 must be lowercase hex"), "{msg}");
        assert!(
            !msg.contains("failed to read"),
            "non-hex hash must fail before missing-WASM IO: {msg}"
        );
    }

    #[test]
    fn guard_publish_preflight_rejects_wasm_sha256_mismatch() {
        let project_dir = tempfile::tempdir().unwrap();
        let wasm_bytes = b"\x00asm\x01\x00\x00\x00guard publish preflight mismatch";
        fs::write(project_dir.path().join("guard.wasm"), wasm_bytes).unwrap();
        let wrong_sha = "0".repeat(64);
        write_publish_manifest(project_dir.path(), "guard.wasm", &wrong_sha);

        let err = must_cli_err(
            guard_publish_preflight(project_dir.path()),
            "publish preflight with hash mismatch",
        );
        assert_registry_error(&err, "urn:chio:error:guard:denied", "guard");
        let actual_sha = hex::encode(Sha256::digest(wasm_bytes));
        let msg = err.to_string();
        assert!(msg.contains("wasm_sha256 mismatch"), "{msg}");
        assert!(msg.contains(&wrong_sha), "{msg}");
        assert!(msg.contains(&actual_sha), "{msg}");
    }

    #[test]
    fn guard_publish_preflight_accepts_valid_manifest_and_wasm() {
        let project_dir = tempfile::tempdir().unwrap();
        let wasm_bytes = b"\x00asm\x01\x00\x00\x00guard publish preflight valid";
        fs::write(project_dir.path().join("guard.wasm"), wasm_bytes).unwrap();
        let expected_sha = hex::encode(Sha256::digest(wasm_bytes));
        write_publish_manifest(project_dir.path(), "guard.wasm", &expected_sha);

        let preflight = guard_publish_preflight(project_dir.path()).unwrap();

        assert_eq!(preflight.manifest.name, "test-guard");
        assert_eq!(preflight.manifest.wasm_sha256, expected_sha);
        assert_eq!(preflight.wasm_bytes, wasm_bytes);
    }

    #[test]
    fn test_fixture_yaml_deserializes() {
        let yaml = r#"
- name: "allows read in /home"
  request:
    tool_name: read_file
    server_id: fs-server
    agent_id: agent-1
    arguments:
      path: "/home/user/doc.txt"
    scopes:
      - "fs-server:read_file"
    action_type: file_access
    extracted_path: "/home/user/doc.txt"
  expected_verdict: allow

- name: "denies read in /etc"
  request:
    tool_name: read_file
    server_id: fs-server
    agent_id: agent-1
    arguments:
      path: "/etc/shadow"
    scopes:
      - "fs-server:read_file"
    action_type: file_access
    extracted_path: "/etc/shadow"
  expected_verdict: deny
  deny_reason_contains: "restricted"
"#;

        let fixtures: Vec<TestFixture> = serde_yml::from_str(yaml).unwrap();
        assert_eq!(fixtures.len(), 2);

        // First fixture: allow
        assert_eq!(fixtures[0].name, "allows read in /home");
        assert_eq!(fixtures[0].request.tool_name, "read_file");
        assert_eq!(fixtures[0].request.server_id, "fs-server");
        assert_eq!(fixtures[0].request.agent_id, "agent-1");
        assert_eq!(fixtures[0].request.scopes, vec!["fs-server:read_file"]);
        assert_eq!(
            fixtures[0].request.action_type.as_deref(),
            Some("file_access")
        );
        assert_eq!(
            fixtures[0].request.extracted_path.as_deref(),
            Some("/home/user/doc.txt")
        );
        assert_eq!(fixtures[0].expected_verdict, "allow");
        assert!(fixtures[0].deny_reason_contains.is_none());

        // Second fixture: deny with reason substring
        assert_eq!(fixtures[1].name, "denies read in /etc");
        assert_eq!(fixtures[1].expected_verdict, "deny");
        assert_eq!(
            fixtures[1].deny_reason_contains.as_deref(),
            Some("restricted")
        );
    }

    #[test]
    fn test_fixture_expected_verdict_values() {
        let allow_yaml = r#"
- name: "allow case"
  request:
    tool_name: t
    server_id: s
    agent_id: a
    arguments: {}
  expected_verdict: allow
"#;
        let deny_yaml = r#"
- name: "deny case"
  request:
    tool_name: t
    server_id: s
    agent_id: a
    arguments: {}
  expected_verdict: deny
"#;

        let allow_fixtures: Vec<TestFixture> = serde_yml::from_str(allow_yaml).unwrap();
        assert_eq!(allow_fixtures[0].expected_verdict, "allow");

        let deny_fixtures: Vec<TestFixture> = serde_yml::from_str(deny_yaml).unwrap();
        assert_eq!(deny_fixtures[0].expected_verdict, "deny");
    }

    #[test]
    fn test_fixture_all_guard_request_fields() {
        let yaml = r#"
- name: "full fields"
  request:
    tool_name: write_file
    server_id: fs-server
    agent_id: agent-2
    arguments:
      content: "hello"
    scopes:
      - "fs-server:write_file"
    action_type: file_write
    extracted_path: "/tmp/out.txt"
    extracted_target: "example.com"
    filesystem_roots:
      - "/tmp"
      - "/home"
    matched_grant_index: 3
  expected_verdict: allow
"#;

        let fixtures: Vec<TestFixture> = serde_yml::from_str(yaml).unwrap();
        assert_eq!(fixtures.len(), 1);
        let req = &fixtures[0].request;
        assert_eq!(req.tool_name, "write_file");
        assert_eq!(req.server_id, "fs-server");
        assert_eq!(req.agent_id, "agent-2");
        assert_eq!(req.action_type.as_deref(), Some("file_write"));
        assert_eq!(req.extracted_path.as_deref(), Some("/tmp/out.txt"));
        assert_eq!(req.extracted_target.as_deref(), Some("example.com"));
        assert_eq!(req.filesystem_roots, vec!["/tmp", "/home"]);
        assert_eq!(req.matched_grant_index, Some(3));
    }

    #[test]
    fn test_check_verdict_allow_pass() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "allow".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Allow;
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_deny_pass() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("blocked".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_allow_but_denied_fails() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "allow".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("nope".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => panic!("expected fail, got pass"),
            FixtureResult::Fail(_) => {}
        }
    }

    #[test]
    fn test_check_verdict_deny_reason_contains_match() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: Some("restricted".to_string()),
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("path is restricted zone".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_deny_reason_contains_mismatch() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: Some("restricted".to_string()),
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("blocked by policy".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => panic!("expected fail, got pass"),
            FixtureResult::Fail(_) => {}
        }
    }

    fn make_test_request() -> GuardRequest {
        GuardRequest {
            tool_name: "test_tool".to_string(),
            server_id: "test-server".to_string(),
            agent_id: "test-agent".to_string(),
            arguments: serde_json::json!({}),
            scopes: Vec::new(),
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        }
    }

    // --- Percentile / bench helper tests ---

    #[test]
    fn test_percentile_basic() {
        let data = vec![1, 2, 3, 4, 5];
        // p50: index = 5 * 50 / 100 = 2 -> data[2] = 3
        assert_eq!(percentile(&data, 50), 3);
        // p99: index = 5 * 99 / 100 = 4 -> data[4] = 5
        assert_eq!(percentile(&data, 99), 5);
    }

    #[test]
    fn test_percentile_single_element() {
        let data = vec![42];
        assert_eq!(percentile(&data, 50), 42);
        assert_eq!(percentile(&data, 99), 42);
    }

    #[test]
    fn test_percentile_empty() {
        let data: Vec<u64> = vec![];
        assert_eq!(percentile(&data, 50), 0);
        assert_eq!(percentile(&data, 99), 0);
    }

    #[test]
    fn test_mean_u64_basic() {
        assert_eq!(mean_u64(&[10, 20, 30]), 20);
        assert_eq!(mean_u64(&[1, 2, 3, 4, 5]), 3);
    }

    #[test]
    fn test_mean_u64_empty() {
        assert_eq!(mean_u64(&[]), 0);
    }

    #[test]
    fn test_format_duration_us() {
        // 1000 ns = 1.00 us
        assert_eq!(format_duration_us(1000), "1.00 us");
        // 1500 ns = 1.50 us
        assert_eq!(format_duration_us(1500), "1.50 us");
        // 0 ns = 0.00 us
        assert_eq!(format_duration_us(0), "0.00 us");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1_000_000), "1,000,000");
        assert_eq!(format_number(12_345), "12,345");
    }

    // --- Pack / Install tests ---

    #[test]
    fn test_pack_and_install_round_trip() {
        let project_dir = tempfile::tempdir().unwrap();

        // Create a minimal guard-manifest.yaml
        let manifest_content = r#"name: test-guard
version: "0.1.0"
abi_version: "1"
wasm_path: "test_guard.wasm"
wasm_sha256: "deadbeef"
"#;
        fs::write(
            project_dir.path().join("guard-manifest.yaml"),
            manifest_content,
        )
        .unwrap();

        let wasm_content = b"\x00asm\x01\x00\x00\x00fixture wasm content for round-trip test";
        fs::write(project_dir.path().join("test_guard.wasm"), wasm_content).unwrap();

        pack_from_dir(project_dir.path()).unwrap();

        let archive_path = project_dir.path().join("test-guard-0.1.0.arcguard");
        assert!(
            archive_path.exists(),
            "archive should exist at {}",
            archive_path.display()
        );
        assert!(
            archive_path.metadata().unwrap().len() > 0,
            "archive should be non-empty"
        );

        // Install to a separate directory
        let install_dir = tempfile::tempdir().unwrap();
        cmd_guard_install(&archive_path, install_dir.path()).unwrap();

        // Verify extracted files exist in {target_dir}/test-guard/
        let guard_dir = install_dir.path().join("test-guard");
        assert!(guard_dir.exists(), "guard subdirectory should exist");

        let extracted_manifest = guard_dir.join("guard-manifest.yaml");
        assert!(
            extracted_manifest.exists(),
            "extracted manifest should exist"
        );

        let extracted_wasm = guard_dir.join("test_guard.wasm");
        assert!(extracted_wasm.exists(), "extracted wasm should exist");

        // Verify wasm content is identical
        let extracted_wasm_bytes = fs::read(&extracted_wasm).unwrap();
        assert_eq!(
            extracted_wasm_bytes, wasm_content,
            "extracted wasm content should match original"
        );

        // Verify manifest has updated wasm_path pointing to co-located filename
        let extracted_manifest_content = fs::read_to_string(&extracted_manifest).unwrap();
        assert!(
            extracted_manifest_content.contains("wasm_path"),
            "extracted manifest should contain wasm_path"
        );
        // The wasm_path in the extracted manifest should point to the local filename
        let parsed: serde_yml::Value = serde_yml::from_str(&extracted_manifest_content).unwrap();
        let wasm_path_val = parsed.get("wasm_path").unwrap();
        assert_eq!(
            wasm_path_val.as_str().unwrap(),
            "test_guard.wasm",
            "extracted manifest wasm_path should be the co-located filename"
        );
    }

    #[test]
    fn test_pack_fails_without_manifest() {
        let project_dir = tempfile::tempdir().unwrap();
        // No guard-manifest.yaml created
        let err = must_cli_err(pack_from_dir(project_dir.path()), "pack without manifest");
        assert_registry_error(&err, "urn:chio:error:cli:io", "cli");
        let msg = err.to_string();
        assert!(msg.contains("failed to read"), "{msg}");
        assert!(msg.contains("guard-manifest.yaml"), "{msg}");
    }

    #[test]
    fn test_pack_fails_with_cli_yaml_for_invalid_manifest() {
        let project_dir = tempfile::tempdir().unwrap();
        fs::write(project_dir.path().join("guard-manifest.yaml"), "name: [").unwrap();

        let err = must_cli_err(
            pack_from_dir(project_dir.path()),
            "pack with invalid manifest yaml",
        );
        assert_registry_error(&err, "urn:chio:error:cli:yaml", "cli");
        let msg = err.to_string();
        assert!(msg.contains("failed to parse guard-manifest.yaml"), "{msg}");
    }

    #[test]
    fn test_pack_fails_with_missing_wasm() {
        let project_dir = tempfile::tempdir().unwrap();

        // Create manifest pointing to a .wasm that does not exist
        let manifest_content = r#"name: test-guard
version: "0.1.0"
abi_version: "1"
wasm_path: "nonexistent.wasm"
wasm_sha256: "deadbeef"
"#;
        fs::write(
            project_dir.path().join("guard-manifest.yaml"),
            manifest_content,
        )
        .unwrap();

        let err = must_cli_err(pack_from_dir(project_dir.path()), "pack with missing wasm");
        assert_registry_error(&err, "urn:chio:error:cli:io", "cli");
        let msg = err.to_string();
        assert!(msg.contains("failed to read wasm file"), "{msg}");
    }

    #[test]
    fn test_install_fails_with_missing_archive() {
        let install_dir = tempfile::tempdir().unwrap();
        let bogus_path = install_dir.path().join("nonexistent.arcguard");
        let err = must_cli_err(
            cmd_guard_install(&bogus_path, install_dir.path()),
            "install missing archive",
        );
        assert_registry_error(&err, "urn:chio:error:cli:io", "cli");
        let msg = err.to_string();
        assert!(msg.contains("failed to inspect"), "{msg}");
    }

    #[test]
    fn guard_install_rejects_symlink_member() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("evil.arcguard");
        let file = fs::File::create(&archive).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../escape").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "guard-manifest.yaml", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap();

        let install_dir = tempfile::tempdir().unwrap();
        let err = must_cli_err(
            cmd_guard_install(&archive, install_dir.path()),
            "install symlink archive",
        );
        let msg = err.to_string();
        assert!(msg.contains("non-regular"), "{msg}");
    }
