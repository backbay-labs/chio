#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_guards::path_allowlist::PathAllowlistConfig;
use chio_guards::secret_leak::CustomSecretPattern;
use chio_guards::secret_leak::SecretLeakConfig;
use chio_guards::{EgressAllowlistGuard, ForbiddenPathGuard, PathAllowlistGuard, SecretLeakGuard};

fn test_ok<T, E>(result: Result<T, E>, context: &str) -> T
where
    E: std::fmt::Display,
{
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

#[test]
fn forbidden_path_exceptions_do_not_widen_neighboring_secret_paths() {
    let guard = test_ok(
        ForbiddenPathGuard::with_patterns(
            vec!["**/secret/**".to_string(), "**/.env".to_string()],
            vec!["**/secret/public/**".to_string()],
        ),
        "build forbidden-path guard",
    );

    assert!(guard.is_forbidden("/workspace/secret/private/key.txt"));
    assert!(!guard.is_forbidden("/workspace/secret/public/readme.txt"));
    assert!(guard.is_forbidden("/workspace/app/.env"));
}

#[test]
fn path_allowlist_patch_falls_back_to_write_allowlist_and_denies_siblings() {
    let guard = PathAllowlistGuard::with_config(PathAllowlistConfig {
        enabled: true,
        file_access_allow: vec!["/workspace/read/**".to_string()],
        file_write_allow: vec!["/workspace/write/**".to_string()],
        patch_allow: Vec::new(),
    });

    assert!(guard.is_file_access_allowed("/workspace/read/report.txt"));
    assert!(!guard.is_file_access_allowed("/workspace/write/report.txt"));
    assert!(guard.is_file_write_allowed("/workspace/write/report.txt"));
    assert!(guard.is_patch_allowed("/workspace/write/report.txt"));
    assert!(!guard.is_patch_allowed("/workspace/read/report.txt"));
}

#[test]
fn egress_blocklist_takes_precedence_over_allowlist_case_insensitively() {
    let guard = test_ok(
        EgressAllowlistGuard::with_lists(
            vec!["*.example.com".to_string()],
            vec!["blocked.example.com".to_string()],
        ),
        "egress guard config",
    );

    assert!(guard.is_allowed("API.EXAMPLE.COM"));
    assert!(!guard.is_allowed("blocked.example.com"));
    assert!(!guard.is_allowed("outside.example.net"));
}

#[test]
fn secret_leak_custom_patterns_scan_and_skip_paths_are_bounded() {
    let guard = test_ok(
        SecretLeakGuard::with_config(SecretLeakConfig {
            enabled: true,
            skip_paths: vec!["**/fixtures/**".to_string()],
            custom_patterns: vec![CustomSecretPattern {
                name: "internal_token".to_string(),
                pattern: "CHIO_[A-Z0-9]{12}".to_string(),
            }],
        }),
        "secret guard config",
    );

    let matches = guard.scan(b"token = CHIO_ABCDEF123456");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].pattern_name, "internal_token");
    assert!(matches[0].redacted.starts_with("CHIO"));
    assert!(guard.should_skip_path("/workspace/tests/fixtures/token.txt"));
    assert!(!guard.should_skip_path("/workspace/src/token.txt"));
}

#[test]
fn invalid_custom_secret_pattern_is_rejected_at_load_time() {
    let result = SecretLeakGuard::with_config(SecretLeakConfig {
        enabled: true,
        skip_paths: Vec::new(),
        custom_patterns: vec![CustomSecretPattern {
            name: "broken".to_string(),
            pattern: "(".to_string(),
        }],
    });

    assert!(result.is_err(), "invalid custom regex must fail closed");
}
