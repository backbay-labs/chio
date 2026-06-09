//! Smoke tests for the embedded built-in rulesets.
//!
//! For each ruleset we assert that:
//!
//! 1. The YAML blob parses cleanly as a HushSpec document.
//! 2. The HushSpec validation layer accepts it (no schema errors).
//! 3. The compiler produces a [`CompiledPolicy`] with a non-failing
//!    pipeline. Some rulesets (notably `permissive`) intentionally emit
//!    fewer guards; we only assert that compilation succeeds.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_policy::{compile_policy, load_builtin, validate, HushSpec, BUILTIN_RULESETS};

#[test]
fn exposes_seven_builtin_rulesets() {
    let names: Vec<&str> = BUILTIN_RULESETS.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names,
        vec![
            "default",
            "strict",
            "permissive",
            "ai-agent",
            "cicd",
            "remote-desktop",
            "panic",
        ],
        "built-in ruleset catalogue changed; update this test if the port list changed"
    );
}

#[test]
fn every_builtin_parses_as_hushspec() {
    for (name, yaml) in BUILTIN_RULESETS {
        let spec = HushSpec::parse(yaml)
            .unwrap_or_else(|e| panic!("ruleset {name} should parse as HushSpec: {e}"));
        assert_eq!(
            spec.hushspec, "0.1.0",
            "ruleset {name} should target HushSpec 0.1.0"
        );
    }
}

#[test]
fn every_builtin_passes_hushspec_validation() {
    for (name, yaml) in BUILTIN_RULESETS {
        let spec = HushSpec::parse(yaml).expect("parse");
        let validation = validate(&spec);
        assert!(
            validation.is_valid(),
            "ruleset {name} should validate; errors: {:?}",
            validation.errors
        );
    }
}

#[test]
fn every_builtin_compiles_without_error() {
    for (name, yaml) in BUILTIN_RULESETS {
        let spec = HushSpec::parse(yaml).expect("parse");
        let compiled = compile_policy(&spec)
            .unwrap_or_else(|e| panic!("ruleset {name} should compile: {e:?}"));
        // The pipeline and name-list always have matching length.
        assert_eq!(
            compiled.guards.len(),
            compiled.guard_names.len(),
            "ruleset {name} guards vs guard_names length mismatch"
        );
    }
}

#[test]
fn load_builtin_accepts_raw_and_prefixed_names() {
    for (name, _) in BUILTIN_RULESETS {
        load_builtin(name).unwrap_or_else(|e| panic!("load_builtin({name:?}) should succeed: {e}"));

        let prefixed = format!("chio:{name}");
        load_builtin(&prefixed)
            .unwrap_or_else(|e| panic!("load_builtin({prefixed:?}) should succeed: {e}"));

        let hush_prefixed = format!("hushspec:{name}");
        load_builtin(&hush_prefixed)
            .unwrap_or_else(|e| panic!("load_builtin({hush_prefixed:?}) should succeed: {e}"));
    }
}

#[test]
fn load_builtin_rejects_unknown_names() {
    let err = match load_builtin("this-does-not-exist") {
        Ok(_) => panic!("should error"),
        Err(e) => e,
    };
    assert!(
        matches!(err, chio_policy::RulesetError::Unknown(ref n) if n == "this-does-not-exist"),
        "expected Unknown error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Per-ruleset shape assertions
//
// Each ruleset has characteristic behaviours the catalogue should preserve.
// These tests pin the behaviours we care about so an inadvertent edit to a
// YAML file is caught at test time rather than in production.
// ---------------------------------------------------------------------------

#[test]
fn default_ruleset_blocks_ssh_and_restricts_egress() {
    let compiled = load_builtin("default").expect("compile default");
    assert!(compiled.guard_names.contains(&"forbidden-path".to_string()));
    assert!(compiled
        .guard_names
        .contains(&"egress-allowlist".to_string()));
    // SSRF companion comes along for the ride.
    assert!(compiled
        .guard_names
        .contains(&"internal-network".to_string()));
}

#[test]
fn strict_ruleset_blocks_tools_by_default() {
    let compiled = load_builtin("strict").expect("compile strict");
    assert!(compiled.guard_names.contains(&"mcp-tool".to_string()));
    // Strict has no allowlist entries that translate to wildcard grants
    // beyond the explicit read-only set, so the scope should be finite.
    assert!(!compiled.default_scope.grants.is_empty());
    assert!(
        compiled
            .default_scope
            .grants
            .iter()
            .all(|g| g.tool_name != "*"),
        "strict ruleset should never emit wildcard tool grants"
    );
}

#[test]
fn permissive_ruleset_allows_all_tools() {
    let compiled = load_builtin("permissive").expect("compile permissive");
    // No tool_access block -> permissive scope falls back to wildcard.
    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(compiled.default_scope.grants[0].tool_name, "*");
}

#[test]
fn panic_ruleset_denies_everything() {
    let compiled = load_builtin("panic").expect("compile panic");
    // tool_access default=block with empty allow -> empty scope.
    assert!(compiled.default_scope.grants.is_empty());
    assert!(compiled.guard_names.contains(&"forbidden-path".to_string()));
    assert!(compiled.guard_names.contains(&"shell-command".to_string()));
    assert!(compiled.guard_names.contains(&"mcp-tool".to_string()));
}

#[test]
fn cicd_ruleset_compiles_with_tool_allowlist() {
    let compiled = load_builtin("cicd").expect("compile cicd");
    let allowed: Vec<&str> = compiled
        .default_scope
        .grants
        .iter()
        .map(|g| g.tool_name.as_str())
        .collect();
    assert!(allowed.contains(&"read_file"));
    assert!(allowed.contains(&"build"));
    assert!(allowed.contains(&"run_tests"));
}

#[test]
fn ai_agent_ruleset_adds_shell_command_patterns() {
    let compiled = load_builtin("ai-agent").expect("compile ai-agent");
    assert!(compiled.guard_names.contains(&"shell-command".to_string()));
    assert!(compiled.guard_names.contains(&"forbidden-path".to_string()));
}

#[test]
fn remote_desktop_ruleset_compiles_computer_use_blocks() {
    // The remote-desktop ruleset opts into computer_use,
    // remote_desktop_channels, and input_injection. All three now compile
    // to concrete guards on the pipeline.
    let compiled = load_builtin("remote-desktop").expect("compile remote-desktop");
    assert!(compiled.guard_names.contains(&"computer-use".to_string()));
    assert!(compiled
        .guard_names
        .contains(&"remote-desktop-side-channel".to_string()));
    assert!(compiled
        .guard_names
        .contains(&"input-injection-capability".to_string()));
}
