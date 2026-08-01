use super::detection::{jailbreak_config_from, prompt_level_to_score_threshold};
use super::rules::{
    compile_browser_automation_rule, compile_code_execution_rule, compile_computer_use_rule,
    compile_input_injection_rule, compile_output_sanitizer_config,
};
use super::*;
use crate::models::{DetectionLevel, HushSpec, JailbreakDetection};
use chio_core::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core::capability::scope::Constraint;
use chio_core::crypto::{Keypair, PublicKey};
use chio_guards::computer_use::EnforcementMode;
use chio_kernel::threshold_approval::{ApproverDirectory, ResolvedApproverIdentity};
use std::path::PathBuf;

struct TestApproverDirectory {
    entries: std::collections::BTreeMap<String, PublicKey>,
}

impl ApproverDirectory for TestApproverDirectory {
    fn resolve_approver(&self, identifier: &str) -> Result<ResolvedApproverIdentity, String> {
        let public_key = self
            .entries
            .get(identifier)
            .cloned()
            .ok_or_else(|| "unknown approver".to_string())?;
        Ok(ResolvedApproverIdentity {
            identifier: identifier.to_string(),
            public_key,
            directory_version: "directory-v7".to_string(),
        })
    }
}

fn threshold_policy(approvers: &str, timeout: &str) -> HushSpec {
    HushSpec::parse(&format!(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    human_in_loop:
      approvers:
        n: 2
        of: {approvers}
{timeout}
"#
    ))
    .unwrap()
}

fn test_approver_directory() -> TestApproverDirectory {
    TestApproverDirectory {
        entries: ["alice", "bob", "carol"]
            .into_iter()
            .map(|identifier| (identifier.to_string(), Keypair::generate().public_key()))
            .collect(),
    }
}

fn sample_threat_intel_pattern_db() -> &'static str {
    r#"
[
  {
    "id": "known-prompt-injection",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "Known malicious prompt embedding",
    "embedding": [1.0, 0.0, 0.0]
  }
]
"#
}

fn write_temp_threat_intel_pattern_db() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "chio-policy-threat-intel-{}.json",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, sample_threat_intel_pattern_db()).unwrap();
    path
}

#[test]
fn compile_empty_policy() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: empty
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guards.len(), 0);
    assert!(compiled.guard_names.is_empty());
    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(compiled.default_scope.grants[0].tool_name, "*");
}

#[test]
fn threshold_approval_requires_an_authenticated_directory() {
    let spec = threshold_policy("[\"alice\", \"bob\"]", "");
    let error = compile_policy(&spec).err().expect("directory is required");
    assert!(error
        .to_string()
        .contains("authenticated approver directory"));
}

#[test]
fn threshold_approval_compiles_canonical_identity_set() {
    let directory = test_approver_directory();
    let first = compile_policy_with_approver_directory(
        &threshold_policy("[\"carol\", \"alice\", \"bob\"]", ""),
        &directory,
    )
    .unwrap()
    .threshold_approval
    .expect("threshold requirement");
    let reordered = compile_policy_with_approver_directory(
        &threshold_policy("[\"bob\", \"carol\", \"alice\"]", ""),
        &directory,
    )
    .unwrap()
    .threshold_approval
    .expect("reordered threshold requirement");

    assert_eq!(first.eligible_set_digest, reordered.eligible_set_digest);
    assert_eq!(first.timeout_seconds, 900);
    assert_eq!(first.directory_version, "directory-v7");
    first.validate().unwrap();
}

#[test]
fn threshold_approval_rejects_invalid_quorum_and_timeout() {
    let directory = test_approver_directory();
    let invalid_quorum = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    human_in_loop:
      approvers:
        n: 3
        of: ["alice", "bob"]
"#,
    )
    .unwrap();
    assert!(compile_policy_with_approver_directory(&invalid_quorum, &directory).is_err());
    let invalid_timeout = threshold_policy("[\"alice\", \"bob\"]", "        timeout_seconds: 3601");
    assert!(compile_policy_with_approver_directory(&invalid_timeout, &directory).is_err());
}

#[test]
fn compile_rejects_validation_errors_before_materializing_policy() {
    let spec = HushSpec::parse(
        r#"
hushspec: "9.9.9"
rules:
  tool_access:
    enabled: true
    allow: [read_file]
    default: block
    max_args_size: 0
"#,
    )
    .unwrap();

    let error = match compile_policy(&spec) {
        Ok(_) => panic!("invalid policy should fail compilation"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("HushSpec validation failed"),
        "unexpected error: {error}"
    );
    assert!(
        message.contains("unsupported hushspec version"),
        "unexpected error: {error}"
    );
    assert!(
        message.contains("rules.tool_access.max_args_size must be >= 1"),
        "unexpected error: {error}"
    );
}

#[test]
fn compile_forbidden_paths_guard() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
      - "**/.env"
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guards.len(), 1);
    assert_eq!(compiled.guard_names, vec!["forbidden-path".to_string()]);
}

#[test]
fn compile_egress_adds_internal_network_companion() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  egress:
    enabled: true
    allow: ["*.github.com"]
    default: block
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guards.len(), 2);
    assert_eq!(
        compiled.guard_names,
        vec![
            "egress-allowlist".to_string(),
            "internal-network".to_string()
        ]
    );
}

#[test]
fn compile_egress_rejects_invalid_globs() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  egress:
    enabled: true
    allow: ["["]
"#,
    )
    .unwrap();

    let error = match compile_policy(&spec) {
        Ok(_) => panic!("invalid egress patterns should fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("invalid egress allowlist pattern"),
        "unexpected error: {error}"
    );
}

#[test]
fn compile_computer_use_preserves_empty_allowed_actions() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions: []
"#,
    )
    .unwrap();
    let rule = spec.rules.as_ref().unwrap().computer_use.as_ref().unwrap();
    let config = compile_computer_use_rule(rule);
    assert!(config.allowed_action_types.is_empty());
    assert_eq!(config.mode, EnforcementMode::FailClosed);
}

#[test]
fn compile_input_injection_preserves_empty_allowed_types() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  input_injection:
    enabled: true
    allowed_types: []
"#,
    )
    .unwrap();
    let rule = spec
        .rules
        .as_ref()
        .unwrap()
        .input_injection
        .as_ref()
        .unwrap();
    let config = compile_input_injection_rule(rule);
    assert!(config.allowed_input_types.is_empty());
}

#[test]
fn compile_browser_automation_preserves_empty_allowed_verbs() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    allowed_verbs: []
"#,
    )
    .unwrap();
    let rule = spec
        .rules
        .as_ref()
        .unwrap()
        .browser_automation
        .as_ref()
        .unwrap();
    let config = compile_browser_automation_rule(rule);
    assert!(config.allowed_verbs.is_empty());
}

#[test]
fn compile_code_execution_preserves_empty_module_denylist() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    module_denylist: []
"#,
    )
    .unwrap();
    let rule = spec
        .rules
        .as_ref()
        .unwrap()
        .code_execution
        .as_ref()
        .unwrap();
    let config = compile_code_execution_rule(rule);
    assert!(config.module_denylist.is_empty());
}

#[test]
fn compile_patch_integrity_rejects_invalid_regex() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  patch_integrity:
    enabled: true
    forbidden_patterns: ["["]
"#,
    )
    .unwrap();

    let error = match compile_policy(&spec) {
        Ok(_) => panic!("invalid patch integrity regex should fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("rules.patch_integrity.forbidden_patterns[0]"),
        "unexpected error: {error}"
    );
}

#[test]
fn compile_secret_patterns_use_post_invocation_sanitizer_only() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guards.len(), 1);
    assert_eq!(compiled.post_invocation.len(), 1);
    assert_eq!(compiled.guard_names, vec!["secret-leak".to_string()]);
    let outcome = compiled.post_invocation.evaluate_with_evidence(
        "read_file",
        &serde_json::json!({
            "access_key": "AKIA1234567890ABCDEF"
        }),
    );
    assert!(matches!(
        outcome.verdict,
        chio_kernel::PostInvocationVerdict::Redact(_)
    ));
}

#[test]
fn compile_secret_patterns_preserves_custom_denylist_patterns() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: internal-token
        pattern: "INTERNAL-[0-9]{4}"
        severity: critical
"#,
    )
    .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));
    let rule = spec
        .rules
        .as_ref()
        .unwrap_or_else(|| unreachable!("test policy should contain rules"))
        .secret_patterns
        .as_ref()
        .unwrap_or_else(|| unreachable!("test policy should contain secret patterns"));

    let config = compile_output_sanitizer_config(rule);

    assert_eq!(config.denylist.patterns, vec!["INTERNAL-[0-9]{4}"]);
}

#[test]
fn compile_detection_prompt_injection_adds_guard() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
      max_scan_bytes: 100000
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guard_names, vec!["prompt-injection".to_string()]);
}

#[test]
fn compile_detection_jailbreak_adds_guard() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      enabled: true
      block_threshold: 70
      warn_threshold: 30
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guard_names, vec!["jailbreak".to_string()]);
}

#[test]
fn compile_detection_threat_intel_adds_guard() {
    let pattern_db = write_temp_threat_intel_pattern_db();
    let spec = HushSpec::parse(&format!(
        r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "{}"
      similarity_threshold: 0.8
      top_k: 1
"#,
        pattern_db.display()
    ))
    .unwrap();

    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guard_names, vec!["embedding-anomaly".to_string()]);

    let _ = std::fs::remove_file(pattern_db);
}

#[test]
fn compile_detection_threat_intel_resolves_relative_pattern_db_against_source() {
    let policy_dir = std::env::temp_dir().join(format!(
        "chio-policy-threat-intel-dir-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&policy_dir).unwrap();
    let pattern_db = policy_dir.join("pattern-db.json");
    std::fs::write(&pattern_db, sample_threat_intel_pattern_db()).unwrap();
    let policy_path = policy_dir.join("policy.yaml");
    std::fs::write(&policy_path, "hushspec: \"0.1.0\"\n").unwrap();

    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "pattern-db.json"
      similarity_threshold: 0.8
      top_k: 1
"#,
    )
    .unwrap();

    let compiled = compile_policy_with_source(&spec, Some(&policy_path)).unwrap();
    assert_eq!(compiled.guard_names, vec!["embedding-anomaly".to_string()]);

    let _ = std::fs::remove_file(pattern_db);
    let _ = std::fs::remove_file(policy_path);
    let _ = std::fs::remove_dir(policy_dir);
}

#[test]
fn compile_origin_budget_adds_agent_velocity() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: default
        budgets:
          tool_calls: 120
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guard_names, vec!["agent-velocity".to_string()]);
}

#[test]
fn compile_all_12_guard_types() {
    let pattern_db = write_temp_threat_intel_pattern_db();
    let spec = HushSpec::parse(&format!(
        r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/.ssh/**"]
  path_allowlist:
    enabled: true
    read: ["/app/**"]
  shell_commands:
    enabled: true
    forbidden_patterns: ["rm -rf /"]
  egress:
    enabled: true
    allow: ["*.example.com"]
    default: block
  tool_access:
    enabled: true
    allow: [read_file]
    default: block
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{{16}}"
        severity: critical
  patch_integrity:
    enabled: true
extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 70
    threat_intel:
      enabled: true
      pattern_db: "{}"
      similarity_threshold: 0.8
      top_k: 1
  origins:
    profiles:
      - id: default
        budgets:
          tool_calls: 1000
"#,
        pattern_db.display()
    ))
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    let expected: std::collections::HashSet<&str> = [
        "forbidden-path",
        "shell-command",
        "egress-allowlist",
        "internal-network",
        "mcp-tool",
        "secret-leak",
        "patch-integrity",
        "path-allowlist",
        "prompt-injection",
        "jailbreak",
        "embedding-anomaly",
        "agent-velocity",
    ]
    .into_iter()
    .collect();

    let actual: std::collections::HashSet<&str> =
        compiled.guard_names.iter().map(String::as_str).collect();

    assert_eq!(
        actual, expected,
        "all 12 guard types should compile; got {actual:?}"
    );
    assert_eq!(compiled.guards.len(), 12);

    let _ = std::fs::remove_file(pattern_db);
}

#[test]
fn compile_disabled_guards_excluded() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: false
  shell_commands:
    enabled: false
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.guards.len(), 0);
}

#[test]
fn compile_tool_access_scope() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [read_file, write_file, shell_exec]
    default: block
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.default_scope.grants.len(), 3);
    assert_eq!(compiled.default_scope.grants[0].tool_name, "read_file");
    assert_eq!(compiled.default_scope.grants[1].tool_name, "write_file");
    assert_eq!(compiled.default_scope.grants[2].tool_name, "shell_exec");
}

#[test]
fn compile_tool_access_scope_omits_only_allow_entries_overlapping_block() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [read_file, shell_exec]
    block: [shell_exec]
    default: block
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(compiled.default_scope.grants[0].tool_name, "read_file");
}

#[test]
fn compile_tool_access_scope_preserves_representable_security_constraints() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [write_file]
    require_confirmation: [write_*]
    max_args_size: 2048
    default: block
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(
        compiled.default_scope.grants[0].constraints,
        vec![
            Constraint::MaxArgsSize(2048),
            Constraint::RequireApprovalAbove { threshold_units: 0 }
        ]
    );
}

#[test]
fn compile_tool_access_default_allow_selective_confirmation_fails_closed() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    require_confirmation: [git_push]
    default: allow
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    assert!(compiled.default_scope.grants.is_empty());
}

#[test]
fn compile_tool_access_default_allow_global_confirmation_emits_constrained_wildcard() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    require_confirmation: ["*"]
    default: allow
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    assert_eq!(compiled.default_scope.grants.len(), 1);
    let grant = &compiled.default_scope.grants[0];
    assert_eq!(grant.server_id, "*");
    assert_eq!(grant.tool_name, "*");
    assert_eq!(
        grant.constraints,
        vec![Constraint::RequireApprovalAbove { threshold_units: 0 }]
    );
}

#[test]
fn compile_tool_access_default_allow_max_args_size_emits_constrained_wildcard() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    max_args_size: 2048
    default: allow
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    assert_eq!(compiled.default_scope.grants.len(), 1);
    let grant = &compiled.default_scope.grants[0];
    assert_eq!(grant.server_id, "*");
    assert_eq!(grant.tool_name, "*");
    assert_eq!(grant.constraints, vec![Constraint::MaxArgsSize(2048)]);
}

#[test]
fn compile_tool_access_default_allow_max_args_size_with_selective_confirmation_fails_closed() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    max_args_size: 2048
    require_confirmation: [git_push]
    default: allow
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    assert!(compiled.default_scope.grants.is_empty());
}

#[test]
fn compile_tool_access_default_allow_runtime_assurance_emits_constrained_wildcard() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    require_runtime_assurance_tier: attested
    default: allow
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    assert_eq!(compiled.default_scope.grants.len(), 1);
    let grant = &compiled.default_scope.grants[0];
    assert_eq!(grant.server_id, "*");
    assert_eq!(grant.tool_name, "*");
    assert_eq!(
        grant.constraints,
        vec![Constraint::MinimumRuntimeAssurance(
            RuntimeAssuranceTier::Attested
        )]
    );
}

#[test]
fn compile_tool_access_default_allow_runtime_assurance_preference_stays_warning_only() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    prefer_runtime_assurance_tier: attested
    default: allow
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    assert_eq!(compiled.default_scope.grants.len(), 1);
    let grant = &compiled.default_scope.grants[0];
    assert_eq!(grant.server_id, "*");
    assert_eq!(grant.tool_name, "*");
    assert!(grant.constraints.is_empty());
}

#[test]
fn compile_tool_access_allow_runtime_assurance_preference_does_not_harden_grant() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [payments.charge]
    prefer_runtime_assurance_tier: attested
    default: block
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();

    assert_eq!(compiled.default_scope.grants.len(), 1);
    let grant = &compiled.default_scope.grants[0];
    assert_eq!(grant.server_id, "*");
    assert_eq!(grant.tool_name, "payments.charge");
    assert!(grant.constraints.is_empty());
}

#[test]
fn exact_confirmation_patterns_do_not_overlap_different_tools() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [payments.charge]
    default: block
  human_in_loop:
    enabled: true
    require_confirmation: [payments.refund]
    approve_above: 15000
"#,
    )
    .unwrap_or_else(|error| unreachable!("test policy should parse: {error}"));
    let compiled =
        compile_policy(&spec).unwrap_or_else(|error| unreachable!("compile should pass: {error}"));

    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(
        compiled.default_scope.grants[0].constraints,
        vec![Constraint::RequireApprovalAbove {
            threshold_units: 15000
        }]
    );
}

#[test]
fn compile_tool_access_rejects_oversized_confirmation_globs() {
    let oversized_glob = "*".repeat(600_000);
    let spec = HushSpec::parse(&format!(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: [read_file]
    require_confirmation: ["{oversized_glob}"]
    default: block
"#
    ))
    .unwrap();

    let error = match compile_policy(&spec) {
        Ok(_) => panic!("expected oversized glob to fail compilation"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CompileError::Invalid(ref message) if message.contains("invalid policy glob pattern")),
        "unexpected compile error: {error:?}"
    );
}

#[test]
fn compile_tool_access_default_allow_with_security_overrides_fails_closed() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    block: [shell_exec]
    require_confirmation: [git_push]
    max_args_size: 2048
    default: allow
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert!(compiled.default_scope.grants.is_empty());
}

#[test]
fn compile_block_default_empty_allow_produces_empty_scope() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
"#,
    )
    .unwrap();
    let compiled = compile_policy(&spec).unwrap();
    assert!(compiled.default_scope.grants.is_empty());
}

#[test]
fn prompt_level_ordering() {
    assert!(
        prompt_level_to_score_threshold(DetectionLevel::Safe)
            < prompt_level_to_score_threshold(DetectionLevel::Suspicious)
    );
    assert!(
        prompt_level_to_score_threshold(DetectionLevel::Suspicious)
            < prompt_level_to_score_threshold(DetectionLevel::High)
    );
    assert!(
        prompt_level_to_score_threshold(DetectionLevel::High)
            <= prompt_level_to_score_threshold(DetectionLevel::Critical)
    );
}

#[test]
fn jailbreak_block_threshold_maps_to_zero_one() {
    let jb = JailbreakDetection {
        enabled: Some(true),
        block_threshold: Some(70),
        warn_threshold: Some(30),
        max_input_bytes: Some(100_000),
    };
    let cfg = jailbreak_config_from(&jb).unwrap();
    assert!((cfg.threshold - 0.70).abs() < f32::EPSILON);
    assert_eq!(cfg.detector.max_scan_bytes, 100_000);
}

#[test]
fn jailbreak_oversize_threshold_clamped() {
    let jb = JailbreakDetection {
        enabled: Some(true),
        block_threshold: Some(200),
        warn_threshold: None,
        max_input_bytes: None,
    };
    let cfg = jailbreak_config_from(&jb).unwrap();
    assert!(cfg.threshold <= 1.0 + f32::EPSILON);
}
