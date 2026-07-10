//! End-to-end test: `compile_policy(yaml)` emits a Vec of guards that
//! includes all 12 guard types.
//!
//! This exercises the HushSpec YAML -> `CompiledPolicy` path rather than
//! the Rust-struct path; the rust-struct path is covered by the module
//! tests in `crates/guards/chio-policy/src/compiler.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chio_policy::{compile_policy, HushSpec};

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A HushSpec policy that exercises every guard type the compiler knows how
/// to emit. The rule / extension blocks are deliberately minimal -- we only
/// need each block present and enabled; the specific patterns / thresholds
/// are not the subject of this test.
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
        "chio-policy-compile-test-{}-{}-{}.json",
        std::process::id(),
        TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos()
    ));
    std::fs::write(&path, sample_threat_intel_pattern_db()).expect("write pattern db");
    path
}

fn all_twelve_guards_yaml(pattern_db: &Path) -> String {
    format!(
        r#"
hushspec: "0.1.0"
name: all-guards-coverage
description: Exercises every guard type the compiler can emit.

rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/.ssh/**"
  path_allowlist:
    enabled: true
    read:
      - "/app/**"
    write:
      - "/app/tmp/**"
    patch:
      - "/app/**"
  shell_commands:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
  egress:
    enabled: true
    allow:
      - "api.example.com"
    default: block
  tool_access:
    enabled: true
    allow:
      - read_file
    block:
      - raw_file_write
    default: block
  secret_patterns:
    enabled: true
    patterns:
      - name: aws
        pattern: "AKIA[0-9A-Z]{{16}}"
        severity: critical
    skip_paths:
      - "**/tests/**"
  patch_integrity:
    enabled: true
    max_additions: 500
    max_deletions: 200

extensions:
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
      max_scan_bytes: 65536
    jailbreak:
      enabled: true
      block_threshold: 70
      warn_threshold: 30
      max_input_bytes: 200000
    threat_intel:
      enabled: true
      pattern_db: "{}"
      similarity_threshold: 0.8
      top_k: 1
  origins:
    default_behavior: deny
    profiles:
      - id: default
        budgets:
          tool_calls: 1000
"#,
        pattern_db.display()
    )
}

#[test]
fn compile_policy_emits_all_twelve_guard_types() {
    let pattern_db = write_temp_threat_intel_pattern_db();
    let spec = HushSpec::parse(&all_twelve_guards_yaml(&pattern_db)).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");

    let expected: HashSet<&'static str> = [
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

    let actual: HashSet<&str> = compiled.guard_names.iter().map(String::as_str).collect();

    let missing: Vec<&&str> = expected.difference(&actual).collect();
    assert!(
        missing.is_empty(),
        "missing guard types after compilation: {missing:?}; got {actual:?}"
    );
    assert_eq!(
        expected.len(),
        12,
        "the compiler emits 12 distinct guard types"
    );
    assert!(
        compiled.guards.len() >= 12,
        "guard pipeline should contain at least 12 guards, found {}",
        compiled.guards.len()
    );

    let _ = std::fs::remove_file(pattern_db);
}

#[test]
fn compile_policy_produces_vec_of_guards_accessible_via_pipeline() {
    // The GuardPipeline stores guards as `Vec<Box<dyn Guard>>` internally;
    // the sidecar `guard_names` list mirrors that vector's ordering and
    // size, so it stands in for the otherwise-private guard vector when
    // asserting that all 12 guard types are present.
    let pattern_db = write_temp_threat_intel_pattern_db();
    let spec = HushSpec::parse(&all_twelve_guards_yaml(&pattern_db)).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert_eq!(compiled.guards.len(), compiled.guard_names.len());
    let _ = std::fs::remove_file(pattern_db);
}

#[test]
fn compile_empty_policy_yields_empty_pipeline() {
    let yaml = r#"
hushspec: "0.1.0"
name: empty
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(compiled.guard_names.is_empty());
    assert!(compiled.guards.is_empty());
}

#[test]
fn compile_policy_emits_velocity_guard_from_velocity_rule() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  velocity:
    max_invocations_per_window: 40
    max_spend_per_window: 50000
    max_requests_per_agent: 20
    window_secs: 3600
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(
        compiled.guard_names.contains(&"velocity".to_string()),
        "expected velocity guard, got {:?}",
        compiled.guard_names
    );
    assert!(
        compiled.guard_names.contains(&"agent-velocity".to_string()),
        "expected agent-velocity guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn compile_policy_emits_require_approval_above_from_human_in_loop() {
    use chio_core::capability::scope::Constraint;

    let yaml = r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
    default: block
  human_in_loop:
    enabled: true
    approve_above: 15000
    approve_above_currency: "USD"
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    let grant = compiled
        .default_scope
        .grants
        .first()
        .expect("grant from tool_access allow");
    assert!(
        grant
            .constraints
            .iter()
            .any(|c| matches!(c, Constraint::RequireApprovalAbove { threshold_units: 15000 })),
        "expected RequireApprovalAbove {{ threshold_units: 15000 }} from human_in_loop.approve_above; got {:?}",
        grant.constraints
    );
}

#[test]
fn compile_policy_accepts_canonical_hushspec_fixture() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../examples/policies/canonical-hushspec.yaml");
    let yaml = std::fs::read_to_string(&fixture).expect("read canonical fixture");
    let spec = HushSpec::parse(&yaml).expect("parse canonical hushspec");
    let compiled = compile_policy(&spec).expect("compile canonical should succeed");
    // Canonical fixture exercises forbidden_paths, path_allowlist, shell,
    // tool_access, secret_patterns, patch_integrity. With no commented
    // velocity/human_in_loop stanzas active, compilation must still be
    // accepted (partial spec is valid).
    assert!(
        !compiled.guard_names.is_empty(),
        "canonical fixture should emit at least one guard"
    );
}

#[test]
fn compile_policy_emits_computer_use_guard_from_rule() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  computer_use:
    enabled: true
    mode: fail_closed
    allowed_actions:
      - remote.session.connect
      - input.inject
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(
        compiled.guard_names.contains(&"computer-use".to_string()),
        "expected computer-use guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn compile_policy_emits_remote_desktop_side_channel_guard_from_rule() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(
        compiled
            .guard_names
            .contains(&"remote-desktop-side-channel".to_string()),
        "expected remote-desktop-side-channel guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn compile_policy_emits_input_injection_capability_guard_from_rule() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  input_injection:
    enabled: true
    allowed_types:
      - keyboard
      - mouse
    require_postcondition_probe: true
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(
        compiled
            .guard_names
            .contains(&"input-injection-capability".to_string()),
        "expected input-injection-capability guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn compile_policy_emits_browser_automation_guard_from_rule() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  browser_automation:
    enabled: true
    allowed_domains:
      - "*.example.com"
    blocked_domains:
      - "evil.com"
    allowed_verbs:
      - navigate
      - screenshot
    credential_detection: true
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(
        compiled
            .guard_names
            .contains(&"browser-automation".to_string()),
        "expected browser-automation guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn compile_policy_emits_code_execution_guard_from_rule() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  code_execution:
    enabled: true
    language_allowlist:
      - python
    network_access: false
    max_execution_time_ms: 5000
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(
        compiled.guard_names.contains(&"code-execution".to_string()),
        "expected code-execution guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn disabled_detection_blocks_do_not_emit_guards() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: false
      block_at_or_above: high
    jailbreak:
      enabled: false
      block_threshold: 70
"#;
    let spec = HushSpec::parse(yaml).expect("parse hushspec");
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(!compiled
        .guard_names
        .contains(&"prompt-injection".to_string()));
    assert!(!compiled.guard_names.contains(&"jailbreak".to_string()));
}
