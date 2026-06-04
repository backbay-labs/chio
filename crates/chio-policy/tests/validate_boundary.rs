#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_policy::{compile_policy, validate, HushSpec, ValidationResult};

fn parse_policy(yaml: &str) -> HushSpec {
    match HushSpec::parse(yaml) {
        Ok(spec) => spec,
        Err(error) => panic!("test policy should parse: {error}"),
    }
}

fn assert_error_contains(result: &ValidationResult, needle: &str) {
    assert!(
        result
            .errors
            .iter()
            .any(|error| error.to_string().contains(needle)),
        "expected validation error containing {needle:?}, got {:?}",
        result.errors
    );
}

fn assert_warning_contains(result: &ValidationResult, needle: &str) {
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains(needle)),
        "expected validation warning containing {needle:?}, got {:?}",
        result.warnings
    );
}

#[test]
fn tool_access_zero_sized_argument_budget_is_invalid() {
    let spec = parse_policy(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["files.read"]
    default: block
    max_args_size: 0
"#,
    );
    let result = validate(&spec);

    assert_error_contains(&result, "rules.tool_access.max_args_size must be >= 1");
}

#[test]
fn empty_secret_pattern_fields_fail_validation() {
    let spec = parse_policy(
        r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: ""
        pattern: ""
        severity: critical
"#,
    );
    let result = validate(&spec);

    assert_error_contains(
        &result,
        "rules.secret_patterns.patterns[0].name must not be empty",
    );
    assert_error_contains(
        &result,
        "rules.secret_patterns.patterns[0].pattern cannot be empty",
    );
}

#[test]
fn compile_policy_rejects_empty_secret_pattern_name_before_guard_materialization() {
    let spec = parse_policy(
        r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    enabled: true
    patterns:
      - name: "   "
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
"#,
    );

    let error = match compile_policy(&spec) {
        Ok(compiled) => panic!(
            "empty secret pattern should fail before compiling guards: {:?}",
            compiled.guard_names
        ),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("HushSpec validation failed"),
        "expected validation compile error, got {message:?}"
    );
    assert!(
        message.contains("rules.secret_patterns.patterns[0].name must not be empty"),
        "expected empty name validation message, got {message:?}"
    );
}

#[test]
fn posture_validation_rejects_missing_timeout_duration_and_negative_budgets() {
    let spec = parse_policy(
        r#"
hushspec: "0.1.0"
extensions:
  posture:
    initial: missing_initial
    states:
      draft:
        capabilities: ["tool_call", "unknown"]
        budgets:
          tool_calls: -1
          shadow_budget: 4
      review:
        capabilities: ["tool_call"]
    transitions:
      - from: draft
        to: review
        on: timeout
      - from: missing
        to: review
        on: critical_violation
"#,
    );
    let result = validate(&spec);

    assert_error_contains(
        &result,
        "posture.initial 'missing_initial' does not reference a defined state",
    );
    assert_error_contains(
        &result,
        "posture.states.draft.budgets.tool_calls must be non-negative, got -1",
    );
    assert_error_contains(
        &result,
        "posture.transitions[0]: timeout trigger requires 'after' field",
    );
    assert_error_contains(
        &result,
        "posture.transitions[1].from 'missing' does not reference a defined state",
    );
    assert_warning_contains(
        &result,
        "posture.states.draft.capabilities includes unknown capability 'unknown'",
    );
    assert_warning_contains(
        &result,
        "posture.states.draft.budgets uses unknown budget key 'shadow_budget'",
    );
}

#[test]
fn detection_threshold_boundaries_are_inclusive() {
    let valid = parse_policy(
        r#"
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 100
      warn_threshold: 0
      max_input_bytes: 1
    threat_intel:
      enabled: false
      similarity_threshold: 1.0
      top_k: 1
"#,
    );
    assert!(
        validate(&valid).errors.is_empty(),
        "inclusive detection boundaries should validate"
    );

    let invalid = parse_policy(
        r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      max_scan_bytes: 0
    jailbreak:
      block_threshold: 101
      warn_threshold: 101
      max_input_bytes: 0
    threat_intel:
      enabled: true
      similarity_threshold: 1.01
      top_k: 0
"#,
    );
    let result = validate(&invalid);

    assert_error_contains(
        &result,
        "detection.prompt_injection.max_scan_bytes must be >= 1",
    );
    assert_error_contains(
        &result,
        "detection.jailbreak.block_threshold must be between 0 and 100",
    );
    assert_error_contains(
        &result,
        "detection.jailbreak.warn_threshold must be between 0 and 100",
    );
    assert_error_contains(&result, "detection.jailbreak.max_input_bytes must be >= 1");
    assert_error_contains(
        &result,
        "detection.threat_intel.pattern_db is required when enabled",
    );
    assert_error_contains(
        &result,
        "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0",
    );
    assert_error_contains(&result, "detection.threat_intel.top_k must be >= 1");
}
