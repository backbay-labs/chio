use super::guards::{validate_https_url, SAFE_BROWSING_DEFAULT_BASE_URL};
use super::issuance::materialize_runtime_assurance_policy;
use super::tool_access::{tool_patterns_overlap, MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES};
use super::types::default_max_capability_ttl;
use super::util::runtime_hash_for_chio_yaml;
use super::*;
use chio_core::capability::{
    runtime_attestation::RuntimeAssuranceTier,
    scope::{ChioScope, MonetaryAmount, Operation},
};
use chio_test_support::prelude::*;
use std::net::IpAddr;
use std::path::PathBuf;

const EXAMPLE_POLICY: &str = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5

guards:
  forbidden_path:
    enabled: true
    additional_patterns:
      - "/custom/secret/*"
  path_allowlist:
    enabled: true
    read:
      - "/workspace/project/**"
    write:
      - "/workspace/project/**"
  shell_command:
    enabled: true
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.github.com"
      - "*.openai.com"
      - "api.anthropic.com"
  internal_network:
    enabled: true

capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;

const FULL_GUARD_POLICY: &str = r#"
kernel:
  max_capability_ttl: 3600

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/workspace/secret/**"
    exceptions:
      - "/workspace/secret/allowed.txt"
  path_allowlist:
    enabled: true
    read:
      - "/workspace/**"
    write:
      - "/workspace/**"
    patch:
      - "/workspace/**"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.openai.com"
    blocked_domains:
      - "evil.example"
  internal_network:
    enabled: true
    extra_blocked_hosts:
      - "internal.corp.example.com"
    dns_rebinding_detection: true
  tool_access:
    enabled: true
    default_action: block
    allow:
      - read_file
      - bash
    max_args_size: 2048
  secret_patterns:
    enabled: true
    skip_paths:
      - "**/fixtures/**"
  patch_integrity:
    enabled: true
    max_additions: 200
    max_deletions: 100
    forbidden_patterns:
      - "eval\\("
    require_balance: true
    max_imbalance_ratio: 3.0
"#;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../examples/policies")
        .join(name)
}

fn sample_threat_intel_pattern_db(label: &str) -> String {
    format!(
        r#"
[
  {{
    "id": "known-prompt-injection",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "{label}",
    "embedding": [1.0, 0.0, 0.0]
  }}
]
"#
    )
}

#[test]
fn parse_example_policy() {
    let policy = parse_policy(EXAMPLE_POLICY).test_unwrap();
    assert_eq!(policy.kernel.max_capability_ttl, 3600);
    assert_eq!(policy.kernel.delegation_depth_limit, 5);
    assert!(!policy.kernel.allow_sampling);
    assert!(!policy.kernel.allow_sampling_tool_use);
    assert!(!policy.kernel.allow_elicitation);
    assert!(!policy.kernel.require_web3_evidence);
    assert_eq!(
        policy.kernel.durable_admission_mode,
        chio_kernel::admission_operation::DurableAdmissionMode::SideEffecting
    );
    assert_eq!(
        policy.kernel.checkpoint_batch_size,
        chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE
    );
    assert!(policy.guards.forbidden_path.is_some());
    assert!(policy.guards.path_allowlist.is_some());
    assert!(policy.guards.shell_command.is_some());
    assert!(policy.guards.egress_allowlist.is_some());
    assert!(policy.guards.internal_network.is_some());
}

#[test]
fn parse_policy_web3_evidence_gate_fields() {
    let yaml = r#"
kernel:
  require_web3_evidence: true
  checkpoint_batch_size: 32
"#;

    let policy = parse_policy(yaml).test_unwrap();
    assert!(policy.kernel.require_web3_evidence);
    assert_eq!(policy.kernel.checkpoint_batch_size, 32);
}

#[test]
fn durable_admission_policy_supports_qualification_modes_and_rejects_unsafe_off() {
    use chio_kernel::admission_operation::DurableAdmissionMode;

    let monetary = parse_policy(
        r#"
kernel:
  durable_admission_mode: monetary
"#,
    )
    .test_unwrap();
    assert_eq!(
        monetary.kernel.durable_admission_mode,
        DurableAdmissionMode::Monetary
    );

    for yaml in [
        r#"
kernel:
  durable_admission_mode: off
"#,
        r#"
kernel:
  durable_admission_mode: off
  allow_unsafe_durable_admission_off: true
"#,
        r#"
kernel:
  allow_ephemeral_receipt_log: true
  allow_unsafe_durable_admission_off: true
"#,
    ] {
        assert!(parse_policy(yaml).is_err());
    }

    let off = parse_policy(
        r#"
kernel:
  durable_admission_mode: off
  allow_ephemeral_receipt_log: true
  allow_unsafe_durable_admission_off: true
"#,
    )
    .test_unwrap();
    assert_eq!(off.kernel.durable_admission_mode, DurableAdmissionMode::Off);
}

#[test]
fn build_pipeline_from_policy() {
    let policy = parse_policy(EXAMPLE_POLICY).test_unwrap();
    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 5);
}

#[test]
fn parse_full_guard_policy() {
    let policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
    assert!(policy.guards.forbidden_path.is_some());
    assert!(policy.guards.path_allowlist.is_some());
    assert!(policy.guards.shell_command.is_some());
    assert!(policy.guards.egress_allowlist.is_some());
    assert!(policy.guards.internal_network.is_some());
    assert!(policy.guards.tool_access.is_some());
    assert!(policy.guards.secret_patterns.is_some());
    assert!(policy.guards.patch_integrity.is_some());
}

#[test]
fn build_pipeline_from_full_guard_policy() {
    let policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 8);
}

#[test]
fn build_pipeline_rejects_invalid_egress_patterns() {
    let policy = parse_policy(
        r#"
guards:
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "["
"#,
    )
    .test_unwrap();

    let error = match build_guard_pipeline(&policy.guards) {
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
fn build_pipeline_rejects_invalid_patch_patterns() {
    let policy = parse_policy(
        r#"
guards:
  patch_integrity:
    enabled: true
    forbidden_patterns:
      - "["
"#,
    )
    .test_unwrap();

    let error = match build_guard_pipeline(&policy.guards) {
        Ok(_) => panic!("invalid patch integrity patterns should fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("invalid patch integrity forbidden pattern"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_pipeline_rejects_invalid_shell_command_patterns() {
    let policy = parse_policy(
        r#"
guards:
  shell_command:
    enabled: true
    forbidden_patterns:
      - "["
"#,
    )
    .test_unwrap();

    let error = match build_guard_pipeline(&policy.guards) {
        Ok(_) => panic!("invalid shell command patterns should fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("invalid shell-command forbidden pattern"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_post_invocation_pipeline_from_secret_patterns() {
    let policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
    let pipeline = build_post_invocation_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 1);
}

#[test]
fn build_pipeline_from_data_guard_policy() {
    let policy = parse_policy(
        r#"
guards:
  sql_query:
    operation_allowlist: [select]
    table_allowlist: [orders]
  vector_db:
    collection_allowlist: [memories]
  warehouse_cost:
    max_bytes_scanned: 1000
  query_result:
    redact_pii_patterns:
      - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
"#,
    )
    .test_unwrap();

    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    let post_invocation = build_post_invocation_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 3);
    assert_eq!(post_invocation.len(), 1);
}

#[test]
fn build_pipeline_from_content_review_policy() {
    let policy = parse_policy(
        r#"
guards:
  content_review:
    enabled: true
    default_rules:
      banned_words:
        - "classified"
"#,
    )
    .test_unwrap();

    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 1);
}

#[test]
fn build_pipeline_from_external_guard_policy() {
    let policy = parse_policy(
        r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "https://example.cognitiveservices.azure.com"
      api_key: "azure-key"
      tool_patterns: ["slack_*"]
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "https://safebrowsing.googleapis.com/v4"
      tool_patterns: ["fetch_url"]
"#,
    )
    .test_unwrap();

    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 2);
}

#[test]
fn build_pipeline_validates_safe_browsing_default_base_url() {
    chio_external_guards::validate_external_guard_url_without_dns(
        "threat_intel.safe_browsing.base_url",
        SAFE_BROWSING_DEFAULT_BASE_URL,
    )
    .test_expect("default safe browsing base URL should pass external guard validation");

    let policy = parse_policy(
        r#"
guards:
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
"#,
    )
    .test_unwrap();

    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 1);
}

#[test]
fn build_pipeline_rejects_invalid_external_guard_config() {
    let policy = parse_policy(
        r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "not-a-url"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: ""
"#,
    )
    .test_unwrap();

    let error = match build_guard_pipeline(&policy.guards) {
        Ok(_) => panic!("invalid external guard config should fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("cloud_guardrails.azure_content_safety.endpoint must be a valid URL"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_pipeline_rejects_insecure_external_guard_urls() {
    let policy = parse_policy(
        r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "http://example.cognitiveservices.azure.com"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "http://safebrowsing.googleapis.com/v4"
"#,
    )
    .test_unwrap();

    let error = match build_guard_pipeline(&policy.guards) {
        Ok(_) => panic!("insecure external guard config should fail"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains(
            "cloud_guardrails.azure_content_safety.endpoint must use https or localhost-only http"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn build_pipeline_allows_localhost_http_external_guard_urls() {
    let policy = parse_policy(
        r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "http://127.0.0.1:8080"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "http://localhost:9000/v4"
"#,
    )
    .test_unwrap();

    build_guard_pipeline(&policy.guards)
        .test_expect("localhost-only http endpoints should remain allowed for local testing");
}

#[test]
fn build_pipeline_rejects_private_network_external_guard_urls_even_over_https() {
    let policy = parse_policy(
        r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "https://169.254.169.254/content-safety"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "https://192.168.1.10/v4"
"#,
    )
    .test_unwrap();

    let error = build_guard_pipeline(&policy.guards)
        .err()
        .test_expect("private-network external guard URLs should fail closed");
    assert!(
        error
            .to_string()
            .contains("must not target localhost, link-local, or private-network hosts"),
        "unexpected error: {error}"
    );
}

#[test]
fn external_guard_dns_resolution_rejects_rebound_private_addresses() {
    let error = chio_external_guards::validate_external_guard_url_with_resolver(
        "cloud_guardrails.azure_content_safety.endpoint",
        "https://guard.example.test/moderate",
        |_host, _port| Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 8))]),
    )
    .test_expect_err("private DNS answers should fail closed");

    assert!(
        error.to_string().contains("resolved to disallowed address"),
        "unexpected error: {error}"
    );
}

#[test]
fn external_guard_validation_rejects_ipv4_multicast_addresses() {
    let error = validate_https_url(
        "cloud_guardrails.azure_content_safety.endpoint",
        "https://224.0.0.1/moderate",
    )
    .test_expect_err("IPv4 multicast should fail closed");
    assert!(
        error
            .to_string()
            .contains("must not target localhost, link-local, or private-network hosts"),
        "unexpected error: {error}"
    );
}

#[test]
fn external_guard_validation_rejects_ipv4_mapped_ipv6_private_addresses() {
    for endpoint in [
        "https://[::ffff:169.254.169.254]/moderate",
        "https://[::ffff:10.0.0.1]/moderate",
    ] {
        let error = validate_https_url("cloud_guardrails.azure_content_safety.endpoint", endpoint)
            .test_expect_err("IPv4-mapped IPv6 private endpoint should fail closed");
        assert!(
            error
                .to_string()
                .contains("must not target localhost, link-local, or private-network hosts"),
            "unexpected error for {endpoint}: {error}"
        );
    }
}

#[test]
fn build_pipeline_rejects_dot_localhost_external_guard_urls() {
    let policy = parse_policy(
        r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "http://metadata.localhost:8080/moderate"
      api_key: "azure-key"
"#,
    )
    .test_unwrap();

    let error = build_guard_pipeline(&policy.guards)
        .err()
        .test_expect(".localhost endpoints should fail closed");
    assert!(
        error
            .to_string()
            .contains("must use https or localhost-only http")
            || error
                .to_string()
                .contains("must not target localhost, link-local, or private-network hosts"),
        "unexpected error: {error}"
    );
}

#[test]
fn query_result_policy_pipeline_redacts_wrapped_value_output() {
    let policy = parse_policy(
        r#"
guards:
  query_result:
    redact_pii_patterns:
      - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
"#,
    )
    .test_unwrap();

    let pipeline = build_post_invocation_pipeline(&policy.guards).test_unwrap();
    let context = chio_guards::post_invocation::PostInvocationContext::synthetic("sql");
    let outcome = pipeline.evaluate_with_context_and_evidence(
        &context,
        &serde_json::json!({
            "kind": "value",
            "value": {
                "rows": [
                    {"email": "alice@example.com"}
                ]
            }
        }),
    );

    match outcome.verdict {
        chio_kernel::PostInvocationVerdict::Redact(value) => {
            assert_eq!(value["value"]["rows"][0]["email"], "[REDACTED]");
        }
        other => panic!("expected Redact, got {other:?}"),
    }
}

#[test]
fn build_post_invocation_pipeline_rejects_excessive_redact_pii_patterns() {
    let patterns = (0..65)
        .map(|idx| format!("      - \"pattern-{idx}\"\n"))
        .collect::<String>();
    let policy = parse_policy(&format!(
        "guards:\n  query_result:\n    redact_pii_patterns:\n{patterns}"
    ))
    .test_unwrap();

    let error = build_post_invocation_pipeline(&policy.guards)
        .err()
        .test_expect("excessive PII pattern count should fail closed");
    assert!(
        error.to_string().contains("allows at most 64 patterns"),
        "unexpected error: {error}"
    );
}

#[test]
fn build_scope_from_policy() {
    let policy = parse_policy(EXAMPLE_POLICY).test_unwrap();
    let capabilities =
        build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
            .test_unwrap();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].scope.grants.len(), 1);
    assert_eq!(capabilities[0].scope.grants[0].server_id, "*");
    assert_eq!(capabilities[0].scope.grants[0].tool_name, "*");
    assert_eq!(capabilities[0].ttl, 300);
}

#[test]
fn build_scope_with_resources_and_prompts() {
    let yaml = r#"
kernel:
  max_capability_ttl: 3600
capabilities:
  default:
    resources:
      - uri: "repo://docs/*"
        operations: [read]
        ttl: 120
    prompts:
      - prompt: "summarize_*"
        operations: [get]
        ttl: 120
"#;

    let policy = parse_policy(yaml).test_unwrap();
    let capabilities =
        build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
            .test_unwrap();

    assert_eq!(capabilities.len(), 1);
    assert!(capabilities[0].scope.grants.is_empty());
    assert_eq!(capabilities[0].scope.resource_grants.len(), 1);
    assert_eq!(capabilities[0].scope.prompt_grants.len(), 1);
    assert_eq!(
        capabilities[0].scope.resource_grants[0].uri_pattern,
        "repo://docs/*"
    );
    assert_eq!(
        capabilities[0].scope.prompt_grants[0].prompt_name,
        "summarize_*"
    );
    assert_eq!(
        capabilities[0].scope.resource_grants[0].operations,
        vec![Operation::Read]
    );
    assert_eq!(
        capabilities[0].scope.prompt_grants[0].operations,
        vec![Operation::Get]
    );
    assert_eq!(capabilities[0].ttl, 120);
}

#[test]
fn yaml_tool_access_synthesizes_default_capabilities() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - read_file
      - list_directory
"#,
    )
    .test_unwrap();

    let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].ttl, 3600);
    assert_eq!(capabilities[0].scope.grants.len(), 2);
    assert_eq!(capabilities[0].scope.grants[0].tool_name, "read_file");
    assert_eq!(capabilities[0].scope.grants[1].tool_name, "list_directory");
}

#[test]
fn yaml_tool_access_synthesizes_security_constraints() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - write_file
      - read_file
    max_args_size: 2048
    require_confirmation:
      - write_*
"#,
    )
    .test_unwrap();

    let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(
        capabilities[0].scope.grants[0].constraints,
        vec![
            chio_core::capability::scope::Constraint::MaxArgsSize(2048),
            chio_core::capability::scope::Constraint::RequireApprovalAbove { threshold_units: 0 },
        ]
    );
    assert_eq!(
        capabilities[0].scope.grants[1].constraints,
        vec![chio_core::capability::scope::Constraint::MaxArgsSize(2048)]
    );
}

#[test]
fn yaml_tool_access_default_allow_with_scoped_confirmation_is_rejected() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: allow
    block:
      - shell_exec
    max_args_size: 2048
    require_confirmation:
      - git_push
"#,
    )
    .test_unwrap();

    let error = build_runtime_default_capabilities(&policy).test_expect_err(
        "scoped confirmation cannot be represented by a synthesized wildcard grant",
    );
    assert!(error.to_string().contains(
            "guards.tool_access.require_confirmation with default_action=allow requires either explicit allow entries or a wildcard '*' confirmation pattern"
        ));
}

#[test]
fn yaml_tool_access_default_allow_with_wildcard_confirmation_preserves_wildcard_capability() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: allow
    block:
      - shell_exec
    max_args_size: 2048
    require_confirmation:
      - "*"
"#,
    )
    .test_unwrap();

    let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].scope.grants.len(), 1);
    assert_eq!(capabilities[0].scope.grants[0].tool_name, "*");
    assert_eq!(
        capabilities[0].scope.grants[0].constraints,
        vec![
            chio_core::capability::scope::Constraint::MaxArgsSize(2048),
            chio_core::capability::scope::Constraint::RequireApprovalAbove { threshold_units: 0 },
        ]
    );
}

#[test]
fn yaml_tool_access_explicit_wildcard_allow_with_scoped_confirmation_is_rejected() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - "*"
    require_confirmation:
      - git_push
"#,
    )
    .test_unwrap();

    let error = build_runtime_default_capabilities(&policy)
        .test_expect_err("scoped confirmation cannot narrow an explicit wildcard allow grant");
    assert!(error.to_string().contains(
        "guards.tool_access.require_confirmation cannot narrow wildcard allow pattern '*'"
    ));
}

#[test]
fn yaml_tool_access_question_wildcard_allow_with_scoped_confirmation_is_rejected() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - db_?
    require_confirmation:
      - db_a
"#,
    )
    .test_unwrap();

    let error = build_runtime_default_capabilities(&policy)
        .test_expect_err("scoped confirmation cannot narrow a question-mark wildcard allow grant");
    assert!(error.to_string().contains(
        "guards.tool_access.require_confirmation cannot narrow wildcard allow pattern 'db_?'"
    ));
}

#[test]
fn yaml_tool_access_matching_wildcard_confirmation_preserves_explicit_wildcard_allow() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - git_*
    require_confirmation:
      - git_*
"#,
    )
    .test_unwrap();

    let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].scope.grants.len(), 1);
    assert_eq!(capabilities[0].scope.grants[0].tool_name, "git_*");
    assert_eq!(
        capabilities[0].scope.grants[0].constraints,
        vec![chio_core::capability::scope::Constraint::RequireApprovalAbove { threshold_units: 0 }]
    );
}

#[test]
fn wildcard_overlap_conservatively_rejects_ambiguous_leading_globs() {
    assert!(!tool_patterns_overlap("read_file", "*_write").test_unwrap());
    assert!(!tool_patterns_overlap("*_write", "git_push").test_unwrap());
    // Leading unbounded globs are intentionally treated as overlapping so
    // capability synthesis fails closed instead of under-confirming.
    assert!(tool_patterns_overlap("*_read", "*_write").test_unwrap());
    assert!(!tool_patterns_overlap("bb*", "?a").test_unwrap());
    assert!(tool_patterns_overlap("read_*", "*_read").test_unwrap());
}

#[test]
fn wildcard_overlap_rejects_oversized_patterns_before_recursing() {
    let oversized = "*".repeat(MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES + 1);
    let error = tool_patterns_overlap(&oversized, "read_file")
        .test_expect_err("oversized overlap pattern should fail policy loading");
    assert!(error.to_string().contains("glob pattern exceeds"));
}

#[test]
fn wildcard_overlap_rejects_excessive_recursive_state_budget() {
    let pattern = "a".repeat(200);
    let error = tool_patterns_overlap(&pattern, &pattern)
        .test_expect_err("large overlap state space should fail policy loading");
    assert!(error.to_string().contains("recursive states"));
}

#[test]
fn yaml_tool_access_rejects_leading_wildcard_confirmation_overlap() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - "*_read"
    require_confirmation:
      - "*_write"
"#,
    )
    .test_unwrap();

    let error = build_runtime_default_capabilities(&policy)
        .test_expect_err("leading wildcard confirmation overlap is unrepresentable");

    assert!(error
        .to_string()
        .contains("cannot narrow wildcard allow pattern '*_read'"));
}

#[test]
fn explicit_tool_capabilities_skip_tool_access_synthesis() {
    let policy = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: allow
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        ttl: 60
"#,
    )
    .test_unwrap();

    let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].ttl, 60);
    assert_eq!(capabilities[0].scope.grants.len(), 1);
    assert_eq!(capabilities[0].scope.grants[0].tool_name, "read_file");
}

#[test]
fn empty_policy_defaults() {
    let policy = parse_policy("{}").test_unwrap();
    assert_eq!(policy.kernel.max_capability_ttl, 3600);
    assert_eq!(policy.kernel.delegation_depth_limit, 5);
    assert!(!policy.kernel.allow_sampling);
    assert!(!policy.kernel.allow_sampling_tool_use);
    assert!(!policy.kernel.allow_elicitation);
    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 0);
}

#[test]
fn kernel_nested_flow_flags_parse() {
    let yaml = r#"
kernel:
  allow_sampling: true
  allow_sampling_tool_use: true
  allow_elicitation: true
"#;

    let policy = parse_policy(yaml).test_unwrap();
    assert!(policy.kernel.allow_sampling);
    assert!(policy.kernel.allow_sampling_tool_use);
    assert!(policy.kernel.allow_elicitation);
}

#[test]
fn disabled_guards_not_added() {
    let yaml = r#"
guards:
  forbidden_path:
    enabled: false
  path_allowlist:
    enabled: false
  shell_command:
    enabled: false
  egress_allowlist:
    enabled: false
  internal_network:
    enabled: false
"#;
    let policy = parse_policy(yaml).test_unwrap();
    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 0);
}

#[test]
fn internal_network_guard_requires_explicit_policy() {
    let without_egress = parse_policy(
        r#"
guards:
  shell_command:
    enabled: true
"#,
    )
    .test_unwrap();
    let without_egress_pipeline = build_guard_pipeline(&without_egress.guards).test_unwrap();
    assert_eq!(without_egress_pipeline.len(), 1);

    let with_egress = parse_policy(
        r#"
guards:
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.openai.com"
"#,
    )
    .test_unwrap();
    let with_egress_pipeline = build_guard_pipeline(&with_egress.guards).test_unwrap();
    assert_eq!(with_egress_pipeline.len(), 1);

    let with_internal_network = parse_policy(
        r#"
guards:
  internal_network:
    enabled: true
    extra_blocked_hosts:
      - "internal.corp.example.com"
    dns_rebinding_detection: false
"#,
    )
    .test_unwrap();
    let with_internal_network_pipeline =
        build_guard_pipeline(&with_internal_network.guards).test_unwrap();
    assert_eq!(with_internal_network_pipeline.len(), 1);
}

#[test]
fn policy_path_allowlist_guard_denies_out_of_root_session_tool() {
    use chio_kernel::Guard;

    let yaml = r#"
guards:
  path_allowlist:
    enabled: true
    read:
      - "**"
    write:
      - "**"
"#;
    let policy = parse_policy(yaml).test_unwrap();
    let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
    assert_eq!(pipeline.len(), 1);

    let kp = chio_core::crypto::Keypair::generate();
    let scope = ChioScope::default();
    let agent_id = kp.public_key().to_hex();
    let server_id = "filesystem".to_string();
    let cap_body = chio_core::capability::token::CapabilityTokenBody {
        id: "cap-test".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let cap = chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).test_unwrap();
    let request = chio_kernel::ToolCallRequest {
        request_id: "req-test".to_string(),
        capability: cap,
        tool_name: "filesystem".to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: serde_json::json!({"path": "/etc/passwd"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let session_roots = vec!["/workspace/project".to_string()];
    let ctx = chio_kernel::GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: Some(session_roots.as_slice()),
        matched_grant_index: None,
    };

    let result = pipeline.evaluate(&ctx).test_unwrap();
    assert_eq!(
        result.verdict,
        chio_kernel::Verdict::Deny,
        "out-of-root filesystem tool should deny"
    );
}

#[test]
fn minimal_capabilities() {
    let yaml = r#"
capabilities:
  default:
    tools:
      - server: "my-server"
        tool: "read_file"
        ttl: 600
"#;
    let policy = parse_policy(yaml).test_unwrap();
    let capabilities =
        build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
            .test_unwrap();
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].scope.grants.len(), 1);
    assert_eq!(capabilities[0].scope.grants[0].server_id, "my-server");
    assert_eq!(capabilities[0].scope.grants[0].tool_name, "read_file");
    assert_eq!(capabilities[0].ttl, 600);
}

#[test]
fn splits_default_capabilities_by_ttl() {
    let yaml = r#"
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        ttl: 60
      - server: "network"
        tool: "fetch"
        ttl: 3600
      - server: "filesystem"
        tool: "write_file"
        ttl: 60
"#;
    let policy = parse_policy(yaml).test_unwrap();
    let capabilities =
        build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
            .test_unwrap();

    assert_eq!(capabilities.len(), 2);
    assert_eq!(capabilities[0].ttl, 60);
    assert_eq!(capabilities[0].scope.grants.len(), 2);
    assert_eq!(capabilities[1].ttl, 3600);
    assert_eq!(capabilities[1].scope.grants.len(), 1);
}

#[test]
fn rejects_ttl_above_kernel_max() {
    let yaml = r#"
kernel:
  max_capability_ttl: 60
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        ttl: 300
"#;
    let policy = parse_policy(yaml).test_unwrap();
    let err = build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
        .test_unwrap_err();
    assert!(err
        .to_string()
        .contains("exceeds kernel max_capability_ttl"));
}

#[test]
fn rejects_unknown_operations() {
    let yaml = r#"
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        operations: [invoke, teleport]
        ttl: 60
"#;
    let policy = parse_policy(yaml).test_unwrap();
    let err = build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
        .test_unwrap_err();
    assert!(err.to_string().contains("unsupported capability operation"));
}

#[test]
fn runtime_hash_ignores_yaml_formatting_noise() {
    let policy_a = parse_policy(
        r#"
kernel:
  max_capability_ttl: 3600
guards:
  shell_command:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "read_file"
        ttl: 300
"#,
    )
    .test_unwrap();
    let policy_b = parse_policy(
        r#"

kernel: { max_capability_ttl: 3600 }
guards:
  shell_command: { enabled: true }
capabilities:
  default:
    tools:
      - { server: "*", tool: "read_file", ttl: 300 }
"#,
    )
    .test_unwrap();

    let caps_a =
        build_default_capabilities(&policy_a.capabilities, policy_a.kernel.max_capability_ttl)
            .test_unwrap();
    let caps_b =
        build_default_capabilities(&policy_b.capabilities, policy_b.kernel.max_capability_ttl)
            .test_unwrap();

    let hash_a = runtime_hash_for_chio_yaml(&policy_a, &caps_a).test_unwrap();
    let hash_b = runtime_hash_for_chio_yaml(&policy_b, &caps_b).test_unwrap();
    assert_eq!(hash_a, hash_b);
}

#[test]
fn load_hushspec_policy_materializes_runtime_state() {
    let loaded = load_policy(&fixture_path("hushspec-tool-allow.yaml")).test_unwrap();

    assert_eq!(loaded.format, PolicyFormat::HushSpec);
    assert_eq!(loaded.guard_pipeline.len(), 1);
    assert_eq!(loaded.default_capabilities.len(), 1);
    assert_eq!(
        loaded.default_capabilities[0].ttl,
        default_max_capability_ttl()
    );
    assert_eq!(loaded.default_capabilities[0].scope.grants.len(), 2);
    assert_eq!(
        loaded.default_capabilities[0].scope.grants[0].tool_name,
        "read_file"
    );
    assert_ne!(loaded.identity.source_hash, loaded.identity.runtime_hash);
}

#[test]
fn load_hushspec_materializes_threshold_approval_against_runtime_policy_hash() {
    let approver_a = chio_core::Keypair::generate().public_key().to_hex();
    let approver_b = chio_core::Keypair::generate().public_key().to_hex();
    let policy_dir = std::env::temp_dir().join(format!(
        "chio-threshold-policy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&policy_dir).test_unwrap();
    let policy_path = policy_dir.join("policy.yaml");
    std::fs::write(
        &policy_path,
        format!(
            r#"
hushspec: "0.1.0"
name: threshold-runtime
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  chio:
    human_in_loop:
      approvers:
        n: 2
        of: ["{approver_a}", "{approver_b}"]
        timeout_seconds: 600
"#
        ),
    )
    .test_unwrap();

    let loaded = load_policy(&policy_path).test_unwrap();
    let requirement = loaded
        .threshold_approval
        .as_ref()
        .test_expect("threshold requirement");
    assert_eq!(requirement.policy_hash, loaded.identity.runtime_hash);
    assert_eq!(requirement.threshold, 2);
    assert_eq!(requirement.timeout_seconds, 600);
    assert_eq!(
        requirement.directory_version,
        "self-authenticating-public-key-v1"
    );
    requirement.validate().test_unwrap();

    std::fs::remove_dir_all(policy_dir).test_unwrap();
}

#[test]
fn load_hushspec_policy_identity_tracks_threat_intel_pattern_db_bytes() {
    let policy_dir = std::env::temp_dir().join(format!(
        "chio-hushspec-asset-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_millis()
    ));
    std::fs::create_dir_all(&policy_dir).test_unwrap();
    let pattern_db = policy_dir.join("pattern-db.json");
    let policy_path = policy_dir.join("policy.yaml");

    std::fs::write(&pattern_db, sample_threat_intel_pattern_db("first")).test_unwrap();
    std::fs::write(
        &policy_path,
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - read_file
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "pattern-db.json"
"#,
    )
    .test_unwrap();

    let first = load_policy(&policy_path).test_unwrap();
    std::fs::write(&pattern_db, sample_threat_intel_pattern_db("second")).test_unwrap();
    let second = load_policy(&policy_path).test_unwrap();

    assert_ne!(first.identity.source_hash, second.identity.source_hash);
    assert_ne!(first.identity.runtime_hash, second.identity.runtime_hash);

    let _ = std::fs::remove_dir_all(policy_dir);
}

#[test]
fn load_hushspec_block_all_issues_no_default_capabilities() {
    let loaded = load_policy(&fixture_path("hushspec-block-all.yaml")).test_unwrap();
    assert_eq!(loaded.format, PolicyFormat::HushSpec);
    assert!(loaded.default_capabilities.is_empty());
    assert_eq!(loaded.guard_pipeline.len(), 1);
}

#[test]
fn load_hushspec_resolves_extends_before_compiling() {
    let loaded = load_policy(&fixture_path("hushspec-extended.yaml")).test_unwrap();

    assert_eq!(loaded.format, PolicyFormat::HushSpec);
    assert_eq!(loaded.guard_pipeline.len(), 2);
    assert_eq!(loaded.default_capabilities.len(), 1);
    assert_eq!(loaded.default_capabilities[0].scope.grants.len(), 2);
    assert_eq!(
        loaded.default_capabilities[0].scope.grants[1].tool_name,
        "list_directory"
    );
}

#[test]
fn load_hushspec_materializes_reputation_issuance_policy() {
    let loaded = load_policy(&fixture_path("hushspec-reputation.yaml")).test_unwrap();

    let issuance_policy = loaded
        .issuance_policy
        .test_expect("reputation issuance policy should materialize");
    assert_eq!(issuance_policy.probationary_receipt_count, 1000);
    assert_eq!(issuance_policy.probationary_min_days, 30);
    assert_eq!(issuance_policy.probationary_score_ceiling, 0.60);
    assert_eq!(issuance_policy.tiers.len(), 4);
    assert_eq!(issuance_policy.tiers[0].name, "probationary");
    assert_eq!(
        issuance_policy.tiers[0].max_scope.max_total_cost,
        Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        })
    );
    assert_eq!(
        issuance_policy
            .tiers
            .last()
            .test_expect("elevated tier")
            .max_scope
            .operations,
        vec![
            Operation::Read,
            Operation::Get,
            Operation::Invoke,
            Operation::ReadResult,
            Operation::Delegate,
            Operation::Subscribe,
        ]
    );
}

#[test]
fn chio_yaml_guard_surface_matches_hushspec_fixture() {
    let chio_policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
    let chio_pipeline = build_guard_pipeline(&chio_policy.guards).test_unwrap();
    let chio_post_invocation = build_post_invocation_pipeline(&chio_policy.guards).test_unwrap();
    let chio_capabilities = build_runtime_default_capabilities(&chio_policy).test_unwrap();

    let hushspec = load_policy(&fixture_path("hushspec-guard-heavy.yaml")).test_unwrap();

    assert_eq!(chio_pipeline.len(), hushspec.guard_pipeline.len());
    assert_eq!(
        chio_post_invocation.len(),
        hushspec.post_invocation_pipeline.len()
    );
    assert_eq!(chio_capabilities.len(), hushspec.default_capabilities.len());
    assert_eq!(
        chio_capabilities[0].ttl,
        hushspec.default_capabilities[0].ttl
    );
    assert_eq!(
        serde_json::to_value(&chio_capabilities[0].scope.grants).test_unwrap(),
        serde_json::to_value(&hushspec.default_capabilities[0].scope.grants).test_unwrap()
    );
}

#[test]
fn hushspec_materializes_runtime_assurance_policy() {
    let spec = chio_policy::HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: runtime-assurance
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          max_invocations: 5
          max_cost_per_invocation:
            units: 50
            currency: USD
          max_total_cost:
            units: 100
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 30
      attested:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke", "read_result"]
          max_invocations: 20
          max_cost_per_invocation:
            units: 250
            currency: USD
          max_total_cost:
            units: 1000
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 300
    trusted_verifiers:
      azure_contoso:
        schema: chio.runtime-attestation.azure-maa.jwt.v1
        verifier: https://maa.contoso.test/
        effective_tier: verified
        verifier_family: azure_maa
        max_evidence_age_seconds: 120
        allowed_attestation_types: [sgx]
        required_assertions:
          attestationType: sgx
"#,
    )
    .test_unwrap();

    let runtime_assurance_policy = materialize_runtime_assurance_policy(&spec)
        .test_unwrap()
        .test_expect("runtime assurance policy should materialize");
    assert_eq!(runtime_assurance_policy.tiers.len(), 2);
    assert_eq!(runtime_assurance_policy.tiers[0].name, "baseline");
    assert_eq!(
        runtime_assurance_policy.tiers[1].minimum_attestation_tier,
        RuntimeAssuranceTier::Attested
    );
    assert_eq!(
        runtime_assurance_policy.tiers[1].max_scope.max_total_cost,
        Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        })
    );
    let trust_policy = runtime_assurance_policy
        .attestation_trust_policy
        .test_expect("trusted verifier policy should materialize");
    assert_eq!(trust_policy.rules.len(), 1);
    assert_eq!(trust_policy.rules[0].name, "azure_contoso");
    assert_eq!(
        trust_policy.rules[0].effective_tier,
        RuntimeAssuranceTier::Verified
    );
    assert_eq!(
        trust_policy.rules[0].verifier_family,
        Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa)
    );
    assert_eq!(
        trust_policy.rules[0].allowed_attestation_types,
        vec!["sgx".to_string()]
    );
    assert_eq!(
        trust_policy.rules[0]
            .required_assertions
            .get("attestationType")
            .map(String::as_str),
        Some("sgx")
    );
}
