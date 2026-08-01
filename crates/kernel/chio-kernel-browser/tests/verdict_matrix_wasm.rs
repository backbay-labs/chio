#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core_types::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_kernel_browser::{evaluate_pure, BrowserClock, EvaluateRequestJson, ToolCallRequestJson};
use serde::Deserialize;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test_configure;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

const MATRIX_SERVER_ID: &str = "verdict-matrix";
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;
const REASON_NONE: &str = "urn:chio:error:none";
const REASON_SCOPE_EXCEEDED: &str = "urn:chio:error:capability:scope-exceeded";
const REASON_KERNEL_INTERNAL: &str = "urn:chio:error:kernel:internal-error";
const SCENARIO_COUNT: usize = 48;
const SCENARIO_FIXTURES: [(&str, &str); SCENARIO_COUNT] = [
    (
        "capability_subset/capability-subset-001-read-exact.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-001-read-exact.json"),
    ),
    (
        "capability_subset/capability-subset-002-write-exact.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-002-write-exact.json"),
    ),
    (
        "capability_subset/capability-subset-003-admin-exact.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-003-admin-exact.json"),
    ),
    (
        "capability_subset/capability-subset-004-read-superset.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-004-read-superset.json"),
    ),
    (
        "capability_subset/capability-subset-005-telemetry-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-005-telemetry-read.json"),
    ),
    (
        "capability_subset/capability-subset-006-prompt-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-006-prompt-read.json"),
    ),
    (
        "capability_subset/capability-subset-007-missing-write.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-007-missing-write.json"),
    ),
    (
        "capability_subset/capability-subset-008-missing-admin.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-008-missing-admin.json"),
    ),
    (
        "capability_subset/capability-subset-009-empty-scope.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-009-empty-scope.json"),
    ),
    (
        "capability_subset/capability-subset-010-resource-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-010-resource-read.json"),
    ),
    (
        "capability_subset/capability-subset-011-mixed-tool-call.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-011-mixed-tool-call.json"),
    ),
    (
        "capability_subset/capability-subset-012-prompt-write-denied.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/capability_subset/capability-subset-012-prompt-write-denied.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-001-input-mask-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-001-input-mask-read.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-002-output-mask-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-002-output-mask-read.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-003-input-drop-write.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-003-input-drop-write.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-004-input-deny-write.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-004-input-deny-write.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-005-no-redaction-resource.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-005-no-redaction-resource.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-006-output-drop-resource.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-006-output-drop-resource.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-007-input-mask-prompt.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-007-input-mask-prompt.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-008-output-deny-prompt.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-008-output-deny-prompt.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-009-input-mask-telemetry.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-009-input-mask-telemetry.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-010-output-mask-telemetry.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-010-output-mask-telemetry.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-011-input-deny-admin.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-011-input-deny-admin.json"),
    ),
    (
        "redaction_determinism/redaction-determinism-012-no-redaction-tool-call.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism/redaction-determinism-012-no-redaction-tool-call.json"),
    ),
    (
        "replay_verdict/replay-verdict-001-fresh-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-001-fresh-read.json"),
    ),
    (
        "replay_verdict/replay-verdict-002-duplicate-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-002-duplicate-read.json"),
    ),
    (
        "replay_verdict/replay-verdict-003-stale-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-003-stale-read.json"),
    ),
    (
        "replay_verdict/replay-verdict-004-missing-trace.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-004-missing-trace.json"),
    ),
    (
        "replay_verdict/replay-verdict-005-fresh-write.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-005-fresh-write.json"),
    ),
    (
        "replay_verdict/replay-verdict-006-duplicate-write.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-006-duplicate-write.json"),
    ),
    (
        "replay_verdict/replay-verdict-007-fresh-resource.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-007-fresh-resource.json"),
    ),
    (
        "replay_verdict/replay-verdict-008-stale-resource.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-008-stale-resource.json"),
    ),
    (
        "replay_verdict/replay-verdict-009-fresh-prompt.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-009-fresh-prompt.json"),
    ),
    (
        "replay_verdict/replay-verdict-010-duplicate-prompt.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-010-duplicate-prompt.json"),
    ),
    (
        "replay_verdict/replay-verdict-011-fresh-telemetry.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-011-fresh-telemetry.json"),
    ),
    (
        "replay_verdict/replay-verdict-012-missing-trace-admin.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict/replay-verdict-012-missing-trace-admin.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-001-active-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-001-active-read.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-002-revoked-read.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-002-revoked-read.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-003-active-write.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-003-active-write.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-004-revoked-write.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-004-revoked-write.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-005-revoked-superset.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-005-revoked-superset.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-006-active-resource.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-006-active-resource.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-007-revoked-resource.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-007-revoked-resource.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-008-active-prompt.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-008-active-prompt.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-009-revoked-prompt.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-009-revoked-prompt.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-010-active-telemetry.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-010-active-telemetry.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-011-revoked-admin.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-011-revoked-admin.json"),
    ),
    (
        "revocation_propagation/revocation-propagation-012-active-tool-call.json",
        include_str!("../../../tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation/revocation-propagation-012-active-tool-call.json"),
    ),
];

#[derive(Debug, Clone, Deserialize)]
struct VerdictScenario {
    schema: String,
    id: String,
    category: String,
    #[serde(default)]
    requires: Vec<String>,
    script: ScenarioScript,
    expected: VerdictTuple,
}

#[derive(Debug, Clone, Deserialize)]
struct ScenarioScript {
    operation: String,
    tool: String,
    input_json: String,
    #[serde(default)]
    capability_scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct VerdictTuple {
    verdict: String,
    reason_code: String,
    scope_set: Vec<String>,
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn wasm_browser_driver_reports_real_supported_tuples_and_unsupported_stateful_classes() {
    let scenarios = load_scenarios();
    assert_eq!(scenarios.len(), SCENARIO_COUNT);

    let mut failures = Vec::new();
    let mut passed = 0usize;
    let mut unsupported = 0usize;
    for scenario in scenarios {
        match evaluate_browser_scenario(&scenario) {
            DriverOutcome::Pass => passed += 1,
            DriverOutcome::Unsupported(reason) => {
                unsupported += 1;
                assert!(
                    scenario.category != "capability",
                    "{} was unexpectedly unsupported: {}",
                    scenario.id,
                    reason
                );
            }
            DriverOutcome::Fail { expected, actual } => {
                failures.push(format!(
                    "{} expected {:?}, actual {:?}",
                    scenario.id, expected, actual
                ));
            }
        }
    }

    assert_eq!(passed, 12);
    assert_eq!(unsupported, 36);
    assert!(
        failures.is_empty(),
        "wasm browser verdict driver failures ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

enum DriverOutcome {
    Pass,
    Unsupported(String),
    Fail {
        expected: VerdictTuple,
        actual: VerdictTuple,
    },
}

fn evaluate_browser_scenario(scenario: &VerdictScenario) -> DriverOutcome {
    let expected = normalized(scenario.expected.clone());
    if scenario.schema != "chio.verdict-matrix.scenario.v1" {
        return DriverOutcome::Fail {
            expected,
            actual: tuple(
                "error",
                REASON_KERNEL_INTERNAL,
                scenario.script.capability_scopes.clone(),
            ),
        };
    }
    if scenario.script.operation != "tool.call" {
        return DriverOutcome::Fail {
            expected,
            actual: tuple(
                "error",
                REASON_KERNEL_INTERNAL,
                scenario.script.capability_scopes.clone(),
            ),
        };
    }
    if let Some(unsupported) = unsupported_requirement(&scenario.requires) {
        return DriverOutcome::Unsupported(format!(
            "browser evaluate_pure does not support requirement `{unsupported}`"
        ));
    }
    if scenario.category != "capability" {
        return DriverOutcome::Unsupported(format!(
            "browser evaluate_pure has no revocation store, execution nonce store, or guard pipeline for category `{}`",
            scenario.category
        ));
    }

    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = match make_capability(
        &scenario.id,
        &scenario.script.capability_scopes,
        &subject,
        &issuer,
    ) {
        Ok(capability) => capability,
        Err(reason) => {
            return DriverOutcome::Fail {
                expected,
                actual: tuple("error", &reason, scenario.script.capability_scopes.clone()),
            };
        }
    };
    let arguments = match serde_json::from_str(&scenario.script.input_json) {
        Ok(arguments) => arguments,
        Err(error) => {
            return DriverOutcome::Fail {
                expected,
                actual: tuple(
                    "error",
                    &format!("{}: {error}", REASON_KERNEL_INTERNAL),
                    scenario.script.capability_scopes.clone(),
                ),
            };
        }
    };
    let input = EvaluateRequestJson {
        request: ToolCallRequestJson {
            request_id: scenario.id.clone(),
            tool_name: scenario.script.tool.clone(),
            server_id: MATRIX_SERVER_ID.to_string(),
            agent_id: subject.public_key().to_hex(),
            arguments,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
        },
        capability,
        trusted_issuers_hex: vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        session_filesystem_roots: None,
        peer_capabilities: None,
        direct_root_capability: None,
        capability_trust_roots: Default::default(),
        parent_budget_snapshots: Vec::new(),
    };
    let browser_clock = BrowserClock::new();
    let core = match evaluate_pure(input, &browser_clock) {
        Ok(core) => core,
        Err(error) => {
            return DriverOutcome::Fail {
                expected,
                actual: tuple(
                    "error",
                    &format!("{}: {}", REASON_KERNEL_INTERNAL, error.message),
                    scenario.script.capability_scopes.clone(),
                ),
            };
        }
    };

    let actual = tuple_from_browser_core(&core, &scenario.script.capability_scopes);
    if actual == expected {
        DriverOutcome::Pass
    } else {
        DriverOutcome::Fail { expected, actual }
    }
}

fn tuple_from_browser_core(
    core: &chio_kernel_browser::EvaluationVerdictJson,
    scope_set: &[String],
) -> VerdictTuple {
    match core.capability_verdict.as_str() {
        "allow" => tuple("allow", REASON_NONE, scope_set.to_vec()),
        "deny" => tuple(
            "deny",
            deny_reason_code(core.reason.as_deref()),
            scope_set.to_vec(),
        ),
        _ => tuple("error", REASON_KERNEL_INTERNAL, scope_set.to_vec()),
    }
}

fn deny_reason_code(reason: Option<&str>) -> &'static str {
    let Some(reason) = reason else {
        return REASON_KERNEL_INTERNAL;
    };
    let lower = reason.to_ascii_lowercase();
    if lower.contains("not in capability scope") || lower.contains("out of scope") {
        REASON_SCOPE_EXCEEDED
    } else {
        REASON_KERNEL_INTERNAL
    }
}

fn unsupported_requirement(requirements: &[String]) -> Option<&str> {
    for requirement in requirements {
        match requirement.as_str() {
            "rust-kernel" | "kernel-semantics" | "wasm-browser-kernel" => {}
            other => return Some(other),
        }
    }
    None
}

fn make_capability(
    scenario_id: &str,
    labels: &[String],
    subject: &Keypair,
    issuer: &Keypair,
) -> Result<CapabilityToken, String> {
    let mut grants = Vec::new();
    for label in labels {
        grants.push(grant_from_label(label)?);
    }
    let body = CapabilityTokenBody {
        id: format!("cap-{scenario_id}"),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope {
            grants,
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).map_err(|error| error.to_string())
}

fn grant_from_label(label: &str) -> Result<ToolGrant, String> {
    let tool_name = match label {
        "tool:read" => "files.read",
        "tool:write" => "files.write",
        "tool:admin" => "system.rotate",
        "telemetry:read" => "metrics.query",
        "prompt:read" => "prompts.get",
        "prompt:write" => "prompts.update",
        "resource:read" => "resources.read",
        "tool:call" => "tools.invoke",
        other => return Err(format!("unsupported capability scope label `{other}`")),
    };
    Ok(ToolGrant {
        server_id: MATRIX_SERVER_ID.to_string(),
        tool_name: tool_name.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    })
}

fn tuple(verdict: &str, reason_code: &str, scope_set: Vec<String>) -> VerdictTuple {
    normalized(VerdictTuple {
        verdict: verdict.to_string(),
        reason_code: reason_code.to_string(),
        scope_set,
    })
}

fn normalized(mut tuple: VerdictTuple) -> VerdictTuple {
    tuple.scope_set.sort();
    tuple
}

fn load_scenarios() -> Vec<VerdictScenario> {
    SCENARIO_FIXTURES
        .iter()
        .map(
            |(path, text)| match serde_json::from_str::<VerdictScenario>(text) {
                Ok(scenario) => scenario,
                Err(error) => panic!("failed to parse {path}: {error}"),
            },
        )
        .collect()
}
