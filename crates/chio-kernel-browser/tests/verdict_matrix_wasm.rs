#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use chio_core_types::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core_types::crypto::Keypair;
use chio_kernel_browser::{evaluate_pure, BrowserClock, EvaluateRequestJson, ToolCallRequestJson};
use serde::Deserialize;

const MATRIX_SERVER_ID: &str = "verdict-matrix";
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;
const REASON_NONE: &str = "urn:chio:error:none";
const REASON_SCOPE_EXCEEDED: &str = "urn:chio:error:capability:scope-exceeded";
const REASON_KERNEL_INTERNAL: &str = "urn:chio:error:kernel:internal-error";

#[derive(Debug, Clone, Deserialize)]
struct VerdictScenario {
    schema: String,
    id: String,
    category: String,
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

#[test]
fn wasm_browser_driver_reports_real_supported_tuples_and_unsupported_stateful_classes() {
    let scenarios = load_scenarios();
    assert_eq!(scenarios.len(), 48);

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
        },
        capability,
        trusted_issuers_hex: vec![issuer.public_key().to_hex()],
        clock_override_unix_secs: Some(ISSUED_AT + 1),
        session_filesystem_roots: None,
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
    match core.verdict.as_str() {
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
    let root = repo_root()
        .join("crates")
        .join("chio-conformance")
        .join("verdict_matrix")
        .join("scenarios");
    let mut files = Vec::new();
    collect_json_files(&root, &mut files);
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let text = match fs::read_to_string(&file) {
                Ok(text) => text,
                Err(error) => panic!("failed to read {}: {error}", file.display()),
            };
            match serde_json::from_str::<VerdictScenario>(&text) {
                Ok(scenario) => scenario,
                Err(error) => panic!("failed to parse {}: {error}", file.display()),
            }
        })
        .collect()
}

fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(crates_dir) = manifest_dir.parent() else {
        panic!(
            "CARGO_MANIFEST_DIR has no parent: {}",
            manifest_dir.display()
        );
    };
    let Some(root) = crates_dir.parent() else {
        panic!("crates dir has no parent: {}", crates_dir.display());
    };
    root.to_path_buf()
}

fn collect_json_files(path: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => panic!("failed to list {}: {error}", path.display()),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!(
                "failed to read directory entry in {}: {error}",
                path.display()
            ),
        };
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_json_files(&entry_path, files);
        } else if entry_path
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("json")
        {
            files.push(entry_path);
        }
    }
}
