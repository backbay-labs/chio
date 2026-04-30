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
const REASON_REVOKED: &str = "urn:chio:error:capability:revoked";
const REASON_REPLAY_DRIFT: &str = "urn:chio:error:replay:deterministic-mismatch";
const REASON_REPLAY_TRACE_MISSING: &str = "urn:chio:error:replay:trace-not-found";
const REASON_INPUT_REDACTED: &str = "urn:chio:error:guard:input-redacted";
const REASON_OUTPUT_REDACTED: &str = "urn:chio:error:guard:output-redacted";
const REASON_GUARD_DENIED: &str = "urn:chio:error:guard:denied";
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
    #[serde(default)]
    required_scope: Option<String>,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    replay_nonce_status: Option<String>,
    #[serde(default)]
    redaction_action: Option<String>,
    #[serde(default)]
    redaction_phase: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct VerdictTuple {
    verdict: String,
    reason_code: String,
    scope_set: Vec<String>,
}

#[test]
fn wasm_browser_driver_matches_verdict_matrix_tuples() {
    let scenarios = load_scenarios();
    assert_eq!(scenarios.len(), 48);

    let mut failures = Vec::new();
    for scenario in scenarios {
        let actual = evaluate_browser_scenario(&scenario);
        let expected = normalized(scenario.expected.clone());
        if actual != expected {
            failures.push(format!(
                "{} expected {:?}, actual {:?}",
                scenario.id, expected, actual
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "wasm browser verdict driver failures ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn evaluate_browser_scenario(scenario: &VerdictScenario) -> VerdictTuple {
    if scenario.schema != "chio.verdict-matrix.scenario.v1" {
        return tuple(
            "error",
            REASON_KERNEL_INTERNAL,
            scenario.script.capability_scopes.clone(),
        );
    }
    if scenario.script.operation != "tool.call" {
        return tuple(
            "error",
            REASON_KERNEL_INTERNAL,
            scenario.script.capability_scopes.clone(),
        );
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
            return tuple("error", &reason, scenario.script.capability_scopes.clone());
        }
    };
    let arguments = match serde_json::from_str(&scenario.script.input_json) {
        Ok(arguments) => arguments,
        Err(error) => {
            return tuple(
                "error",
                &format!("{}: {error}", REASON_KERNEL_INTERNAL),
                scenario.script.capability_scopes.clone(),
            );
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
            return tuple(
                "error",
                &format!("{}: {}", REASON_KERNEL_INTERNAL, error.message),
                scenario.script.capability_scopes.clone(),
            );
        }
    };

    if core.verdict == "deny" {
        return tuple(
            "deny",
            REASON_SCOPE_EXCEEDED,
            scenario.script.capability_scopes.clone(),
        );
    }
    if let Some(required_scope) = &scenario.script.required_scope {
        if !scenario.script.capability_scopes.contains(required_scope) {
            return tuple(
                "deny",
                REASON_SCOPE_EXCEEDED,
                scenario.script.capability_scopes.clone(),
            );
        }
    }
    if scenario.script.revoked {
        return tuple(
            "deny",
            REASON_REVOKED,
            scenario.script.capability_scopes.clone(),
        );
    }
    if scenario.category == "replay" {
        match scenario
            .script
            .replay_nonce_status
            .as_deref()
            .unwrap_or("fresh")
        {
            "fresh" => {}
            "duplicate" | "stale" => {
                return tuple(
                    "deny",
                    REASON_REPLAY_DRIFT,
                    scenario.script.capability_scopes.clone(),
                );
            }
            "trace_missing" => {
                return tuple(
                    "error",
                    REASON_REPLAY_TRACE_MISSING,
                    scenario.script.capability_scopes.clone(),
                );
            }
            _ => {
                return tuple(
                    "error",
                    REASON_KERNEL_INTERNAL,
                    scenario.script.capability_scopes.clone(),
                );
            }
        }
    }
    if scenario.category == "redaction" {
        match scenario
            .script
            .redaction_action
            .as_deref()
            .unwrap_or("none")
        {
            "deny" => {
                return tuple(
                    "deny",
                    REASON_GUARD_DENIED,
                    scenario.script.capability_scopes.clone(),
                );
            }
            "mask" | "drop" => {
                let reason = if scenario.script.redaction_phase.as_deref() == Some("output") {
                    REASON_OUTPUT_REDACTED
                } else {
                    REASON_INPUT_REDACTED
                };
                return tuple("allow", reason, scenario.script.capability_scopes.clone());
            }
            "none" => {}
            _ => {
                return tuple(
                    "error",
                    REASON_KERNEL_INTERNAL,
                    scenario.script.capability_scopes.clone(),
                );
            }
        }
    }
    tuple(
        "allow",
        REASON_NONE,
        scenario.script.capability_scopes.clone(),
    )
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
