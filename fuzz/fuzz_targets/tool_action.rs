#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chio_core::capability::{
    aggregate_invocation::{AggregateInvocationBudget, AggregateInvocationScope},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{EgressAllowlistGuard, McpToolGuard, ShellCommandGuard, ToolAction};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 16 * 1024;
const MAX_TEXT_CHARS: usize = 512;
const TOOL_ACTION_SEEDS: &[&[u8]] = &[
    include_bytes!("../corpus/fuzz_tool_action/egress-allow.json"),
    include_bytes!("../corpus/fuzz_tool_action/egress-deny.json"),
    include_bytes!("../corpus/fuzz_tool_action/egress-internal-metadata.json"),
    include_bytes!("../corpus/fuzz_tool_action/egress-ipv6-internal.json"),
    include_bytes!("../corpus/fuzz_tool_action/egress-userinfo.json"),
    include_bytes!("../corpus/fuzz_tool_action/mcp-allow.json"),
    include_bytes!("../corpus/fuzz_tool_action/mcp-block.json"),
    include_bytes!("../corpus/fuzz_tool_action/memory-write.json"),
    include_bytes!("../corpus/fuzz_tool_action/shell-allow.json"),
    include_bytes!("../corpus/fuzz_tool_action/shell-deny.json"),
    include_bytes!("../corpus/fuzz_tool_action/shell-obfuscated-rm.json"),
    include_bytes!("../corpus/fuzz_tool_action/sql-query.json"),
];

#[derive(Arbitrary, Debug)]
struct ToolActionInput {
    issuer_seed: [u8; 32],
    subject_seed: [u8; 32],
    tool_selector: u8,
    argument_selector: u8,
    budget_selector: u8,
    text: String,
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedAction {
    FileAccess,
    FileWrite,
    ShellCommand,
    NetworkEgress,
    DatabaseQuery,
    BrowserAction,
    CodeExecution,
    MemoryWrite,
    McpTool,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedVerdict {
    Allow,
    Deny,
}

struct GeneratedToolAction {
    tool_name: &'static str,
    args: serde_json::Value,
    expected_action: ExpectedAction,
    expected_verdict: Option<ExpectedVerdict>,
}

fn trim(input: &str) -> String {
    input.chars().take(MAX_TEXT_CHARS).collect()
}

fn expected_action_from_str(value: &str) -> Option<ExpectedAction> {
    match value {
        "file_access" => Some(ExpectedAction::FileAccess),
        "file_write" => Some(ExpectedAction::FileWrite),
        "shell_command" => Some(ExpectedAction::ShellCommand),
        "network_egress" => Some(ExpectedAction::NetworkEgress),
        "database_query" => Some(ExpectedAction::DatabaseQuery),
        "browser_action" => Some(ExpectedAction::BrowserAction),
        "code_execution" => Some(ExpectedAction::CodeExecution),
        "memory_write" => Some(ExpectedAction::MemoryWrite),
        "mcp_tool" => Some(ExpectedAction::McpTool),
        "unknown" => Some(ExpectedAction::Unknown),
        _ => None,
    }
}

fn expected_verdict_from_str(value: &str) -> Option<ExpectedVerdict> {
    match value {
        "allow" => Some(ExpectedVerdict::Allow),
        "deny" => Some(ExpectedVerdict::Deny),
        _ => None,
    }
}

fn expected_action_from_value(value: &serde_json::Value) -> Option<ExpectedAction> {
    value
        .get("expected_action")
        .and_then(|value| value.as_str())
        .and_then(expected_action_from_str)
}

fn expected_verdict_from_value(value: &serde_json::Value) -> Option<ExpectedVerdict> {
    value
        .get("expected_verdict")
        .and_then(|value| value.as_str())
        .and_then(expected_verdict_from_str)
}

fn is_exact_seed(data: &[u8], seeds: &[&[u8]]) -> bool {
    seeds.contains(&data)
}

fn generated_case(input: &ToolActionInput) -> GeneratedToolAction {
    let text = trim(&input.text);
    let selector = input.tool_selector.wrapping_add(input.argument_selector) % 12;
    match selector {
        0 => GeneratedToolAction {
            tool_name: "read_file",
            args: serde_json::json!({"path": format!("/tmp/chio-fuzz/{text}")}),
            expected_action: ExpectedAction::FileAccess,
            expected_verdict: None,
        },
        1 => GeneratedToolAction {
            tool_name: "write_file",
            args: serde_json::json!({"path": "/tmp/chio-fuzz/out.txt", "content": text}),
            expected_action: ExpectedAction::FileWrite,
            expected_verdict: None,
        },
        2 => GeneratedToolAction {
            tool_name: "bash",
            args: serde_json::json!({"command": "rm -rf /"}),
            expected_action: ExpectedAction::ShellCommand,
            expected_verdict: Some(ExpectedVerdict::Deny),
        },
        3 => GeneratedToolAction {
            tool_name: "bash",
            args: serde_json::json!({"command": "echo ok"}),
            expected_action: ExpectedAction::ShellCommand,
            expected_verdict: Some(ExpectedVerdict::Allow),
        },
        4 => GeneratedToolAction {
            tool_name: "http_request",
            args: serde_json::json!({"url": "https://api.github.com/repos"}),
            expected_action: ExpectedAction::NetworkEgress,
            expected_verdict: Some(ExpectedVerdict::Allow),
        },
        5 => GeneratedToolAction {
            tool_name: "http_request",
            args: serde_json::json!({"url": "http://169.254.169.254/latest/meta-data"}),
            expected_action: ExpectedAction::NetworkEgress,
            expected_verdict: Some(ExpectedVerdict::Deny),
        },
        6 => GeneratedToolAction {
            tool_name: "sql",
            args: serde_json::json!({"query": format!("SELECT id FROM audit_log WHERE id = {}", input.port), "database": "fuzz"}),
            expected_action: ExpectedAction::DatabaseQuery,
            expected_verdict: None,
        },
        7 => GeneratedToolAction {
            tool_name: "browser",
            args: serde_json::json!({"action": "click", "selector": text}),
            expected_action: ExpectedAction::BrowserAction,
            expected_verdict: None,
        },
        8 => GeneratedToolAction {
            tool_name: "python",
            args: serde_json::json!({"code": text, "language": "python"}),
            expected_action: ExpectedAction::CodeExecution,
            expected_verdict: None,
        },
        9 => GeneratedToolAction {
            tool_name: "memory_write",
            args: serde_json::json!({"collection": "memories", "id": text}),
            expected_action: ExpectedAction::MemoryWrite,
            expected_verdict: None,
        },
        10 => GeneratedToolAction {
            tool_name: "raw_file_write",
            args: serde_json::json!({"path": "/tmp/chio-fuzz/out.txt", "content": "x"}),
            expected_action: ExpectedAction::McpTool,
            expected_verdict: Some(ExpectedVerdict::Deny),
        },
        _ => GeneratedToolAction {
            tool_name: "custom_tool",
            args: serde_json::json!({"input": text, "limit": input.port}),
            expected_action: ExpectedAction::McpTool,
            expected_verdict: Some(ExpectedVerdict::Allow),
        },
    }
}

fn aggregate_budget(selector: u8) -> Option<AggregateInvocationBudget> {
    (selector % 3 == 1).then_some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: u32::from(selector),
        root_binding: None,
    })
}

fn capability(
    issuer: &Keypair,
    subject: &Keypair,
    tool_name: &str,
    budget_selector: u8,
) -> CapabilityToken {
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-fuzz".to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(false),
        }],
        ..ChioScope::default()
    };
    let body = CapabilityTokenBody {
        id: "cap-fuzz-tool-action".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: 0,
        expires_at: 60,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: aggregate_budget(budget_selector),
    };
    let signed = if budget_selector % 3 == 2 {
        CapabilityToken::sign_aggregate_family_root(body, u32::from(budget_selector), issuer)
    } else {
        CapabilityToken::sign(body, issuer)
    };
    match signed {
        Ok(token) => token,
        Err(error) => panic!("tool-action capability should sign: {error}"),
    }
}

fn with_guard_context(
    tool_name: &str,
    args: serde_json::Value,
    issuer: &Keypair,
    subject: &Keypair,
    budget_selector: u8,
    f: impl FnOnce(&GuardContext<'_>),
) {
    let token = capability(issuer, subject, tool_name, budget_selector);
    let scope = token.scope.clone();
    let agent_id = "agent-fuzz".to_string();
    let server_id = "srv-fuzz".to_string();
    let request = ToolCallRequest {
        request_id: "req-fuzz-tool-action".to_string(),
        capability: token,
        tool_name: tool_name.to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: args,
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
    let ctx = GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: Some(0),
    };
    f(&ctx);
}

fn assert_guard_verdict(actual: Verdict, expected: ExpectedVerdict) {
    match expected {
        ExpectedVerdict::Allow => assert_eq!(actual, Verdict::Allow),
        ExpectedVerdict::Deny => assert_eq!(actual, Verdict::Deny),
    }
}

fn action_kind(action: &ToolAction) -> ExpectedAction {
    match action {
        ToolAction::FileAccess(_) => ExpectedAction::FileAccess,
        ToolAction::FileWrite(_, _) => ExpectedAction::FileWrite,
        ToolAction::ShellCommand(_) => ExpectedAction::ShellCommand,
        ToolAction::NetworkEgress(_, _) => ExpectedAction::NetworkEgress,
        ToolAction::DatabaseQuery { .. } => ExpectedAction::DatabaseQuery,
        ToolAction::BrowserAction { .. } => ExpectedAction::BrowserAction,
        ToolAction::CodeExecution { .. } => ExpectedAction::CodeExecution,
        ToolAction::MemoryWrite { .. } => ExpectedAction::MemoryWrite,
        ToolAction::McpTool(_, _) => ExpectedAction::McpTool,
        ToolAction::Unknown => ExpectedAction::Unknown,
        ToolAction::Patch(_, _)
        | ToolAction::ExternalApiCall { .. }
        | ToolAction::MemoryRead { .. } => ExpectedAction::McpTool,
    }
}

fn assert_action_contract(
    tool_name: &str,
    args: &serde_json::Value,
    ctx: &GuardContext<'_>,
    expected_action: Option<ExpectedAction>,
    expected_verdict: Option<ExpectedVerdict>,
) {
    let action = chio_guards::extract_action(tool_name, args);
    let shell = ShellCommandGuard::new();
    let egress = EgressAllowlistGuard::new();
    let mcp = McpToolGuard::new();

    if let Some(expected) = expected_action {
        assert_eq!(action_kind(&action), expected);
    }

    match action {
        ToolAction::FileAccess(path) => {
            assert!(!path.is_empty());
        }
        ToolAction::FileWrite(path, _content) => {
            assert!(!path.is_empty());
        }
        ToolAction::ShellCommand(_command) => {
            let verdict = match shell.evaluate(ctx) {
                Ok(verdict) => verdict,
                Err(error) => panic!("shell guard should return a verdict: {error}"),
            };
            if let Some(expected) = expected_verdict {
                assert_guard_verdict(verdict.verdict, expected);
            }
        }
        ToolAction::NetworkEgress(host, _port) => {
            assert!(!host.is_empty());
            let verdict = match egress.evaluate(ctx) {
                Ok(verdict) => verdict,
                Err(error) => panic!("egress guard should return a verdict: {error}"),
            };
            if let Some(expected) = expected_verdict {
                assert_guard_verdict(verdict.verdict, expected);
            }
        }
        ToolAction::McpTool(name, _mcp_args) => {
            assert!(!name.is_empty());
            let verdict = match mcp.evaluate(ctx) {
                Ok(verdict) => verdict,
                Err(error) => panic!("mcp guard should return a verdict: {error}"),
            };
            if let Some(expected) = expected_verdict {
                assert_guard_verdict(verdict.verdict, expected);
            }
        }
        ToolAction::Patch(path, diff) => {
            assert!(!path.is_empty());
            assert!(!diff.is_empty() || args.get("diff").is_none());
        }
        ToolAction::CodeExecution { language, .. } => {
            assert!(!language.is_empty());
        }
        ToolAction::BrowserAction { verb, .. } => {
            assert!(!verb.is_empty());
        }
        ToolAction::DatabaseQuery { database, query } => {
            assert!(!database.is_empty());
            assert!(!query.is_empty());
        }
        ToolAction::ExternalApiCall { service, endpoint } => {
            assert!(!service.is_empty());
            assert!(!endpoint.is_empty());
        }
        ToolAction::MemoryWrite { store, .. } | ToolAction::MemoryRead { store, .. } => {
            assert!(!store.is_empty());
        }
        ToolAction::Unknown => {}
    }
}

fn exercise_tool_action(
    tool_name: &str,
    args: serde_json::Value,
    issuer: &Keypair,
    subject: &Keypair,
    budget_selector: u8,
    expected_action: Option<ExpectedAction>,
    expected_verdict: Option<ExpectedVerdict>,
) {
    with_guard_context(
        tool_name,
        args.clone(),
        issuer,
        subject,
        budget_selector,
        |ctx| {
            assert_action_contract(tool_name, &args, ctx, expected_action, expected_verdict);
        },
    );
}

fn exercise_raw(data: &[u8], issuer: &Keypair, subject: &Keypair) {
    if data.len() > MAX_RAW_BYTES {
        return;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Some(object) = value.as_object() else {
        return;
    };

    let Some(tool_name) = object
        .get("tool_name")
        .or_else(|| object.get("tool"))
        .and_then(|value| value.as_str())
    else {
        return;
    };
    let args = object
        .get("arguments")
        .or_else(|| object.get("args"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let enforce_expected = is_exact_seed(data, TOOL_ACTION_SEEDS);
    let expected_action = enforce_expected
        .then(|| expected_action_from_value(&value))
        .flatten();
    let expected_verdict = enforce_expected
        .then(|| expected_verdict_from_value(&value))
        .flatten();
    exercise_tool_action(
        tool_name,
        args,
        issuer,
        subject,
        data.first().copied().unwrap_or(0),
        expected_action,
        expected_verdict,
    );
}

fn exercise_generated(input: ToolActionInput) {
    let generated = generated_case(&input);
    let issuer = Keypair::from_seed(&input.issuer_seed);
    let subject = Keypair::from_seed(&input.subject_seed);
    exercise_tool_action(
        generated.tool_name,
        generated.args,
        &issuer,
        &subject,
        input.budget_selector,
        Some(generated.expected_action),
        generated.expected_verdict,
    );
}

fuzz_target!(|data: &[u8]| {
    let issuer = Keypair::from_seed(&[0x11; 32]);
    let subject = Keypair::from_seed(&[0x12; 32]);
    exercise_raw(data, &issuer, &subject);

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = ToolActionInput::arbitrary(&mut unstructured) {
        exercise_generated(input);
    }
});
