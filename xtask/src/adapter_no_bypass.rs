//! Structured adapter mediation and side-effect boundary checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use serde::Deserialize;
use syn::visit::{self, Visit};
use syn::{Attribute, ExprBinary, ExprCall, ExprMethodCall, ExprPath, ItemImpl};

use crate::{display_path, workspace_root, XtaskError};

const SOURCE_INVENTORY_PATH: &str = "formal/adapter-source-inventory.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInventory {
    schema: String,
    crate_name_markers: Vec<String>,
    explicit_roots: Vec<String>,
    contract_sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DangerousKind {
    CommandNew,
    Spawn,
    Invoke,
}

impl DangerousKind {
    fn label(self) -> &'static str {
        match self {
            Self::CommandNew => "Command::new",
            Self::Spawn => ".spawn",
            Self::Invoke => ".invoke",
        }
    }
}

#[derive(Clone, Debug)]
struct DangerousCall {
    kind: DangerousKind,
    receiver: Option<String>,
}

#[derive(Clone, Debug)]
struct CallFact {
    target: String,
    tokens: String,
}

#[derive(Clone, Debug)]
struct FunctionFacts {
    compatibility_surface: bool,
    calls: Vec<CallFact>,
    paths: BTreeSet<String>,
    binaries: Vec<String>,
    dangerous: Vec<DangerousCall>,
}

#[derive(Clone, Debug, Default)]
struct SourceFacts {
    functions: BTreeMap<String, FunctionFacts>,
}

#[derive(Clone, Copy)]
struct ExceptionRule {
    path: &'static str,
    function: &'static str,
    kind: DangerousKind,
    receiver: Option<&'static str>,
    class: &'static str,
    compatibility_only: bool,
}

const EXCEPTION_RULES: &[ExceptionRule] = &[
    ExceptionRule {
        path: "crates/protocol/chio-acp-proxy/src/transport.rs",
        function: "AcpTransport::spawn",
        kind: DangerousKind::CommandNew,
        receiver: None,
        class: "ACP agent process lifecycle",
        compatibility_only: false,
    },
    ExceptionRule {
        path: "crates/protocol/chio-acp-proxy/src/transport.rs",
        function: "AcpTransport::spawn",
        kind: DangerousKind::Spawn,
        receiver: Some("cmd"),
        class: "ACP agent process lifecycle",
        compatibility_only: false,
    },
    ExceptionRule {
        path: "crates/protocol/chio-mcp-adapter/src/transport/stdio.rs",
        function: "StdioMcpTransport::spawn",
        kind: DangerousKind::CommandNew,
        receiver: None,
        class: "MCP server process lifecycle",
        compatibility_only: false,
    },
    ExceptionRule {
        path: "crates/protocol/chio-mcp-adapter/src/transport/stdio.rs",
        function: "StdioMcpTransport::spawn",
        kind: DangerousKind::Spawn,
        receiver: Some("child_command"),
        class: "MCP server process lifecycle",
        compatibility_only: false,
    },
    ExceptionRule {
        path: "crates/protocol/chio-a2a-edge/src/edge.rs",
        function: "ChioA2aEdge::handle_send_message_passthrough",
        kind: DangerousKind::Invoke,
        receiver: Some("server"),
        class: "A2A compatibility-only passthrough",
        compatibility_only: true,
    },
    ExceptionRule {
        path: "crates/protocol/chio-acp-edge/src/edge.rs",
        function: "ChioAcpEdge::invoke_passthrough",
        kind: DangerousKind::Invoke,
        receiver: Some("server"),
        class: "ACP compatibility-only passthrough",
        compatibility_only: true,
    },
    ExceptionRule {
        path: "crates/protocol/chio-acp-edge/src/edge.rs",
        function: "ChioAcpEdge::handle_jsonrpc",
        kind: DangerousKind::Invoke,
        receiver: Some("self"),
        class: "ACP authoritative dispatch into the kernel-backed invoke method",
        compatibility_only: false,
    },
];

#[derive(Clone, Copy)]
struct CallContract {
    path: &'static str,
    function: &'static str,
    target: &'static str,
    minimum: usize,
}

const CALL_CONTRACTS: &[CallContract] = &[
    CallContract {
        path: "crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs",
        function: "ChioMcpEdge::evaluate_tool_call_operation",
        target: "self.kernel.evaluate_session_operation",
        minimum: 1,
    },
    CallContract {
        path: "crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs",
        function: "ChioMcpEdge::evaluate_tool_call_operation_with_transport",
        target: "self.kernel.evaluate_tool_call_operation_with_nested_flow_client",
        minimum: 1,
    },
    CallContract {
        path: "crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs",
        function: "ChioMcpEdge::evaluate_tool_call_operation_with_transport_channel",
        target: "self.kernel.evaluate_tool_call_operation_with_nested_flow_client",
        minimum: 1,
    },
    CallContract {
        path: "crates/products/chio-api-protect/src/evaluator.rs",
        function: "RequestEvaluator::evaluate_with_execution_nonce",
        target: "self.authority.evaluate",
        minimum: 1,
    },
    CallContract {
        path: "crates/products/chio-api-protect/src/evaluator.rs",
        function: "RequestEvaluator::evaluate_chio_request",
        target: "self.authority.evaluate",
        minimum: 1,
    },
    CallContract {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/swarm_ref.rs",
        function: "swarm_ref_from_request",
        target: "required_swarm_evidence_ref",
        minimum: 7,
    },
    CallContract {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs",
        function: "verify_swarm_authority_reference_from_store",
        target: "verify_route_metadata_matches",
        minimum: 1,
    },
    CallContract {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs",
        function: "verify_swarm_authority_reference_from_store",
        target: "verify_swarm_authority_bundle",
        minimum: 1,
    },
    CallContract {
        path: "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        function: "<ChioRuntimeAdmissionHook as RuntimeAdmissionHook>::evaluate",
        target: "verify_swarm_authority_reference_from_store",
        minimum: 1,
    },
    CallContract {
        path: "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        function: "<ChioRuntimeAdmissionHook as RuntimeAdmissionHook>::evaluate",
        target: "self.store.consume_swarm_continuation",
        minimum: 1,
    },
    CallContract {
        path: "crates/kernel/chio-kernel/src/kernel/validation.rs",
        function: "ChioKernel::verify_capability_full_pre_admit",
        target: "chio_kernel_core::verify_capability_full",
        minimum: 1,
    },
    CallContract {
        path: "crates/kernel/chio-kernel/src/kernel/validation.rs",
        function: "ChioKernel::admit_capability_budget",
        target: "budgets.try_admit_child",
        minimum: 1,
    },
    CallContract {
        path: "crates/protocol/chio-acp-edge/src/edge.rs",
        function: "ChioAcpEdge::handle_jsonrpc",
        target: "validate_execution_context",
        minimum: 2,
    },
    CallContract {
        path: "crates/protocol/chio-acp-edge/src/edge.rs",
        function: "ChioAcpEdge::invoke",
        target: "execute_orchestrated_acp_request",
        minimum: 1,
    },
];

pub(crate) fn run() -> Result<(), XtaskError> {
    let root = workspace_root()?;
    validate_workspace(&root).map_err(XtaskError::AdapterNoBypass)?;
    println!("adapter-no-bypass: structured mediation contracts passed");
    Ok(())
}

fn validate_workspace(root: &Path) -> Result<(), String> {
    let inventory = load_source_inventory(root)?;
    validate_contract_source_registry(&inventory)?;
    let adapter_sources = discover_adapter_sources(root, &inventory)?;
    let mut parsed = BTreeMap::new();
    for relative in &adapter_sources {
        parsed.insert(relative.clone(), parse_repo_source(root, relative)?);
    }
    validate_dangerous_calls(&parsed, true)?;

    for relative in &inventory.contract_sources {
        if !parsed.contains_key(relative) {
            parsed.insert(relative.clone(), parse_repo_source(root, relative)?);
        }
    }
    for contract in CALL_CONTRACTS {
        let source = parsed
            .get(contract.path)
            .ok_or_else(|| format!("internal source lookup failed: {}", contract.path))?;
        require_call(source, contract)?;
    }
    require_path(
        parsed
            .get("crates/products/chio-api-protect/src/evaluator.rs")
            .ok_or_else(|| "API protect evaluator was not parsed".to_string())?,
        "RequestEvaluator::match_route_with_status",
        "PolicyDecision::DenyByDefault",
    )?;
    require_path(
        parsed
            .get("crates/kernel/chio-kernel/src/kernel/validation.rs")
            .ok_or_else(|| "kernel validation source was not parsed".to_string())?,
        "ChioKernel::verify_capability_full_pre_admit",
        "chio_kernel_core::NoopBudgetRegistry",
    )?;
    require_call_tokens(
        parsed
            .get("crates/kernel/chio-runtime-core/src/admission_hook/swarm_ref.rs")
            .ok_or_else(|| "swarm reference source was not parsed".to_string())?,
        "swarm_ref_from_request",
        "required_swarm_evidence_ref",
        &["\"routePlanReceipt\"", "\"routePlanReceiptSha256\""],
    )?;
    require_binary_tokens(
        parsed
            .get("crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs")
            .ok_or_else(|| "swarm authority source was not parsed".to_string())?,
        "verify_swarm_authority_reference_from_store",
        &[
            "continuation.route_plan_receipt_id",
            "reference.route_plan_receipt.evidence_id",
        ],
    )?;
    Ok(())
}

fn load_source_inventory(root: &Path) -> Result<SourceInventory, String> {
    let path = root.join(SOURCE_INVENTORY_PATH);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot stat {SOURCE_INVENTORY_PATH}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "adapter source inventory is not a regular file: {SOURCE_INVENTORY_PATH}"
        ));
    }
    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {SOURCE_INVENTORY_PATH}: {error}"))?;
    let inventory: SourceInventory = toml::from_str(&raw)
        .map_err(|error| format!("cannot parse {SOURCE_INVENTORY_PATH}: {error}"))?;
    if inventory.schema != "chio.adapter-source-inventory.v1" {
        return Err(format!(
            "unknown adapter source inventory schema: {}",
            inventory.schema
        ));
    }
    validate_unique_strings("crate_name_markers", &inventory.crate_name_markers, false)?;
    validate_unique_strings("explicit_roots", &inventory.explicit_roots, true)?;
    validate_unique_strings("contract_sources", &inventory.contract_sources, true)?;
    Ok(inventory)
}

fn validate_unique_strings(label: &str, values: &[String], paths: bool) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!(
            "adapter source inventory {label} must not be empty"
        ));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        if value.is_empty() || value.trim() != value {
            return Err(format!(
                "adapter source inventory {label} contains an empty or padded value"
            ));
        }
        if paths {
            let path = Path::new(value);
            if path.is_absolute()
                || !path.starts_with("crates")
                || path
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(format!(
                    "adapter source inventory {label} contains an unsafe path: {value}"
                ));
            }
        } else if !value
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '-')
        {
            return Err(format!(
                "adapter source inventory {label} contains an invalid marker: {value}"
            ));
        }
        if !unique.insert(value) {
            return Err(format!(
                "adapter source inventory {label} contains a duplicate: {value}"
            ));
        }
    }
    Ok(())
}

fn validate_contract_source_registry(inventory: &SourceInventory) -> Result<(), String> {
    let expected = CALL_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect::<BTreeSet<_>>();
    let actual = inventory
        .contract_sources
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
        let extra = actual.difference(&expected).copied().collect::<Vec<_>>();
        return Err(format!(
            "adapter contract source registry mismatch: missing={missing:?} extra={extra:?}"
        ));
    }
    Ok(())
}

fn parse_repo_source(root: &Path, relative: impl AsRef<Path>) -> Result<SourceFacts, String> {
    let relative = relative.as_ref();
    let absolute = root.join(relative);
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|error| format!("cannot stat {}: {error}", display_path(relative)))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "production Rust source is not a regular file: {}",
            display_path(relative)
        ));
    }
    let source = fs::read_to_string(&absolute)
        .map_err(|error| format!("cannot read {}: {error}", display_path(relative)))?;
    parse_source(&source, &display_path(relative))
}

fn discover_adapter_sources(
    root: &Path,
    inventory: &SourceInventory,
) -> Result<Vec<String>, String> {
    let mut roots = Vec::new();
    let crates = root.join("crates");
    for group in read_dirs(&crates)? {
        for candidate in read_dirs(&group)? {
            let Some(name) = candidate.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if inventory
                .crate_name_markers
                .iter()
                .any(|marker| name.contains(marker))
            {
                roots.push(candidate.join("src"));
            }
        }
    }
    for explicit in &inventory.explicit_roots {
        let path = root.join(explicit);
        roots.push(path);
    }

    let mut files = Vec::new();
    for source_root in roots {
        collect_rust_sources(root, &source_root, &mut files)?;
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Err("adapter source discovery produced no Rust files".to_string());
    }
    Ok(files)
}

fn read_dirs(path: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(path)
        .map_err(|error| format!("cannot read directory {}: {error}", display_path(path)))?;
    let mut directories = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read directory entry under {}: {error}",
                display_path(path)
            )
        })?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", display_path(&entry.path())))?;
        if file_type.is_dir() {
            directories.push(entry.path());
        }
    }
    directories.sort();
    Ok(directories)
}

fn collect_rust_sources(root: &Path, path: &Path, files: &mut Vec<String>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot stat directory {}: {error}", display_path(path)))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "adapter source root is not a regular directory: {}",
            display_path(path)
        ));
    }
    for entry in fs::read_dir(path)
        .map_err(|error| format!("cannot read directory {}: {error}", display_path(path)))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read directory entry under {}: {error}",
                display_path(path)
            )
        })?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", display_path(&entry.path())))?;
        if file_type.is_symlink() {
            return Err(format!(
                "adapter source tree contains a symlink: {}",
                display_path(&entry.path())
            ));
        }
        if file_type.is_dir() {
            collect_rust_sources(root, &entry.path(), files)?;
            continue;
        }
        let candidate = entry.path();
        if !file_type.is_file()
            || candidate.extension().and_then(|value| value.to_str()) != Some("rs")
        {
            continue;
        }
        let relative = candidate.strip_prefix(root).map_err(|_| {
            format!(
                "adapter source escaped workspace: {}",
                display_path(&candidate)
            )
        })?;
        if is_test_path(relative) {
            continue;
        }
        files.push(relative.to_string_lossy().replace('\\', "/"));
    }
    Ok(())
}

fn is_test_path(path: &Path) -> bool {
    path.components().any(|part| part.as_os_str() == "tests")
        || path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
}

fn parse_source(source: &str, label: &str) -> Result<SourceFacts, String> {
    let syntax = syn::parse_file(source)
        .map_err(|error| format!("cannot parse production Rust source {label}: {error}"))?;
    let mut visitor = FunctionVisitor::default();
    visitor.visit_file(&syntax);
    let mut functions = BTreeMap::new();
    for (name, facts) in visitor.functions {
        if functions.insert(name.clone(), facts).is_some() {
            return Err(format!("duplicate function identity in {label}: {name}"));
        }
    }
    Ok(SourceFacts { functions })
}

#[derive(Default)]
struct FunctionVisitor {
    owner: Option<String>,
    functions: Vec<(String, FunctionFacts)>,
}

impl<'ast> Visit<'ast> for FunctionVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if test_only(&node.attrs) {
            return;
        }
        let previous = self.owner.take();
        self.owner = impl_name(node);
        visit::visit_item_impl(self, node);
        self.owner = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !test_only(&node.attrs) {
            self.record_function(node.sig.ident.to_string(), &node.attrs, &node.block);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if test_only(&node.attrs) {
            return;
        }
        let name = match &self.owner {
            Some(owner) => format!("{owner}::{}", node.sig.ident),
            None => node.sig.ident.to_string(),
        };
        self.record_function(name, &node.attrs, &node.block);
    }
}

impl FunctionVisitor {
    fn record_function(&mut self, name: String, attrs: &[Attribute], block: &syn::Block) {
        let mut body = BodyVisitor::default();
        body.visit_block(block);
        self.functions.push((
            name,
            FunctionFacts {
                compatibility_surface: attrs.iter().any(|attribute| {
                    normalize_tokens(attribute).contains("feature=\"compatibility-surface\"")
                }),
                calls: body.calls,
                paths: body.paths,
                binaries: body.binaries,
                dangerous: body.dangerous,
            },
        ));
    }
}

#[derive(Default)]
struct BodyVisitor {
    calls: Vec<CallFact>,
    paths: BTreeSet<String>,
    binaries: Vec<String>,
    dangerous: Vec<DangerousCall>,
}

impl<'ast> Visit<'ast> for BodyVisitor {
    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let target = normalize_tokens(node.func.as_ref());
        if target.ends_with("Command::new") {
            self.dangerous.push(DangerousCall {
                kind: DangerousKind::CommandNew,
                receiver: None,
            });
        }
        self.calls.push(CallFact {
            target,
            tokens: normalize_tokens(node),
        });
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let receiver = normalize_tokens(node.receiver.as_ref());
        let method = node.method.to_string();
        let kind = match method.as_str() {
            "spawn" => Some(DangerousKind::Spawn),
            "invoke" => Some(DangerousKind::Invoke),
            _ => None,
        };
        if let Some(kind) = kind {
            self.dangerous.push(DangerousCall {
                kind,
                receiver: Some(receiver.clone()),
            });
        }
        self.calls.push(CallFact {
            target: format!("{receiver}.{method}"),
            tokens: normalize_tokens(node),
        });
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        self.paths.insert(normalize_tokens(node));
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        self.binaries.push(normalize_tokens(node));
        visit::visit_expr_binary(self, node);
    }
}

fn type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn impl_name(node: &ItemImpl) -> Option<String> {
    let self_type = type_name(&node.self_ty)?;
    match &node.trait_ {
        Some((_, trait_path, _)) => {
            Some(format!("<{self_type} as {}>", normalize_tokens(trait_path)))
        }
        None => Some(self_type),
    }
}

fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        let path = normalize_tokens(attribute.path());
        path == "test" || path.ends_with("::test") || normalize_tokens(attribute) == "#[cfg(test)]"
    })
}

fn normalize_tokens(tokens: &impl ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn validate_dangerous_calls(
    sources: &BTreeMap<String, SourceFacts>,
    require_all_rules: bool,
) -> Result<(), String> {
    let mut observed = vec![0_usize; EXCEPTION_RULES.len()];
    for (path, source) in sources {
        for (function, facts) in &source.functions {
            for call in &facts.dangerous {
                let matching: Vec<usize> = EXCEPTION_RULES
                    .iter()
                    .enumerate()
                    .filter_map(|(index, rule)| {
                        (rule.path == path
                            && rule.function == function
                            && rule.kind == call.kind
                            && rule.receiver.map(str::to_string) == call.receiver)
                            .then_some(index)
                    })
                    .collect();
                if matching.len() != 1 {
                    return Err(format!(
                        "unregistered production side effect {} in {path}::{function}",
                        call.kind.label()
                    ));
                }
                let index = matching[0];
                let rule = EXCEPTION_RULES[index];
                if rule.compatibility_only && !facts.compatibility_surface {
                    return Err(format!(
                        "{} exception lacks compatibility-surface cfg in {path}::{function}",
                        rule.class
                    ));
                }
                observed[index] += 1;
            }
        }
    }
    if require_all_rules {
        for (rule, count) in EXCEPTION_RULES.iter().zip(observed) {
            if count != 1 {
                return Err(format!(
                    "side-effect exception must match exactly once: {} {}::{} matched {count}",
                    rule.class, rule.path, rule.function
                ));
            }
        }
    }
    Ok(())
}

fn require_call(source: &SourceFacts, contract: &CallContract) -> Result<(), String> {
    let facts = source.functions.get(contract.function).ok_or_else(|| {
        format!(
            "mediation contract function missing: {}::{}",
            contract.path, contract.function
        )
    })?;
    let count = facts
        .calls
        .iter()
        .filter(|call| call.target == contract.target)
        .count();
    if count < contract.minimum {
        return Err(format!(
            "mediation contract call missing: {}::{} requires {} at least {} time(s)",
            contract.path, contract.function, contract.target, contract.minimum
        ));
    }
    Ok(())
}

fn require_path(source: &SourceFacts, function: &str, path: &str) -> Result<(), String> {
    let facts = source
        .functions
        .get(function)
        .ok_or_else(|| format!("mediation contract function missing: {function}"))?;
    if !facts.paths.contains(path) {
        return Err(format!(
            "mediation contract path missing: {function} requires {path}"
        ));
    }
    Ok(())
}

fn require_call_tokens(
    source: &SourceFacts,
    function: &str,
    target: &str,
    fragments: &[&str],
) -> Result<(), String> {
    let facts = source
        .functions
        .get(function)
        .ok_or_else(|| format!("mediation contract function missing: {function}"))?;
    let matched = facts.calls.iter().any(|call| {
        call.target == target
            && fragments
                .iter()
                .all(|fragment| call.tokens.contains(fragment))
    });
    if !matched {
        return Err(format!(
            "mediation contract call arguments missing: {function}::{target}"
        ));
    }
    Ok(())
}

fn require_binary_tokens(
    source: &SourceFacts,
    function: &str,
    fragments: &[&str],
) -> Result<(), String> {
    let facts = source
        .functions
        .get(function)
        .ok_or_else(|| format!("mediation contract function missing: {function}"))?;
    if !facts
        .binaries
        .iter()
        .any(|binary| fragments.iter().all(|fragment| binary.contains(fragment)))
    {
        return Err(format!("mediation contract comparison missing: {function}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_fixture(path: &str, source: &str) -> Result<(), String> {
        let mut sources = BTreeMap::new();
        sources.insert(path.to_string(), parse_source(source, path)?);
        validate_dangerous_calls(&sources, false)
    }

    #[test]
    fn comments_strings_and_unrelated_functions_do_not_mediate_command_new() {
        let source = r#"
            fn evaluate() {}
            fn unrelated() {
                let _text = "kernel evaluate";
                // kernel.evaluate();
                let _child = Command::new("tool");
            }
        "#;
        assert!(
            validate_fixture("crates/protocol/chio-example-adapter/src/lib.rs", source).is_err()
        );
    }

    #[test]
    fn unrelated_evaluate_function_does_not_mediate_spawn() {
        let source = r#"
            fn evaluate() {}
            fn run_side_effect(mut command: Command) {
                let _child = command.spawn();
            }
        "#;
        assert!(validate_fixture("crates/protocol/chio-example-edge/src/lib.rs", source).is_err());
    }

    #[test]
    fn unrelated_kernel_function_does_not_mediate_invoke() {
        let source = r#"
            fn kernel() {}
            fn run_side_effect(server: &dyn Server) {
                let _result = server.invoke("tool");
            }
        "#;
        assert!(validate_fixture("crates/protocol/chio-example-proxy/src/lib.rs", source).is_err());
    }

    #[test]
    fn cfg_test_impls_are_ignored() {
        let source = r#"
            struct TestTransport;
            #[cfg(test)]
            impl TestTransport {
                fn run_side_effect(server: &dyn Server) {
                    let _result = server.invoke("tool");
                }
            }
        "#;
        assert!(validate_fixture("crates/protocol/chio-example-edge/src/lib.rs", source).is_ok());
    }

    #[test]
    fn inherent_and_trait_methods_with_the_same_name_do_not_merge() {
        let source = r#"
            trait Authority {
                fn evaluate(&self);
            }
            struct Adapter;
            impl Adapter {
                fn evaluate(&self) {}
            }
            impl Authority for Adapter {
                fn evaluate(&self) {
                    self.authority.evaluate();
                }
            }
        "#;
        let facts = match parse_source(source, "fixture.rs") {
            Ok(facts) => facts,
            Err(error) => panic!("fixture must parse: {error}"),
        };
        assert!(facts.functions.contains_key("Adapter::evaluate"));
        assert!(facts
            .functions
            .contains_key("<Adapter as Authority>::evaluate"));
        let contract = CallContract {
            path: "fixture.rs",
            function: "Adapter::evaluate",
            target: "self.authority.evaluate",
            minimum: 1,
        };
        assert!(require_call(&facts, &contract).is_err());
    }

    #[test]
    fn compatibility_exception_requires_the_feature_cfg() {
        let source = r#"
            struct ChioA2aEdge;
            impl ChioA2aEdge {
                fn handle_send_message_passthrough(&self, server: &dyn Server) {
                    let _result = server.invoke("tool");
                }
            }
        "#;
        assert!(validate_fixture("crates/protocol/chio-a2a-edge/src/edge.rs", source).is_err());
    }

    #[test]
    fn explicit_compatibility_exception_is_accepted() {
        let source = r#"
            struct ChioA2aEdge;
            impl ChioA2aEdge {
                #[cfg(any(test, feature = "compatibility-surface"))]
                fn handle_send_message_passthrough(&self, server: &dyn Server) {
                    let _result = server.invoke("tool");
                }
            }
        "#;
        assert!(validate_fixture("crates/protocol/chio-a2a-edge/src/edge.rs", source).is_ok());
    }

    #[test]
    fn process_lifecycle_exception_is_function_scoped() {
        let source = r#"
            struct AcpTransport;
            impl AcpTransport {
                fn spawn(command: &str) {
                    let mut cmd = Command::new(command);
                    let _child = cmd.spawn();
                }
            }
        "#;
        assert!(
            validate_fixture("crates/protocol/chio-acp-proxy/src/transport.rs", source).is_ok()
        );
    }

    #[test]
    fn strings_do_not_satisfy_named_call_contracts() {
        let source = r#"
            struct RequestEvaluator;
            impl RequestEvaluator {
                fn evaluate_with_execution_nonce(&self) {
                    let _text = "self.authority.evaluate";
                }
            }
        "#;
        let facts = match parse_source(source, "fixture.rs") {
            Ok(facts) => facts,
            Err(error) => panic!("fixture must parse: {error}"),
        };
        let contract = CallContract {
            path: "fixture.rs",
            function: "RequestEvaluator::evaluate_with_execution_nonce",
            target: "self.authority.evaluate",
            minimum: 1,
        };
        assert!(require_call(&facts, &contract).is_err());
    }
}
