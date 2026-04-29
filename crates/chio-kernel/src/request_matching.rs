use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{ModelMetadata, ModelSafetyTier};
use dashmap::DashMap;
use regex::Regex;

use crate::session::SessionRequestStart;

use super::*;

pub(super) fn session_from_map(
    sessions: &DashMap<SessionId, Arc<Session>>,
    session_id: &SessionId,
) -> Result<Arc<Session>, KernelError> {
    sessions
        .get(session_id)
        .map(|session| Arc::clone(session.value()))
        .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))
}

pub(super) fn begin_session_request_in_sessions(
    sessions: &DashMap<SessionId, Arc<Session>>,
    context: &OperationContext,
    operation_kind: OperationKind,
    cancellable: bool,
) -> Result<SessionRequestStart, KernelError> {
    let session = session_from_map(sessions, &context.session_id)?;
    Ok(session.track_request(context, operation_kind, cancellable)?)
}

pub(super) fn begin_child_request_in_sessions(
    sessions: &DashMap<SessionId, Arc<Session>>,
    parent_context: &OperationContext,
    request_id: RequestId,
    operation_kind: OperationKind,
    progress_token: Option<ProgressToken>,
    cancellable: bool,
) -> Result<(OperationContext, SessionRequestStart), KernelError> {
    let parent_session = session_from_map(sessions, &parent_context.session_id)?;
    parent_session.validate_context(parent_context)?;

    let child_context = OperationContext {
        session_id: parent_context.session_id.clone(),
        request_id,
        agent_id: parent_context.agent_id.clone(),
        parent_request_id: Some(parent_context.request_id.clone()),
        progress_token,
    };
    let start =
        begin_session_request_in_sessions(sessions, &child_context, operation_kind, cancellable)?;
    Ok((child_context, start))
}

pub(super) fn complete_session_request_with_terminal_state_in_sessions(
    sessions: &DashMap<SessionId, Arc<Session>>,
    session_id: &SessionId,
    request_id: &RequestId,
    terminal_state: OperationTerminalState,
) -> Result<(), KernelError> {
    session_from_map(sessions, session_id)?
        .complete_request_with_terminal_state(request_id, terminal_state)?;
    Ok(())
}

pub(super) fn validate_sampling_request_in_sessions(
    sessions: &DashMap<SessionId, Arc<Session>>,
    allow_sampling: bool,
    allow_sampling_tool_use: bool,
    context: &OperationContext,
    operation: &CreateMessageOperation,
) -> Result<(), KernelError> {
    let session = session_from_map(sessions, &context.session_id)?;
    session.validate_context(context)?;
    session.ensure_operation_allowed(OperationKind::CreateMessage)?;

    let parent_request_id = context
        .parent_request_id
        .as_ref()
        .ok_or(KernelError::InvalidChildRequestParent)?;
    session.validate_parent_request_lineage(&context.request_id, parent_request_id)?;

    if !allow_sampling {
        return Err(KernelError::SamplingNotAllowedByPolicy);
    }

    let peer_capabilities = session.peer_capabilities();
    if !peer_capabilities.supports_sampling {
        return Err(KernelError::SamplingNotNegotiated);
    }

    if matches!(
        operation.include_context.as_deref(),
        Some("thisServer") | Some("allServers")
    ) && !peer_capabilities.sampling_context
    {
        return Err(KernelError::SamplingContextNotSupported);
    }

    let requests_tool_use = !operation.tools.is_empty()
        || operation
            .tool_choice
            .as_ref()
            .is_some_and(|choice| choice.mode != "none");
    if requests_tool_use {
        if !allow_sampling_tool_use {
            return Err(KernelError::SamplingToolUseNotAllowedByPolicy);
        }
        if !peer_capabilities.sampling_tools {
            return Err(KernelError::SamplingToolUseNotNegotiated);
        }
    }

    Ok(())
}

pub(super) fn validate_elicitation_request_in_sessions(
    sessions: &DashMap<SessionId, Arc<Session>>,
    allow_elicitation: bool,
    context: &OperationContext,
    operation: &CreateElicitationOperation,
) -> Result<(), KernelError> {
    let session = session_from_map(sessions, &context.session_id)?;
    session.validate_context(context)?;
    session.ensure_operation_allowed(OperationKind::CreateElicitation)?;

    let parent_request_id = context
        .parent_request_id
        .as_ref()
        .ok_or(KernelError::InvalidChildRequestParent)?;
    session.validate_parent_request_lineage(&context.request_id, parent_request_id)?;

    if !allow_elicitation {
        return Err(KernelError::ElicitationNotAllowedByPolicy);
    }

    let peer_capabilities = session.peer_capabilities();
    if !peer_capabilities.supports_elicitation {
        return Err(KernelError::ElicitationNotNegotiated);
    }

    match operation {
        CreateElicitationOperation::Form { .. } => {
            if !peer_capabilities.elicitation_form {
                return Err(KernelError::ElicitationFormNotSupported);
            }
        }
        CreateElicitationOperation::Url { .. } => {
            if !peer_capabilities.elicitation_url {
                return Err(KernelError::ElicitationUrlNotSupported);
            }
        }
    }

    Ok(())
}

pub(super) fn nested_child_request_id(parent_request_id: &RequestId, suffix: &str) -> RequestId {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    RequestId::new(format!("{parent_request_id}-{suffix}-{nonce}"))
}

pub(super) fn check_time_bounds(cap: &CapabilityToken, now: u64) -> Result<(), KernelError> {
    if now >= cap.expires_at {
        return Err(KernelError::CapabilityExpired);
    }
    if now < cap.issued_at {
        return Err(KernelError::CapabilityNotYetValid);
    }
    Ok(())
}

pub(super) fn check_subject_binding(
    cap: &CapabilityToken,
    agent_id: &str,
) -> Result<(), KernelError> {
    let expected = cap.subject.to_hex();
    if expected == agent_id {
        Ok(())
    } else {
        Err(KernelError::SubjectMismatch {
            expected,
            actual: agent_id.to_string(),
        })
    }
}

pub fn capability_matches_request(
    cap: &CapabilityToken,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
) -> Result<bool, KernelError> {
    capability_matches_request_with_model_metadata(cap, tool_name, server_id, arguments, None)
}

pub fn capability_matches_request_with_model_metadata(
    cap: &CapabilityToken,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
    model_metadata: Option<&ModelMetadata>,
) -> Result<bool, KernelError> {
    Ok(!resolve_matching_grants(cap, tool_name, server_id, arguments, model_metadata)?.is_empty())
}

pub fn capability_matches_resource_request(
    cap: &CapabilityToken,
    uri: &str,
) -> Result<bool, KernelError> {
    Ok(cap
        .scope
        .resource_grants
        .iter()
        .any(|grant| resource_grant_matches_request(grant, uri)))
}

pub fn capability_matches_resource_subscription(
    cap: &CapabilityToken,
    uri: &str,
) -> Result<bool, KernelError> {
    Ok(cap
        .scope
        .resource_grants
        .iter()
        .any(|grant| resource_grant_matches_subscription(grant, uri)))
}

pub fn capability_matches_resource_pattern(
    cap: &CapabilityToken,
    pattern: &str,
) -> Result<bool, KernelError> {
    Ok(cap.scope.resource_grants.iter().any(|grant| {
        resource_pattern_matches(&grant.uri_pattern, pattern)
            && grant.operations.contains(&Operation::Read)
    }))
}

pub fn capability_matches_prompt_request(
    cap: &CapabilityToken,
    prompt_name: &str,
) -> Result<bool, KernelError> {
    Ok(cap
        .scope
        .prompt_grants
        .iter()
        .any(|grant| prompt_grant_matches_request(grant, prompt_name)))
}

pub(super) fn resolve_matching_grants<'a>(
    cap: &'a CapabilityToken,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
    model_metadata: Option<&ModelMetadata>,
) -> Result<Vec<MatchingGrant<'a>>, KernelError> {
    let mut matches = Vec::new();

    for (index, grant) in cap.scope.grants.iter().enumerate() {
        if !grant_matches_request(grant, tool_name, server_id, arguments, model_metadata)? {
            continue;
        }

        matches.push(MatchingGrant {
            index,
            grant,
            specificity: (
                u8::from(grant.server_id == server_id),
                u8::from(grant.tool_name == tool_name),
                grant.constraints.len(),
            ),
        });
    }

    matches.sort_by(|left, right| {
        right
            .specificity
            .cmp(&left.specificity)
            .then_with(|| left.index.cmp(&right.index))
    });

    Ok(matches)
}

fn grant_matches_request(
    grant: &ToolGrant,
    tool_name: &str,
    server_id: &str,
    arguments: &serde_json::Value,
    model_metadata: Option<&ModelMetadata>,
) -> Result<bool, KernelError> {
    Ok(matches_server(&grant.server_id, server_id)
        && matches_name(&grant.tool_name, tool_name)
        && grant.operations.contains(&Operation::Invoke)
        && constraints_match(&grant.constraints, arguments, model_metadata)?)
}

fn matches_server(pattern: &str, server_id: &str) -> bool {
    pattern == "*" || pattern == server_id
}

fn matches_name(pattern: &str, name: &str) -> bool {
    pattern == "*" || pattern == name
}

fn constraints_match(
    constraints: &[Constraint],
    arguments: &serde_json::Value,
    model_metadata: Option<&ModelMetadata>,
) -> Result<bool, KernelError> {
    for constraint in constraints {
        if !constraint_matches(constraint, arguments, model_metadata)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn constraint_matches(
    constraint: &Constraint,
    arguments: &serde_json::Value,
    model_metadata: Option<&ModelMetadata>,
) -> Result<bool, KernelError> {
    let string_leaves = collect_string_leaves(arguments);

    match constraint {
        Constraint::PathPrefix(prefix) => {
            let candidates: Vec<&str> = string_leaves
                .iter()
                .filter(|leaf| {
                    leaf.key.as_deref().is_some_and(is_path_key) || looks_like_path(&leaf.value)
                })
                .map(|leaf| leaf.value.as_str())
                .collect();
            Ok(!candidates.is_empty()
                && candidates
                    .into_iter()
                    .all(|path| path_has_prefix(path, prefix)))
        }
        Constraint::DomainExact(expected) => {
            let expected = normalize_domain(expected);
            let domains = collect_domain_candidates(&string_leaves);
            Ok(!domains.is_empty() && domains.into_iter().all(|domain| domain == expected))
        }
        Constraint::DomainGlob(pattern) => {
            let pattern = pattern.to_ascii_lowercase();
            let domains = collect_domain_candidates(&string_leaves);
            Ok(!domains.is_empty()
                && domains
                    .into_iter()
                    .all(|domain| wildcard_matches(&pattern, &domain)))
        }
        Constraint::RegexMatch(pattern) => {
            let regex = Regex::new(pattern).map_err(|error| {
                KernelError::InvalidConstraint(format!(
                    "regex \"{pattern}\" failed to compile: {error}"
                ))
            })?;
            Ok(string_leaves.iter().any(|leaf| regex.is_match(&leaf.value)))
        }
        Constraint::MaxLength(max) => Ok(string_leaves.iter().all(|leaf| leaf.value.len() <= *max)),
        Constraint::MaxArgsSize(max) => Ok(arguments.to_string().len() <= *max),
        Constraint::GovernedIntentRequired
        | Constraint::RequireApprovalAbove { .. }
        | Constraint::SellerExact(_)
        | Constraint::MinimumRuntimeAssurance(_)
        | Constraint::MinimumAutonomyTier(_) => Ok(true),
        Constraint::Custom(key, expected) => Ok(argument_contains_custom(arguments, key, expected)),

        // Phase 2.2 additions. These constraints either require domain-
        // specific evaluation (SQL parsing, post-invocation result
        // inspection, or cross-request HITL state) that lives outside
        // this argument-matching stage, or they match against
        // well-known argument keys. Unless a specific check below
        // rejects the request, the constraint is accepted at this
        // stage and enforced by a downstream guard.
        Constraint::TableAllowlist(_)
        | Constraint::ColumnDenylist(_)
        | Constraint::MaxRowsReturned(_)
        | Constraint::OperationClass(_) => Ok(true),
        Constraint::ContentReviewTier(_) => Ok(false),
        Constraint::MaxTransactionAmountUsd(_) | Constraint::RequireDualApproval(_) => Ok(false),

        // Phase 2.3 / RTC-08: evaluate the model-routing constraint
        // against request-carried `model_metadata`. The separate
        // provenance class rides on the metadata for receipt and audit
        // surfaces; routing checks compare the concrete model identity
        // and safety tier only.
        Constraint::ModelConstraint {
            allowed_model_ids,
            min_safety_tier,
        } => Ok(model_constraint_matches(
            allowed_model_ids,
            *min_safety_tier,
            model_metadata,
        )),

        Constraint::AudienceAllowlist(allowed) => {
            Ok(audience_allowlist_matches(arguments, allowed))
        }
        Constraint::MemoryStoreAllowlist(allowed) => {
            Ok(memory_store_allowlist_matches(arguments, allowed))
        }
        Constraint::MemoryWriteDenyPatterns(patterns) => {
            memory_write_deny_patterns_match(arguments, patterns)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::capability::{
        CapabilityTokenBody, ChioScope, Constraint, ContentReviewTier, Operation, ToolGrant,
    };
    use chio_core::crypto::Keypair;

    fn capability_with_constraints(constraints: Vec<Constraint>) -> CapabilityToken {
        let issuer = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-request-matching".to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv".to_string(),
                        tool_name: "tool".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints,
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: 1,
                expires_at: u64::MAX,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("sign capability")
    }

    #[test]
    fn content_review_tier_fails_closed_without_review_guard_context() {
        let capability = capability_with_constraints(vec![Constraint::ContentReviewTier(
            ContentReviewTier::Strict,
        )]);
        assert!(
            !capability_matches_request(
                &capability,
                "tool",
                "srv",
                &serde_json::json!({"text": "review this outbound message"}),
            )
            .expect("evaluate request match"),
            "content review tier should deny until a review guard supplies runtime context"
        );
    }

    #[test]
    fn governed_transaction_constraints_fail_closed_without_specialized_enforcement() {
        let constraints = [
            Constraint::MaxTransactionAmountUsd("100.00".to_string()),
            Constraint::RequireDualApproval(true),
        ];

        for constraint in constraints {
            let capability = capability_with_constraints(vec![constraint]);
            assert!(
                !capability_matches_request(
                    &capability,
                    "tool",
                    "srv",
                    &serde_json::json!({"amount_usd": "25.00"}),
                )
                .expect("evaluate request match"),
                "governed transaction constraint should deny without its dedicated enforcement path"
            );
        }
    }

    #[test]
    fn path_prefix_constraint_rejects_traversal_and_sibling_prefixes() {
        let capability = capability_with_constraints(vec![Constraint::PathPrefix(
            "/workspace/safe".to_string(),
        )]);

        assert!(capability_matches_request(
            &capability,
            "tool",
            "srv",
            &serde_json::json!({"path": "/workspace/safe/report.txt"}),
        )
        .expect("allow matching path"),);
        assert!(!capability_matches_request(
            &capability,
            "tool",
            "srv",
            &serde_json::json!({"path": "/workspace/safe/../secret.txt"}),
        )
        .expect("deny traversal path"),);
        assert!(!capability_matches_request(
            &capability,
            "tool",
            "srv",
            &serde_json::json!({"path": "/workspace/safeX/report.txt"}),
        )
        .expect("deny sibling prefix"),);
    }

    #[test]
    fn audience_allowlist_rejects_non_string_values() {
        assert!(audience_allowlist_matches(
            &serde_json::json!({"recipient": "#ops"}),
            &["#ops".to_string()]
        ));
        assert!(!audience_allowlist_matches(
            &serde_json::json!({"recipient": {"channel": "#ops"}}),
            &["#ops".to_string()]
        ));
        assert!(!audience_allowlist_matches(
            &serde_json::json!({"recipients": []}),
            &["#ops".to_string()]
        ));
    }

    #[test]
    fn memory_store_allowlist_rejects_non_string_values() {
        assert!(memory_store_allowlist_matches(
            &serde_json::json!({"store": "session-cache"}),
            &["session-cache".to_string()]
        ));
        assert!(!memory_store_allowlist_matches(
            &serde_json::json!({"store": {"name": "session-cache"}}),
            &["session-cache".to_string()]
        ));
        assert!(!memory_store_allowlist_matches(
            &serde_json::json!({"store": null}),
            &["session-cache".to_string()]
        ));
    }
}

/// Evaluate `Constraint::ModelConstraint` against request-carried
/// `model_metadata`.
///
/// Denies (returns `false`) when:
/// - the constraint carries any requirement (non-empty `allowed_model_ids`
///   or `Some(min_safety_tier)`) and `model_metadata` is absent;
/// - `allowed_model_ids` is non-empty and the request's `model_id` is
///   not in the list;
/// - `min_safety_tier` is `Some` and the request's `safety_tier` is
///   `None` or strictly below the required tier (the ordering comes
///   from the `Ord` derive on `ModelSafetyTier`).
///
/// A constraint that specifies neither requirement is vacuously
/// satisfied and returns `true` regardless of whether metadata is
/// present.
fn model_constraint_matches(
    allowed_model_ids: &[String],
    min_safety_tier: Option<ModelSafetyTier>,
    model_metadata: Option<&ModelMetadata>,
) -> bool {
    let has_allowlist = !allowed_model_ids.is_empty();
    let has_tier_floor = min_safety_tier.is_some();
    if !has_allowlist && !has_tier_floor {
        return true;
    }

    let Some(metadata) = model_metadata else {
        return false;
    };

    if has_allowlist
        && !allowed_model_ids
            .iter()
            .any(|allowed| allowed == &metadata.model_id)
    {
        return false;
    }

    if let Some(required_tier) = min_safety_tier {
        match metadata.safety_tier {
            Some(actual) if actual >= required_tier => {}
            _ => return false,
        }
    }

    true
}

/// Returns true when no recipient-style argument is present, or when
/// every recipient value the call carries is in the allowlist.
///
/// Recognised argument keys: `recipient`, `recipients`, `audience`,
/// `to`, `channel`, `channels`. Nested objects and arrays are walked.
fn audience_allowlist_matches(arguments: &serde_json::Value, allowed: &[String]) -> bool {
    let mut observed = ObservedStringValues::default();
    collect_audience_values(arguments, &mut observed);
    if observed.invalid {
        return false;
    }
    if !observed.saw_relevant_key {
        return true;
    }
    observed
        .values
        .iter()
        .all(|value| allowed.iter().any(|a| a == value))
}

fn collect_audience_values(arguments: &serde_json::Value, out: &mut ObservedStringValues) {
    match arguments {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if is_audience_key(key) {
                    let before = out.values.len();
                    out.saw_relevant_key = true;
                    if !collect_string_values_strict(value, &mut out.values)
                        || out.values.len() == before
                    {
                        out.invalid = true;
                    }
                } else {
                    collect_audience_values(value, out);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_audience_values(value, out);
            }
        }
        _ => {}
    }
}

fn is_audience_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "recipient" | "recipients" | "audience" | "to" | "channel" | "channels"
    )
}

fn collect_string_values_strict(value: &serde_json::Value, out: &mut Vec<String>) -> bool {
    match value {
        serde_json::Value::String(s) => {
            out.push(s.clone());
            true
        }
        serde_json::Value::Array(values) => {
            for v in values {
                if !collect_string_values_strict(v, out) {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

/// Returns true when no `store` argument is present, or when every
/// `store` value the call carries is in the allowlist.
fn memory_store_allowlist_matches(arguments: &serde_json::Value, allowed: &[String]) -> bool {
    let mut observed = ObservedStringValues::default();
    collect_memory_store_values(arguments, &mut observed);
    if observed.invalid {
        return false;
    }
    if !observed.saw_relevant_key {
        return true;
    }
    observed
        .values
        .iter()
        .all(|value| allowed.iter().any(|a| a == value))
}

fn collect_memory_store_values(arguments: &serde_json::Value, out: &mut ObservedStringValues) {
    match arguments {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if is_memory_store_key(key) {
                    let before = out.values.len();
                    out.saw_relevant_key = true;
                    if !collect_string_values_strict(value, &mut out.values)
                        || out.values.len() == before
                    {
                        out.invalid = true;
                    }
                } else {
                    collect_memory_store_values(value, out);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_memory_store_values(value, out);
            }
        }
        _ => {}
    }
}

fn is_memory_store_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "store" | "memory_store" | "collection" | "namespace"
    )
}

/// Returns Ok(false) when any string leaf in the arguments matches any
/// deny pattern. An invalid regex surfaces as `InvalidConstraint`.
fn memory_write_deny_patterns_match(
    arguments: &serde_json::Value,
    patterns: &[String],
) -> Result<bool, KernelError> {
    let leaves = collect_string_leaves(arguments);
    for pattern in patterns {
        let regex = Regex::new(pattern).map_err(|error| {
            KernelError::InvalidConstraint(format!(
                "memory write deny pattern \"{pattern}\" failed to compile: {error}"
            ))
        })?;
        for leaf in &leaves {
            if regex.is_match(&leaf.value) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn resource_grant_matches_request(grant: &ResourceGrant, uri: &str) -> bool {
    resource_pattern_matches(&grant.uri_pattern, uri) && grant.operations.contains(&Operation::Read)
}

fn resource_grant_matches_subscription(grant: &ResourceGrant, uri: &str) -> bool {
    resource_pattern_matches(&grant.uri_pattern, uri)
        && grant.operations.contains(&Operation::Subscribe)
}

fn prompt_grant_matches_request(grant: &PromptGrant, prompt_name: &str) -> bool {
    matches_pattern(&grant.prompt_name, prompt_name) && grant.operations.contains(&Operation::Get)
}

fn resource_pattern_matches(pattern: &str, uri: &str) -> bool {
    matches_pattern(pattern, uri)
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    pattern == value
}

fn path_has_prefix(candidate: &str, prefix: &str) -> bool {
    let Some(candidate) = normalize_path(candidate) else {
        return false;
    };
    let Some(prefix) = normalize_path(prefix) else {
        return false;
    };
    if candidate.is_absolute != prefix.is_absolute {
        return false;
    }
    if prefix.segments.len() > candidate.segments.len() {
        return false;
    }
    prefix
        .segments
        .iter()
        .zip(candidate.segments.iter())
        .all(|(expected, actual)| expected == actual)
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedPath {
    is_absolute: bool,
    segments: Vec<String>,
}

fn normalize_path(path: &str) -> Option<NormalizedPath> {
    let is_absolute = path.starts_with('/') || path.starts_with('\\');
    let mut segments = Vec::new();
    for segment in path.split(['/', '\\']) {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            segments.pop()?;
            continue;
        }
        segments.push(segment.to_string());
    }
    Some(NormalizedPath {
        is_absolute,
        segments,
    })
}

#[derive(Clone)]
struct StringLeaf {
    key: Option<String>,
    value: String,
}

#[derive(Default)]
struct ObservedStringValues {
    values: Vec<String>,
    saw_relevant_key: bool,
    invalid: bool,
}

fn collect_string_leaves(arguments: &serde_json::Value) -> Vec<StringLeaf> {
    let mut leaves = Vec::new();
    collect_string_leaves_inner(arguments, None, &mut leaves);
    leaves
}

fn collect_string_leaves_inner(
    arguments: &serde_json::Value,
    current_key: Option<&str>,
    leaves: &mut Vec<StringLeaf>,
) {
    match arguments {
        serde_json::Value::String(value) => leaves.push(StringLeaf {
            key: current_key.map(str::to_string),
            value: value.clone(),
        }),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_string_leaves_inner(value, current_key, leaves);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                collect_string_leaves_inner(value, Some(key), leaves);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn is_path_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("path")
        || matches!(
            key.as_str(),
            "file" | "filepath" | "dir" | "directory" | "root" | "cwd"
        )
}

fn looks_like_path(value: &str) -> bool {
    !value.contains("://")
        && (value.starts_with('/')
            || value.starts_with("./")
            || value.starts_with("../")
            || value.starts_with("~/")
            || value.contains('/')
            || value.contains('\\'))
}

fn collect_domain_candidates(string_leaves: &[StringLeaf]) -> Vec<String> {
    string_leaves
        .iter()
        .filter_map(|leaf| parse_domain(&leaf.value))
        .collect()
}

fn parse_domain(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let host_port = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else {
        trimmed
    };

    let authority = host_port
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(host_port)
        .rsplit('@')
        .next()
        .unwrap_or(host_port);
    let host = authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .trim_matches('.');
    let normalized = normalize_domain(host);

    if normalized == "localhost"
        || (!normalized.is_empty()
            && normalized.contains('.')
            && normalized.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '.'
            }))
    {
        Some(normalized)
    } else {
        None
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_matches('.').to_ascii_lowercase()
}

fn wildcard_matches(pattern: &str, candidate: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let candidate_chars: Vec<char> = candidate.chars().collect();
    let (mut pattern_idx, mut candidate_idx) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while candidate_idx < candidate_chars.len() {
        if pattern_idx < pattern_chars.len()
            && (pattern_chars[pattern_idx] == candidate_chars[candidate_idx]
                || pattern_chars[pattern_idx] == '*')
        {
            if pattern_chars[pattern_idx] == '*' {
                star_idx = Some(pattern_idx);
                match_idx = candidate_idx;
                pattern_idx += 1;
            } else {
                pattern_idx += 1;
                candidate_idx += 1;
            }
        } else if let Some(star_position) = star_idx {
            pattern_idx = star_position + 1;
            match_idx += 1;
            candidate_idx = match_idx;
        } else {
            return false;
        }
    }

    while pattern_idx < pattern_chars.len() && pattern_chars[pattern_idx] == '*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern_chars.len()
}

fn argument_contains_custom(arguments: &serde_json::Value, key: &str, expected: &str) -> bool {
    match arguments {
        serde_json::Value::Object(map) => map.iter().any(|(entry_key, value)| {
            (entry_key == key && value.as_str() == Some(expected))
                || argument_contains_custom(value, key, expected)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| argument_contains_custom(value, key, expected)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => false,
    }
}
