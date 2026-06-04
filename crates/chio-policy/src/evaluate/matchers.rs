// ---------------------------------------------------------------------------
// Condition filtering
// ---------------------------------------------------------------------------

fn apply_conditions(
    spec: &HushSpec,
    context: &RuntimeContext,
    conditions: &HashMap<String, Condition>,
) -> HushSpec {
    let mut effective = spec.clone();

    if let Some(rules) = &mut effective.rules {
        for (block_name, condition) in conditions {
            if !evaluate_condition(condition, context) && !rules.clear_block(block_name) {
                debug_assert!(
                    false,
                    "unknown condition block name `{block_name}`; \
                     validate_condition_keys should have rejected it"
                );
            }
        }
    }

    effective
}

// ---------------------------------------------------------------------------
// Per-action-type evaluators
// ---------------------------------------------------------------------------

fn evaluate_tool_call(
    spec: &HushSpec,
    action: &EvaluationAction,
    matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    let base_rule = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.tool_access.as_ref())
        .filter(|rule| rule.enabled);
    let profile_rule = matched_profile
        .and_then(|profile| profile.tool_access.as_ref())
        .filter(|rule| rule.enabled);

    if base_rule.is_none() && profile_rule.is_none() {
        return allow_result(None, None, origin_profile_id, posture);
    }

    let target = action.target.as_deref().unwrap_or_default();
    let profile_prefix =
        matched_profile.map(|profile| profile_rule_prefix(&profile.id, "tool_access"));
    let actual_runtime_tier = action
        .runtime_attestation
        .as_ref()
        .filter(|attestation| attestation.valid)
        .map(|attestation| attestation.tier)
        .unwrap_or(chio_core::capability::RuntimeAssuranceTier::None);
    let actual_workload_identity = action
        .runtime_attestation
        .as_ref()
        .filter(|attestation| attestation.valid)
        .and_then(|attestation| attestation.workload_identity.as_ref());

    // max_args_size check
    let smallest_arg_limit = [
        base_rule.and_then(|rule| {
            rule.max_args_size
                .map(|max| (max, "rules.tool_access.max_args_size".to_string()))
        }),
        profile_rule.and_then(|rule| {
            profile_prefix.as_ref().and_then(|prefix| {
                rule.max_args_size
                    .map(|max| (max, format!("{prefix}.max_args_size")))
            })
        }),
    ]
    .into_iter()
    .flatten()
    .min_by_key(|(max, _)| *max);

    if let Some((max_args_size, matched_rule)) = smallest_arg_limit {
        if action.args_size.unwrap_or_default() > max_args_size {
            return deny_result(
                Some(matched_rule),
                Some("tool arguments exceeded max_args_size".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }

    // Block list
    if let Some(rule) = base_rule {
        let matched = match find_first_match_or_deny(
            target,
            &rule.block,
            "rules.tool_access.block",
            origin_profile_id.clone(),
            posture.clone(),
        ) {
            Ok(matched) => matched,
            Err(result) => return *result,
        };
        if matched.is_some() {
            return deny_result(
                Some("rules.tool_access.block".to_string()),
                Some("tool is explicitly blocked".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }
    if let Some(prefix) = profile_prefix.as_ref() {
        if let Some(rule) = profile_rule {
            let field = format!("{prefix}.block");
            let matched = match find_first_match_or_deny(
                target,
                &rule.block,
                &field,
                origin_profile_id.clone(),
                posture.clone(),
            ) {
                Ok(matched) => matched,
                Err(result) => return *result,
            };
            if matched.is_some() {
                return deny_result(
                    Some(field),
                    Some("tool is explicitly blocked".to_string()),
                    origin_profile_id,
                    posture,
                );
            }
        }
    }

    let required_runtime_tier = [
        base_rule.and_then(|rule| rule.require_runtime_assurance_tier),
        profile_rule.and_then(|rule| rule.require_runtime_assurance_tier),
    ]
    .into_iter()
    .flatten()
    .max();
    if let Some(required_runtime_tier) = required_runtime_tier {
        if actual_runtime_tier < required_runtime_tier {
            let matched_rule = if profile_rule
                .and_then(|rule| rule.require_runtime_assurance_tier)
                .is_some()
            {
                profile_prefix
                    .as_ref()
                    .map(|prefix| format!("{prefix}.require_runtime_assurance_tier"))
            } else {
                Some("rules.tool_access.require_runtime_assurance_tier".to_string())
            };
            return deny_result(
                matched_rule,
                Some(format!(
                    "runtime assurance tier '{actual_runtime_tier:?}' is below required '{required_runtime_tier:?}'"
                )),
                origin_profile_id,
                posture,
            );
        }
    }

    let preferred_runtime_tier = [
        base_rule.and_then(|rule| rule.prefer_runtime_assurance_tier),
        profile_rule.and_then(|rule| rule.prefer_runtime_assurance_tier),
    ]
    .into_iter()
    .flatten()
    .max();
    if let Some(preferred_runtime_tier) = preferred_runtime_tier {
        if actual_runtime_tier < preferred_runtime_tier {
            let matched_rule = if profile_rule
                .and_then(|rule| rule.prefer_runtime_assurance_tier)
                .is_some()
            {
                profile_prefix
                    .as_ref()
                    .map(|prefix| format!("{prefix}.prefer_runtime_assurance_tier"))
            } else {
                Some("rules.tool_access.prefer_runtime_assurance_tier".to_string())
            };
            return warn_result(
                matched_rule,
                Some(format!(
                    "runtime assurance tier '{actual_runtime_tier:?}' is below preferred '{preferred_runtime_tier:?}'"
                )),
                origin_profile_id,
                posture,
            );
        }
    }

    let required_workload_identity = [
        base_rule.and_then(|rule| rule.require_workload_identity.as_ref()),
        profile_rule.and_then(|rule| rule.require_workload_identity.as_ref()),
    ]
    .into_iter()
    .flatten()
    .last();
    if let Some(required_workload_identity) = required_workload_identity {
        let matched = actual_workload_identity
            .is_some_and(|actual| workload_identity_matches(required_workload_identity, actual));
        if !matched {
            let matched_rule = if profile_rule
                .and_then(|rule| rule.require_workload_identity.as_ref())
                .is_some()
            {
                profile_prefix
                    .as_ref()
                    .map(|prefix| format!("{prefix}.require_workload_identity"))
            } else {
                Some("rules.tool_access.require_workload_identity".to_string())
            };
            return deny_result(
                matched_rule,
                Some(
                    "runtime workload identity is missing or does not satisfy the required mapping"
                        .to_string(),
                ),
                origin_profile_id,
                posture,
            );
        }
    }

    let preferred_workload_identity = [
        base_rule.and_then(|rule| rule.prefer_workload_identity.as_ref()),
        profile_rule.and_then(|rule| rule.prefer_workload_identity.as_ref()),
    ]
    .into_iter()
    .flatten()
    .last();
    if let Some(preferred_workload_identity) = preferred_workload_identity {
        let matched = actual_workload_identity
            .is_some_and(|actual| workload_identity_matches(preferred_workload_identity, actual));
        if !matched {
            let matched_rule = if profile_rule
                .and_then(|rule| rule.prefer_workload_identity.as_ref())
                .is_some()
            {
                profile_prefix
                    .as_ref()
                    .map(|prefix| format!("{prefix}.prefer_workload_identity"))
            } else {
                Some("rules.tool_access.prefer_workload_identity".to_string())
            };
            return warn_result(
                matched_rule,
                Some(
                    "runtime workload identity is missing or does not satisfy the preferred mapping"
                        .to_string(),
                ),
                origin_profile_id,
                posture,
            );
        }
    }

    // Confirmation
    if let Some(rule) = base_rule {
        let matched = match find_first_match_or_deny(
            target,
            &rule.require_confirmation,
            "rules.tool_access.require_confirmation",
            origin_profile_id.clone(),
            posture.clone(),
        ) {
            Ok(matched) => matched,
            Err(result) => return *result,
        };
        if matched.is_some() {
            return warn_result(
                Some("rules.tool_access.require_confirmation".to_string()),
                Some("tool requires confirmation".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }
    if let Some(prefix) = profile_prefix.as_ref() {
        if let Some(rule) = profile_rule {
            let field = format!("{prefix}.require_confirmation");
            let matched = match find_first_match_or_deny(
                target,
                &rule.require_confirmation,
                &field,
                origin_profile_id.clone(),
                posture.clone(),
            ) {
                Ok(matched) => matched,
                Err(result) => return *result,
            };
            if matched.is_some() {
                return warn_result(
                    Some(field),
                    Some("tool requires confirmation".to_string()),
                    origin_profile_id,
                    posture,
                );
            }
        }
    }

    // Allow list
    let base_has_allow = base_rule.is_some_and(|rule| !rule.allow.is_empty());
    let profile_has_allow = profile_rule.is_some_and(|rule| !rule.allow.is_empty());
    let base_allow_match = if let Some(rule) = base_rule.filter(|rule| !rule.allow.is_empty()) {
        match find_first_match_or_deny(
            target,
            &rule.allow,
            "rules.tool_access.allow",
            origin_profile_id.clone(),
            posture.clone(),
        ) {
            Ok(matched) => matched.is_some(),
            Err(result) => return *result,
        }
    } else {
        true
    };
    let profile_allow_match = if let Some(rule) = profile_rule.filter(|rule| !rule.allow.is_empty())
    {
        let field = profile_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}.allow"))
            .unwrap_or_else(|| "extensions.origins.profiles.tool_access.allow".to_string());
        match find_first_match_or_deny(
            target,
            &rule.allow,
            &field,
            origin_profile_id.clone(),
            posture.clone(),
        ) {
            Ok(matched) => matched.is_some(),
            Err(result) => return *result,
        }
    } else {
        true
    };
    if (base_has_allow || profile_has_allow) && base_allow_match && profile_allow_match {
        let matched_rule = if profile_has_allow {
            profile_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}.allow"))
        } else if base_has_allow {
            Some("rules.tool_access.allow".to_string())
        } else {
            None
        };
        return allow_result(
            matched_rule,
            Some("tool is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    // Default action
    let default_action = if base_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
        || profile_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
    {
        DefaultAction::Block
    } else {
        DefaultAction::Allow
    };
    let default_rule = if profile_rule.is_some() {
        profile_prefix.map(|prefix| format!("{prefix}.default"))
    } else if base_rule.is_some() {
        Some("rules.tool_access.default".to_string())
    } else {
        None
    };

    match default_action {
        DefaultAction::Allow => allow_result(
            default_rule,
            Some("tool matched default allow".to_string()),
            origin_profile_id,
            posture,
        ),
        DefaultAction::Block => deny_result(
            default_rule,
            Some("tool matched default block".to_string()),
            origin_profile_id,
            posture,
        ),
    }
}

fn workload_identity_matches(
    expected: &crate::models::WorkloadIdentityMatch,
    actual: &chio_core::capability::WorkloadIdentity,
) -> bool {
    expected
        .scheme
        .is_none_or(|scheme| scheme == actual.scheme)
        && expected
            .trust_domain
            .as_deref()
            .is_none_or(|trust_domain| trust_domain == actual.trust_domain)
        && (expected.path_prefixes.is_empty()
            || expected
                .path_prefixes
                .iter()
                .any(|prefix| workload_identity_path_matches_prefix(prefix, &actual.path)))
        && (expected.credential_kinds.is_empty()
            || expected.credential_kinds.contains(&actual.credential_kind))
}

fn workload_identity_path_matches_prefix(expected_prefix: &str, actual_path: &str) -> bool {
    if !actual_path.starts_with('/') || actual_path.contains("//") {
        return false;
    }

    let prefix = if expected_prefix == "/" {
        expected_prefix
    } else {
        expected_prefix.trim_end_matches('/')
    };
    if prefix == "/" {
        return true;
    }
    if prefix.is_empty() || !prefix.starts_with('/') || prefix.contains("//") {
        return false;
    }

    actual_path == prefix
        || actual_path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn evaluate_egress(
    spec: &HushSpec,
    action: &EvaluationAction,
    matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    let base_rule = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.egress.as_ref())
        .filter(|rule| rule.enabled);
    let profile_rule = matched_profile
        .and_then(|profile| profile.egress.as_ref())
        .filter(|rule| rule.enabled);

    if base_rule.is_none() && profile_rule.is_none() {
        return allow_result(None, None, origin_profile_id, posture);
    }

    let target = action.target.as_deref().unwrap_or_default();
    let profile_prefix = matched_profile.map(|profile| profile_rule_prefix(&profile.id, "egress"));

    if let Some(rule) = base_rule {
        let matched = match find_first_match_or_deny(
            target,
            &rule.block,
            "rules.egress.block",
            origin_profile_id.clone(),
            posture.clone(),
        ) {
            Ok(matched) => matched,
            Err(result) => return *result,
        };
        if matched.is_some() {
            return deny_result(
                Some("rules.egress.block".to_string()),
                Some("domain is explicitly blocked".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }
    if let Some(prefix) = profile_prefix.as_ref() {
        if let Some(rule) = profile_rule {
            let field = format!("{prefix}.block");
            let matched = match find_first_match_or_deny(
                target,
                &rule.block,
                &field,
                origin_profile_id.clone(),
                posture.clone(),
            ) {
                Ok(matched) => matched,
                Err(result) => return *result,
            };
            if matched.is_some() {
                return deny_result(
                    Some(field),
                    Some("domain is explicitly blocked".to_string()),
                    origin_profile_id,
                    posture,
                );
            }
        }
    }

    let base_has_allow = base_rule.is_some_and(|rule| !rule.allow.is_empty());
    let profile_has_allow = profile_rule.is_some_and(|rule| !rule.allow.is_empty());
    let base_allow_match = if let Some(rule) = base_rule.filter(|rule| !rule.allow.is_empty()) {
        match find_first_match_or_deny(
            target,
            &rule.allow,
            "rules.egress.allow",
            origin_profile_id.clone(),
            posture.clone(),
        ) {
            Ok(matched) => matched.is_some(),
            Err(result) => return *result,
        }
    } else {
        true
    };
    let profile_allow_match = if let Some(rule) = profile_rule.filter(|rule| !rule.allow.is_empty())
    {
        let field = profile_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}.allow"))
            .unwrap_or_else(|| "extensions.origins.profiles.egress.allow".to_string());
        match find_first_match_or_deny(
            target,
            &rule.allow,
            &field,
            origin_profile_id.clone(),
            posture.clone(),
        ) {
            Ok(matched) => matched.is_some(),
            Err(result) => return *result,
        }
    } else {
        true
    };
    if (base_has_allow || profile_has_allow) && base_allow_match && profile_allow_match {
        let matched_rule = if profile_has_allow {
            profile_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}.allow"))
        } else if base_has_allow {
            Some("rules.egress.allow".to_string())
        } else {
            None
        };
        return allow_result(
            matched_rule,
            Some("domain is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    let default_action = if base_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
        || profile_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
    {
        DefaultAction::Block
    } else {
        DefaultAction::Allow
    };
    let default_rule = if profile_rule.is_some() {
        profile_prefix.map(|prefix| format!("{prefix}.default"))
    } else if base_rule.is_some() {
        Some("rules.egress.default".to_string())
    } else {
        None
    };

    match default_action {
        DefaultAction::Allow => allow_result(
            default_rule,
            Some("domain matched default allow".to_string()),
            origin_profile_id,
            posture,
        ),
        DefaultAction::Block => deny_result(
            default_rule,
            Some("domain matched default block".to_string()),
            origin_profile_id,
            posture,
        ),
    }
}

fn evaluate_file_read(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(result) = evaluate_path_guards(
        spec,
        action.target.as_deref().unwrap_or_default(),
        PathOperation::Read,
        posture.clone(),
        origin_profile_id.clone(),
    ) {
        return result;
    }
    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_file_write(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(result) = evaluate_path_guards(
        spec,
        action.target.as_deref().unwrap_or_default(),
        PathOperation::Write,
        posture.clone(),
        origin_profile_id.clone(),
    ) {
        return result;
    }

    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.secret_patterns.as_ref())
    {
        return evaluate_secret_patterns(
            rule,
            action.target.as_deref().unwrap_or_default(),
            action.content.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_patch(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(result) = evaluate_path_guards(
        spec,
        action.target.as_deref().unwrap_or_default(),
        PathOperation::Patch,
        posture.clone(),
        origin_profile_id.clone(),
    ) {
        return result;
    }

    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.patch_integrity.as_ref())
    {
        return evaluate_patch_integrity(
            rule,
            action.content.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_shell_command(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.shell_commands.as_ref())
    {
        return evaluate_shell_rule(
            rule,
            action.target.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }
    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_computer_use(
    spec: &HushSpec,
    action: &EvaluationAction,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    let target = action.target.as_deref().unwrap_or_default();
    let cu_result = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.computer_use.as_ref())
        .map(|rule| {
            evaluate_computer_use_rule(rule, target, posture.clone(), origin_profile_id.clone())
        });
    let rd_result = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.remote_desktop_channels.as_ref())
        .and_then(|rule| {
            evaluate_remote_desktop_channels_rule(
                rule,
                target,
                posture.clone(),
                origin_profile_id.clone(),
            )
        });

    match (cu_result, rd_result) {
        (Some(left), Some(right)) => more_restrictive_result(left, right),
        (Some(result), None) | (None, Some(result)) => result,
        (None, None) => allow_result(None, None, origin_profile_id, posture),
    }
}

fn evaluate_input_injection(
    spec: &HushSpec,
    action: &EvaluationAction,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.input_injection.as_ref())
    {
        return evaluate_input_injection_rule(
            rule,
            action.target.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }
    allow_result(None, None, origin_profile_id, posture)
}

// ---------------------------------------------------------------------------
// Rule-level evaluators
// ---------------------------------------------------------------------------

fn evaluate_secret_patterns(
    rule: &SecretPatternsRule,
    target: &str,
    content: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    let skip_path_match = match find_first_match_or_deny(
        target,
        &rule.skip_paths,
        "rules.secret_patterns.skip_paths",
        origin_profile_id.clone(),
        posture.clone(),
    ) {
        Ok(matched) => matched,
        Err(result) => return *result,
    };
    if skip_path_match.is_some() {
        return allow_result(
            Some("rules.secret_patterns.skip_paths".to_string()),
            Some("path is excluded from secret scanning".to_string()),
            origin_profile_id,
            posture,
        );
    }

    for pattern in &rule.patterns {
        let field = format!("rules.secret_patterns.patterns.{}", pattern.name);
        match policy_regex_is_match(&pattern.pattern, &field, content) {
            Ok(true) => {
                return deny_result(
                    Some(field),
                    Some(format!("content matched secret pattern '{}'", pattern.name)),
                    origin_profile_id,
                    posture,
                );
            }
            Ok(false) => {}
            Err(error) => {
                return deny_result(
                    Some(field),
                    Some(format!("invalid secret pattern regex: {error}")),
                    origin_profile_id,
                    posture,
                );
            }
        }
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_patch_integrity(
    rule: &PatchIntegrityRule,
    content: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    for (index, pattern) in rule.forbidden_patterns.iter().enumerate() {
        let field = format!("rules.patch_integrity.forbidden_patterns[{index}]");
        match policy_regex_is_match(pattern, &field, content) {
            Ok(true) => {
                return deny_result(
                    Some(field),
                    Some("patch content matched a forbidden pattern".to_string()),
                    origin_profile_id,
                    posture,
                );
            }
            Ok(false) => {}
            Err(error) => {
                return deny_result(
                    Some(field),
                    Some(format!("invalid forbidden patch regex: {error}")),
                    origin_profile_id,
                    posture,
                );
            }
        }
    }

    let stats = patch_stats(content);
    if stats.additions > rule.max_additions {
        return deny_result(
            Some("rules.patch_integrity.max_additions".to_string()),
            Some("patch additions exceeded max_additions".to_string()),
            origin_profile_id,
            posture,
        );
    }
    if stats.deletions > rule.max_deletions {
        return deny_result(
            Some("rules.patch_integrity.max_deletions".to_string()),
            Some("patch deletions exceeded max_deletions".to_string()),
            origin_profile_id,
            posture,
        );
    }
    if rule.require_balance {
        let ratio = imbalance_ratio(stats.additions, stats.deletions);
        if ratio > rule.max_imbalance_ratio {
            return deny_result(
                Some("rules.patch_integrity.max_imbalance_ratio".to_string()),
                Some("patch exceeded max imbalance ratio".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_shell_rule(
    rule: &ShellCommandsRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    for (index, pattern) in rule.forbidden_patterns.iter().enumerate() {
        let field = format!("rules.shell_commands.forbidden_patterns[{index}]");
        match policy_regex_is_match(pattern, &field, target) {
            Ok(true) => {
                return deny_result(
                    Some(field),
                    Some("shell command matched a forbidden pattern".to_string()),
                    origin_profile_id,
                    posture,
                );
            }
            Ok(false) => {}
            Err(error) => {
                return deny_result(
                    Some(field),
                    Some(format!("invalid forbidden shell regex: {error}")),
                    origin_profile_id,
                    posture,
                );
            }
        }
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_computer_use_rule(
    rule: &ComputerUseRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    if rule.allowed_actions.iter().any(|action| action == target) {
        return allow_result(
            Some("rules.computer_use.allowed_actions".to_string()),
            Some("computer-use action is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    match rule.mode {
        ComputerUseMode::Observe => allow_result(
            Some("rules.computer_use.mode".to_string()),
            Some("observe mode does not block unlisted actions".to_string()),
            origin_profile_id,
            posture,
        ),
        ComputerUseMode::Guardrail => warn_result(
            Some("rules.computer_use.mode".to_string()),
            Some("guardrail mode warns on unlisted actions".to_string()),
            origin_profile_id,
            posture,
        ),
        ComputerUseMode::FailClosed => deny_result(
            Some("rules.computer_use.mode".to_string()),
            Some("fail_closed mode denies unlisted actions".to_string()),
            origin_profile_id,
            posture,
        ),
    }
}

fn evaluate_remote_desktop_channels_rule(
    rule: &RemoteDesktopChannelsRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> Option<EvaluationResult> {
    if !rule.enabled {
        return None;
    }

    let (field, allowed) = match target {
        "remote.clipboard" => ("clipboard", rule.clipboard),
        "remote.file_transfer" => ("file_transfer", rule.file_transfer),
        "remote.audio" => ("audio", rule.audio),
        "remote.drive_mapping" => ("drive_mapping", rule.drive_mapping),
        _ => return None,
    };

    if allowed {
        return Some(allow_result(
            Some(format!("rules.remote_desktop_channels.{field}")),
            Some(format!("remote desktop channel '{field}' is enabled")),
            origin_profile_id,
            posture,
        ));
    }

    Some(deny_result(
        Some(format!("rules.remote_desktop_channels.{field}")),
        Some(format!("remote desktop channel '{field}' is disabled")),
        origin_profile_id,
        posture,
    ))
}

fn evaluate_input_injection_rule(
    rule: &InputInjectionRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    if rule.allowed_types.is_empty() {
        return deny_result(
            Some("rules.input_injection.allowed_types".to_string()),
            Some("input injection is not allowed when allowed_types is empty".to_string()),
            origin_profile_id,
            posture,
        );
    }

    if rule.allowed_types.iter().any(|allowed| allowed == target) {
        return allow_result(
            Some("rules.input_injection.allowed_types".to_string()),
            Some("input injection type is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    deny_result(
        Some("rules.input_injection.allowed_types".to_string()),
        Some("input injection type is not allowed".to_string()),
        origin_profile_id,
        posture,
    )
}

// ---------------------------------------------------------------------------
// Path guard helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum PathOperation {
    Read,
    Write,
    Patch,
}

struct ForbiddenPathOutcome {
    denied: Option<EvaluationResult>,
    exception_matched: bool,
}

fn evaluate_path_guards(
    spec: &HushSpec,
    target: &str,
    operation: PathOperation,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> Option<EvaluationResult> {
    let rules = spec.rules.as_ref()?;
    let mut forbidden_exception_matched = false;

    if let Some(rule) = rules.forbidden_paths.as_ref() {
        let result =
            evaluate_forbidden_paths(rule, target, posture.clone(), origin_profile_id.clone());
        if let Some(denied) = result.denied {
            return Some(denied);
        }
        forbidden_exception_matched = result.exception_matched;
    }

    if let Some(rule) = rules.path_allowlist.as_ref() {
        if let Some(result) = evaluate_path_allowlist(
            rule,
            target,
            operation,
            posture.clone(),
            origin_profile_id.clone(),
        ) {
            return Some(result);
        }
    }

    if forbidden_exception_matched {
        return Some(allow_result(
            Some("rules.forbidden_paths.exceptions".to_string()),
            Some("path matched an explicit exception".to_string()),
            origin_profile_id,
            posture,
        ));
    }

    None
}

fn evaluate_forbidden_paths(
    rule: &ForbiddenPathsRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> ForbiddenPathOutcome {
    if !rule.enabled {
        return ForbiddenPathOutcome {
            denied: None,
            exception_matched: false,
        };
    }

    let exception_match = match find_first_match_or_deny(
        target,
        &rule.exceptions,
        "rules.forbidden_paths.exceptions",
        origin_profile_id.clone(),
        posture.clone(),
    ) {
        Ok(matched) => matched,
        Err(result) => {
            return ForbiddenPathOutcome {
                denied: Some(*result),
                exception_matched: false,
            };
        }
    };
    if exception_match.is_some() {
        return ForbiddenPathOutcome {
            denied: None,
            exception_matched: true,
        };
    }

    let forbidden_match = match find_first_match_or_deny(
        target,
        &rule.patterns,
        "rules.forbidden_paths.patterns",
        origin_profile_id.clone(),
        posture.clone(),
    ) {
        Ok(matched) => matched,
        Err(result) => {
            return ForbiddenPathOutcome {
                denied: Some(*result),
                exception_matched: false,
            };
        }
    };
    if forbidden_match.is_some() {
        return ForbiddenPathOutcome {
            denied: Some(deny_result(
                Some("rules.forbidden_paths.patterns".to_string()),
                Some("path matched a forbidden pattern".to_string()),
                origin_profile_id,
                posture,
            )),
            exception_matched: false,
        };
    }

    ForbiddenPathOutcome {
        denied: None,
        exception_matched: false,
    }
}

fn evaluate_path_allowlist(
    rule: &PathAllowlistRule,
    target: &str,
    operation: PathOperation,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> Option<EvaluationResult> {
    if !rule.enabled {
        return None;
    }

    let patterns = match operation {
        PathOperation::Read => &rule.read,
        PathOperation::Write => &rule.write,
        PathOperation::Patch => {
            if rule.patch.is_empty() {
                &rule.write
            } else {
                &rule.patch
            }
        }
    };

    let allowlist_match = match find_first_match_or_deny(
        target,
        patterns,
        "rules.path_allowlist",
        origin_profile_id.clone(),
        posture.clone(),
    ) {
        Ok(matched) => matched,
        Err(result) => return Some(*result),
    };
    if allowlist_match.is_some() {
        return Some(allow_result(
            Some("rules.path_allowlist".to_string()),
            Some("path matched allowlist".to_string()),
            origin_profile_id,
            posture,
        ));
    }

    Some(deny_result(
        Some("rules.path_allowlist".to_string()),
        Some("path did not match allowlist".to_string()),
        origin_profile_id,
        posture,
    ))
}

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

fn posture_capability_guard(
    action: &EvaluationAction,
    posture: &Option<PostureResult>,
    spec: &HushSpec,
    origin_profile_id: &Option<String>,
) -> Option<EvaluationResult> {
    let posture_result = posture.as_ref()?;
    let posture_extension = spec
        .extensions
        .as_ref()
        .and_then(|ext| ext.posture.as_ref())?;
    let capability = required_capability(action.action_type.as_str())?;
    let current_state = posture_extension.states.get(&posture_result.current)?;

    if current_state
        .capabilities
        .iter()
        .any(|entry| entry == capability)
    {
        return None;
    }

    Some(deny_result(
        Some(format!(
            "extensions.posture.states.{}.capabilities",
            posture_result.current
        )),
        Some(format!(
            "posture '{}' does not allow capability '{capability}'",
            posture_result.current
        )),
        origin_profile_id.clone(),
        Some(posture_result.clone()),
    ))
}

fn resolve_posture(
    spec: &HushSpec,
    matched_profile: Option<&OriginProfile>,
    posture: Option<&PostureContext>,
) -> Option<PostureResult> {
    let posture_extension = spec
        .extensions
        .as_ref()
        .and_then(|ext| ext.posture.as_ref())?;

    let current = matched_profile
        .and_then(|profile| profile.posture.clone())
        .or_else(|| posture.and_then(|ctx| ctx.current.clone()))
        .unwrap_or_else(|| posture_extension.initial.clone());

    let signal = posture
        .and_then(|ctx| ctx.signal.as_deref())
        .filter(|s| *s != "none");
    let next = signal
        .and_then(|sig| next_posture_state(posture_extension, &current, sig))
        .unwrap_or_else(|| current.clone());

    Some(PostureResult { current, next })
}

fn next_posture_state(posture: &PostureExtension, current: &str, signal: &str) -> Option<String> {
    posture.transitions.iter().find_map(|transition| {
        if transition.from != "*" && transition.from != current {
            return None;
        }
        if trigger_name(&transition.on) != signal {
            return None;
        }
        Some(transition.to.clone())
    })
}

// ---------------------------------------------------------------------------
// Origin profile selection
// ---------------------------------------------------------------------------

fn origin_admission_denial(
    spec: &HushSpec,
    origin: Option<&OriginContext>,
    matched_profile: Option<&OriginProfile>,
) -> Option<EvaluationResult> {
    if matched_profile.is_some() {
        return None;
    }

    let origins = spec.extensions.as_ref()?.origins.as_ref()?;
    if origins.default_behavior.unwrap_or_default() == OriginDefaultBehavior::MinimalProfile {
        return None;
    }

    let reason = if origin.is_some() {
        "origin context did not match any configured origin profile"
    } else {
        "origin context is required by origins policy"
    };
    Some(deny_result(
        Some("extensions.origins.default_behavior".to_string()),
        Some(reason.to_string()),
        None,
        None,
    ))
}

fn select_origin_profile<'a>(
    spec: &'a HushSpec,
    origin: Option<&OriginContext>,
) -> Option<&'a OriginProfile> {
    let origin = origin?;
    let profiles = spec
        .extensions
        .as_ref()
        .and_then(|ext| ext.origins.as_ref())
        .map(|origins| origins.profiles.as_slice())?;

    profiles
        .iter()
        .filter_map(|profile| {
            profile
                .match_rules
                .as_ref()
                .and_then(|rules| match_origin(rules, origin).map(|score| (score, profile)))
        })
        .max_by_key(|(score, _)| *score)
        .map(|(_, profile)| profile)
}

pub fn selected_origin_profile_id(spec: &HushSpec, origin: &OriginContext) -> Option<String> {
    select_origin_profile(spec, Some(origin)).map(|profile| profile.id.clone())
}

fn match_origin(rules: &OriginMatch, origin: &OriginContext) -> Option<u32> {
    let mut score = 0;

    if let Some(provider) = &rules.provider {
        if origin.provider.as_ref() != Some(provider) {
            return None;
        }
        score += 4;
    }
    if let Some(tenant_id) = &rules.tenant_id {
        if origin.tenant_id.as_ref() != Some(tenant_id) {
            return None;
        }
        score += 6;
    }
    if let Some(organization_id) = &rules.organization_id {
        if origin.organization_id.as_ref() != Some(organization_id) {
            return None;
        }
        score += 6;
    }
    if let Some(space_id) = &rules.space_id {
        if origin.space_id.as_ref() != Some(space_id) {
            return None;
        }
        score += 8;
    }
    if let Some(space_type) = &rules.space_type {
        if origin.space_type.as_ref() != Some(space_type) {
            return None;
        }
        score += 4;
    }
    if let Some(visibility) = &rules.visibility {
        if origin.visibility.as_ref() != Some(visibility) {
            return None;
        }
        score += 4;
    }
    if let Some(external_participants) = rules.external_participants {
        if origin.external_participants != Some(external_participants) {
            return None;
        }
        score += 2;
    }
    if !rules.tags.is_empty() {
        if !rules
            .tags
            .iter()
            .all(|tag| origin.tags.iter().any(|candidate| candidate == tag))
        {
            return None;
        }
        score += rules.tags.len() as u32;
    }
    if !rules.groups.is_empty() {
        if !rules
            .groups
            .iter()
            .all(|group| origin.groups.iter().any(|candidate| candidate == group))
        {
            return None;
        }
        score += (rules.groups.len() as u32) * 3;
    }
    if !rules.roles.is_empty() {
        if !rules
            .roles
            .iter()
            .all(|role| origin.roles.iter().any(|candidate| candidate == role))
        {
            return None;
        }
        score += (rules.roles.len() as u32) * 3;
    }
    if let Some(sensitivity) = &rules.sensitivity {
        if origin.sensitivity.as_ref() != Some(sensitivity) {
            return None;
        }
        score += 4;
    }
    if let Some(actor_role) = &rules.actor_role {
        if origin.actor_role.as_ref() != Some(actor_role) {
            return None;
        }
        score += 4;
    }

    Some(score)
}
