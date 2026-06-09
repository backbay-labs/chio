// ---------------------------------------------------------------------------
// Core evaluation
// ---------------------------------------------------------------------------

pub fn evaluate(spec: &HushSpec, action: &EvaluationAction) -> EvaluationResult {
    if is_panic_active() {
        return EvaluationResult {
            decision: Decision::Deny,
            matched_rule: Some("__hushspec_panic__".to_string()),
            reason: Some("emergency panic mode is active".to_string()),
            origin_profile: None,
            posture: None,
        };
    }

    let matched_profile = select_origin_profile(spec, action.origin.as_ref());
    let origin_profile_id = matched_profile.map(|profile| profile.id.clone());
    if let Some(denied) = origin_admission_denial(spec, action.origin.as_ref(), matched_profile) {
        return denied;
    }
    let posture = resolve_posture(spec, matched_profile, action.posture.as_ref());

    if let Some(denied) = posture_capability_guard(action, &posture, spec, &origin_profile_id) {
        return denied;
    }

    match action.action_type.as_str() {
        "tool_call" => {
            evaluate_tool_call(spec, action, matched_profile, posture, origin_profile_id)
        }
        "egress" => evaluate_egress(spec, action, matched_profile, posture, origin_profile_id),
        "file_read" => {
            evaluate_file_read(spec, action, matched_profile, posture, origin_profile_id)
        }
        "file_write" => {
            evaluate_file_write(spec, action, matched_profile, posture, origin_profile_id)
        }
        "patch_apply" => evaluate_patch(spec, action, matched_profile, posture, origin_profile_id),
        "shell_command" => {
            evaluate_shell_command(spec, action, matched_profile, posture, origin_profile_id)
        }
        "computer_use" => evaluate_computer_use(spec, action, posture, origin_profile_id),
        "input_inject" => evaluate_input_injection(spec, action, posture, origin_profile_id),
        _ => EvaluationResult {
            decision: Decision::Deny,
            matched_rule: None,
            reason: Some(
                "no reference evaluator rule for this action type; denying fail-closed".to_string(),
            ),
            origin_profile: origin_profile_id,
            posture,
        },
    }
}

/// Like [`evaluate`] but filters rule blocks through `when` conditions first.
pub fn evaluate_with_context(
    spec: &HushSpec,
    action: &EvaluationAction,
    context: &RuntimeContext,
    conditions: &HashMap<String, Condition>,
) -> EvaluationResult {
    if is_panic_active() {
        return EvaluationResult {
            decision: Decision::Deny,
            matched_rule: Some("__hushspec_panic__".to_string()),
            reason: Some("emergency panic mode is active".to_string()),
            origin_profile: None,
            posture: None,
        };
    }

    let matched_profile = select_origin_profile(spec, action.origin.as_ref());
    let origin_profile_id = matched_profile.map(|profile| profile.id.clone());
    if let Some(denied) = origin_admission_denial(spec, action.origin.as_ref(), matched_profile) {
        return denied;
    }
    let posture = resolve_posture(spec, matched_profile, action.posture.as_ref());

    if let Some(denied) = posture_capability_guard(action, &posture, spec, &origin_profile_id) {
        return denied;
    }

    // Reject condition maps that reference unknown rule-block names before
    // filtering, so a misspelled key fails closed instead of silently leaving
    // its target rule active (which apply_conditions would otherwise no-op).
    if let Err(reason) = validate_condition_keys(conditions) {
        return EvaluationResult {
            decision: Decision::Deny,
            matched_rule: None,
            reason: Some(format!(
                "invalid policy condition keys; denying fail-closed: {reason}"
            )),
            origin_profile: None,
            posture: None,
        };
    }

    let effective_spec = apply_conditions(spec, context, conditions);

    match action.action_type.as_str() {
        "tool_call" => evaluate_tool_call(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "egress" => evaluate_egress(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "file_read" => evaluate_file_read(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "file_write" => evaluate_file_write(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "patch_apply" => evaluate_patch(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "shell_command" => evaluate_shell_command(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "computer_use" => {
            evaluate_computer_use(&effective_spec, action, posture, origin_profile_id)
        }
        "input_inject" => {
            evaluate_input_injection(&effective_spec, action, posture, origin_profile_id)
        }
        _ => EvaluationResult {
            decision: Decision::Deny,
            matched_rule: None,
            reason: Some(
                "no reference evaluator rule for this action type; denying fail-closed".to_string(),
            ),
            origin_profile: origin_profile_id,
            posture,
        },
    }
}
