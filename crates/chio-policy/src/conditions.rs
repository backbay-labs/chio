//! Conditional rules system for HushSpec policies.
//!
//! Ported from the HushSpec reference implementation. Provides a `Condition`
//! type that gates whether a rule block is active, evaluated against a
//! `RuntimeContext`.
//!
//! Design principles:
//! - Fail-closed: missing context fields cause conditions to evaluate to false.
//! - Deterministic: same context + condition = same result, always.
//! - Not Turing-complete: fixed predicate types composed with AND/OR/NOT.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum allowed nesting depth for compound conditions.
const MAX_NESTING_DEPTH: usize = 8;

/// Rule-block names a condition may gate. Must stay in sync with the fields
/// of `models::Rules` and the match arms in `apply_conditions`.
/// `validate_condition_keys` rejects any condition key outside this set so a
/// misspelled key cannot silently leave a rule active.
pub const CONDITIONABLE_RULE_BLOCKS: [&str; 14] = [
    "forbidden_paths",
    "path_allowlist",
    "egress",
    "secret_patterns",
    "patch_integrity",
    "shell_commands",
    "tool_access",
    "computer_use",
    "remote_desktop_channels",
    "input_injection",
    "browser_automation",
    "code_execution",
    "velocity",
    "human_in_loop",
];

/// Reject condition maps whose keys are not known rule-block names. The
/// reference evaluator calls this at the start of `evaluate_with_context`;
/// callers that assemble condition maps elsewhere should also validate at load
/// time, so a misspelled key fails closed instead of silently no-oping the rule
/// it was meant to gate.
///
/// # Errors
///
/// Returns the offending key when a condition references a block name outside
/// `CONDITIONABLE_RULE_BLOCKS`.
pub fn validate_condition_keys(conditions: &HashMap<String, Condition>) -> Result<(), String> {
    for block_name in conditions.keys() {
        if !CONDITIONABLE_RULE_BLOCKS.contains(&block_name.as_str()) {
            return Err(format!(
                "condition key `{block_name}` is not a known rule-block name; \
                 valid blocks: {}",
                CONDITIONABLE_RULE_BLOCKS.join(", ")
            ));
        }
    }
    Ok(())
}

/// A condition that gates whether a rule block is active.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindowCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_of: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_of: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not: Option<Box<Condition>>,
}

/// Time window condition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowCondition {
    pub start: String,
    pub end: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<String>,
}

/// Runtime context provided by the enforcement engine at evaluation time.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeContext {
    #[serde(default)]
    pub user: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default)]
    pub deployment: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub agent: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub session: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub request: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub custom: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_time: Option<String>,
}

/// Missing context fields cause the condition to evaluate to false (fail-closed).
pub fn evaluate_condition(condition: &Condition, context: &RuntimeContext) -> bool {
    evaluate_condition_depth(condition, context, 0)
}

fn evaluate_condition_depth(condition: &Condition, context: &RuntimeContext, depth: usize) -> bool {
    if depth > MAX_NESTING_DEPTH {
        return false;
    }

    if let Some(tw) = &condition.time_window {
        if !check_time_window(tw, context) {
            return false;
        }
    }

    if let Some(ctx) = &condition.context {
        if !check_context_match(ctx, context) {
            return false;
        }
    }

    if let Some(all) = &condition.all_of {
        if !all
            .iter()
            .all(|c| evaluate_condition_depth(c, context, depth + 1))
        {
            return false;
        }
    }

    if let Some(any) = &condition.any_of {
        if !any.is_empty()
            && !any
                .iter()
                .any(|c| evaluate_condition_depth(c, context, depth + 1))
        {
            return false;
        }
    }

    if let Some(not_cond) = &condition.not {
        if evaluate_condition_depth(not_cond, context, depth + 1) {
            return false;
        }
    }

    true
}

fn check_time_window(tw: &TimeWindowCondition, context: &RuntimeContext) -> bool {
    let now = resolve_current_time(context, tw.timezone.as_deref());
    let Some((hour, minute, day_of_week)) = now else {
        return false;
    };

    let Some((start_h, start_m)) = parse_hhmm(&tw.start) else {
        return false;
    };
    let Some((end_h, end_m)) = parse_hhmm(&tw.end) else {
        return false;
    };

    let current_minutes = hour as u32 * 60 + minute as u32;
    let start_minutes = start_h as u32 * 60 + start_m as u32;
    let end_minutes = end_h as u32 * 60 + end_m as u32;
    let wraps_midnight = start_minutes > end_minutes;

    if !tw.days.is_empty() {
        let effective_day = if wraps_midnight && current_minutes < end_minutes {
            (day_of_week + 6) % 7
        } else {
            day_of_week
        };
        let day_abbrev = day_abbreviation(effective_day);
        if !tw.days.iter().any(|d| d.eq_ignore_ascii_case(day_abbrev)) {
            return false;
        }
    }

    if start_minutes == end_minutes {
        return true;
    }

    if start_minutes < end_minutes {
        current_minutes >= start_minutes && current_minutes < end_minutes
    } else {
        current_minutes >= start_minutes || current_minutes < end_minutes
    }
}

fn parse_hhmm(s: &str) -> Option<(u8, u8)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let hour: u8 = parts[0].parse().ok()?;
    let minute: u8 = parts[1].parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some((hour, minute))
}

fn day_abbreviation(day: u32) -> &'static str {
    match day {
        0 => "mon",
        1 => "tue",
        2 => "wed",
        3 => "thu",
        4 => "fri",
        5 => "sat",
        6 => "sun",
        _ => "mon",
    }
}

fn resolve_current_time(context: &RuntimeContext, timezone: Option<&str>) -> Option<(u8, u8, u32)> {
    use chrono::{Datelike, FixedOffset, NaiveDateTime, Timelike, Utc};
    use std::str::FromStr;

    let utc_now = if let Some(ref time_str) = context.current_time {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(time_str) {
            dt.with_timezone(&Utc)
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(time_str, "%Y-%m-%dT%H:%M:%S") {
            dt.and_utc()
        } else {
            return None;
        }
    } else {
        Utc::now()
    };

    let tz = timezone.unwrap_or("UTC");
    let adjusted = if let Ok(tz) = chrono_tz::Tz::from_str(tz) {
        utc_now.with_timezone(&tz).fixed_offset()
    } else {
        let offset_minutes = parse_timezone_offset(tz)?;
        let offset = FixedOffset::east_opt(offset_minutes.saturating_mul(60))?;
        utc_now.with_timezone(&offset)
    };
    let hour = adjusted.hour() as u8;
    let minute = adjusted.minute() as u8;
    let day_of_week = adjusted.weekday().num_days_from_monday();

    Some((hour, minute, day_of_week))
}

fn parse_timezone_offset(tz: &str) -> Option<i32> {
    match tz {
        "UTC" | "utc" | "Etc/UTC" | "Etc/GMT" | "GMT" => Some(0),
        "US/Eastern" | "EST" => Some(-5 * 60),
        "US/Central" | "CST" => Some(-6 * 60),
        "US/Mountain" | "MST" => Some(-7 * 60),
        "US/Pacific" | "PST" => Some(-8 * 60),
        "GB" => Some(0),
        "CET" => Some(60),
        "EET" => Some(120),
        "Japan" | "JST" => Some(9 * 60),
        "PRC" => Some(8 * 60),
        "IST" => Some(5 * 60 + 30),
        _ => {
            if let Some(rest) = tz.strip_prefix('+') {
                parse_offset_value(rest)
            } else if let Some(rest) = tz.strip_prefix('-') {
                parse_offset_value(rest).map(|value| -value)
            } else {
                None
            }
        }
    }
}

fn parse_offset_value(s: &str) -> Option<i32> {
    if let Some((hours, minutes)) = s.split_once(':') {
        let hours = hours.parse::<i32>().ok()?;
        let minutes = minutes.parse::<i32>().ok()?;
        if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
            return None;
        }
        Some(hours.saturating_mul(60).saturating_add(minutes))
    } else {
        let hours = s.parse::<i32>().ok()?;
        if !(0..=23).contains(&hours) {
            return None;
        }
        Some(hours.saturating_mul(60))
    }
}

fn check_context_match(
    expected: &HashMap<String, serde_json::Value>,
    context: &RuntimeContext,
) -> bool {
    for (key, expected_value) in expected {
        let actual = resolve_context_value(key, context);
        if !match_value(&actual, expected_value) {
            return false;
        }
    }
    true
}

fn resolve_context_value(path: &str, context: &RuntimeContext) -> Option<serde_json::Value> {
    let (namespace, subkey) = match path.split_once('.') {
        Some((ns, key)) => (ns, Some(key)),
        None => (path, None),
    };

    match namespace {
        "environment" => context
            .environment
            .as_ref()
            .map(|s| serde_json::Value::String(s.clone())),
        "user" => resolve_map_field(&context.user, subkey),
        "deployment" => resolve_map_field(&context.deployment, subkey),
        "agent" => resolve_map_field(&context.agent, subkey),
        "session" => resolve_map_field(&context.session, subkey),
        "request" => resolve_map_field(&context.request, subkey),
        "custom" => resolve_map_field(&context.custom, subkey),
        _ => None,
    }
}

fn resolve_map_field(
    map: &HashMap<String, serde_json::Value>,
    subkey: Option<&str>,
) -> Option<serde_json::Value> {
    match subkey {
        Some(key) => map.get(key).cloned(),
        None => Some(serde_json::to_value(map).unwrap_or_default()),
    }
}

fn values_equal(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match expected {
        serde_json::Value::String(expected_str) => actual.as_str() == Some(expected_str.as_str()),
        serde_json::Value::Bool(expected_bool) => actual.as_bool() == Some(*expected_bool),
        serde_json::Value::Number(expected_num) => {
            if let Some(expected_i64) = expected_num.as_i64() {
                actual.as_i64() == Some(expected_i64)
            } else if let Some(expected_f64) = expected_num.as_f64() {
                actual
                    .as_f64()
                    .is_some_and(|n| (n - expected_f64).abs() < f64::EPSILON)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn matches_scalar_or_membership(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match actual {
        serde_json::Value::Array(arr) => arr.iter().any(|item| values_equal(item, expected)),
        _ => values_equal(actual, expected),
    }
}

fn match_value(actual: &Option<serde_json::Value>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };

    match expected {
        serde_json::Value::String(_)
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_) => matches_scalar_or_membership(actual, expected),
        serde_json::Value::Array(expected_arr) => expected_arr
            .iter()
            .any(|candidate| matches_scalar_or_membership(actual, candidate)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_condition_keys_rejects_unknown_block_name() {
        let conditions = HashMap::from([("egres".to_string(), Condition::default())]); // typo
        let err = validate_condition_keys(&conditions)
            .expect_err("a misspelled condition key must be rejected");
        assert!(
            err.contains("`egres`"),
            "error should name the offending key, got: {err}"
        );
    }

    #[test]
    fn validate_condition_keys_accepts_every_known_block() {
        for block in CONDITIONABLE_RULE_BLOCKS {
            let conditions = HashMap::from([(block.to_string(), Condition::default())]);
            assert!(
                validate_condition_keys(&conditions).is_ok(),
                "known block `{block}` must validate"
            );
        }
    }

    fn context_at(current_time: &str) -> RuntimeContext {
        RuntimeContext {
            current_time: Some(current_time.to_string()),
            ..RuntimeContext::default()
        }
    }

    fn nested_all_of_condition(depth: usize) -> Condition {
        if depth == 0 {
            Condition::default()
        } else {
            Condition {
                all_of: Some(vec![nested_all_of_condition(depth - 1)]),
                ..Condition::default()
            }
        }
    }

    fn nested_any_of_condition(depth: usize) -> Condition {
        if depth == 0 {
            Condition::default()
        } else {
            Condition {
                any_of: Some(vec![nested_any_of_condition(depth - 1)]),
                ..Condition::default()
            }
        }
    }

    #[test]
    fn overnight_windows_resolve_the_previous_day_after_midnight() {
        let condition = Condition {
            time_window: Some(TimeWindowCondition {
                start: "22:00".to_string(),
                end: "02:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec!["tue".to_string()],
            }),
            ..Condition::default()
        };

        assert!(evaluate_condition(
            &condition,
            &context_at("2026-04-15T01:30:00Z")
        ));
    }

    #[test]
    fn context_matching_supports_scalars_membership_and_environment() {
        let mut context = RuntimeContext {
            environment: Some("prod".to_string()),
            ..RuntimeContext::default()
        };
        context
            .user
            .insert("role".to_string(), serde_json::json!("admin"));
        context
            .request
            .insert("scopes".to_string(), serde_json::json!(["read", "write"]));
        context
            .request
            .insert("retries".to_string(), serde_json::json!(3));
        context
            .custom
            .insert("enabled".to_string(), serde_json::json!(true));

        let expected = HashMap::from([
            ("environment".to_string(), serde_json::json!("prod")),
            ("user.role".to_string(), serde_json::json!("admin")),
            (
                "request.scopes".to_string(),
                serde_json::json!(["execute", "write"]),
            ),
            ("request.retries".to_string(), serde_json::json!(3)),
            ("custom.enabled".to_string(), serde_json::json!(true)),
        ]);

        assert!(evaluate_condition(
            &Condition {
                context: Some(expected),
                ..Condition::default()
            },
            &context
        ));
    }

    #[test]
    fn invalid_timezones_and_missing_fields_fail_closed() {
        let invalid_timezone = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("+25:00".to_string()),
                days: Vec::new(),
            }),
            ..Condition::default()
        };
        assert!(!evaluate_condition(
            &invalid_timezone,
            &context_at("2026-04-15T12:00:00Z")
        ));

        let expected = HashMap::from([("user.team".to_string(), serde_json::json!("ops"))]);
        assert!(!evaluate_condition(
            &Condition {
                context: Some(expected),
                ..Condition::default()
            },
            &RuntimeContext::default()
        ));
    }

    #[test]
    fn excessive_condition_nesting_is_rejected() {
        assert!(!evaluate_condition(
            &nested_all_of_condition(MAX_NESTING_DEPTH + 2),
            &RuntimeContext::default()
        ));
        assert!(!evaluate_condition(
            &nested_any_of_condition(MAX_NESTING_DEPTH + 2),
            &RuntimeContext::default()
        ));
    }

    #[test]
    fn compound_conditions_cover_any_of_not_and_full_day_windows() {
        let mut context = RuntimeContext {
            environment: Some("prod".to_string()),
            current_time: Some("2026-04-15T12:00:00Z".to_string()),
            ..RuntimeContext::default()
        };
        context
            .user
            .insert("role".to_string(), serde_json::json!("admin"));
        context
            .session
            .insert("flags".to_string(), serde_json::json!(["trusted", "beta"]));

        let condition = Condition {
            time_window: Some(TimeWindowCondition {
                start: "00:00".to_string(),
                end: "00:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: Vec::new(),
            }),
            all_of: Some(vec![Condition {
                context: Some(HashMap::from([(
                    "user.role".to_string(),
                    serde_json::json!("admin"),
                )])),
                ..Condition::default()
            }]),
            any_of: Some(vec![
                Condition {
                    context: Some(HashMap::from([(
                        "environment".to_string(),
                        serde_json::json!("dev"),
                    )])),
                    ..Condition::default()
                },
                Condition {
                    context: Some(HashMap::from([(
                        "session.flags".to_string(),
                        serde_json::json!("trusted"),
                    )])),
                    ..Condition::default()
                },
            ]),
            not: Some(Box::new(Condition {
                context: Some(HashMap::from([(
                    "custom.blocked".to_string(),
                    serde_json::json!(true),
                )])),
                ..Condition::default()
            })),
            ..Condition::default()
        };

        assert!(evaluate_condition(&condition, &context));
        assert!(evaluate_condition(
            &Condition {
                any_of: Some(Vec::new()),
                ..Condition::default()
            },
            &context
        ));
        assert!(!evaluate_condition(
            &Condition {
                time_window: Some(TimeWindowCondition {
                    start: "09:00".to_string(),
                    end: "17:00".to_string(),
                    timezone: Some("UTC".to_string()),
                    days: vec!["thu".to_string()],
                }),
                ..Condition::default()
            },
            &context
        ));
    }

    #[test]
    fn helper_parsers_and_matchers_cover_remaining_edges() {
        assert_eq!(parse_hhmm("23:59"), Some((23, 59)));
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(day_abbreviation(6), "sun");
        assert_eq!(day_abbreviation(99), "mon");

        assert_eq!(parse_timezone_offset("UTC"), Some(0));
        assert_eq!(parse_timezone_offset("EST"), Some(-5 * 60));
        assert_eq!(parse_timezone_offset("+05:30"), Some(5 * 60 + 30));
        assert_eq!(parse_timezone_offset("-8"), Some(-8 * 60));
        assert_eq!(parse_timezone_offset("+24:00"), None);
        assert_eq!(parse_offset_value("7"), Some(7 * 60));
        assert_eq!(parse_offset_value("12:60"), None);

        let actual = Some(serde_json::json!(["read", "write"]));
        assert!(match_value(&actual, &serde_json::json!("write")));
        assert!(match_value(
            &Some(serde_json::json!("east")),
            &serde_json::json!(["west", "east"])
        ));
        assert!(match_value(
            &Some(serde_json::json!(1.5)),
            &serde_json::json!(1.5)
        ));
        assert!(!match_value(
            &Some(serde_json::json!({"nested": true})),
            &serde_json::json!({"nested": true})
        ));
    }

    #[test]
    fn current_time_and_context_resolution_cover_naive_and_root_map_paths() {
        assert_eq!(
            resolve_current_time(&context_at("2026-04-15T07:45:00"), Some("US/Pacific")),
            Some((0, 45, 2))
        );
        assert_eq!(
            resolve_current_time(&context_at("2026-04-15T12:15:00+02:00"), Some("UTC")),
            Some((10, 15, 2))
        );
        assert_eq!(
            resolve_current_time(&context_at("not-a-timestamp"), Some("UTC")),
            None
        );

        let mut context = RuntimeContext::default();
        context
            .deployment
            .insert("region".to_string(), serde_json::json!("us-east-1"));

        assert_eq!(
            resolve_context_value("deployment.region", &context),
            Some(serde_json::json!("us-east-1"))
        );
        assert_eq!(
            resolve_context_value("deployment", &context),
            Some(serde_json::json!({"region": "us-east-1"}))
        );
        assert_eq!(resolve_context_value("unknown.field", &context), None);
    }
}
