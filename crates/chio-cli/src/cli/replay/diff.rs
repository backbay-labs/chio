// Diff renderer for `chio replay traffic --against`.
// Groups material changes by drift class: allow/deny flip, guard delta,
// and reason delta. Human output is the default; `--json` uses `diff/json.rs`.

mod replay_diff_json {
    use super::*;
    include!("diff/json.rs");
}

mod replay_diff_human {
    use super::*;
    include!("diff/human.rs");
}

pub use replay_diff_human::render_traffic_diff_human;
pub use replay_diff_json::{render_traffic_diff_json, render_traffic_diff_json_string};

/// Stable schema identifier for `chio replay traffic --against --json`.
pub const TRAFFIC_DIFF_SCHEMA_ID: &str = "chio.replay.traffic-diff/v1";

/// Primary drift classes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDriftClass {
    /// Captured and replayed verdicts disagree.
    AllowDenyFlip,
    /// Verdicts agree but the denying guard changed.
    GuardDelta,
    /// Verdicts and guards agree but the denial reason changed.
    ReasonDelta,
}

impl ReplayDriftClass {
    fn human_label(self) -> &'static str {
        match self {
            ReplayDriftClass::AllowDenyFlip => "allow/deny flips",
            ReplayDriftClass::GuardDelta => "guard deltas",
            ReplayDriftClass::ReasonDelta => "reason deltas",
        }
    }
}

/// Normalized decision view for diff rendering.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficReplayDecision {
    /// Captured or replayed verdict.
    pub verdict: chio_tee_frame::Verdict,
    /// Guard attribution when available.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub guard: Option<String>,
    /// Reason attribution when available.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

impl TrafficReplayDecision {
    fn captured(outcome: &TrafficFrameOutcome) -> Self {
        Self {
            verdict: outcome.captured_verdict,
            guard: outcome.captured_guard.clone(),
            reason: outcome.captured_reason.clone(),
        }
    }

    fn replay(outcome: &TrafficFrameOutcome) -> Option<Self> {
        outcome.replay_verdict.map(|verdict| Self {
            verdict,
            guard: outcome.replay_guard.clone(),
            reason: outcome.replay_reason.clone(),
        })
    }

    fn compact(&self) -> String {
        let mut value = format!("verdict={}", traffic_verdict_label(self.verdict));
        if let Some(guard) = self.guard.as_deref() {
            value.push_str(" guard=");
            value.push_str(guard);
        }
        if let Some(reason) = self.reason.as_deref() {
            value.push_str(" reason=");
            value.push_str(reason);
        }
        value
    }
}

/// One drift row under a grouped class.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficReplayDiffItem {
    /// 1-based source line in the input NDJSON.
    pub line: u64,
    /// Source frame id.
    pub frame_id: String,
    /// Namespaced replay receipt id.
    pub replay_receipt_id: String,
    /// Captured production decision view.
    pub captured: TrafficReplayDecision,
    /// Replayed decision view.
    pub replay: TrafficReplayDecision,
}

/// Group of drift rows under one class.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficReplayDiffGroup {
    /// Drift class for the grouped rows.
    pub class: ReplayDriftClass,
    /// Number of rows in this class.
    pub count: u64,
    /// Drift rows in source order.
    pub outcomes: Vec<TrafficReplayDiffItem>,
}

/// Replay execution errors that did not produce a replay decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficReplayErrorItem {
    /// 1-based source line in the input NDJSON.
    pub line: u64,
    /// Source frame id, or `parse-error:<line>` for line parse errors.
    pub frame_id: String,
    /// Namespaced replay receipt id.
    pub replay_receipt_id: String,
    /// Captured production decision view.
    pub captured: TrafficReplayDecision,
    /// Error text returned by the replay path.
    pub error: String,
}

/// Machine-readable grouped diff report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficReplayDiffReport {
    /// Stable schema id.
    pub schema: String,
    /// Replay partition run id.
    pub run_id: String,
    /// `--against` label.
    pub against_label: String,
    /// Total NDJSON frames processed.
    pub total: u64,
    /// Frames with no drift.
    pub matches: u64,
    /// Frames with grouped drift.
    pub drifts: u64,
    /// Frames that failed replay or parsing before a replay verdict.
    pub errors: u64,
    /// Drift groups in stable class order.
    pub groups: Vec<TrafficReplayDiffGroup>,
    /// Error outcomes in source order.
    pub error_outcomes: Vec<TrafficReplayErrorItem>,
}

impl TrafficReplayDiffReport {
    /// `true` when the replay found no drift and no errors.
    pub fn ok(&self) -> bool {
        self.drifts == 0 && self.errors == 0
    }
}

/// Build a grouped diff report from a traffic replay execution report.
#[must_use]
pub fn build_traffic_diff_report(
    report: &TrafficReplayReport,
) -> TrafficReplayDiffReport {
    let mut allow_deny_flips = Vec::new();
    let mut guard_deltas = Vec::new();
    let mut reason_deltas = Vec::new();
    let mut error_outcomes = Vec::new();

    for outcome in &report.outcomes {
        if let Some(error) = outcome.error.as_ref() {
            error_outcomes.push(TrafficReplayErrorItem {
                line: outcome.line,
                frame_id: outcome.frame_id.clone(),
                replay_receipt_id: outcome.replay_receipt_id.clone(),
                captured: TrafficReplayDecision::captured(outcome),
                error: error.clone(),
            });
            continue;
        }

        let Some(replay) = TrafficReplayDecision::replay(outcome) else {
            error_outcomes.push(TrafficReplayErrorItem {
                line: outcome.line,
                frame_id: outcome.frame_id.clone(),
                replay_receipt_id: outcome.replay_receipt_id.clone(),
                captured: TrafficReplayDecision::captured(outcome),
                error: "missing replay verdict".to_string(),
            });
            continue;
        };

        let captured = TrafficReplayDecision::captured(outcome);
        let item = TrafficReplayDiffItem {
            line: outcome.line,
            frame_id: outcome.frame_id.clone(),
            replay_receipt_id: outcome.replay_receipt_id.clone(),
            captured: captured.clone(),
            replay: replay.clone(),
        };

        match classify_traffic_drift(&captured, &replay) {
            Some(ReplayDriftClass::AllowDenyFlip) => allow_deny_flips.push(item),
            Some(ReplayDriftClass::GuardDelta) => guard_deltas.push(item),
            Some(ReplayDriftClass::ReasonDelta) => reason_deltas.push(item),
            None => {}
        }
    }

    let groups = vec![
        diff_group(ReplayDriftClass::AllowDenyFlip, allow_deny_flips),
        diff_group(ReplayDriftClass::GuardDelta, guard_deltas),
        diff_group(ReplayDriftClass::ReasonDelta, reason_deltas),
    ];
    let drifts = groups.iter().map(|group| group.count).sum();
    let errors = error_outcomes.len() as u64;

    TrafficReplayDiffReport {
        schema: TRAFFIC_DIFF_SCHEMA_ID.to_string(),
        run_id: report.run_id.clone(),
        against_label: report.against_label.clone(),
        total: report.total,
        matches: report.matches,
        drifts,
        errors,
        groups,
        error_outcomes,
    }
}

fn diff_group(
    class: ReplayDriftClass,
    outcomes: Vec<TrafficReplayDiffItem>,
) -> TrafficReplayDiffGroup {
    TrafficReplayDiffGroup {
        class,
        count: outcomes.len() as u64,
        outcomes,
    }
}

fn classify_traffic_drift(
    captured: &TrafficReplayDecision,
    replay: &TrafficReplayDecision,
) -> Option<ReplayDriftClass> {
    if captured.verdict != replay.verdict {
        return Some(ReplayDriftClass::AllowDenyFlip);
    }
    if captured.guard != replay.guard {
        return Some(ReplayDriftClass::GuardDelta);
    }
    if captured.reason != replay.reason {
        return Some(ReplayDriftClass::ReasonDelta);
    }
    None
}

fn traffic_verdict_label(verdict: chio_tee_frame::Verdict) -> &'static str {
    match verdict {
        chio_tee_frame::Verdict::Allow => "allow",
        chio_tee_frame::Verdict::Deny => "deny",
        chio_tee_frame::Verdict::Rewrite => "rewrite",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_diff_tests {
    use super::*;

    fn outcome(
        line: u64,
        captured_verdict: chio_tee_frame::Verdict,
        captured_guard: Option<&str>,
        captured_reason: Option<&str>,
        replay_verdict: Option<chio_tee_frame::Verdict>,
        replay_guard: Option<&str>,
        replay_reason: Option<&str>,
    ) -> TrafficFrameOutcome {
        TrafficFrameOutcome {
            line,
            frame_id: format!("frame-{line}"),
            replay_receipt_id: format!("replay:run-1:frame-{line}"),
            captured_verdict,
            captured_guard: captured_guard.map(str::to_string),
            captured_reason: captured_reason.map(str::to_string),
            replay_verdict,
            replay_guard: replay_guard.map(str::to_string),
            replay_reason: replay_reason.map(str::to_string),
            error: None,
        }
    }

    fn base_report(outcomes: Vec<TrafficFrameOutcome>) -> TrafficReplayReport {
        TrafficReplayReport {
            run_id: "run-1".to_string(),
            against_label: "path:policy.yaml".to_string(),
            total: outcomes.len() as u64,
            matches: 0,
            drifts: outcomes.len() as u64,
            errors: 0,
            outcomes,
        }
    }

    #[test]
    fn replay_diff_groups_allow_deny_guard_and_reason_drift() {
        let report = base_report(vec![
            outcome(
                1,
                chio_tee_frame::Verdict::Allow,
                None,
                None,
                Some(chio_tee_frame::Verdict::Deny),
                Some("kernel"),
                Some("scope denied"),
            ),
            outcome(
                2,
                chio_tee_frame::Verdict::Deny,
                Some("pii"),
                Some("email"),
                Some(chio_tee_frame::Verdict::Deny),
                Some("secret-leak"),
                Some("email"),
            ),
            outcome(
                3,
                chio_tee_frame::Verdict::Deny,
                Some("pii"),
                Some("email"),
                Some(chio_tee_frame::Verdict::Deny),
                Some("pii"),
                Some("phone"),
            ),
        ]);

        let diff = build_traffic_diff_report(&report);

        assert_eq!(diff.schema, TRAFFIC_DIFF_SCHEMA_ID);
        assert_eq!(diff.drifts, 3);
        assert_eq!(diff.groups.len(), 3);
        assert_eq!(diff.groups[0].class, ReplayDriftClass::AllowDenyFlip);
        assert_eq!(diff.groups[0].count, 1);
        assert_eq!(diff.groups[1].class, ReplayDriftClass::GuardDelta);
        assert_eq!(diff.groups[1].count, 1);
        assert_eq!(diff.groups[2].class, ReplayDriftClass::ReasonDelta);
        assert_eq!(diff.groups[2].count, 1);
    }

    #[test]
    fn replay_diff_error_outcomes_are_separate_from_drift_classes() {
        let mut item = outcome(
            7,
            chio_tee_frame::Verdict::Deny,
            Some("kernel"),
            Some("old"),
            None,
            None,
            None,
        );
        item.error = Some("parse failed".to_string());
        let report = TrafficReplayReport {
            run_id: "run-1".to_string(),
            against_label: "path:policy.yaml".to_string(),
            total: 1,
            matches: 0,
            drifts: 0,
            errors: 1,
            outcomes: vec![item],
        };

        let diff = build_traffic_diff_report(&report);

        assert_eq!(diff.drifts, 0);
        assert_eq!(diff.errors, 1);
        assert_eq!(diff.error_outcomes[0].error, "parse failed");
        assert!(!diff.ok());
    }
}
