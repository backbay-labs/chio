/// Render the grouped traffic diff in the default human format.
///
/// The layout is intentionally line-oriented and TTY-friendly: a compact
/// summary followed by per-class sections ordered by severity.
pub fn render_traffic_diff_human<W: std::io::Write>(
    writer: &mut W,
    report: &TrafficReplayDiffReport,
) -> Result<(), std::io::Error> {
    writeln!(writer, "chio replay traffic diff")?;
    writeln!(writer, "  against: {}", report.against_label)?;
    writeln!(writer, "  run_id: {}", report.run_id)?;
    writeln!(
        writer,
        "  frames: {} total, {} match, {} drift, {} error",
        report.total, report.matches, report.drifts, report.errors,
    )?;

    if report.ok() {
        writeln!(writer, "  status: ok")?;
        return Ok(());
    }

    for group in report.groups.iter().filter(|group| group.count > 0) {
        writeln!(writer)?;
        writeln!(writer, "{} ({})", group.class.human_label(), group.count)?;
        for item in &group.outcomes {
            writeln!(
                writer,
                "  line {:>4} {}",
                item.line,
                item.replay_receipt_id,
            )?;
            writeln!(
                writer,
                "    captured: {}",
                item.captured.compact(),
            )?;
            writeln!(writer, "    replay:   {}", item.replay.compact())?;
        }
    }

    if !report.error_outcomes.is_empty() {
        writeln!(writer)?;
        writeln!(writer, "replay errors ({})", report.error_outcomes.len())?;
        for item in &report.error_outcomes {
            writeln!(
                writer,
                "  line {:>4} {}",
                item.line,
                item.replay_receipt_id,
            )?;
            writeln!(
                writer,
                "    captured: {}",
                item.captured.compact(),
            )?;
            writeln!(writer, "    error: {}", item.error)?;
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_diff_human_tests {
    use super::*;

    #[test]
    fn replay_diff_human_groups_by_drift_class() {
        let report = TrafficReplayDiffReport {
            schema: TRAFFIC_DIFF_SCHEMA_ID.to_string(),
            run_id: "run-1".to_string(),
            against_label: "path:policy.yaml".to_string(),
            total: 1,
            matches: 0,
            drifts: 1,
            errors: 0,
            groups: vec![TrafficReplayDiffGroup {
                class: ReplayDriftClass::GuardDelta,
                count: 1,
                outcomes: vec![TrafficReplayDiffItem {
                    line: 4,
                    frame_id: "frame-4".to_string(),
                    replay_receipt_id: "replay:run-1:frame-4".to_string(),
                    captured: TrafficReplayDecision {
                        verdict: chio_tee_frame::Verdict::Deny,
                        guard: Some("pii".to_string()),
                        reason: Some("email".to_string()),
                    },
                    replay: TrafficReplayDecision {
                        verdict: chio_tee_frame::Verdict::Deny,
                        guard: Some("secret-leak".to_string()),
                        reason: Some("email".to_string()),
                    },
                }],
            }],
            error_outcomes: vec![],
        };
        let mut out = Vec::new();

        render_traffic_diff_human(&mut out, &report).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(rendered.contains("guard deltas (1)"));
        assert!(rendered.contains("captured: verdict=deny guard=pii reason=email"));
        assert!(rendered.contains("replay:   verdict=deny guard=secret-leak reason=email"));
    }
}
