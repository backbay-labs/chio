/// Render the grouped traffic diff as a single-line JSON document.
pub fn render_traffic_diff_json<W: std::io::Write>(
    writer: &mut W,
    report: &TrafficReplayDiffReport,
) -> Result<(), std::io::Error> {
    serde_json::to_writer(&mut *writer, report).map_err(std::io::Error::other)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Render the grouped traffic diff as a single-line JSON string.
pub fn render_traffic_diff_json_string(
    report: &TrafficReplayDiffReport,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(report)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_diff_json_tests {
    use super::*;

    #[test]
    fn replay_diff_json_serializes_schema_and_group_classes() {
        let report = TrafficReplayDiffReport {
            schema: TRAFFIC_DIFF_SCHEMA_ID.to_string(),
            run_id: "run-1".to_string(),
            against_label: "path:policy.yaml".to_string(),
            total: 1,
            matches: 0,
            drifts: 1,
            errors: 0,
            groups: vec![TrafficReplayDiffGroup {
                class: ReplayDriftClass::AllowDenyFlip,
                count: 1,
                outcomes: vec![TrafficReplayDiffItem {
                    line: 1,
                    frame_id: "frame-1".to_string(),
                    replay_receipt_id: "replay:run-1:frame-1".to_string(),
                    captured: TrafficReplayDecision {
                        verdict: chio_tee_frame::Verdict::Allow,
                        guard: None,
                        reason: None,
                    },
                    replay: TrafficReplayDecision {
                        verdict: chio_tee_frame::Verdict::Deny,
                        guard: Some("kernel".to_string()),
                        reason: Some("scope denied".to_string()),
                    },
                }],
            }],
            error_outcomes: vec![],
        };

        let json = render_traffic_diff_json_string(&report).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["schema"], TRAFFIC_DIFF_SCHEMA_ID);
        assert_eq!(value["groups"][0]["class"], "allow_deny_flip");
        assert_eq!(value["groups"][0]["outcomes"][0]["line"], 1);
    }
}
