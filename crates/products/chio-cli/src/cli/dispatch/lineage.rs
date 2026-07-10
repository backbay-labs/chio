use super::*;

pub(crate) fn dispatch_lineage(command: LineageCommands, json_output: bool) -> Result<(), CliError> {
    use crate::lineage as ln;
    use chio_lineage::query::QueryBounds;
    match command {
        LineageCommands::Query {
            graph,
            seeds,
            direction,
            depth_limit,
            row_limit,
            json,
        } => {
            let dir = match direction.as_str() {
                "forward" => ln::Direction::Forward,
                "reverse" => ln::Direction::Reverse,
                other => {
                    return Err(CliError::Other(format!(
                        "lineage query: unknown direction {other:?}; expected forward or reverse"
                    )));
                }
            };
            let bounds = QueryBounds {
                depth_limit,
                row_limit,
            };
            let report = ln::cmd_query(&graph, &seeds, dir, bounds)
                .map_err(|e| CliError::Other(format!("lineage query: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let line = format!(
                    "lineage {}: nodes={} edges={}\n",
                    report.direction,
                    report.graph.nodes.len(),
                    report.graph.edges.len(),
                );
                std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage query write: {e}")))
            }
        }
        LineageCommands::Diff {
            left_label,
            left,
            right_label,
            right,
            json,
        } => {
            let report = ln::cmd_diff(&left_label, &left, &right_label, &right)
                .map_err(|e| CliError::Other(format!("lineage diff: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let text = ln::render_diff_text(&report);
                std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage diff write: {e}")))
            }
        }
        LineageCommands::Roots { dir, json } => {
            let report =
                ln::cmd_roots(&dir).map_err(|e| CliError::Other(format!("lineage roots: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let line = format!("anchored roots: {}\n", report.roots.len());
                std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage roots write: {e}")))
            }
        }
    }
}

pub(crate) fn emit_lineage_report<T: serde::Serialize>(report: &T, json: bool) -> Result<(), CliError> {
    if json {
        let bytes = serde_json::to_vec_pretty(report)
            .map_err(|e| CliError::Other(format!("lineage serialize: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
    } else {
        let line = serde_json::to_string(report)
            .map_err(|e| CliError::Other(format!("lineage serialize: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
    }
    Ok(())
}
