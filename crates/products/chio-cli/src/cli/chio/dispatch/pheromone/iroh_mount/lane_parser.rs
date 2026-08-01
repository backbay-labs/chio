use super::IrohLane;
use crate::CliError;

/// Parse the comma-separated `--iroh-lanes` value.
///
/// Fail-closed: an empty set, an unknown token, or a lane that is not wireable on
/// the relay-serve hook (revocation / bilateral, see the module docs) is rejected
/// rather than silently dropped.
pub(crate) fn parse_iroh_lanes(raw: &str) -> Result<Vec<IrohLane>, CliError> {
    let mut lanes = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let lane = match token {
            "pheromone" => IrohLane::Pheromone,
            "revocation" => IrohLane::Revocation,
            "bilateral" => IrohLane::Bilateral,
            other => {
                return Err(CliError::cli_other_error(format!(
                    "Chio iroh transport: unknown lane '{other}' (expected pheromone, revocation, or bilateral)"
                )));
            }
        };
        if !matches!(lane, IrohLane::Pheromone) {
            return Err(CliError::cli_other_error(format!(
                "Chio iroh transport: lane '{}' is not yet wired on the pheromone relay serve hook \
                 (it needs collaborators the relay does not host); only 'pheromone' is supported here",
                lane.label()
            )));
        }
        if !lanes.contains(&lane) {
            lanes.push(lane);
        }
    }
    if lanes.is_empty() {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: --iroh-lanes selected no lanes".to_string(),
        ));
    }
    Ok(lanes)
}
