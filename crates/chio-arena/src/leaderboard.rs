//! Leaderboard renderer for arena fitness reports.
//!
//! Consumes a [`FitnessReport`] (the output of the co-evolution driver) and
//! renders both a Markdown table and a stable-schema JSON document. The JSON
//! schema is pinned at `chio.arena.leaderboard/v1` and is the contract the
//! reputation layer reads against.
//!
//! The verdict oracle that decides who survives an action is upstream of this
//! module: see [`crate::coevolve::evaluate_population`], which composes the
//! cross-provider verdict equality oracle with the toy guard pool. This
//! renderer only ranks the result.

use std::cmp::Ordering;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chio_core::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::coevolve::FitnessReport;

/// Stable schema marker for the leaderboard JSON output.
pub const LEADERBOARD_SCHEMA: &str = "chio.arena.leaderboard/v1";
/// Default leaderboard JSON filename under `target/arena/`.
pub const LEADERBOARD_JSON_FILENAME: &str = "leaderboard.json";
/// Default leaderboard Markdown filename under `target/arena/`.
pub const LEADERBOARD_MARKDOWN_FILENAME: &str = "leaderboard.md";

/// Per-population row in the leaderboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeaderboardRow {
    /// 1-indexed rank, ties broken on population name.
    pub rank: u32,
    /// Population name.
    pub population: String,
    /// Adversary class name.
    pub class: String,
    /// Survival rate in `[0.0, 1.0]`.
    pub survival_rate: f64,
    /// Survivals (the guard pool failed to deny).
    pub survivals: u32,
    /// Defeats (the guard pool denied as expected).
    pub defeats: u32,
    /// Total actions evaluated.
    pub total_actions: u32,
}

/// Top-level leaderboard document. Stable schema chio.arena.leaderboard/v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Leaderboard {
    /// Schema version marker.
    pub schema_version: String,
    /// Scenario id this leaderboard ranks.
    pub scenario_id: String,
    /// Generation index. Use `0` for one-shot renders.
    pub generation: u32,
    /// Population rows sorted descending by survival_rate, ties broken on
    /// population name (ascending) for byte-stable output.
    pub rows: Vec<LeaderboardRow>,
}

impl Leaderboard {
    /// Render the leaderboard from a [`FitnessReport`] for a given scenario.
    pub fn from_fitness_report(report: &FitnessReport, scenario_id: &str, generation: u32) -> Self {
        let mut rows: Vec<LeaderboardRow> = report
            .samples
            .iter()
            .map(|(name, sample)| LeaderboardRow {
                rank: 0,
                // Use the canonical kebab-case identifier (the same one
                // emitted by `AdversaryClass::as_str()` and serialised by
                // `#[serde(rename_all = "kebab-case")]`) so the
                // `chio.arena.leaderboard/v1` schema is consistent with
                // every other arena artifact and matches the canonical
                // "prompt-injection" tokens the reputation surface keys on
                // (not the Debug form "promptinjection").
                population: name.clone(),
                class: sample.class.as_str().to_string(),
                survival_rate: sample.survival_rate(),
                survivals: sample.survivals,
                defeats: sample.defeats,
                total_actions: sample.total(),
            })
            .collect();
        rows.sort_by(|a, b| match b.survival_rate.partial_cmp(&a.survival_rate) {
            Some(Ordering::Equal) | None => a.population.cmp(&b.population),
            Some(other) => other,
        });
        for (idx, row) in rows.iter_mut().enumerate() {
            row.rank = (idx + 1) as u32;
        }
        Self {
            schema_version: LEADERBOARD_SCHEMA.to_string(),
            scenario_id: scenario_id.to_string(),
            generation,
            rows,
        }
    }

    /// Render a Markdown table.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Arena leaderboard ({})\n\n",
            self.schema_version
        ));
        out.push_str(&format!(
            "Scenario: `{}`  Generation: {}\n\n",
            self.scenario_id, self.generation
        ));
        out.push_str(
            "| Rank | Population | Class | Survival rate | Survivals | Defeats | Total |\n",
        );
        out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
        for row in &self.rows {
            out.push_str(&format!(
                "| {} | {} | {} | {:.4} | {} | {} | {} |\n",
                row.rank,
                row.population,
                row.class,
                row.survival_rate,
                row.survivals,
                row.defeats,
                row.total_actions,
            ));
        }
        out
    }

    /// Render the canonical JSON form (stable schema).
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, LeaderboardError> {
        canonical_json_bytes(self).map_err(LeaderboardError::Canonical)
    }
}

/// Outcome of [`render_leaderboard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderboardArtifacts {
    /// Path to the JSON document.
    pub json_path: PathBuf,
    /// Path to the Markdown document.
    pub markdown_path: PathBuf,
}

/// Render and persist the leaderboard under `dir`. The directory is created
/// if it does not exist; existing files are overwritten so re-runs are
/// idempotent.
pub fn render_leaderboard(
    dir: &Path,
    leaderboard: &Leaderboard,
) -> Result<LeaderboardArtifacts, LeaderboardError> {
    fs::create_dir_all(dir).map_err(|source| LeaderboardError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let json_path = dir.join(LEADERBOARD_JSON_FILENAME);
    let markdown_path = dir.join(LEADERBOARD_MARKDOWN_FILENAME);
    let json_bytes = leaderboard.to_canonical_json()?;
    fs::write(&json_path, &json_bytes).map_err(|source| LeaderboardError::Io {
        path: json_path.clone(),
        source,
    })?;
    fs::write(&markdown_path, leaderboard.to_markdown()).map_err(|source| {
        LeaderboardError::Io {
            path: markdown_path.clone(),
            source,
        }
    })?;
    Ok(LeaderboardArtifacts {
        json_path,
        markdown_path,
    })
}

/// Errors emitted by the leaderboard renderer.
#[derive(Debug, Error)]
pub enum LeaderboardError {
    /// Canonical-JSON encoding failed.
    #[error("canonical-JSON encoding failed: {0}")]
    Canonical(#[from] chio_core::Error),
    /// Filesystem write failed.
    #[error("leaderboard write failed at {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}
