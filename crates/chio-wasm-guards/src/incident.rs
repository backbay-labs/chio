//! Incident writer for hot-reload rollback evidence.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Redacted evaluation trace retained for rollback incidents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalTrace {
    /// Stable request identifier or synthetic test id.
    pub request_id: String,
    /// Verdict class such as `trap`, `fuel_exhausted`, or `serialization`.
    pub verdict_class: String,
    /// Redacted detail string. Request arguments must not be stored here.
    pub detail: String,
}

impl EvalTrace {
    /// Build a redacted evaluation trace.
    #[must_use]
    pub fn new(
        request_id: impl Into<String>,
        verdict_class: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            verdict_class: verdict_class.into(),
            detail: detail.into(),
        }
    }
}

/// Incident payload written when a reload rolls back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadIncident {
    /// Guard identifier.
    pub guard_id: String,
    /// Reload sequence associated with the rolled-back epoch.
    pub reload_seq: u64,
    /// Rolled-back epoch identifier.
    pub epoch_id: u64,
    /// Human-readable fail-closed reason.
    pub reason: String,
    /// Last five redacted traces.
    pub last_5_eval_traces: Vec<EvalTrace>,
}

/// Directory writer rooted at `${XDG_STATE_HOME}/chio/incidents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentWriter {
    root: PathBuf,
}

impl IncidentWriter {
    /// Build an incident writer rooted at `${state_home}/chio/incidents`.
    #[must_use]
    pub fn from_state_home(state_home: impl Into<PathBuf>) -> Self {
        Self::new(state_home.into().join("chio").join("incidents"))
    }

    /// Build an incident writer from an explicit incident root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the incident root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write one rollback incident directory and return its path.
    pub fn write_reload_incident(
        &self,
        incident: &ReloadIncident,
    ) -> Result<PathBuf, IncidentError> {
        let stamp = utc_timestamp();
        let dir = self.root.join(format!(
            "{stamp}-{}-{}",
            sanitize_path_segment(&incident.guard_id),
            incident.reload_seq
        ));
        fs::create_dir_all(&dir).map_err(|source| IncidentError::Io {
            operation: "create",
            path: dir.clone(),
            source,
        })?;

        let summary =
            serde_json::to_vec_pretty(incident).map_err(|source| IncidentError::Json {
                path: dir.join("incident.json"),
                source,
            })?;
        let summary_path = dir.join("incident.json");
        fs::write(&summary_path, summary).map_err(|source| IncidentError::Io {
            operation: "write",
            path: summary_path,
            source,
        })?;

        let traces_path = dir.join("last_5_eval_traces.ndjson");
        let mut traces = Vec::new();
        for trace in &incident.last_5_eval_traces {
            serde_json::to_writer(&mut traces, trace).map_err(|source| IncidentError::Json {
                path: traces_path.clone(),
                source,
            })?;
            traces.push(b'\n');
        }
        fs::write(&traces_path, traces).map_err(|source| IncidentError::Io {
            operation: "write",
            path: traces_path,
            source,
        })?;

        Ok(dir)
    }
}

/// Incident persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum IncidentError {
    /// Incident file IO failed.
    #[error("failed to {operation} incident path {}: {source}", path.display())]
    Io {
        /// Operation name.
        operation: &'static str,
        /// Path being accessed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Incident JSON failed to serialize.
    #[error("incident JSON failed at {}: {source}", path.display())]
    Json {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: serde_json::Error,
    },
}

fn sanitize_path_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => ch,
            _ => '_',
        })
        .collect()
}

fn utc_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_seconds = duration.as_secs() as i64;
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year, month, day)
}
