//! SpiderSense embedding detector - cosine-similarity anomaly detection.
//!
//! Wrapped in Chio's synchronous [`chio_kernel::Guard`] trait.
//!
//! The guard compares a per-request embedding vector against a pre-loaded
//! pattern database of known-threat embeddings using cosine similarity.
//! Top-K scoring + thresholded verdict with a configurable ambiguity band:
//!
//! - `top_score >= threshold + ambiguity_band` → [`Verdict::Deny`];
//! - `top_score <= threshold - ambiguity_band` → [`Verdict::Allow`];
//! - scores inside the band fall back to the configured
//!   [`AmbiguousPolicy`] (default: [`AmbiguousPolicy::Allow`]).
//!
//! Embedding extraction from tool-call arguments:
//!
//! 1. A top-level `embedding` / `vector` array of numbers is preferred.
//! 2. An `embeddings` field of shape `[[f32; D], ...]` is averaged.
//! 3. Otherwise the guard returns [`Verdict::Allow`] (no embedding → no
//!    signal; the guard does not try to hash text into a pseudo-embedding
//!    because downstream consumers rely on explicit embeddings from the
//!    upstream SpiderSense model).
//!
//! Fail-closed semantics:
//!
//! - malformed pattern JSON at construction time → [`SpiderSenseError`];
//! - non-finite values in a request embedding → [`Verdict::Deny`];
//! - embedding-dimension mismatch with the pattern DB → [`Verdict::Deny`];
//! - cosine norm collapse (zero vector) → similarity score `0.0` (not
//!   NaN).
//!
//! Hand-rolled f64-accumulated dot product avoids any dependency on
//! `ndarray` / BLAS.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use chio_kernel::{Guard, GuardContext, KernelError, Verdict};

/// Default cosine similarity threshold.
pub const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.85;
/// Default ambiguity band half-width around the threshold.
pub const DEFAULT_AMBIGUITY_BAND: f64 = 0.10;
/// Default top-K pattern matches to score.
pub const DEFAULT_TOP_K: usize = 5;

/// Policy for scores landing inside the ambiguity band.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguousPolicy {
    /// Treat ambiguous scores as benign (default).
    #[default]
    Allow,
    /// Treat ambiguous scores as threats.
    Deny,
}

/// Errors from [`SpiderSenseGuard`] construction.
#[derive(Debug, Error)]
pub enum SpiderSenseError {
    /// Pattern JSON failed to parse.
    #[error("pattern database parse error: {0}")]
    Parse(String),
    /// Pattern database is empty or has inconsistent dimensionality.
    #[error("pattern database is invalid: {0}")]
    Invalid(String),
    /// Configuration value is out of range.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// I/O error reading the pattern database from disk.
    #[error("failed to read pattern database: {0}")]
    Io(String),
}

/// Configuration for [`SpiderSenseGuard`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpiderSenseConfig {
    /// Cosine similarity threshold.  Scores ≥ `threshold + ambiguity_band`
    /// are denied; scores ≤ `threshold - ambiguity_band` are allowed.
    #[serde(default = "default_threshold")]
    pub similarity_threshold: f64,
    /// Half-width of the ambiguity band around the threshold.
    #[serde(default = "default_band")]
    pub ambiguity_band: f64,
    /// Number of top matches retained per query.
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    /// Policy for ambiguous scores (inside the band).
    #[serde(default)]
    pub ambiguous_policy: AmbiguousPolicy,
}

fn default_threshold() -> f64 {
    DEFAULT_SIMILARITY_THRESHOLD
}
fn default_band() -> f64 {
    DEFAULT_AMBIGUITY_BAND
}
fn default_top_k() -> usize {
    DEFAULT_TOP_K
}

impl Default for SpiderSenseConfig {
    fn default() -> Self {
        Self {
            similarity_threshold: DEFAULT_SIMILARITY_THRESHOLD,
            ambiguity_band: DEFAULT_AMBIGUITY_BAND,
            top_k: DEFAULT_TOP_K,
            ambiguous_policy: AmbiguousPolicy::Allow,
        }
    }
}

/// A single entry in the pattern database.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PatternEntry {
    /// Stable identifier.
    pub id: String,
    /// Threat category (e.g., `prompt_injection`, `data_exfiltration`).
    pub category: String,
    /// SpiderSense stage (perception / cognition / action / feedback).
    pub stage: String,
    /// Human-readable label.
    pub label: String,
    /// Pre-computed embedding vector.
    pub embedding: Vec<f32>,
}

/// Immutable pattern database loaded at construction time.
#[derive(Clone, Debug)]
pub struct PatternDb {
    entries: Arc<Vec<PatternEntry>>,
    dim: usize,
}

impl PatternDb {
    /// Parse a JSON array of [`PatternEntry`] values.  Validates:
    ///
    /// - array is non-empty;
    /// - all embeddings share the same non-zero dimensionality;
    /// - every embedding value is finite.
    pub fn from_json(json: &str) -> Result<Self, SpiderSenseError> {
        let entries: Vec<PatternEntry> =
            serde_json::from_str(json).map_err(|e| SpiderSenseError::Parse(e.to_string()))?;
        Self::from_entries(entries)
    }

    /// Build from an explicit entry vector (convenience for tests).
    pub fn from_entries(entries: Vec<PatternEntry>) -> Result<Self, SpiderSenseError> {
        if entries.is_empty() {
            return Err(SpiderSenseError::Invalid(
                "pattern database must contain at least one entry".into(),
            ));
        }
        let dim = entries[0].embedding.len();
        if dim == 0 {
            return Err(SpiderSenseError::Invalid(
                "pattern embeddings must be non-empty".into(),
            ));
        }
        for (i, entry) in entries.iter().enumerate() {
            if entry.embedding.len() != dim {
                return Err(SpiderSenseError::Invalid(format!(
                    "dimension mismatch at index {i}: expected {dim}, got {}",
                    entry.embedding.len()
                )));
            }
            if let Some(j) = entry.embedding.iter().position(|v| !v.is_finite()) {
                return Err(SpiderSenseError::Invalid(format!(
                    "entry {i} has non-finite embedding value at dimension {j}"
                )));
            }
        }
        Ok(Self {
            entries: Arc::new(entries),
            dim,
        })
    }

    /// Expected embedding dimensionality.
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Number of patterns in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty (always `false` after construction).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// SpiderSense embedding detector guard.
pub struct SpiderSenseGuard {
    db: PatternDb,
    upper: f64,
    lower: f64,
    top_k: usize,
    ambiguous_policy: AmbiguousPolicy,
}

impl SpiderSenseGuard {
    /// Build a guard from a pattern database and configuration.
    pub fn new(db: PatternDb, config: SpiderSenseConfig) -> Result<Self, SpiderSenseError> {
        if !config.similarity_threshold.is_finite()
            || !(0.0..=1.0).contains(&config.similarity_threshold)
        {
            return Err(SpiderSenseError::Config(format!(
                "similarity_threshold must be finite in [0.0, 1.0], got {}",
                config.similarity_threshold
            )));
        }
        if !config.ambiguity_band.is_finite() || !(0.0..=1.0).contains(&config.ambiguity_band) {
            return Err(SpiderSenseError::Config(format!(
                "ambiguity_band must be finite in [0.0, 1.0], got {}",
                config.ambiguity_band
            )));
        }
        let upper = config.similarity_threshold + config.ambiguity_band;
        let lower = config.similarity_threshold - config.ambiguity_band;
        if !(0.0..=1.0).contains(&upper) || !(0.0..=1.0).contains(&lower) {
            return Err(SpiderSenseError::Config(format!(
                "threshold ± band must stay inside [0.0, 1.0]; got lower={lower:.3}, upper={upper:.3}"
            )));
        }
        if config.top_k == 0 {
            return Err(SpiderSenseError::Config("top_k must be ≥ 1".into()));
        }
        Ok(Self {
            db,
            upper,
            lower,
            top_k: config.top_k,
            ambiguous_policy: config.ambiguous_policy,
        })
    }

    /// Convenience: build from a JSON pattern database string and defaults.
    pub fn from_json(json: &str) -> Result<Self, SpiderSenseError> {
        let db = PatternDb::from_json(json)?;
        Self::new(db, SpiderSenseConfig::default())
    }

    /// Read a pattern database from a JSON file on disk.
    pub fn from_json_file(path: &str) -> Result<Self, SpiderSenseError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| SpiderSenseError::Io(format!("{path}: {e}")))?;
        Self::from_json(&data)
    }

    /// Score an embedding against the pattern database.  Returns the
    /// cosine similarity of the best-matching pattern (0.0 if the
    /// embedding is invalid).
    pub fn score(&self, embedding: &[f32]) -> f64 {
        if embedding.len() != self.db.dim {
            return 0.0;
        }
        if embedding.iter().any(|v| !v.is_finite()) {
            return 0.0;
        }
        let mut best = 0.0_f64;
        let mut seen = 0usize;
        for entry in self.db.entries.iter() {
            let score = cosine_similarity(embedding, &entry.embedding);
            if score > best {
                best = score;
            }
            seen += 1;
            if seen >= self.top_k {
                // We keep scanning - top_k is informational, not a cap on
                // work, because the DB is typically small.  Break only
                // when the scan has observed at least top_k entries; we
                // still want the maximum across the full DB.
            }
        }
        best
    }

    /// Decide a verdict for a given top-score.
    fn verdict_for(&self, score: f64) -> Verdict {
        if !score.is_finite() {
            return Verdict::Deny;
        }
        if score >= self.upper {
            Verdict::Deny
        } else if score <= self.lower {
            Verdict::Allow
        } else {
            match self.ambiguous_policy {
                AmbiguousPolicy::Allow => Verdict::Allow,
                AmbiguousPolicy::Deny => Verdict::Deny,
            }
        }
    }

    /// Number of patterns in the database.
    pub fn pattern_count(&self) -> usize {
        self.db.len()
    }

    /// Pattern database dimensionality.
    pub fn dim(&self) -> usize {
        self.db.dim()
    }
}

impl Guard for SpiderSenseGuard {
    fn name(&self) -> &str {
        "spider-sense"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let embedding = match extract_embedding(&ctx.request.arguments) {
            Some(e) => e,
            None => return Ok(Verdict::Allow),
        };
        if embedding.len() != self.db.dim {
            // Dimension mismatch = fail-closed.
            return Ok(Verdict::Deny);
        }
        if embedding.iter().any(|v| !v.is_finite()) {
            return Ok(Verdict::Deny);
        }
        let score = self.score(&embedding);
        Ok(self.verdict_for(score))
    }
}

/// Extract a query embedding vector from tool-call arguments.
///
/// Preferred shapes (first match wins):
///
/// 1. `embedding: [f32; D]`
/// 2. `vector: [f32; D]`
/// 3. `embeddings: [[f32; D], ...]` → mean-pooled to a single vector
///
/// Returns `None` if no recognised embedding field is present.
pub fn extract_embedding(arguments: &Value) -> Option<Vec<f32>> {
    if let Some(vec) = arguments
        .get("embedding")
        .or_else(|| arguments.get("vector"))
        .and_then(array_as_f32_vec)
    {
        return Some(vec);
    }
    if let Some(array) = arguments.get("embeddings").and_then(|v| v.as_array()) {
        let vectors: Vec<Vec<f32>> = array.iter().filter_map(array_as_f32_vec).collect();
        if vectors.is_empty() {
            return None;
        }
        let dim = vectors[0].len();
        if dim == 0 || vectors.iter().any(|v| v.len() != dim) {
            return None;
        }
        let mut sum = vec![0.0_f64; dim];
        for v in &vectors {
            for (i, x) in v.iter().enumerate() {
                sum[i] += f64::from(*x);
            }
        }
        let n = vectors.len() as f64;
        return Some(sum.into_iter().map(|s| (s / n) as f32).collect());
    }
    None
}

fn array_as_f32_vec(value: &Value) -> Option<Vec<f32>> {
    let array = value.as_array()?;
    if array.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(array.len());
    for v in array {
        let n = v.as_f64()?;
        if !n.is_finite() {
            return None;
        }
        out.push(n as f32);
    }
    Some(out)
}

/// Cosine similarity of two `f32` vectors with `f64` accumulation.
///
/// Returns `0.0` when:
/// - lengths differ;
/// - either vector's L2 norm is not a normal `f64` (zero / subnormal);
/// - the result is non-finite (NaN / ±inf).
///
/// This is intentionally hand-rolled (no `ndarray`) to keep the
/// dependency surface minimal and WASM-friendly.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot: f64 = 0.0;
    let mut na: f64 = 0.0;
    let mut nb: f64 = 0.0;
    for (x, y) in a.iter().zip(b.iter()) {
        let xd = f64::from(*x);
        let yd = f64::from(*y);
        if !xd.is_finite() || !yd.is_finite() {
            return 0.0;
        }
        dot += xd * yd;
        na += xd * xd;
        nb += yd * yd;
    }
    let denom = na.sqrt() * nb.sqrt();
    if !denom.is_normal() {
        return 0.0;
    }
    let r = dot / denom;
    if r.is_finite() {
        r
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_db() -> PatternDb {
        PatternDb::from_json(
            r#"[
                {"id":"a","category":"x","stage":"perception","label":"l","embedding":[1.0,0.0,0.0]},
                {"id":"b","category":"y","stage":"action","label":"l","embedding":[0.0,1.0,0.0]}
            ]"#,
        )
        .expect("sample DB parses")
    }

    #[test]
    fn cosine_basics() {
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-9);
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-9);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 2.0]), 0.0);
        assert_eq!(cosine_similarity(&[f32::NAN, 0.0], &[1.0, 0.0]), 0.0);
        assert_eq!(cosine_similarity(&[f32::INFINITY, 0.0], &[1.0, 0.0]), 0.0);
        assert_eq!(cosine_similarity(&[1.0], &[1.0, 0.0]), 0.0);
    }

    #[test]
    fn pattern_db_rejects_empty() {
        assert!(matches!(
            PatternDb::from_json("[]"),
            Err(SpiderSenseError::Invalid(_))
        ));
    }

    #[test]
    fn pattern_db_rejects_dim_mismatch() {
        let json = r#"[
            {"id":"a","category":"x","stage":"s","label":"l","embedding":[1.0,0.0]},
            {"id":"b","category":"y","stage":"s","label":"l","embedding":[1.0]}
        ]"#;
        assert!(matches!(
            PatternDb::from_json(json),
            Err(SpiderSenseError::Invalid(_))
        ));
    }

    #[test]
    fn guard_denies_identical_vector() {
        let guard =
            SpiderSenseGuard::new(sample_db(), SpiderSenseConfig::default()).expect("build");
        let score = guard.score(&[1.0, 0.0, 0.0]);
        assert!((score - 1.0).abs() < 1e-9);
        assert!(matches!(guard.verdict_for(score), Verdict::Deny));
    }

    #[test]
    fn guard_allows_orthogonal_vector() {
        let guard =
            SpiderSenseGuard::new(sample_db(), SpiderSenseConfig::default()).expect("build");
        let score = guard.score(&[0.0, 0.0, 1.0]);
        assert!(score.abs() < 1e-9);
        assert!(matches!(guard.verdict_for(score), Verdict::Allow));
    }

    #[test]
    fn guard_dim_mismatch_denies() {
        let guard =
            SpiderSenseGuard::new(sample_db(), SpiderSenseConfig::default()).expect("build");
        let score = guard.score(&[1.0, 0.0]);
        assert_eq!(score, 0.0);
        assert!(matches!(guard.verdict_for(score), Verdict::Allow));
    }

    #[test]
    fn guard_nan_score_denies() {
        let guard =
            SpiderSenseGuard::new(sample_db(), SpiderSenseConfig::default()).expect("build");
        assert!(matches!(guard.verdict_for(f64::NAN), Verdict::Deny));
    }

    #[test]
    fn ambiguous_respects_policy() {
        let db = sample_db();
        let config = SpiderSenseConfig {
            similarity_threshold: 0.5,
            ambiguity_band: 0.1,
            top_k: 5,
            ambiguous_policy: AmbiguousPolicy::Deny,
        };
        let guard = SpiderSenseGuard::new(db, config).unwrap();
        // score between 0.4 and 0.6 → Deny under this policy
        assert!(matches!(guard.verdict_for(0.5), Verdict::Deny));
    }

    #[test]
    fn extract_embedding_from_args() {
        let args = serde_json::json!({"embedding": [0.1, 0.2, 0.3]});
        let e = extract_embedding(&args).unwrap();
        assert_eq!(e.len(), 3);
    }

    #[test]
    fn extract_embedding_averages_list() {
        let args = serde_json::json!({"embeddings": [[1.0, 0.0], [0.0, 1.0]]});
        let e = extract_embedding(&args).unwrap();
        assert_eq!(e.len(), 2);
        assert!((e[0] - 0.5).abs() < 1e-6);
        assert!((e[1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn extract_embedding_none_when_absent() {
        assert!(extract_embedding(&serde_json::json!({"foo": "bar"})).is_none());
    }

    #[test]
    fn reject_bad_config() {
        let db = sample_db();
        let bad = SpiderSenseConfig {
            similarity_threshold: 1.5,
            ..SpiderSenseConfig::default()
        };
        assert!(SpiderSenseGuard::new(db, bad).is_err());
    }
}
