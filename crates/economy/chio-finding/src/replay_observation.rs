//! `chio.finding.replay-observation.v1`: the UNSIGNED strict preimage one
//! replay execution emits for one phase.
//!
//! Integrity comes from bytes, not from a signature. The governed executor
//! writes these bytes, the mediated runner receipt commits their digest as
//! its `content_hash`, and the checkpoint proves the receipt. A challenge
//! therefore carries the exact preimage and lets the consumer re-derive the
//! digest instead of trusting a restated summary. Like the replay recipe
//! input, this schema registers in the public registry and manifest but MUST
//! NOT enter the signed-artifact allowlist.
//!
//! Every member is a commitment that was fixed before the phase ran, plus
//! the phase's own terminal facts. There is no member for a claimed verdict:
//! the predicate belongs to the committed recipe, and an observation that
//! could assert its own conclusion would be an opinion rather than evidence.

use serde::{Deserialize, Serialize};

use crate::recipe::FindingRecipePhaseKind;
use crate::validate::{require_bounded_id, require_hex64, FindingError};

/// Unsigned strict replay observation preimage.
pub const FINDING_REPLAY_OBSERVATION_SCHEMA_V1: &str = "chio.finding.replay-observation.v1";

/// Bound on one canonical observation preimage. Observations travel inside
/// challenge submissions, so an unbounded one is an amplification vector.
pub const MAX_REPLAY_OBSERVATION_BYTES: usize = 16_384;

/// Lowest and highest process exit status an observation may report,
/// covering POSIX statuses and the negated-signal convention.
const MIN_EXIT_CODE: i64 = -256;
const MAX_EXIT_CODE: i64 = 255;

/// How one replay phase ended. Closed vocabulary: only `completed`
/// observations can feed a predicate, and every other terminal is an
/// infrastructure fact that can never become seller fraud.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingReplayTerminalResult {
    /// The phase ran to completion and its report is authoritative.
    Completed,
    /// The runner reported a failed execution.
    Failed,
    /// The phase exceeded its committed runtime bound.
    TimedOut,
    /// The phase exceeded a committed resource cap.
    ResourceExhausted,
    /// The runner itself failed before or after the phase.
    RunnerError,
}

impl FindingReplayTerminalResult {
    /// Whether a predicate may read this observation at all.
    #[must_use]
    pub fn is_completed(self) -> bool {
        matches!(self, FindingReplayTerminalResult::Completed)
    }
}

/// One phase of one replay run, as the executor observed it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingReplayObservation {
    pub schema: String,
    /// Canonical digest of the committed `chio.finding.replay-recipe-input.v1`.
    pub recipe_digest: String,
    /// Envelope digest of the admitted challenge-verifier profile.
    pub verifier_profile_digest: String,
    /// Which committed phase this observation covers.
    pub phase_id: FindingRecipePhaseKind,
    pub runner_manifest_digest: String,
    pub resolved_input_bundle_digest: String,
    pub environment_digest: String,
    pub terminal_result: FindingReplayTerminalResult,
    pub exit_code: i64,
    pub report_digest: String,
    /// Shared by every phase of one execution; the tuples a challenge
    /// carries must agree on it.
    pub replay_run_id: String,
}

impl FindingReplayObservation {
    /// Structural validation. Resolving the digests against the recipe, the
    /// profile, and the mediated receipt is the consumer's obligation.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_REPLAY_OBSERVATION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.recipe_digest, "recipe_digest")?;
        require_hex64(&self.verifier_profile_digest, "verifier_profile_digest")?;
        require_hex64(&self.runner_manifest_digest, "runner_manifest_digest")?;
        require_hex64(
            &self.resolved_input_bundle_digest,
            "resolved_input_bundle_digest",
        )?;
        require_hex64(&self.environment_digest, "environment_digest")?;
        if !(MIN_EXIT_CODE..=MAX_EXIT_CODE).contains(&self.exit_code) {
            return Err(FindingError::InvalidField("exit_code"));
        }
        require_hex64(&self.report_digest, "report_digest")?;
        require_bounded_id(&self.replay_run_id, "replay_run_id")
    }

    /// Canonical digest of the observation. The mediated replay receipt's
    /// `content_hash` MUST equal this value; the evaluator enforces that
    /// equality, this type only defines the derivation.
    pub fn canonical_sha256(&self) -> Result<String, FindingError> {
        let bytes = chio_core_types::canonical_json_bytes(self)
            .map_err(|_| FindingError::Canonicalization)?;
        Ok(chio_core_types::crypto::sha256_hex(&bytes))
    }
}
