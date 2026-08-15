use chio_core::crypto::sha256_hex;
use chio_core::receipt::decision::ToolCallAction;
use chio_finding::{FindingRecipePhaseKind, FindingReplayRecipeInput, FindingReplayTerminalResult};

use super::{AnyError, REPLAY_RUN_ID};

/// One reproduction phase as the runner reported it.
#[derive(Debug, Clone, Copy)]
pub(super) struct PhaseShape {
    pub(super) phase: FindingRecipePhaseKind,
    pub(super) terminal: FindingReplayTerminalResult,
    pub(super) exit_code: i64,
}

impl PhaseShape {
    pub(super) const fn baseline_fails() -> Self {
        Self {
            phase: FindingRecipePhaseKind::Baseline,
            terminal: FindingReplayTerminalResult::Completed,
            exit_code: 1,
        }
    }

    pub(super) const fn candidate_passes() -> Self {
        Self {
            phase: FindingRecipePhaseKind::Candidate,
            terminal: FindingReplayTerminalResult::Completed,
            exit_code: 0,
        }
    }

    pub(super) const fn candidate_fails() -> Self {
        Self {
            exit_code: 1,
            ..Self::candidate_passes()
        }
    }
}

pub(super) struct ReplayActionFactory {
    recipe: FindingReplayRecipeInput,
    recipe_sha256: String,
}

impl ReplayActionFactory {
    pub(super) fn from_preimage(preimage: &str) -> Result<Self, AnyError> {
        Ok(Self {
            recipe: serde_json::from_str(preimage)?,
            recipe_sha256: sha256_hex(preimage.as_bytes()),
        })
    }

    pub(super) fn recipe_sha256(&self) -> &str {
        &self.recipe_sha256
    }

    pub(super) fn for_phase(
        &self,
        phase: FindingRecipePhaseKind,
    ) -> Result<ToolCallAction, AnyError> {
        let recipe_phase = self
            .recipe
            .phases
            .iter()
            .find(|recipe_phase| recipe_phase.phase == phase)
            .ok_or_else(|| std::io::Error::other("replay phase absent from committed recipe"))?;
        Ok(ToolCallAction::from_parameters(serde_json::json!({
            "input_bundle_sha256": &recipe_phase.input_bundle_sha256,
            "parameters_sha256": &self.recipe.parameters_sha256,
            "phase": recipe_phase.phase,
            "pre_run_template_sha256": &self.recipe.pre_run_template_sha256,
            "recipe_sha256": &self.recipe_sha256,
            "replay_run_id": REPLAY_RUN_ID,
            "runner_manifest_sha256": &self.recipe.runner_manifest_sha256,
            "verifier_profile_envelope_sha256":
                &self.recipe.verifier_profile_envelope_sha256,
        }))?)
    }
}
