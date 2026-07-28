//! `chio.finding.replay-recipe-input.v1`: the UNSIGNED strict replay
//! verifier input and its cycle-free pre-run template.
//!
//! Integrity comes from bytes, not signatures: a `deterministic_replay`
//! publication must supply a size-bounded strict raw preimage whose
//! canonical digest equals the signed Finding's `replay_recipe_sha256`.
//! This schema registers in the public registry and manifest but MUST NOT
//! enter the signed-artifact allowlist; it travels only as a
//! content-addressed non-authority attachment.
//!
//! The pre-run template commits everything knowable before execution and
//! excludes everything outcome-derived (final payload digest, producing
//! receipts, selected outcome class, claimed verdict). The final recipe
//! binds the exact template digest and then adds those outcome fields
//! without pretending they were known in advance.

use serde::{Deserialize, Serialize};

use crate::profile::{FindingPredicate, FindingResourceCaps};
use crate::types::FindingOutcomeClass;
use crate::validate::{require_hex64, require_non_empty, FindingError};

/// Unsigned replay-recipe verifier input.
pub const FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1: &str = "chio.finding.replay-recipe-input.v1";

/// Replay phase order is normative: baseline first, candidate second.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingRecipePhaseKind {
    Baseline,
    Candidate,
}

/// Claimed predicate verdict. A verdict is a claim to re-check, never a
/// verified fact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingClaimedVerdict {
    PredicateHolds,
    PredicateFails,
}

/// One ordered replay phase with its immutable input commitment and the
/// exact payload-application semantics for that phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingRecipePhase {
    pub phase: FindingRecipePhaseKind,
    pub input_bundle_sha256: String,
    /// How the sealed payload applies in this phase (e.g. `not_applied`
    /// for baseline, `apply_patch_v1` for candidate). Closed vocabulary
    /// is enforced by the verifier profile, not this wire type.
    pub payload_application: String,
}

/// Deterministic execution environment policy. Every member is an exact
/// commitment; "unspecified" is not encodable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingRecipeEnvironment {
    pub runtime_image_sha256: String,
    pub platform: String,
    pub network_policy: String,
    pub clock_policy: String,
    pub randomness_policy: String,
    pub locale: String,
    pub timezone: String,
}

impl FindingRecipeEnvironment {
    fn validate(&self) -> Result<(), FindingError> {
        require_hex64(
            &self.runtime_image_sha256,
            "environment.runtime_image_sha256",
        )?;
        require_non_empty(&self.platform, "environment.platform")?;
        require_non_empty(&self.network_policy, "environment.network_policy")?;
        require_non_empty(&self.clock_policy, "environment.clock_policy")?;
        require_non_empty(&self.randomness_policy, "environment.randomness_policy")?;
        require_non_empty(&self.locale, "environment.locale")?;
        require_non_empty(&self.timezone, "environment.timezone")?;
        Ok(())
    }
}

/// Cycle-free pre-run descriptor/protocol template. Committed (by digest)
/// through the intent receipt BEFORE execution; the final recipe binds the
/// same digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPreRunTemplate {
    pub topic: String,
    pub context_sha256: String,
    pub verifier_profile_envelope_sha256: String,
    pub runner_server: String,
    pub runner_tool: String,
    pub runner_manifest_sha256: String,
    pub input_bundle_sha256s: Vec<String>,
    pub environment: FindingRecipeEnvironment,
    pub resource_bounds: FindingResourceCaps,
    pub allowed_predicates: Vec<FindingPredicate>,
    pub allowed_outcome_classes: Vec<FindingOutcomeClass>,
}

impl FindingPreRunTemplate {
    pub fn validate(&self) -> Result<(), FindingError> {
        require_non_empty(&self.topic, "template.topic")?;
        require_hex64(&self.context_sha256, "template.context_sha256")?;
        require_hex64(
            &self.verifier_profile_envelope_sha256,
            "template.verifier_profile_envelope_sha256",
        )?;
        require_non_empty(&self.runner_server, "template.runner_server")?;
        require_non_empty(&self.runner_tool, "template.runner_tool")?;
        require_hex64(
            &self.runner_manifest_sha256,
            "template.runner_manifest_sha256",
        )?;
        if self.input_bundle_sha256s.is_empty() {
            return Err(FindingError::MissingEntry("template.input_bundle_sha256s"));
        }
        for bundle in &self.input_bundle_sha256s {
            require_hex64(bundle, "template.input_bundle_sha256s[]")?;
        }
        self.environment.validate()?;
        self.resource_bounds.validate()?;
        if self.allowed_predicates.is_empty() {
            return Err(FindingError::MissingEntry("template.allowed_predicates"));
        }
        if self.allowed_outcome_classes.is_empty() {
            return Err(FindingError::MissingEntry(
                "template.allowed_outcome_classes",
            ));
        }
        Ok(())
    }

    /// Canonical digest of the template, the value the intent receipt's
    /// parameter hash and the final recipe both commit.
    pub fn canonical_sha256(&self) -> Result<String, FindingError> {
        let bytes = chio_core_types::canonical_json_bytes(self)
            .map_err(|_| FindingError::Canonicalization)?;
        Ok(chio_core_types::crypto::sha256_hex(&bytes))
    }
}

/// The unsigned strict replay-recipe input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingReplayRecipeInput {
    pub schema: String,
    pub decision_rule_ref: String,
    /// Envelope digest of the ALREADY admitted verifier profile; the
    /// recipe commits the profile, never the reverse.
    pub verifier_profile_envelope_sha256: String,
    /// Finding context and payload commitments.
    pub context_sha256: String,
    pub payload_sha256: String,
    /// Mediated runner binding.
    pub runner_server: String,
    pub runner_tool: String,
    pub runner_manifest_sha256: String,
    /// Ordered phases: exactly baseline then candidate for the v1
    /// predicate.
    pub phases: Vec<FindingRecipePhase>,
    /// Canonical parameter bundle digest (content-addressed dependency,
    /// retained alongside the recipe); no inline parameters, no
    /// substitution ambiguity.
    pub parameters_sha256: String,
    pub environment: FindingRecipeEnvironment,
    pub resource_bounds: FindingResourceCaps,
    pub predicate: FindingPredicate,
    /// Digest of the cycle-free pre-run template above.
    pub pre_run_template_sha256: String,
    pub claimed_verdict: FindingClaimedVerdict,
}

impl FindingReplayRecipeInput {
    /// Structural validation. Digest cross-checks against the Finding and
    /// retained dependencies are surface obligations (publish/verify),
    /// not wire-type checks.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_non_empty(&self.decision_rule_ref, "decision_rule_ref")?;
        require_hex64(
            &self.verifier_profile_envelope_sha256,
            "verifier_profile_envelope_sha256",
        )?;
        require_hex64(&self.context_sha256, "context_sha256")?;
        require_hex64(&self.payload_sha256, "payload_sha256")?;
        require_non_empty(&self.runner_server, "runner_server")?;
        require_non_empty(&self.runner_tool, "runner_tool")?;
        require_hex64(&self.runner_manifest_sha256, "runner_manifest_sha256")?;
        if self.phases.len() != 2
            || self.phases[0].phase != FindingRecipePhaseKind::Baseline
            || self.phases[1].phase != FindingRecipePhaseKind::Candidate
        {
            return Err(FindingError::InvalidField("phases"));
        }
        for phase in &self.phases {
            require_hex64(&phase.input_bundle_sha256, "phases[].input_bundle_sha256")?;
            require_non_empty(&phase.payload_application, "phases[].payload_application")?;
        }
        require_hex64(&self.parameters_sha256, "parameters_sha256")?;
        self.environment.validate()?;
        self.resource_bounds.validate()?;
        require_hex64(&self.pre_run_template_sha256, "pre_run_template_sha256")?;
        Ok(())
    }

    /// Canonical digest of the recipe input; must equal the signed
    /// Finding's `replay_recipe_sha256` for a `deterministic_replay`
    /// publication.
    pub fn canonical_sha256(&self) -> Result<String, FindingError> {
        let bytes = chio_core_types::canonical_json_bytes(self)
            .map_err(|_| FindingError::Canonicalization)?;
        Ok(chio_core_types::crypto::sha256_hex(&bytes))
    }
}
