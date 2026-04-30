//! DSL-aware mutation operator tests (M08.P4.T2).
//!
//! Asserts:
//!
//!   * Mutation never alters the determinism witness (we test the
//!     blueprint shape directly; the operator surface is forbidden from
//!     touching anything outside the adversary block by construction).
//!   * Per-class mutation strategies all emit a result that differs from
//!     the input when the canonical alternative set is non-empty.
//!   * Mutation is deterministic: same RNG seed and same input produce
//!     byte-identical output.
//!   * `MutationConfig::max_mutations = 0` is rejected.

use chio_arena::adversary::capability_overrequest::OverrequestVariant;
use chio_arena::adversary::scope_escape::ScopeEscalation;
use chio_arena::{
    mutate_overrequest_population, mutate_population, mutate_prompt_injection_population,
    mutate_replay_attempt_population, mutate_scope_escape_population, MutationConfig,
    MutationError, MutationKind, OverrequestBlueprint, PopulationBlueprint,
    PromptInjectionBlueprint, ReplayAttemptBlueprint, ReplayAttemptEntry, ScopeEscapeBlueprint,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn prompt_injection_mutation_changes_pattern_field() -> Result<(), Box<dyn std::error::Error>> {
    let blueprint = PromptInjectionBlueprint {
        population: "p".to_string(),
        patterns: vec!["ignore-previous-instructions", "system-prompt-leak"],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (mutated, kind) =
        mutate_prompt_injection_population(&blueprint, &mut rng, MutationConfig::default())?;
    assert_eq!(mutated.population, blueprint.population);
    assert!(matches!(
        kind,
        MutationKind::PromptInjectionPatternSwap | MutationKind::PromptInjectionReorder
    ));
    assert_ne!(mutated.patterns, blueprint.patterns);
    Ok(())
}

#[test]
fn overrequest_mutation_swaps_server_or_tool() -> Result<(), Box<dyn std::error::Error>> {
    let blueprint = OverrequestBlueprint {
        population: "p".to_string(),
        variants: vec![OverrequestVariant {
            label: "v".to_string(),
            target_server: "filesystem".to_string(),
            target_tool: "read_file".to_string(),
        }],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (mutated, kind) =
        mutate_overrequest_population(&blueprint, &mut rng, MutationConfig::default())?;
    assert!(matches!(
        kind,
        MutationKind::OverrequestSwapServer | MutationKind::OverrequestSwapTool
    ));
    let original = &blueprint.variants[0];
    let new = &mutated.variants[0];
    assert!(
        original.target_server != new.target_server || original.target_tool != new.target_tool,
        "mutation must change at least one of server or tool"
    );
    Ok(())
}

#[test]
fn replay_attempt_mutation_swaps_nonce_or_pattern() -> Result<(), Box<dyn std::error::Error>> {
    let blueprint = ReplayAttemptBlueprint {
        population: "p".to_string(),
        entries: vec![ReplayAttemptEntry {
            pattern: "immediate-reuse",
            captured_nonce: "nonce-original".to_string(),
        }],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let (mutated, kind) =
        mutate_replay_attempt_population(&blueprint, &mut rng, MutationConfig::default())?;
    assert!(matches!(
        kind,
        MutationKind::ReplayAttemptSwapNonce | MutationKind::ReplayAttemptPatternSwap
    ));
    let original = &blueprint.entries[0];
    let new = &mutated.entries[0];
    assert!(original.pattern != new.pattern || original.captured_nonce != new.captured_nonce);
    Ok(())
}

#[test]
fn scope_escape_mutation_swaps_server_or_tool() -> Result<(), Box<dyn std::error::Error>> {
    let blueprint = ScopeEscapeBlueprint {
        population: "p".to_string(),
        escalations: vec![ScopeEscalation {
            label: "broaden".to_string(),
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        }],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(17);
    let (mutated, kind) =
        mutate_scope_escape_population(&blueprint, &mut rng, MutationConfig::default())?;
    assert!(matches!(
        kind,
        MutationKind::ScopeEscapeSwapServer | MutationKind::ScopeEscapeSwapTool
    ));
    let original = &blueprint.escalations[0];
    let new = &mutated.escalations[0];
    assert!(original.server != new.server || original.tool != new.tool);
    Ok(())
}

#[test]
fn mutation_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let blueprint = PromptInjectionBlueprint {
        population: "p".to_string(),
        patterns: vec![
            "ignore-previous-instructions",
            "system-prompt-leak",
            "tool-name-spoof",
        ],
    };
    let mut rng_a = ChaCha20Rng::seed_from_u64(31);
    let mut rng_b = ChaCha20Rng::seed_from_u64(31);
    let (mutated_a, kind_a) =
        mutate_prompt_injection_population(&blueprint, &mut rng_a, MutationConfig::default())?;
    let (mutated_b, kind_b) =
        mutate_prompt_injection_population(&blueprint, &mut rng_b, MutationConfig::default())?;
    assert_eq!(mutated_a, mutated_b);
    assert_eq!(kind_a as u8, kind_b as u8);
    Ok(())
}

#[test]
fn mutate_population_dispatches_per_class() -> Result<(), Box<dyn std::error::Error>> {
    let blueprint = PopulationBlueprint::ScopeEscape(ScopeEscapeBlueprint {
        population: "p".to_string(),
        escalations: vec![ScopeEscalation {
            label: "broaden".to_string(),
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        }],
    });
    let mut rng = ChaCha20Rng::seed_from_u64(19);
    let (mutated, kind) =
        mutate_population(blueprint.clone(), &mut rng, MutationConfig::default())?;
    assert!(matches!(
        kind,
        MutationKind::ScopeEscapeSwapServer | MutationKind::ScopeEscapeSwapTool
    ));
    assert!(matches!(mutated, PopulationBlueprint::ScopeEscape(_)));
    Ok(())
}

#[test]
fn zero_max_mutations_rejected() {
    let blueprint = PromptInjectionBlueprint {
        population: "p".to_string(),
        patterns: vec!["ignore-previous-instructions"],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let err = mutate_population(
        PopulationBlueprint::PromptInjection(blueprint),
        &mut rng,
        MutationConfig { max_mutations: 0 },
    )
    .err();
    assert_eq!(err, Some(MutationError::ZeroMutationCount));
}

#[test]
fn empty_blueprint_rejected() {
    let blueprint = OverrequestBlueprint {
        population: "p".to_string(),
        variants: Vec::new(),
    };
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let err = mutate_overrequest_population(&blueprint, &mut rng, MutationConfig::default()).err();
    assert_eq!(err, Some(MutationError::EmptyPopulation));
}
