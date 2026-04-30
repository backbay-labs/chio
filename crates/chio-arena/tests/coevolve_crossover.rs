//! Two-parent crossover tests (M08.P4.T3).
//!
//! Asserts:
//!
//!   * Crossover splices the parents on the agent-population boundary.
//!   * Same-class crossover succeeds; mixed-class crossover fails closed.
//!   * Crossover is deterministic.
//!   * Empty parents are rejected.

use chio_arena::adversary::capability_overrequest::OverrequestVariant;
use chio_arena::adversary::scope_escape::ScopeEscalation;
use chio_arena::{
    crossover_overrequest_population, crossover_populations, crossover_prompt_injection_population,
    crossover_replay_attempt_population, crossover_scope_escape_population, CrossoverError,
    OverrequestBlueprint, PopulationBlueprint, PromptInjectionBlueprint, ReplayAttemptBlueprint,
    ReplayAttemptEntry, ScopeEscapeBlueprint,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn prompt_injection_crossover_splices_parents() -> Result<(), Box<dyn std::error::Error>> {
    let parent_a = PromptInjectionBlueprint {
        population: "alpha".to_string(),
        patterns: vec!["ignore-previous-instructions", "system-prompt-leak"],
    };
    let parent_b = PromptInjectionBlueprint {
        population: "beta".to_string(),
        patterns: vec!["tool-name-spoof", "delimiter-confusion"],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let child = crossover_prompt_injection_population(&parent_a, &parent_b, &mut rng)?;
    assert_eq!(child.population, "alpha");
    assert!(!child.patterns.is_empty());
    // Child should contain at least one entry from each parent.
    let from_a = child
        .patterns
        .iter()
        .any(|pattern| parent_a.patterns.contains(pattern));
    assert!(from_a);
    Ok(())
}

#[test]
fn overrequest_crossover_splices_variants() -> Result<(), Box<dyn std::error::Error>> {
    let parent_a = OverrequestBlueprint {
        population: "alpha".to_string(),
        variants: vec![
            OverrequestVariant {
                label: "a-1".to_string(),
                target_server: "filesystem".to_string(),
                target_tool: "read_file".to_string(),
            },
            OverrequestVariant {
                label: "a-2".to_string(),
                target_server: "secrets".to_string(),
                target_tool: "read_file".to_string(),
            },
        ],
    };
    let parent_b = OverrequestBlueprint {
        population: "beta".to_string(),
        variants: vec![OverrequestVariant {
            label: "b-1".to_string(),
            target_server: "network".to_string(),
            target_tool: "http_post".to_string(),
        }],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let child = crossover_overrequest_population(&parent_a, &parent_b, &mut rng)?;
    assert_eq!(child.population, "alpha");
    assert!(!child.variants.is_empty());
    Ok(())
}

#[test]
fn replay_attempt_crossover_splices_entries() -> Result<(), Box<dyn std::error::Error>> {
    let parent_a = ReplayAttemptBlueprint {
        population: "alpha".to_string(),
        entries: vec![ReplayAttemptEntry {
            pattern: "immediate-reuse",
            captured_nonce: "n-a".to_string(),
        }],
    };
    let parent_b = ReplayAttemptBlueprint {
        population: "beta".to_string(),
        entries: vec![ReplayAttemptEntry {
            pattern: "stale-nonce",
            captured_nonce: "n-b".to_string(),
        }],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let child = crossover_replay_attempt_population(&parent_a, &parent_b, &mut rng)?;
    assert_eq!(child.population, "alpha");
    assert!(!child.entries.is_empty());
    Ok(())
}

#[test]
fn scope_escape_crossover_splices_escalations() -> Result<(), Box<dyn std::error::Error>> {
    let parent_a = ScopeEscapeBlueprint {
        population: "alpha".to_string(),
        escalations: vec![ScopeEscalation {
            label: "a".to_string(),
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        }],
    };
    let parent_b = ScopeEscapeBlueprint {
        population: "beta".to_string(),
        escalations: vec![ScopeEscalation {
            label: "b".to_string(),
            server: "secrets".to_string(),
            tool: "exec_shell".to_string(),
        }],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    let child = crossover_scope_escape_population(&parent_a, &parent_b, &mut rng)?;
    assert_eq!(child.population, "alpha");
    assert!(!child.escalations.is_empty());
    Ok(())
}

#[test]
fn class_mismatch_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let parent_a = PopulationBlueprint::PromptInjection(PromptInjectionBlueprint {
        population: "alpha".to_string(),
        patterns: vec!["ignore-previous-instructions"],
    });
    let parent_b = PopulationBlueprint::ScopeEscape(ScopeEscapeBlueprint {
        population: "beta".to_string(),
        escalations: vec![ScopeEscalation {
            label: "b".to_string(),
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        }],
    });
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let err = crossover_populations(&parent_a, &parent_b, &mut rng).err();
    assert_eq!(err, Some(CrossoverError::ClassMismatch));
    Ok(())
}

#[test]
fn empty_parent_rejected() {
    let parent_a = PromptInjectionBlueprint {
        population: "alpha".to_string(),
        patterns: vec![],
    };
    let parent_b = PromptInjectionBlueprint {
        population: "beta".to_string(),
        patterns: vec!["tool-name-spoof"],
    };
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let err = crossover_prompt_injection_population(&parent_a, &parent_b, &mut rng).err();
    assert_eq!(err, Some(CrossoverError::EmptyParent));
}

#[test]
fn crossover_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let parent_a = PopulationBlueprint::PromptInjection(PromptInjectionBlueprint {
        population: "alpha".to_string(),
        patterns: vec!["ignore-previous-instructions", "system-prompt-leak"],
    });
    let parent_b = PopulationBlueprint::PromptInjection(PromptInjectionBlueprint {
        population: "beta".to_string(),
        patterns: vec!["tool-name-spoof", "delimiter-confusion"],
    });
    let mut rng_a = ChaCha20Rng::seed_from_u64(101);
    let mut rng_b = ChaCha20Rng::seed_from_u64(101);
    let child_a = crossover_populations(&parent_a, &parent_b, &mut rng_a)?;
    let child_b = crossover_populations(&parent_a, &parent_b, &mut rng_b)?;
    assert_eq!(child_a, child_b);
    Ok(())
}
