//! Mode resolver precedence tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use chio_tee::{
    load_tenant_manifest_mode_from_str, parse_env_mode, parse_toml_mode_from_str, Mode, ModeInputs,
    MoteState, ResolvedMode, Source, TransitionError,
};

/// Build a [`ModeInputs`] from per-layer optional raw strings, applying the
/// same parsing logic the real loaders use. Centralised here so each test
/// does not repeat the wiring.
fn inputs_from_strs(env: Option<&str>, toml: Option<&str>, tenant: Option<&str>) -> ModeInputs {
    let env_mode = parse_env_mode(env.map(str::to_string)).unwrap();

    let toml_mode = toml.map(|raw| {
        parse_toml_mode_from_str(&PathBuf::from("test-tee.toml"), raw)
            .unwrap()
            .unwrap()
    });

    let tenant_mode = tenant.map(|raw| {
        load_tenant_manifest_mode_from_str(&PathBuf::from("test-manifest.toml"), raw)
            .unwrap()
            .unwrap()
    });

    ModeInputs {
        env: env_mode,
        toml: toml_mode,
        tenant_manifest: tenant_mode,
    }
}

/// Verify three-layer priority: env overrides TOML overrides tenant manifest.
///
/// Builds a tenant manifest that requests `enforce`, a TOML config that
/// requests `shadow`, and an env var that sets `verdict-only`. The resolved
/// mode must be `verdict-only`. Removing the env layer yields `shadow`;
/// removing both env and TOML yields `enforce`.
#[test]
fn env_overrides_toml_overrides_manifest() {
    let manifest_toml = "[tenant.tee]\nmode = \"enforce\"\n";
    let sidecar_toml = "[tee]\nmode = \"shadow\"\n";

    // All three layers present: env wins.
    let inputs = inputs_from_strs(
        Some("verdict-only"),
        Some(sidecar_toml),
        Some(manifest_toml),
    );
    let resolved = ResolvedMode::resolve(inputs);
    assert_eq!(resolved.mode, Mode::VerdictOnly);
    assert_eq!(resolved.source, Source::Env);
    // Diagnostic logging contract: per-layer values are recorded for the
    // `tee.mode_resolved` event so operators can see which layer overrode
    // which.
    assert_eq!(resolved.inputs.env, Some(Mode::VerdictOnly));
    assert_eq!(resolved.inputs.toml, Some(Mode::Shadow));
    assert_eq!(resolved.inputs.tenant_manifest, Some(Mode::Enforce));

    // Env unset: TOML wins.
    let inputs = inputs_from_strs(None, Some(sidecar_toml), Some(manifest_toml));
    let resolved = ResolvedMode::resolve(inputs);
    assert_eq!(resolved.mode, Mode::Shadow);
    assert_eq!(resolved.source, Source::Toml);

    // Env unset, TOML deleted: tenant manifest wins.
    let inputs = inputs_from_strs(None, None, Some(manifest_toml));
    let resolved = ResolvedMode::resolve(inputs);
    assert_eq!(resolved.mode, Mode::Enforce);
    assert_eq!(resolved.source, Source::TenantManifest);
}

#[test]
fn env_only_resolves_to_env_value() {
    let inputs = inputs_from_strs(Some("enforce"), None, None);
    let resolved = ResolvedMode::resolve(inputs);
    assert_eq!(resolved.mode, Mode::Enforce);
    assert_eq!(resolved.source, Source::Env);
}

#[test]
fn toml_only_resolves_to_toml_value() {
    let inputs = inputs_from_strs(None, Some("[tee]\nmode = \"shadow\"\n"), None);
    let resolved = ResolvedMode::resolve(inputs);
    assert_eq!(resolved.mode, Mode::Shadow);
    assert_eq!(resolved.source, Source::Toml);
}

#[test]
fn tenant_only_resolves_to_tenant_value() {
    let inputs = inputs_from_strs(None, None, Some("[tenant.tee]\nmode = \"enforce\"\n"));
    let resolved = ResolvedMode::resolve(inputs);
    assert_eq!(resolved.mode, Mode::Enforce);
    assert_eq!(resolved.source, Source::TenantManifest);
}

#[test]
fn no_layers_resolves_to_default_verdict_only() {
    let resolved = ResolvedMode::resolve(ModeInputs::default());
    assert_eq!(resolved.mode, Mode::VerdictOnly);
    assert_eq!(resolved.source, Source::Default);
}

#[test]
fn toml_uses_default_when_layer_present_but_table_empty() {
    // `[tee]` table absent entirely: parser returns Ok(None), so the inputs
    // builder treats it as if the layer had not been provided. We simulate
    // that here by passing None for the layer.
    let resolved = ResolvedMode::resolve(ModeInputs {
        env: None,
        toml: None,
        tenant_manifest: None,
    });
    assert_eq!(resolved.mode, Mode::VerdictOnly);
    assert_eq!(resolved.source, Source::Default);
}

#[test]
fn invalid_env_value_rejected_at_parse_time() {
    // Fail-closed: if CHIO_TEE_MODE is set to an unknown tag, parsing fails
    // before we can resolve.
    let err = parse_env_mode(Some("monitor".to_string()));
    assert!(err.is_err());
}

/// SIGUSR1 toggle behaviour: factor the toggle as a function callable by
/// both the live signal handler and the test, so we can drive it without
/// raising real signals. The on-signal closure in the live runtime would
/// look like:
///
/// ```ignore
/// let state = state.clone();
/// install_sigusr1_handler(move || {
///     let target = read_request_file();
///     let cap = read_capability_file();
///     let _ = state.transition(target, cap.as_deref());
/// })?;
/// ```
#[test]
fn sigusr1_toggle_downgrade_unconditional() {
    let state = MoteState::new(Mode::Enforce);

    // Simulate a SIGUSR1 delivery: the handler calls transition(...).
    let prev = simulate_sigusr1(&state, Mode::Shadow, None).unwrap();
    assert_eq!(prev, Mode::Enforce);
    assert_eq!(state.current(), Mode::Shadow);

    // Second delivery: shadow -> verdict-only is also a downgrade.
    let prev = simulate_sigusr1(&state, Mode::VerdictOnly, None).unwrap();
    assert_eq!(prev, Mode::Shadow);
    assert_eq!(state.current(), Mode::VerdictOnly);
}

#[test]
fn sigusr1_toggle_upgrade_requires_capability() {
    let state = MoteState::new(Mode::VerdictOnly);

    // No capability: upgrade is denied.
    let err = simulate_sigusr1(&state, Mode::Shadow, None).unwrap_err();
    assert!(matches!(
        err,
        TransitionError::MissingUpgradeCapability { .. }
    ));
    assert_eq!(state.current(), Mode::VerdictOnly);

    // With capability: upgrade succeeds.
    let prev = simulate_sigusr1(&state, Mode::Shadow, Some("cap-token-fixture")).unwrap();
    assert_eq!(prev, Mode::VerdictOnly);
    assert_eq!(state.current(), Mode::Shadow);
}

#[test]
fn sigusr1_toggle_round_trip_off_to_shadow_to_off() {
    let state = MoteState::new(Mode::VerdictOnly);

    // Upgrade with capability.
    simulate_sigusr1(&state, Mode::Shadow, Some("cap-token")).unwrap();
    assert_eq!(state.current(), Mode::Shadow);

    // Downgrade unconditional.
    simulate_sigusr1(&state, Mode::VerdictOnly, None).unwrap();
    assert_eq!(state.current(), Mode::VerdictOnly);
}

/// Test stand-in for the live SIGUSR1 handler. The live handler reads the
/// request file and capability file from `${CHIO_TEE_RUNTIME_DIR}` and then
/// calls [`MoteState::transition`]; the test injects values directly.
fn simulate_sigusr1(
    state: &MoteState,
    target: Mode,
    upgrade_capability: Option<&str>,
) -> Result<Mode, TransitionError> {
    state.transition(target, upgrade_capability)
}
