use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_runtime_core::*;
use chio_weights::card::{ModelCard, StringSet};
use chrono::{TimeZone, Utc};
use std::io;

#[path = "runtime_ops/support.rs"]
mod runtime_ops_support;

use runtime_ops_support::supervisor_profile;

fn provider_binding(weights_binding_mode: Option<WeightsBindingMode>) -> RuntimeProviderBinding {
    RuntimeProviderBinding {
        provider_id: "provider-vendor-b".to_string(),
        binding_id: Some("provider-binding-vendor-b".to_string()),
        local_kernel_id: "kernel.vendor-b".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        discovery_allowed: false,
        model_card_id: Some("model-card-vendor-b".to_string()),
        model_card_digest: Some("a".repeat(64)),
        loaded_weights_hash: Some("b".repeat(64)),
        weights_binding_mode,
    }
}

fn provider_bindings_document(binding: RuntimeProviderBinding) -> RuntimeProviderBindingsDocument {
    RuntimeProviderBindingsDocument {
        schema: CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA.to_string(),
        bindings: vec![binding],
    }
}

fn loaded_weights_evidence(hash: &str) -> RuntimeProviderLoadedWeightsEvidence {
    RuntimeProviderLoadedWeightsEvidence {
        binding_id: "provider-binding-vendor-b".to_string(),
        loaded_weights_hash: hash.to_string(),
    }
}

fn model_card(
    weights_hash: &str,
    expires_at_unix_ms: i64,
) -> Result<ModelCard, Box<dyn std::error::Error>> {
    let issued = Utc
        .with_ymd_and_hms(2026, 4, 30, 12, 0, 0)
        .single()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid issued timestamp"))?;
    let expires = Utc
        .timestamp_millis_opt(expires_at_unix_ms)
        .single()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid expiry timestamp"))?;
    Ok(ModelCard::new(
        weights_hash,
        StringSet::new(["tool:close_account", "tool:delete_account"]),
        StringSet::new(["tool:delete_account"]),
        "public-internet",
        "https://example.com/issuer",
        issued,
        expires,
    )?)
}

fn model_card_digest(card: &ModelCard) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sha256_hex(&canonical_json_bytes(card)?))
}

#[test]
fn runtime_ops_provider_health_rejects_discovery_attempts() -> Result<(), Box<dyn std::error::Error>>
{
    let bindings = RuntimeProviderBindingsDocument {
        schema: CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA.to_string(),
        bindings: vec![RuntimeProviderBinding {
            provider_id: "provider-vendor-b".to_string(),
            binding_id: None,
            local_kernel_id: "kernel.vendor-b".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            discovery_allowed: true,
            model_card_id: None,
            model_card_digest: None,
            loaded_weights_hash: None,
            weights_binding_mode: None,
        }],
    };
    let report = chio_runtime_core::generate_runtime_provider_health_report(
        &supervisor_profile(),
        &bindings,
        1_800_000_000_000,
    )?;
    assert_eq!(report.schema, "chio.runtime.provider-health-report.v1");
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_discovery_not_allowed")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_stale_supervisor_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let bindings = RuntimeProviderBindingsDocument {
        schema: CHIO_RUNTIME_PROVIDER_BINDINGS_SCHEMA.to_string(),
        bindings: vec![RuntimeProviderBinding {
            provider_id: "provider-vendor-b".to_string(),
            binding_id: None,
            local_kernel_id: "kernel.vendor-b".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            discovery_allowed: false,
            model_card_id: None,
            model_card_digest: None,
            loaded_weights_hash: None,
            weights_binding_mode: None,
        }],
    };
    let mut profile = supervisor_profile();
    profile.expires_at_unix_ms = 1_800_000_001_000;

    let report = chio_runtime_core::generate_runtime_provider_health_report(
        &profile,
        &bindings,
        1_800_000_001_000,
    )?;

    assert_eq!(report.schema, "chio.runtime.provider-health-report.v1");
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_supervisor_profile_stale")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_binding_rejects_missing_model_card_when_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut binding = provider_binding(Some(WeightsBindingMode::Required));
    binding.model_card_id = None;
    let document = provider_bindings_document(binding);

    let error = match validate_runtime_provider_bindings(&document) {
        Ok(()) => {
            return Err(
                io::Error::other("provider bindings validation unexpectedly passed").into(),
            );
        }
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("runtime_provider_model_card_missing"));
    Ok(())
}

#[test]
fn runtime_ops_provider_health_accepts_required_model_card_with_loaded_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let card = model_card(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1_800_003_600_000,
    )?;
    let mut binding = provider_binding(Some(WeightsBindingMode::Required));
    binding.model_card_digest = Some(model_card_digest(&card)?);
    let bindings = provider_bindings_document(binding);
    let cards = [("model-card-vendor-b".to_string(), card)]
        .into_iter()
        .collect();

    let report =
        chio_runtime_core::generate_runtime_provider_health_report_with_model_card_evidence(
            &supervisor_profile(),
            &bindings,
            &cards,
            &[loaded_weights_evidence(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )],
            1_800_000_000_000,
        )?;

    assert!(report.accepted);
    assert_eq!(report.failure_code, None);
    assert_eq!(report.provider_checks[0].failure_code, None);
    assert_eq!(report.healthy_provider_count, 1);
    Ok(())
}

#[test]
fn runtime_ops_provider_health_accepts_prefixed_model_card_tool_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let card = model_card(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1_800_003_600_000,
    )?;
    let mut binding = provider_binding(Some(WeightsBindingMode::Required));
    binding.tool_name = "tool:close_account".to_string();
    binding.model_card_digest = Some(model_card_digest(&card)?);
    let bindings = provider_bindings_document(binding);
    let cards = [("model-card-vendor-b".to_string(), card)]
        .into_iter()
        .collect();

    let report =
        chio_runtime_core::generate_runtime_provider_health_report_with_model_card_evidence(
            &supervisor_profile(),
            &bindings,
            &cards,
            &[loaded_weights_evidence(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )],
            1_800_000_000_000,
        )?;

    assert!(report.accepted);
    assert_eq!(report.failure_code, None);
    assert_eq!(report.provider_checks[0].failure_code, None);
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_banned_model_card_tool_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let card = model_card(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1_800_003_600_000,
    )?;
    let mut binding = provider_binding(Some(WeightsBindingMode::Required));
    binding.tool_name = "delete_account".to_string();
    binding.model_card_digest = Some(model_card_digest(&card)?);
    let bindings = provider_bindings_document(binding);
    let cards = [("model-card-vendor-b".to_string(), card)]
        .into_iter()
        .collect();

    let report =
        chio_runtime_core::generate_runtime_provider_health_report_with_model_card_evidence(
            &supervisor_profile(),
            &bindings,
            &cards,
            &[loaded_weights_evidence(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )],
            1_800_000_000_000,
        )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_model_card_tool_banned")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_model_card_without_observed_loaded_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let card = model_card(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1_800_003_600_000,
    )?;
    let mut binding = provider_binding(Some(WeightsBindingMode::Required));
    binding.model_card_digest = Some(model_card_digest(&card)?);
    let bindings = provider_bindings_document(binding);
    let cards = [("model-card-vendor-b".to_string(), card)]
        .into_iter()
        .collect();

    let report = chio_runtime_core::generate_runtime_provider_health_report_with_model_cards(
        &supervisor_profile(),
        &bindings,
        &cards,
        1_800_000_000_000,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_loaded_weights_unavailable")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_loaded_hash_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let card = model_card(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1_800_003_600_000,
    )?;
    let mut binding = provider_binding(Some(WeightsBindingMode::Required));
    binding.model_card_digest = Some(model_card_digest(&card)?);
    let bindings = provider_bindings_document(binding);
    let cards = [("model-card-vendor-b".to_string(), card)]
        .into_iter()
        .collect();

    let report =
        chio_runtime_core::generate_runtime_provider_health_report_with_model_card_evidence(
            &supervisor_profile(),
            &bindings,
            &cards,
            &[loaded_weights_evidence(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )],
            1_800_000_000_000,
        )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_loaded_weights_hash_mismatch")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_report_rejects_accepted_failed_provider_check(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = RuntimeProviderHealthReport {
        schema: CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA.to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_000_000,
        provider_bindings_sha256: "a".repeat(64),
        checked_provider_count: 1,
        healthy_provider_count: 0,
        degraded_provider_ids: vec!["provider-vendor-b".to_string()],
        provider_checks: vec![RuntimeProviderHealthCheck {
            provider_id: "provider-vendor-b".to_string(),
            binding_id: "provider-binding-vendor-b".to_string(),
            accepted: false,
            failure_code: Some("runtime_provider_loaded_weights_unavailable".to_string()),
            weights_binding_mode: WeightsBindingMode::Required,
            model_card_id: Some("model-card-vendor-b".to_string()),
            checks: vec!["runtime_provider_loaded_weights".to_string()],
        }],
        checks: vec!["runtime_ops.provider_bindings_health".to_string()],
    };

    let error = match validate_runtime_provider_health_report(&report) {
        Ok(()) => {
            return Err(io::Error::other("provider health validation unexpectedly passed").into());
        }
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("runtime_provider_health_accepted_with_failed_check"));
    report.accepted = false;
    report.failure_code = Some("runtime_provider_loaded_weights_unavailable".to_string());
    validate_runtime_provider_health_report(&report)?;
    Ok(())
}

#[test]
fn runtime_ops_provider_health_report_rejects_inconsistent_provider_counts(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = RuntimeProviderHealthReport {
        schema: CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA.to_string(),
        accepted: false,
        failure_code: Some("runtime_provider_loaded_weights_unavailable".to_string()),
        generated_at_unix_ms: 1_800_000_000_000,
        provider_bindings_sha256: "a".repeat(64),
        checked_provider_count: 2,
        healthy_provider_count: 0,
        degraded_provider_ids: vec!["provider-vendor-b".to_string()],
        provider_checks: vec![RuntimeProviderHealthCheck {
            provider_id: "provider-vendor-b".to_string(),
            binding_id: "provider-binding-vendor-b".to_string(),
            accepted: false,
            failure_code: Some("runtime_provider_loaded_weights_unavailable".to_string()),
            weights_binding_mode: WeightsBindingMode::Required,
            model_card_id: Some("model-card-vendor-b".to_string()),
            checks: vec!["runtime_provider_loaded_weights".to_string()],
        }],
        checks: vec!["runtime_ops.provider_bindings_health".to_string()],
    };

    let error = match validate_runtime_provider_health_report(&report) {
        Ok(()) => {
            return Err(io::Error::other("provider health validation unexpectedly passed").into());
        }
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("runtime_provider_health_check_count_mismatch"));
    Ok(())
}

#[test]
fn runtime_ops_provider_health_report_rejects_inconsistent_degraded_ids(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = RuntimeProviderHealthReport {
        schema: CHIO_RUNTIME_PROVIDER_HEALTH_REPORT_SCHEMA.to_string(),
        accepted: false,
        failure_code: Some("runtime_provider_loaded_weights_unavailable".to_string()),
        generated_at_unix_ms: 1_800_000_000_000,
        provider_bindings_sha256: "a".repeat(64),
        checked_provider_count: 1,
        healthy_provider_count: 0,
        degraded_provider_ids: vec!["provider-other".to_string()],
        provider_checks: vec![RuntimeProviderHealthCheck {
            provider_id: "provider-vendor-b".to_string(),
            binding_id: "provider-binding-vendor-b".to_string(),
            accepted: false,
            failure_code: Some("runtime_provider_loaded_weights_unavailable".to_string()),
            weights_binding_mode: WeightsBindingMode::Required,
            model_card_id: Some("model-card-vendor-b".to_string()),
            checks: vec!["runtime_provider_loaded_weights".to_string()],
        }],
        checks: vec!["runtime_ops.provider_bindings_health".to_string()],
    };

    let error = match validate_runtime_provider_health_report(&report) {
        Ok(()) => {
            return Err(io::Error::other("provider health validation unexpectedly passed").into());
        }
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("runtime_provider_health_degraded_ids_mismatch"));
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_unavailable_required_model_card(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut binding = provider_binding(Some(WeightsBindingMode::Unavailable));
    binding.model_card_id = None;
    binding.model_card_digest = None;
    binding.loaded_weights_hash = None;
    let bindings = provider_bindings_document(binding);

    let report = chio_runtime_core::generate_runtime_provider_health_report(
        &supervisor_profile(),
        &bindings,
        1_800_000_000_000,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_loaded_weights_unavailable")
    );
    assert_eq!(report.provider_checks[0].provider_id, "provider-vendor-b");
    assert_eq!(
        report.provider_checks[0].binding_id,
        "provider-binding-vendor-b"
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_model_card_digest_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let card = model_card(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1_800_003_600_000,
    )?;
    let bindings = provider_bindings_document(provider_binding(Some(WeightsBindingMode::Required)));
    let cards = [("model-card-vendor-b".to_string(), card)]
        .into_iter()
        .collect();

    let report = chio_runtime_core::generate_runtime_provider_health_report_with_model_cards(
        &supervisor_profile(),
        &bindings,
        &cards,
        1_800_000_000_000,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_model_card_digest_mismatch")
    );
    Ok(())
}

#[test]
fn runtime_ops_provider_health_rejects_stale_model_card() -> Result<(), Box<dyn std::error::Error>>
{
    let card = model_card(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1_799_999_999_000,
    )?;
    let mut binding = provider_binding(Some(WeightsBindingMode::Required));
    binding.model_card_digest = Some(model_card_digest(&card)?);
    let bindings = provider_bindings_document(binding);
    let cards = [("model-card-vendor-b".to_string(), card)]
        .into_iter()
        .collect();

    let report = chio_runtime_core::generate_runtime_provider_health_report_with_model_cards(
        &supervisor_profile(),
        &bindings,
        &cards,
        1_800_000_000_000,
    )?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_provider_model_card_stale")
    );
    Ok(())
}
