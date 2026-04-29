//! Ignored phase-boundary gate for the M06 guard platform.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use chio_core::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
use chio_core::crypto::Keypair;
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};
use chio_wasm_guards::manifest::{verify_wit_world, REQUIRED_WIT_WORLD};
use chio_wasm_guards::runtime::MockWasmBackend;
use chio_wasm_guards::{
    Engine, EvalTrace, IncidentWriter, WasmGuard, WasmGuardAbi, WasmGuardError, WatchdogConfig,
};

#[derive(Clone, Debug)]
struct GuardArtifact {
    digest: String,
    bytes: Vec<u8>,
    ed25519_verified: bool,
    sigstore_verified: bool,
}

#[derive(Debug, Default)]
struct FakeGuardRegistry {
    artifacts: HashMap<String, GuardArtifact>,
    cache_hits: HashSet<String>,
}

impl FakeGuardRegistry {
    fn publish(&mut self, name: &str, bytes: &[u8]) -> GuardArtifact {
        let digest = format!("{name}-{:012x}", bytes.len());
        let artifact = GuardArtifact {
            digest: digest.clone(),
            bytes: bytes.to_vec(),
            ed25519_verified: true,
            sigstore_verified: true,
        };
        self.artifacts.insert(name.to_string(), artifact.clone());
        artifact
    }

    fn pull(&mut self, name: &str) -> Result<(GuardArtifact, bool), String> {
        let artifact = self
            .artifacts
            .get(name)
            .cloned()
            .ok_or_else(|| format!("guard artifact {name} not found"))?;
        let cache_hit = !self.cache_hits.insert(name.to_string());
        Ok((artifact, cache_hit))
    }
}

#[derive(Debug, Default)]
struct ObservedMetricValues {
    eval_count: u64,
    fuel_total: u64,
    verdict_total: u64,
    deny_total: u64,
    reload_total: u64,
    host_call_count: u64,
    module_bytes: u64,
}

impl ObservedMetricValues {
    fn from_prometheus(scrape: &str) -> Self {
        let mut values = Self::default();
        for line in scrape.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let Some((sample, value)) = line.rsplit_once(' ') else {
                continue;
            };
            let parsed = value.parse::<f64>().unwrap_or(0.0).max(0.0) as u64;
            let metric = sample.split_once('{').map_or(sample, |(name, _)| name);
            match metric {
                "chio_guard_eval_duration_seconds_count" => values.eval_count += parsed,
                "chio_guard_fuel_consumed_total" => values.fuel_total += parsed,
                "chio_guard_verdict_total" => values.verdict_total += parsed,
                "chio_guard_deny_total" => values.deny_total += parsed,
                "chio_guard_reload_total" => values.reload_total += parsed,
                "chio_guard_host_call_duration_seconds_count" => {
                    values.host_call_count += parsed;
                }
                "chio_guard_module_bytes" => values.module_bytes += parsed,
                _ => {}
            }
        }
        values
    }

    fn assert_activity(&self) {
        assert!(self.eval_count > 0);
        assert!(self.fuel_total > 0);
        assert!(self.verdict_total > 0);
        assert!(self.reload_total > 0);
        assert!(self.module_bytes > 0);
    }
}

fn loaded_allowing_backend(bytes: &[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
    let mut backend = MockWasmBackend::allowing();
    backend.load_module(bytes, 1_000_000)?;
    Ok(Box::new(backend))
}

fn capability_request() -> (ToolCallRequest, ChioScope, String, String) {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let signer = Keypair::generate();
    let scope = ChioScope::default();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-guard-platform".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        },
        &signer,
    )
    .unwrap_or_else(|err| panic!("capability signing failed: {err}"));

    let request = ToolCallRequest {
        request_id: "req-guard-platform".to_string(),
        capability,
        tool_name: "guarded_tool".to_string(),
        server_id: "srv".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({"path": "/tmp/example"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    (request, scope, "agent-1".to_string(), "srv".to_string())
}

fn temp_incident_root() -> PathBuf {
    std::env::temp_dir().join(format!("chio-guard-platform-e2e-{}", std::process::id()))
}

#[test]
#[ignore]
fn publish_pull_verify_swap_rollback_and_metrics_gate() {
    let manifest_wit_world = Some(REQUIRED_WIT_WORLD.to_string());
    verify_wit_world(manifest_wit_world.as_deref())
        .unwrap_or_else(|err| panic!("WIT world verification failed: {err}"));
    assert!(verify_wit_world(Some("chio:guard/wrong@9.9.9")).is_err());

    let mut registry = FakeGuardRegistry::default();
    let published = registry.publish("tool-gate", b"module-v1");
    assert!(published.ed25519_verified);
    assert!(published.sigstore_verified);

    let (pulled_first, first_cache_hit) = registry
        .pull("tool-gate")
        .unwrap_or_else(|err| panic!("first pull failed: {err}"));
    let (pulled_second, second_cache_hit) = registry
        .pull("tool-gate")
        .unwrap_or_else(|err| panic!("second pull failed: {err}"));
    assert!(!first_cache_hit);
    assert!(second_cache_hit);
    assert_eq!(pulled_first.digest, pulled_second.digest);
    assert_eq!(pulled_first.bytes, pulled_second.bytes);

    let engine = Engine::new(|bytes: &[u8]| loaded_allowing_backend(bytes)).without_blocklist();
    let guard = WasmGuard::new_with_metadata(
        "tool-gate".to_string(),
        "1.4.0".to_string(),
        loaded_allowing_backend(&pulled_first.bytes)
            .unwrap_or_else(|err| panic!("initial backend failed: {err}")),
        false,
        Some(published.digest.clone()),
    );
    let guard = engine
        .register_guard("tool-gate", guard)
        .unwrap_or_else(|err| panic!("guard registration failed: {err}"));
    let prior_epoch = guard.current_epoch_id();

    let (request, scope, agent_id, server_id) = capability_request();
    let ctx = GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };

    let mut canary_verdicts = Vec::new();
    for index in 0..32 {
        let verdict = guard
            .evaluate(&ctx)
            .unwrap_or_else(|err| panic!("canary {index} evaluation failed: {err}"));
        assert!(matches!(verdict, Verdict::Allow));
        canary_verdicts.push(format!("{verdict:?}"));
    }

    let incident_root = temp_incident_root();
    let _ = std::fs::remove_dir_all(&incident_root);
    let mut watchdog = engine
        .reload_with_watchdog(
            "tool-gate",
            b"module-v2",
            7,
            WatchdogConfig {
                max_errors: 5,
                window: Duration::from_secs(60),
                incident_writer: IncidentWriter::new(&incident_root),
            },
        )
        .unwrap_or_else(|err| panic!("reload with watchdog failed: {err}"));
    assert_ne!(guard.current_epoch_id(), prior_epoch);

    let mut dropped = 0u64;
    for index in 0..100 {
        match guard.evaluate(&ctx) {
            Ok(Verdict::Allow) => {}
            Ok(other) => panic!("request {index} produced unexpected verdict {other:?}"),
            Err(_) => dropped += 1,
        }
    }
    assert_eq!(dropped, 0);

    for index in 0..5 {
        let incident = watchdog
            .record_error(EvalTrace::new(
                format!("req-{index}"),
                "trap",
                "redacted e2e canary failure",
            ))
            .unwrap_or_else(|err| panic!("watchdog record failed: {err}"));
        if index < 4 {
            assert!(incident.is_none());
        } else {
            assert!(incident.is_some());
        }
    }
    assert_eq!(guard.current_epoch_id(), prior_epoch);

    for (index, expected) in canary_verdicts.iter().enumerate() {
        let verdict = guard
            .evaluate(&ctx)
            .unwrap_or_else(|err| panic!("post-rollback canary {index} failed: {err}"));
        assert_eq!(&format!("{verdict:?}"), expected);
    }

    let metrics_body = chio_kernel::render_guard_metrics_prometheus();
    for family in [
        "chio_guard_eval_duration_seconds",
        "chio_guard_fuel_consumed_total",
        "chio_guard_verdict_total",
        "chio_guard_deny_total",
        "chio_guard_reload_total",
        "chio_guard_host_call_duration_seconds",
        "chio_guard_module_bytes",
    ] {
        assert!(
            metrics_body.contains(family),
            "metrics scrape missing {family}"
        );
    }

    ObservedMetricValues::from_prometheus(&metrics_body).assert_activity();

    let evidence = guard.guard_evidence_metadata();
    assert!(evidence
        .get("epoch_id")
        .and_then(|value| value.as_u64())
        .is_some());

    let _ = std::fs::remove_dir_all(&incident_root);
}
