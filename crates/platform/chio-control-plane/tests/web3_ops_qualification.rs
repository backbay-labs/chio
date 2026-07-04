use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_anchor::{
    ensure_anchor_operation_allowed, AnchorAlertSeverity, AnchorControlState,
    AnchorEmergencyControls, AnchorEmergencyMode, AnchorIncidentAlert, AnchorIndexerCursor,
    AnchorIndexerCursorInput, AnchorLaneKind, AnchorLaneRuntimeStatus,
    AnchorLaneRuntimeStatusInput, AnchorOperationKind, AnchorRuntimeReport,
};
use chio_link::config::{
    build_default_egress_contract, OracleBackendKind, PairConfig, PairRuntimeOverride,
    PriceOracleConfig, ARBITRUM_ONE_CHAIN_ID,
};
use chio_link::control::ChioLinkControlState;
use chio_link::{ChioLinkOracle, ExchangeRate, OracleBackend, OracleFuture, PriceOracleError};
use chio_settle::{
    ensure_settlement_operation_allowed, SettlementAlertSeverity, SettlementControlState,
    SettlementEmergencyControls, SettlementEmergencyMode, SettlementFinalityStatus,
    SettlementIncidentAlert, SettlementIndexerCursor, SettlementIndexerCursorInput,
    SettlementIndexerStatus, SettlementLaneRuntimeStatus, SettlementLaneRuntimeStatusInput,
    SettlementOperationKind, SettlementRecoveryAction, SettlementRecoveryRecord,
    SettlementRuntimeReport,
};
use serde::Serialize;
use serde_json::json;

use chio_test_support::prelude::*;

struct StaticBackend {
    kind: OracleBackendKind,
    responses: BTreeMap<String, Result<ExchangeRate, PriceOracleError>>,
}

impl StaticBackend {
    fn new(
        kind: OracleBackendKind,
        responses: impl IntoIterator<Item = (String, Result<ExchangeRate, PriceOracleError>)>,
    ) -> Self {
        Self {
            kind,
            responses: responses.into_iter().collect(),
        }
    }
}

impl OracleBackend for StaticBackend {
    fn kind(&self) -> OracleBackendKind {
        self.kind
    }

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, _now: u64) -> OracleFuture<'a> {
        let response = self
            .responses
            .get(&pair.pair())
            .cloned()
            .unwrap_or_else(|| {
                Err(PriceOracleError::NoPairAvailable {
                    base: pair.base.clone(),
                    quote: pair.quote.clone(),
                })
            });
        Box::pin(async move { response })
    }
}

fn sample_rate(pair: &PairConfig, source: &str, numerator: u128, updated_at: u64) -> ExchangeRate {
    ExchangeRate {
        base: pair.base.clone(),
        quote: pair.quote.clone(),
        rate_numerator: numerator,
        rate_denominator: 100,
        updated_at,
        fetched_at: updated_at.saturating_add(15),
        source: source.to_string(),
        feed_reference: pair
            .chainlink
            .as_ref()
            .map(|feed| feed.address.clone())
            .or_else(|| pair.pyth.as_ref().map(|feed| feed.id.clone()))
            .unwrap_or_else(|| "feed-unavailable".to_string()),
        max_age_seconds: pair.policy.max_age_seconds,
        conversion_margin_bps: pair.policy.exchange_rate_margin_bps,
        confidence_numerator: None,
        confidence_denominator: None,
    }
}

fn output_root() -> PathBuf {
    if let Ok(path) = std::env::var("CHIO_WEB3_OPS_OUTPUT_DIR") {
        return PathBuf::from(path);
    }
    std::env::temp_dir().join("chio-web3-ops-qualification")
}

fn write_json(path: &Path, value: &impl Serialize) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).test_unwrap();
    }
    let payload = serde_json::to_vec_pretty(value).test_unwrap();
    fs::write(path, payload).test_unwrap();
}

#[tokio::test]
async fn web3_ops_qualification_emits_generated_runtime_reports_and_control_audits() {
    let generated_at = 1_764_620_000;
    // Use loopback addresses so config.validate() does not perform a live DNS
    // lookup. The test uses StaticBackend for all rates so no real RPC occurs.
    let mut config =
        PriceOracleConfig::base_arbitrum_default("http://127.0.0.1:8545", "http://127.0.0.1:9545");
    config.egress_contract = build_default_egress_contract(&config.pyth, &config.operator.chains);
    config.egress_contract.deny_loopback = false;
    for chain in &mut config.operator.chains {
        chain.sequencer_uptime_feed = None;
    }
    let initial_operator = config.operator.clone();

    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        config.pairs.iter().map(|pair| {
            let numerator = match pair.pair().as_str() {
                "ETH/USD" => 300_000,
                "BTC/USD" => 6_800_000,
                "USDC/USD" => 100,
                "LINK/USD" => 1_800,
                _ => 100,
            };
            (
                pair.pair(),
                Ok(sample_rate(
                    pair,
                    "chainlink:twap",
                    numerator,
                    generated_at - 45,
                )),
            )
        }),
    ));
    let fallback = Arc::new(StaticBackend::new(
        OracleBackendKind::Pyth,
        config.pairs.iter().filter_map(|pair| {
            pair.pyth.as_ref().map(|_| {
                (
                    pair.pair(),
                    Ok(sample_rate(pair, "pyth", 299_500, generated_at - 60)),
                )
            })
        }),
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, Some(fallback)).test_unwrap();

    let mut link_state = ChioLinkControlState::new(generated_at - 120, initial_operator);
    oracle
        .set_global_pause(true, Some("investigating price-source drift".to_string()))
        .await
        .test_unwrap();
    link_state.record_global_pause(
        true,
        Some("investigating price-source drift".to_string()),
        "ops-oncall",
        "qualification_drill",
        generated_at - 110,
        "pause all conversions while chain and pair controls are reviewed",
    );
    oracle.set_global_pause(false, None).await.test_unwrap();
    link_state.record_global_pause(
        false,
        None,
        "ops-oncall",
        "qualification_drill",
        generated_at - 105,
        "resume conversions after explicit pair and chain controls are set",
    );
    oracle
        .set_chain_enabled(ARBITRUM_ONE_CHAIN_ID, true)
        .await
        .test_unwrap();
    link_state
        .record_chain_enabled(
            ARBITRUM_ONE_CHAIN_ID,
            true,
            "ops-oncall",
            "qualification_drill",
            generated_at - 95,
            "verify standby chain can be toggled before final disable",
        )
        .test_unwrap();
    oracle
        .set_chain_enabled(ARBITRUM_ONE_CHAIN_ID, false)
        .await
        .test_unwrap();
    link_state
        .record_chain_enabled(
            ARBITRUM_ONE_CHAIN_ID,
            false,
            "ops-oncall",
            "qualification_drill",
            generated_at - 90,
            "leave standby chain disabled after the drill",
        )
        .test_unwrap();
    let btc_pair = oracle
        .config()
        .pairs
        .iter()
        .find(|pair| pair.base == "BTC" && pair.quote == "USD")
        .test_unwrap()
        .clone();
    let disabled_btc = PairRuntimeOverride {
        enabled: false,
        ..PairRuntimeOverride::from_pair(&btc_pair)
    };
    oracle
        .set_pair_override(disabled_btc.clone())
        .await
        .test_unwrap();
    link_state
        .record_pair_override(
            disabled_btc,
            "ops-oncall",
            "qualification_drill",
            generated_at - 80,
            "freeze BTC/USD while operator incident review remains open",
        )
        .test_unwrap();
    let link_report = oracle.runtime_report().await.test_unwrap();
    assert!(!link_report.global_pause);
    assert!(link_report
        .alerts
        .iter()
        .any(|alert| alert.code == "pair_paused" && alert.pair.as_deref() == Some("BTC/USD")));
    assert!(link_report
        .chains
        .iter()
        .any(|chain| chain.chain_id == ARBITRUM_ONE_CHAIN_ID && !chain.enabled));

    let mut anchor_state = AnchorControlState::new(
        generated_at - 120,
        AnchorEmergencyControls::normal(generated_at - 120),
    );
    anchor_state.apply_change(
        AnchorEmergencyMode::PublishPaused,
        generated_at - 70,
        "ops-oncall",
        Some("pause new root publication during replay drill".to_string()),
        "qualification_drill",
    );
    anchor_state.apply_change(
        AnchorEmergencyMode::RecoveryOnly,
        generated_at - 60,
        "ops-oncall",
        Some("keep only canonical confirmation actions available".to_string()),
        "qualification_drill",
    );
    ensure_anchor_operation_allowed(
        anchor_state.controls.clone(),
        AnchorOperationKind::PublishRoot,
    )
    .test_unwrap_err();
    ensure_anchor_operation_allowed(
        anchor_state.controls.clone(),
        AnchorOperationKind::ConfirmPublication,
    )
    .test_unwrap();

    let root_registry_indexer = AnchorIndexerCursor::from_sequences(AnchorIndexerCursorInput {
        service_id: "root-registry-indexer".to_string(),
        lane: AnchorLaneKind::EvmPrimary,
        chain_id: Some("eip155:8453".to_string()),
        indexed_checkpoint_seq: 9_182,
        canonical_checkpoint_seq: 9_184,
        indexed_block_number: Some(29_920_123),
        replaying: true,
        failed: false,
        checked_at: generated_at - 10,
        note: Some(
            "Indexer is replaying publishRoot events after a canonical rollback.".to_string(),
        ),
    });
    let ots_indexer = AnchorIndexerCursor::from_sequences(AnchorIndexerCursorInput {
        service_id: "ots-import-monitor".to_string(),
        lane: AnchorLaneKind::BitcoinOts,
        chain_id: Some("bitcoin:mainnet".to_string()),
        indexed_checkpoint_seq: 9_182,
        canonical_checkpoint_seq: 9_184,
        indexed_block_number: None,
        replaying: false,
        failed: false,
        checked_at: generated_at - 12,
        note: Some(
            "OTS attachment remains behind the canonical EVM head during replay.".to_string(),
        ),
    });
    let mut anchor_report = AnchorRuntimeReport::new(generated_at, anchor_state.controls.clone());
    anchor_report.indexers = vec![root_registry_indexer.clone(), ots_indexer.clone()];
    anchor_report.lanes = vec![
        AnchorLaneRuntimeStatus::from_indexer(
            &root_registry_indexer,
            AnchorLaneRuntimeStatusInput {
                lane: AnchorLaneKind::EvmPrimary,
                chain_id: Some("eip155:8453".to_string()),
                latest_checkpoint_seq: 9_184,
                controls: anchor_state.controls.clone(),
                reorg_depth: 2,
                last_published_at: Some(generated_at - 40),
                next_action: Some(
                    "confirm the canonical publishRoot event for checkpoint 9184 before resuming new publication"
                        .to_string(),
                ),
                note: Some("Primary publication remains in recovery-only mode.".to_string()),
            },
        ),
        AnchorLaneRuntimeStatus::from_indexer(
            &ots_indexer,
            AnchorLaneRuntimeStatusInput {
                lane: AnchorLaneKind::BitcoinOts,
                chain_id: Some("bitcoin:mainnet".to_string()),
                latest_checkpoint_seq: 9_184,
                controls: anchor_state.controls.clone(),
                reorg_depth: 0,
                last_published_at: Some(generated_at - 50),
                next_action: Some(
                    "hold imported OTS attachment until the EVM lane reconverges".to_string(),
                ),
                note: Some("Secondary proof import is gated behind canonical replay.".to_string()),
            },
        ),
    ];
    anchor_report.incidents = vec![
        AnchorIncidentAlert {
            code: "root_registry_reorg".to_string(),
            severity: AnchorAlertSeverity::Critical,
            lane: AnchorLaneKind::EvmPrimary,
            chain_id: Some("eip155:8453".to_string()),
            checkpoint_seq: Some(9_184),
            observed_at: generated_at - 60,
            message:
                "Observed root publication disappeared from canonical Base history and requires replay."
                    .to_string(),
        },
        AnchorIncidentAlert {
            code: "secondary_proof_import_paused".to_string(),
            severity: AnchorAlertSeverity::Warning,
            lane: AnchorLaneKind::BitcoinOts,
            chain_id: Some("bitcoin:mainnet".to_string()),
            checkpoint_seq: Some(9_184),
            observed_at: generated_at - 55,
            message:
                "Secondary proof import remains paused until the primary EVM lane is canonical again."
                    .to_string(),
        },
    ];
    assert_eq!(
        anchor_report.controls.mode,
        AnchorEmergencyMode::RecoveryOnly
    );

    let mut settlement_state = SettlementControlState::new(
        generated_at - 120,
        SettlementEmergencyControls::normal(generated_at - 120),
    );
    settlement_state.apply_change(
        SettlementEmergencyMode::DispatchPaused,
        generated_at - 50,
        "ops-oncall",
        Some(
            "pause new escrow dispatch while canonical settlement history is reviewed".to_string(),
        ),
        "qualification_drill",
    );
    settlement_state.apply_change(
        SettlementEmergencyMode::RefundOnly,
        generated_at - 40,
        "ops-oncall",
        Some("keep only refund and impairment actions writable during replay".to_string()),
        "qualification_drill",
    );
    ensure_settlement_operation_allowed(
        settlement_state.controls.clone(),
        SettlementOperationKind::DispatchEscrow,
    )
    .test_unwrap_err();
    ensure_settlement_operation_allowed(
        settlement_state.controls.clone(),
        SettlementOperationKind::RefundEscrow,
    )
    .test_unwrap();

    let escrow_indexer = SettlementIndexerCursor::from_blocks(SettlementIndexerCursorInput {
        service_id: "escrow-release-indexer".to_string(),
        chain_id: "eip155:8453".to_string(),
        last_indexed_block_number: Some(29_920_145),
        canonical_block_number: 29_920_148,
        replaying: true,
        failed: false,
        checked_at: generated_at - 15,
        note: Some(
            "Escrow release events are being replayed against the canonical head.".to_string(),
        ),
    });
    let bond_indexer = SettlementIndexerCursor::from_blocks(SettlementIndexerCursorInput {
        service_id: "bond-watchdog-indexer".to_string(),
        chain_id: "eip155:8453".to_string(),
        last_indexed_block_number: Some(29_920_148),
        canonical_block_number: 29_920_148,
        replaying: false,
        failed: false,
        checked_at: generated_at - 14,
        note: Some("Bond lifecycle observation is current.".to_string()),
    });
    let recovery = SettlementRecoveryRecord {
        execution_receipt_id: "chio.web3-execution-receipt.replay-001".to_string(),
        chain_id: "eip155:8453".to_string(),
        tx_hash: "0x9c4c7e6af6a876d4dd9d9a4e66d60b7222d7c23bb0b4f5a0f2d43c1d3f0ac7bb".to_string(),
        finality_status: SettlementFinalityStatus::Reorged,
        recovery_action: Some(SettlementRecoveryAction::ResubmitAfterReorg),
        reorg_depth: Some(2),
        observed_at: generated_at - 20,
        note: Some(
            "Merkle release disappeared from canonical Base history and must be rebuilt."
                .to_string(),
        ),
    };
    let mut settlement_report =
        SettlementRuntimeReport::new(generated_at, settlement_state.controls.clone());
    settlement_report.indexers = vec![escrow_indexer.clone(), bond_indexer];
    settlement_report.lanes = vec![SettlementLaneRuntimeStatus::new(
        SettlementLaneRuntimeStatusInput {
            chain_id: "eip155:8453".to_string(),
            network_name: "Base Mainnet".to_string(),
            indexer_status: SettlementIndexerStatus::Replaying,
            finality_status: Some(SettlementFinalityStatus::Reorged),
            controls: settlement_state.controls.clone(),
            queued_recoveries: 1,
            last_observed_at: Some(generated_at - 15),
            note: Some(
                "New dispatch is paused; refunds and expiry remain allowed while replay completes."
                    .to_string(),
            ),
        },
    )];
    settlement_report.recoveries = vec![recovery.clone()];
    settlement_report.incidents = vec![
        SettlementIncidentAlert {
            code: "settlement_reorg".to_string(),
            severity: SettlementAlertSeverity::Critical,
            chain_id: "eip155:8453".to_string(),
            execution_receipt_id: Some(recovery.execution_receipt_id.clone()),
            observed_at: generated_at - 20,
            message:
                "Confirmed settlement receipt no longer matches canonical chain history."
                    .to_string(),
        },
        SettlementIncidentAlert {
            code: "refund_only_mode".to_string(),
            severity: SettlementAlertSeverity::Warning,
            chain_id: "eip155:8453".to_string(),
            execution_receipt_id: None,
            observed_at: generated_at - 40,
            message:
                "New dispatch and beneficiary release remain paused while refund-first recovery is active."
                    .to_string(),
        },
    ];
    assert_eq!(
        settlement_report.controls.mode,
        SettlementEmergencyMode::RefundOnly
    );

    let root = output_root();
    let runtime_reports_dir = root.join("runtime-reports");
    let control_state_dir = root.join("control-state");
    let control_traces_dir = root.join("control-traces");
    write_json(
        &runtime_reports_dir.join("chio-link-runtime-report.json"),
        &link_report,
    );
    write_json(
        &runtime_reports_dir.join("chio-anchor-runtime-report.json"),
        &anchor_report,
    );
    write_json(
        &runtime_reports_dir.join("chio-settle-runtime-report.json"),
        &settlement_report,
    );
    write_json(
        &control_state_dir.join("chio-link-control-state.json"),
        &link_state,
    );
    write_json(
        &control_state_dir.join("chio-anchor-control-state.json"),
        &anchor_state,
    );
    write_json(
        &control_state_dir.join("chio-settle-control-state.json"),
        &settlement_state,
    );
    write_json(
        &control_traces_dir.join("chio-link-control-trace.json"),
        &link_state.history,
    );
    write_json(
        &control_traces_dir.join("chio-anchor-control-trace.json"),
        &anchor_state.history,
    );
    write_json(
        &control_traces_dir.join("chio-settle-control-trace.json"),
        &settlement_state.history,
    );
    let incident_audit = json!({
        "schema": "chio.web3-ops-incident-audit.v1",
        "generatedAt": generated_at,
        "drill": "operator-controls-drill",
        "artifacts": {
            "runtimeReports": [
                "runtime-reports/chio-link-runtime-report.json",
                "runtime-reports/chio-anchor-runtime-report.json",
                "runtime-reports/chio-settle-runtime-report.json"
            ],
            "controlState": [
                "control-state/chio-link-control-state.json",
                "control-state/chio-anchor-control-state.json",
                "control-state/chio-settle-control-state.json"
            ],
            "controlTraces": [
                "control-traces/chio-link-control-trace.json",
                "control-traces/chio-anchor-control-trace.json",
                "control-traces/chio-settle-control-trace.json"
            ]
        },
        "assertions": [
            {
                "component": "chio-link",
                "result": "pass",
                "details": "runtime report reflects pair pause and disabled standby chain after explicit operator actions"
            },
            {
                "component": "chio-anchor",
                "result": "pass",
                "details": "recovery-only mode denies new publication while preserving confirmation actions"
            },
            {
                "component": "chio-settle",
                "result": "pass",
                "details": "refund-only mode blocks dispatch and retains explicit reorg recovery records"
            }
        ]
    });
    write_json(&root.join("incident-audit.json"), &incident_audit);

    let written_link: chio_link::monitor::OracleRuntimeReport = serde_json::from_slice(
        &fs::read(runtime_reports_dir.join("chio-link-runtime-report.json")).test_unwrap(),
    )
    .test_unwrap();
    assert!(written_link.pairs.iter().any(|pair| pair.pair == "BTC/USD"
        && pair.status == chio_link::monitor::PairHealthStatus::Paused));
    let written_anchor: AnchorRuntimeReport = serde_json::from_slice(
        &fs::read(runtime_reports_dir.join("chio-anchor-runtime-report.json")).test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(
        written_anchor.controls.mode,
        AnchorEmergencyMode::RecoveryOnly
    );
    let written_settlement: SettlementRuntimeReport = serde_json::from_slice(
        &fs::read(runtime_reports_dir.join("chio-settle-runtime-report.json")).test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(
        written_settlement.controls.mode,
        SettlementEmergencyMode::RefundOnly
    );
    let written_audit: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("incident-audit.json")).test_unwrap())
            .test_unwrap();
    assert_eq!(written_audit["schema"], "chio.web3-ops-incident-audit.v1");
}
