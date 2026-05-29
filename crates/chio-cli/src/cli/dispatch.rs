use super::*;

#[path = "dispatch/api_mcp.rs"]
mod api_mcp;
#[path = "dispatch/trust.rs"]
mod trust_cmd;
#[path = "dispatch/receipt_evidence.rs"]
mod receipt_evidence;
#[path = "dispatch/certify_cert.rs"]
mod certify_cert;
#[path = "dispatch/did_passport.rs"]
mod did_passport;
#[path = "dispatch/reputation_guard.rs"]
mod reputation_guard;
#[path = "dispatch/settle_arena.rs"]
mod settle_arena;

use api_mcp::{dispatch_api, dispatch_mcp};
use certify_cert::{dispatch_cert, dispatch_certify};
use did_passport::{dispatch_did, dispatch_passport};
use receipt_evidence::{dispatch_evidence, dispatch_receipt};
use reputation_guard::{dispatch_conformance, dispatch_guard, dispatch_reputation};
use settle_arena::{dispatch_arena, dispatch_settle};
use trust_cmd::dispatch_trust;

pub(crate) fn run() {
    let cli = Cli::parse();
    let receipt_db = cli.receipt_db.clone();
    let revocation_db = cli.revocation_db.clone();
    let authority_seed_file = cli.authority_seed_file.clone();
    let authority_db = cli.authority_db.clone();
    let budget_db = cli.budget_db.clone();
    let session_db = cli.session_db.clone();
    let control_url = cli.control_url.clone();
    let control_token = cli.control_token.clone();
    let json_output = cli.json_output();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let command = cli.command;
    let result = match command {
        Commands::Run { policy, command } => cmd_run(
            &policy,
            &command,
            json_output,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Check {
            policy,
            tool,
            params,
            server,
        } => cmd_check(
            &policy,
            &tool,
            &params,
            &server,
            json_output,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        Commands::Init { path } => scaffold::cmd_init(&path),
        Commands::Api { command } => dispatch_api(command, receipt_db, authority_seed_file),
        Commands::Mcp { command } => dispatch_mcp(command, receipt_db, revocation_db, authority_seed_file, authority_db, budget_db, session_db, control_url, control_token),
        Commands::Trust { command } => dispatch_trust(command, json_output, receipt_db, revocation_db, authority_seed_file, authority_db, budget_db, session_db, control_url, control_token),
        Commands::Receipt { command } => dispatch_receipt(command, json_output, receipt_db, control_url, control_token),
        Commands::Evidence { command } => dispatch_evidence(command, json_output, receipt_db, control_url, control_token),
        Commands::Certify { command } => dispatch_certify(command, json_output, control_url, control_token),
        Commands::Did { command } => dispatch_did(command, json_output),
        Commands::Passport { command } => dispatch_passport(command, json_output, receipt_db, budget_db, control_url, control_token),
        Commands::Cert { command } => dispatch_cert(command, json_output, authority_seed_file),
        Commands::Reputation { command } => dispatch_reputation(command, json_output, receipt_db, budget_db, authority_seed_file, control_url, control_token),
        Commands::Guard { command } => dispatch_guard(command, json_output),
        Commands::Conformance { command } => dispatch_conformance(command),
        Commands::Federation { command } => dispatch_chio_federation_command(command),
        Commands::Attest { command } => dispatch_chio_attest_command(command),
        Commands::Runtime { command } => dispatch_chio_runtime_command(command),
        Commands::Pheromone { command } => dispatch_chio_pheromone_command(command),
        Commands::Replay(args) => cmd_replay(&args),
        Commands::Lineage { command } => dispatch_lineage(command, json_output),
        Commands::Settle { command } => dispatch_settle(command, json_output, receipt_db),
        Commands::Doctor(args) => cmd_doctor(&args, json_output),
        Commands::Arena { command } => dispatch_arena(command, json_output),
        Commands::Bind {
            provider,
            card,
            bundle,
            issuer_san_regex,
            issuer_oidc,
        } => commands::bind::cmd_bind(
            &provider,
            &card,
            bundle.as_deref(),
            issuer_san_regex.as_deref(),
            issuer_oidc.as_deref(),
            json_output,
        ),
        Commands::Start {
            listen,
            receipt_store,
            print_config,
        } => cmd_start(
            &listen,
            receipt_store.as_deref().or(receipt_db.as_deref()),
            authority_seed_file.as_deref(),
            print_config,
        ),
    };

    if let Err(e) = result {
        let mut stderr = std::io::stderr();
        let _ = write_cli_error(&mut stderr, &e, json_output);
        std::process::exit(1);
    }
}

pub(crate) fn write_cli_error(
    writer: &mut impl Write,
    error: &CliError,
    json_output: bool,
) -> std::io::Result<()> {
    let report = error.report();
    if json_output {
        serde_json::to_writer(&mut *writer, &report).map_err(std::io::Error::other)?;
        writeln!(writer)
    } else {
        writeln!(writer, "error [{}]: {}", report.code, report.message)?;
        writeln!(writer, "context: {}", report.context)?;
        writeln!(writer, "suggested fix: {}", report.suggested_fix)
    }
}

pub(crate) fn parse_market_tier(value: &str) -> Result<chio_reputation::ReputationTier, CliError> {
    match value {
        "tier0" | "tier_0" => Ok(chio_reputation::ReputationTier::Tier0),
        "tier1" | "tier_1" => Ok(chio_reputation::ReputationTier::Tier1),
        "tier2" | "tier_2" => Ok(chio_reputation::ReputationTier::Tier2),
        "tier3" | "tier_3" => Ok(chio_reputation::ReputationTier::Tier3),
        other => Err(CliError::Other(format!(
            "unknown reputation tier '{other}'; expected tier0..tier3"
        ))),
    }
}

pub(crate) fn cmd_market_list(
    catalog: &Path,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    json: bool,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let report = market::market_list(catalog, &context)
        .map_err(|err| CliError::Other(format!("market list: {err}")))?;
    if json {
        let bytes = serde_json::to_vec_pretty(&report)
            .map_err(|err| CliError::Other(format!("market list serialize: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|err| CliError::Other(format!("market list write: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|err| CliError::Other(format!("market list write: {err}")))?;
    } else {
        let table = market::render_list_table(&report);
        std::io::Write::write_all(&mut std::io::stdout(), table.as_bytes())
            .map_err(|err| CliError::Other(format!("market list write: {err}")))?;
    }
    Ok(())
}

pub(crate) fn cmd_market_info(
    catalog: &Path,
    reference: &str,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    publisher_revoked: bool,
    json: bool,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let report = market::market_info(catalog, &context, reference, publisher_revoked)
        .map_err(|err| CliError::Other(format!("market info: {err}")))?;
    if json {
        let bytes = serde_json::to_vec_pretty(&report)
            .map_err(|err| CliError::Other(format!("market info serialize: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|err| CliError::Other(format!("market info write: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|err| CliError::Other(format!("market info write: {err}")))?;
    } else {
        let text = market::render_info_text(&report);
        std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes())
            .map_err(|err| CliError::Other(format!("market info write: {err}")))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_market_install(
    catalog: &Path,
    bundle_dir: &Path,
    reference: &str,
    tenant: &str,
    tier_str: &str,
    currency: &str,
    publisher_revoked: bool,
    json: bool,
) -> Result<(), CliError> {
    let tier = parse_market_tier(tier_str)?;
    let context = market::MarketTenantContext {
        tenant_id: tenant.to_owned(),
        tier,
        currency: currency.to_owned(),
    };
    let record =
        market::market_install(catalog, bundle_dir, &context, reference, publisher_revoked)
            .map_err(|err| CliError::Other(format!("market install: {err}")))?;
    if json {
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|err| CliError::Other(format!("market install serialize: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|err| CliError::Other(format!("market install write: {err}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|err| CliError::Other(format!("market install write: {err}")))?;
    } else {
        let line = format!(
            "installed {} for tenant {} at {} {} (limit {} {})\n",
            record.reference,
            record.tenant_id,
            record.registered_price_units,
            record.registered_price_currency,
            record.credit_limit_units,
            record.credit_limit_currency,
        );
        std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
            .map_err(|err| CliError::Other(format!("market install write: {err}")))?;
    }
    Ok(())
}

pub(crate) fn dispatch_lineage(command: LineageCommands, json_output: bool) -> Result<(), CliError> {
    use crate::lineage as ln;
    use chio_lineage::query::QueryBounds;
    match command {
        LineageCommands::Query {
            graph,
            seeds,
            direction,
            depth_limit,
            row_limit,
            json,
        } => {
            let dir = match direction.as_str() {
                "forward" => ln::Direction::Forward,
                "reverse" => ln::Direction::Reverse,
                other => {
                    return Err(CliError::Other(format!(
                        "lineage query: unknown direction {other:?}; expected forward or reverse"
                    )));
                }
            };
            let bounds = QueryBounds {
                depth_limit,
                row_limit,
            };
            let report = ln::cmd_query(&graph, &seeds, dir, bounds)
                .map_err(|e| CliError::Other(format!("lineage query: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let line = format!(
                    "lineage {}: nodes={} edges={}\n",
                    report.direction,
                    report.graph.nodes.len(),
                    report.graph.edges.len(),
                );
                std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage query write: {e}")))
            }
        }
        LineageCommands::Diff {
            left_label,
            left,
            right_label,
            right,
            json,
        } => {
            let report = ln::cmd_diff(&left_label, &left, &right_label, &right)
                .map_err(|e| CliError::Other(format!("lineage diff: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let text = ln::render_diff_text(&report);
                std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage diff write: {e}")))
            }
        }
        LineageCommands::Roots { dir, json } => {
            let report =
                ln::cmd_roots(&dir).map_err(|e| CliError::Other(format!("lineage roots: {e}")))?;
            if json || json_output {
                emit_lineage_report(&report, true)
            } else {
                let line = format!("anchored roots: {}\n", report.roots.len());
                std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
                    .map_err(|e| CliError::Other(format!("lineage roots write: {e}")))
            }
        }
    }
}

pub(crate) fn emit_lineage_report<T: serde::Serialize>(report: &T, json: bool) -> Result<(), CliError> {
    if json {
        let bytes = serde_json::to_vec_pretty(report)
            .map_err(|e| CliError::Other(format!("lineage serialize: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), &bytes)
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
    } else {
        let line = serde_json::to_string(report)
            .map_err(|e| CliError::Other(format!("lineage serialize: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes())
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
        std::io::Write::write_all(&mut std::io::stdout(), b"\n")
            .map_err(|e| CliError::Other(format!("lineage write: {e}")))?;
    }
    Ok(())
}

pub(crate) fn dispatch_chio_federation_command(command: ChioFederationCommands) -> Result<(), CliError> {
    match command {
        ChioFederationCommands::Authority { command } => dispatch_chio_authority_command(command),
        ChioFederationCommands::Treaty { command } => dispatch_chio_treaty_command(command),
    }
}

pub(crate) fn dispatch_chio_authority_command(command: ChioAuthorityCommands) -> Result<(), CliError> {
    match command {
        ChioAuthorityCommands::Issue {
            profile,
            request,
            signing_keys,
            out_dir,
        } => cmd_chio_federation_authority_issue(&profile, &request, &signing_keys, &out_dir),
        ChioAuthorityCommands::Checkpoint {
            profile,
            revocations,
            signing_keys,
            out,
        } => cmd_chio_federation_authority_checkpoint(&profile, &revocations, &signing_keys, &out),
        ChioAuthorityCommands::TrustBundle { command } => match command {
            ChioTrustBundleCommands::Assemble {
                profile,
                peer_pins,
                workflow_intersection,
                disclosure_policy,
                checkpoint,
                out,
            } => cmd_chio_federation_authority_trust_bundle_assemble(
                &profile,
                &peer_pins,
                &workflow_intersection,
                &disclosure_policy,
                &checkpoint,
                &out,
            ),
        },
    }
}

pub(crate) fn dispatch_chio_treaty_command(command: ChioTreatyCommands) -> Result<(), CliError> {
    match command {
        ChioTreatyCommands::Intersect {
            treaty_scope,
            manifest,
            now_unix_ms,
            report,
        } => cmd_chio_federation_treaty_intersect(&treaty_scope, &manifest, now_unix_ms, &report),
        ChioTreatyCommands::Admit {
            treaty_scope,
            ladder_intersection,
            expected_ladder_intersection_sha256,
            action_class_id,
            evidence,
            now_unix_ms,
            report,
        } => cmd_chio_federation_treaty_admit(
            &treaty_scope,
            &ladder_intersection,
            &expected_ladder_intersection_sha256,
            &action_class_id,
            &evidence,
            now_unix_ms,
            &report,
        ),
        ChioTreatyCommands::VerifyPacket {
            packet,
            lineage_statement,
            continuation,
            admission_report,
            bilateral_invocation,
            report,
        } => cmd_chio_federation_treaty_verify_packet(
            &packet,
            &lineage_statement,
            &continuation,
            &admission_report,
            &bilateral_invocation,
            &report,
        ),
    }
}

pub(crate) fn dispatch_chio_attest_command(command: ChioAttestCommands) -> Result<(), CliError> {
    match command {
        ChioAttestCommands::Buyer { command } => dispatch_chio_buyer_command(command),
        ChioAttestCommands::SupplyChain { command } => match command {
            ChioSupplyChainCommands::Verify {
                artifact,
                bundle,
                issuer_san_regex,
                issuer_oidc,
                report,
            } => cmd_chio_attest_supply_chain_verify(
                &artifact,
                &bundle,
                &issuer_san_regex,
                &issuer_oidc,
                report.as_deref(),
            ),
        },
        ChioAttestCommands::RuntimeQuote { command } => match command {
            ChioRuntimeQuoteCommands::Verify {
                kernel_public_key,
                receipt_root,
                report_data,
                tee_kind,
                quote,
                collateral,
                report,
            } => cmd_chio_attest_runtime_quote_verify(
                &kernel_public_key,
                &receipt_root,
                report_data.as_deref(),
                tee_kind.as_deref(),
                quote.as_deref(),
                collateral.as_deref(),
                report.as_deref(),
            ),
        },
    }
}

pub(crate) fn dispatch_chio_buyer_command(command: ChioBuyerCommands) -> Result<(), CliError> {
    match command {
        ChioBuyerCommands::Packet { run_output, out } => {
            cmd_chio_attest_buyer_package(&run_output, &out)
        }
        ChioBuyerCommands::Verify {
            package,
            trust_bundle,
            context,
            report,
        } => cmd_chio_attest_buyer_verify(&package, &trust_bundle, &context, &report),
        ChioBuyerCommands::VerifyProof {
            package,
            trust_bundle,
            context,
            report,
        } => cmd_chio_attest_buyer_verify_proof(&package, &trust_bundle, &context, &report),
        ChioBuyerCommands::VerifyPacket {
            packet,
            lineage_statement,
            continuation,
            admission_report,
            bilateral_invocation,
            report,
        } => cmd_chio_attest_buyer_verify_packet(
            &packet,
            &lineage_statement,
            &continuation,
            &admission_report,
            &bilateral_invocation,
            &report,
        ),
        ChioBuyerCommands::Explain {
            report,
            format,
            out,
        } => cmd_chio_attest_buyer_explain(&report, &format, &out),
    }
}

pub(crate) fn dispatch_chio_runtime_command(command: ChioRuntimeCommands) -> Result<(), CliError> {
    match command {
        ChioRuntimeCommands::Admit {
            request,
            admission_profile,
            admission_bundle,
            runtime_trust_input,
            trusted_verifiers,
            pheromone_query_report,
            runtime_pheromone_policy,
            runtime_peer_weights,
            action_class_id,
            trust_floor_state,
            store,
            now_unix_ms,
            report,
        } => cmd_chio_runtime_admit(
            &request,
            &admission_profile,
            &admission_bundle,
            runtime_trust_input.as_deref(),
            trusted_verifiers.as_deref(),
            pheromone_query_report.as_deref(),
            runtime_pheromone_policy.as_deref(),
            runtime_peer_weights.as_deref(),
            action_class_id.as_deref(),
            trust_floor_state.as_deref(),
            &store,
            now_unix_ms,
            &report,
        ),
        ChioRuntimeCommands::SignTrustInput {
            body,
            signing_seed_file,
            out,
        } => cmd_chio_runtime_sign_trust_input(&body, &signing_seed_file, &out),
        ChioRuntimeCommands::Policy { command } => match command {
            ChioRuntimePolicyCommands::Sign {
                body,
                signing_seed_file,
                out,
            } => cmd_chio_runtime_sign_policy(&body, &signing_seed_file, &out),
        },
        ChioRuntimeCommands::PeerWeights { command } => match command {
            ChioRuntimePeerWeightsCommands::Hash { body, out } => {
                cmd_chio_runtime_peer_weights_hash(&body, &out)
            }
            ChioRuntimePeerWeightsCommands::Sign {
                body,
                signing_seed_file,
                out,
            } => cmd_chio_runtime_sign_peer_weights(&body, &signing_seed_file, &out),
        },
        ChioRuntimeCommands::Pheromone { command } => match command {
            ChioRuntimePheromoneCommands::SignQueryReport {
                body,
                signing_seed_file,
                out,
            } => cmd_chio_runtime_sign_pheromone_query_report(&body, &signing_seed_file, &out),
            ChioRuntimePheromoneCommands::Evaluate {
                admission_bundle,
                runtime_trust_input,
                trusted_verifiers,
                pheromone_query_report,
                runtime_pheromone_policy,
                runtime_peer_weights,
                action_class_id,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_pheromone_evaluate(
                &admission_bundle,
                &runtime_trust_input,
                &trusted_verifiers,
                &pheromone_query_report,
                &runtime_pheromone_policy,
                &runtime_peer_weights,
                action_class_id.as_deref(),
                now_unix_ms,
                &report,
            ),
        },
        ChioRuntimeCommands::Orchestrate { command } => match command {
            ChioRuntimeOrchestrateCommands::Lint { profile, report } => {
                cmd_chio_runtime_orchestrate_lint(&profile, &report)
            }
            ChioRuntimeOrchestrateCommands::Plan {
                profile,
                run_contract,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_plan(
                &profile,
                &run_contract,
                &store,
                &evidence_dir,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Run {
                profile,
                run_contract,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_run(
                &profile,
                &run_contract,
                &store,
                &evidence_dir,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Resume {
                profile,
                resume_plan,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_resume(
                &profile,
                &resume_plan,
                &store,
                &evidence_dir,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Status {
                profile,
                store,
                evidence_dir,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_status(
                &profile,
                &store,
                &evidence_dir,
                now_unix_ms.unwrap_or_else(unix_now_ms),
                &report,
            ),
            ChioRuntimeOrchestrateCommands::Drift {
                profile,
                runs_dir,
                since_unix_ms,
                until_unix_ms,
                report,
            } => cmd_chio_runtime_orchestrate_drift(
                &profile,
                &runs_dir,
                since_unix_ms,
                until_unix_ms,
                &report,
            ),
        },
        ChioRuntimeCommands::Ops { command } => match command {
            ChioRuntimeOpsCommands::Supervise {
                supervisor_profile,
                store,
                evidence_root,
                provider_bindings,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_status(
                &supervisor_profile,
                &store,
                &evidence_root,
                provider_bindings.as_deref(),
                Some(now_unix_ms),
                &report,
            ),
            ChioRuntimeOpsCommands::Tick {
                supervisor_profile,
                store,
                evidence_root,
                owner_id,
                now_unix_ms,
                max_runs,
                report,
            } => cmd_chio_runtime_ops_tick(
                &supervisor_profile,
                &store,
                &evidence_root,
                &owner_id,
                now_unix_ms,
                max_runs,
                &report,
            ),
            ChioRuntimeOpsCommands::Status {
                supervisor_profile,
                store,
                evidence_root,
                provider_bindings,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_status(
                &supervisor_profile,
                &store,
                &evidence_root,
                provider_bindings.as_deref(),
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOpsCommands::RecoveryDrill {
                supervisor_profile,
                run_id,
                store,
                evidence_root,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_recovery_drill(
                &supervisor_profile,
                &run_id,
                &store,
                &evidence_root,
                now_unix_ms,
                &report,
            ),
            ChioRuntimeOpsCommands::EvidenceHealth {
                supervisor_profile,
                run_id,
                store,
                evidence_root,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_evidence_health(
                &supervisor_profile,
                &run_id,
                &store,
                &evidence_root,
                now_unix_ms.unwrap_or_else(unix_now_ms),
                &report,
            ),
            ChioRuntimeOpsCommands::ProviderHealth {
                supervisor_profile,
                provider_bindings,
                now_unix_ms,
                report,
            } => cmd_chio_runtime_ops_provider_health(
                &supervisor_profile,
                &provider_bindings,
                now_unix_ms.unwrap_or_else(unix_now_ms),
                &report,
            ),
            ChioRuntimeOpsCommands::Retention { command } => match command {
                ChioRuntimeOpsRetentionCommands::Plan {
                    retention_profile,
                    store,
                    evidence_root,
                    now_unix_ms,
                    report,
                } => cmd_chio_runtime_ops_retention_plan(
                    &retention_profile,
                    &store,
                    &evidence_root,
                    now_unix_ms,
                    &report,
                ),
            },
        },
        ChioRuntimeCommands::RunLoopback {
            scenario,
            store_dir,
            now_unix_ms,
            out_dir,
        } => cmd_chio_runtime_run_loopback(&scenario, &store_dir, now_unix_ms, &out_dir),
    }
}

pub(crate) fn dispatch_chio_pheromone_command(command: ChioPheromoneCommands) -> Result<(), CliError> {
    match command {
        ChioPheromoneCommands::Receive {
            batch,
            transit_policy,
            proof_package,
            trust_bundle,
            context,
            store,
            now_unix_ms,
            report,
        } => cmd_chio_pheromone_receive(
            &batch,
            &transit_policy,
            &proof_package,
            &trust_bundle,
            &context,
            &store,
            now_unix_ms,
            &report,
        ),
        ChioPheromoneCommands::Query {
            store,
            subject_class,
            namespace,
            reputation_epoch,
            peer_weights,
            now_unix_ms,
            report,
        } => cmd_chio_pheromone_query(
            &store,
            &subject_class,
            &namespace,
            reputation_epoch,
            &peer_weights,
            now_unix_ms,
            &report,
        ),
        ChioPheromoneCommands::Relay { command } => match command {
            ChioPheromoneRelayCommands::Lint {
                peer_directory,
                peer_directory_state,
                profile,
                trusted_issuers,
                report,
            } => cmd_chio_pheromone_relay_lint(
                peer_directory.as_deref(),
                peer_directory_state.as_deref(),
                profile.into(),
                trusted_issuers.as_deref(),
                &report,
            ),
            ChioPheromoneRelayCommands::Serve {
                listen,
                store,
                peer_directory,
                peer_directory_state,
                profile,
                trusted_issuers,
                transit_policy,
                proof_package,
                trust_bundle,
                context,
                report_dir,
                operator_token_env,
            } => cmd_chio_pheromone_relay_serve(
                &listen,
                &store,
                peer_directory.as_deref(),
                peer_directory_state.as_deref(),
                profile.into(),
                trusted_issuers.as_deref(),
                &transit_policy,
                &proof_package,
                &trust_bundle,
                &context,
                &report_dir,
                operator_token_env.as_deref(),
            ),
            ChioPheromoneRelayCommands::Enqueue {
                store,
                batch,
                transit_policy,
                trust_bundle,
                peer_directory,
                peer_directory_state,
                profile,
                trusted_issuers,
                now_unix_ms,
                report,
            } => cmd_chio_pheromone_relay_enqueue(
                &store,
                &batch,
                &transit_policy,
                &trust_bundle,
                peer_directory.as_deref(),
                peer_directory_state.as_deref(),
                profile.into(),
                trusted_issuers.as_deref(),
                now_unix_ms,
                &report,
            ),
            ChioPheromoneRelayCommands::Tick {
                store,
                peer_directory,
                peer_directory_state,
                profile,
                trusted_issuers,
                now_unix_ms,
                max_batches,
                signing_key,
                report,
                report_dir,
            } => cmd_chio_pheromone_relay_tick(
                &store,
                peer_directory.as_deref(),
                peer_directory_state.as_deref(),
                profile.into(),
                trusted_issuers.as_deref(),
                now_unix_ms,
                max_batches,
                &signing_key,
                &report,
                report_dir.as_deref(),
            ),
            ChioPheromoneRelayCommands::Catchup {
                store,
                peer,
                peer_directory_state,
                profile,
                trusted_issuers,
                now_unix_ms,
                treaty,
                after_cursor,
                limit,
                report,
            } => cmd_chio_pheromone_relay_catchup(
                &store,
                &peer,
                peer_directory_state.as_deref(),
                profile.into(),
                trusted_issuers.as_deref(),
                now_unix_ms,
                &treaty,
                &after_cursor,
                limit,
                &report,
            ),
            ChioPheromoneRelayCommands::Status { store, report } => {
                cmd_chio_pheromone_relay_status(&store, &report)
            }
            ChioPheromoneRelayCommands::Observe {
                store,
                peer_directory_state,
                profile,
                trusted_issuers,
                report_dir,
                limit,
                report,
            } => cmd_chio_pheromone_relay_observe(
                &store,
                &peer_directory_state,
                profile.into(),
                &trusted_issuers,
                &report_dir,
                limit,
                &report,
            ),
            ChioPheromoneRelayCommands::Metrics {
                store,
                format,
                output,
            } => cmd_chio_pheromone_relay_metrics(&store, format.into(), &output),
            ChioPheromoneRelayCommands::Alert { command } => match command {
                ChioPheromoneRelayAlertCommands::Evaluate {
                    observability_report,
                    event_dir,
                    routing_profile,
                    suppression_state,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_alert_evaluate(
                    &observability_report,
                    &event_dir,
                    &routing_profile,
                    &suppression_state,
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Handoff {
                    alert_report,
                    trend_report,
                    routing_profile,
                    handoff_profile,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_alert_handoff(
                    &alert_report,
                    &trend_report,
                    &routing_profile,
                    &handoff_profile,
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Normalize {
                    profile,
                    input_dir,
                    now_unix_ms,
                    out_dir,
                    report,
                } => cmd_chio_pheromone_relay_alert_normalize(
                    &profile,
                    &input_dir,
                    now_unix_ms,
                    &out_dir,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Delivery { command } => match command {
                    ChioPheromoneRelayAlertDeliveryCommands::Import {
                        handoff_report,
                        delivery_profile,
                        evidence_dir,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_import(
                        &handoff_report,
                        &delivery_profile,
                        &evidence_dir,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertDeliveryCommands::Acknowledge {
                        handoff_report,
                        delivery_report,
                        delivery_profile,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_acknowledge(
                        &handoff_report,
                        &delivery_report,
                        &delivery_profile,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertDeliveryCommands::Drift {
                        handoff_reports_dir,
                        delivery_reports_dir,
                        delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_drift(
                        &handoff_reports_dir,
                        &delivery_reports_dir,
                        &delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertDeliveryCommands::DriftWindow {
                        handoff_reports_dir,
                        delivery_reports_dir,
                        delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_delivery_drift_window(
                        &handoff_reports_dir,
                        &delivery_reports_dir,
                        &delivery_profile,
                        since_unix_ms,
                        until_unix_ms,
                        &report,
                    ),
                },
                ChioPheromoneRelayAlertCommands::Review {
                    handoff_report,
                    delivery_report,
                    acknowledgement_report,
                    drift_report,
                    route_owner_profile,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_alert_review(
                    &handoff_report,
                    &delivery_report,
                    &acknowledgement_report,
                    &drift_report,
                    &route_owner_profile,
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayAlertCommands::Assurance { command } => match command {
                    ChioPheromoneRelayAlertAssuranceCommands::Package {
                        alert_report,
                        trend_report,
                        handoff_report,
                        normalization_report,
                        delivery_report,
                        acknowledgement_report,
                        drift_report,
                        review_packet,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_package(
                        &alert_report,
                        &trend_report,
                        &handoff_report,
                        &normalization_report,
                        &delivery_report,
                        &acknowledgement_report,
                        &drift_report,
                        &review_packet,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Export {
                        package,
                        alert_report,
                        trend_report,
                        handoff_report,
                        normalization_report,
                        delivery_report,
                        acknowledgement_report,
                        drift_report,
                        review_packet,
                        retention_profile,
                        signing_key,
                        now_unix_ms,
                        out_dir,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_export(
                        &package,
                        &alert_report,
                        &trend_report,
                        &handoff_report,
                        &normalization_report,
                        &delivery_report,
                        &acknowledgement_report,
                        &drift_report,
                        &review_packet,
                        &retention_profile,
                        &signing_key,
                        now_unix_ms,
                        &out_dir,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Verify {
                        bundle_dir,
                        trusted_exporters,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_verify(
                        &bundle_dir,
                        &trusted_exporters,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Replay {
                        bundle_dir,
                        trusted_exporters,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_replay(
                        &bundle_dir,
                        &trusted_exporters,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Retention { command } => {
                        match command {
                            ChioPheromoneRelayAlertAssuranceRetentionCommands::Plan {
                                bundle_root,
                                retention_profile,
                                now_unix_ms,
                                report,
                            } => cmd_chio_pheromone_relay_alert_assurance_retention_plan(
                                &bundle_root,
                                &retention_profile,
                                now_unix_ms,
                                &report,
                            ),
                            ChioPheromoneRelayAlertAssuranceRetentionCommands::Handoff {
                                command,
                            } => match command {
                                ChioPheromoneRelayAlertAssuranceRetentionHandoffCommands::Review {
                                    evidence,
                                    profile,
                                    package_report,
                                    now_unix_ms,
                                    report,
                                } => cmd_chio_pheromone_relay_alert_assurance_retention_handoff_review(
                                    &evidence,
                                    &profile,
                                    &package_report,
                                    now_unix_ms,
                                    &report,
                                ),
                            },
                            ChioPheromoneRelayAlertAssuranceRetentionCommands::ExternalReview {
                                package_dir,
                                source_report_dir,
                                trusted_packagers,
                                trusted_exporters,
                                profile,
                                since_unix_ms,
                                until_unix_ms,
                                now_unix_ms,
                                report,
                            } => cmd_chio_pheromone_relay_alert_assurance_retention_external_review(
                                &package_dir,
                                &source_report_dir,
                                &trusted_packagers,
                                &trusted_exporters,
                                &profile,
                                since_unix_ms,
                                until_unix_ms,
                                now_unix_ms,
                                &report,
                            ),
                        }
                    }
                    ChioPheromoneRelayAlertAssuranceCommands::RecoveryDrill {
                        bundle_dir,
                        trusted_exporters,
                        case,
                        now_unix_ms,
                        report,
                    } => cmd_chio_pheromone_relay_alert_assurance_recovery_drill(
                        &bundle_dir,
                        &trusted_exporters,
                        &case,
                        now_unix_ms,
                        &report,
                    ),
                    ChioPheromoneRelayAlertAssuranceCommands::Archive { command } => {
                        match command {
                            ChioPheromoneRelayAlertAssuranceArchiveCommands::Plan {
                                bundle_root,
                                trusted_exporters,
                                archive_profile,
                                retention_profile,
                                now_unix_ms,
                                report,
                            } => cmd_chio_pheromone_relay_alert_assurance_archive_plan(
                                &bundle_root,
                                &trusted_exporters,
                                &archive_profile,
                                &retention_profile,
                                now_unix_ms,
                                &report,
                            ),
                            ChioPheromoneRelayAlertAssuranceArchiveCommands::Package { command } => {
                                match command {
                                    ChioPheromoneRelayAlertAssuranceArchivePackageCommands::Create {
                                        bundle_root,
                                        trusted_exporters,
                                        archive_report,
                                        closeout_report,
                                        signing_key,
                                        package_id,
                                        packager_key_id,
                                        package_generation,
                                        previous_package_report,
                                        now_unix_ms,
                                        out,
                                        report,
                                    } => cmd_chio_pheromone_relay_alert_assurance_archive_package_create(
                                        &bundle_root,
                                        &trusted_exporters,
                                        &archive_report,
                                        &closeout_report,
                                        &signing_key,
                                        &package_id,
                                        &packager_key_id,
                                        package_generation,
                                        previous_package_report.as_deref(),
                                        now_unix_ms,
                                        &out,
                                        &report,
                                    ),
                                    ChioPheromoneRelayAlertAssuranceArchivePackageCommands::Verify {
                                        package,
                                        trusted_packagers,
                                        trusted_exporters,
                                        archive_report,
                                        closeout_report,
                                        now_unix_ms,
                                        report,
                                    } => cmd_chio_pheromone_relay_alert_assurance_archive_package_verify(
                                        &package,
                                        &trusted_packagers,
                                        &trusted_exporters,
                                        &archive_report,
                                        &closeout_report,
                                        now_unix_ms,
                                        &report,
                                    ),
                                    ChioPheromoneRelayAlertAssuranceArchivePackageCommands::Extract {
                                        package,
                                        trusted_packagers,
                                        trusted_exporters,
                                        archive_report,
                                        closeout_report,
                                        out_dir,
                                        now_unix_ms,
                                        report,
                                    } => cmd_chio_pheromone_relay_alert_assurance_archive_package_extract(
                                        &package,
                                        &trusted_packagers,
                                        &trusted_exporters,
                                        &archive_report,
                                        &closeout_report,
                                        &out_dir,
                                        now_unix_ms,
                                        &report,
                                    ),
                                }
                            }
                            ChioPheromoneRelayAlertAssuranceArchiveCommands::PhysicalDrill {
                                command,
                            } => match command {
                                ChioPheromoneRelayAlertAssurancePhysicalDrillCommands::Review {
                                    evidence,
                                    package_report,
                                    now_unix_ms,
                                    report,
                                } => cmd_chio_pheromone_relay_alert_assurance_physical_drill_review(
                                    &evidence,
                                    &package_report,
                                    now_unix_ms,
                                    &report,
                                ),
                            },
                            ChioPheromoneRelayAlertAssuranceArchiveCommands::RestoreDrill {
                                command,
                            } => match command {
                                ChioPheromoneRelayAlertAssuranceArchiveRestoreDrillCommands::Review {
                                    package_dir,
                                    source_report_dir,
                                    trusted_packagers,
                                    trusted_exporters,
                                    restore_profile,
                                    now_unix_ms,
                                    report,
                                } => cmd_chio_pheromone_relay_alert_assurance_archive_restore_drill_review(
                                    &package_dir,
                                    &source_report_dir,
                                    &trusted_packagers,
                                    &trusted_exporters,
                                    &restore_profile,
                                    now_unix_ms,
                                    &report,
                                ),
                            },
                        }
                    }
                    ChioPheromoneRelayAlertAssuranceCommands::Closeout { command } => {
                        match command {
                            ChioPheromoneRelayAlertAssuranceCloseoutCommands::Review {
                                bundle_root,
                                trusted_exporters,
                                closeout_profile,
                                retention_profile,
                                now_unix_ms,
                                report,
                            } => cmd_chio_pheromone_relay_alert_assurance_closeout_review(
                                &bundle_root,
                                &trusted_exporters,
                                &closeout_profile,
                                &retention_profile,
                                now_unix_ms,
                                &report,
                            ),
                        }
                    }
                },
            },
            ChioPheromoneRelayCommands::Trend {
                reports_dir,
                event_dir,
                routing_profile,
                since_unix_ms,
                until_unix_ms,
                report,
            } => cmd_chio_pheromone_relay_trend(
                &reports_dir,
                &event_dir,
                &routing_profile,
                since_unix_ms,
                until_unix_ms,
                &report,
            ),
            ChioPheromoneRelayCommands::Directory { command } => match command {
                ChioPheromoneRelayDirectoryCommands::Inspect { state, report } => {
                    cmd_chio_pheromone_relay_directory_inspect(&state, &report)
                }
                ChioPheromoneRelayDirectoryCommands::Promote {
                    state,
                    candidate,
                    trusted_issuers,
                    profile,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_directory_promote(
                    &state,
                    &candidate,
                    &trusted_issuers,
                    profile.into(),
                    now_unix_ms,
                    &report,
                ),
                ChioPheromoneRelayDirectoryCommands::Reject {
                    state,
                    candidate,
                    reason,
                    now_unix_ms,
                    report,
                } => cmd_chio_pheromone_relay_directory_reject(
                    &state,
                    &candidate,
                    &reason,
                    now_unix_ms,
                    &report,
                ),
            },
            ChioPheromoneRelayCommands::Supervisor { command } => match command {
                ChioPheromoneRelaySupervisorCommands::Lint { profile, report } => {
                    cmd_chio_pheromone_relay_supervisor_lint(&profile, &report)
                }
            },
        },
    }
}

pub(crate) fn cmd_chio_attest_supply_chain_verify(
    artifact: &Path,
    bundle: &Path,
    issuer_san_regex: &str,
    issuer_oidc: &str,
    report: Option<&Path>,
) -> Result<(), CliError> {
    let artifact_bytes = fs::read(artifact)?;
    let bundle_json = fs::read(bundle)?;
    let expected =
        chio_attest_verify::ExpectedIdentity::doc_hidden_inline(issuer_san_regex, issuer_oidc);
    let verifier = chio_attest_verify::SigstoreVerifier::with_embedded_root()
        .map_err(|error| CliError::Other(format!("supply-chain verifier init: {error}")))?;
    let verified = chio_attest_verify::AttestVerifier::verify_bundle(
        &verifier,
        &artifact_bytes,
        &bundle_json,
        &expected,
    )
    .map_err(|error| CliError::Other(format!("supply-chain verify: {error}")))?;
    let signed_at_unix_seconds = verified
        .signed_at
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CliError::Other(format!("supply-chain signing time: {error}")))?
        .as_secs();
    let report_json = serde_json::json!({
        "schema": "chio.attest.supply-chain.verify-report.v1",
        "accepted": true,
        "artifact": artifact,
        "bundle": bundle,
        "subjectDigestSha256": hex::encode(verified.subject_digest_sha256),
        "certificateIdentity": verified.certificate_identity,
        "certificateOidcIssuer": verified.certificate_oidc_issuer,
        "rekorLogIndex": verified.rekor_log_index,
        "rekorInclusionVerified": verified.rekor_inclusion_verified,
        "signedAtUnixSeconds": signed_at_unix_seconds
    });
    write_chio_attest_report(&report_json, report)
}

pub(crate) fn cmd_chio_attest_runtime_quote_verify(
    kernel_public_key: &str,
    receipt_root: &str,
    report_data: Option<&str>,
    tee_kind: Option<&str>,
    quote: Option<&Path>,
    collateral: Option<&Path>,
    report: Option<&Path>,
) -> Result<(), CliError> {
    let kernel_public_key = chio_core::crypto::PublicKey::from_hex(kernel_public_key)?;
    let receipt_root = decode_fixed_hex::<32>(receipt_root, "receipt-root")?;
    let observed_report_data = report_data
        .map(|value| decode_fixed_hex::<64>(value, "report-data"))
        .transpose()?;
    let expected_report_data =
        chio_attest_verify::expect_report_data(&kernel_public_key, &receipt_root);

    let Some(quote) = quote else {
        let report_json = serde_json::json!({
            "schema": "chio.attest.runtime-quote.verification-report.v1",
            "accepted": false,
            "verificationKind": "reportDataBindingOnly",
            "verificationState": "unresolved",
            "failureCode": "quote_evidence_missing",
            "detail": "report-data binding alone is not runtime quote verification",
            "kernelPublicKey": kernel_public_key.to_hex(),
            "receiptRoot": hex::encode(receipt_root),
            "expectedReportData": hex::encode(expected_report_data),
            "observedReportData": observed_report_data.map(hex::encode)
        });
        write_chio_attest_report(&report_json, report)?;
        return Err(CliError::Other(
            "runtime-quote verification requires full quote evidence".to_string(),
        ));
    };
    let tee_kind = tee_kind.ok_or_else(|| {
        CliError::Other("runtime-quote verification requires --tee-kind".to_string())
    })?;
    let collateral = collateral.ok_or_else(|| {
        CliError::Other("runtime-quote verification requires --collateral".to_string())
    })?;

    match verify_runtime_quote_with_backend(tee_kind, quote, collateral, &kernel_public_key, &receipt_root) {
        Ok(verified) => {
            if let Some(provided_report_data) = observed_report_data {
                if provided_report_data != verified.report_data {
                    let report_json = serde_json::json!({
                        "schema": "chio.attest.runtime-quote.verification-report.v1",
                        "accepted": false,
                        "verificationKind": "teeQuote",
                        "verificationState": "rejected",
                        "failureCode": "provided_report_data_mismatch",
                        "teeKind": verified.tee_kind,
                        "kernelPublicKey": kernel_public_key.to_hex(),
                        "receiptRoot": hex::encode(receipt_root),
                        "expectedReportData": hex::encode(expected_report_data),
                        "verifiedReportData": hex::encode(verified.report_data),
                        "observedReportData": hex::encode(provided_report_data)
                    });
                    write_chio_attest_report(&report_json, report)?;
                    return Err(CliError::Other(
                        "runtime-quote provided report-data does not match verified quote".to_string(),
                    ));
                }
            }
            let report_json = serde_json::json!({
                "schema": "chio.attest.runtime-quote.verification-report.v1",
                "accepted": true,
                "verificationKind": "teeQuote",
                "verificationState": "verified",
                "teeKind": verified.tee_kind,
                "tcbStatus": verified.tcb_status,
                "signedAtUnixSeconds": verified.signed_at_unix_seconds,
                "kernelPublicKey": kernel_public_key.to_hex(),
                "receiptRoot": hex::encode(receipt_root),
                "expectedReportData": hex::encode(expected_report_data),
                "observedReportData": hex::encode(verified.report_data)
            });
            write_chio_attest_report(&report_json, report)
        }
        Err(error) => {
            let failure_code = if error.to_string().contains("tee-quotes feature") {
                "tee_quote_feature_disabled"
            } else {
                "quote_verification_failed"
            };
            let report_json = serde_json::json!({
                "schema": "chio.attest.runtime-quote.verification-report.v1",
                "accepted": false,
                "verificationKind": "teeQuote",
                "verificationState": "rejected",
                "failureCode": failure_code,
                "detail": error.to_string(),
                "teeKind": tee_kind,
                "kernelPublicKey": kernel_public_key.to_hex(),
                "receiptRoot": hex::encode(receipt_root),
                "expectedReportData": hex::encode(expected_report_data),
                "observedReportData": observed_report_data.map(hex::encode)
            });
            write_chio_attest_report(&report_json, report)?;
            Err(error)
        }
    }
}

pub(crate) struct RuntimeQuoteBackendReport {
    tee_kind: String,
    report_data: [u8; 64],
    tcb_status: String,
    signed_at_unix_seconds: u64,
}

#[cfg(feature = "tee-quotes")]
pub(crate) fn verify_runtime_quote_with_backend(
    tee_kind: &str,
    quote: &Path,
    collateral: &Path,
    kernel_public_key: &chio_core::crypto::PublicKey,
    receipt_root: &[u8; 32],
) -> Result<RuntimeQuoteBackendReport, CliError> {
    use chio_attest_verify::QuoteVerifier;

    let quote_bytes = fs::read(quote)?;
    let collateral_bytes = fs::read(collateral)?;
    let collateral: RuntimeQuoteCollateralDocument = serde_json::from_slice(&collateral_bytes)?;
    let verification_time = collateral
        .verification_time_unix_seconds
        .map(unix_seconds_to_system_time)
        .transpose()?;
    let context = chio_attest_verify::QuoteVerificationContext::new(kernel_public_key, receipt_root);
    let verified = match tee_kind {
        "intel-tdx" => {
            let verification_time =
                verification_time.unwrap_or_else(std::time::SystemTime::now);
            let verifier = chio_attest_verify::tdx::TdxDcapVerifier::with_verification_time(
                chio_attest_verify::tdx::TdxCollateral::new(
                    decode_hex_required(
                        collateral.intel_root_ca_der_hex.as_deref(),
                        "intelRootCaDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.pck_certificate_chain_der_hex.as_deref(),
                        "pckCertificateChainDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.tcb_info_issuer_chain_der_hex.as_deref(),
                        "tcbInfoIssuerChainDerHex",
                    )?,
                    collateral_required_u32(
                        collateral.tcb_recovery_event_id,
                        "tcbRecoveryEventId",
                    )?,
                    parse_quote_tcb_status(&collateral.tcb_status)?,
                    unix_seconds_to_system_time(collateral.not_before_unix_seconds)?,
                    unix_seconds_to_system_time(collateral.not_after_unix_seconds)?,
                ),
                collateral_required_u32(
                    collateral.min_tcb_recovery_event_id,
                    "minTcbRecoveryEventId",
                )?,
                verification_time,
            );
            verifier
                .verify_quote(&quote_bytes, &context)
                .map_err(|error| CliError::cli_other_error(format!("attest verify: {error}")))?
        }
        "amd-sev-snp" => {
            let verification_time =
                verification_time.unwrap_or_else(std::time::SystemTime::now);
            let expected_launch_digest = decode_fixed_hex::<48>(
                collateral_required_str(
                    collateral.expected_launch_digest_hex.as_deref(),
                    "expectedLaunchDigestHex",
                )?,
                "expectedLaunchDigestHex",
            )?;
            let verifier = chio_attest_verify::sev_snp::SevSnpVerifier::with_verification_time(
                chio_attest_verify::sev_snp::SevSnpCollateral::new(
                    decode_hex_required(
                        collateral.amd_kds_root_der_hex.as_deref(),
                        "amdKdsRootDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.vcek_chain_der_hex.as_deref(),
                        "vcekChainDerHex",
                    )?,
                    decode_hex_vec_required(
                        collateral.vlek_chain_der_hex.as_deref(),
                        "vlekChainDerHex",
                    )?,
                    collateral_required_u32(
                        collateral.tcb_recovery_event_id,
                        "tcbRecoveryEventId",
                    )?,
                    parse_quote_tcb_status(&collateral.tcb_status)?,
                    unix_seconds_to_system_time(collateral.not_before_unix_seconds)?,
                    unix_seconds_to_system_time(collateral.not_after_unix_seconds)?,
                ),
                collateral_required_u32(
                    collateral.min_tcb_recovery_event_id,
                    "minTcbRecoveryEventId",
                )?,
                expected_launch_digest,
                verification_time,
            );
            verifier
                .verify_quote(&quote_bytes, &context)
                .map_err(|error| CliError::cli_other_error(format!("attest verify: {error}")))?
        }
        "aws-nitro" => {
            let verification_time =
                verification_time.unwrap_or_else(std::time::SystemTime::now);
            let expected_pcr0 = decode_fixed_hex::<48>(
                collateral_required_str(collateral.expected_pcr0_hex.as_deref(), "expectedPcr0Hex")?,
                "expectedPcr0Hex",
            )?;
            let verifier = chio_attest_verify::nitro::NitroVerifier::with_verification_time(
                chio_attest_verify::nitro::NitroCollateral::new(
                    decode_hex_required(
                        collateral.aws_nitro_root_der_hex.as_deref(),
                        "awsNitroRootDerHex",
                    )?,
                    decode_hex_vec_required(collateral.chain_der_hex.as_deref(), "chainDerHex")?,
                    parse_quote_tcb_status(&collateral.tcb_status)?,
                    unix_seconds_to_system_time(collateral.not_before_unix_seconds)?,
                    unix_seconds_to_system_time(collateral.not_after_unix_seconds)?,
                ),
                expected_pcr0,
                verification_time,
            );
            verifier
                .verify_quote(&quote_bytes, &context)
                .map_err(|error| CliError::cli_other_error(format!("attest verify: {error}")))?
        }
        other => {
            return Err(CliError::Other(format!(
                "unsupported runtime quote tee kind {other}"
            )));
        }
    };

    Ok(RuntimeQuoteBackendReport {
        tee_kind: verified.tee_kind.to_string(),
        report_data: verified.report_data,
        tcb_status: verified.tcb_status.to_string(),
        signed_at_unix_seconds: verified
            .signed_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|error| {
                CliError::Other(format!("runtime quote signed_at precedes unix epoch: {error}"))
            })?
            .as_secs(),
    })
}

#[cfg(not(feature = "tee-quotes"))]
pub(crate) fn verify_runtime_quote_with_backend(
    _tee_kind: &str,
    _quote: &Path,
    _collateral: &Path,
    _kernel_public_key: &chio_core::crypto::PublicKey,
    _receipt_root: &[u8; 32],
) -> Result<RuntimeQuoteBackendReport, CliError> {
    Err(CliError::Other(
        "runtime-quote TEE backend verification requires the tee-quotes feature".to_string(),
    ))
}

#[cfg(feature = "tee-quotes")]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeQuoteCollateralDocument {
    #[serde(rename = "schema")]
    _schema: Option<String>,
    tcb_status: String,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
    verification_time_unix_seconds: Option<u64>,
    intel_root_ca_der_hex: Option<String>,
    pck_certificate_chain_der_hex: Option<Vec<String>>,
    tcb_info_issuer_chain_der_hex: Option<Vec<String>>,
    tcb_recovery_event_id: Option<u32>,
    min_tcb_recovery_event_id: Option<u32>,
    amd_kds_root_der_hex: Option<String>,
    vcek_chain_der_hex: Option<Vec<String>>,
    vlek_chain_der_hex: Option<Vec<String>>,
    expected_launch_digest_hex: Option<String>,
    aws_nitro_root_der_hex: Option<String>,
    chain_der_hex: Option<Vec<String>>,
    expected_pcr0_hex: Option<String>,
}

#[cfg(feature = "tee-quotes")]
pub(crate) fn parse_quote_tcb_status(
    value: &str,
) -> Result<chio_attest_verify::QuoteTcbStatus, CliError> {
    match value {
        "up-to-date" | "up_to_date" => Ok(chio_attest_verify::QuoteTcbStatus::UpToDate),
        "configuration-needed" | "configuration_needed" => {
            Ok(chio_attest_verify::QuoteTcbStatus::ConfigurationNeeded)
        }
        "out-of-date" | "out_of_date" => Ok(chio_attest_verify::QuoteTcbStatus::OutOfDate),
        "revoked" => Ok(chio_attest_verify::QuoteTcbStatus::Revoked),
        "unrecognized" => Ok(chio_attest_verify::QuoteTcbStatus::Unrecognized),
        other => Err(CliError::Other(format!(
            "unsupported runtime quote tcbStatus {other}"
        ))),
    }
}

#[cfg(feature = "tee-quotes")]
pub(crate) fn unix_seconds_to_system_time(seconds: u64) -> Result<std::time::SystemTime, CliError> {
    std::time::SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(seconds))
        .ok_or_else(|| CliError::Other("runtime quote timestamp overflow".to_string()))
}

#[cfg(feature = "tee-quotes")]
pub(crate) fn collateral_required_str<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, CliError> {
    value.ok_or_else(|| CliError::Other(format!("runtime quote collateral missing {name}")))
}

#[cfg(feature = "tee-quotes")]
pub(crate) fn collateral_required_u32(value: Option<u32>, name: &str) -> Result<u32, CliError> {
    value.ok_or_else(|| CliError::Other(format!("runtime quote collateral missing {name}")))
}

#[cfg(feature = "tee-quotes")]
pub(crate) fn decode_hex_required(value: Option<&str>, name: &str) -> Result<Vec<u8>, CliError> {
    let value = collateral_required_str(value, name)?;
    hex::decode(value).map_err(|error| {
        CliError::Other(format!("runtime quote collateral {name} is not hex: {error}"))
    })
}

#[cfg(feature = "tee-quotes")]
pub(crate) fn decode_hex_vec_required(values: Option<&[String]>, name: &str) -> Result<Vec<Vec<u8>>, CliError> {
    let values =
        values.ok_or_else(|| CliError::Other(format!("runtime quote collateral missing {name}")))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            hex::decode(value).map_err(|error| {
                CliError::Other(format!(
                    "runtime quote collateral {name}[{index}] is not hex: {error}"
                ))
            })
        })
        .collect()
}

pub(crate) fn decode_fixed_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], CliError> {
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|error| CliError::Other(format!("{name}: expected {N} bytes of hex: {error}")))?;
    Ok(bytes)
}

pub(crate) fn write_chio_attest_report(
    report_json: &serde_json::Value,
    report: Option<&Path>,
) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(report_json)?;
    if let Some(report) = report {
        fs::write(report, &bytes)?;
        fs::OpenOptions::new()
            .append(true)
            .open(report)?
            .write_all(b"\n")?;
    } else {
        std::io::stdout().write_all(&bytes)?;
        std::io::stdout().write_all(b"\n")?;
    }
    Ok(())
}
