use super::*;

mod api_mcp;
mod attest;
mod certify_cert;
mod did_passport;
mod federation;
#[path = "lineage.rs"]
mod lineage_cmd;
#[path = "market.rs"]
mod market_cmd;
mod output;
mod pheromone;
mod policy_analysis;
mod proof;
mod receipt_evidence;
mod reputation_guard;
mod runtime;
mod settle_arena;
#[path = "trust.rs"]
mod trust_cmd;
mod workflow;

use api_mcp::{dispatch_api, dispatch_mcp};
#[allow(unused_imports)]
pub(crate) use self::attest::{
    cmd_chio_attest_runtime_quote_verify, cmd_chio_attest_supply_chain_verify, decode_fixed_hex,
    dispatch_chio_attest_command, dispatch_chio_buyer_command, verify_runtime_quote_with_backend,
    write_chio_attest_report, RuntimeQuoteBackendReport,
};
#[cfg(feature = "tee-quotes")]
#[allow(unused_imports)]
pub(crate) use self::attest::{
    collateral_required_str, collateral_required_u32, decode_hex_required,
    decode_hex_vec_required, parse_quote_tcb_status, unix_seconds_to_system_time,
    RuntimeQuoteCollateralDocument,
};
use certify_cert::{dispatch_cert, dispatch_certify};
use did_passport::{dispatch_did, dispatch_passport};
#[allow(unused_imports)]
pub(crate) use self::federation::{
    dispatch_chio_authority_command, dispatch_chio_federation_command,
    dispatch_chio_treaty_command,
};
#[allow(unused_imports)]
pub(crate) use self::lineage_cmd::{dispatch_lineage, emit_lineage_report};
#[allow(unused_imports)]
pub(crate) use self::market_cmd::{
    cmd_market_info, cmd_market_install, cmd_market_list, parse_market_tier,
};
pub(crate) use output::write_cli_error;
#[allow(unused_imports)]
pub(crate) use self::pheromone::dispatch_chio_pheromone_command;
use policy_analysis::dispatch_policy;
use proof::{dispatch_commerce, dispatch_proof};
use receipt_evidence::{dispatch_evidence, dispatch_receipt};
use reputation_guard::{dispatch_conformance, dispatch_guard, dispatch_reputation};
#[allow(unused_imports)]
pub(crate) use self::runtime::dispatch_chio_runtime_command;
use settle_arena::{dispatch_arena, dispatch_settle};
use trust_cmd::dispatch_trust;
use workflow::dispatch_workflow;

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
            mode,
            tool,
            params,
            server,
            output_fixture,
        } => cmd_check(
            &policy,
            mode,
            &tool,
            &params,
            &server,
            output_fixture.as_deref(),
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
        Commands::Policy { command } => dispatch_policy(command, json_output),
        Commands::Api { command } => dispatch_api(command, receipt_db, authority_seed_file),
        Commands::Mcp { command } => dispatch_mcp(command, receipt_db, revocation_db, authority_seed_file, authority_db, budget_db, session_db, control_url, control_token),
        Commands::Trust { command } => dispatch_trust(command, json_output, receipt_db, revocation_db, authority_seed_file, authority_db, budget_db, session_db, control_url, control_token),
        Commands::Receipt { command } => dispatch_receipt(command, json_output, receipt_db, control_url, control_token),
        Commands::Evidence { command } => dispatch_evidence(command, json_output, receipt_db, control_url, control_token),
        Commands::Certify { command } => dispatch_certify(command, json_output, control_url, control_token),
        Commands::Did { command } => dispatch_did(command, json_output),
        Commands::Passport { command } => dispatch_passport(command, json_output, receipt_db, budget_db, control_url, control_token),
        Commands::Proof { command } => dispatch_proof(command, json_output),
        Commands::Commerce { command } => dispatch_commerce(command, json_output),
        Commands::Workflow { command } => dispatch_workflow(command, json_output),
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
            weights_binding_mode,
        } => commands::bind::cmd_bind(
            &provider,
            &card,
            bundle.as_deref(),
            issuer_san_regex.as_deref(),
            issuer_oidc.as_deref(),
            &weights_binding_mode,
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
