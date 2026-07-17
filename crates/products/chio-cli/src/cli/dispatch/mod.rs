use super::*;

mod api_mcp;
mod attest;
mod budget;
mod certify_cert;
mod did_passport;
mod federation;
#[path = "lineage.rs"]
mod lineage_cmd;
#[path = "market.rs"]
mod market_cmd;
mod output;
mod pheromone;
mod proof;
mod receipt_evidence;
mod reputation_guard;
mod runtime;
mod settle_arena;
#[path = "trust.rs"]
mod trust_cmd;
mod workflow;

use api_mcp::{dispatch_api, dispatch_mcp};
use budget::dispatch_budget;
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
use proof::{dispatch_commerce, dispatch_proof};
use receipt_evidence::{dispatch_evidence, dispatch_receipt};
use reputation_guard::{dispatch_conformance, dispatch_guard, dispatch_reputation};
#[allow(unused_imports)]
pub(crate) use self::runtime::dispatch_chio_runtime_command;
use settle_arena::{dispatch_arena, dispatch_settle};
use trust_cmd::dispatch_trust;
use workflow::dispatch_workflow;

/// Control-encode a log field so untrusted content cannot forge log lines.
///
/// SECURITY: the redaction layer only masks known-sensitive values; a payload,
/// error string, or tool output that survives redaction can still carry a raw
/// `\n`/`\r` (or other control character) that would split the single stderr
/// event into several physical lines and let an attacker inject fabricated
/// operator log entries. `char::escape_debug` escapes every newline, carriage
/// return, tab, quote, backslash, and non-printable char while leaving ordinary
/// printable text intact, guaranteeing the field stays on one line.
fn escape_log_field(value: &str) -> String {
    value.chars().flat_map(char::escape_debug).collect()
}

/// Format a redacted tracing event into one stderr line. Both field names and
/// values are control-encoded so no field can introduce a line break and forge
/// an additional log record.
fn format_redacted_event_line(event: &chio_log_redact::RedactedEvent) -> String {
    let mut line = format!("{} {}", event.level, event.target);
    for field in &event.fields {
        line.push_str(&format!(
            " {}={}",
            escape_log_field(&field.name),
            escape_log_field(&field.value)
        ));
    }
    line
}

/// Format a redacted tracing event into one stderr line and write it.
fn write_redacted_event_to_stderr(event: chio_log_redact::RedactedEvent) {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        format_redacted_event_line(&event)
    );
}

#[cfg(test)]
mod redacted_format_tests {
    use super::{escape_log_field, format_redacted_event_line};
    use chio_log_redact::{RedactedEvent, RedactedField};

    #[test]
    fn redacted_field_newline_cannot_forge_a_log_line() {
        // A field value carrying a newline (e.g. untrusted tool output that
        // survived redaction) must not split the single stderr event into two
        // physical lines and forge an operator log record.
        let event = RedactedEvent {
            target: "chio::dispatch".to_string(),
            level: tracing::Level::WARN,
            fields: vec![RedactedField {
                name: "payload".to_string(),
                value: "first line\nWARN chio::auth forged=admin-granted".to_string(),
            }],
        };
        let line = format_redacted_event_line(&event);
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "control characters in a field value must be escaped: {line:?}"
        );
        assert!(
            line.contains("first line\\nWARN"),
            "the newline must be control-encoded, not passed through: {line:?}"
        );
    }

    #[test]
    fn escape_log_field_leaves_ordinary_text_intact() {
        assert_eq!(escape_log_field("cap-1234 allow"), "cap-1234 allow");
        assert_eq!(escape_log_field("tab\there"), "tab\\there");
    }
}

/// Install the process tracing subscriber whose ONLY event-formatting layer is
/// the redacting one, so any field a call site forgot to wrap in `redacted!` is
/// still redacted before it reaches an operator (subscriber-level backstop).
/// Also seeds the known metric label sets so `absent_over_time` alerts fire
/// only on a true scrape gap, and defaults `chio.guard=info` so guard telemetry
/// is not dropped by the default `warn` filter. Fail-closed: a redaction
/// construction failure aborts startup rather than serving unredacted logs.
fn init_redacted_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    chio_metrics_spec::runtime::preregister_known_label_sets();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,chio.guard=info"));
    let redaction = match chio_log_redact::RedactionLayer::new(write_redacted_event_to_stderr) {
        Ok(layer) => layer,
        Err(error) => {
            eprintln!("fatal: log redaction subscriber failed to initialize: {error}");
            std::process::exit(1);
        }
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(redaction)
        .init();
}

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

    init_redacted_tracing();

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
        Commands::Api { command } => dispatch_api(command, receipt_db, revocation_db, authority_seed_file, budget_db, control_url, control_token),
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
        Commands::Settle { command } => {
            dispatch_settle(command, json_output, receipt_db, &cli.settlement_driver)
        }
        Commands::Budget { command } => dispatch_budget(command, json_output, budget_db.clone()),
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
            allow_ephemeral_receipts,
            print_config,
        } => cmd_start(
            &listen,
            receipt_store.as_deref().or(receipt_db.as_deref()),
            authority_seed_file.as_deref(),
            budget_db.as_deref(),
            revocation_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
            allow_ephemeral_receipts,
            print_config,
        ),
    };

    if let Err(e) = result {
        let mut stderr = std::io::stderr();
        let _ = write_cli_error(&mut stderr, &e, json_output);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn redaction_subscriber_builds() {
        let layer =
            chio_log_redact::RedactionLayer::new(|_event: chio_log_redact::RedactedEvent| {});
        assert!(layer.is_ok(), "redaction layer must construct");
    }
}
