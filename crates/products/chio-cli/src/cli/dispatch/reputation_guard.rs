// Dispatch handlers for the `chio reputation`, `chio guard`, and `chio conformance` command groups.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_reputation(
    command: ReputationCommands,
    json_output: bool,
    receipt_db: Option<PathBuf>,
    budget_db: Option<PathBuf>,
    authority_seed_file: Option<PathBuf>,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
            ReputationCommands::Local {
                subject_public_key,
                since,
                until,
                policy,
            } => reputation::cmd_reputation_local(reputation::ReputationLocalCommand {
                subject_public_key: &subject_public_key,
                since,
                until,
                policy_path: policy.as_deref(),
                json_output,
                receipt_db_path: receipt_db.as_deref(),
                budget_db_path: budget_db.as_deref(),
                control_url: control_url.as_deref(),
                control_token: control_token.as_deref(),
                authority_seed_file: authority_seed_file.as_deref(),
            }),
            ReputationCommands::Compare {
                subject_public_key,
                passport,
                since,
                until,
                local_policy,
                verifier_policy,
            } => reputation::cmd_reputation_compare(reputation::ReputationCompareCommand {
                subject_public_key: &subject_public_key,
                passport_path: &passport,
                since,
                until,
                local_policy_path: local_policy.as_deref(),
                verifier_policy_path: verifier_policy.as_deref(),
                json_output,
                receipt_db_path: receipt_db.as_deref(),
                budget_db_path: budget_db.as_deref(),
                control_url: control_url.as_deref(),
                control_token: control_token.as_deref(),
                authority_seed_file: authority_seed_file.as_deref(),
            }),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_guard(
    command: GuardCommands,
    json_output: bool,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
            GuardCommands::New { name } => guard::cmd_guard_new(&name),
            GuardCommands::Build => guard::cmd_guard_build(),
            GuardCommands::Inspect { path } => guard::cmd_guard_inspect(&path),
            GuardCommands::Test {
                wasm,
                fixtures,
                fuel_limit,
            } => guard::cmd_guard_test(&wasm, &fixtures, fuel_limit),
            GuardCommands::Bench {
                path,
                iterations,
                fuel_limit,
            } => guard::cmd_guard_bench(&path, iterations, fuel_limit),
            GuardCommands::Pack => guard::cmd_guard_pack(),
            GuardCommands::Publish {
                project,
                reference,
                wit,
                signer_public_key,
                signer_subject,
                fuel_limit,
                memory_limit_bytes,
                epoch_id_seed,
                username,
                password,
                allow_http_registry,
            } => guard::cmd_guard_publish(guard::GuardPublishCommand {
                project_dir: &project,
                reference: &reference,
                wit_path: &wit,
                signer_public_key: signer_public_key.as_deref(),
                signer_subject: signer_subject.as_deref(),
                fuel_limit,
                memory_limit_bytes,
                epoch_id_seed: &epoch_id_seed,
                username: username.as_deref(),
                password: password.as_deref(),
                allow_http_registry: allow_http_registry.clone(),
            }),
            GuardCommands::Pull {
                reference,
                username,
                password,
                allow_http_registry,
                sigstore_bundle,
                sigstore_identity_regex,
                sigstore_oidc_issuer,
            } => guard::cmd_guard_pull(guard::GuardPullCommand {
                reference: &reference,
                username: username.as_deref(),
                password: password.as_deref(),
                allow_http_registry: allow_http_registry.clone(),
                sigstore_bundle: sigstore_bundle.as_deref(),
                sigstore_identity_regex: sigstore_identity_regex.as_deref(),
                sigstore_oidc_issuer: sigstore_oidc_issuer.as_deref(),
            }),
            GuardCommands::Blocklist { command } => match command {
                GuardBlocklistCommands::Remove { digest } => {
                    commands::guard_blocklist::cmd_guard_blocklist_remove(&digest)
                }
            },
            GuardCommands::Install { path, target_dir } => {
                guard::cmd_guard_install(&path, &target_dir)
            }
            GuardCommands::Sign {
                wasm,
                key,
                name,
                version,
            } => guards::sign::cmd_guard_sign(&wasm, &key, &name, &version),
            GuardCommands::Verify { wasm } => guards::sign::cmd_guard_verify(&wasm),
            GuardCommands::Market { command } => match command {
                GuardMarketCommands::List {
                    catalog,
                    tenant,
                    tier,
                    currency,
                    json,
                } => cmd_market_list(
                    &catalog,
                    &tenant,
                    &tier,
                    &currency,
                    json || json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                GuardMarketCommands::Info {
                    catalog,
                    reference,
                    tenant,
                    tier,
                    currency,
                    publisher_revoked,
                    json,
                } => cmd_market_info(
                    &catalog,
                    &reference,
                    &tenant,
                    &tier,
                    &currency,
                    publisher_revoked,
                    json || json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
                GuardMarketCommands::Install {
                    catalog,
                    bundle_dir,
                    reference,
                    tenant,
                    tier,
                    currency,
                    publisher_revoked,
                    json,
                } => cmd_market_install(
                    &catalog,
                    &bundle_dir,
                    &reference,
                    &tenant,
                    &tier,
                    &currency,
                    publisher_revoked,
                    json || json_output,
                    control_url.as_deref(),
                    control_token.as_deref(),
                ),
            },
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_conformance(
    command: ConformanceCommands,
) -> Result<(), CliError> {
    match command {
            ConformanceCommands::Run {
                peer,
                report,
                scenario,
                output,
                peer_binary,
            } => cmd_conformance_run(
                &peer,
                report.as_deref(),
                scenario.as_deref(),
                output.as_deref(),
                peer_binary.as_deref(),
            ),
            ConformanceCommands::FetchPeers {
                check,
                out,
                language,
                allow_unpublished_only,
                lockfile,
            } => cmd_conformance_fetch_peers(
                check,
                &out,
                language.as_deref(),
                allow_unpublished_only,
                lockfile.as_deref(),
            ),
    }
}
