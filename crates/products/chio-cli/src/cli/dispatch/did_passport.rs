// Dispatch handlers for the `chio did` and `chio passport` command groups.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_did(command: DidCommands, json_output: bool) -> Result<(), CliError> {
    match command {
        DidCommands::Resolve {
            did,
            public_key,
            receipt_log_urls,
            passport_status_urls,
        } => did::cmd_did_resolve(
            did.as_deref(),
            public_key.as_deref(),
            &receipt_log_urls,
            &passport_status_urls,
            json_output,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_passport(
    command: PassportCommands,
    json_output: bool,
    receipt_db: Option<PathBuf>,
    budget_db: Option<PathBuf>,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
        PassportCommands::Generate {
            agent,
            output,
            compliance_score,
            behavioral_anomaly,
            validity_days,
        } => passport::cmd_passport_generate(
            &agent,
            output.as_deref(),
            compliance_score,
            behavioral_anomaly,
            validity_days,
            json_output,
        ),
        PassportCommands::Create {
            subject_public_key,
            output,
            signing_seed_file,
            validity_days,
            since,
            until,
            receipt_log_urls,
            require_checkpoints,
            enterprise_identity,
        } => passport::cmd_passport_create(
            &subject_public_key,
            &output,
            &signing_seed_file,
            validity_days,
            since,
            until,
            &receipt_log_urls,
            require_checkpoints,
            enterprise_identity.as_deref(),
            receipt_db.as_deref(),
            budget_db.as_deref(),
            json_output,
        ),
        PassportCommands::Verify {
            input,
            at,
            passport_statuses_file,
        } => passport::cmd_passport_verify(
            &input,
            at,
            passport_statuses_file.as_deref(),
            json_output,
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        PassportCommands::Evaluate {
            input,
            policy,
            at,
            passport_statuses_file,
        } => passport::cmd_passport_evaluate(
            &input,
            &policy,
            at,
            passport_statuses_file.as_deref(),
            json_output,
            control_url.as_deref(),
            control_token.as_deref(),
        ),
        PassportCommands::Present {
            input,
            output,
            issuers,
            max_credentials,
        } => {
            passport::cmd_passport_present(&input, &output, &issuers, max_credentials, json_output)
        }
        PassportCommands::Policy { command } => match command {
            PassportPolicyCommands::Create {
                output,
                policy_id,
                verifier,
                signing_seed_file,
                policy,
                expires_at,
                verifier_policies_file,
            } => {
                passport::verifier::cmd_passport_policy_create(passport::PassportPolicyCreateArgs {
                    output: &output,
                    policy_id: &policy_id,
                    verifier: &verifier,
                    signing_seed_file: &signing_seed_file,
                    policy_path: &policy,
                    expires_at,
                    verifier_policies_file: verifier_policies_file.as_deref(),
                    json_output,
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                })
            }
            PassportPolicyCommands::Verify { input, at } => {
                passport::verifier::cmd_passport_policy_verify(&input, at, json_output)
            }
            PassportPolicyCommands::List {
                verifier_policies_file,
            } => passport::verifier::cmd_passport_policy_list(
                json_output,
                verifier_policies_file.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportPolicyCommands::Get {
                policy_id,
                verifier_policies_file,
            } => passport::verifier::cmd_passport_policy_get(
                &policy_id,
                json_output,
                verifier_policies_file.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportPolicyCommands::Upsert {
                input,
                verifier_policies_file,
            } => passport::verifier::cmd_passport_policy_upsert(
                &input,
                json_output,
                verifier_policies_file.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportPolicyCommands::Delete {
                policy_id,
                verifier_policies_file,
            } => passport::verifier::cmd_passport_policy_delete(
                &policy_id,
                json_output,
                verifier_policies_file.as_deref(),
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        PassportCommands::Challenge { command } => match command {
            PassportChallengeCommands::Create {
                output,
                verifier,
                ttl_secs,
                issuers,
                max_credentials,
                policy,
                policy_id,
                verifier_policies_file,
                verifier_challenge_db,
            } => passport::verifier::cmd_passport_challenge_create(
                passport::PassportChallengeCreateArgs {
                    output: &output,
                    verifier: &verifier,
                    ttl_secs,
                    issuers: &issuers,
                    max_credentials,
                    policy_path: policy.as_deref(),
                    policy_id: policy_id.as_deref(),
                    verifier_policies_file: verifier_policies_file.as_deref(),
                    verifier_challenge_db: verifier_challenge_db.as_deref(),
                    json_output,
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
            PassportChallengeCommands::Respond {
                input,
                challenge,
                challenge_url,
                holder_seed_file,
                output,
                at,
            } => passport::verifier::cmd_passport_challenge_respond(
                &input,
                challenge.as_deref(),
                challenge_url.as_deref(),
                &holder_seed_file,
                &output,
                at,
                json_output,
            ),
            PassportChallengeCommands::Submit { input, submit_url } => {
                passport::verifier::cmd_passport_challenge_submit(&input, &submit_url, json_output)
            }
            PassportChallengeCommands::Verify {
                input,
                challenge,
                verifier_policies_file,
                verifier_challenge_db,
                passport_statuses_file,
                at,
            } => passport::verifier::cmd_passport_challenge_verify(
                &input,
                challenge.as_deref(),
                verifier_policies_file.as_deref(),
                verifier_challenge_db.as_deref(),
                passport_statuses_file.as_deref(),
                at,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        PassportCommands::Status { command } => match command {
            PassportStatusCommands::Publish {
                input,
                passport_statuses_file,
                resolve_urls,
                cache_ttl_secs,
            } => passport::verifier::cmd_passport_status_publish(
                &input,
                passport_statuses_file.as_deref(),
                &resolve_urls,
                cache_ttl_secs,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportStatusCommands::List {
                passport_statuses_file,
            } => passport::verifier::cmd_passport_status_list(
                passport_statuses_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportStatusCommands::Get {
                passport_id,
                passport_statuses_file,
            } => passport::verifier::cmd_passport_status_get(
                &passport_id,
                passport_statuses_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportStatusCommands::Resolve {
                passport_id,
                passport_statuses_file,
            } => passport::verifier::cmd_passport_status_resolve(
                &passport_id,
                passport_statuses_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportStatusCommands::Revoke {
                passport_id,
                passport_statuses_file,
                reason,
                revoked_at,
            } => passport::verifier::cmd_passport_status_revoke(
                &passport_id,
                passport_statuses_file.as_deref(),
                reason.as_deref(),
                revoked_at,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        PassportCommands::Issuance { command } => match command {
            PassportIssuanceCommands::Metadata {
                issuer_url,
                signing_seed_file,
                passport_status_url,
                passport_status_cache_ttl_secs,
            } => passport::cmd_passport_issuance_metadata(
                issuer_url.as_deref(),
                signing_seed_file.as_deref(),
                passport_status_url.as_deref(),
                passport_status_cache_ttl_secs,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportIssuanceCommands::Offer {
                input,
                output,
                issuer_url,
                passport_issuance_offers_file,
                passport_statuses_file,
                signing_seed_file,
                credential_configuration_id,
                ttl_secs,
            } => passport::cmd_passport_issuance_offer_create(
                &input,
                output.as_deref(),
                issuer_url.as_deref(),
                passport_issuance_offers_file.as_deref(),
                passport_statuses_file.as_deref(),
                signing_seed_file.as_deref(),
                credential_configuration_id.as_deref(),
                ttl_secs,
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportIssuanceCommands::Token {
                offer,
                output,
                passport_issuance_offers_file,
            } => passport::cmd_passport_issuance_token_redeem(
                &offer,
                output.as_deref(),
                passport_issuance_offers_file.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
            PassportIssuanceCommands::Credential {
                offer,
                token,
                output,
                passport_issuance_offers_file,
                passport_statuses_file,
                signing_seed_file,
                credential_configuration_id,
                credential_format,
            } => passport::cmd_passport_issuance_credential_redeem(
                &offer,
                &token,
                output.as_deref(),
                passport_issuance_offers_file.as_deref(),
                passport_statuses_file.as_deref(),
                signing_seed_file.as_deref(),
                credential_configuration_id.as_deref(),
                credential_format.as_deref(),
                json_output,
                control_url.as_deref(),
                control_token.as_deref(),
            ),
        },
        PassportCommands::Oid4vp { command } => match command {
            PassportOid4vpCommands::Create {
                output,
                disclosure_claims,
                issuer_allowlist,
                ttl_secs,
                identity_subject,
                identity_continuity_id,
                identity_provider,
                identity_session_hint,
                identity_ttl_secs,
            } => passport::verifier::cmd_passport_oid4vp_request_create(
                passport::PassportOid4vpRequestCreateArgs {
                    output: output.as_deref(),
                    disclosure_claims: &disclosure_claims,
                    issuer_allowlist: &issuer_allowlist,
                    ttl_secs,
                    identity_subject: identity_subject.as_deref(),
                    identity_continuity_id: identity_continuity_id.as_deref(),
                    identity_provider: identity_provider.as_deref(),
                    identity_session_hint: identity_session_hint.as_deref(),
                    identity_ttl_secs,
                    json_output,
                    control_url: control_url.as_deref(),
                    control_token: control_token.as_deref(),
                },
            ),
            PassportOid4vpCommands::Respond {
                input,
                request_url,
                same_device_url,
                cross_device_url,
                holder_seed_file,
                output,
                submit,
                submit_url,
                at,
            } => passport::verifier::cmd_passport_oid4vp_respond(
                passport::PassportOid4vpRespondArgs {
                    input: &input,
                    request_url: request_url.as_deref(),
                    same_device_url: same_device_url.as_deref(),
                    cross_device_url: cross_device_url.as_deref(),
                    holder_seed_file: &holder_seed_file,
                    output: output.as_deref(),
                    submit,
                    submit_url: submit_url.as_deref(),
                    at,
                    json_output,
                },
            ),
            PassportOid4vpCommands::Submit { input, submit_url } => {
                passport::verifier::cmd_passport_oid4vp_submit(&input, &submit_url, json_output)
            }
            PassportOid4vpCommands::Metadata { verifier_url } => {
                passport::verifier::cmd_passport_oid4vp_metadata(&verifier_url, json_output)
            }
        },
    }
}
