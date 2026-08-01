use super::*;

pub(crate) struct LiabilityMarketListArgs<'a> {
    pub(crate) quote_request_id: Option<&'a str>,
    pub(crate) provider_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) jurisdiction: Option<&'a str>,
    pub(crate) coverage_class: Option<&'a str>,
    pub(crate) currency: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) struct LiabilityClaimsListArgs<'a> {
    pub(crate) claim_id: Option<&'a str>,
    pub(crate) provider_id: Option<&'a str>,
    pub(crate) agent_subject: Option<&'a str>,
    pub(crate) jurisdiction: Option<&'a str>,
    pub(crate) policy_number: Option<&'a str>,
    pub(crate) limit: usize,
}

pub(crate) fn cmd_trust_liability_provider_issue(
    input_file: &Path,
    supersedes_provider_record_id: Option<&str>,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let report = load_liability_provider_report(input_file)?;
    let provider = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let request = trust_control::LiabilityProviderIssueRequest {
            report,
            supersedes_provider_record_id: supersedes_provider_record_id.map(ToOwned::to_owned),
        };
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_provider(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability provider issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_provider(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &report,
            supersedes_provider_record_id,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&provider)?);
    } else {
        println!("provider_record_id: {}", provider.body.provider_record_id);
        println!("provider_id:        {}", provider.body.report.provider_id);
        println!("display_name:       {}", provider.body.report.display_name);
        println!("lifecycle_state:    {:?}", provider.body.lifecycle_state);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_provider_list(
    provider_id: Option<&str>,
    jurisdiction: Option<&str>,
    coverage_class: Option<&str>,
    currency: Option<&str>,
    lifecycle_state: Option<&str>,
    limit: usize,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityProviderListQuery {
        provider_id: provider_id.map(ToOwned::to_owned),
        jurisdiction: jurisdiction.map(ToOwned::to_owned),
        coverage_class: coverage_class
            .map(parse_liability_coverage_class)
            .transpose()?,
        currency: currency.map(ToOwned::to_owned),
        lifecycle_state: lifecycle_state
            .map(parse_liability_provider_lifecycle_state)
            .transpose()?,
        limit: Some(limit),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.list_liability_providers(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability provider list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_providers(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("providers: {}", report.summary.returned_providers);
        for row in report.providers {
            println!(
                "- {} [{}] lifecycle={:?}",
                row.provider.body.report.provider_id,
                row.provider.body.report.display_name,
                row.lifecycle_state
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_provider_resolve(
    provider_id: &str,
    jurisdiction: &str,
    coverage_class: &str,
    currency: &str,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityProviderResolutionQuery {
        provider_id: provider_id.to_string(),
        jurisdiction: jurisdiction.to_string(),
        coverage_class: parse_liability_coverage_class(coverage_class)?,
        currency: currency.to_string(),
    };

    let report = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.resolve_liability_provider(&query)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability provider resolution requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::resolve_liability_provider(receipt_db_path, &query)?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "provider_id:        {}",
            report.provider.body.report.provider_id
        );
        println!(
            "display_name:       {}",
            report.provider.body.report.display_name
        );
        println!("jurisdiction:       {}", report.matched_policy.jurisdiction);
        println!(
            "coverage_classes:   {}",
            serde_json::to_string(&report.matched_policy.coverage_classes)?
        );
        println!(
            "currencies:         {}",
            serde_json::to_string(&report.matched_policy.supported_currencies)?
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_quote_request_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_quote_request_issue_request(input_file)?;
    let quote_request = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_quote_request(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability quote request issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_quote_request(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&quote_request)?);
    } else {
        println!(
            "quote_request_id:      {}",
            quote_request.body.quote_request_id
        );
        println!(
            "provider_id:           {}",
            quote_request.body.provider_policy.provider_id
        );
        println!(
            "jurisdiction:          {}",
            quote_request.body.provider_policy.jurisdiction
        );
        println!(
            "coverage_class:        {:?}",
            quote_request.body.provider_policy.coverage_class
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_quote_response_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_quote_response_issue_request(input_file)?;
    let quote_response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_quote_response(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability quote response issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_quote_response(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&quote_response)?);
    } else {
        println!(
            "quote_response_id:     {}",
            quote_response.body.quote_response_id
        );
        println!(
            "quote_request_id:      {}",
            quote_response.body.quote_request.body.quote_request_id
        );
        println!(
            "disposition:           {:?}",
            quote_response.body.disposition
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_pricing_authority_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_pricing_authority_issue_request(input_file)?;
    let authority = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_pricing_authority(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability pricing authority issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_pricing_authority(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&authority)?);
    } else {
        println!("authority_id:          {}", authority.body.authority_id);
        println!(
            "quote_request_id:      {}",
            authority.body.quote_request.body.quote_request_id
        );
        println!("expires_at:            {}", authority.body.expires_at);
        println!(
            "auto_bind_enabled:     {}",
            authority.body.auto_bind_enabled
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_placement_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_placement_issue_request(input_file)?;
    let placement = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_placement(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability placement issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_placement(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&placement)?);
    } else {
        println!("placement_id:          {}", placement.body.placement_id);
        println!(
            "quote_response_id:     {}",
            placement.body.quote_response.body.quote_response_id
        );
        println!("effective_from:        {}", placement.body.effective_from);
        println!("effective_until:       {}", placement.body.effective_until);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_bound_coverage_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_bound_coverage_issue_request(input_file)?;
    let bound = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_bound_coverage(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability bound coverage issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_bound_coverage(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&bound)?);
    } else {
        println!("bound_coverage_id:     {}", bound.body.bound_coverage_id);
        println!(
            "placement_id:          {}",
            bound.body.placement.body.placement_id
        );
        println!("policy_number:         {}", bound.body.policy_number);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_auto_bind_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_auto_bind_issue_request(input_file)?;
    let decision = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_auto_bind(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability auto-bind issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_auto_bind(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        println!("decision_id:           {}", decision.body.decision_id);
        println!("disposition:           {:?}", decision.body.disposition);
        println!(
            "authority_id:          {}",
            decision.body.authority.body.authority_id
        );
        println!(
            "placement_id:          {}",
            decision
                .body
                .placement
                .as_ref()
                .map(|placement| placement.body.placement_id.as_str())
                .unwrap_or("-"),
        );
        println!(
            "bound_coverage_id:     {}",
            decision
                .body
                .bound_coverage
                .as_ref()
                .map(|bound| bound.body.bound_coverage_id.as_str())
                .unwrap_or("-"),
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_issue_request(input_file)?;
    let claim = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_claim_package(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_package(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&claim)?);
    } else {
        println!("claim_id:              {}", claim.body.claim_id);
        println!(
            "bound_coverage_id:     {}",
            claim.body.bound_coverage.body.bound_coverage_id
        );
        println!("claimant:              {}", claim.body.claimant);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_response_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_response_issue_request(input_file)?;
    let response = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_claim_response(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim response issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_response(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("claim_response_id:     {}", response.body.claim_response_id);
        println!(
            "claim_id:              {}",
            response.body.claim.body.claim_id
        );
        println!("disposition:           {:?}", response.body.disposition);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_dispute_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_dispute_issue_request(input_file)?;
    let dispute = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_claim_dispute(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim dispute issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_dispute(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&dispute)?);
    } else {
        println!("dispute_id:            {}", dispute.body.dispute_id);
        println!(
            "claim_response_id:     {}",
            dispute.body.provider_response.body.claim_response_id
        );
        println!("opened_by:             {}", dispute.body.opened_by);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_adjudication_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    roster_policy_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_adjudication_issue_request(input_file)?;
    let adjudication = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_liability_claim_adjudication(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim adjudication issuance requires --receipt-db <path> when \
                 --control-url is not set"
                    .to_string(),
            )
        })?;
        let policy = roster_policy_file
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "liability claim adjudication issuance requires --roster-policy-file <path> \
                     when --control-url is not set"
                        .to_string(),
                )
            })
            .and_then(load_roster_policy)?;
        trust_control::issue_signed_liability_claim_adjudication(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
            &policy,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&adjudication)?);
    } else {
        println!(
            "adjudication_id:       {}",
            adjudication.body.adjudication_id
        );
        println!(
            "dispute_id:            {}",
            adjudication.body.dispute.body.dispute_id
        );
        println!("outcome:               {:?}", adjudication.body.outcome);
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_payout_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    roster_policy_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_payout_instruction_issue_request(input_file)?;
    let payout_instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_liability_claim_payout_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim payout instruction issuance requires --receipt-db <path> when \
                 --control-url is not set"
                    .to_string(),
            )
        })?;
        let policy = roster_policy_file
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "liability claim payout instruction issuance requires --roster-policy-file \
                     <path> when --control-url is not set"
                        .to_string(),
                )
            })
            .and_then(load_roster_policy)?;
        trust_control::issue_signed_liability_claim_payout_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
            &policy,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&payout_instruction)?);
    } else {
        println!(
            "payout_instruction_id: {}",
            payout_instruction.body.payout_instruction_id
        );
        println!(
            "adjudication_id:       {}",
            payout_instruction.body.adjudication.body.adjudication_id
        );
        println!(
            "capital_instruction_id:{}",
            payout_instruction
                .body
                .capital_instruction
                .body
                .instruction_id
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_payout_receipt_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_payout_receipt_issue_request(input_file)?;
    let payout_receipt = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.issue_liability_claim_payout_receipt(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim payout receipt issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_payout_receipt(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&payout_receipt)?);
    } else {
        println!(
            "payout_receipt_id:     {}",
            payout_receipt.body.payout_receipt_id
        );
        println!(
            "payout_instruction_id: {}",
            payout_receipt
                .body
                .payout_instruction
                .body
                .payout_instruction_id
        );
        println!(
            "reconciliation_state:  {:?}",
            payout_receipt.body.reconciliation_state
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_settlement_instruction_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    roster_policy_file: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_settlement_instruction_issue_request(input_file)?;
    let settlement_instruction = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_liability_claim_settlement_instruction(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim settlement instruction issuance requires --receipt-db <path> \
                 when --control-url is not set"
                    .to_string(),
            )
        })?;
        let policy = roster_policy_file
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "liability claim settlement instruction issuance requires \
                     --roster-policy-file <path> when --control-url is not set"
                        .to_string(),
                )
            })
            .and_then(load_roster_policy)?;
        trust_control::issue_signed_liability_claim_settlement_instruction(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
            &policy,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&settlement_instruction)?);
    } else {
        println!(
            "settlement_instruction_id: {}",
            settlement_instruction.body.settlement_instruction_id
        );
        println!(
            "payout_receipt_id:        {}",
            settlement_instruction
                .body
                .payout_receipt
                .body
                .payout_receipt_id
        );
        println!(
            "settlement_kind:          {:?}",
            settlement_instruction.body.settlement_kind
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claim_settlement_receipt_issue(
    input_file: &Path,
    json_output: bool,
    receipt_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let request = load_liability_claim_settlement_receipt_issue_request(input_file)?;
    let settlement_receipt = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?
            .issue_liability_claim_settlement_receipt(&request)?
    } else {
        let receipt_db_path = receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claim settlement receipt issuance requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::issue_signed_liability_claim_settlement_receipt(
            receipt_db_path,
            authority_seed_path,
            authority_db_path,
            &request,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&settlement_receipt)?);
    } else {
        println!(
            "settlement_receipt_id:    {}",
            settlement_receipt.body.settlement_receipt_id
        );
        println!(
            "settlement_instruction_id:{}",
            settlement_receipt
                .body
                .settlement_instruction
                .body
                .settlement_instruction_id
        );
        println!(
            "reconciliation_state:     {:?}",
            settlement_receipt.body.reconciliation_state
        );
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_market_list(
    args: LiabilityMarketListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityMarketWorkflowQuery {
        quote_request_id: args.quote_request_id.map(ToOwned::to_owned),
        provider_id: args.provider_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        jurisdiction: args.jurisdiction.map(ToOwned::to_owned),
        coverage_class: args
            .coverage_class
            .map(parse_liability_coverage_class)
            .transpose()?,
        currency: args.currency.map(ToOwned::to_owned),
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.liability_market_workflows(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability market list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_market_workflows(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "matching_requests:     {}",
            report.summary.matching_requests
        );
        println!(
            "returned_requests:     {}",
            report.summary.returned_requests
        );
        println!("quote_responses:       {}", report.summary.quote_responses);
        println!(
            "pricing_authorities:   {}",
            report.summary.pricing_authorities
        );
        println!(
            "auto_bind_decisions:   {}",
            report.summary.auto_bind_decisions
        );
        println!(
            "auto_bound_decisions:  {}",
            report.summary.auto_bound_decisions
        );
        println!("placements:            {}", report.summary.placements);
        println!("bound_coverages:       {}", report.summary.bound_coverages);
        for workflow in report.workflows {
            println!(
                "- {} provider={} response={} authority={} auto_bind={} placement={} bound={}",
                workflow.quote_request.body.quote_request_id,
                workflow.quote_request.body.provider_policy.provider_id,
                workflow
                    .latest_quote_response
                    .as_ref()
                    .map(|response| response.body.quote_response_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .pricing_authority
                    .as_ref()
                    .map(|authority| authority.body.authority_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .latest_auto_bind_decision
                    .as_ref()
                    .map(|decision| decision.body.decision_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .placement
                    .as_ref()
                    .map(|placement| placement.body.placement_id.as_str())
                    .unwrap_or("-"),
                workflow
                    .bound_coverage
                    .as_ref()
                    .map(|bound| bound.body.bound_coverage_id.as_str())
                    .unwrap_or("-"),
            );
        }
    }

    Ok(())
}

pub(crate) fn cmd_trust_liability_claims_list(
    args: LiabilityClaimsListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let query = chio_kernel::LiabilityClaimWorkflowQuery {
        claim_id: args.claim_id.map(ToOwned::to_owned),
        provider_id: args.provider_id.map(ToOwned::to_owned),
        agent_subject: args.agent_subject.map(ToOwned::to_owned),
        jurisdiction: args.jurisdiction.map(ToOwned::to_owned),
        policy_number: args.policy_number.map(ToOwned::to_owned),
        limit: Some(args.limit),
    };

    let report = if let Some(url) = backend.control_url {
        let token = require_control_token(backend.control_token)?;
        trust_control::service_runtime::client::build_client(url, token)?.liability_claim_workflows(&query)?
    } else {
        let receipt_db_path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "liability claims list requires --receipt-db <path> when --control-url is not set"
                    .to_string(),
            )
        })?;
        trust_control::list_liability_claim_workflows(receipt_db_path, &query)?
    };

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("matching_claims:       {}", report.summary.matching_claims);
        println!("returned_claims:       {}", report.summary.returned_claims);
        println!(
            "provider_responses:    {}",
            report.summary.provider_responses
        );
        println!(
            "accepted_responses:    {}",
            report.summary.accepted_responses
        );
        println!("denied_responses:      {}", report.summary.denied_responses);
        println!("disputes:              {}", report.summary.disputes);
        println!("adjudications:         {}", report.summary.adjudications);
        println!(
            "payout_instructions:   {}",
            report.summary.payout_instructions
        );
        println!("payout_receipts:       {}", report.summary.payout_receipts);
        println!(
            "matched_payouts:       {}",
            report.summary.matched_payout_receipts
        );
        println!(
            "mismatched_payouts:    {}",
            report.summary.mismatched_payout_receipts
        );
        println!(
            "settlement_instructions:{}",
            report.summary.settlement_instructions
        );
        println!(
            "settlement_receipts:   {}",
            report.summary.settlement_receipts
        );
        println!(
            "matched_settlements:   {}",
            report.summary.matched_settlement_receipts
        );
        println!(
            "mismatched_settlements:{}",
            report.summary.mismatched_settlement_receipts
        );
        println!(
            "counterparty_mismatch_settlements:{}",
            report.summary.counterparty_mismatch_settlement_receipts
        );
        for claim in report.claims {
            println!(
                "- {} policy={} response={} dispute={} adjudication={} payout_instruction={} payout_receipt={} settlement_instruction={} settlement_receipt={}",
                claim.claim.body.claim_id,
                claim.claim.body.bound_coverage.body.policy_number,
                claim.provider_response
                    .as_ref()
                    .map(|response| response.body.claim_response_id.as_str())
                    .unwrap_or("-"),
                claim.dispute
                    .as_ref()
                    .map(|dispute| dispute.body.dispute_id.as_str())
                    .unwrap_or("-"),
                claim.adjudication
                    .as_ref()
                    .map(|adjudication| adjudication.body.adjudication_id.as_str())
                    .unwrap_or("-"),
                claim.payout_instruction
                    .as_ref()
                    .map(|instruction| instruction.body.payout_instruction_id.as_str())
                    .unwrap_or("-"),
                claim.payout_receipt
                    .as_ref()
                    .map(|receipt| receipt.body.payout_receipt_id.as_str())
                    .unwrap_or("-"),
                claim.settlement_instruction
                    .as_ref()
                    .map(|instruction| instruction.body.settlement_instruction_id.as_str())
                    .unwrap_or("-"),
                claim.settlement_receipt
                    .as_ref()
                    .map(|receipt| receipt.body.settlement_receipt_id.as_str())
                    .unwrap_or("-"),
            );
        }
    }

    Ok(())
}

pub(crate) fn load_liability_provider_report(
    path: &Path,
) -> Result<chio_kernel::LiabilityProviderReport, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_quote_request_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityQuoteRequestIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_quote_response_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityQuoteResponseIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_pricing_authority_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityPricingAuthorityIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_placement_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityPlacementIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_bound_coverage_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityBoundCoverageIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_auto_bind_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityAutoBindIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPackageIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_response_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimResponseIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_dispute_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimDisputeIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_adjudication_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimAdjudicationIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_payout_instruction_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPayoutInstructionIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_payout_receipt_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimPayoutReceiptIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_settlement_instruction_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimSettlementInstructionIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn load_liability_claim_settlement_receipt_issue_request(
    path: &Path,
) -> Result<trust_control::LiabilityClaimSettlementReceiptIssueRequest, CliError> {
    load_json_or_yaml(path)
}

pub(crate) fn parse_liability_coverage_class(
    value: &str,
) -> Result<chio_kernel::LiabilityCoverageClass, CliError> {
    serde_json::from_str(&format!("\"{value}\""))
        .map_err(|_| CliError::policy_constraint_error(format!("invalid liability coverage class `{value}`")))
}

pub(crate) fn parse_liability_provider_lifecycle_state(
    value: &str,
) -> Result<chio_kernel::LiabilityProviderLifecycleState, CliError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|_| {
        CliError::policy_constraint_error(format!(
            "invalid liability provider lifecycle state `{value}`"
        ))
    })
}
