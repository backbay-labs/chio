use super::*;

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
