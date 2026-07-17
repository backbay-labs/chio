// CLI handlers for `chio cert` commands.

use std::collections::BTreeSet;
use std::path::Path;

use chio_acp_proxy::{
    generate_compliance_certificate, verify_compliance_certificate, ComplianceCertificate,
    ComplianceConfig, ComplianceReceiptEntry, VerificationMode,
};

use crate::CliError;

/// `chio cert generate` -- walk the receipt store for a session and produce
/// a signed compliance certificate.
pub fn cmd_cert_generate(
    session_id: &str,
    receipt_db: &Path,
    budget_limit: u64,
    output: Option<&Path>,
    authority_seed_file: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let default_seed_path = std::path::PathBuf::from(".chio-authority-seed");
    let seed_path = authority_seed_file.unwrap_or(&default_seed_path);
    let keypair = crate::load_or_create_authority_keypair(seed_path)?;

    let db_path = receipt_db.to_string_lossy();
    let conn = rusqlite::Connection::open(receipt_db).map_err(|e| {
        CliError::cli_other_error(format!("failed to open receipt db {db_path}: {e}"))
    })?;

    let receipts = load_session_receipts(&conn, session_id)?;

    let config = ComplianceConfig {
        budget_limit,
        required_guards: Vec::new(),
        authorized_scopes: Vec::new(),
        expected_tenant_id: None,
        trusted_kernel_keys: BTreeSet::from([keypair.public_key().to_hex()]),
    };

    let cert = generate_compliance_certificate(session_id, &receipts, &config, &keypair)
        .map_err(|e| CliError::cli_other_error(format!("certificate generation failed: {e}")))?;

    let cert_json = serde_json::to_string_pretty(&cert)
        .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &cert_json)
            .map_err(|e| CliError::cli_other_error(format!("failed to write output: {e}")))?;
        if !json_output {
            eprintln!(
                "compliance certificate for session {} written to {}",
                session_id,
                out_path.display()
            );
        }
    }

    if json_output || output.is_none() {
        println!("{cert_json}");
    }

    Ok(())
}

/// `chio cert verify` -- verify a compliance certificate.
pub fn cmd_cert_verify(
    certificate_path: &Path,
    full: bool,
    receipt_db: Option<&Path>,
    trusted_kernel_pubkey: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let cert_text = std::fs::read_to_string(certificate_path)
        .map_err(|e| CliError::cli_other_error(format!("failed to read certificate: {e}")))?;

    let cert: ComplianceCertificate = serde_json::from_str(&cert_text)
        .map_err(|e| CliError::cli_other_error(format!("failed to parse certificate: {e}")))?;

    let mode = if full {
        VerificationMode::FullBundle
    } else {
        VerificationMode::Lightweight
    };

    let receipts = if full {
        if let Some(db_path) = receipt_db {
            let conn = rusqlite::Connection::open(db_path).map_err(|e| {
                CliError::cli_other_error(format!("failed to open receipt db: {e}"))
            })?;
            let entries = load_session_receipts(&conn, &cert.body.session_id)?;
            Some(entries)
        } else {
            return Err(CliError::cli_other_error(
                "full-bundle verification requires --receipt-db".to_string(),
            ));
        }
    } else {
        None
    };

    let trusted_kernel_key =
        crate::load_trusted_kernel_pubkey(trusted_kernel_pubkey).map_err(|e| {
            CliError::cli_other_error(format!("failed to load trusted kernel pubkey: {e}"))
        })?;
    let config = ComplianceConfig {
        budget_limit: 0,
        required_guards: Vec::new(),
        authorized_scopes: Vec::new(),
        expected_tenant_id: None,
        trusted_kernel_keys: BTreeSet::from([trusted_kernel_key.to_hex()]),
    };

    let result = verify_compliance_certificate(&cert, mode, receipts.as_deref(), &config);

    if json_output {
        let result_json = serde_json::to_string_pretty(&result)
            .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?;
        println!("{result_json}");
    } else if result.passed {
        println!("PASS: {}", result.summary);
    } else {
        println!("FAIL: {}", result.summary);
    }

    if !result.passed {
        std::process::exit(1);
    }

    Ok(())
}

/// `chio cert inspect` -- display certificate contents.
pub fn cmd_cert_inspect(certificate_path: &Path, json_output: bool) -> Result<(), CliError> {
    let cert_text = std::fs::read_to_string(certificate_path)
        .map_err(|e| CliError::cli_other_error(format!("failed to read certificate: {e}")))?;

    let cert: ComplianceCertificate = serde_json::from_str(&cert_text)
        .map_err(|e| CliError::cli_other_error(format!("failed to parse certificate: {e}")))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&cert.body)
                .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?
        );
    } else {
        println!("Session ID:     {}", cert.body.session_id);
        println!("Schema:         {}", cert.body.schema);
        println!("Issued at:      {}", cert.body.issued_at);
        println!("Receipt count:  {}", cert.body.receipt_count);
        println!("First receipt:  {}", cert.body.first_receipt_at);
        println!("Last receipt:   {}", cert.body.last_receipt_at);
        println!(
            "Signatures:     {}",
            if cert.body.all_signatures_valid {
                "valid"
            } else {
                "INVALID"
            }
        );
        println!(
            "Chain:          {}",
            if cert.body.chain_continuous {
                "continuous"
            } else {
                "BROKEN"
            }
        );
        println!(
            "Scope:          {}",
            if cert.body.scope_compliant {
                "compliant"
            } else {
                "VIOLATED"
            }
        );
        println!(
            "Budget:         {}",
            if cert.body.budget_compliant {
                "compliant"
            } else {
                "EXCEEDED"
            }
        );
        println!(
            "Guards:         {}",
            if cert.body.guards_compliant {
                "compliant"
            } else {
                "BYPASSED"
            }
        );
        if !cert.body.anomalies.is_empty() {
            println!("Anomalies:");
            for a in &cert.body.anomalies {
                println!("  - {a}");
            }
        }
        println!("Signer key:     {}", cert.signer_key.to_hex());
        println!("Kernel key:     {}", cert.body.kernel_key.to_hex());
    }

    Ok(())
}

/// Load Chio receipts for a given session from the SQLite receipt store.
///
/// This queries the `chio_receipts` table for receipts whose
/// `capability_id` starts with `acp-session:{session_id}`.
fn load_session_receipts(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Vec<ComplianceReceiptEntry>, CliError> {
    let table_exists: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chio_receipts'")
        .and_then(|mut stmt| stmt.exists([]))
        .unwrap_or(false);

    if !table_exists {
        return Ok(Vec::new());
    }

    let capability_prefix = format!("acp-session:{session_id}");
    let mut stmt = conn
        .prepare(
            "SELECT rowid, json_data FROM chio_receipts WHERE capability_id LIKE ?1 ORDER BY rowid",
        )
        .map_err(|e| CliError::cli_other_error(format!("SQL prepare failed: {e}")))?;

    let rows = stmt
        .query_map([format!("{capability_prefix}%")], |row| {
            let seq: i64 = row.get(0)?;
            let json_data: String = row.get(1)?;
            Ok((seq as u64, json_data))
        })
        .map_err(|e| CliError::cli_other_error(format!("SQL query failed: {e}")))?;

    let mut entries = Vec::new();
    for row in rows {
        let (seq, json_data) =
            row.map_err(|e| CliError::cli_other_error(format!("row read failed: {e}")))?;
        let receipt: chio_core::receipt::body::ChioReceipt = serde_json::from_str(&json_data)
            .map_err(|e| CliError::cli_other_error(format!("receipt parse failed: {e}")))?;
        entries.push(ComplianceReceiptEntry { receipt, seq });
    }

    Ok(entries)
}
