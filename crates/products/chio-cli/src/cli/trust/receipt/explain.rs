use super::*;

pub(crate) struct ReceiptExplainArgs<'a> {
    pub(crate) receipt_id: &'a str,
    pub(crate) input_file: Option<&'a Path>,
    pub(crate) depth: usize,
    pub(crate) fanout_limit: usize,
    /// Inspect-only: the CLI does not carry the org A / org B passport
    /// public keys and cannot perform real Ed25519 verification, so the
    /// trace reports structural / schema checks only. The compatibility CLI flag
    /// spelling is preserved as a `clap` alias on the parent enum.
    pub(crate) inspect_bilateral: bool,
    pub(crate) tenant: Option<&'a str>,
    pub(crate) admin_all: bool,
}

pub(crate) fn cmd_receipt_explain(
    args: ReceiptExplainArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    let value = if let Some(input_file) = args.input_file {
        serde_json::from_slice::<serde_json::Value>(&fs::read(input_file)?)?
    } else {
        load_receipt_for_explain(args.receipt_id, args.tenant, args.admin_all, &backend)?
    };
    if is_bilateral_artifacts_value(&value) {
        return render_bilateral_explain(&value, &args, &backend);
    }
    let report = explain_receipt_value(args.receipt_id, value, args.depth, args.fanout_limit)?;
    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("receipt: {}", report["receipt_id"].as_str().unwrap_or(args.receipt_id));
        println!("schema: {}", report["schema"].as_str().unwrap_or("unknown"));
        println!("identity: {}", report["identity"].as_str().unwrap_or("unknown"));
        println!("decision: {}", report["decision"].as_str().unwrap_or("unknown"));
        if let Some(reason) = report.get("reason").and_then(|value| value.as_str()) {
            println!("reason: {reason}");
        }
        if let Some(guard) = report.get("guard").and_then(|value| value.as_str()) {
            println!("guard: {guard}");
        }
        if let Some(policy_hash) = report.get("policy_hash").and_then(|value| value.as_str()) {
            println!("policy_hash: {policy_hash}");
        }
        if let Some(scope) = report.get("scope_diff").and_then(|value| value.as_str()) {
            println!("scope_diff: {scope}");
        }
        if let Some(parents) = report.get("parents").and_then(|value| value.as_array()) {
            println!("parents: {}", parents.len());
            for parent in parents.iter().take(args.fanout_limit) {
                if let Some(parent) = parent.as_str() {
                    println!("  {parent}");
                }
            }
        }
        if let Some(witness) = report.get("batch_witness").and_then(|value| value.as_str()) {
            println!("batch_witness: {witness}");
        }
        if let Some(hint) = report.get("repair_hint").and_then(|value| value.as_str()) {
            println!("repair_hint: {hint}");
        }
    }
    Ok(())
}


pub(crate) fn is_bilateral_artifacts_value(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    let has_dual = obj.contains_key("dual_signed_receipt") || obj.contains_key("dualSignedReceipt");
    let has_dsse = obj.contains_key("dsse_envelope") || obj.contains_key("dsseEnvelope");
    has_dual && has_dsse
}

pub(crate) fn bilateral_field<'a>(
    value: &'a serde_json::Value,
    snake: &str,
    camel: &str,
) -> Option<&'a serde_json::Value> {
    value.get(snake).or_else(|| value.get(camel))
}

pub(crate) fn render_bilateral_explain(
    value: &serde_json::Value,
    args: &ReceiptExplainArgs<'_>,
    backend: &QueryBackend<'_>,
) -> Result<(), CliError> {
    let dual = bilateral_field(value, "dual_signed_receipt", "dualSignedReceipt").ok_or_else(
        || {
            CliError::cli_other_error(
                "bilateral artifact missing dual_signed_receipt section".to_string(),
            )
        },
    )?;
    let dsse = bilateral_field(value, "dsse_envelope", "dsseEnvelope").ok_or_else(|| {
        CliError::cli_other_error(
            "bilateral artifact missing dsse_envelope section".to_string(),
        )
    })?;

    let dual_section = explain_dual_signed_receipt(dual)?;
    let dsse_section = explain_dsse_envelope(dsse)?;
    // Emit a structural inspection trace, not a "verifier trace".
    // The CLI does not have org A / org B passport public keys in
    // scope and cannot perform real Ed25519 verification.
    let trace_section = if args.inspect_bilateral {
        Some(inspect_bilateral_envelope_trace(dual, dsse)?)
    } else {
        None
    };

    let report = serde_json::json!({
        "schema": "chio.cli.receipt-explain.bilateral.v1",
        "shape": "BilateralCoSignArtifacts",
        "dual_signed_receipt": dual_section,
        "dsse_envelope": dsse_section,
        "bilateral_inspection_trace": trace_section,
    });

    if backend.json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Pretty-print: boxed sections.
    print_bilateral_human(&report, args.inspect_bilateral);
    Ok(())
}

pub(crate) fn explain_dual_signed_receipt(
    dual: &serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    let body = dual.get("body").cloned().unwrap_or(serde_json::Value::Null);
    let receipt_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let org_a = dual
        .get("org_a_kernel_id")
        .or_else(|| dual.get("orgAKernelId"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let org_b = dual
        .get("org_b_kernel_id")
        .or_else(|| dual.get("orgBKernelId"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let org_a_sig = dual
        .get("org_a_signature")
        .or_else(|| dual.get("orgASignature"))
        .cloned();
    let org_b_sig = dual
        .get("org_b_signature")
        .or_else(|| dual.get("orgBSignature"))
        .cloned();
    let schema = dual
        .get("schema")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    Ok(serde_json::json!({
        "schema": schema,
        "receipt_id": receipt_id,
        "org_a_kernel_id": org_a,
        "org_b_kernel_id": org_b,
        "org_a_signature": org_a_sig,
        "org_b_signature": org_b_sig,
        "non_section6_disclaimer": "DualSignedReceipt signs canonical JSON of CoSigningBody, not the DSSE PAE preimage required by section 6. This section is NOT section-6 conformant. For section-6 conformance use the dsse_envelope section.",
    }))
}

pub(crate) fn explain_dsse_envelope(dsse: &serde_json::Value) -> Result<serde_json::Value, CliError> {
    // DsseEnvelope is `serde(rename_all = "camelCase")` so wire keys are
    // camelCase: `payloadType`, `payload`, `signatures`, optional `schema`.
    let payload_type = dsse
        .get("payloadType")
        .or_else(|| dsse.get("payload_type"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let payload_hex = payload_b64
        .as_deref()
        .and_then(|p| {
            use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
            use base64::Engine;
            BASE64_STANDARD.decode(p.as_bytes()).ok()
        })
        .map(hex::encode);
    let signatures = dsse
        .get("signatures")
        .and_then(|v| v.as_array())
        .map(|sigs| {
            sigs.iter()
                .map(|s| {
                    serde_json::json!({
                        "keyid": s.get("keyid").and_then(|v| v.as_str()),
                        "sig": s.get("sig").and_then(|v| v.as_str()),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let schema = dsse
        .get("schema")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    Ok(serde_json::json!({
        "schema": schema,
        "payload_type": payload_type,
        "payload_b64": payload_b64,
        "payload_hex": payload_hex,
        "signatures": signatures,
        "section6_conformance_note": "This is the DSSE signature-slice API artifact. The signatures cover Ed25519(pae(payloadType, base64_decode(payload))), but the predicate is not the strict treaty-bound bilateral invocation schema.",
    }))
}

/// Produces an INSPECTION trace (structural / schema /
/// fingerprint-presence checks only); the CLI does not have the org A /
/// org B passport public keys in scope and cannot perform real Ed25519
/// verification, and the emitted JSON labels itself accordingly. Real
/// verification belongs in
/// `chio_federation::bilateral_dsse::verify_dsse_envelope` against
/// pinned passport keys.
pub(crate) fn inspect_bilateral_envelope_trace(
    dual: &serde_json::Value,
    dsse: &serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    use chio_federation::bilateral_dsse;

    let mut steps: Vec<serde_json::Value> = Vec::with_capacity(17);
    let mut step = |idx: u8, name: &str, status: &str, note: &str| {
        steps.push(serde_json::json!({
            "step": idx,
            "name": name,
            "status": status,
            "note": note,
        }));
    };

    // Step 1: receipt body present in dual artifact (subject anchor).
    let body = dual.get("body");
    if body.is_none() {
        step(
            1,
            "receipt_body_present",
            "fail",
            "dual_signed_receipt.body missing",
        );
    } else {
        step(
            1,
            "receipt_body_present",
            "ok",
            "dual_signed_receipt.body parsed",
        );
    }

    // Step 2: payloadType binding.
    let payload_type = dsse
        .get("payloadType")
        .or_else(|| dsse.get("payload_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if payload_type == bilateral_dsse::PAYLOAD_TYPE_IN_TOTO {
        step(
            2,
            "payload_type_binding",
            "ok",
            "payloadType == application/vnd.in-toto+json",
        );
    } else {
        step(
            2,
            "payload_type_binding",
            "fail",
            "payloadType does not bind to in-toto",
        );
    }

    // Step 3: payload base64 decodes.
    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let payload_bytes = {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine;
        BASE64_STANDARD.decode(payload_b64.as_bytes()).ok()
    };
    if payload_bytes.is_some() {
        step(
            3,
            "payload_base64_decodable",
            "ok",
            "payload bytes recovered",
        );
    } else {
        step(
            3,
            "payload_base64_decodable",
            "fail",
            "payload base64 decode failed",
        );
    }

    // Step 4: predicateType is the chio bilateral or its in-toto.io alias.
    let stmt_value: Option<serde_json::Value> = payload_bytes
        .as_ref()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());
    let predicate_type = stmt_value
        .as_ref()
        .and_then(|s| s.get("predicateType"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if predicate_type == bilateral_dsse::PREDICATE_TYPE_BILATERAL
        || predicate_type == "https://in-toto.io/attestation/bilateral-cosign-invocation/v1"
    {
        step(
            4,
            "predicate_type_recognised",
            "ok",
            predicate_type,
        );
    } else {
        step(
            4,
            "predicate_type_recognised",
            "fail",
            "predicateType not recognised",
        );
    }

    // Step 5: statement _type is in-toto v1.
    let stmt_type = stmt_value
        .as_ref()
        .and_then(|s| s.get("_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if stmt_type == bilateral_dsse::STATEMENT_TYPE_V1 {
        step(5, "statement_type_v1", "ok", stmt_type);
    } else {
        step(
            5,
            "statement_type_v1",
            "fail",
            "_type does not bind to in-toto Statement v1",
        );
    }

    // Step 6: subject array length == 1.
    let subjects_len = stmt_value
        .as_ref()
        .and_then(|s| s.get("subject"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if subjects_len == 1 {
        step(6, "subject_arity_one", "ok", "exactly one subject");
    } else {
        step(
            6,
            "subject_arity_one",
            "fail",
            "envelopes carry exactly one subject",
        );
    }

    // Step 7: subject digest == sha256(canonical_json(receipt)). We bound
    // this: with only the deserialised `body` JSON value we cannot
    // reliably re-canonicalise without a `ChioReceipt` round-trip; we
    // perform a best-effort canonical re-encoding via canonical_json on
    // the body subtree.
    let claimed_digest = stmt_value
        .as_ref()
        .and_then(|s| s.get("subject"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|s0| s0.get("digest"))
        .and_then(|d| d.get("sha256"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    if claimed_digest.is_some() {
        step(
            7,
            "subject_digest_present",
            "bounded",
            "receipt-explain renders the claimed digest; full re-canonicalisation against the underlying ChioReceipt is deferred to the in-process verifier",
        );
    } else {
        step(
            7,
            "subject_digest_present",
            "fail",
            "subject[0].digest.sha256 missing",
        );
    }

    // Step 8: signature count == 2.
    let sigs = dsse
        .get("signatures")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if sigs.len() == 2 {
        step(8, "signature_count_two", "ok", "exactly two signatures");
    } else {
        step(
            8,
            "signature_count_two",
            "fail",
            "envelopes MUST carry exactly two signatures",
        );
    }

    // Step 9: each signature has keyid + sig.
    let well_formed = sigs.iter().all(|s| {
        s.get("keyid").and_then(|v| v.as_str()).is_some()
            && s.get("sig").and_then(|v| v.as_str()).is_some()
    });
    if well_formed {
        step(
            9,
            "signature_fields_present",
            "ok",
            "every signature has keyid + sig",
        );
    } else {
        step(
            9,
            "signature_fields_present",
            "fail",
            "at least one signature lacks keyid or sig",
        );
    }

    // Step 10: keyids match the predicate's tool_server fingerprints.
    let predicate = stmt_value
        .as_ref()
        .and_then(|s| s.get("predicate"));
    let fp_a = predicate
        .and_then(|p| p.get("tool_server_a"))
        .and_then(|s| s.get("passport_key_fingerprint"))
        .and_then(|v| v.as_str());
    let fp_b = predicate
        .and_then(|p| p.get("tool_server_b"))
        .and_then(|s| s.get("passport_key_fingerprint"))
        .and_then(|v| v.as_str());
    let sig_keyids: std::collections::HashSet<&str> = sigs
        .iter()
        .filter_map(|s| s.get("keyid").and_then(|v| v.as_str()))
        .collect();
    let keyid_a_present = fp_a.map(|f| sig_keyids.contains(f)).unwrap_or(false);
    let keyid_b_present = fp_b.map(|f| sig_keyids.contains(f)).unwrap_or(false);
    if keyid_a_present && keyid_b_present {
        step(
            10,
            "keyids_match_predicate_fingerprints",
            "ok",
            "both tool_server fingerprints present in signatures",
        );
    } else {
        step(
            10,
            "keyids_match_predicate_fingerprints",
            "fail",
            "at least one keyid is unbound to a predicate.tool_server_*",
        );
    }

    // Step 11: cryptographic verification of org A signature.
    // Step 12: cryptographic verification of org B signature.
    // The CLI does not have the passport public keys in scope. The
    // signatures are NOT verified here. The honest label is
    // `not-verified`; operators that need real verification must route
    // the envelope through
    // `chio_federation::bilateral_dsse::verify_dsse_envelope` with
    // pinned passport keys.
    step(
        11,
        "ed25519_verify_org_a_pae",
        "not-verified",
        "CLI does not carry Org A passport public key; signature is NOT cryptographically verified by this inspect output",
    );
    step(
        12,
        "ed25519_verify_org_b_pae",
        "not-verified",
        "CLI does not carry Org B passport public key; signature is NOT cryptographically verified by this inspect output",
    );

    // Step 13: predicate body schema discriminator. The
    // BilateralPredicate struct serialises `schema: String` as the
    // body's discriminator (distinct from the parent Statement's
    // `predicateType`); the upstream is `serde(rename_all =
    // "snake_case")` so on the wire this is `schema`.
    let pred_schema = predicate
        .and_then(|p| p.get("schema").or_else(|| p.get("_type")))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if pred_schema == bilateral_dsse::PREDICATE_BODY_SCHEMA {
        step(
            13,
            "predicate_body_schema",
            "ok",
            "predicate.schema matches chio.bilateral-cosign.signature-slice.v1",
        );
    } else {
        step(
            13,
            "predicate_body_schema",
            "fail",
            "predicate.schema does not match the chio bilateral schema",
        );
    }

    step(
        14,
        "capability_lease_resolution",
        "bounded",
        "deferred (out of scope here; CLI verifier does not resolve this step)",
    );

    step(
        15,
        "governance_receipt_resolution",
        "bounded",
        "deferred (out of scope here; CLI verifier does not resolve this step)",
    );

    step(
        16,
        "consistency_anchor_reconciliation",
        "bounded",
        "deferred (out of scope here; CLI verifier does not resolve this step)",
    );

    step(
        17,
        "peer_pin_revocation_freshness",
        "bounded",
        "this CLI does not carry a revocation oracle handle; route to the kernel-resident verifier for steps 7-9",
    );

    Ok(serde_json::json!({
        "spec": "treaty-bound bilateral invocation profile section 7",
        "trace_kind": "inspection",
        "verification_performed": false,
        "scope_note": "ok = locally verifiable structural check, not-verified = no cryptographic verification (use bilateral_dsse::verify_dsse_envelope), bounded = step deferred to kernel-resident verifier, fail = local structural check failed",
        "honesty_note": "This is an INSPECTION trace, not a verifier trace. Ed25519 signatures are NOT verified here; this trace is informational only. For cryptographic verification, pin org A / org B passport keys and call bilateral_dsse::verify_dsse_envelope or the kernel-resident bilateral verifier.",
        "steps": steps,
    }))
}

pub(crate) fn print_bilateral_human(report: &serde_json::Value, with_trace: bool) {
    println!("=== bilateral co-sign artifacts ===");
    println!("schema: {}", report["schema"].as_str().unwrap_or("?"));
    println!("shape:  {}", report["shape"].as_str().unwrap_or("?"));
    println!();

    println!("--- DualSignedReceipt (NON-SECTION-6-CONFORMANT) ---");
    let dual = &report["dual_signed_receipt"];
    println!(
        "  receipt_id:       {}",
        dual["receipt_id"].as_str().unwrap_or("?")
    );
    println!(
        "  schema:           {}",
        dual["schema"].as_str().unwrap_or("?")
    );
    println!(
        "  org_a_kernel_id:  {}",
        dual["org_a_kernel_id"].as_str().unwrap_or("?")
    );
    println!(
        "  org_b_kernel_id:  {}",
        dual["org_b_kernel_id"].as_str().unwrap_or("?")
    );
    println!(
        "  disclaimer:       {}",
        dual["non_section6_disclaimer"].as_str().unwrap_or("?")
    );
    println!();

    println!("--- DSSE envelope (signature-slice API artifact) ---");
    let dsse = &report["dsse_envelope"];
    println!(
        "  schema:        {}",
        dsse["schema"].as_str().unwrap_or("?")
    );
    println!(
        "  payload_type:  {}",
        dsse["payload_type"].as_str().unwrap_or("?")
    );
    let payload_hex = dsse["payload_hex"].as_str().unwrap_or("");
    if payload_hex.len() > 96 {
        println!("  payload_hex:   {}... ({} bytes)", &payload_hex[..96], payload_hex.len() / 2);
    } else {
        println!("  payload_hex:   {}", payload_hex);
    }
    if let Some(sigs) = dsse["signatures"].as_array() {
        println!("  signatures:");
        for sig in sigs {
            println!(
                "    - keyid: {}",
                sig["keyid"].as_str().unwrap_or("?")
            );
            let s = sig["sig"].as_str().unwrap_or("");
            if s.len() > 32 {
                println!("      sig:   {}... ({} chars)", &s[..32], s.len());
            } else {
                println!("      sig:   {}", s);
            }
        }
    }
    println!(
        "  conformance:   {}",
        dsse["section6_conformance_note"].as_str().unwrap_or("?")
    );
    println!();

    if with_trace {
        if let Some(trace) = report.get("bilateral_inspection_trace") {
            println!("--- bilateral envelope inspection trace ---");
            println!(
                "  WARNING: this is an inspection trace, not a verifier trace."
            );
            println!(
                "  Ed25519 signatures are NOT cryptographically verified here."
            );
            println!(
                "  spec: {}",
                trace["spec"].as_str().unwrap_or("?")
            );
            println!(
                "  scope: {}",
                trace["scope_note"].as_str().unwrap_or("?")
            );
            if let Some(steps) = trace["steps"].as_array() {
                for entry in steps {
                    let idx = entry["step"].as_u64().unwrap_or(0);
                    let name = entry["name"].as_str().unwrap_or("?");
                    let status = entry["status"].as_str().unwrap_or("?");
                    let note = entry["note"].as_str().unwrap_or("");
                    println!("  [{:>2}] {:<38} {:<8} {}", idx, name, status, note);
                }
            }
        }
    }
}

pub(crate) fn load_receipt_for_explain(
    receipt_id: &str,
    tenant: Option<&str>,
    admin_all: bool,
    backend: &QueryBackend<'_>,
) -> Result<serde_json::Value, CliError> {
    const RECEIPT_EXPLAIN_PAGE_LIMIT: usize = 1000;

    if let Some(url) = backend.control_url {
        if tenant.is_some() || admin_all {
            return Err(CliError::cli_other_error(
                "receipt explain read-boundary flags apply to local --receipt-db; remote reads derive scope from the control token"
                    .to_string(),
            ));
        }
        let token = require_control_token(backend.control_token)?;
        let client = trust_control::service_runtime::client::build_client(url, token)?;
        let mut cursor = None;
        let mut matches = Vec::new();
        loop {
            let query = trust_control::ReceiptQueryHttpQuery {
                capability_id: None,
                tool_server: None,
                tool_name: None,
                outcome: None,
                since: None,
                until: None,
                min_cost: None,
                max_cost: None,
                cost_currency: None,
                cursor,
                limit: Some(RECEIPT_EXPLAIN_PAGE_LIMIT),
                agent_subject: None,
            };
            let response = client.query_receipts(&query)?;
            push_receipt_explain_matches(receipt_id, response.receipts, &mut matches)?;
            match response.next_cursor {
                Some(next_cursor) => {
                    if cursor == Some(next_cursor) {
                        return Err(CliError::cli_other_error(
                            "control plane receipt query returned a non-advancing cursor"
                                .to_string(),
                        ));
                    }
                    cursor = Some(next_cursor);
                }
                None => break,
            }
        }
        return finish_receipt_for_explain(
            receipt_id,
            matches,
            "control plane receipt query",
        );
    }
    let path = backend.receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "receipt explain requires --input-file, --receipt-db, or --control-url".to_string(),
        )
    })?;
    if !path.is_file() {
        return Err(CliError::cli_other_error(format!(
            "receipt explain requires an existing --receipt-db <path>: {}",
            path.display()
        )));
    }
    let read_context = local_receipt_read_context(tenant, admin_all)?;
    let store = chio_store_sqlite::SqliteReceiptStore::open_existing(path)?;
    let mut cursor = None;
    let mut matches = Vec::new();
    loop {
        let result = store.query_receipts(&chio_kernel::ReceiptQuery {
            capability_id: None,
            tool_server: None,
            tool_name: None,
            outcome: None,
            since: None,
            until: None,
            min_cost: None,
            max_cost: None,
            cost_currency: None,
            cursor,
            limit: RECEIPT_EXPLAIN_PAGE_LIMIT,
            agent_subject: None,
            tenant_filter: tenant.map(ToOwned::to_owned),
            read_context: Some(read_context.clone()),
        })?;
        let receipts = result
            .receipts
            .into_iter()
            .map(|stored| serde_json::to_value(stored.receipt))
            .collect::<Result<Vec<_>, _>>()?;
        push_receipt_explain_matches(receipt_id, receipts, &mut matches)?;
        match result.next_cursor {
            Some(next_cursor) => {
                if cursor == Some(next_cursor) {
                    return Err(CliError::cli_other_error(
                        "local receipt store returned a non-advancing cursor".to_string(),
                    ));
                }
                cursor = Some(next_cursor);
            }
            None => break,
        }
    }
    finish_receipt_for_explain(receipt_id, matches, "local receipt store")
}

#[cfg(test)]
pub(crate) fn select_receipt_for_explain(
    receipt_id: &str,
    receipts: Vec<serde_json::Value>,
    source: &str,
) -> Result<serde_json::Value, CliError> {
    let mut matches = Vec::new();
    push_receipt_explain_matches(receipt_id, receipts, &mut matches)?;
    finish_receipt_for_explain(receipt_id, matches, source)
}

pub(crate) fn push_receipt_explain_matches(
    receipt_id: &str,
    receipts: Vec<serde_json::Value>,
    matches: &mut Vec<serde_json::Value>,
) -> Result<(), CliError> {
    for receipt in receipts {
        if receipt_value_matches_id(&receipt, receipt_id) {
            matches.push(receipt);
            if matches.len() > 1 {
                return Err(CliError::cli_other_error(format!(
                    "receipt ID prefix `{receipt_id}` is ambiguous"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn finish_receipt_for_explain(
    receipt_id: &str,
    mut matches: Vec<serde_json::Value>,
    source: &str,
) -> Result<serde_json::Value, CliError> {
    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    Err(CliError::cli_other_error(format!(
        "receipt `{receipt_id}` not found in paginated receipt rows from {source}"
    )))
}

pub(crate) fn receipt_value_matches_id(value: &serde_json::Value, receipt_id: &str) -> bool {
    let candidate_paths = [
        ["id"].as_slice(),
        ["receipt_id"].as_slice(),
        ["receiptId"].as_slice(),
        ["receipt", "id"].as_slice(),
        ["receipt", "receipt_id"].as_slice(),
        ["receipt", "receiptId"].as_slice(),
    ];
    candidate_paths
        .iter()
        .filter_map(|path| json_path_str(value, path))
        .any(|candidate| candidate == receipt_id)
}

pub(crate) fn json_path_str<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

pub(crate) fn explain_receipt_value(
    requested_id: &str,
    value: serde_json::Value,
    depth: usize,
    fanout_limit: usize,
) -> Result<serde_json::Value, CliError> {
    let receipt: chio_core::receipt::body::ChioReceipt = serde_json::from_value(value)?;
    let signature_ok = receipt.verify_signature()?;
    let receipt_id_ok = chio_core::receipt::body::chio_receipt_id(&receipt.body())? == receipt.id;
    let parameter_hash_ok = receipt.action.verify_hash()?;
    let decision = explain_decision_label(receipt.decision.as_ref());
    let semantics = receipt.semantic_fields();
    let semantic_authorized = semantics.is_authorized(receipt.decision.as_ref());
    let verified = signature_ok && receipt_id_ok && parameter_hash_ok;
    let result = if verified || !semantic_authorized {
        semantics.result_label(receipt.decision.as_ref())
    } else {
        "Unverified"
    };
    let authorized = verified && semantic_authorized;
    let receipt_kind = semantics.receipt_kind.as_str();
    let boundary_class = semantics.boundary_class.as_str();
    let observation_outcome = semantics
        .observation_outcome
        .map(|outcome| outcome.as_str());
    let tool_origin = semantics.tool_origin.as_str();
    let redaction_mode = semantics.redaction_mode.as_str();
    let (reason, guard) = decision_details(receipt.decision.as_ref());
    let parents = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("parent_receipt_ids"))
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .take(fanout_limit)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let batch_witness = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("batch_witness"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    Ok(serde_json::json!({
        "schema": "chio.receipt.v1",
        "receipt_id": receipt.id,
        "identity": receipt.id,
        "requested_id": requested_id,
        "signature_ok": signature_ok,
        "receipt_id_ok": receipt_id_ok,
        "parameter_hash_ok": parameter_hash_ok,
        "decision": decision,
        "receipt_kind": receipt_kind,
        "boundary_class": boundary_class,
        "observation_outcome": observation_outcome,
        "tool_origin": tool_origin,
        "redaction_mode": redaction_mode,
        "result": result,
        "authorized": authorized,
        "reason": reason,
        "guard": guard,
        "policy_hash": receipt.policy_hash,
        "guards": receipt.evidence,
        "scope_diff": "requested scope vs granted scope is not embedded in this receipt",
        "parents": parents,
        "depth_limit": depth,
        "fanout_limit": fanout_limit,
        "batch_witness": batch_witness,
        "repair_hint": repair_hint(receipt.decision.as_ref()),
    }))
}

pub(crate) fn explain_decision_label(decision: Option<&chio_core::receipt::decision::Decision>) -> &'static str {
    match decision {
        Some(chio_core::receipt::decision::Decision::Allow) => "allow",
        Some(chio_core::receipt::decision::Decision::Deny { .. }) => "deny",
        Some(chio_core::receipt::decision::Decision::Cancelled { .. }) => "cancelled",
        Some(chio_core::receipt::decision::Decision::Incomplete { .. }) => "incomplete",
        None => "none",
    }
}

pub(crate) fn decision_details(
    decision: Option<&chio_core::receipt::decision::Decision>,
) -> (Option<&str>, Option<&str>) {
    match decision {
        Some(chio_core::receipt::decision::Decision::Deny { reason, guard }) => {
            (Some(reason.as_str()), Some(guard.as_str()))
        }
        Some(chio_core::receipt::decision::Decision::Cancelled { reason })
        | Some(chio_core::receipt::decision::Decision::Incomplete { reason }) => {
            (Some(reason.as_str()), None)
        }
        Some(chio_core::receipt::decision::Decision::Allow) | None => (None, None),
    }
}

pub(crate) fn repair_hint(decision: Option<&chio_core::receipt::decision::Decision>) -> Option<&'static str> {
    match decision {
        Some(chio_core::receipt::decision::Decision::Deny { .. }) => {
            Some("inspect the guard and policy_hash, then mint or narrow a matching capability")
        }
        Some(chio_core::receipt::decision::Decision::Incomplete { .. }) => {
            Some("retry after checking the parent receipt and terminal operation state")
        }
        Some(chio_core::receipt::decision::Decision::Cancelled { .. }) => {
            Some("resume only if the caller still owns the request and session")
        }
        Some(chio_core::receipt::decision::Decision::Allow) | None => None,
    }
}

#[cfg(test)]
mod receipt_explain_tests {
    use super::*;

    fn signed_explain_receipt(
        decision: chio_core::receipt::decision::Decision,
        semantics: Option<chio_core::receipt::metadata::ReceiptSemanticFields>,
    ) -> chio_core::receipt::body::ChioReceipt {
        let keypair = Keypair::generate();
        let semantics = semantics
            .unwrap_or_else(chio_core::receipt::metadata::ReceiptSemanticFields::mediated_prevent);
        let decision =
            if semantics.receipt_kind == chio_core::receipt::kinds::ReceiptKind::MediatedDecision {
                Some(decision)
            } else {
                None
            };
        let trust_level =
            if semantics.receipt_kind == chio_core::receipt::kinds::ReceiptKind::MediatedDecision {
                chio_core::receipt::kinds::TrustLevel::Mediated
            } else {
                chio_core::receipt::kinds::TrustLevel::Verified
            };
        chio_core::receipt::body::ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: "ignored-before-content-id".to_string(),
                timestamp: 1,
                capability_id: "cap-explain".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                    serde_json::json!({}),
                )
                .unwrap_or_else(|error| panic!("valid tool action: {error}")),
                decision,
                receipt_kind: semantics.receipt_kind,
                boundary_class: semantics.boundary_class,
                observation_outcome: semantics.observation_outcome,
                tool_origin: semantics.tool_origin,
                redaction_mode: semantics.redaction_mode,
                actor_chain: semantics.actor_chain,
                content_hash: "content-explain".to_string(),
                policy_hash: "policy-explain".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level,
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .unwrap_or_else(|error| panic!("valid receipt: {error}"))
    }

    #[test]
    fn receipt_value_matches_flat_and_nested_ids() {
        let flat = serde_json::json!({
            "id": "receipt-compat",
            "decision": {"type": "allow"}
        });
        let nested = serde_json::json!({
            "receipt": {
                "id": "nested-receipt"
            }
        });

        assert!(receipt_value_matches_id(&flat, "receipt-compat"));
        assert!(receipt_value_matches_id(&nested, "nested-receipt"));
        assert!(!receipt_value_matches_id(&flat, "missing"));
    }

    #[test]
    fn select_receipt_for_explain_requires_one_match() -> Result<(), CliError> {
        let receipt = serde_json::json!({"id": "receipt-a"});
        let selected =
            select_receipt_for_explain("receipt-a", vec![receipt.clone()], "test source")?;
        assert_eq!(selected, receipt);

        let duplicate = select_receipt_for_explain(
            "receipt-a",
            vec![
                serde_json::json!({"id": "receipt-a"}),
                serde_json::json!({"receiptId": "receipt-a"}),
            ],
            "test source",
        );
        assert!(duplicate.is_err());

        let missing = select_receipt_for_explain(
            "missing",
            vec![serde_json::json!({"id": "receipt-a"})],
            "test source",
        );
        assert!(missing.is_err());

        Ok(())
    }

    #[test]
    fn receipt_explain_match_collection_spans_pages() -> Result<(), CliError> {
        let mut matches = Vec::new();
        push_receipt_explain_matches(
            "receipt-b",
            vec![serde_json::json!({"id": "receipt-a"})],
            &mut matches,
        )?;
        push_receipt_explain_matches(
            "receipt-b",
            vec![serde_json::json!({"id": "receipt-b"})],
            &mut matches,
        )?;

        let selected = finish_receipt_for_explain("receipt-b", matches, "test source")?;
        assert_eq!(selected["id"].as_str(), Some("receipt-b"));

        Ok(())
    }

    #[test]
    fn receipt_explain_reports_semantic_authorization_fields() -> Result<(), CliError> {
        let mediated =
            signed_explain_receipt(chio_core::receipt::decision::Decision::Allow, None);
        let mediated_explain = explain_receipt_value(
            &mediated.id,
            serde_json::to_value(&mediated)?,
            1,
            1,
        )?;
        assert_eq!(mediated_explain["receipt_kind"].as_str(), Some("mediated_decision"));
        assert_eq!(mediated_explain["boundary_class"].as_str(), Some("prevent"));
        assert_eq!(mediated_explain["result"].as_str(), Some("Authorized"));
        assert_eq!(mediated_explain["authorized"].as_bool(), Some(true));

        let trace = signed_explain_receipt(
            chio_core::receipt::decision::Decision::Incomplete {
                reason: "trace only".to_string(),
            },
            Some(chio_core::receipt::metadata::ReceiptSemanticFields::trace_detect_only()),
        );
        let trace_explain = explain_receipt_value(
            &trace.id,
            serde_json::to_value(&trace)?,
            1,
            1,
        )?;
        assert_eq!(trace_explain["receipt_kind"].as_str(), Some("trace_observation"));
        assert_eq!(trace_explain["boundary_class"].as_str(), Some("detect_only"));
        assert_eq!(trace_explain["result"].as_str(), Some("Observed"));
        assert_eq!(trace_explain["authorized"].as_bool(), Some(false));

        Ok(())
    }
}
