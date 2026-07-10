use super::*;

pub fn sign_dsse_envelope(
    receipt: &ChioReceipt,
    org_a_keypair: &Keypair,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    sign_dsse_envelope_full(
        receipt,
        org_a_keypair,
        org_b_keypair,
        org_a_kernel_id,
        org_b_kernel_id,
        tool_name,
        timestamp_unix_ms,
        BilateralPredicateExtensions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_dsse_envelope_full(
    receipt: &ChioReceipt,
    org_a_keypair: &Keypair,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    let org_a_pub = org_a_keypair.public_key();
    let org_b_pub = org_b_keypair.public_key();
    let org_a_keyid = Keyid::from_public_key(&org_a_pub);
    let org_b_keyid = Keyid::from_public_key(&org_b_pub);
    if org_a_pub == org_b_pub || org_a_keyid == org_b_keyid {
        return Err(BilateralCoSigningError::CanonicalJson(
            "strict Chio requires independent Org A and Org B signer keys".to_string(),
        ));
    }

    let predicate = build_predicate_full(
        receipt,
        KernelIdentity {
            kernel_id: org_a_kernel_id.to_string(),
            passport_key_fingerprint: org_a_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        KernelIdentity {
            kernel_id: org_b_kernel_id.to_string(),
            passport_key_fingerprint: org_b_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        tool_name,
        timestamp_unix_ms,
        extensions,
    )?;

    let statement = build_statement(receipt, predicate)?;
    let statement_bytes = statement.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);

    let backend_a = Ed25519Backend::new(org_a_keypair.clone());
    let backend_b = Ed25519Backend::new(org_b_keypair.clone());
    let sig_a = backend_a
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
    let sig_b = backend_b
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;

    let envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: BASE64_STANDARD.encode(&statement_bytes),
        signatures: vec![
            DsseSignature {
                keyid: org_a_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_a.to_bytes()),
            },
            DsseSignature {
                keyid: org_b_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_b.to_bytes()),
            },
        ],
    };

    // Self-check: the envelope verifies under the same public keys we signed
    // with. Mirrors the self-check `co_sign_with_origin` performs on the
    // `DualSignedReceipt` so any subtle encoding drift is caught at
    // the producer.
    verify_dsse_envelope(&envelope, &org_a_pub, &org_b_pub)?;
    Ok(envelope)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_chio_bilateral_dsse_envelope(
    receipt: &ChioReceipt,
    org_a_keypair: &Keypair,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    let org_a_pub = org_a_keypair.public_key();
    let org_b_pub = org_b_keypair.public_key();
    let org_a_keyid = Keyid::from_public_key(&org_a_pub);
    let org_b_keyid = Keyid::from_public_key(&org_b_pub);

    let predicate = build_chio_bilateral_invocation_predicate(
        receipt,
        KernelIdentity {
            kernel_id: org_a_kernel_id.to_string(),
            passport_key_fingerprint: org_a_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        KernelIdentity {
            kernel_id: org_b_kernel_id.to_string(),
            passport_key_fingerprint: org_b_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        tool_name,
        timestamp_unix_ms,
        extensions,
    )?;

    let statement = build_chio_bilateral_invocation_statement(receipt, predicate)?;
    let statement_bytes = statement.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);

    let backend_a = Ed25519Backend::new(org_a_keypair.clone());
    let backend_b = Ed25519Backend::new(org_b_keypair.clone());
    let sig_a = backend_a
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
    let sig_b = backend_b
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;

    let envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: BASE64_STANDARD.encode(&statement_bytes),
        signatures: vec![
            DsseSignature {
                keyid: org_a_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_a.to_bytes()),
            },
            DsseSignature {
                keyid: org_b_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_b.to_bytes()),
            },
        ],
    };

    verify_chio_bilateral_dsse_envelope(&envelope, &org_a_pub, &org_b_pub)?;
    Ok(envelope)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_dsse_envelope_with_cosigner(
    receipt: &ChioReceipt,
    org_a_public_key: &PublicKey,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
    cosigner: &dyn BilateralCoSigningProtocol,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    let org_a_keyid = Keyid::from_public_key(org_a_public_key);
    let org_b_pub = org_b_keypair.public_key();
    let org_b_keyid = Keyid::from_public_key(&org_b_pub);

    let predicate = build_predicate_full(
        receipt,
        KernelIdentity {
            kernel_id: org_a_kernel_id.to_string(),
            passport_key_fingerprint: org_a_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        KernelIdentity {
            kernel_id: org_b_kernel_id.to_string(),
            passport_key_fingerprint: org_b_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        tool_name,
        timestamp_unix_ms,
        extensions,
    )?;

    let statement = build_statement(receipt, predicate)?;
    let statement_bytes = statement.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);

    let backend_b = Ed25519Backend::new(org_b_keypair.clone());
    let sig_b = backend_b
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
    let request = DsseCoSigningRequest::new(
        org_a_kernel_id.to_string(),
        org_b_kernel_id.to_string(),
        pae_bytes.clone(),
        sig_b.clone(),
    );
    let response = cosigner.request_dsse_cosignature(&request)?;
    if response.schema != crate::bilateral::BILATERAL_DSSE_COSIGNING_SCHEMA {
        return Err(BilateralCoSigningError::UnsupportedSchema(response.schema));
    }
    if !org_a_public_key.verify(&pae_bytes, &response.org_a_signature) {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }

    let envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: BASE64_STANDARD.encode(&statement_bytes),
        signatures: vec![
            DsseSignature {
                keyid: org_a_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(response.org_a_signature.to_bytes()),
            },
            DsseSignature {
                keyid: org_b_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_b.to_bytes()),
            },
        ],
    };

    verify_dsse_envelope(&envelope, org_a_public_key, &org_b_pub)?;
    Ok(envelope)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_chio_bilateral_dsse_envelope_with_cosigner(
    receipt: &ChioReceipt,
    org_a_public_key: &PublicKey,
    org_b_keypair: &Keypair,
    org_a_kernel_id: &str,
    org_b_kernel_id: &str,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
    cosigner: &dyn BilateralCoSigningProtocol,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    let org_a_keyid = Keyid::from_public_key(org_a_public_key);
    let org_b_pub = org_b_keypair.public_key();
    let org_b_keyid = Keyid::from_public_key(&org_b_pub);

    let predicate = build_chio_bilateral_invocation_predicate(
        receipt,
        KernelIdentity {
            kernel_id: org_a_kernel_id.to_string(),
            passport_key_fingerprint: org_a_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        KernelIdentity {
            kernel_id: org_b_kernel_id.to_string(),
            passport_key_fingerprint: org_b_keyid.clone(),
            alg: "ed25519".to_string(),
        },
        tool_name,
        timestamp_unix_ms,
        extensions,
    )?;

    let statement = build_chio_bilateral_invocation_statement(receipt, predicate)?;
    let statement_bytes = statement.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);

    let backend_b = Ed25519Backend::new(org_b_keypair.clone());
    let sig_b = backend_b
        .sign_bytes(&pae_bytes)
        .map_err(|e| BilateralCoSigningError::TransportFailure(e.to_string()))?;
    let request = DsseCoSigningRequest::new(
        org_a_kernel_id.to_string(),
        org_b_kernel_id.to_string(),
        pae_bytes.clone(),
        sig_b.clone(),
    );
    let response = cosigner.request_dsse_cosignature(&request)?;
    if response.schema != crate::bilateral::BILATERAL_DSSE_COSIGNING_SCHEMA {
        return Err(BilateralCoSigningError::UnsupportedSchema(response.schema));
    }
    if !org_a_public_key.verify(&pae_bytes, &response.org_a_signature) {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }

    let envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: BASE64_STANDARD.encode(&statement_bytes),
        signatures: vec![
            DsseSignature {
                keyid: org_a_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(response.org_a_signature.to_bytes()),
            },
            DsseSignature {
                keyid: org_b_keyid.0.clone(),
                sig: BASE64_STANDARD.encode(sig_b.to_bytes()),
            },
        ],
    };

    verify_chio_bilateral_dsse_envelope(&envelope, org_a_public_key, &org_b_pub)?;
    Ok(envelope)
}
