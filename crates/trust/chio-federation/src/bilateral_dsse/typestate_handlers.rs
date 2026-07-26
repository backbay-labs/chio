use super::*;

pub(crate) struct DraftedData<'a> {
    org_a_public_key: &'a PublicKey,
    org_b_keypair: &'a Keypair,
    org_b_public_key: PublicKey,
    org_a_keyid: Keyid,
    org_b_keyid: Keyid,
    org_a_kernel_id: &'a str,
    org_b_kernel_id: &'a str,
    statement_bytes: Vec<u8>,
    pae_bytes: Vec<u8>,
    cosigner: &'a dyn BilateralCoSigningProtocol,
}

pub(crate) struct HostSignedData<'a> {
    org_a_public_key: &'a PublicKey,
    org_b_public_key: PublicKey,
    org_a_keyid: Keyid,
    org_b_keyid: Keyid,
    statement_bytes: Vec<u8>,
    request: DsseCoSigningRequest,
    cosigner: &'a dyn BilateralCoSigningProtocol,
}

pub(crate) struct CosignedData<'a> {
    org_a_public_key: &'a PublicKey,
    org_b_public_key: PublicKey,
    org_a_keyid: Keyid,
    org_b_keyid: Keyid,
    statement_bytes: Vec<u8>,
    org_a_signature: Signature,
    org_b_signature: Signature,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn draft<'a>(
    receipt: &'a ChioReceipt,
    org_a_public_key: &'a PublicKey,
    org_b_keypair: &'a Keypair,
    org_a_kernel_id: &'a str,
    org_b_kernel_id: &'a str,
    tool_name: &'a str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
    cosigner: &'a dyn BilateralCoSigningProtocol,
) -> Result<DraftedData<'a>, BilateralCoSigningError> {
    let org_b_public_key = org_b_keypair.public_key();
    if org_a_public_key == &org_b_public_key {
        return Err(BilateralCoSigningError::CanonicalJson(
            "strict Chio requires independent Org A and Org B signer keys".to_string(),
        ));
    }
    let org_a_keyid = Keyid::from_public_key(org_a_public_key);
    let org_b_keyid = Keyid::from_public_key(&org_b_public_key);
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
    Ok(DraftedData {
        org_a_public_key,
        org_b_keypair,
        org_b_public_key,
        org_a_keyid,
        org_b_keyid,
        org_a_kernel_id,
        org_b_kernel_id,
        statement_bytes,
        pae_bytes,
        cosigner,
    })
}

pub(crate) fn sign_host(
    drafted: DraftedData<'_>,
) -> Result<HostSignedData<'_>, BilateralCoSigningError> {
    let backend = Ed25519Backend::new(drafted.org_b_keypair.clone());
    let org_b_signature = backend
        .sign_bytes(&drafted.pae_bytes)
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
    let request = DsseCoSigningRequest::new(
        drafted.org_a_kernel_id.to_string(),
        drafted.org_b_kernel_id.to_string(),
        drafted.pae_bytes,
        org_b_signature,
    );

    Ok(HostSignedData {
        org_a_public_key: drafted.org_a_public_key,
        org_b_public_key: drafted.org_b_public_key,
        org_a_keyid: drafted.org_a_keyid,
        org_b_keyid: drafted.org_b_keyid,
        statement_bytes: drafted.statement_bytes,
        request,
        cosigner: drafted.cosigner,
    })
}

pub(crate) fn request_cosignature(
    host_signed: HostSignedData<'_>,
) -> Result<CosignedData<'_>, BilateralCoSigningError> {
    let response = host_signed
        .cosigner
        .request_dsse_cosignature(&host_signed.request)?;
    if response.schema != crate::bilateral::BILATERAL_DSSE_COSIGNING_SCHEMA {
        return Err(BilateralCoSigningError::UnsupportedSchema(response.schema));
    }
    if !host_signed
        .org_a_public_key
        .verify(&host_signed.request.pae_bytes, &response.org_a_signature)
    {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }

    Ok(CosignedData {
        org_a_public_key: host_signed.org_a_public_key,
        org_b_public_key: host_signed.org_b_public_key,
        org_a_keyid: host_signed.org_a_keyid,
        org_b_keyid: host_signed.org_b_keyid,
        statement_bytes: host_signed.statement_bytes,
        org_a_signature: response.org_a_signature,
        org_b_signature: host_signed.request.org_b_signature,
    })
}

pub(crate) fn verify_envelope(
    cosigned: CosignedData<'_>,
) -> Result<DsseEnvelope, BilateralCoSigningError> {
    let envelope = DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: BASE64_STANDARD.encode(&cosigned.statement_bytes),
        signatures: vec![
            DsseSignature {
                keyid: cosigned.org_a_keyid.0,
                sig: BASE64_STANDARD.encode(cosigned.org_a_signature.to_bytes()),
            },
            DsseSignature {
                keyid: cosigned.org_b_keyid.0,
                sig: BASE64_STANDARD.encode(cosigned.org_b_signature.to_bytes()),
            },
        ],
    };
    verify_chio_bilateral_dsse_envelope(
        &envelope,
        cosigned.org_a_public_key,
        &cosigned.org_b_public_key,
    )?;
    Ok(envelope)
}
