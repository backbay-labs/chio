use super::*;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use p384::ecdsa::signature::Signer as _;
use p384::ecdsa::SigningKey as P384SigningKey;
use p384::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair as RcgenKeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::rand_core::OsRng;
use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
use rsa::traits::PublicKeyParts;
use serde_json::json;

use chio_test_support::prelude::*;

fn sign_rs256_jwt(private_key: &rsa::RsaPrivateKey, header: Value, claims: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).test_unwrap());
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).test_unwrap());
    let signed_input = format!("{header}.{payload}");
    let signature = RsaPkcs1v15SigningKey::<Sha256>::new(private_key.clone())
        .sign_with_rng(&mut OsRng, signed_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signature.to_vec());
    format!("{signed_input}.{signature}")
}

fn rsa_jwk_set(private_key: &rsa::RsaPrivateKey, kid: &str) -> AzureMaaJwks {
    let public_key = private_key.to_public_key();
    AzureMaaJwks {
        keys: vec![AzureMaaJwk {
            kty: "RSA".to_string(),
            kid: Some(kid.to_string()),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            n: Some(URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be())),
            e: Some(URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())),
            x5c: Vec::new(),
        }],
    }
}

struct AwsNitroTestMaterials {
    root_pem: String,
    leaf_der: Vec<u8>,
    leaf_signing_key: P384SigningKey,
}

fn generate_aws_nitro_test_materials() -> AwsNitroTestMaterials {
    let mut root_params = CertificateParams::new(Vec::<String>::new()).test_unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Chio Nitro Root");
    let root_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).test_unwrap();
    let root_cert = root_params.self_signed(&root_key).test_unwrap();

    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).test_unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Chio Nitro Leaf");
    leaf_params.is_ca = IsCa::NoCa;
    let leaf_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).test_unwrap();
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &root_cert, &root_key)
        .test_unwrap();

    AwsNitroTestMaterials {
        root_pem: root_cert.pem(),
        leaf_der: leaf_cert.der().to_vec(),
        leaf_signing_key: P384SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).test_unwrap(),
    }
}

fn build_aws_nitro_attestation_document(
    materials: &AwsNitroTestMaterials,
    timestamp_ms: u64,
    pcrs: BTreeMap<u8, Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> Vec<u8> {
    let payload = CborValue::Map(vec![
        (
            CborValue::Text("module_id".to_string()),
            CborValue::Text("i-arcnitro123".to_string()),
        ),
        (
            CborValue::Text("timestamp".to_string()),
            CborValue::Integer(timestamp_ms.into()),
        ),
        (
            CborValue::Text("digest".to_string()),
            CborValue::Text("SHA384".to_string()),
        ),
        (
            CborValue::Text("pcrs".to_string()),
            CborValue::Map(
                pcrs.iter()
                    .map(|(index, value)| {
                        (
                            CborValue::Integer((*index).into()),
                            CborValue::Bytes(value.clone()),
                        )
                    })
                    .collect(),
            ),
        ),
        (
            CborValue::Text("certificate".to_string()),
            CborValue::Bytes(materials.leaf_der.clone()),
        ),
        (
            CborValue::Text("cabundle".to_string()),
            CborValue::Array(Vec::new()),
        ),
        (
            CborValue::Text("public_key".to_string()),
            CborValue::Bytes(vec![1, 2, 3, 4]),
        ),
        (
            CborValue::Text("user_data".to_string()),
            CborValue::Bytes(vec![9, 9, 9]),
        ),
        (
            CborValue::Text("nonce".to_string()),
            CborValue::Bytes(nonce.unwrap_or_else(|| vec![0xAA, 0xBB])),
        ),
    ]);
    let mut payload_bytes = Vec::new();
    cbor_into_writer(&payload, &mut payload_bytes).test_unwrap();

    let protected = CborValue::Map(vec![(
        CborValue::Integer(COSE_HEADER_ALGORITHM_KEY.into()),
        CborValue::Integer(COSE_ES384_ALGORITHM.into()),
    )]);
    let mut protected_bytes = Vec::new();
    cbor_into_writer(&protected, &mut protected_bytes).test_unwrap();

    let sig_structure =
        build_cose_sign1_sig_structure(&protected_bytes, &payload_bytes).test_unwrap();
    let signature: P384Signature = materials.leaf_signing_key.sign(&sig_structure);
    let signature = signature.to_bytes().to_vec();

    let sign1 = CborValue::Array(vec![
        CborValue::Bytes(protected_bytes),
        CborValue::Map(Vec::new()),
        CborValue::Bytes(payload_bytes),
        CborValue::Bytes(signature),
    ]);
    let mut bytes = Vec::new();
    cbor_into_writer(&sign1, &mut bytes).test_unwrap();
    bytes
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_secs()
}

fn serve_json_once(body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
    let address = listener.local_addr().test_unwrap();
    let body = body.to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().test_unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request);
        let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        stream.write_all(response.as_bytes()).test_unwrap();
    });
    format!("http://{address}")
}

fn closed_local_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
    let address = listener.local_addr().test_unwrap();
    drop(listener);
    format!("http://{address}")
}

fn sample_enterprise_evidence(now: u64) -> RuntimeAttestationEvidence {
    RuntimeAttestationEvidence {
        schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
        verifier: "https://attest.contoso.example".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(30),
        expires_at: now.saturating_add(300),
        evidence_sha256: "sha256-enterprise-attestation".to_string(),
        runtime_identity: Some("spiffe://chio.example/workloads/enterprise".to_string()),
        workload_identity: Some(
            WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/enterprise")
                .test_unwrap(),
        ),
        claims: Some(json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_confidential_vm",
                "hardwareModel": "AMD_SEV_SNP",
                "secureBoot": "enabled",
                "digest": "sha384:enterprise-measurement",
                "pcrs": {
                    "0": "8f7f1be8"
                }
            }
        })),
    }
}

fn sample_aws_document(materials: &AwsNitroTestMaterials, now: u64) -> AwsNitroAttestationDocument {
    AwsNitroAttestationDocument {
        module_id: "i-arcnitro123".to_string(),
        timestamp: now.saturating_sub(10) * 1000,
        digest: "SHA384".to_string(),
        pcrs: BTreeMap::from([(0, vec![0x11; 48])]),
        certificate: materials.leaf_der.clone(),
        cabundle: Vec::new(),
        public_key: Some(vec![1, 2, 3, 4]),
        user_data: Some(vec![9, 9, 9]),
        nonce: Some(vec![0xCA, 0xFE]),
    }
}

#[test]
fn attestation_policy_validation_and_adapter_identity_helpers_cover_branch_guards() {
    let aws_policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec!["root-pem".to_string()],
        expected_pcrs: BTreeMap::new(),
        max_document_age_seconds: 60,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: None,
    };
    let aws_adapter = AwsNitroVerifierAdapter::new(aws_policy.clone()).test_unwrap();
    assert_eq!(
        default_aws_nitro_runtime_tier(),
        RuntimeAssuranceTier::Attested
    );
    assert_eq!(aws_adapter.adapter_name(), AWS_NITRO_VERIFIER_ADAPTER);
    assert_eq!(
        aws_adapter.verifier_family(),
        AttestationVerifierFamily::AwsNitro
    );
    assert!(matches!(
        AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: Vec::new(),
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AwsNitroVerificationPolicy {
            max_document_age_seconds: 0,
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AwsNitroVerificationPolicy {
            tier: RuntimeAssuranceTier::Verified,
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AwsNitroVerificationPolicy {
            trusted_root_certificates_pem: vec![" ".to_string()],
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AwsNitroVerificationPolicy {
            expected_pcrs: BTreeMap::from([(0, "zz".to_string())]),
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AwsNitroVerificationPolicy {
            expected_pcrs: BTreeMap::from([(0, "11".repeat(47))]),
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AwsNitroVerificationPolicy {
            expected_nonce_hex: Some("zz".to_string()),
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AwsNitroVerificationPolicy {
            expected_nonce_hex: Some(String::new()),
            ..aws_policy.clone()
        }
        .validate(),
        Err(AwsNitroVerificationError::InvalidPolicy(_))
    ));

    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let azure_policy = AzureMaaVerificationPolicy {
        issuer: "https://maa.contoso.test".to_string(),
        allowed_attestation_types: vec!["sgx".to_string()],
        tier: RuntimeAssuranceTier::Attested,
        workload_claim_path: None,
    };
    let azure_adapter =
        AzureMaaVerifierAdapter::new(azure_policy.clone(), rsa_jwk_set(&private_key, "maa-key"))
            .test_unwrap();
    assert_eq!(
        default_azure_maa_runtime_tier(),
        RuntimeAssuranceTier::Attested
    );
    assert_eq!(azure_adapter.adapter_name(), AZURE_MAA_VERIFIER_ADAPTER);
    assert_eq!(
        azure_adapter.verifier_family(),
        AttestationVerifierFamily::AzureMaa
    );
    assert!(matches!(
        AzureMaaVerificationPolicy {
            issuer: " ".to_string(),
            ..azure_policy.clone()
        }
        .validate(),
        Err(AzureMaaVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        AzureMaaVerificationPolicy {
            workload_claim_path: Some(" ".to_string()),
            ..azure_policy.clone()
        }
        .validate(),
        Err(AzureMaaVerificationError::InvalidPolicy(_))
    ));

    let google_policy = GoogleConfidentialVmVerificationPolicy {
        issuer: "https://confidentialcomputing.googleapis.com".to_string(),
        allowed_audiences: vec!["chio-runtime".to_string()],
        allowed_service_accounts: vec!["svc@example.test".to_string()],
        allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
        tier: RuntimeAssuranceTier::Attested,
        require_secure_boot: true,
    };
    let google_adapter = GoogleConfidentialVmVerifierAdapter::new(
        google_policy.clone(),
        GoogleConfidentialVmJwks { keys: Vec::new() },
    )
    .test_unwrap();
    assert_eq!(
        default_google_confidential_vm_runtime_tier(),
        RuntimeAssuranceTier::Attested
    );
    assert_eq!(
        google_adapter.adapter_name(),
        GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER
    );
    assert_eq!(
        google_adapter.verifier_family(),
        AttestationVerifierFamily::GoogleAttestation
    );
    assert!(matches!(
        GoogleConfidentialVmVerificationPolicy {
            issuer: " ".to_string(),
            ..google_policy.clone()
        }
        .validate(),
        Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        GoogleConfidentialVmVerificationPolicy {
            tier: RuntimeAssuranceTier::Verified,
            ..google_policy.clone()
        }
        .validate(),
        Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        GoogleConfidentialVmVerificationPolicy {
            allowed_audiences: vec![" ".to_string()],
            ..google_policy.clone()
        }
        .validate(),
        Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        GoogleConfidentialVmVerificationPolicy {
            allowed_service_accounts: vec![" ".to_string()],
            ..google_policy.clone()
        }
        .validate(),
        Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        GoogleConfidentialVmVerificationPolicy {
            allowed_hardware_models: vec![" ".to_string()],
            ..google_policy.clone()
        }
        .validate(),
        Err(GoogleConfidentialVmVerificationError::InvalidPolicy(_))
    ));

    let trusted_signer = chio_core::crypto::Keypair::generate();
    let enterprise_policy = EnterpriseVerifierVerificationPolicy {
        verifier: "https://attest.contoso.example".to_string(),
        trusted_signer_keys: vec![trusted_signer.public_key().to_hex()],
        max_evidence_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
    };
    let enterprise_adapter =
        EnterpriseVerifierAdapter::new(enterprise_policy.clone()).test_unwrap();
    assert_eq!(
        default_enterprise_verifier_runtime_tier(),
        RuntimeAssuranceTier::Attested
    );
    assert_eq!(
        enterprise_adapter.adapter_name(),
        ENTERPRISE_VERIFIER_ADAPTER
    );
    assert_eq!(
        enterprise_adapter.verifier_family(),
        AttestationVerifierFamily::EnterpriseVerifier
    );
    assert!(matches!(
        EnterpriseVerifierVerificationPolicy {
            verifier: " ".to_string(),
            ..enterprise_policy.clone()
        }
        .validate(),
        Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        EnterpriseVerifierVerificationPolicy {
            trusted_signer_keys: Vec::new(),
            ..enterprise_policy.clone()
        }
        .validate(),
        Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        EnterpriseVerifierVerificationPolicy {
            max_evidence_age_seconds: 0,
            ..enterprise_policy.clone()
        }
        .validate(),
        Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        EnterpriseVerifierVerificationPolicy {
            tier: RuntimeAssuranceTier::Verified,
            ..enterprise_policy.clone()
        }
        .validate(),
        Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        EnterpriseVerifierVerificationPolicy {
            trusted_signer_keys: vec![" ".to_string()],
            ..enterprise_policy.clone()
        }
        .validate(),
        Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
    ));
    assert!(matches!(
        EnterpriseVerifierVerificationPolicy {
            trusted_signer_keys: vec!["deadbeef".to_string()],
            ..enterprise_policy
        }
        .validate(),
        Err(EnterpriseVerifierVerificationError::InvalidPolicy(_))
    ));
}

#[test]
fn attestation_oidc_and_metadata_helpers_cover_parse_and_resolution_edges() {
    assert_eq!(
        AzureMaaJwtAlgorithm::parse("RS256").test_unwrap().as_str(),
        "RS256"
    );
    assert_eq!(
        AzureMaaJwtAlgorithm::parse("PS256").test_unwrap().as_str(),
        "PS256"
    );
    assert!(matches!(
        AzureMaaJwtAlgorithm::parse("HS256"),
        Err(AzureMaaVerificationError::UnsupportedAlgorithm(_))
    ));
    assert!(AzureMaaResolvedJwk {
        key: rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .test_unwrap()
            .to_public_key(),
        alg_hint: None,
    }
    .supports_alg(AzureMaaJwtAlgorithm::Rs256));
    assert!(!AzureMaaResolvedJwk {
        key: rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .test_unwrap()
            .to_public_key(),
        alg_hint: Some("PS256".to_string()),
    }
    .supports_alg(AzureMaaJwtAlgorithm::Rs256));
    assert!(matches!(
        AzureMaaVerificationError::from(OidcJwtDecodeError::InvalidJwt("bad")),
        AzureMaaVerificationError::InvalidJwt("bad")
    ));
    assert!(matches!(
        GoogleConfidentialVmVerificationError::from(OidcJwtDecodeError::InvalidJwt("bad")),
        GoogleConfidentialVmVerificationError::InvalidJwt("bad")
    ));
    assert!(matches!(
        AzureMaaVerificationError::from(OidcRsaKeyResolveError::UntrustedSigningKey),
        AzureMaaVerificationError::UntrustedSigningKey
    ));
    assert!(matches!(
        GoogleConfidentialVmVerificationError::from(
            OidcRsaKeyResolveError::KeyAlgorithmMismatch("RS256".to_string())
        ),
        GoogleConfidentialVmVerificationError::KeyAlgorithmMismatch(alg) if alg == "RS256"
    ));

    assert!(decode_cose_protected_headers(&[]).test_unwrap().is_empty());
    assert!(matches!(
        decode_cose_protected_headers(b"not-cbor"),
        Err(AwsNitroVerificationError::InvalidCose(_))
    ));
    assert_eq!(cbor_integer_to_i64(&CborValue::Integer(7.into())), Some(7));
    assert_eq!(
        cbor_integer_to_i64(&CborValue::Text("nope".to_string())),
        None
    );

    assert!(matches!(
        decode_jwt_parts::<Value>("header-only"),
        Err(OidcJwtDecodeError::InvalidJwt("missing payload"))
    ));
    assert!(matches!(
        decode_jwt_parts::<Value>("a.b"),
        Err(OidcJwtDecodeError::InvalidJwt("missing signature"))
    ));
    assert!(matches!(
        decode_jwt_parts::<Value>("a.b.c.d"),
        Err(OidcJwtDecodeError::InvalidJwt("too many segments"))
    ));
    assert!(matches!(
        decode_jwt_parts::<Value>("***.b.c"),
        Err(OidcJwtDecodeError::InvalidJwt("invalid header encoding"))
    ));
    let bad_json = URL_SAFE_NO_PAD.encode(b"not-json");
    assert!(matches!(
        decode_jwt_parts::<Value>(&format!("{bad_json}.b.c")),
        Err(OidcJwtDecodeError::InvalidJwt("invalid header json"))
    ));
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    assert!(matches!(
        decode_jwt_parts::<Value>(&format!("{header}.***.c")),
        Err(OidcJwtDecodeError::InvalidJwt("invalid payload encoding"))
    ));
    let bad_payload = URL_SAFE_NO_PAD.encode(b"not-json");
    assert!(matches!(
        decode_jwt_parts::<Value>(&format!("{header}.{bad_payload}.c")),
        Err(OidcJwtDecodeError::InvalidJwt("invalid payload json"))
    ));
    let valid_payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"demo"}"#);
    assert!(matches!(
        decode_jwt_parts::<Value>(&format!("{header}.{valid_payload}.***")),
        Err(OidcJwtDecodeError::InvalidJwt("invalid signature encoding"))
    ));

    assert!(matches!(
        decode_urlsafe_component("***", "n"),
        Err(OidcRsaKeyResolveError::InvalidJwkComponent { component: "n", .. })
    ));
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        google_token_audiences(&Value::String("chio-runtime".to_string())).test_unwrap(),
        vec!["chio-runtime".to_string()]
    );
    assert_eq!(
        google_token_audiences(&json!(["chio-runtime", "", 7, "fallback"])).test_unwrap(),
        vec!["chio-runtime".to_string(), "fallback".to_string()]
    );
    assert!(matches!(
        google_token_audiences(&json!(["", 7])),
        Err(GoogleConfidentialVmVerificationError::MissingClaim("aud"))
    ));
    assert_eq!(
        canonicalize_issuer(" https://issuer.example/path/ "),
        "https://issuer.example/path"
    );
    assert_eq!(canonicalize_issuer("issuer.example/"), "issuer.example");

    assert_eq!(
        resolve_workload_identity(None, None).test_unwrap(),
        (None, None)
    );
    let runtime = json!({
        "claims": {
            "nested": {
                "spiffe": "spiffe://contoso.test/runtime/worker"
            }
        }
    });
    let (runtime_identity, workload_identity) =
        resolve_workload_identity(Some(&runtime), Some("nested.spiffe")).test_unwrap();
    assert_eq!(
        runtime_identity.as_deref(),
        Some("spiffe://contoso.test/runtime/worker")
    );
    assert_eq!(workload_identity.test_unwrap().trust_domain, "contoso.test");
    assert!(matches!(
        resolve_workload_identity(None, Some("nested.spiffe")),
        Err(AzureMaaVerificationError::InvalidWorkloadClaim(path))
        if path == "nested.spiffe"
    ));
    assert!(matches!(
        resolve_workload_identity(Some(&json!({"claims": {"nested": {"spiffe": 7}}})), Some("nested.spiffe")),
        Err(AzureMaaVerificationError::InvalidWorkloadClaim(path))
        if path == "nested.spiffe"
    ));
    assert!(matches!(
        resolve_workload_identity(
            Some(&json!({"claims": {"nested": {"spiffe": "not-a-spiffe"}}})),
            Some("nested.spiffe")
        ),
        Err(AzureMaaVerificationError::InvalidWorkloadIdentity(_))
    ));

    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let jwks_json = serde_json::to_string(&rsa_jwk_set(&private_key, "maa-key-1")).test_unwrap();

    let azure_metadata_url = serve_json_once(
        r#"{"issuer":"https://maa.contoso.test","jwksUri":"https://maa.contoso.test/keys"}"#,
    );
    assert_eq!(
        fetch_azure_maa_openid_metadata(&azure_metadata_url)
            .test_unwrap()
            .jwks_uri,
        "https://maa.contoso.test/keys"
    );
    let azure_jwks_url = serve_json_once(&jwks_json);
    assert_eq!(
        fetch_azure_maa_jwks(&azure_jwks_url)
            .test_unwrap()
            .keys
            .len(),
        1
    );
    let azure_parse_url = serve_json_once("{bad json");
    assert!(matches!(
        fetch_azure_maa_openid_metadata(&azure_parse_url),
        Err(AzureMaaVerificationError::MetadataParse { .. })
    ));
    let azure_fetch_url = closed_local_url();
    assert!(matches!(
        fetch_azure_maa_jwks(&azure_fetch_url),
        Err(AzureMaaVerificationError::MetadataFetch { .. })
    ));

    let google_metadata_url = serve_json_once(
        r#"{"issuer":"https://confidentialcomputing.googleapis.com","jwksUri":"https://confidentialcomputing.googleapis.com/keys"}"#,
    );
    assert_eq!(
        fetch_google_confidential_vm_openid_metadata(&google_metadata_url)
            .test_unwrap()
            .issuer,
        "https://confidentialcomputing.googleapis.com"
    );
    let google_jwks_url = serve_json_once(&jwks_json);
    assert_eq!(
        fetch_google_confidential_vm_jwks(&google_jwks_url)
            .test_unwrap()
            .keys
            .len(),
        1
    );
    let google_parse_url = serve_json_once("{bad json");
    assert!(matches!(
        fetch_google_confidential_vm_jwks(&google_parse_url),
        Err(GoogleConfidentialVmVerificationError::MetadataParse { .. })
    ));
    let google_fetch_url = closed_local_url();
    assert!(matches!(
        fetch_google_confidential_vm_openid_metadata(&google_fetch_url),
        Err(GoogleConfidentialVmVerificationError::MetadataFetch { .. })
    ));
}

#[test]
fn attestation_jwk_resolution_and_aws_helpers_cover_remaining_error_branches() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let compatible = rsa_jwk_set(&private_key, "maa-key-1");
    let resolved = resolve_signing_key(&compatible, Some("maa-key-1"), AzureMaaJwtAlgorithm::Rs256)
        .test_unwrap();
    assert!(resolved.supports_alg(AzureMaaJwtAlgorithm::Rs256));

    let mismatched_alg = AzureMaaJwks {
        keys: vec![AzureMaaJwk {
            alg: Some("PS256".to_string()),
            ..compatible.keys[0].clone()
        }],
    };
    assert!(matches!(
        resolve_signing_key(
            &mismatched_alg,
            Some("maa-key-1"),
            AzureMaaJwtAlgorithm::Rs256
        ),
        Err(OidcRsaKeyResolveError::KeyAlgorithmMismatch(alg)) if alg == "RS256"
    ));

    let anonymous = AzureMaaJwks {
        keys: vec![AzureMaaJwk {
            kid: None,
            ..compatible.keys[0].clone()
        }],
    };
    assert!(resolve_signing_key(&anonymous, None, AzureMaaJwtAlgorithm::Rs256).is_ok());

    let ambiguous = AzureMaaJwks {
        keys: vec![
            AzureMaaJwk {
                kid: None,
                ..compatible.keys[0].clone()
            },
            AzureMaaJwk {
                kid: None,
                ..compatible.keys[0].clone()
            },
        ],
    };
    assert!(matches!(
        resolve_signing_key(&ambiguous, None, AzureMaaJwtAlgorithm::Rs256),
        Err(OidcRsaKeyResolveError::UntrustedSigningKey)
    ));

    let encryption_only = AzureMaaJwks {
        keys: vec![AzureMaaJwk {
            key_use: Some("enc".to_string()),
            ..compatible.keys[0].clone()
        }],
    };
    assert!(matches!(
        resolve_signing_key(
            &encryption_only,
            Some("maa-key-1"),
            AzureMaaJwtAlgorithm::Rs256
        ),
        Err(OidcRsaKeyResolveError::UntrustedSigningKey)
    ));

    assert!(matches!(
        resolve_jwk_public_key(&AzureMaaJwk {
            kty: "EC".to_string(),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            x5c: Vec::new(),
        }),
        Err(OidcRsaKeyResolveError::InvalidRsaKey(_))
    ));
    assert!(matches!(
        resolve_jwk_public_key(&AzureMaaJwk {
            kty: "RSA".to_string(),
            kid: None,
            alg: None,
            key_use: None,
            n: None,
            e: None,
            x5c: Vec::new(),
        }),
        Err(OidcRsaKeyResolveError::InvalidRsaKey(_))
    ));
    assert!(matches!(
        resolve_jwk_public_key(&AzureMaaJwk {
            kty: "RSA".to_string(),
            kid: None,
            alg: None,
            key_use: None,
            n: Some("***".to_string()),
            e: Some("AQAB".to_string()),
            x5c: Vec::new(),
        }),
        Err(OidcRsaKeyResolveError::InvalidJwkComponent { component: "n", .. })
    ));

    let materials = generate_aws_nitro_test_materials();
    let now = current_unix_time();
    let policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec![materials.root_pem.clone()],
        expected_pcrs: BTreeMap::new(),
        max_document_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: Some("cafe".to_string()),
    };
    let valid_document = sample_aws_document(&materials, now);
    assert!(validate_aws_nitro_document(&valid_document, &policy, now).is_ok());
    assert!(matches!(
        validate_aws_nitro_document(
            &AwsNitroAttestationDocument {
                module_id: " ".to_string(),
                ..sample_aws_document(&materials, now)
            },
            &policy,
            now
        ),
        Err(AwsNitroVerificationError::MissingField("module_id"))
    ));
    assert!(matches!(
        validate_aws_nitro_document(
            &AwsNitroAttestationDocument {
                certificate: Vec::new(),
                ..sample_aws_document(&materials, now)
            },
            &policy,
            now
        ),
        Err(AwsNitroVerificationError::MissingField("certificate"))
    ));
    assert!(matches!(
        validate_aws_nitro_document(
            &AwsNitroAttestationDocument {
                digest: "SHA256".to_string(),
                ..sample_aws_document(&materials, now)
            },
            &policy,
            now
        ),
        Err(AwsNitroVerificationError::UnsupportedDigest(_))
    ));
    assert!(matches!(
        validate_aws_nitro_document(
            &AwsNitroAttestationDocument {
                timestamp: now.saturating_add(10) * 1000,
                ..sample_aws_document(&materials, now)
            },
            &policy,
            now
        ),
        Err(AwsNitroVerificationError::FutureDocument { .. })
    ));
    assert!(matches!(
        validate_aws_nitro_document(
            &AwsNitroAttestationDocument {
                pcrs: BTreeMap::new(),
                ..sample_aws_document(&materials, now)
            },
            &policy,
            now
        ),
        Err(AwsNitroVerificationError::MissingField("pcrs"))
    ));
    assert!(matches!(
        validate_aws_nitro_document(
            &AwsNitroAttestationDocument {
                pcrs: BTreeMap::from([(0, vec![0x11; 47])]),
                ..sample_aws_document(&materials, now)
            },
            &policy,
            now
        ),
        Err(AwsNitroVerificationError::InvalidField("pcrs"))
    ));
    assert!(matches!(
        validate_aws_nitro_document(
            &valid_document,
            &AwsNitroVerificationPolicy {
                expected_pcrs: BTreeMap::from([(1, "11".repeat(48))]),
                ..policy.clone()
            },
            now
        ),
        Err(AwsNitroVerificationError::MissingPcr { index: 1 })
    ));
    assert!(matches!(
        validate_aws_nitro_document(
            &AwsNitroAttestationDocument {
                nonce: None,
                ..valid_document
            },
            &policy,
            now
        ),
        Err(AwsNitroVerificationError::MissingField("nonce"))
    ));
}

#[test]
fn enterprise_and_appraisal_negative_paths_cover_remaining_branch_states() {
    let now = current_unix_time();
    let signer = chio_core::crypto::Keypair::generate();
    let policy = EnterpriseVerifierVerificationPolicy {
        verifier: "https://attest.contoso.example".to_string(),
        trusted_signer_keys: vec![signer.public_key().to_hex()],
        max_evidence_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
    };
    let adapter = EnterpriseVerifierAdapter::new(policy.clone()).test_unwrap();

    assert!(matches!(
        adapter.verify_and_appraise("{", now),
        Err(EnterpriseVerifierVerificationError::InvalidEnvelope(_))
    ));

    let signed = SignedExportEnvelope::sign(sample_enterprise_evidence(now), &signer).test_unwrap();
    let mut tampered = signed.clone();
    tampered.body.verifier = "https://attest.other.example".to_string();
    assert!(matches!(
        adapter.verify_and_appraise(&serde_json::to_string(&tampered).test_unwrap(), now),
        Err(EnterpriseVerifierVerificationError::InvalidSignature)
    ));

    let unsupported = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.other.v1".to_string(),
        ..sample_enterprise_evidence(now)
    };
    let unsupported = SignedExportEnvelope::sign(unsupported, &signer).test_unwrap();
    assert!(matches!(
        adapter.verify_and_appraise(&serde_json::to_string(&unsupported).test_unwrap(), now),
        Err(EnterpriseVerifierVerificationError::UnsupportedSchema { .. })
    ));

    let mismatch = RuntimeAttestationEvidence {
        verifier: "https://attest.other.example".to_string(),
        ..sample_enterprise_evidence(now)
    };
    let mismatch = SignedExportEnvelope::sign(mismatch, &signer).test_unwrap();
    assert!(matches!(
        adapter.verify_and_appraise(&serde_json::to_string(&mismatch).test_unwrap(), now),
        Err(EnterpriseVerifierVerificationError::VerifierMismatch { .. })
    ));

    let future = RuntimeAttestationEvidence {
        issued_at: now.saturating_add(30),
        expires_at: now.saturating_add(300),
        ..sample_enterprise_evidence(now)
    };
    let future = SignedExportEnvelope::sign(future, &signer).test_unwrap();
    assert!(matches!(
        adapter.verify_and_appraise(&serde_json::to_string(&future).test_unwrap(), now),
        Err(EnterpriseVerifierVerificationError::EvidenceNotValid { .. })
    ));

    let stale = RuntimeAttestationEvidence {
        issued_at: now.saturating_sub(500),
        expires_at: now.saturating_add(300),
        ..sample_enterprise_evidence(now)
    };
    let stale = SignedExportEnvelope::sign(stale, &signer).test_unwrap();
    assert!(matches!(
        adapter.verify_and_appraise(&serde_json::to_string(&stale).test_unwrap(), now),
        Err(EnterpriseVerifierVerificationError::EvidenceTooOld { .. })
    ));

    let too_high = RuntimeAttestationEvidence {
        tier: RuntimeAssuranceTier::Verified,
        ..sample_enterprise_evidence(now)
    };
    let too_high = SignedExportEnvelope::sign(too_high, &signer).test_unwrap();
    assert!(matches!(
        adapter.verify_and_appraise(&serde_json::to_string(&too_high).test_unwrap(), now),
        Err(EnterpriseVerifierVerificationError::TierTooHigh { .. })
    ));

    let foreign_google = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.other.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };
    let google_appraisal = appraise_google_confidential_vm_evidence(&foreign_google);
    assert_eq!(
        google_appraisal.reason_codes,
        vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
    );
    assert_eq!(
        google_appraisal.verdict,
        chio_core::appraisal::RuntimeAttestationAppraisalVerdict::Rejected
    );

    let foreign_aws = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.other.v1".to_string(),
        verifier: "aws-nitro".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };
    let aws_appraisal = appraise_aws_nitro_evidence(&foreign_aws);
    assert_eq!(
        aws_appraisal.reason_codes,
        vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
    );
    assert_eq!(
        aws_appraisal.verdict,
        chio_core::appraisal::RuntimeAttestationAppraisalVerdict::Rejected
    );
    assert!(extract_vendor_claims(&foreign_aws, "awsNitro").is_empty());
}

#[test]
fn azure_maa_jwt_normalizes_runtime_attestation_and_workload_identity() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let token = sign_rs256_jwt(
        &private_key,
        json!({"alg": "RS256", "kid": "maa-key-1", "typ": "JWT"}),
        json!({
            "iss": "https://maa.contoso.test",
            "iat": 100,
            "nbf": 100,
            "exp": 200,
            "jti": "maa-token-1",
            "x-ms-ver": "1.0",
            "x-ms-attestation-type": "sgx",
            "x-ms-policy-hash": "policy-hash-1",
            "x-ms-runtime": {
                "claims": {
                    "spiffe_uri": "spiffe://contoso.test/runtime/worker"
                }
            }
        }),
    );
    let policy = AzureMaaVerificationPolicy {
        issuer: "https://maa.contoso.test".to_string(),
        allowed_attestation_types: vec!["sgx".to_string()],
        tier: RuntimeAssuranceTier::Attested,
        workload_claim_path: Some("spiffe_uri".to_string()),
    };

    let evidence = verify_azure_maa_attestation_jwt(
        &token,
        &policy,
        &rsa_jwk_set(&private_key, "maa-key-1"),
        150,
    )
    .test_unwrap();

    assert_eq!(evidence.schema, AZURE_MAA_ATTESTATION_SCHEMA);
    assert_eq!(evidence.verifier, "https://maa.contoso.test");
    assert_eq!(evidence.tier, RuntimeAssuranceTier::Attested);
    assert_eq!(
        evidence.runtime_identity.as_deref(),
        Some("spiffe://contoso.test/runtime/worker")
    );
    assert_eq!(
        evidence
            .workload_identity
            .as_ref()
            .test_unwrap()
            .trust_domain,
        "contoso.test"
    );
    assert_eq!(
        evidence.claims.test_unwrap()["azureMaa"]["attestationType"],
        "sgx"
    );
}

#[test]
fn azure_maa_jwt_rejects_disallowed_attestation_type() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let token = sign_rs256_jwt(
        &private_key,
        json!({"alg": "RS256", "kid": "maa-key-1", "typ": "JWT"}),
        json!({
            "iss": "https://maa.contoso.test",
            "iat": 100,
            "nbf": 100,
            "exp": 200,
            "x-ms-ver": "1.0",
            "x-ms-attestation-type": "sev_snp"
        }),
    );
    let policy = AzureMaaVerificationPolicy {
        issuer: "https://maa.contoso.test".to_string(),
        allowed_attestation_types: vec!["sgx".to_string()],
        tier: RuntimeAssuranceTier::Attested,
        workload_claim_path: None,
    };

    let error = verify_azure_maa_attestation_jwt(
        &token,
        &policy,
        &rsa_jwk_set(&private_key, "maa-key-1"),
        150,
    )
    .test_unwrap_err();
    assert!(matches!(
        error,
        AzureMaaVerificationError::DisallowedAttestationType { .. }
    ));
}

#[test]
fn azure_maa_policy_rejects_assurance_tier_above_attested() {
    let policy = AzureMaaVerificationPolicy {
        issuer: "https://maa.contoso.test".to_string(),
        allowed_attestation_types: Vec::new(),
        tier: RuntimeAssuranceTier::Verified,
        workload_claim_path: None,
    };

    let error = policy.validate().test_unwrap_err();
    assert!(matches!(error, AzureMaaVerificationError::InvalidPolicy(_)));
}

#[test]
fn azure_maa_adapter_emits_canonical_appraisal_contract() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let token = sign_rs256_jwt(
        &private_key,
        json!({"alg": "RS256", "kid": "maa-key-1", "typ": "JWT"}),
        json!({
            "iss": "https://maa.contoso.test",
            "iat": 100,
            "nbf": 100,
            "exp": 200,
            "jti": "maa-token-1",
            "x-ms-ver": "1.0",
            "x-ms-attestation-type": "sgx",
            "x-ms-runtime": {
                "claims": {
                    "spiffe_uri": "spiffe://contoso.test/runtime/worker"
                }
            }
        }),
    );
    let adapter = AzureMaaVerifierAdapter::new(
        AzureMaaVerificationPolicy {
            issuer: "https://maa.contoso.test".to_string(),
            allowed_attestation_types: vec!["sgx".to_string()],
            tier: RuntimeAssuranceTier::Attested,
            workload_claim_path: Some("spiffe_uri".to_string()),
        },
        rsa_jwk_set(&private_key, "maa-key-1"),
    )
    .test_unwrap();

    let verified = adapter.verify_and_appraise(&token, 150).test_unwrap();

    assert_eq!(verified.appraisal.adapter, AZURE_MAA_VERIFIER_ADAPTER);
    assert_eq!(
        verified.appraisal.verifier_family,
        AttestationVerifierFamily::AzureMaa
    );
    assert_eq!(
        verified.appraisal.reason_codes,
        vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified]
    );
    assert_eq!(
        verified.appraisal.normalized_assertions["attestationType"],
        "sgx"
    );
    assert_eq!(
        verified.appraisal.normalized_assertions["workloadIdentityUri"],
        "spiffe://contoso.test/runtime/worker"
    );
    assert_eq!(verified.appraisal.vendor_claims["attestationType"], "sgx");
}

#[test]
fn azure_maa_appraisal_rejects_non_azure_schema() {
    let evidence = RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.other.v1".to_string(),
        verifier: "https://maa.contoso.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 100,
        expires_at: 200,
        evidence_sha256: "digest".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: None,
    };

    let appraisal = appraise_azure_maa_evidence(&evidence);
    assert_eq!(
        appraisal.reason_codes,
        vec![RuntimeAttestationAppraisalReasonCode::UnsupportedEvidence]
    );
    assert_eq!(
        appraisal.verdict,
        chio_core::appraisal::RuntimeAttestationAppraisalVerdict::Rejected
    );
    assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::None);
}

#[test]
fn google_confidential_vm_jwt_verifies_and_appraises() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let token = sign_rs256_jwt(
        &private_key,
        json!({"alg": "RS256", "kid": "google-key-1", "typ": "JWT"}),
        json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "sub": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1",
            "aud": ["chio-runtime"],
            "iat": 100,
            "nbf": 100,
            "exp": 200,
            "secboot": true,
            "hwmodel": "GCP_AMD_SEV",
            "swname": "GCE",
            "google_service_accounts": ["svc-demo@project.iam.gserviceaccount.com"]
        }),
    );
    let policy = GoogleConfidentialVmVerificationPolicy {
        issuer: "https://confidentialcomputing.googleapis.com".to_string(),
        allowed_audiences: vec!["chio-runtime".to_string()],
        allowed_service_accounts: vec!["svc-demo@project.iam.gserviceaccount.com".to_string()],
        allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
        tier: RuntimeAssuranceTier::Attested,
        require_secure_boot: true,
    };

    let evidence = verify_google_confidential_vm_attestation_jwt(
        &token,
        &policy,
        &rsa_jwk_set(&private_key, "google-key-1"),
        150,
    )
    .test_unwrap();

    assert_eq!(evidence.schema, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA);
    assert_eq!(
        evidence.runtime_identity.as_deref(),
        Some("//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1")
    );
    assert_eq!(
        evidence.claims.as_ref().test_unwrap()["googleAttestation"]["hardwareModel"],
        "GCP_AMD_SEV"
    );

    let appraisal = appraise_google_confidential_vm_evidence(&evidence);
    assert_eq!(
        appraisal.verifier_family,
        AttestationVerifierFamily::GoogleAttestation
    );
    assert_eq!(appraisal.normalized_assertions["secureBoot"], "enabled");
}

#[test]
fn google_confidential_vm_jwt_rejects_audience_mismatch() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let token = sign_rs256_jwt(
        &private_key,
        json!({"alg": "RS256", "kid": "google-key-1", "typ": "JWT"}),
        json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "sub": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1",
            "aud": ["unexpected-audience"],
            "iat": 100,
            "nbf": 100,
            "exp": 200,
            "secboot": true,
            "hwmodel": "GCP_AMD_SEV"
        }),
    );
    let policy = GoogleConfidentialVmVerificationPolicy {
        issuer: "https://confidentialcomputing.googleapis.com".to_string(),
        allowed_audiences: vec!["chio-runtime".to_string()],
        allowed_service_accounts: Vec::new(),
        allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
        tier: RuntimeAssuranceTier::Attested,
        require_secure_boot: false,
    };

    let error = verify_google_confidential_vm_attestation_jwt(
        &token,
        &policy,
        &rsa_jwk_set(&private_key, "google-key-1"),
        150,
    )
    .test_unwrap_err();
    assert!(matches!(
        error,
        GoogleConfidentialVmVerificationError::AudienceMismatch
    ));
}

#[test]
fn google_confidential_vm_jwt_rejects_insecure_boot() {
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).test_unwrap();
    let token = sign_rs256_jwt(
        &private_key,
        json!({"alg": "RS256", "kid": "google-key-1", "typ": "JWT"}),
        json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "sub": "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1",
            "aud": ["chio-runtime"],
            "iat": 100,
            "nbf": 100,
            "exp": 200,
            "secboot": false,
            "hwmodel": "GCP_AMD_SEV"
        }),
    );
    let policy = GoogleConfidentialVmVerificationPolicy {
        issuer: "https://confidentialcomputing.googleapis.com".to_string(),
        allowed_audiences: vec!["chio-runtime".to_string()],
        allowed_service_accounts: Vec::new(),
        allowed_hardware_models: vec!["GCP_AMD_SEV".to_string()],
        tier: RuntimeAssuranceTier::Attested,
        require_secure_boot: true,
    };

    let error = verify_google_confidential_vm_attestation_jwt(
        &token,
        &policy,
        &rsa_jwk_set(&private_key, "google-key-1"),
        150,
    )
    .test_unwrap_err();
    assert!(matches!(
        error,
        GoogleConfidentialVmVerificationError::InsecureBoot
    ));
}

#[test]
fn aws_nitro_attestation_document_verifies_and_appraises() {
    let materials = generate_aws_nitro_test_materials();
    let now = current_unix_time();
    let pcr0 = vec![0x11; 48];
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, pcr0.clone());
    let document = build_aws_nitro_attestation_document(
        &materials,
        (now - 50) * 1000,
        pcrs,
        Some(vec![0xCA, 0xFE]),
    );
    let policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec![materials.root_pem.clone()],
        expected_pcrs: BTreeMap::from([(0, hex::encode(&pcr0))]),
        max_document_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: Some("cafe".to_string()),
    };

    let evidence = verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap();
    assert_eq!(evidence.schema, AWS_NITRO_ATTESTATION_SCHEMA);
    assert_eq!(evidence.verifier, "aws-nitro");
    assert_eq!(
        evidence.claims.as_ref().test_unwrap()["awsNitro"]["moduleId"],
        "i-arcnitro123"
    );

    let appraisal = appraise_aws_nitro_evidence(&evidence);
    assert_eq!(appraisal.adapter, AWS_NITRO_VERIFIER_ADAPTER);
    assert_eq!(appraisal.normalized_assertions["digest"], "SHA384");
}

#[test]
fn aws_nitro_attestation_document_rejects_pcr_mismatch() {
    let materials = generate_aws_nitro_test_materials();
    let now = current_unix_time();
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0x11; 48]);
    let document = build_aws_nitro_attestation_document(&materials, (now - 50) * 1000, pcrs, None);
    let policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec![materials.root_pem.clone()],
        expected_pcrs: BTreeMap::from([(0, hex::encode(vec![0x22; 48]))]),
        max_document_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: None,
    };

    let error = verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
    assert!(matches!(
        error,
        AwsNitroVerificationError::PcrMismatch { index: 0 }
    ));
}

#[test]
fn aws_nitro_attestation_document_rejects_stale_document() {
    let materials = generate_aws_nitro_test_materials();
    let now = current_unix_time();
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0x11; 48]);
    let document = build_aws_nitro_attestation_document(&materials, (now - 10) * 1000, pcrs, None);
    let policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec![materials.root_pem.clone()],
        expected_pcrs: BTreeMap::new(),
        max_document_age_seconds: 5,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: None,
    };

    let error = verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
    assert!(matches!(
        error,
        AwsNitroVerificationError::StaleDocument { .. }
    ));
}

#[test]
fn aws_nitro_attestation_document_rejects_debug_mode_by_default() {
    let materials = generate_aws_nitro_test_materials();
    let now = current_unix_time();
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0x00; 48]);
    let document = build_aws_nitro_attestation_document(&materials, (now - 50) * 1000, pcrs, None);
    let policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec![materials.root_pem.clone()],
        expected_pcrs: BTreeMap::new(),
        max_document_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: None,
    };

    let error = verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
    assert!(matches!(
        error,
        AwsNitroVerificationError::DebugModeEvidence
    ));
}

#[test]
fn aws_nitro_attestation_document_rejects_nonce_mismatch() {
    let materials = generate_aws_nitro_test_materials();
    let now = current_unix_time();
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0x11; 48]);
    let document = build_aws_nitro_attestation_document(
        &materials,
        (now - 50) * 1000,
        pcrs,
        Some(vec![0xCA, 0xFE]),
    );
    let policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec![materials.root_pem.clone()],
        expected_pcrs: BTreeMap::new(),
        max_document_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: Some("beef".to_string()),
    };

    let error = verify_aws_nitro_attestation_document(&document, &policy, now).test_unwrap_err();
    assert!(matches!(error, AwsNitroVerificationError::NonceMismatch));
}

#[test]
fn aws_nitro_attestation_document_rejects_malformed_cose() {
    let policy = AwsNitroVerificationPolicy {
        trusted_root_certificates_pem: vec![
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".to_string(),
        ],
        expected_pcrs: BTreeMap::new(),
        max_document_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
        allow_debug_mode: false,
        expected_nonce_hex: None,
    };

    let error = verify_aws_nitro_attestation_document(b"not-cbor", &policy, current_unix_time())
        .test_unwrap_err();
    assert!(matches!(error, AwsNitroVerificationError::InvalidCose(_)));
}

#[test]
fn enterprise_verifier_adapter_verifies_signed_envelope_and_derives_portable_appraisal() {
    let signer = chio_core::crypto::Keypair::generate();
    let now = current_unix_time();
    let evidence = RuntimeAttestationEvidence {
        schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
        verifier: "https://attest.contoso.example".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(30),
        expires_at: now.saturating_add(300),
        evidence_sha256: "sha256-enterprise-attestation".to_string(),
        runtime_identity: Some("spiffe://chio.example/workloads/enterprise".to_string()),
        workload_identity: Some(
            WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/enterprise")
                .test_unwrap(),
        ),
        claims: Some(json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_confidential_vm",
                "hardwareModel": "AMD_SEV_SNP",
                "secureBoot": "enabled",
                "digest": "sha384:enterprise-measurement",
                "pcrs": {
                    "0": "8f7f1be8"
                }
            }
        })),
    };
    let signed = SignedExportEnvelope::sign(evidence.clone(), &signer).test_unwrap();
    let adapter = EnterpriseVerifierAdapter::new(EnterpriseVerifierVerificationPolicy {
        verifier: "https://attest.contoso.example".to_string(),
        trusted_signer_keys: vec![signer.public_key().to_hex()],
        max_evidence_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
    })
    .test_unwrap();

    let verified = adapter
        .verify_and_appraise(&serde_json::to_string(&signed).test_unwrap(), now)
        .test_unwrap();
    assert_eq!(verified.evidence, evidence);
    assert_eq!(
        verified.appraisal.verifier_family,
        AttestationVerifierFamily::EnterpriseVerifier
    );
    assert_eq!(
        verified.appraisal.normalized_assertions["secureBoot"],
        json!("enabled")
    );
    assert_eq!(
        verified.appraisal.normalized_assertions["digest"],
        json!("sha384:enterprise-measurement")
    );
}

#[test]
fn enterprise_verifier_adapter_rejects_untrusted_signer() {
    let trusted_signer = chio_core::crypto::Keypair::generate();
    let actual_signer = chio_core::crypto::Keypair::generate();
    let now = current_unix_time();
    let signed = SignedExportEnvelope::sign(
        RuntimeAttestationEvidence {
            schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://attest.contoso.example".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(30),
            expires_at: now.saturating_add(300),
            evidence_sha256: "sha256-enterprise-attestation".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(json!({
                "enterpriseVerifier": {
                    "attestationType": "enterprise_confidential_vm"
                }
            })),
        },
        &actual_signer,
    )
    .test_unwrap();
    let adapter = EnterpriseVerifierAdapter::new(EnterpriseVerifierVerificationPolicy {
        verifier: "https://attest.contoso.example".to_string(),
        trusted_signer_keys: vec![trusted_signer.public_key().to_hex()],
        max_evidence_age_seconds: 120,
        tier: RuntimeAssuranceTier::Attested,
    })
    .test_unwrap();

    let error = adapter
        .verify_and_appraise(&serde_json::to_string(&signed).test_unwrap(), now)
        .test_unwrap_err();
    assert!(matches!(
        error,
        EnterpriseVerifierVerificationError::UntrustedSigner { .. }
    ));
}
