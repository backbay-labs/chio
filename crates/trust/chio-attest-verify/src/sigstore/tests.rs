use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sigstore::bundle::Bundle;
use sigstore::crypto::CosignVerificationKey;
use x509_cert::Certificate;

use crate::{AttestError, ExpectedIdentity};

use super::bundle_verify::{
    bundle_leaf_certificate_der, bundle_rekor_inclusion_verified, bundle_rekor_metadata,
};
use super::compat as sigstore_protobuf_specs_compat;
use super::identity::{match_identity, read_oidc_issuer_extension};
use super::parse::{decode_oidc_issuer_value, parse_certificate_to_der};
use super::policy::IssuerOnlyPolicy;
use super::validators::{
    certificate_validity, is_within_validity_window, map_webpki_error, verify_signature_bytes,
};
use super::{ID_KP_CODE_SIGNING, OIDC_ISSUER_OID, OTHERNAME_OID};

#[cfg(test)]
mod sigstore_internal_tests {
    //! Trust-boundary unit tests that exercise the private helpers
    //! `match_identity`, `read_oidc_issuer_extension`,
    //! `decode_oidc_issuer_value`, `parse_certificate_to_der`, and
    //! `bundle_rekor_metadata` directly. The helpers cannot be reached
    //! from the keyless integration paths without a real Fulcio-issued
    //! cert (see `tests/integration.rs`); these tests build synthetic
    //! certificates with `rcgen` and feed them through the helpers so
    //! that a mutation in `==`, `!=`, branch arms, or the regex anchor
    //! is killed by an assertion that the wrong-input path returns the
    //! documented [`AttestError`] variant.
    //!
    //! No `unwrap` / `expect` is permitted under `src/`, so each fixture
    //! is materialized through an explicit `match` and any unexpected
    //! `Err` short-circuits the test through a `panic!` that names the
    //! input. The lint allow-lists in `tests/` do not extend to this
    //! module.
    #![allow(clippy::panic)]
    #![allow(clippy::missing_panics_doc)]

    use super::*;
    use const_oid::ObjectIdentifier;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, Ia5String, IsCa,
        KeyPair as RcgenKeyPair, SanType, PKCS_ECDSA_P256_SHA256,
    };
    use x509_cert::der::asn1::Utf8StringRef;
    use x509_cert::der::{Decode, Encode};

    const FULCIO_OIDC_ISSUER_OID_STR: &str = "1.3.6.1.4.1.57264.1.1";

    fn build_leaf_with_san_and_issuer(
        san_uri: &str,
        oidc_issuer: Option<&str>,
        wrap_issuer_as_der_utf8string: bool,
    ) -> Vec<u8> {
        let mut params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(err) => panic!("rcgen params: {err}"),
        };
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, "chio-attest-verify-test-leaf");
        let san_value = match Ia5String::try_from(san_uri.to_owned()) {
            Ok(value) => value,
            Err(err) => panic!("invalid SAN ia5 string: {err}"),
        };
        params.subject_alt_names = vec![SanType::URI(san_value)];

        if let Some(issuer_value) = oidc_issuer {
            let oid_components = match parse_oid_components(FULCIO_OIDC_ISSUER_OID_STR) {
                Some(parts) => parts,
                None => panic!("oidc issuer oid string did not parse"),
            };
            let extension_bytes = if wrap_issuer_as_der_utf8string {
                let utf8_ref = match Utf8StringRef::new(issuer_value) {
                    Ok(value) => value,
                    Err(err) => panic!("utf8 string ref: {err}"),
                };
                match utf8_ref.to_der() {
                    Ok(bytes) => bytes,
                    Err(err) => panic!("utf8 string der encode: {err}"),
                }
            } else {
                issuer_value.as_bytes().to_vec()
            };
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &oid_components,
                    extension_bytes,
                ));
        }

        let mut root_params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(err) => panic!("rcgen root params: {err}"),
        };
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "chio-attest-verify-test-root");

        let root_key = match RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
            Ok(k) => k,
            Err(err) => panic!("rcgen root key: {err}"),
        };
        let root_cert = match root_params.self_signed(&root_key) {
            Ok(c) => c,
            Err(err) => panic!("rcgen root self-signed: {err}"),
        };
        let leaf_key = match RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
            Ok(k) => k,
            Err(err) => panic!("rcgen leaf key: {err}"),
        };
        let leaf = match params.signed_by(&leaf_key, &root_cert, &root_key) {
            Ok(c) => c,
            Err(err) => panic!("rcgen leaf signed: {err}"),
        };
        leaf.der().to_vec()
    }

    fn parse_oid_components(s: &str) -> Option<Vec<u64>> {
        s.split('.').map(|c| c.parse::<u64>().ok()).collect()
    }

    fn parse_leaf(leaf_der: &[u8]) -> Certificate {
        match Certificate::from_der(leaf_der) {
            Ok(c) => c,
            Err(err) => panic!("test leaf der parse: {err}"),
        }
    }

    fn ghactions_identity(regex: &str) -> ExpectedIdentity {
        ExpectedIdentity {
            certificate_identity_regexp: regex.to_owned(),
            certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        }
    }

    #[test]
    fn match_identity_accepts_san_uri_with_der_wrapped_issuer() {
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://github.com/backbay-labs/chio/.github/workflows/release.yml@refs/tags/v1.0.0",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let cert = parse_leaf(&leaf_der);
        let result = match_identity(
            &cert,
            &ghactions_identity(r"https://github\.com/backbay-labs/chio/.*"),
        );
        match result {
            Ok(ident) => assert!(
                ident.starts_with("https://github.com/backbay-labs/chio/"),
                "matched SAN must echo the URI: {ident}"
            ),
            Err(err) => panic!("expected SAN match, got {err:?}"),
        }
    }

    #[test]
    fn match_identity_accepts_san_uri_with_raw_utf8_issuer() {
        // Some hand-rolled emitters embed the issuer URL as raw UTF-8
        // bytes rather than wrapping it in a DER UTF8String. The
        // verifier must accept both encodings.
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://github.com/backbay-labs/chio/.github/workflows/release.yml@refs/tags/v1.0.0",
            Some("https://token.actions.githubusercontent.com"),
            false,
        );
        let cert = parse_leaf(&leaf_der);
        let result = match_identity(
            &cert,
            &ghactions_identity(r"https://github\.com/backbay-labs/chio/.*"),
        );
        assert!(
            result.is_ok(),
            "raw-utf8 issuer extension must match: {result:?}"
        );
    }

    #[test]
    fn match_identity_fails_closed_on_issuer_mismatch() {
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://github.com/backbay-labs/chio/x.yml@refs/tags/v1.0.0",
            Some("https://other.example.com"),
            true,
        );
        let cert = parse_leaf(&leaf_der);
        let result = match_identity(
            &cert,
            &ghactions_identity(r"https://github\.com/backbay-labs/chio/.*"),
        );
        match result {
            Err(AttestError::IssuerMismatch) => {}
            other => panic!("expected IssuerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn match_identity_fails_closed_on_missing_issuer_extension() {
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://github.com/backbay-labs/chio/x.yml@refs/tags/v1.0.0",
            None,
            true,
        );
        let cert = parse_leaf(&leaf_der);
        let result = match_identity(
            &cert,
            &ghactions_identity(r"https://github\.com/backbay-labs/chio/.*"),
        );
        match result {
            Err(AttestError::IssuerMismatch) => {}
            other => panic!("expected IssuerMismatch on missing OIDC ext, got {other:?}"),
        }
    }

    #[test]
    fn match_identity_fails_closed_on_san_regex_mismatch() {
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://gitlab.com/some-org/x.yml@refs/tags/v1.0.0",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let cert = parse_leaf(&leaf_der);
        let result = match_identity(
            &cert,
            &ghactions_identity(r"https://github\.com/backbay-labs/chio/.*"),
        );
        match result {
            Err(AttestError::IdentityMismatch) => {}
            other => panic!("expected IdentityMismatch on SAN regex miss, got {other:?}"),
        }
    }

    #[test]
    fn match_identity_anchors_regex_at_both_ends() {
        // Caller-supplied regex omits anchors; verifier must inject
        // `^...$`. A SAN that contains the pattern as a substring (but
        // does not match end-to-end) MUST be rejected.
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://attacker.example.com/?wrap=https://github.com/backbay-labs/chio/x.yml@refs/tags/v1#tail",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let cert = parse_leaf(&leaf_der);
        let result = match_identity(
            &cert,
            &ghactions_identity(r"https://github\.com/backbay-labs/chio/.*"),
        );
        match result {
            Err(AttestError::IdentityMismatch) => {}
            other => panic!("expected anchored regex to reject substring SAN, got {other:?}"),
        }
    }

    #[test]
    fn decode_oidc_issuer_value_accepts_der_utf8string() {
        // 0x0c is the DER tag for UTF8String. The decoder must prefer
        // this path over raw UTF-8 because 0x0c is itself a valid ASCII
        // byte (form feed) and would otherwise be mis-read as part of
        // the issuer URL.
        let issuer = "https://token.actions.githubusercontent.com";
        let utf8_ref = match Utf8StringRef::new(issuer) {
            Ok(v) => v,
            Err(err) => panic!("utf8 ref: {err}"),
        };
        let der_bytes = match utf8_ref.to_der() {
            Ok(b) => b,
            Err(err) => panic!("utf8 der encode: {err}"),
        };
        match decode_oidc_issuer_value(&der_bytes) {
            Ok(decoded) => assert_eq!(decoded, issuer),
            Err(err) => panic!("DER UTF8String must decode: {err:?}"),
        }
    }

    #[test]
    fn decode_oidc_issuer_value_accepts_raw_utf8_url() {
        let issuer = "https://token.actions.githubusercontent.com";
        match decode_oidc_issuer_value(issuer.as_bytes()) {
            Ok(decoded) => assert_eq!(decoded, issuer),
            Err(err) => panic!("raw UTF-8 issuer must decode: {err:?}"),
        }
    }

    #[test]
    fn decode_oidc_issuer_value_rejects_empty_input() {
        match decode_oidc_issuer_value(&[]) {
            Err(AttestError::Malformed(_)) => {}
            other => panic!("empty issuer extension must reject as Malformed: {other:?}"),
        }
    }

    #[test]
    fn decode_oidc_issuer_value_rejects_control_byte_payload() {
        // Bytes that are valid UTF-8 but contain a control character
        // are rejected. This guards the printable filter from being
        // weakened by a mutant flipping `!is_control()` to
        // `is_control()`.
        match decode_oidc_issuer_value(b"https://issuer\x01attack") {
            Err(AttestError::Malformed(_)) => {}
            other => panic!("control byte payload must reject: {other:?}"),
        }
    }

    #[test]
    fn parse_certificate_to_der_accepts_pem() {
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let pem = pem::Pem::new("CERTIFICATE", leaf_der.clone());
        let pem_bytes = pem::encode(&pem).into_bytes();
        match parse_certificate_to_der(&pem_bytes) {
            Ok(der) => assert_eq!(der, leaf_der, "PEM round-trip must yield original DER"),
            Err(err) => panic!("PEM input must decode: {err:?}"),
        }
    }

    #[test]
    fn parse_certificate_to_der_accepts_raw_der() {
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        match parse_certificate_to_der(&leaf_der) {
            Ok(der) => assert_eq!(der, leaf_der),
            Err(err) => panic!("raw DER input must decode: {err:?}"),
        }
    }

    #[test]
    fn parse_certificate_to_der_rejects_non_certificate_pem() {
        // PEM tag mismatch (PUBLIC KEY) MUST fall through to the DER
        // branch and then to the "neither PEM nor DER" error rather
        // than silently accepting non-cert PEM as a leaf.
        let pem = pem::Pem::new("PUBLIC KEY", b"\xAA\xBB\xCC".to_vec());
        let pem_bytes = pem::encode(&pem).into_bytes();
        match parse_certificate_to_der(&pem_bytes) {
            Err(AttestError::Malformed(msg)) => assert!(
                msg.contains("neither PEM nor DER"),
                "unexpected message: {msg}"
            ),
            other => panic!("non-certificate PEM must reject: {other:?}"),
        }
    }

    #[test]
    fn parse_certificate_to_der_rejects_neither_pem_nor_der() {
        // Bytes that do not start with the SEQUENCE tag (0x30) and do
        // not parse as PEM must be rejected.
        match parse_certificate_to_der(&[0x01, 0x02, 0x03]) {
            Err(AttestError::Malformed(_)) => {}
            other => panic!("garbage must reject: {other:?}"),
        }
    }

    #[test]
    fn read_oidc_issuer_extension_returns_value_when_present() {
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let cert = parse_leaf(&leaf_der);
        match read_oidc_issuer_extension(&cert) {
            Ok(value) => assert_eq!(value, "https://token.actions.githubusercontent.com"),
            Err(err) => panic!("issuer extension must read: {err:?}"),
        }
    }

    #[test]
    fn read_oidc_issuer_extension_fails_closed_when_absent() {
        let leaf_der =
            build_leaf_with_san_and_issuer("https://example.com/x.yml@refs/tags/v1", None, true);
        let cert = parse_leaf(&leaf_der);
        match read_oidc_issuer_extension(&cert) {
            Err(AttestError::IssuerMismatch) => {}
            other => panic!("missing extension must surface IssuerMismatch: {other:?}"),
        }
    }

    #[test]
    fn issuer_only_policy_accepts_matching_issuer_and_rejects_mismatch() {
        use sigstore::bundle::verify::policy::VerificationPolicy;

        let matching_leaf = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let cert_match = parse_leaf(&matching_leaf);
        let policy = IssuerOnlyPolicy {
            expected_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        };
        match policy.verify(&cert_match) {
            Ok(()) => {}
            Err(err) => panic!("matching issuer must accept: {err:?}"),
        }

        let mismatch_leaf = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://attacker.example.com"),
            true,
        );
        let cert_mismatch = parse_leaf(&mismatch_leaf);
        match policy.verify(&cert_mismatch) {
            Err(_) => {}
            Ok(()) => panic!("non-matching issuer must reject"),
        }
    }

    #[test]
    fn certificate_oid_constants_match_documented_values() {
        // Guards the OID constants against accidental edits. The
        // documented values are pinned by the Fulcio docs page cited
        // in `src/sigstore.rs`.
        assert_eq!(
            OIDC_ISSUER_OID,
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1")
        );
        assert_eq!(
            OTHERNAME_OID,
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.7")
        );
        assert_eq!(
            ID_KP_CODE_SIGNING,
            ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3")
        );
    }

    #[test]
    fn bundled_rekor_materials_do_not_imply_chio_inclusion_verification() {
        use sigstore_protobuf_specs::dev::sigstore::{
            bundle::v1::{verification_material, Bundle, VerificationMaterial},
            common::v1::{LogId, X509Certificate},
            rekor::v1::{
                Checkpoint, InclusionPromise, InclusionProof, KindVersion, TransparencyLogEntry,
            },
        };

        let bundle = Bundle {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".to_owned(),
            content: None,
            verification_material: Some(VerificationMaterial {
                content: Some(verification_material::Content::Certificate(
                    X509Certificate {
                        raw_bytes: vec![0x30],
                    },
                )),
                tlog_entries: vec![TransparencyLogEntry {
                    log_index: 42,
                    log_id: Some(LogId {
                        key_id: vec![1, 2, 3],
                    }),
                    kind_version: Some(KindVersion {
                        kind: "hashedrekord".to_owned(),
                        version: "0.0.1".to_owned(),
                    }),
                    integrated_time: 1_700_000_000,
                    inclusion_promise: Some(InclusionPromise {
                        signed_entry_timestamp: vec![4, 5, 6],
                    }),
                    inclusion_proof: Some(InclusionProof {
                        log_index: 42,
                        root_hash: vec![7; 32],
                        tree_size: 64,
                        hashes: vec![vec![8; 32], vec![9; 32]],
                        checkpoint: Some(Checkpoint {
                            envelope:
                                "rekor.sigstore.dev - 1193050959916656506\n64\nroot\n\n-signature"
                                    .to_owned(),
                        }),
                    }),
                    canonicalized_body: br#"{"kind":"hashedrekord"}"#.to_vec(),
                }],
                timestamp_verification_data: None,
            }),
        };

        assert!(
            !bundle_rekor_inclusion_verified(&bundle),
            "Chio must not report Rekor inclusion as verified from bundled materials until it verifies the Merkle proof and SET itself"
        );
    }

    // -----------------------------------------------------------------
    // Bundle helper tests: build sigstore_protobuf_specs Bundle structs
    // from scratch and feed them through the private compat helpers so
    // mutants in the bundle field walk are killed by direct assertions.
    // -----------------------------------------------------------------

    use sigstore_protobuf_specs::dev::sigstore::{
        bundle::v1::{verification_material, Bundle as ProtoBundle, VerificationMaterial},
        common::v1::{LogId, X509Certificate, X509CertificateChain},
        rekor::v1::{KindVersion, TransparencyLogEntry},
    };

    fn build_bundle_with_x509_chain(certs: Vec<Vec<u8>>) -> Bundle {
        let chain = X509CertificateChain {
            certificates: certs
                .into_iter()
                .map(|raw| X509Certificate { raw_bytes: raw })
                .collect(),
        };
        ProtoBundle {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".to_owned(),
            content: None,
            verification_material: Some(VerificationMaterial {
                content: Some(verification_material::Content::X509CertificateChain(chain)),
                tlog_entries: Vec::new(),
                timestamp_verification_data: None,
            }),
        }
    }

    fn build_bundle_with_single_certificate(raw: Vec<u8>) -> Bundle {
        ProtoBundle {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".to_owned(),
            content: None,
            verification_material: Some(VerificationMaterial {
                content: Some(verification_material::Content::Certificate(
                    X509Certificate { raw_bytes: raw },
                )),
                tlog_entries: Vec::new(),
                timestamp_verification_data: None,
            }),
        }
    }

    fn build_bundle_without_verification_material() -> Bundle {
        ProtoBundle {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".to_owned(),
            content: None,
            verification_material: None,
        }
    }

    fn build_bundle_with_rekor_entry(log_index: i64, integrated_time: i64) -> Bundle {
        ProtoBundle {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".to_owned(),
            content: None,
            verification_material: Some(VerificationMaterial {
                content: Some(verification_material::Content::Certificate(
                    X509Certificate {
                        raw_bytes: vec![0x30, 0x00],
                    },
                )),
                tlog_entries: vec![TransparencyLogEntry {
                    log_index,
                    log_id: Some(LogId {
                        key_id: vec![0xab, 0xcd],
                    }),
                    kind_version: Some(KindVersion {
                        kind: "hashedrekord".to_owned(),
                        version: "0.0.1".to_owned(),
                    }),
                    integrated_time,
                    inclusion_promise: None,
                    inclusion_proof: None,
                    canonicalized_body: br#"{"kind":"hashedrekord"}"#.to_vec(),
                }],
                timestamp_verification_data: None,
            }),
        }
    }

    fn build_bundle_without_tlog_entries() -> Bundle {
        ProtoBundle {
            media_type: "application/vnd.dev.sigstore.bundle+json;version=0.2".to_owned(),
            content: None,
            verification_material: Some(VerificationMaterial {
                content: Some(verification_material::Content::Certificate(
                    X509Certificate {
                        raw_bytes: vec![0x30, 0x00],
                    },
                )),
                tlog_entries: Vec::new(),
                timestamp_verification_data: None,
            }),
        }
    }

    // -----------------------------------------------------------------
    // sigstore_protobuf_specs_compat::leaf_der
    // -----------------------------------------------------------------

    #[test]
    fn leaf_der_returns_first_cert_from_x509_chain() {
        // Kills: replace leaf_der -> Some(vec![]),
        //        replace leaf_der -> Some(vec![0]),
        //        replace leaf_der -> Some(vec![1]),
        //        delete match arm verification_material::Content::X509CertificateChain.
        let first = vec![0x30, 0xAA, 0xBB, 0xCC];
        let second = vec![0x30, 0xDD, 0xEE];
        let bundle = build_bundle_with_x509_chain(vec![first.clone(), second.clone()]);
        let extracted = sigstore_protobuf_specs_compat::leaf_der(&bundle);
        match extracted {
            Some(bytes) => {
                assert_eq!(
                    bytes, first,
                    "leaf_der must return the FIRST certificate in the chain, not the last or empty"
                );
                assert_ne!(
                    bytes, second,
                    "leaf_der must not return the second certificate"
                );
                assert!(
                    !bytes.is_empty(),
                    "leaf_der must not return an empty Vec for a populated chain"
                );
                assert_ne!(
                    bytes,
                    vec![0u8],
                    "leaf_der must echo the actual cert bytes, not a constant"
                );
                assert_ne!(
                    bytes,
                    vec![1u8],
                    "leaf_der must echo the actual cert bytes, not a constant"
                );
            }
            None => panic!("leaf_der must surface the first cert from a populated chain"),
        }
    }

    #[test]
    fn leaf_der_returns_certificate_bytes_from_single_certificate_variant() {
        // Kills: delete match arm verification_material::Content::Certificate,
        //        replace leaf_der -> Some(vec![]),
        //        replace leaf_der -> Some(vec![0]),
        //        replace leaf_der -> Some(vec![1]),
        //        replace leaf_der -> None.
        let raw = vec![0x30, 0x82, 0x10, 0x00];
        let bundle = build_bundle_with_single_certificate(raw.clone());
        match sigstore_protobuf_specs_compat::leaf_der(&bundle) {
            Some(bytes) => {
                assert_eq!(
                    bytes, raw,
                    "leaf_der must echo the Certificate variant raw bytes"
                );
                assert!(
                    !bytes.is_empty(),
                    "leaf_der must not return empty for a populated single-cert variant"
                );
                assert_ne!(bytes, vec![0u8]);
                assert_ne!(bytes, vec![1u8]);
            }
            None => panic!("leaf_der must succeed on the Certificate variant"),
        }
    }

    #[test]
    fn leaf_der_returns_none_when_verification_material_missing() {
        // Kills: replace leaf_der -> Some(vec![]),
        //        replace leaf_der -> Some(vec![0]),
        //        replace leaf_der -> Some(vec![1]).
        let bundle = build_bundle_without_verification_material();
        assert!(
            sigstore_protobuf_specs_compat::leaf_der(&bundle).is_none(),
            "leaf_der MUST be None when verification_material is absent"
        );
    }

    #[test]
    fn leaf_der_returns_none_when_x509_chain_is_empty() {
        // Kills: replace leaf_der -> Some(vec![]),
        //        replace leaf_der -> Some(vec![0]),
        //        replace leaf_der -> Some(vec![1]),
        //        delete match arm X509CertificateChain (since empty chain
        //        must return None, while the mutant's deleted arm would
        //        skip past to either Certificate (n/a) or fall through).
        let bundle = build_bundle_with_x509_chain(Vec::new());
        assert!(
            sigstore_protobuf_specs_compat::leaf_der(&bundle).is_none(),
            "leaf_der MUST be None when the X.509 chain has no certificates"
        );
    }

    // -----------------------------------------------------------------
    // sigstore_protobuf_specs_compat::rekor_metadata
    // -----------------------------------------------------------------

    #[test]
    fn rekor_metadata_extracts_log_index_and_integrated_time() {
        // Kills every Some((const, const)) replacement at line 579 plus
        // the None replacement: distinct (log_index, integrated_time)
        // values must round-trip through the helper.
        let bundle = build_bundle_with_rekor_entry(98_765_432, 1_700_000_000);
        match sigstore_protobuf_specs_compat::rekor_metadata(&bundle) {
            Some((index, integrated)) => {
                assert_eq!(index, 98_765_432, "log_index must round-trip exactly");
                assert_eq!(
                    integrated, 1_700_000_000,
                    "integrated_time must round-trip exactly"
                );
                assert_ne!(index, 0, "log_index must not collapse to a constant 0");
                assert_ne!(index, 1, "log_index must not collapse to a constant 1");
                assert_ne!(integrated, 0);
                assert_ne!(integrated, 1);
                assert_ne!(integrated, -1);
            }
            None => panic!("rekor_metadata must surface metadata when an entry exists"),
        }
    }

    #[test]
    fn rekor_metadata_returns_none_when_no_tlog_entries() {
        // Kills: replace rekor_metadata -> Some((0, 0)),
        //        replace rekor_metadata -> Some((0, 1)),
        //        replace rekor_metadata -> Some((1, 0)),
        //        replace rekor_metadata -> Some((1, 1)),
        //        replace rekor_metadata -> Some((0, -1)),
        //        replace rekor_metadata -> Some((1, -1)).
        let bundle = build_bundle_without_tlog_entries();
        assert!(
            sigstore_protobuf_specs_compat::rekor_metadata(&bundle).is_none(),
            "rekor_metadata MUST be None when tlog_entries is empty"
        );
    }

    #[test]
    fn rekor_metadata_returns_none_when_verification_material_missing() {
        // Kills: replace rekor_metadata -> Some((0, 0)),
        //        replace rekor_metadata -> Some((0, 1)),
        //        replace rekor_metadata -> Some((1, 0)),
        //        replace rekor_metadata -> Some((1, 1)),
        //        replace rekor_metadata -> Some((0, -1)),
        //        replace rekor_metadata -> Some((1, -1)).
        let bundle = build_bundle_without_verification_material();
        assert!(
            sigstore_protobuf_specs_compat::rekor_metadata(&bundle).is_none(),
            "rekor_metadata MUST be None when verification_material is absent"
        );
    }

    // -----------------------------------------------------------------
    // bundle_leaf_certificate_der
    // -----------------------------------------------------------------

    #[test]
    fn bundle_leaf_certificate_der_returns_actual_bytes_not_constant() {
        // Kills: replace bundle_leaf_certificate_der -> Ok(vec![]),
        //        replace bundle_leaf_certificate_der -> Ok(vec![0]),
        //        replace bundle_leaf_certificate_der -> Ok(vec![1]).
        let raw = vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let bundle = build_bundle_with_single_certificate(raw.clone());
        match bundle_leaf_certificate_der(&bundle) {
            Ok(bytes) => {
                assert_eq!(
                    bytes, raw,
                    "bundle_leaf_certificate_der must echo the bundle's raw cert bytes"
                );
                assert!(
                    !bytes.is_empty(),
                    "bundle_leaf_certificate_der must not return an empty Vec"
                );
                assert_ne!(
                    bytes,
                    vec![0u8],
                    "bundle_leaf_certificate_der must not collapse to vec![0]"
                );
                assert_ne!(
                    bytes,
                    vec![1u8],
                    "bundle_leaf_certificate_der must not collapse to vec![1]"
                );
            }
            Err(err) => panic!("bundle_leaf_certificate_der must succeed: {err:?}"),
        }
    }

    #[test]
    fn bundle_leaf_certificate_der_fails_closed_when_no_material() {
        // Kills: replace bundle_leaf_certificate_der -> Ok(vec![]),
        //        replace bundle_leaf_certificate_der -> Ok(vec![0]),
        //        replace bundle_leaf_certificate_der -> Ok(vec![1]).
        let bundle = build_bundle_without_verification_material();
        match bundle_leaf_certificate_der(&bundle) {
            Err(AttestError::Malformed(msg)) => assert!(
                msg.contains("no leaf certificate"),
                "unexpected malformed message: {msg}"
            ),
            other => {
                panic!("missing verification_material must surface Malformed, got {other:?}")
            }
        }
    }

    // -----------------------------------------------------------------
    // bundle_rekor_metadata
    // -----------------------------------------------------------------

    #[test]
    fn bundle_rekor_metadata_uses_integrated_time_when_positive() {
        // Kills: replace > with < in bundle_rekor_metadata,
        //        replace > with == in bundle_rekor_metadata,
        //        replace > with >= in bundle_rekor_metadata (when
        //        integrated == 0 the >= mutant would still take the
        //        positive branch and leak SystemTime::now-derived values),
        //        replace + with - / + with * in bundle_rekor_metadata.
        let integrated_seconds: i64 = 1_700_000_000;
        let bundle = build_bundle_with_rekor_entry(42, integrated_seconds);
        let (index, signed_at) = bundle_rekor_metadata(&bundle);
        assert_eq!(index, 42, "log_index must propagate from the entry");
        let expected = UNIX_EPOCH + Duration::from_secs(integrated_seconds as u64);
        assert_eq!(
            signed_at, expected,
            "signed_at MUST be UNIX_EPOCH + integrated_time when integrated_time > 0"
        );
        // Subtract: assert that a `+ -> -` mutant would produce a wrong
        // value. UNIX_EPOCH - duration is undefined for sufficiently
        // large `duration`, but the equality above already forbids the
        // subtract path on this fixture.
    }

    #[test]
    fn bundle_rekor_metadata_falls_back_to_now_when_integrated_time_is_zero() {
        // Kills: replace > with < (would take positive branch when
        //        integrated == 0, returning UNIX_EPOCH),
        //        replace > with == (would take positive branch when 0),
        //        replace > with >= (would take positive branch when 0).
        let before = SystemTime::now();
        let bundle = build_bundle_with_rekor_entry(7, 0);
        let (_, signed_at) = bundle_rekor_metadata(&bundle);
        let after = SystemTime::now();
        // Branch-correct path: signed_at must be SystemTime::now() at
        // call-time, NOT UNIX_EPOCH. Anchor with a tight window.
        assert!(
            signed_at >= before && signed_at <= after,
            "signed_at must be SystemTime::now() when integrated_time == 0; got {signed_at:?}, window=[{before:?}, {after:?}]"
        );
        let unix_epoch_lower_bound = UNIX_EPOCH + Duration::from_secs(60 * 60 * 24);
        assert!(
            signed_at > unix_epoch_lower_bound,
            "signed_at must NOT collapse to UNIX_EPOCH branch when integrated_time == 0"
        );
    }

    #[test]
    fn bundle_rekor_metadata_falls_back_to_now_when_integrated_time_is_negative() {
        // Kills: replace > with < in bundle_rekor_metadata.
        let before = SystemTime::now();
        let bundle = build_bundle_with_rekor_entry(7, -42);
        let (_, signed_at) = bundle_rekor_metadata(&bundle);
        let after = SystemTime::now();
        assert!(
            signed_at >= before && signed_at <= after,
            "signed_at must be SystemTime::now() when integrated_time is negative"
        );
    }

    #[test]
    fn bundle_rekor_metadata_returns_zero_index_and_now_when_no_entry() {
        // Kills: replace rekor_metadata -> Some((1, _)) variants, since
        //        the surrounding bundle_rekor_metadata maps None to
        //        (0, now) and a Some((1, _)) mutant would yield index 1.
        let before = SystemTime::now();
        let bundle = build_bundle_without_tlog_entries();
        let (index, signed_at) = bundle_rekor_metadata(&bundle);
        let after = SystemTime::now();
        assert_eq!(
            index, 0,
            "bundle_rekor_metadata must yield index 0 when no entry"
        );
        assert!(
            signed_at >= before && signed_at <= after,
            "signed_at must be SystemTime::now() when no rekor entry"
        );
    }

    // -----------------------------------------------------------------
    // certificate_validity boundary arithmetic
    // -----------------------------------------------------------------

    #[test]
    fn certificate_validity_returns_unix_offset_for_not_before_and_not_after() {
        // Kills: replace + with - in certificate_validity (line 480),
        //        replace + with - in certificate_validity (line 481).
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let cert = parse_leaf(&leaf_der);
        match certificate_validity(&cert) {
            Ok((not_before, not_after)) => {
                // Synthetic certs minted by `rcgen` carry post-1970
                // validity windows. UNIX_EPOCH + duration must be >=
                // UNIX_EPOCH; UNIX_EPOCH - duration would be unrepresentable
                // (which `SystemTime` saturates differently per platform)
                // but more importantly < UNIX_EPOCH for any non-zero
                // duration. Anchor the assertion against UNIX_EPOCH.
                assert!(
                    not_before >= UNIX_EPOCH,
                    "not_before must be >= UNIX_EPOCH (mutant `+` -> `-` would fail this)"
                );
                assert!(
                    not_after >= UNIX_EPOCH,
                    "not_after must be >= UNIX_EPOCH (mutant `+` -> `-` would fail this)"
                );
                // not_after must be strictly after not_before for any
                // sensibly-issued cert, including rcgen's defaults.
                assert!(
                    not_after > not_before,
                    "not_after must be strictly after not_before; got nb={not_before:?} na={not_after:?}"
                );
                // `+ -> -` would also collapse the window: a one-second
                // certificate at unix 1700000000 would yield not_before
                // ≈ 1970-01-01 - 53 years vs not_after ≈ 1970-01-01 - 53
                // years, both well below "now".
                let now = SystemTime::now();
                assert!(
                    not_after > UNIX_EPOCH + Duration::from_secs(60 * 60 * 24 * 365 * 50),
                    "not_after must land in this century, not 1970 (mutant `+` -> `-` would fail)"
                );
                // Sanity: `now` should fall inside the rcgen-default
                // validity window (~10 years from minting).
                assert!(
                    now >= not_before && now <= not_after,
                    "rcgen leaf must be valid right now: now={now:?} window=[{not_before:?},{not_after:?}]"
                );
            }
            Err(err) => panic!("certificate_validity must succeed for a synthetic leaf: {err:?}"),
        }
    }

    // -----------------------------------------------------------------
    // is_within_validity_window boundary
    // -----------------------------------------------------------------

    #[test]
    fn is_within_validity_window_accepts_at_lower_bound() {
        // Kills: replace < with > / == / <= at line 163 col 16
        //        (now < not_before) by asserting now == not_before is
        //        accepted (the production code uses `<` so equality is
        //        accepted; a `<=` mutant would reject equality).
        let not_before = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = not_before + Duration::from_secs(3600);
        assert!(
            is_within_validity_window(not_before, not_before, not_after),
            "now == not_before MUST be accepted; `< -> <=` mutant would reject"
        );
    }

    #[test]
    fn is_within_validity_window_rejects_below_lower_bound() {
        // Kills: replace < with > / == at line 163.
        let not_before = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = not_before + Duration::from_secs(3600);
        let too_early = not_before - Duration::from_secs(1);
        assert!(
            !is_within_validity_window(too_early, not_before, not_after),
            "now < not_before MUST be rejected; `< -> >` and `< -> ==` mutants would accept"
        );
    }

    #[test]
    fn is_within_validity_window_accepts_at_upper_bound() {
        // Kills: replace > with == / >= at line 163 col 36.
        let not_before = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = not_before + Duration::from_secs(3600);
        assert!(
            is_within_validity_window(not_after, not_before, not_after),
            "now == not_after MUST be accepted; `> -> >=` mutant would reject"
        );
    }

    #[test]
    fn is_within_validity_window_rejects_above_upper_bound() {
        // Kills: replace > with < / == at line 163 col 36.
        let not_before = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = not_before + Duration::from_secs(3600);
        let too_late = not_after + Duration::from_secs(1);
        assert!(
            !is_within_validity_window(too_late, not_before, not_after),
            "now > not_after MUST be rejected; `> -> <` and `> -> ==` mutants would accept"
        );
    }

    #[test]
    fn is_within_validity_window_rejects_below_when_above_upper_bound_is_false() {
        // Kills: replace || with && at line 163 col 29.
        // Construct: now < not_before AND NOT (now > not_after).
        // Production: `now < not_before || now > not_after` -> true (reject).
        // Mutant && : `now < not_before && now > not_after` -> false (accept).
        // So the validity window check must REJECT (not within).
        let not_before = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = not_before + Duration::from_secs(3600);
        let too_early = not_before - Duration::from_secs(1);
        assert!(
            !is_within_validity_window(too_early, not_before, not_after),
            "too-early input must be rejected; `|| -> &&` mutant would treat too-early as in-window"
        );
    }

    #[test]
    fn is_within_validity_window_accepts_within_window() {
        let not_before = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let not_after = not_before + Duration::from_secs(3600);
        let middle = not_before + Duration::from_secs(1800);
        assert!(
            is_within_validity_window(middle, not_before, not_after),
            "middle-of-window input must be accepted"
        );
    }

    // -----------------------------------------------------------------
    // verify_signature_bytes
    // -----------------------------------------------------------------

    #[test]
    fn verify_signature_bytes_rejects_random_signature_bytes() {
        // Kills: replace verify_signature_bytes -> Result<(), AttestError>
        //        with Ok(()).
        // Strategy: build a real ECDSA P-256 leaf via rcgen, then feed
        // an obviously-wrong signature. The production code MUST surface
        // SignatureMismatch; the mutant Ok(()) would silently accept.
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let leaf_cert = parse_leaf(&leaf_der);
        let key = match CosignVerificationKey::try_from(
            &leaf_cert.tbs_certificate.subject_public_key_info,
        ) {
            Ok(k) => k,
            Err(err) => panic!("rcgen leaf SPKI must be cosign-compatible: {err}"),
        };
        // Plain garbage: not base64, not a valid raw DER ECDSA sig.
        let bad_signature = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09";
        let artifact = b"hello world";
        match verify_signature_bytes(&key, bad_signature, artifact) {
            Err(AttestError::SignatureMismatch) => {}
            other => panic!(
                "garbage signature MUST yield SignatureMismatch (mutant Ok(()) would accept); got {other:?}"
            ),
        }
    }

    #[test]
    fn verify_signature_bytes_rejects_empty_signature() {
        // Kills: replace verify_signature_bytes -> Ok(()).
        let leaf_der = build_leaf_with_san_and_issuer(
            "https://example.com/x.yml@refs/tags/v1",
            Some("https://token.actions.githubusercontent.com"),
            true,
        );
        let leaf_cert = parse_leaf(&leaf_der);
        let key = match CosignVerificationKey::try_from(
            &leaf_cert.tbs_certificate.subject_public_key_info,
        ) {
            Ok(k) => k,
            Err(err) => panic!("rcgen leaf SPKI must be cosign-compatible: {err}"),
        };
        match verify_signature_bytes(&key, b"", b"hello world") {
            Err(AttestError::SignatureMismatch) => {}
            other => {
                panic!("empty signature MUST yield SignatureMismatch; got {other:?}")
            }
        }
    }

    // -----------------------------------------------------------------
    // map_webpki_error
    // -----------------------------------------------------------------

    #[test]
    fn map_webpki_error_maps_cert_expired_to_certificate_expired() {
        // Kills: delete match arm webpki::Error::CertNotValidYet{..} |
        //        webpki::Error::CertExpired{..} (line 377).
        match map_webpki_error(webpki::Error::CertExpired {
            time: pki_types::UnixTime::since_unix_epoch(Duration::from_secs(0)),
            not_after: pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1)),
        }) {
            AttestError::CertificateExpired => {}
            other => panic!("CertExpired must map to CertificateExpired, got {other:?}"),
        }
    }

    #[test]
    fn map_webpki_error_maps_cert_not_yet_valid_to_certificate_expired() {
        // Kills: delete match arm webpki::Error::CertNotValidYet{..} |
        //        webpki::Error::CertExpired{..} (line 377).
        match map_webpki_error(webpki::Error::CertNotValidYet {
            time: pki_types::UnixTime::since_unix_epoch(Duration::from_secs(0)),
            not_before: pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1)),
        }) {
            AttestError::CertificateExpired => {}
            other => panic!("CertNotValidYet must map to CertificateExpired, got {other:?}"),
        }
    }

    #[test]
    fn map_webpki_error_maps_unknown_issuer_to_trust_root() {
        // Kills: delete match arm webpki::Error::UnknownIssuer (line 380).
        match map_webpki_error(webpki::Error::UnknownIssuer) {
            AttestError::TrustRoot => {}
            other => panic!("UnknownIssuer must map to TrustRoot, got {other:?}"),
        }
    }

    #[test]
    fn map_webpki_error_maps_other_errors_to_malformed() {
        // Sanity check that non-special-cased errors fall through to
        // Malformed. This guards the wildcard arm against accidental
        // promotion of TrustRoot or CertificateExpired beyond their
        // intended cases.
        match map_webpki_error(webpki::Error::BadDer) {
            AttestError::Malformed(msg) => {
                assert!(
                    msg.contains("BadDer") || msg.contains("certificate"),
                    "Malformed message should include the chained error: {msg}"
                );
            }
            other => panic!("non-special webpki error must map to Malformed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // match_identity SAN handling
    // -----------------------------------------------------------------

    fn build_leaf_with_rfc822_san_and_issuer(rfc822: &str, oidc_issuer: &str) -> Vec<u8> {
        // Build a certificate whose SAN contains an Rfc822Name (email
        // address). Used to kill the `delete match arm
        // GeneralName::Rfc822Name(s)` mutant in match_identity.
        let mut params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(err) => panic!("rcgen params: {err}"),
        };
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, "chio-attest-verify-rfc822-leaf");
        let san_value = match Ia5String::try_from(rfc822.to_owned()) {
            Ok(value) => value,
            Err(err) => panic!("invalid SAN ia5 string: {err}"),
        };
        params.subject_alt_names = vec![SanType::Rfc822Name(san_value)];

        let oid_components = match parse_oid_components(FULCIO_OIDC_ISSUER_OID_STR) {
            Some(parts) => parts,
            None => panic!("oidc issuer oid string did not parse"),
        };
        let utf8_ref = match Utf8StringRef::new(oidc_issuer) {
            Ok(value) => value,
            Err(err) => panic!("utf8 string ref: {err}"),
        };
        let extension_bytes = match utf8_ref.to_der() {
            Ok(bytes) => bytes,
            Err(err) => panic!("utf8 string der encode: {err}"),
        };
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &oid_components,
                extension_bytes,
            ));

        let mut root_params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(err) => panic!("rcgen root params: {err}"),
        };
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "chio-attest-verify-rfc822-root");

        let root_key = match RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
            Ok(k) => k,
            Err(err) => panic!("rcgen root key: {err}"),
        };
        let root_cert = match root_params.self_signed(&root_key) {
            Ok(c) => c,
            Err(err) => panic!("rcgen root self-signed: {err}"),
        };
        let leaf_key = match RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
            Ok(k) => k,
            Err(err) => panic!("rcgen leaf key: {err}"),
        };
        let leaf = match params.signed_by(&leaf_key, &root_cert, &root_key) {
            Ok(c) => c,
            Err(err) => panic!("rcgen leaf signed: {err}"),
        };
        leaf.der().to_vec()
    }

    #[test]
    fn match_identity_accepts_rfc822_san_when_regex_matches() {
        // Kills: delete match arm GeneralName::Rfc822Name(s) at line 412.
        // The mutant deletes the Rfc822Name arm, so an Rfc822-only SAN
        // would yield IdentityMismatch. The production code MUST accept.
        let leaf_der = build_leaf_with_rfc822_san_and_issuer(
            "release@chio.example.com",
            "https://token.actions.githubusercontent.com",
        );
        let cert = parse_leaf(&leaf_der);
        let identity = ExpectedIdentity {
            certificate_identity_regexp: r"release@chio\.example\.com".to_owned(),
            certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        };
        match match_identity(&cert, &identity) {
            Ok(matched) => assert_eq!(
                matched, "release@chio.example.com",
                "Rfc822 SAN must round-trip to the matched identity"
            ),
            Err(err) => panic!(
                "Rfc822-only SAN regex match MUST accept (delete-arm mutant would fail): {err:?}"
            ),
        }
    }

    fn build_leaf_with_othername_san_and_issuer(
        san_value: &[u8],
        san_type_oid: &str,
        oidc_issuer: &str,
    ) -> Vec<u8> {
        // Build a cert whose SAN contains an OtherName entry with a
        // chosen type-id OID. The Sigstore OtherName OID is
        // 1.3.6.1.4.1.57264.1.7. Other OIDs MUST be ignored by the
        // verifier (the production code's match guard rejects them).
        use rcgen::OtherNameValue;

        let mut params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(err) => panic!("rcgen params: {err}"),
        };
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, "chio-attest-verify-othername-leaf");
        let oid_components = match parse_oid_components(san_type_oid) {
            Some(parts) => parts,
            None => panic!("san othername oid string did not parse"),
        };
        let utf8_san = match std::str::from_utf8(san_value) {
            Ok(s) => s.to_owned(),
            Err(err) => panic!("non-utf8 othername value in test fixture: {err}"),
        };
        params.subject_alt_names = vec![SanType::OtherName((
            oid_components,
            OtherNameValue::Utf8String(utf8_san),
        ))];

        let issuer_oid_components = match parse_oid_components(FULCIO_OIDC_ISSUER_OID_STR) {
            Some(parts) => parts,
            None => panic!("oidc issuer oid string did not parse"),
        };
        let utf8_ref = match Utf8StringRef::new(oidc_issuer) {
            Ok(value) => value,
            Err(err) => panic!("utf8 string ref: {err}"),
        };
        let extension_bytes = match utf8_ref.to_der() {
            Ok(bytes) => bytes,
            Err(err) => panic!("utf8 string der encode: {err}"),
        };
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &issuer_oid_components,
                extension_bytes,
            ));

        let mut root_params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(err) => panic!("rcgen root params: {err}"),
        };
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "chio-attest-verify-othername-root");

        let root_key = match RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
            Ok(k) => k,
            Err(err) => panic!("rcgen root key: {err}"),
        };
        let root_cert = match root_params.self_signed(&root_key) {
            Ok(c) => c,
            Err(err) => panic!("rcgen root self-signed: {err}"),
        };
        let leaf_key = match RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
            Ok(k) => k,
            Err(err) => panic!("rcgen leaf key: {err}"),
        };
        let leaf = match params.signed_by(&leaf_key, &root_cert, &root_key) {
            Ok(c) => c,
            Err(err) => panic!("rcgen leaf signed: {err}"),
        };
        leaf.der().to_vec()
    }

    #[test]
    fn match_identity_rejects_othername_with_wrong_type_id_oid() {
        // Kills:
        // - replace match guard other.type_id == OTHERNAME_OID with true
        //   (line 414 col 46): mutant accepts ANY OtherName, including
        //   foreign-OID ones, so this regex-matching value would pass.
        //   Production code MUST reject because the OID does not match
        //   the Sigstore OtherName OID.
        let foreign_oid = "1.3.6.1.4.1.99999.1"; // not OTHERNAME_OID.
        let san_value = b"https://github.com/backbay-labs/chio/x.yml";
        let leaf_der = build_leaf_with_othername_san_and_issuer(
            san_value,
            foreign_oid,
            "https://token.actions.githubusercontent.com",
        );
        let cert = parse_leaf(&leaf_der);
        let identity = ExpectedIdentity {
            certificate_identity_regexp: r"https://github\.com/backbay-labs/chio/.*".to_owned(),
            certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        };
        match match_identity(&cert, &identity) {
            Err(AttestError::IdentityMismatch) => {}
            other => panic!(
                "OtherName with foreign type-id OID MUST be rejected (mutant `== -> true` would accept): {other:?}"
            ),
        }
    }

    #[test]
    fn match_identity_accepts_othername_with_sigstore_type_id_oid() {
        // Kills:
        // - replace match guard other.type_id == OTHERNAME_OID with false
        //   (line 414 col 46): mutant rejects all OtherName entries,
        //   including the Sigstore-specific ones. Production code MUST
        //   accept the Sigstore OtherName OID.
        // - replace == with != in match guard (line 414 col 60): mutant
        //   would invert the OID acceptance, rejecting the Sigstore OID
        //   and accepting foreign OIDs. The Sigstore-OID input here
        //   would yield IdentityMismatch under the mutant.
        let sigstore_oid = "1.3.6.1.4.1.57264.1.7";
        let san_value = b"https://github.com/backbay-labs/chio/release.yml@refs/tags/v1";
        let leaf_der = build_leaf_with_othername_san_and_issuer(
            san_value,
            sigstore_oid,
            "https://token.actions.githubusercontent.com",
        );
        let cert = parse_leaf(&leaf_der);
        let identity = ExpectedIdentity {
            certificate_identity_regexp: r"https://github\.com/backbay-labs/chio/.*".to_owned(),
            certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
        };
        match match_identity(&cert, &identity) {
            Ok(matched) => assert!(
                matched.starts_with("https://github.com/backbay-labs/chio/"),
                "Sigstore OtherName SAN must round-trip to the matched identity, got {matched}"
            ),
            Err(err) => panic!(
                "Sigstore OtherName SAN MUST be accepted (mutant `== -> false` and `== -> !=` would reject): {err:?}"
            ),
        }
    }
}
