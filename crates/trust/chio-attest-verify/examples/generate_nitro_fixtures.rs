//! Deterministically regenerate the pinned AWS Nitro NSM fixture
//! corpus under `crates/trust/chio-attest-verify/fixtures/quotes/nitro/`.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p chio-attest-verify --example generate_nitro_fixtures \
//!     --features tee-quotes
//! ```
//!
//! The generator writes positive and negative Nitro NSM attestation
//! documents wrapped in COSE_Sign1 envelopes, and refreshes the
//! MANIFEST.toml entries (file name, role, role tag, note, and SHA256
//! digest). Reviewers verify a fixture matches its manifest digest by
//! re-running this binary and diffing the working tree against HEAD.
//!
//! The fixture envelope is deterministic: the kernel keypair seed,
//! the receipt root, the launch digest (PCR0), the NSM leaf bytes,
//! and the embedded AWS Nitro root all live in this file or in the
//! pinned `fixtures/nitro/aws-nitro-root.pem`. No randomness or
//! wall-clock state enters the output.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(not(feature = "tee-quotes"))]
fn main() {
    eprintln!("rebuild with --features tee-quotes to regenerate the Nitro fixture corpus");
    std::process::exit(2);
}

#[cfg(feature = "tee-quotes")]
fn main() {
    inner::run();
}

#[cfg(feature = "tee-quotes")]
mod inner {
    use std::fs;
    use std::path::PathBuf;

    use chio_attest_verify::expect_report_data;
    use chio_core_types::crypto::Keypair;
    use coset::cbor::Value as CborValue;
    use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
    use p384::ecdsa::{
        signature::Signer as _, Signature as P384Signature, SigningKey, VerifyingKey,
    };
    use sha2::{Digest, Sha256};

    pub(super) const KERNEL_SEED: [u8; 32] = [9u8; 32];
    pub(super) const RECEIPT_ROOT: [u8; 32] = [8u8; 32];
    pub(super) const PINNED_PCR0: [u8; 48] = [0x77u8; 48];
    pub(super) const TIMESTAMP_MS: u64 = 1_700_000_000_000;
    const NITRO_ATTESTATION_KEY_SEED: [u8; 48] = [0x42u8; 48];
    pub(super) const NITRO_INTERMEDIATE_FIXTURE: &[u8] = b"aws-nitro-intermediate-fixture";

    fn aws_nitro_root_bytes() -> Vec<u8> {
        let pem = include_bytes!("../fixtures/nitro/aws-nitro-root.pem");
        pem.to_vec()
    }

    fn nitro_attestation_signing_key() -> SigningKey {
        SigningKey::from_bytes((&NITRO_ATTESTATION_KEY_SEED).into()).unwrap()
    }

    fn nitro_attestation_public_key() -> Vec<u8> {
        let signing_key = nitro_attestation_signing_key();
        let verifying_key = VerifyingKey::from(&signing_key);
        verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    fn sign_nitro_message(message: &[u8]) -> Vec<u8> {
        let signature: P384Signature = nitro_attestation_signing_key().sign(message);
        signature.to_vec()
    }

    #[derive(Debug, Clone)]
    struct FixtureSpec {
        file_name: &'static str,
        role: &'static str,
        role_tag: &'static str,
        note: &'static str,
        module_id: &'static str,
        timestamp_ms: u64,
        pcr0: [u8; 48],
        certificate: Vec<u8>,
        user_data: [u8; 64],
    }

    fn build_payload(spec: &FixtureSpec) -> Vec<u8> {
        let mut entries: Vec<(CborValue, CborValue)> = Vec::new();
        entries.push((
            CborValue::Text("module_id".to_string()),
            CborValue::Text(spec.module_id.to_string()),
        ));
        entries.push((
            CborValue::Text("timestamp".to_string()),
            CborValue::Integer(spec.timestamp_ms.into()),
        ));
        let pcrs = vec![
            (
                CborValue::Integer(0_i64.into()),
                CborValue::Bytes(spec.pcr0.to_vec()),
            ),
            (
                CborValue::Integer(1_i64.into()),
                CborValue::Bytes(vec![0u8; 48]),
            ),
        ];
        entries.push((CborValue::Text("pcrs".to_string()), CborValue::Map(pcrs)));
        entries.push((
            CborValue::Text("certificate".to_string()),
            CborValue::Bytes(spec.certificate.clone()),
        ));
        entries.push((
            CborValue::Text("cabundle".to_string()),
            CborValue::Array(vec![
                CborValue::Bytes(NITRO_INTERMEDIATE_FIXTURE.to_vec()),
                CborValue::Bytes(aws_nitro_root_bytes()),
            ]),
        ));
        entries.push((
            CborValue::Text("user_data".to_string()),
            CborValue::Bytes(spec.user_data.to_vec()),
        ));
        let mut payload = Vec::new();
        coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut payload).unwrap();
        payload
    }

    fn build_envelope(spec: &FixtureSpec) -> Vec<u8> {
        let payload = build_payload(spec);
        CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::ES384)
                    .build(),
            )
            .payload(payload)
            .create_signature(b"", sign_nitro_message)
            .build()
            .to_vec()
            .unwrap()
    }

    fn root_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/quotes/nitro")
    }

    pub(super) fn run() {
        let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
        let bound = expect_report_data(&kernel, &RECEIPT_ROOT);
        let unrelated_pair =
            expect_report_data(&Keypair::from_seed(&[0xCC; 32]).public_key(), &[0xDD; 32]);

        let positives: Vec<FixtureSpec> = vec![
            FixtureSpec {
                file_name: "positive/nitro_kernel_seed_09_root_08.bin",
                role: "positive",
                role_tag: "aws-nitro-bound-default",
                note: "Bound to KERNEL_SEED=[9;32], RECEIPT_ROOT=[8;32]; default cabundle.",
                module_id: "i-0123456789abcdef0-enc01234567890abcd",
                timestamp_ms: TIMESTAMP_MS,
                pcr0: PINNED_PCR0,
                certificate: nitro_attestation_public_key(),
                user_data: bound,
            },
            FixtureSpec {
                file_name: "positive/nitro_kernel_seed_09_root_08_alt_module.bin",
                role: "positive",
                role_tag: "aws-nitro-bound-alt-module-id",
                note: "Same binding; alternate module_id exercises text field path.",
                module_id: "i-fedcba9876543210f-encfedcba98765432",
                timestamp_ms: TIMESTAMP_MS + 1,
                pcr0: PINNED_PCR0,
                certificate: nitro_attestation_public_key(),
                user_data: bound,
            },
            FixtureSpec {
                file_name: "positive/nitro_kernel_seed_09_root_08_long_sig.bin",
                role: "positive",
                role_tag: "aws-nitro-bound-long-sig",
                note: "Bound; alternate timestamp changes the signed COSE payload.",
                module_id: "i-0123456789abcdef0-enc01234567890abcd",
                timestamp_ms: TIMESTAMP_MS + 2,
                pcr0: PINNED_PCR0,
                certificate: nitro_attestation_public_key(),
                user_data: bound,
            },
            FixtureSpec {
                file_name: "positive/nitro_kernel_seed_09_root_08_alt_sig_byte.bin",
                role: "positive",
                role_tag: "aws-nitro-bound-alt-sig-byte",
                note: "Bound; alternate module id changes the signed COSE payload.",
                module_id: "i-0123456789abcdef0-enc01234567890abcd",
                timestamp_ms: TIMESTAMP_MS + 3,
                pcr0: PINNED_PCR0,
                certificate: nitro_attestation_public_key(),
                user_data: bound,
            },
        ];

        let negatives: Vec<FixtureSpec> = vec![
            FixtureSpec {
                file_name: "negative/nitro_user_data_unbound.bin",
                role: "negative",
                role_tag: "aws-nitro-user-data-mismatch",
                note: "user_data bound to a different kernel key plus receipt root.",
                module_id: "i-0123456789abcdef0-enc01234567890abcd",
                timestamp_ms: TIMESTAMP_MS,
                pcr0: PINNED_PCR0,
                certificate: nitro_attestation_public_key(),
                user_data: unrelated_pair,
            },
            FixtureSpec {
                file_name: "negative/nitro_mismatched_pcr0.bin",
                role: "negative",
                role_tag: "aws-nitro-pcr0-mismatch",
                note: "Bound user_data; PCR0 is not the pinned launch image.",
                module_id: "i-0123456789abcdef0-enc01234567890abcd",
                timestamp_ms: TIMESTAMP_MS,
                pcr0: [0x11u8; 48],
                certificate: nitro_attestation_public_key(),
                user_data: bound,
            },
            FixtureSpec {
                file_name: "negative/nitro_certificate_mismatch.bin",
                role: "negative",
                role_tag: "aws-nitro-document-leaf-mismatch",
                note: "Bound; document certificate field is not the trusted chain leaf.",
                module_id: "i-0123456789abcdef0-enc01234567890abcd",
                timestamp_ms: TIMESTAMP_MS,
                pcr0: PINNED_PCR0,
                certificate: b"adversary-leaf-fixture".to_vec(),
                user_data: bound,
            },
            FixtureSpec {
                file_name: "negative/nitro_root_rotation_signed_under_old_root.bin",
                role: "negative",
                role_tag: "aws-nitro-root-rotation-old-leaf",
                note: "Document presents a leaf that the new (rotated) chain does not vouch for.",
                module_id: "i-0123456789abcdef0-enc01234567890abcd",
                timestamp_ms: TIMESTAMP_MS,
                pcr0: PINNED_PCR0,
                certificate: b"aws-nitro-leaf-under-old-root".to_vec(),
                user_data: bound,
            },
        ];

        let mut all = Vec::new();
        all.extend(positives);
        all.extend(negatives);

        let dir = root_path();
        fs::create_dir_all(dir.join("positive")).unwrap();
        fs::create_dir_all(dir.join("negative")).unwrap();

        let mut manifest = String::new();
        manifest.push_str("# Pinned AWS Nitro NSM fixture corpus.\n");
        manifest.push_str(
            "# Regenerate with: cargo run -p chio-attest-verify \\\n#   --example generate_nitro_fixtures --features tee-quotes\n",
        );
        manifest
            .push_str("# Each entry pins file path, role, role tag, note, and sha256 digest.\n");
        manifest
            .push_str("# Reviewers verify a fixture matches its manifest digest by re-running\n");
        manifest.push_str("# the generator and diffing the working tree against HEAD.\n\n");
        manifest.push_str("[corpus]\n");
        manifest.push_str("kernel_seed_hex = \"");
        for byte in KERNEL_SEED {
            manifest.push_str(&format!("{byte:02x}"));
        }
        manifest.push_str("\"\nreceipt_root_hex = \"");
        for byte in RECEIPT_ROOT {
            manifest.push_str(&format!("{byte:02x}"));
        }
        manifest.push_str("\"\npcr0_hex = \"");
        for byte in PINNED_PCR0 {
            manifest.push_str(&format!("{byte:02x}"));
        }
        manifest.push_str("\"\n\n");

        for spec in &all {
            let bytes = build_envelope(spec);
            let path = dir.join(spec.file_name);
            fs::write(&path, &bytes).unwrap();
            let digest = Sha256::digest(&bytes);
            let mut digest_hex = String::new();
            for byte in digest {
                digest_hex.push_str(&format!("{byte:02x}"));
            }
            manifest.push_str("[[fixture]]\n");
            manifest.push_str(&format!("path = \"{}\"\n", spec.file_name));
            manifest.push_str(&format!("role = \"{}\"\n", spec.role));
            manifest.push_str(&format!("role_tag = \"{}\"\n", spec.role_tag));
            manifest.push_str(&format!("note = \"{}\"\n", spec.note));
            manifest.push_str(&format!("size_bytes = {}\n", bytes.len()));
            manifest.push_str(&format!("sha256 = \"{digest_hex}\"\n\n"));
        }

        fs::write(dir.join("MANIFEST.toml"), manifest).unwrap();
        println!(
            "wrote {} fixtures and MANIFEST.toml under {}",
            all.len(),
            dir.display()
        );
    }
}
