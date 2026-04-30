//! Deterministically regenerate the pinned TDX fixture corpus under
//! `crates/chio-attest-verify/fixtures/quotes/tdx/`.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p chio-attest-verify --example generate_tdx_fixtures \
//!     --features tee-quotes
//! ```
//!
//! The generator writes positive and negative TDX v4 quote fixtures and
//! refreshes the MANIFEST.toml entries (file name, role, role-tag, plus
//! SHA256 digest). Reviewers verify a fixture matches its manifest digest
//! by re-running this binary and diffing the working tree against HEAD.
//!
//! The fixture envelope is deterministic: the kernel keypair seed, the
//! receipt root, and the TCB toggles are constants in this file. No
//! randomness or wall-clock state enters the output.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(not(feature = "tee-quotes"))]
fn main() {
    eprintln!("rebuild with --features tee-quotes to regenerate the TDX fixture corpus");
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
    use sha2::{Digest, Sha256};

    const QUOTE_HEADER_LEN: usize = 48;
    const TD10_REPORT_LEN: usize = 584;
    const TD10_REPORT_DATA_OFFSET: usize = QUOTE_HEADER_LEN + 520;
    const SIGNATURE_LEN_OFFSET: usize = QUOTE_HEADER_LEN + TD10_REPORT_LEN;
    const SIGNATURE_BYTES_OFFSET: usize = SIGNATURE_LEN_OFFSET + 4;

    const INTEL_SGX_QE_VENDOR_ID: [u8; 16] = [
        0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06,
        0x07,
    ];

    /// Kernel signing key seed used by every fixture. Mirrors the seed
    /// consumed by `tdx_unit.rs` and `tdx_integration.rs`.
    pub(super) const KERNEL_SEED: [u8; 32] = [9u8; 32];
    /// Receipt root used by every positive fixture. Mirrors the
    /// integration test constant.
    pub(super) const RECEIPT_ROOT: [u8; 32] = [8u8; 32];

    #[derive(Debug, Clone, Copy)]
    enum AttKeyType {
        EcdsaP256,
        EcdsaP384,
        Epid,
    }

    #[derive(Debug, Clone, Copy)]
    enum TeeType {
        IntelTdx,
    }

    #[derive(Debug, Clone, Copy)]
    struct VendorId([u8; 16]);

    #[derive(Debug)]
    struct FixtureSpec {
        file_name: &'static str,
        role: &'static str,
        role_tag: &'static str,
        note: &'static str,
        att_key_type: AttKeyType,
        tee_type: TeeType,
        vendor_id: VendorId,
        report_data: [u8; 64],
        body: &'static [u8],
        sig_byte: u8,
    }

    fn write_quote(spec: &FixtureSpec) -> Vec<u8> {
        let signature_len = 1usize;
        let mut quote = vec![0u8; SIGNATURE_BYTES_OFFSET + signature_len];
        quote[0..2].copy_from_slice(&4u16.to_le_bytes());
        let att = match spec.att_key_type {
            AttKeyType::EcdsaP256 => 2u16,
            AttKeyType::EcdsaP384 => 3u16,
            AttKeyType::Epid => 1u16,
        };
        quote[2..4].copy_from_slice(&att.to_le_bytes());
        let tee = match spec.tee_type {
            TeeType::IntelTdx => 0x0000_0081u32,
        };
        quote[4..8].copy_from_slice(&tee.to_le_bytes());
        quote[12..28].copy_from_slice(&spec.vendor_id.0);
        let body_len = spec.body.len().min(TD10_REPORT_LEN);
        quote[QUOTE_HEADER_LEN..QUOTE_HEADER_LEN + body_len]
            .copy_from_slice(&spec.body[..body_len]);
        quote[TD10_REPORT_DATA_OFFSET..TD10_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&spec.report_data);
        quote[SIGNATURE_LEN_OFFSET..SIGNATURE_LEN_OFFSET + 4]
            .copy_from_slice(&(signature_len as u32).to_le_bytes());
        quote[SIGNATURE_BYTES_OFFSET] = spec.sig_byte;
        quote
    }

    fn root_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/quotes/tdx")
    }

    pub(super) fn run() {
        let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
        let bound = expect_report_data(&kernel, &RECEIPT_ROOT);

        let mut tampered_upper_half = bound;
        tampered_upper_half[40] = 0x01;
        let unrelated_pair =
            expect_report_data(&Keypair::from_seed(&[0xCC; 32]).public_key(), &[0xDD; 32]);

        let positives: Vec<FixtureSpec> = vec![
            FixtureSpec {
                file_name: "positive/kernel_seed_09_root_08.bin",
                role: "positive",
                role_tag: "intel-tdx-bound-ecdsa-p256",
                note: "Bound to KERNEL_SEED=[9;32], RECEIPT_ROOT=[8;32]; ECDSA P-256.",
                att_key_type: AttKeyType::EcdsaP256,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId(INTEL_SGX_QE_VENDOR_ID),
                report_data: bound,
                body: b"chio-tdx-positive-bound-default",
                sig_byte: 0xA5,
            },
            FixtureSpec {
                file_name: "positive/kernel_seed_09_root_08_p384.bin",
                role: "positive",
                role_tag: "intel-tdx-bound-ecdsa-p384",
                note: "Same binding as default positive; ECDSA P-384 attestation key.",
                att_key_type: AttKeyType::EcdsaP384,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId(INTEL_SGX_QE_VENDOR_ID),
                report_data: bound,
                body: b"chio-tdx-positive-bound-p384",
                sig_byte: 0xA6,
            },
            FixtureSpec {
                file_name: "positive/kernel_seed_09_root_08_alt_body.bin",
                role: "positive",
                role_tag: "intel-tdx-bound-alt-body",
                note: "Bound report_data; alternate body marker exercises body bytes.",
                att_key_type: AttKeyType::EcdsaP256,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId(INTEL_SGX_QE_VENDOR_ID),
                report_data: bound,
                body: b"chio-tdx-positive-bound-alt-body-marker",
                sig_byte: 0xA7,
            },
            FixtureSpec {
                file_name: "positive/kernel_seed_09_root_08_alt_sig.bin",
                role: "positive",
                role_tag: "intel-tdx-bound-alt-sig-byte",
                note: "Bound; alternate signature trailing byte exercises envelope tail.",
                att_key_type: AttKeyType::EcdsaP256,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId(INTEL_SGX_QE_VENDOR_ID),
                report_data: bound,
                body: b"chio-tdx-positive-bound-alt-sig",
                sig_byte: 0xB1,
            },
        ];

        let negatives: Vec<FixtureSpec> = vec![
            FixtureSpec {
                file_name: "negative/report_data_unbound.bin",
                role: "negative",
                role_tag: "intel-tdx-report-data-mismatch",
                note: "report_data bound to a different kernel key plus receipt root.",
                att_key_type: AttKeyType::EcdsaP256,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId(INTEL_SGX_QE_VENDOR_ID),
                report_data: unrelated_pair,
                body: b"chio-tdx-negative-unbound-pair",
                sig_byte: 0xC1,
            },
            FixtureSpec {
                file_name: "negative/report_data_upper_half_tamper.bin",
                role: "negative",
                role_tag: "intel-tdx-upper-half-tamper",
                note: "Lower 32 bytes match digest; upper 32 bytes have a 1-bit tamper.",
                att_key_type: AttKeyType::EcdsaP256,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId(INTEL_SGX_QE_VENDOR_ID),
                report_data: tampered_upper_half,
                body: b"chio-tdx-negative-upper-tamper",
                sig_byte: 0xC2,
            },
            FixtureSpec {
                file_name: "negative/wrong_qe_vendor_id.bin",
                role: "negative",
                role_tag: "intel-tdx-non-intel-vendor",
                note: "Bound report_data; qe_vendor_id is not the Intel SGX QE.",
                att_key_type: AttKeyType::EcdsaP256,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId([0xDE; 16]),
                report_data: bound,
                body: b"chio-tdx-negative-wrong-vendor",
                sig_byte: 0xC3,
            },
            FixtureSpec {
                file_name: "negative/unsupported_att_key_type.bin",
                role: "negative",
                role_tag: "intel-tdx-att-key-type-epid",
                note: "Bound report_data; legacy EPID attestation key type rejected.",
                att_key_type: AttKeyType::Epid,
                tee_type: TeeType::IntelTdx,
                vendor_id: VendorId(INTEL_SGX_QE_VENDOR_ID),
                report_data: bound,
                body: b"chio-tdx-negative-epid-key-type",
                sig_byte: 0xC4,
            },
        ];

        let mut all = Vec::new();
        all.extend(positives);
        all.extend(negatives);

        let dir = root_path();
        fs::create_dir_all(dir.join("positive")).unwrap();
        fs::create_dir_all(dir.join("negative")).unwrap();

        let mut manifest = String::new();
        manifest.push_str("# Pinned TDX fixture corpus.\n");
        manifest.push_str(
            "# Regenerate with: cargo run -p chio-attest-verify \\\n#   --example generate_tdx_fixtures --features tee-quotes\n",
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
        manifest.push_str("\"\n\n");

        for spec in &all {
            let bytes = write_quote(spec);
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
