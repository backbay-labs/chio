//! Deterministically regenerate the pinned AMD SEV-SNP fixture corpus
//! under `crates/trust/chio-attest-verify/fixtures/quotes/sev_snp/`.
//!
//! Run with:
//!
//! ```bash
//! cargo run -p chio-attest-verify --example generate_sev_snp_fixtures \
//!     --features tee-quotes
//! ```
//!
//! The generator writes positive and negative SEV-SNP envelope fixtures
//! and refreshes the MANIFEST.toml entries (file name, role, role tag,
//! note, and SHA256 digest). Reviewers verify a fixture matches its
//! manifest digest by re-running this binary and diffing the working
//! tree against HEAD.
//!
//! The fixture envelope is deterministic: the kernel keypair seed, the
//! receipt root, and the launch digest are constants in this file. No
//! randomness or wall-clock state enters the output.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(not(feature = "tee-quotes"))]
fn main() {
    eprintln!("rebuild with --features tee-quotes to regenerate the SEV-SNP fixture corpus");
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
    use p384::ecdsa::{signature::Signer as _, Signature as P384Signature, SigningKey};
    use sha2::{Digest, Sha256};

    const SEV_SNP_HEADER_AND_BODY_LEN: usize = 0x300;
    const SEV_SNP_VERSION_OFFSET: usize = 0;
    const SEV_SNP_VMPL_OFFSET: usize = 12;
    const SEV_SNP_SIG_ALGO_OFFSET: usize = 16;
    const SEV_SNP_KEY_SELECT_OFFSET: usize = 20;
    const SEV_SNP_REPORTED_TCB_OFFSET: usize = 24;
    const SEV_SNP_MEASUREMENT_OFFSET: usize = 0x90;
    const SEV_SNP_REPORT_DATA_OFFSET: usize = 0xC0;
    const SEV_SNP_SIGNATURE_LEN_OFFSET: usize = SEV_SNP_HEADER_AND_BODY_LEN - 4;
    const SEV_SNP_SIGNATURE_BYTES_OFFSET: usize = SEV_SNP_HEADER_AND_BODY_LEN;

    const SIG_ALGO_ECDSA_P384_VCEK: u32 = 0x01;
    const SIG_ALGO_ECDSA_P384_VLEK: u32 = 0x02;
    const KEY_SELECT_VCEK: u8 = 0x00;
    const KEY_SELECT_VLEK: u8 = 0x01;

    /// Kernel signing key seed used by every fixture. Mirrors the seed
    /// consumed by `sev_snp_unit.rs` and the corpus integration test.
    pub(super) const KERNEL_SEED: [u8; 32] = [9u8; 32];
    /// Receipt root used by every positive fixture.
    pub(super) const RECEIPT_ROOT: [u8; 32] = [8u8; 32];
    /// Launch digest pinned by the verifier; positive fixtures embed
    /// this value as the `measurement` field.
    pub(super) const PINNED_LAUNCH_DIGEST: [u8; 48] = [0x4Cu8; 48];
    const VCEK_ATTESTATION_KEY_SEED: [u8; 48] = [0x43u8; 48];
    const VLEK_ATTESTATION_KEY_SEED: [u8; 48] = [0x44u8; 48];

    #[derive(Debug)]
    struct FixtureSpec {
        file_name: &'static str,
        role: &'static str,
        role_tag: &'static str,
        note: &'static str,
        version: u32,
        vmpl: u32,
        sig_algo: u32,
        key_select: u8,
        reported_tcb: u32,
        measurement: [u8; 48],
        report_data: [u8; 64],
        body_marker: &'static [u8],
    }

    fn signing_key(seed: &[u8; 48]) -> SigningKey {
        SigningKey::from_bytes(seed.into()).unwrap()
    }

    fn sign_report(key_select: u8, message: &[u8]) -> Vec<u8> {
        let seed = if key_select == KEY_SELECT_VLEK {
            &VLEK_ATTESTATION_KEY_SEED
        } else {
            &VCEK_ATTESTATION_KEY_SEED
        };
        let signature: P384Signature = signing_key(seed).sign(message);
        signature.to_vec()
    }

    fn write_envelope(spec: &FixtureSpec) -> Vec<u8> {
        let signature_len = 96usize;
        let mut quote = vec![0u8; SEV_SNP_SIGNATURE_BYTES_OFFSET + signature_len];
        quote[SEV_SNP_VERSION_OFFSET..SEV_SNP_VERSION_OFFSET + 4]
            .copy_from_slice(&spec.version.to_le_bytes());
        quote[SEV_SNP_VMPL_OFFSET..SEV_SNP_VMPL_OFFSET + 4]
            .copy_from_slice(&spec.vmpl.to_le_bytes());
        quote[SEV_SNP_SIG_ALGO_OFFSET..SEV_SNP_SIG_ALGO_OFFSET + 4]
            .copy_from_slice(&spec.sig_algo.to_le_bytes());
        quote[SEV_SNP_KEY_SELECT_OFFSET] = spec.key_select;
        quote[SEV_SNP_REPORTED_TCB_OFFSET..SEV_SNP_REPORTED_TCB_OFFSET + 4]
            .copy_from_slice(&spec.reported_tcb.to_le_bytes());
        // Anchor a small marker into the header padding region (offset
        // 32..) so different fixtures cannot accidentally collide on
        // bytes when they share the rest of the envelope.
        let marker_len = spec.body_marker.len().min(48);
        quote[32..32 + marker_len].copy_from_slice(&spec.body_marker[..marker_len]);
        quote[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48]
            .copy_from_slice(&spec.measurement);
        quote[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&spec.report_data);
        quote[SEV_SNP_SIGNATURE_LEN_OFFSET..SEV_SNP_SIGNATURE_LEN_OFFSET + 4]
            .copy_from_slice(&(signature_len as u32).to_le_bytes());
        let signature = sign_report(spec.key_select, &quote[..SEV_SNP_HEADER_AND_BODY_LEN]);
        quote[SEV_SNP_SIGNATURE_BYTES_OFFSET..SEV_SNP_SIGNATURE_BYTES_OFFSET + signature_len]
            .copy_from_slice(&signature);
        quote
    }

    fn root_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/quotes/sev_snp")
    }

    pub(super) fn run() {
        let kernel = Keypair::from_seed(&KERNEL_SEED).public_key();
        let bound = expect_report_data(&kernel, &RECEIPT_ROOT);
        let unrelated_pair =
            expect_report_data(&Keypair::from_seed(&[0xCC; 32]).public_key(), &[0xDD; 32]);

        let positives: Vec<FixtureSpec> = vec![
            FixtureSpec {
                file_name: "positive/sev_snp_kernel_seed_09_root_08_vcek.bin",
                role: "positive",
                role_tag: "amd-sev-snp-bound-vcek",
                note: "Bound to KERNEL_SEED=[9;32], RECEIPT_ROOT=[8;32]; VCEK chain.",
                version: 2,
                vmpl: 0,
                sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
                key_select: KEY_SELECT_VCEK,
                reported_tcb: 0x1234_5678,
                measurement: PINNED_LAUNCH_DIGEST,
                report_data: bound,
                body_marker: b"chio-sev-snp-positive-vcek",
            },
            FixtureSpec {
                file_name: "positive/sev_snp_kernel_seed_09_root_08_vlek.bin",
                role: "positive",
                role_tag: "amd-sev-snp-bound-vlek",
                note: "Same binding as default positive; VLEK chain.",
                version: 2,
                vmpl: 0,
                sig_algo: SIG_ALGO_ECDSA_P384_VLEK,
                key_select: KEY_SELECT_VLEK,
                reported_tcb: 0x1234_5678,
                measurement: PINNED_LAUNCH_DIGEST,
                report_data: bound,
                body_marker: b"chio-sev-snp-positive-vlek",
            },
            FixtureSpec {
                file_name: "positive/sev_snp_kernel_seed_09_root_08_vmpl1.bin",
                role: "positive",
                role_tag: "amd-sev-snp-bound-vmpl1",
                note: "Bound; VMPL=1 to exercise the VMPL range guard.",
                version: 2,
                vmpl: 1,
                sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
                key_select: KEY_SELECT_VCEK,
                reported_tcb: 0x1234_5678,
                measurement: PINNED_LAUNCH_DIGEST,
                report_data: bound,
                body_marker: b"chio-sev-snp-positive-vmpl1",
            },
            FixtureSpec {
                file_name: "positive/sev_snp_kernel_seed_09_root_08_alt_sig.bin",
                role: "positive",
                role_tag: "amd-sev-snp-bound-alt-sig-byte",
                note: "Bound; alternate signature trailing byte exercises envelope tail.",
                version: 2,
                vmpl: 0,
                sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
                key_select: KEY_SELECT_VCEK,
                reported_tcb: 0x1234_5678,
                measurement: PINNED_LAUNCH_DIGEST,
                report_data: bound,
                body_marker: b"chio-sev-snp-positive-alt-sig",
            },
        ];

        let negatives: Vec<FixtureSpec> = vec![
            FixtureSpec {
                file_name: "negative/sev_snp_report_data_unbound.bin",
                role: "negative",
                role_tag: "amd-sev-snp-report-data-mismatch",
                note: "report_data bound to a different kernel key plus receipt root.",
                version: 2,
                vmpl: 0,
                sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
                key_select: KEY_SELECT_VCEK,
                reported_tcb: 0x1234_5678,
                measurement: PINNED_LAUNCH_DIGEST,
                report_data: unrelated_pair,
                body_marker: b"chio-sev-snp-negative-unbound",
            },
            FixtureSpec {
                file_name: "negative/sev_snp_mismatched_launch_digest.bin",
                role: "negative",
                role_tag: "amd-sev-snp-launch-digest-mismatch",
                note: "Bound report_data; envelope measurement is not the pinned launch digest.",
                version: 2,
                vmpl: 0,
                sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
                key_select: KEY_SELECT_VCEK,
                reported_tcb: 0x1234_5678,
                measurement: [0x11u8; 48],
                report_data: bound,
                body_marker: b"chio-sev-snp-negative-launch-digest",
            },
            FixtureSpec {
                file_name: "negative/sev_snp_stale_tcb_marker.bin",
                role: "negative",
                role_tag: "amd-sev-snp-stale-tcb-marker",
                note: "Bound; reported_tcb is the documented stale-marker (0).",
                version: 2,
                vmpl: 0,
                sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
                key_select: KEY_SELECT_VCEK,
                reported_tcb: 0,
                measurement: PINNED_LAUNCH_DIGEST,
                report_data: bound,
                body_marker: b"chio-sev-snp-negative-stale-tcb",
            },
            FixtureSpec {
                file_name: "negative/sev_snp_sig_algo_key_select_mismatch.bin",
                role: "negative",
                role_tag: "amd-sev-snp-sig-algo-key-select-mismatch",
                note: "Bound; sig_algo says VCEK but key_select says VLEK.",
                version: 2,
                vmpl: 0,
                sig_algo: SIG_ALGO_ECDSA_P384_VCEK,
                key_select: KEY_SELECT_VLEK,
                reported_tcb: 0x1234_5678,
                measurement: PINNED_LAUNCH_DIGEST,
                report_data: bound,
                body_marker: b"chio-sev-snp-negative-sig-algo-key-select",
            },
        ];

        let mut all = Vec::new();
        all.extend(positives);
        all.extend(negatives);

        let dir = root_path();
        fs::create_dir_all(dir.join("positive")).unwrap();
        fs::create_dir_all(dir.join("negative")).unwrap();

        let mut manifest = String::new();
        manifest.push_str("# Pinned AMD SEV-SNP fixture corpus.\n");
        manifest.push_str(
            "# Regenerate with: cargo run -p chio-attest-verify \\\n#   --example generate_sev_snp_fixtures --features tee-quotes\n",
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
        manifest.push_str("\"\nlaunch_digest_hex = \"");
        for byte in PINNED_LAUNCH_DIGEST {
            manifest.push_str(&format!("{byte:02x}"));
        }
        manifest.push_str("\"\n\n");

        for spec in &all {
            let bytes = write_envelope(spec);
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
