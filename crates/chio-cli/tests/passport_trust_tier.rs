#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Verify that `chio passport generate --agent <id>` emits a
//! passport with a `trustTier` field derived from the kernel's
//! compliance + behavioral scoring.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_credentials::{synthesize_trust_tier, TrustTier};
use chio_kernel::{behavioral_anomaly_score, EmaBaselineState, COMPLIANCE_SCORE_MAX};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn unique_output_path(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.json"))
}

fn run_generate(args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--json")
        .args(args)
        .output()
        .expect("spawn chio cli");
    assert!(
        output.status.success(),
        "`chio {}` failed: stderr={}, stdout={}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    serde_json::from_slice(&output.stdout).expect("generate output is json")
}

fn kernel_anomaly(anomaly_flag: bool) -> bool {
    // Mirror the CLI's own synthesis path: seed a tiny baseline and run
    // the kernel's `behavioral_anomaly_score` over the same sentinel
    // samples the CLI uses.
    let baseline = EmaBaselineState {
        sample_count: 2,
        ema_mean: 1.0,
        ema_variance: 1.0,
        last_update: 0,
    };
    let sample = if anomaly_flag { 100.0 } else { 1.0 };
    behavioral_anomaly_score("anomaly-probe", &baseline, sample, 3.0, 0).anomaly
}

#[test]
fn passport_generate_emits_trust_tier_for_clean_agent() {
    let output_path = unique_output_path("chio-passport-generate");
    let json = run_generate(&[
        "passport",
        "generate",
        "--agent",
        "did:chio:agent-clean",
        "--output",
        output_path.to_str().expect("output path utf8"),
    ]);

    // The top-level JSON output carries compliance + behavioral inputs
    // alongside the derived tier so tests can assert the kernel's math
    // matches the credentials-crate synthesizer.
    let score = json
        .get("complianceScore")
        .and_then(serde_json::Value::as_u64)
        .expect("complianceScore field");
    assert_eq!(
        u32::try_from(score).expect("score fits u32"),
        COMPLIANCE_SCORE_MAX
    );

    let anomaly = json
        .get("behavioralAnomaly")
        .and_then(serde_json::Value::as_bool)
        .expect("behavioralAnomaly field");
    assert_eq!(anomaly, kernel_anomaly(false));
    assert!(!anomaly);

    let tier_str = json
        .get("trustTier")
        .and_then(serde_json::Value::as_str)
        .expect("trustTier field");
    assert_eq!(tier_str, TrustTier::Premier.label());

    // Reconstruct the synthesizer's verdict and verify the CLI matches.
    let expected_tier = synthesize_trust_tier(score as u32, anomaly);
    assert_eq!(expected_tier, TrustTier::Premier);

    // The emitted passport document also carries the tier under
    // `trustTier` so relying parties can read it without rerunning
    // the synthesizer.
    let passport = json.get("passport").expect("passport payload").clone();
    assert_eq!(
        passport
            .get("trustTier")
            .and_then(serde_json::Value::as_str),
        Some(TrustTier::Premier.label())
    );
    assert_eq!(
        passport.get("subject").and_then(serde_json::Value::as_str),
        Some("did:chio:agent-clean")
    );

    // The file on disk must match the embedded payload byte-for-byte.
    let on_disk = std::fs::read_to_string(&output_path).expect("read passport file");
    let on_disk_value: serde_json::Value =
        serde_json::from_str(&on_disk).expect("passport file is json");
    assert_eq!(on_disk_value, passport);
    std::fs::remove_file(&output_path).ok();
}

#[test]
fn passport_generate_honors_compliance_score_override() {
    let json = run_generate(&[
        "passport",
        "generate",
        "--agent",
        "did:chio:agent-attested",
        "--compliance-score",
        "600",
    ]);
    assert_eq!(
        json.get("complianceScore")
            .and_then(serde_json::Value::as_u64),
        Some(600),
    );
    assert_eq!(
        json.get("trustTier").and_then(serde_json::Value::as_str),
        Some(TrustTier::Attested.label())
    );
    // The synthesizer must agree with the CLI's tier.
    assert_eq!(
        synthesize_trust_tier(600, kernel_anomaly(false)),
        TrustTier::Attested
    );
}

#[test]
fn passport_generate_anomaly_flag_downgrades_premier() {
    let json = run_generate(&[
        "passport",
        "generate",
        "--agent",
        "did:chio:agent-anomalous",
        "--compliance-score",
        "1000",
        "--behavioral-anomaly",
    ]);
    assert_eq!(
        json.get("complianceScore")
            .and_then(serde_json::Value::as_u64),
        Some(1000),
    );
    assert_eq!(
        json.get("behavioralAnomaly")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let tier = json
        .get("trustTier")
        .and_then(serde_json::Value::as_str)
        .expect("trustTier");
    // With an active anomaly, 1000 should degrade from Premier -> Verified.
    assert_eq!(tier, TrustTier::Verified.label());
    assert_eq!(
        synthesize_trust_tier(1000, kernel_anomaly(true)),
        TrustTier::Verified
    );
}

#[test]
fn passport_generate_low_score_surfaces_unverified() {
    let json = run_generate(&[
        "passport",
        "generate",
        "--agent",
        "did:chio:agent-cold-start",
        "--compliance-score",
        "100",
    ]);
    assert_eq!(
        json.get("trustTier").and_then(serde_json::Value::as_str),
        Some(TrustTier::Unverified.label())
    );
}
