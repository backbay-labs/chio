#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
SOURCE=${CHIO_SOURCE:-/Users/connor/.codex/worktrees/985a/arc}
if [[ ! -d "$SOURCE/crates" ]]; then
  SOURCE=$ROOT
fi

RESULT_DIR="$SCRIPT_DIR/results"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-selective-disclosure-target}"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/chio-sd-bench.XXXXXX")
mkdir -p "$RESULT_DIR" "$TARGET_DIR"

CSV="$RESULT_DIR/selective-disclosure.csv"
LOG="$RESULT_DIR/selective-disclosure.log"
INLINE="$RESULT_DIR/selective-disclosure-inline.tex"

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

cat > "$WORK_DIR/Cargo.toml" <<EOF
[package]
name = "paper_selective_disclosure_bench"
version = "0.1.0"
edition = "2021"

[dependencies]
chio-core-types = { path = "$SOURCE/crates/chio-core-types" }
chio-selective-disclosure = { path = "$SOURCE/crates/chio-selective-disclosure", features = ["bbs"] }
serde_json = { version = "1" }
EOF

mkdir -p "$WORK_DIR/src"
cat > "$WORK_DIR/src/main.rs" <<'EOF'
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_receipt_body,
    sign_projection, verify_selective_disclosure_proof, DisclosureSet, InMemoryIssuerRegistry,
};
use serde_json::json;
use std::hint::black_box;
use std::time::Instant;

fn hex_fill(ch: char) -> String {
    std::iter::repeat(ch).take(64).collect()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let index = ((sorted.len().saturating_sub(1)) as f64 * p).round() as usize;
    sorted[index]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kernel = Keypair::from_seed(&[7_u8; 32]);
    let body = ChioReceiptBody {
        id: "receipt-paper-bench-001".to_string(),
        timestamp: 1_800_000_001,
        capability_id: "cap-paper-bench".to_string(),
        tool_server: "server.paper".to_string(),
        tool_name: "quote.settlement".to_string(),
        action: ToolCallAction::from_parameters(json!({
            "amount": "125.00",
            "asset": "usd",
            "buyer": "buyer-a"
        }))?,
        decision: Decision::Allow,
        content_hash: hex_fill('a'),
        policy_hash: hex_fill('b'),
        evidence: Vec::new(),
        metadata: Some(json!({"purpose": "paper-bench"})),
        trust_level: TrustLevel::Mediated,
        tenant_id: Some("tenant-paper".to_string()),
        kernel_key: kernel.public_key(),
    };

    let projection = project_receipt_body(&body)?;
    let issuer = generate_bbs_keypair(&[9_u8; 32], b"paper-selective-disclosure-bench")?;
    let signed = sign_projection(&projection, &issuer)?;
    let disclosure = DisclosureSet(vec![1, 2, 5]);
    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &issuer,
        &disclosure,
        b"paper-bench-nonce",
    )?;

    let mut registry = InMemoryIssuerRegistry::default();
    registry.insert(
        issuer.issuer_fingerprint.clone(),
        issuer.public_key_hex.clone(),
    );
    let verified = verify_selective_disclosure_proof(&proof, &registry)?;
    if verified.disclosed.len() != 3 {
        return Err("verification returned an unexpected disclosure count".into());
    }

    for _ in 0..10 {
        black_box(verify_selective_disclosure_proof(&proof, &registry)?);
    }

    let mut timings = Vec::new();
    for _ in 0..80 {
        let start = Instant::now();
        black_box(verify_selective_disclosure_proof(&proof, &registry)?);
        timings.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    timings.sort_by(|a, b| a.total_cmp(b));
    let mean = timings.iter().sum::<f64>() / timings.len() as f64;

    println!("proof_bytes,p50_us,p99_us,mean_us");
    println!(
        "{},{:.2},{:.2},{:.2}",
        proof.proof_bytes_hex.len() / 2,
        percentile(&timings, 0.50),
        percentile(&timings, 0.99),
        mean
    );
    Ok(())
}
EOF

if ! CARGO_TARGET_DIR="$TARGET_DIR" cargo run --manifest-path "$WORK_DIR/Cargo.toml" --offline > "$CSV" 2> "$LOG"; then
  emit_unreported
  exit 0
fi

row=$(tail -n 1 "$CSV" || true)
if [[ -z "$row" || "$row" == "proof_bytes,p50_us,p99_us,mean_us" ]]; then
  emit_unreported
  exit 0
fi

IFS=',' read -r bytes p50 p99 mean <<< "$row"
printf '%s bytes, p50 %s us, p99 %s us\n' "$bytes" "$p50" "$p99" > "$INLINE"
