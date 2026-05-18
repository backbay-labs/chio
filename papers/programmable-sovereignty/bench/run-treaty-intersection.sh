#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
SOURCE=${CHIO_SOURCE:-/Users/connor/.codex/worktrees/985a/arc}
if [[ ! -d "$SOURCE/crates" ]]; then
  SOURCE=$ROOT
fi

RESULT_DIR="$SCRIPT_DIR/results"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-treaty-target}"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/chio-treaty-bench.XXXXXX")
mkdir -p "$RESULT_DIR" "$TARGET_DIR"

CSV="$RESULT_DIR/treaty-intersection.csv"
LOG="$RESULT_DIR/treaty-intersection.log"
INLINE="$RESULT_DIR/treaty-intersection-inline.tex"

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

cat > "$WORK_DIR/Cargo.toml" <<EOF
[package]
name = "paper_treaty_intersection_bench"
version = "0.1.0"
edition = "2021"

[dependencies]
chio-chiodos-runtime = { path = "$SOURCE/crates/chio-chiodos-runtime" }
chio-core-types = { path = "$SOURCE/crates/chio-core-types" }
EOF

mkdir -p "$WORK_DIR/src"
cat > "$WORK_DIR/src/main.rs" <<'EOF'
use chio_chiodos_runtime::{
    compute_ladder_intersection, governance_ladder_manifest_sha256, GovernanceLadderActionClass,
    GovernanceLadderManifest, TreatyScope, CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA,
    CHIODOS_TREATY_SCOPE_SCHEMA,
};
use chio_core_types::crypto::Keypair;
use std::hint::black_box;
use std::time::Instant;

fn hash_fill(ch: char) -> String {
    std::iter::repeat(ch).take(64).collect()
}

fn action_ids(n: usize) -> Vec<String> {
    (0..n).map(|idx| format!("action_{idx}")).collect()
}

fn manifest(kernel_id: &str, key_id: &str, n: usize, mode: &str) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIODOS_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("manifest-{kernel_id}-{n}"),
        kernel_id: kernel_id.to_string(),
        issuer: kernel_id.to_string(),
        key_id: key_id.to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: action_ids(n)
            .into_iter()
            .map(|action_class_id| GovernanceLadderActionClass {
                action_class_id,
                mode: mode.to_string(),
                destructive: false,
                consistency_model: "totally_ordered".to_string(),
                co_sign: "bilateral_required".to_string(),
                evidence_required: vec!["bilateral_invocation".to_string()],
                aliases: Vec::new(),
            })
            .collect(),
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let index = ((sorted.len().saturating_sub(1)) as f64 * p).round() as usize;
    sorted[index]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let left_key = Keypair::from_seed(&[1_u8; 32]);
    let right_key = Keypair::from_seed(&[2_u8; 32]);
    println!("n,p50_us,p99_us,mean_us");

    for n in [1_usize, 10, 100] {
        let left = manifest("kernel-left", "key-left", n, "receipt_backed");
        let right = manifest("kernel-right", "key-right", n, "quorum_required");
        let scope = TreatyScope {
            schema: CHIODOS_TREATY_SCOPE_SCHEMA.to_string(),
            treaty_id: format!("paper-treaty-{n}"),
            participant_kernel_ids: vec!["kernel-left".to_string(), "kernel-right".to_string()],
            participant_public_keys: vec![left_key.public_key(), right_key.public_key()],
            ladder_manifest_sha256s: vec![
                governance_ladder_manifest_sha256(&left)?,
                governance_ladder_manifest_sha256(&right)?,
            ],
            allowed_action_classes: action_ids(n),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
            revocation_epoch_sha256: hash_fill('a'),
            trust_bundle_sha256: hash_fill('b'),
        };
        let manifests = vec![left, right];
        let now = 1_800_000_001_000;

        for _ in 0..20 {
            black_box(compute_ladder_intersection(&scope, &manifests, now)?);
        }

        let mut timings = Vec::new();
        for _ in 0..250 {
            let start = Instant::now();
            black_box(compute_ladder_intersection(&scope, &manifests, now)?);
            timings.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        }
        timings.sort_by(|a, b| a.total_cmp(b));
        let mean = timings.iter().sum::<f64>() / timings.len() as f64;

        println!(
            "{},{:.2},{:.2},{:.2}",
            n,
            percentile(&timings, 0.50),
            percentile(&timings, 0.99),
            mean
        );
    }
    Ok(())
}
EOF

if ! CARGO_TARGET_DIR="$TARGET_DIR" cargo run --manifest-path "$WORK_DIR/Cargo.toml" --offline > "$CSV" 2> "$LOG"; then
  emit_unreported
  exit 0
fi

lines=$(tail -n +2 "$CSV" | sed '/^$/d' || true)
if [[ -z "$lines" ]]; then
  emit_unreported
  exit 0
fi

summary=$(printf '%s\n' "$lines" | awk -F, '
  BEGIN { first = 1 }
  {
    if (!first) {
      printf "; ";
    }
    printf "N=%s p50 %s us p99 %s us", $1, $2, $3;
    first = 0;
  }
')
printf '%s\n' "$summary" > "$INLINE"
