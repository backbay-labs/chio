#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${ARTIFACT_DIR:-target/release-qualification/browser-kernel}"
mkdir -p "$ARTIFACT_DIR"

cleanup_target_dir=""
cleanup_driver_dir=""
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  cleanup_target_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-portable-browser.XXXXXX")"
  export CARGO_TARGET_DIR="$cleanup_target_dir"
else
  export CARGO_TARGET_DIR
fi

cleanup() {
  if [[ -n "$cleanup_target_dir" ]] && [[ -d "$cleanup_target_dir" ]]; then
    rm -rf "$cleanup_target_dir"
  fi
  if [[ -n "$cleanup_driver_dir" ]] && [[ -d "$cleanup_driver_dir" ]]; then
    rm -rf "$cleanup_driver_dir"
  fi
}
trap cleanup EXIT

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
if [[ -z "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="-C debuginfo=0"
else
  export RUSTFLAGS="${RUSTFLAGS} -C debuginfo=0"
fi

if [[ -z "${CHROMEDRIVER:-}" ]]; then
  CHROMEDRIVER_BIN="$(command -v chromedriver || true)"
  if [[ -z "$CHROMEDRIVER_BIN" ]]; then
    echo "[portable-browser] chromedriver not found on PATH" >&2
    exit 1
  fi
  export CHROMEDRIVER="$CHROMEDRIVER_BIN"
  CHROMEDRIVER_AUTO_DISCOVERED="1"
else
  CHROMEDRIVER_AUTO_DISCOVERED="0"
fi

if [[ -z "${CHROME_BIN:-}" ]]; then
  for candidate in \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/usr/bin/chromium" \
    "/usr/bin/chromium-browser" \
    "/usr/bin/google-chrome" \
    "$(command -v chromium 2>/dev/null || true)" \
    "$(command -v chromium-browser 2>/dev/null || true)" \
    "$(command -v google-chrome 2>/dev/null || true)"; do
    if [[ -n "$candidate" ]] && [[ -x "$candidate" ]]; then
      export CHROME_BIN="$candidate"
      break
    fi
  done
fi

extract_version() {
  printf '%s\n' "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true
}

extract_build() {
  local version="$1"
  printf '%s\n' "$version" | awk -F. '{print $1 "." $2 "." $3}'
}

detect_cft_platform() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)
      printf 'mac-arm64\n'
      ;;
    Darwin-x86_64)
      printf 'mac-x64\n'
      ;;
    Linux-x86_64)
      printf 'linux64\n'
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_matching_chromedriver() {
  if [[ -z "${CHROME_BIN:-}" ]] || [[ ! -x "${CHROME_BIN:-}" ]]; then
    return 0
  fi

  local chrome_version chrome_build driver_version driver_build
  chrome_version="$(extract_version "$("$CHROME_BIN" --version 2>/dev/null || true)")"
  driver_version="$(extract_version "$("$CHROMEDRIVER" --version 2>/dev/null || true)")"
  if [[ -z "$chrome_version" || -z "$driver_version" ]]; then
    return 0
  fi

  chrome_build="$(extract_build "$chrome_version")"
  driver_build="$(extract_build "$driver_version")"
  if [[ "$chrome_build" == "$driver_build" ]]; then
    return 0
  fi

  if [[ "$CHROMEDRIVER_AUTO_DISCOVERED" != "1" ]]; then
    echo "[portable-browser] CHROME_BIN build $chrome_build does not match explicit CHROMEDRIVER build $driver_build" >&2
    return 0
  fi

  local cft_platform resolved_version zip_url zip_path extracted_driver
  cft_platform="$(detect_cft_platform || true)"
  if [[ -z "$cft_platform" ]]; then
    echo "[portable-browser] CHROME_BIN build $chrome_build does not match PATH chromedriver build $driver_build and no Chrome-for-Testing platform is configured for $(uname -s)/$(uname -m)" >&2
    return 0
  fi

  echo "[portable-browser] CHROME_BIN build $chrome_build does not match PATH chromedriver build $driver_build; fetching compatible driver"
  resolved_version="$(curl -fsSL "https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_${chrome_build}")"
  cleanup_driver_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-chromedriver.XXXXXX")"
  zip_path="$cleanup_driver_dir/chromedriver-${cft_platform}.zip"
  zip_url="https://storage.googleapis.com/chrome-for-testing-public/${resolved_version}/${cft_platform}/chromedriver-${cft_platform}.zip"
  expected_md5_b64="$(
    curl -fsSI "$zip_url" | tr -d '\r' | python3 -c '
import sys

for line in sys.stdin:
    if not line.lower().startswith("x-goog-hash:"):
        continue
    for item in line.split(":", 1)[1].split(","):
        item = item.strip()
        if item.startswith("md5="):
            print(item[4:])
            raise SystemExit(0)
raise SystemExit(1)
'
  )"

  curl -fsSL "$zip_url" -o "$zip_path"
  actual_md5_b64="$(
    python3 - "$zip_path" <<'PY'
import base64
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.md5(path.read_bytes()).digest()
print(base64.b64encode(digest).decode("ascii"))
PY
  )"
  if [[ "$actual_md5_b64" != "$expected_md5_b64" ]]; then
    echo "[portable-browser] checksum verification failed for $zip_url" >&2
    exit 1
  fi
  unzip -q "$zip_path" -d "$cleanup_driver_dir"
  extracted_driver="$cleanup_driver_dir/chromedriver-${cft_platform}/chromedriver"
  if [[ ! -x "$extracted_driver" ]]; then
    echo "[portable-browser] failed to extract compatible chromedriver from $zip_url" >&2
    exit 1
  fi

  xattr -d com.apple.quarantine "$extracted_driver" >/dev/null 2>&1 || true
  export CHROMEDRIVER="$extracted_driver"
  echo "[portable-browser] using compatible chromedriver=$CHROMEDRIVER"
}

ensure_matching_chromedriver

CHROME_VERSION_DETECTED=""
if [[ -n "${CHROME_BIN:-}" ]] && [[ -x "${CHROME_BIN:-}" ]]; then
  CHROME_VERSION_DETECTED="$(extract_version "$("$CHROME_BIN" --version 2>/dev/null || true)")"
fi
CHROMEDRIVER_VERSION_DETECTED="$(extract_version "$("$CHROMEDRIVER" --version 2>/dev/null || true)")"
export CHROME_VERSION_DETECTED CHROMEDRIVER_VERSION_DETECTED
echo "[portable-browser] chrome_version=${CHROME_VERSION_DETECTED:-unknown}"
echo "[portable-browser] chromedriver_version=${CHROMEDRIVER_VERSION_DETECTED:-unknown}"

echo "[portable-browser] building wasm package"
wasm-pack build --target web --release crates/kernel/chio-kernel-browser

WASM_ARTIFACT="crates/kernel/chio-kernel-browser/pkg/chio_kernel_browser_bg.wasm"
if [[ ! -f "$WASM_ARTIFACT" ]]; then
  echo "[portable-browser] missing wasm artifact: $WASM_ARTIFACT" >&2
  exit 1
fi

ARTIFACT_BYTES="$(wc -c < "$WASM_ARTIFACT" | tr -d ' ')"
echo "[portable-browser] artifact_bytes=$ARTIFACT_BYTES"
echo "[portable-browser] artifact_path=$WASM_ARTIFACT"

LOG_FILE="$ARTIFACT_DIR/wasm-bindings.log"
REPORT_JSON="$ARTIFACT_DIR/summary.json"
REPORT_MD="$ARTIFACT_DIR/report.md"
rm -f "$LOG_FILE"

echo "[portable-browser] running headless browser bindings tests"
wasm-pack test --release --headless --chrome --chromedriver "$CHROMEDRIVER" crates/kernel/chio-kernel-browser -- --nocapture | tee "$LOG_FILE"

LATENCY_LINE="$(grep -o 'qualify_browser_evaluate_latency_ms=[0-9.]*' "$LOG_FILE" | tail -n 1 || true)"
if [[ -z "$LATENCY_LINE" ]]; then
  echo "[portable-browser] missing latency output from wasm bindings test" >&2
  exit 1
fi

LATENCY_MS="${LATENCY_LINE#*=}"
export ARTIFACT_BYTES LATENCY_MS LOG_FILE

cat >"$REPORT_MD" <<EOF
# Browser Kernel Qualification

| Field | Value |
|---|---|
| \`wasm_artifact\` | \`$WASM_ARTIFACT\` |
| \`artifact_bytes\` | \`$ARTIFACT_BYTES\` |
| \`evaluate_latency_ms\` | \`$LATENCY_MS\` |
| \`cargo_target_dir\` | \`$CARGO_TARGET_DIR\` |
| \`chrome_bin\` | \`${CHROME_BIN:-chrome-on-path}\` |
| \`chrome_version\` | \`${CHROME_VERSION_DETECTED:-unknown}\` |
| \`chromedriver\` | \`$CHROMEDRIVER\` |
| \`chromedriver_version\` | \`${CHROMEDRIVER_VERSION_DETECTED:-unknown}\` |

Artifacts:

- JSON summary: \`$REPORT_JSON\`
- Log: \`$LOG_FILE\`
EOF

python3 - "$REPORT_JSON" <<'PY'
import json
import os
import sys

summary_path = sys.argv[1]
data = {
    "schema": "chio.browser-kernel-qualification.v1",
    "wasm_artifact": "crates/kernel/chio-kernel-browser/pkg/chio_kernel_browser_bg.wasm",
    "artifact_bytes": int(os.environ["ARTIFACT_BYTES"]),
    "evaluate_latency_ms": float(os.environ["LATENCY_MS"]),
    "cargo_target_dir": os.environ["CARGO_TARGET_DIR"],
    "chrome_bin": os.environ.get("CHROME_BIN"),
    "chrome_version": os.environ.get("CHROME_VERSION_DETECTED"),
    "chromedriver": os.environ["CHROMEDRIVER"],
    "chromedriver_version": os.environ.get("CHROMEDRIVER_VERSION_DETECTED"),
    "log_file": os.environ["LOG_FILE"],
}
with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

echo "[portable-browser] $LATENCY_LINE"
echo "[portable-browser] report_md=$REPORT_MD"
echo "[portable-browser] report_json=$REPORT_JSON"
echo "[portable-browser] ok"
