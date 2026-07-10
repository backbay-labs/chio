#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${repo_root}/deploy/docker/Dockerfile"
image="${CHIO_PROOF_ROOM_IMAGE:-chio-proof-room:local}"

if [[ "${CHIO_SKIP_DOCKER_RUN:-0}" == "1" ]]; then
  echo "SKIP Proof Room Docker runtime smoke: CHIO_SKIP_DOCKER_RUN=1"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  if [[ "${CHIO_REQUIRE_DOCKER_DAEMON:-0}" == "1" ]]; then
    echo "proof-room.docker.daemon-unavailable: docker is not installed" >&2
    exit 1
  fi
  echo "SKIP Proof Room Docker runtime smoke: docker is not installed"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  if [[ "${CHIO_REQUIRE_DOCKER_DAEMON:-0}" == "1" ]]; then
    echo "proof-room.docker.daemon-unavailable: docker daemon is not reachable" >&2
    exit 1
  fi
  echo "SKIP Proof Room Docker runtime smoke: docker daemon is not reachable"
  exit 0
fi

port="$(
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

container=""
doctor_report=""
cleanup() {
  if [[ -n "$container" ]]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  if [[ -n "$doctor_report" ]]; then
    rm -f "$doctor_report"
  fi
}
trap cleanup EXIT

docker build -f "$dockerfile" --target chio-proof-room-quickstart -t "$image" "$repo_root"
container="$(docker run -d -p "127.0.0.1:${port}:7391" "$image")"

CHIO_PROOF_ROOM_PORT="$port" python3 - <<'PY'
from __future__ import annotations

import os
import time
from html.parser import HTMLParser
import urllib.request

port = os.environ["CHIO_PROOF_ROOM_PORT"]
base = f"http://127.0.0.1:{port}"
required = {
    "/manifest.json": "chio.proof-room.bundle.v1",
    "/ui/proof-room-static/load-report.json": "chio.proof-room.verifier-report.v1",
    "/proof-room-fixture-catalog.json": "chio.proof-room.fixture-catalog.v1",
    "/proof-room-fixtures/minimal-passport-valid/verifier-report.json": "chio.transaction.verifier-report.v1",
    "/proof-room-fixtures/minimal-passport-valid/transaction-passport.json": "passport-minimal-valid",
    "/proof-room-fixtures/commerce-offline-psp/verifier-report.json": "chio.commerce.order-passport.v1",
    "/?view=proof-room": "Chio",
}

deadline = time.time() + 30
last_error = ""
for path, expected in required.items():
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + path, timeout=2) as response:
                body = response.read().decode("utf-8")
            if expected in body:
                break
            last_error = f"{path} did not contain {expected}"
        except Exception as exc:
            last_error = f"{path}: {exc}"
        time.sleep(0.5)
    else:
        raise SystemExit(f"proof-room.docker.quickstart-smoke-failed: {last_error}")


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for attr in ("href", "src"):
            value = values.get(attr)
            if value and value.startswith("/assets/"):
                self.assets.append(value)


with urllib.request.urlopen(base + "/proof-room?view=proof-room", timeout=2) as response:
    proof_room_html = response.read().decode("utf-8")

parser = AssetParser()
parser.feed(proof_room_html)
assets = sorted(set(parser.assets))
if not assets:
    raise SystemExit("proof-room.docker.quickstart-smoke-failed: proof-room assets missing")

for asset_path in assets:
    with urllib.request.urlopen(base + asset_path, timeout=2) as response:
        content_type = response.headers.get("content-type", "")
        body = response.read()
    if not body:
        raise SystemExit(
            f"proof-room.docker.quickstart-smoke-failed: {asset_path} was empty"
        )
    if "text/html" in content_type.lower():
        raise SystemExit(
            "proof-room.docker.quickstart-smoke-failed: "
            f"{asset_path} returned the HTML fallback"
        )
PY

if [[ "${CHIO_SKIP_PROOF_ROOM_BROWSER_SMOKE:-0}" == "1" ]]; then
  echo "SKIP Proof Room browser smoke: CHIO_SKIP_PROOF_ROOM_BROWSER_SMOKE=1"
elif ! command -v node >/dev/null 2>&1; then
  if [[ "${CHIO_REQUIRE_DOCKER_DAEMON:-0}" == "1" || "${CHIO_REQUIRE_PROOF_ROOM_BROWSER_SMOKE:-0}" == "1" ]]; then
    echo "proof-room.docker.browser-smoke-unavailable: node is not installed" >&2
    exit 1
  fi
  echo "SKIP Proof Room browser smoke: node is not installed"
else
  set +e
  CHIO_PROOF_ROOM_PORT="$port" node --input-type=module - <<'JS'
const setupFailure = 78

let chromium
try {
  ;({ chromium } = await import('@playwright/test'))
} catch (error) {
  console.error(`proof-room.docker.browser-smoke-unavailable: @playwright/test is unavailable: ${error}`)
  process.exit(setupFailure)
}

const port = process.env.CHIO_PROOF_ROOM_PORT
const base = `http://127.0.0.1:${port}`
const channel = process.env.CHIO_PROOF_ROOM_BROWSER_CHANNEL || 'chrome'
const launchOptions = {
  headless: true,
  args: ['--no-sandbox'],
}
if (channel && channel !== 'bundled') {
  launchOptions.channel = channel
}

let browser
try {
  browser = await chromium.launch(launchOptions)
} catch (error) {
  console.error(
    `proof-room.docker.browser-smoke-unavailable: failed to launch ${channel || 'bundled'} browser: ${error}`,
  )
  process.exit(setupFailure)
}

try {
  const page = await browser.newPage()
  await page.goto(`${base}/?view=proof-room`, {
    waitUntil: 'domcontentloaded',
    timeout: 30_000,
  })

  const expectedText = [
    'proof-room-single-call-authority',
    'passport-minimal-valid',
    'claim.transaction.passport_root_verified',
    'verified',
  ]
  const deadline = Date.now() + 30_000
  let lastText = ''
  while (Date.now() < deadline) {
    lastText = await page.locator('body').innerText({ timeout: 2_000 })
    if (lastText.includes('Proof Room load failed')) {
      throw new Error('Proof Room load failed')
    }
    if (expectedText.every((text) => lastText.includes(text))) {
      await browser.close()
      process.exit(0)
    }
    await page.waitForTimeout(250)
  }
  const missing = expectedText.filter((text) => !lastText.includes(text)).join(', ')
  throw new Error(`hydrated Proof Room was missing expected text: ${missing}`)
} catch (error) {
  console.error(`proof-room.docker.quickstart-browser-smoke-failed: ${error}`)
  await browser.close()
  process.exit(1)
}
JS
  browser_status=$?
  set -e
  if [[ "$browser_status" -eq 78 ]]; then
    if [[ "${CHIO_REQUIRE_DOCKER_DAEMON:-0}" == "1" || "${CHIO_REQUIRE_PROOF_ROOM_BROWSER_SMOKE:-0}" == "1" ]]; then
      exit 1
    fi
    echo "SKIP Proof Room browser smoke: browser runtime is unavailable"
  elif [[ "$browser_status" -ne 0 ]]; then
    exit "$browser_status"
  fi
fi

doctor_report="$(mktemp -t chio-proof-room-doctor-report.XXXXXX.json)"
docker cp "${container}:/opt/chio/proof-doctor-report.json" "$doctor_report"
CHIO_PROOF_ROOM_DOCKER_DOCTOR_REPORT="$doctor_report" python3 - <<'PY'
from __future__ import annotations

import json
import os

path = os.environ["CHIO_PROOF_ROOM_DOCKER_DOCTOR_REPORT"]
with open(path, encoding="utf-8") as handle:
    report = json.load(handle)

if report.get("schema") != "chio.proof-room.quickstart-doctor-report.v1":
    raise SystemExit(
        "proof-room.docker.quickstart-doctor-report-invalid: schema mismatch"
    )
if report.get("verdict") != "verified":
    raise SystemExit(
        "proof-room.docker.quickstart-doctor-report-invalid: verdict mismatch"
    )
if report.get("bundle_id") != "proof-room-single-call-authority":
    raise SystemExit(
        "proof-room.docker.quickstart-doctor-report-invalid: bundle mismatch"
    )
if report.get("fixture_id") != "single-call-authority":
    raise SystemExit(
        "proof-room.docker.quickstart-doctor-report-invalid: fixture mismatch"
    )
if not isinstance(report.get("negative_cases"), list) or not report["negative_cases"]:
    raise SystemExit(
        "proof-room.docker.quickstart-doctor-report-invalid: negative cases missing"
    )
if not isinstance(report.get("receipt_coverage"), list) or not report["receipt_coverage"]:
    raise SystemExit(
        "proof-room.docker.quickstart-doctor-report-invalid: receipt coverage missing"
    )
PY

echo "OK Proof Room Docker quickstart runtime smoke"
