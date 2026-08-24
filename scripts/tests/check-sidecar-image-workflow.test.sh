#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
workflow="${repo_root}/.github/workflows/sidecar-image.yml"

python3 - "${workflow}" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")

required = {
    "- platform: linux/amd64": "native amd64 matrix leg",
    "runner: ubuntu-24.04": "native amd64 runner",
    "- platform: linux/arm64": "native arm64 matrix leg",
    "runner: ubuntu-24.04-arm": "native arm64 runner",
    "runs-on: ${{ matrix.runner }}": "matrix runner selection",
    "platforms: ${{ matrix.platform }}": "single-platform native build",
    "scope=sidecar-${{ matrix.artifact }}": "architecture-scoped build cache",
    "push-by-digest=true": "digest-addressed native push",
    "pattern: sidecar-digest-*": "native digest collection",
    "docker buildx imagetools create": "multi-architecture manifest assembly",
    '"linux/amd64"': "amd64 manifest verification",
    '"linux/arm64"': "arm64 manifest verification",
    "IMAGE_DIGEST: ${{ steps.manifest.outputs.digest }}": "assembled-manifest signing",
}
missing = [description for marker, description in required.items() if marker not in text]
if missing:
    raise SystemExit("sidecar image workflow missing: " + ", ".join(missing))

if text.count("platforms: ${{ matrix.platform }}") != 2:
    raise SystemExit("sidecar image workflow must build one native platform in each build path")
if "docker/setup-qemu-action@" in text:
    raise SystemExit("sidecar image workflow must not emulate a release architecture with QEMU")
if "platforms: linux/amd64,linux/arm64" in text:
    raise SystemExit("sidecar image workflow must not serialize both release builds on one runner")

print("PASS: sidecar image workflow builds natively and verifies the assembled manifest")
PY
