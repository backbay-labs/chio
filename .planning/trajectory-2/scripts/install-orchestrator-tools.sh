#!/usr/bin/env bash
# install-orchestrator-tools.sh
#
# Install the manifest-query toolchain pinned for trajectory-2
# orchestration (EXECUTION-BOARD section 0 item 10): yq v4.x and jq.
# yq is fetched as a static binary into ~/.local/bin; jq comes from the
# system package manager.
#
# Usage:
#   bash .planning/trajectory-2/scripts/install-orchestrator-tools.sh

set -euo pipefail

YQ_VERSION="v4.44.3"
YQ_BIN_DIR="${HOME}/.local/bin"
mkdir -p "${YQ_BIN_DIR}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  YQ_ASSET="yq_linux_amd64"  ;;
  Linux-aarch64) YQ_ASSET="yq_linux_arm64"  ;;
  Darwin-arm64)  YQ_ASSET="yq_darwin_arm64" ;;
  Darwin-x86_64) YQ_ASSET="yq_darwin_amd64" ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m) for pinned yq" >&2; exit 2 ;;
esac

curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_ASSET}" \
  -o "${YQ_BIN_DIR}/yq"
chmod +x "${YQ_BIN_DIR}/yq"

if ! command -v jq >/dev/null 2>&1; then
  if   command -v apt-get >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y jq
  elif command -v brew    >/dev/null 2>&1; then brew install jq
  else echo "install jq manually for your platform" >&2; exit 2
  fi
fi

"${YQ_BIN_DIR}/yq" --version
jq --version
echo "ensure ${YQ_BIN_DIR} is on PATH (add 'export PATH=\"${YQ_BIN_DIR}:\$PATH\"' to your shell rc)"
