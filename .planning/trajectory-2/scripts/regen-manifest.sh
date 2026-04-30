#!/usr/bin/env bash
# regen-manifest.sh
#
# Regenerate .planning/trajectory-2/tickets/manifest.yml from the
# per-phase ticket files at .planning/trajectory-2/tickets/M{nn}/P{n}.yml.
# The manifest is the id-sorted concatenation of all phase files; the
# per-phase files remain the source of truth.
#
# Usage:
#   bash .planning/trajectory-2/scripts/regen-manifest.sh
#   bash .planning/trajectory-2/scripts/regen-manifest.sh --check
#
# Requires: yq v4.x (install via .planning/trajectory-2/scripts/install-orchestrator-tools.sh).

set -euo pipefail

CHECK_ONLY=0
case "${1:-}" in
  --check) CHECK_ONLY=1 ;;
  "") ;;
  *) echo "unknown flag: $1" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TRAJ_DIR="${REPO_ROOT}/.planning/trajectory-2"
TICKETS_DIR="${TRAJ_DIR}/tickets"
MANIFEST="${TICKETS_DIR}/manifest.yml"

if ! command -v yq >/dev/null 2>&1; then
  echo "yq not found; install via .planning/trajectory-2/scripts/install-orchestrator-tools.sh" >&2
  exit 2
fi

YQ_VERSION="$(yq --version 2>&1 | head -n1)"
if ! grep -qE 'v?4\.' <<<"${YQ_VERSION}"; then
  echo "yq must be v4.x; saw: ${YQ_VERSION}" >&2
  exit 2
fi

shopt -s nullglob
PHASE_FILES=("${TICKETS_DIR}"/M*/P*.yml)
if [[ "${#PHASE_FILES[@]}" -eq 0 ]]; then
  echo "no per-phase ticket files found under ${TICKETS_DIR}" >&2
  exit 1
fi

TOTAL_TICKETS="$(yq -N ea '[.[]] | length' "${PHASE_FILES[@]}")"

TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

cat > "${TMP}" <<EOF
# GENERATED from per-phase files under .planning/trajectory-2/tickets/M{nn}/P{n}.yml
# Do not hand-edit. Regenerate with:
#   bash .planning/trajectory-2/scripts/regen-manifest.sh
# CI validates manifest.yml against schema.json on every PR.
#
# Total: ${TOTAL_TICKETS} tickets across 10 milestones, ${#PHASE_FILES[@]} per-phase files.
# The per-phase files under tickets/M{nn}/P{n}.yml are the source of truth.
EOF

yq -N ea '[.[]] | sort_by(.id)' "${PHASE_FILES[@]}" >> "${TMP}"

if [[ "${CHECK_ONLY}" -eq 1 ]]; then
  if cmp -s "${TMP}" "${MANIFEST}"; then
    echo "manifest.yml in sync with ${#PHASE_FILES[@]} phase files"
    exit 0
  fi
  echo "manifest.yml is stale; rerun cargo xtask trajectory regen-manifest --trajectory trajectory-2" >&2
  exit 1
fi

mv "${TMP}" "${MANIFEST}"
trap - EXIT

echo "regenerated ${MANIFEST} (${TOTAL_TICKETS} tickets across ${#PHASE_FILES[@]} phase files)"
