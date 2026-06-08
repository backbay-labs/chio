#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
QUALIFY="$REPO_ROOT/scripts/qualify-release.sh"

grep -F "cargo test -p chio-provider-conformance" "$QUALIFY" >/dev/null
grep -F -- "--features fixtures-gemini,fixtures-mistral,fixtures-groq,fixtures-ollama,fixtures-cohere" "$QUALIFY" >/dev/null
grep -F -- "--test replay_gemini" "$QUALIFY" >/dev/null
grep -F -- "--test replay_mistral" "$QUALIFY" >/dev/null
grep -F -- "--test replay_groq" "$QUALIFY" >/dev/null
grep -F -- "--test replay_ollama" "$QUALIFY" >/dev/null
grep -F -- "--test replay_cohere" "$QUALIFY" >/dev/null

echo "qualify-release-provider-replay.test.sh: provider replay gate present"
