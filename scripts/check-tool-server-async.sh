#!/usr/bin/env bash
# Scope guard: we only flag method bodies that appear in the same `impl` block as
# the trait. Other functions named `invoke` (e.g. `pub fn invoke` on adapter
# structs) are not flagged.
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
from pathlib import Path
import re
import sys

IMPL_RE = re.compile(
    r"^(\s*)impl\s+(?:[A-Za-z_][\w:]*\s*::\s*)?ToolServerConnection\b[^\{]*\{\s*$"
)
SYNC_METHOD_RE = re.compile(
    r"^\s*(?:pub(?:\([a-z]+\))?\s+)?fn\s+(?:invoke|invoke_with_cost|invoke_stream|drain_events)\s*\("
)

ROOTS = [Path("crates"), Path("examples"), Path("tests"), Path("integrations")]

violations = []
for root in ROOTS:
    if not root.exists():
        continue
    for path in root.rglob("*.rs"):
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if "ToolServerConnection" not in text:
            continue
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            m = IMPL_RE.match(lines[i])
            if not m:
                i += 1
                continue
            # Walk forward tracking brace depth so we know when the impl block
            # ends. The impl `{` is on this line; depth starts at 1.
            depth = lines[i].count("{") - lines[i].count("}")
            i += 1
            while i < len(lines) and depth > 0:
                ln = lines[i]
                if SYNC_METHOD_RE.match(ln):
                    violations.append(f"{path}:{i + 1}: {ln.strip()}")
                depth += ln.count("{") - ln.count("}")
                i += 1

if violations:
    print(
        "ToolServerConnection async-trait sync-fn detected: sync `fn invoke*` found inside `impl ToolServerConnection` blocks"
    )
    print(
        "Each `impl ToolServerConnection` must use `#[async_trait::async_trait]` and `async fn` bodies."
    )
    print()
    for v in violations:
        print(v)
    sys.exit(1)

print("OK: every ToolServerConnection impl uses async fn bodies")
PY
