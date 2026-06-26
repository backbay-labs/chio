#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
from pathlib import Path

checks = [
    {
        "file": "crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs",
        "required": [
            "evaluate_tool_call_operation",
            "self.kernel.evaluate_session_operation",
            "evaluate_tool_call_operation_with_nested_flow_client",
        ],
    },
    {
        "file": "crates/products/chio-api-protect/src/evaluator.rs",
        "required": [
            "self.authority.evaluate",
            "capability_id",
            "Decision::Deny",
        ],
    },
    {
        "file": "crates/protocol/chio-openapi/src/proxy.rs",
        "required": [
            "evaluate",
            "receipt",
        ],
        "optional": True,
    },
]

swarm_runtime_route_plan_contract = [
    {
        "file": "crates/kernel/chio-runtime-core/src/admission_hook/swarm_ref.rs",
        "required": [
            "routePlanReceipt",
            "routePlanReceiptSha256",
            "required_swarm_evidence_ref",
        ],
    },
    {
        "file": "crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs",
        "required": [
            "verify_swarm_authority_reference_from_store",
            "verify_route_metadata_matches",
            "verify_swarm_authority_bundle",
            "continuation.route_plan_receipt_id != reference.route_plan_receipt.evidence_id",
        ],
    },
    {
        "file": "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        "required": [
            "verify_swarm_authority_reference_from_store",
            "consume_swarm_continuation",
            "admission_now_unix_ms",
        ],
    },
    {
        "file": "crates/kernel/chio-kernel/src/kernel/validation.rs",
        "required": [
            "NoopBudgetRegistry",
            "admit_capability_budget",
            "signature first, admit last",
        ],
    },
]

failures = []
process_lifecycle_spawns = {
    Path("crates/protocol/chio-acp-proxy/src/transport.rs"):
        "ACP transport spawn starts the wrapped agent process; ACP messages are mediated by the proxy interceptor before forwarding",
}

def is_test_path(path: Path) -> bool:
    return "tests" in path.parts or path.name.endswith("_tests.rs")

for check in checks:
    path = Path(check["file"])
    if not path.exists():
        if check.get("optional"):
            continue
        failures.append(f"missing file: {path}")
        continue
    text = path.read_text(encoding="utf-8")
    for required in check["required"]:
        if required not in text:
            failures.append(f"{path} missing mediation marker: {required}")

for check in swarm_runtime_route_plan_contract:
    path = Path(check["file"])
    if not path.exists():
        failures.append(f"missing swarm route-plan enforcement file: {path}")
        continue
    text = path.read_text(encoding="utf-8")
    for required in check["required"]:
        if required not in text:
            failures.append(f"{path} missing swarm route-plan marker: {required}")

adapter_roots = set()
for crate in Path("crates").glob("*/chio-*"):
    if not crate.is_dir():
        continue
    if any(part in crate.name for part in ("adapter", "edge", "bridge", "proxy")):
        adapter_roots.add(crate / "src")
for explicit in (
    "crates/products/chio-api-protect/src",
    "crates/protocol/chio-cross-protocol/src",
    "crates/protocol/chio-openapi/src",
):
    adapter_roots.add(Path(explicit))
for root in sorted(adapter_roots):
    if not root.exists():
        continue
    for path in root.rglob("*.rs"):
        if is_test_path(path):
            continue
        text = path.read_text(encoding="utf-8")
        forbidden_hits = []
        for marker in ["Command::new", ".spawn(", ".invoke("]:
            if marker in text and "evaluate" not in text and "kernel" not in text:
                forbidden_hits.append(marker)
        if forbidden_hits:
            if path in process_lifecycle_spawns:
                continue
            failures.append(
                f"{path} contains side-effect marker(s) without local mediation marker: {forbidden_hits}"
            )

if failures:
    raise SystemExit("adapter no-bypass check failed:\n" + "\n".join(failures))
PY

echo "Adapter no-bypass check passed"
