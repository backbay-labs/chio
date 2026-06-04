from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class ArtifactError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ArtifactError(f"missing artifact: {path.name}") from error
    except json.JSONDecodeError as error:
        raise ArtifactError(f"invalid JSON in {path.name}: {error}") from error
    if not isinstance(payload, dict):
        raise ArtifactError(f"{path.name} must contain a JSON object")
    return payload


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise ArtifactError(f"missing artifact: {path.name}") from error

    records: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise ArtifactError(f"invalid JSON in {path.name}:{index}: {error}") from error
        if not isinstance(payload, dict):
            raise ArtifactError(f"{path.name}:{index} must contain a JSON object")
        records.append(payload)
    return records


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactError(message)


def require_string(payload: dict[str, Any], key: str, artifact: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ArtifactError(f"{artifact}.{key} must be a non-empty string")
    return value


def expected_summary(
    capability_id: str, check: dict[str, Any], verify: dict[str, Any]
) -> dict[str, Any]:
    return {
        "example": "hello-trust-control",
        "capability_id": capability_id,
        "receipt_id": require_string(check, "receipt_id", "check.json"),
        "tool": require_string(check, "tool", "check.json"),
        "verdict": require_string(check, "verdict", "check.json"),
        "evidence_verified": True,
        "tool_receipts": verify.get("toolReceipts"),
    }


def validate_or_write_summary(root: Path, summary: dict[str, Any], write: bool) -> None:
    path = root / "summary.json"
    if write:
        path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        return

    existing = load_json(path)
    for key, value in summary.items():
        require(
            existing.get(key) == value,
            f"summary.json.{key} does not match verified artifacts",
        )


def verify_artifact_tree(root: Path, *, write_summary: bool = False) -> dict[str, Any]:
    capability_response = load_json(root / "capability.json")
    capability = capability_response.get("capability")
    require(isinstance(capability, dict), "capability.json.capability must be an object")
    capability_id = require_string(capability, "id", "capability.json.capability")
    require(
        capability.get("schema") == "chio.capability.v1",
        "capability schema must be chio.capability.v1",
    )

    scope = capability.get("scope")
    require(isinstance(scope, dict), "capability scope must be an object")
    grants = scope.get("grants")
    require(isinstance(grants, list) and len(grants) == 1, "capability must carry one grant")
    grant = grants[0]
    require(isinstance(grant, dict), "capability grant must be an object")
    require(
        grant.get("server_id") == "http-sidecar-client",
        "capability grant must stay scoped to the demo server id",
    )
    require(
        grant.get("tool_name") == "hello_trust_control_invoke",
        "capability grant must stay scoped to the trust-control demo tool",
    )
    require(grant.get("operations") == ["invoke"], "capability grant must allow invoke only")

    token = (root / "capability.token").read_text(encoding="utf-8")
    expected_token = json.dumps(capability, separators=(",", ":")) + "\n"
    require(token == expected_token, "capability.token must be compact issued capability JSON")

    status_before = load_json(root / "status-before.json")
    revoke = load_json(root / "revoke.json")
    status_after = load_json(root / "status-after.json")
    for artifact, payload in [
        ("status-before.json", status_before),
        ("revoke.json", revoke),
        ("status-after.json", status_after),
    ]:
        require(
            payload.get("capability_id") == capability_id,
            f"{artifact}.capability_id must match issued capability",
        )
        backend = require_string(payload, "revocation_backend", artifact)
        require(
            backend.startswith("http://127.0.0.1:"),
            f"{artifact}.revocation_backend must use the local trust-control service",
        )

    require(status_before.get("revoked") is False, "status-before.json must be unrevoked")
    require(revoke.get("revoked") is True, "revoke.json must report revoked")
    require(revoke.get("newly_revoked") is True, "revoke.json must report a new revocation")
    require(status_after.get("revoked") is True, "status-after.json must be revoked")

    check = load_json(root / "check.json")
    require(check.get("tool") == "read_file", "check.json.tool must be read_file")
    require(check.get("server") == "*", "check.json.server must stay the wildcard stub")
    require(check.get("verdict") == "ALLOW", "check.json.verdict must be ALLOW")
    require(check.get("params") == {"path": "README.md"}, "check.json.params drifted")
    check_receipt_id = require_string(check, "receipt_id", "check.json")
    check_policy_hash = require_string(check, "policy_hash", "check.json")
    require_string(check, "policy_source_hash", "check.json")

    receipts = load_ndjson(root / "receipts.ndjson")
    receipt = next((record for record in receipts if record.get("id") == check_receipt_id), None)
    require(receipt is not None, "receipts.ndjson must contain the check receipt id")
    require(receipt.get("tool_name") == "read_file", "receipt tool_name must be read_file")
    require(receipt.get("tool_server") == "*", "receipt tool_server must be wildcard stub")
    decision = receipt.get("decision")
    require(isinstance(decision, dict), "receipt decision must be an object")
    require(decision.get("verdict") == "allow", "receipt decision verdict must be allow")
    require(receipt.get("policy_hash") == check_policy_hash, "receipt policy_hash drifted")

    verify = load_json(root / "verify.json")
    require(
        verify.get("schema") == "chio.evidence_export_manifest.v1",
        "verify.json schema drifted",
    )
    require(verify.get("toolReceipts") == 1, "verify.json must prove one tool receipt")
    verified_files = verify.get("verifiedFiles")
    require(
        type(verified_files) is int and verified_files >= 1,
        "verify.json must report verified files",
    )
    require((root / "evidence" / "manifest.json").is_file(), "evidence manifest is missing")
    require((root / "evidence" / "receipts.ndjson").is_file(), "evidence receipts are missing")

    summary = expected_summary(capability_id, check, verify)
    validate_or_write_summary(root, summary, write_summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--write-summary", action="store_true")
    args = parser.parse_args()

    try:
        summary = verify_artifact_tree(
            args.artifact_root.resolve(), write_summary=args.write_summary
        )
    except ArtifactError as error:
        parser.exit(1, f"artifact verification failed: {error}\n")

    print(json.dumps({"verified": True, **summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
