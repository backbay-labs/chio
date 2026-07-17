#!/usr/bin/env python3
"""MCP server for read-only web3 validation evidence inspection."""
from __future__ import annotations

import json
import os
import sys
import hashlib
from pathlib import Path

ROOT = Path(os.getenv("CHIO_IOA_WEB3_REPO_ROOT", Path(__file__).resolve().parents[3]))
CONTRACT_PACKAGE_PATH = ROOT / "docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json"
EXPECTED_BASE_SEPOLIA_CHAIN_ID = "eip155:84532"

TOOLS = [
    {
        "name": "list_validation_artifacts",
        "description": "List the web3 validation artifacts that gate this example.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "summarize_base_sepolia_smoke",
        "description": "Summarize the Base Sepolia smoke report without exposing secrets.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "build_cutover_readiness",
        "description": "Build a read-only cutover readiness summary from local evidence.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _read(path: Path) -> dict:
    if not path.exists():
        return {"status": "missing", "path": str(path)}
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _status_passes(report: dict) -> bool:
    status = str(report.get("status") or report.get("outcome") or "").lower()
    return status in {"pass", "passed", "approved", "promoted"} or report.get("ok") is True


def _checks_pass(report: dict) -> bool:
    checks = report.get("checks") or report.get("items") or []
    if not checks:
        return _status_passes(report)
    for check in checks:
        if not isinstance(check, dict):
            return False
        status = str(check.get("status") or check.get("outcome") or "").lower()
        if status not in {"pass", "passed", "checked", "complete"} and check.get("checked") is not True:
            return False
    return True


def _tx_hash(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if not value.startswith("0x") or len(value) != 66:
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


def _bytes32(value: object) -> bool:
    return _tx_hash(value)


def _expected_runtime_contracts() -> list[dict]:
    package = _read(CONTRACT_PACKAGE_PATH)
    contracts = package.get("contracts") or []
    if not isinstance(contracts, list):
        return []
    return [
        contract
        for contract in contracts
        if isinstance(contract, dict)
        and contract.get("contract_id")
        and contract.get("kind")
        and contract.get("deployed_runtime_codehash")
    ]


def _runtime_codehash_records_pass(deployment: dict) -> bool:
    if deployment.get("chain_id") != EXPECTED_BASE_SEPOLIA_CHAIN_ID:
        return False
    expected_contracts = _expected_runtime_contracts()
    if not expected_contracts:
        return False
    records = deployment.get("deployed_runtime_codehashes") or {}
    addresses = deployment.get("deployed_contract_addresses") or deployment.get("contracts") or {}
    if not isinstance(records, dict) or not records:
        return False
    if not isinstance(addresses, dict) or not addresses:
        return False
    for contract in expected_contracts:
        contract_id = contract["contract_id"]
        kind = contract["kind"]
        expected_codehash = str(contract["deployed_runtime_codehash"]).lower()
        record = records.get(contract_id) or records.get(kind)
        if not isinstance(record, dict):
            return False
        normalized = record.get("immutable_normalized_runtime_codehash")
        package = record.get("package_runtime_codehash")
        actual = record.get("actual_runtime_codehash")
        if not (_bytes32(actual) and _bytes32(normalized) and _bytes32(package)):
            return False
        if normalized.lower() != expected_codehash or package.lower() != expected_codehash:
            return False
        if not isinstance(record.get("observed_block_number"), int):
            return False
        if not _bytes32(record.get("observed_block_hash")):
            return False
        if record.get("observation_source") != "eth_getCode":
            return False
        if not (addresses.get(contract_id) or addresses.get(contract_id.replace("chio.", "").replace("-", "_"))):
            return False
    return True


def _deployment_transactions_pass(deployment: dict) -> bool:
    expected_contracts = _expected_runtime_contracts()
    if not expected_contracts:
        return False
    transactions = deployment.get("deployment_transactions") or {}
    if not isinstance(transactions, dict) or not transactions:
        return False
    for contract in expected_contracts:
        record = transactions.get(contract["contract_id"]) or transactions.get(contract["kind"])
        if not isinstance(record, dict):
            return False
        status = str(record.get("status") or "").lower()
        if status == "already_deployed":
            if not _bytes32(record.get("observed_block_hash")):
                return False
            if not isinstance(record.get("observed_block_number"), int):
                return False
            continue
        if status not in {"deployed", "submitted", "confirmed"}:
            return False
        if not _tx_hash(record.get("tx_hash")):
            return False
    return True


def _artifact_paths() -> dict[str, Path]:
    return {
        "e2e": ROOT / "target/web3-e2e-qualification/partner-qualification.json",
        "promotion": ROOT / "target/web3-promotion-qualification/promotion-qualification.json",
        "ops": ROOT / "target/web3-ops-qualification/incident-audit.json",
        "base_sepolia_smoke": ROOT / "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json",
        "base_sepolia_deployment": ROOT / "target/web3-live-rollout/base-sepolia/promotion/deployment.json",
        "base_sepolia_promotion": ROOT / "target/web3-live-rollout/base-sepolia/promotion/promotion-report.json",
        "mainnet_checklist": ROOT / "docs/release/CHIO_WEB3_MAINNET_CUTOVER_CHECKLIST.md",
    }


def _list_validation_artifacts() -> dict:
    return {
        name: {"path": str(path), "exists": path.exists(), "sha256": _sha256(path)}
        for name, path in _artifact_paths().items()
    }


def _summarize_base_sepolia_smoke() -> dict:
    smoke = _read(_artifact_paths()["base_sepolia_smoke"])
    if smoke.get("status") == "missing":
        return smoke
    return {
        "status": smoke.get("status"),
        "chain_id": smoke.get("chain_id"),
        "actor": smoke.get("actor"),
        "tx_count": len(smoke.get("transactions", [])),
        "checks": smoke.get("checks", []),
        "transaction_ids": [tx.get("id") for tx in smoke.get("transactions", [])],
    }


def _build_cutover_readiness() -> dict:
    artifacts = _list_validation_artifacts()
    smoke = _summarize_base_sepolia_smoke()
    paths = _artifact_paths()
    e2e = _read(paths["e2e"])
    promotion = _read(paths["promotion"])
    ops = _read(paths["ops"])
    live_deployment = _read(paths["base_sepolia_deployment"])
    live_promotion = _read(paths["base_sepolia_promotion"])
    e2e_passed = _checks_pass(e2e)
    promotion_passed = _checks_pass(promotion)
    ops_passed = _checks_pass(ops)
    live_promotion_passed = _checks_pass(live_promotion)
    live_deployment_bound = (
        _runtime_codehash_records_pass(live_deployment)
        and _deployment_transactions_pass(live_deployment)
    )
    smoke_transactions_bound = bool(smoke.get("transaction_ids"))
    return {
        "mainnet_blocked": True,
        "local_evidence_present": e2e_passed and promotion_passed and ops_passed,
        "base_sepolia_smoke_passed": smoke.get("status") == "pass" and smoke_transactions_bound,
        "base_sepolia_chain_id": smoke.get("chain_id"),
        "base_sepolia_smoke_path": "target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json"
        if smoke
        else None,
        "base_sepolia_transaction_ids": smoke.get("transaction_ids", []),
        "promotion_evidence_passed": promotion_passed and live_promotion_passed,
        "ops_evidence_passed": ops_passed,
        "deployment_evidence_passed": live_deployment_bound,
        "artifact_sha256": {
            name: artifact["sha256"]
            for name, artifact in artifacts.items()
            if artifact.get("sha256")
        },
        "next_gate": "review live Chainlink mainnet feeds and split signer roles before approval",
    }


def _respond(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


while True:
    line = sys.stdin.readline()
    if not line:
        break
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        _respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "internet-of-agents-web3-evidence", "version": "0.1.0"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        _respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = message["params"]["name"]
        if name == "list_validation_artifacts":
            structured = _list_validation_artifacts()
        elif name == "summarize_base_sepolia_smoke":
            structured = _summarize_base_sepolia_smoke()
        elif name == "build_cutover_readiness":
            structured = _build_cutover_readiness()
        else:
            _respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"unknown tool: {name}"},
            })
            continue
        _respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "text", "text": json.dumps(structured)}],
                "structuredContent": structured,
                "isError": False,
            },
        })
    elif message.get("id") is not None:
        _respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32601, "message": f"unsupported method: {method}"},
        })
