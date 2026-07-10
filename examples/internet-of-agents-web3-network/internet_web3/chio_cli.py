"""Real Chio CLI workflows for passport, reputation, and federation artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from .artifacts import ArtifactStore, Json, now_epoch
from .capabilities import grant, scope
from .identity import digest

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EXAMPLE_ROOT.parents[1]
IOA_WEB3_TENANT_ID = "tenant-ioa-web3"
PASSPORT_ISSUER_SEED_HEX = hashlib.sha256(b"meridian-passport-issuer").hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _chio_bin() -> str:
    return os.environ.get("CHIO_BIN", str(REPO_ROOT / "target/debug/chio"))


def _run_chio(args: list[str], *, cwd: Path = REPO_ROOT) -> Json:
    command = [_chio_bin(), "--format", "json", *args]
    recorded_command = ["chio", "--format", "json", *args]
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "chio command failed\n"
            f"command: {' '.join(recorded_command)}\n"
            f"stdout: {completed.stdout}\n"
            f"stderr: {completed.stderr}"
        )
    stdout = completed.stdout.strip()
    if not stdout:
        return {"command": recorded_command, "stdout": ""}
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        parsed = {"stdout": stdout}
    if isinstance(parsed, dict):
        parsed.setdefault("command", recorded_command)
        return parsed
    return {"command": recorded_command, "output": parsed}


def _write_seed(path: Path, seed_hex: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(seed_hex + "\n", encoding="utf-8")


def _signing_key(seed_hex: str) -> SigningKey:
    return SigningKey(bytes.fromhex(seed_hex))


def _sign_json(seed_hex: str, body: Json) -> tuple[str, str]:
    key = _signing_key(seed_hex)
    signature = key.sign(_canonical(body)).signature.hex()
    public_key = key.verify_key.encode(encoder=HexEncoder).decode("utf-8")
    return public_key, signature


def _receipt_id_input(body: Json) -> Json:
    required_fields = (
        "timestamp",
        "capability_id",
        "tool_server",
        "tool_name",
        "action",
        "receipt_kind",
        "boundary_class",
        "tool_origin",
        "redaction_mode",
        "content_hash",
        "policy_hash",
        "trust_level",
        "kernel_key",
    )
    receipt_input = {field: body[field] for field in required_fields}
    for field in (
        "decision",
        "observation_outcome",
        "metadata",
        "tenant_id",
        "bbs_projection_version",
    ):
        if body.get(field) is not None:
            receipt_input[field] = body[field]
    for field in ("actor_chain", "evidence"):
        if body.get(field):
            receipt_input[field] = body[field]
    return receipt_input


def _prepare_chio_receipt_body(body: Json) -> Json:
    prepared = json.loads(json.dumps(body, separators=(",", ":"), sort_keys=True))
    nonce = str(prepared.get("id", "")).strip()
    if nonce:
        metadata = prepared.get("metadata")
        if isinstance(metadata, dict):
            bound_metadata = dict(metadata)
        elif metadata is None:
            bound_metadata = {}
        else:
            bound_metadata = {"original_metadata": metadata}
        bound_metadata["chio_receipt_signing_nonce"] = nonce
        prepared["metadata"] = bound_metadata
    prepared["id"] = _sha256(_receipt_id_input(prepared))
    return prepared


def _sign_chio_receipt(seed_hex: str, body: Json) -> tuple[str, Json]:
    key = _signing_key(seed_hex)
    prepared = _prepare_chio_receipt_body(body)
    signing_body = {"id": prepared["id"], "body": _receipt_id_input(prepared)}
    signature = key.sign(_canonical(signing_body)).signature.hex()
    public_key = key.verify_key.encode(encoder=HexEncoder).decode("utf-8")
    receipt = {**prepared, "signature": signature}
    return public_key, receipt


def _ensure_receipt_schema(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS chio_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                tenant_id TEXT
            );
            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id TEXT PRIMARY KEY,
                subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def _seed_history_receipts(
    *,
    receipt_db: Path,
    provider_identity: Any,
    provider_capability: Json,
    provider_bids: Json,
) -> Json:
    _ensure_receipt_schema(receipt_db)
    now = now_epoch()
    issuer_seed = PASSPORT_ISSUER_SEED_HEX
    issuer_key, _ = _sign_json(issuer_seed, {"seed": "history"})
    grants = scope(
        grant("provider-review", "inspect_service_order", ["invoke"]),
        grant("provider-review", "evaluate_provider_reputation", ["invoke"]),
        grant("provider-review", "issue_review_attestation", ["invoke"]),
    )
    conn = sqlite3.connect(receipt_db)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO capability_lineage (
                capability_id, subject_key, issuer_key, issued_at, expires_at,
                grants_json, delegation_depth, parent_capability_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            """,
            (
                provider_capability["id"],
                provider_identity.public_key,
                provider_capability["issuer"],
                provider_capability["issued_at"],
                provider_capability["expires_at"],
                json.dumps(grants, separators=(",", ":"), sort_keys=True),
                len(provider_capability.get("delegation_chain", [])),
                provider_capability.get("delegation_chain", [{}])[-1].get("capability_id"),
            ),
        )
        jobs = [
            ("history-job-001", "issue_review_attestation", "allow", now - 86400 * 21),
            ("history-job-002", "issue_review_attestation", "allow", now - 86400 * 14),
            ("history-job-003", "issue_review_attestation", "allow", now - 86400 * 10),
            ("history-job-004", "issue_review_attestation", "allow", now - 86400 * 5),
            ("history-job-005", "issue_review_attestation", "allow", now - 86400 * 2),
        ]
        ledger = {
            "schema": "chio.example.ioa-web3.historical-reputation-ledger.v1",
            "source": "seeded-chio-receipt-db",
            "receiptDb": str(receipt_db),
            "subjectPublicKey": provider_identity.public_key,
            "jobs": [],
        }
        for index, (job_id, tool_name, decision, timestamp) in enumerate(jobs):
            decision_body: Json
            if decision == "allow":
                decision_body = {"verdict": "allow"}
            else:
                decision_body = {
                    "verdict": "deny",
                    "reason": "historical provider evidence failed local review",
                    "guard": "ioa-web3-provider-history",
                }
            body = {
                "id": f"rcpt-{job_id}",
                "timestamp": timestamp,
                "capability_id": provider_capability["id"],
                "tool_server": "provider-review",
                "tool_name": tool_name,
                "action": {
                    "parameters": {"job_id": job_id, "provider": "proofworks-agent-auditors"},
                    "parameter_hash": _sha256({"job_id": job_id, "provider": "proofworks-agent-auditors"}),
                },
                "decision": decision_body,
                "receipt_kind": "mediated_decision",
                "boundary_class": "prevent",
                "tool_origin": "caller_executed",
                "redaction_mode": "none",
                "content_hash": _sha256({"job_id": job_id, "outcome": decision}),
                "policy_hash": "ioa-web3-provider-history-policy",
                "metadata": {
                    "attribution": {
                        "subject_key": provider_identity.public_key,
                        "issuer_key": issuer_key,
                        "delegation_depth": len(provider_capability.get("delegation_chain", [])),
                        "grant_index": min(index, 2),
                    },
                    "historical_job": {
                        "job_id": job_id,
                        "provider_id": "proofworks-agent-auditors",
                    },
                },
                "trust_level": "mediated",
                "tenant_id": IOA_WEB3_TENANT_ID,
                "kernel_key": issuer_key,
            }
            _, receipt = _sign_chio_receipt(issuer_seed, body)
            conn.execute(
                """
                INSERT OR REPLACE INTO chio_tool_receipts (
                    receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index,
                    tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json, tenant_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                """,
                (
                    receipt["id"],
                    timestamp,
                    provider_capability["id"],
                    provider_identity.public_key,
                    issuer_key,
                    min(index, 2),
                    "provider-review",
                    tool_name,
                    decision,
                    body["policy_hash"],
                    body["content_hash"],
                    json.dumps(receipt, separators=(",", ":"), sort_keys=True),
                    IOA_WEB3_TENANT_ID,
                ),
            )
            ledger["jobs"].append({
                "job_id": job_id,
                "receipt_id": receipt["id"],
                "decision": decision,
                "timestamp": timestamp,
            })
        conn.commit()
    finally:
        conn.close()
    return ledger


@dataclass(frozen=True)
class ChioPassportWorkflow:
    passport: Json
    passport_verdict: Json
    challenge: Json
    presentation: Json
    presentation_verdict: Json


@dataclass(frozen=True)
class ChioReputationWorkflow:
    report: Json
    comparison: Json
    verdict: Json


@dataclass(frozen=True)
class ChioFederationWorkflow:
    policy: Json
    evidence_export: Json
    evidence_import: Json
    admission: Json
    federated_capability: Json


def run_provider_passport_workflow(
    *,
    store: ArtifactStore,
    provider_identity: Any,
    provider_capability: Json,
    provider_bids: Json,
    federation_control_url: str | None,
    service_token: str,
) -> tuple[ChioPassportWorkflow, Json]:
    state_dir = store.root / "state"
    receipt_db = state_dir / "provider-receipts.sqlite3"
    budget_db = state_dir / "provider-budgets.sqlite3"
    seed_dir = state_dir / "chio-cli-seeds"
    passport_issuer_seed = seed_dir / "passport-issuer.seed"
    holder_seed = seed_dir / "provider-holder.seed"
    challenge_db = state_dir / "provider-passport-challenges.sqlite3"
    passport_path = store.root / "identity/passports/proofworks-provider-passport.json"
    challenge_path = store.root / "identity/presentations/provider-challenge.json"
    response_path = store.root / "identity/presentations/provider-presentation.json"
    verifier_policy_path = state_dir / "provider-passport-verifier-policy.yaml"
    provenance_path = "identity/passports/proofworks-provider-passport-provenance.json"

    _write_seed(passport_issuer_seed, PASSPORT_ISSUER_SEED_HEX)
    ledger = _seed_history_receipts(
        receipt_db=receipt_db,
        provider_identity=provider_identity,
        provider_capability=provider_capability,
        provider_bids=provider_bids,
    )
    _write_seed(holder_seed, provider_identity.seed_hex)
    store.write_json("reputation/history-ledger.json", ledger)

    create = _run_chio([
        "--receipt-db",
        str(receipt_db),
        "--budget-db",
        str(budget_db),
        "passport",
        "create",
        "--subject-public-key",
        provider_identity.public_key,
        "--output",
        str(passport_path),
        "--signing-seed-file",
        str(passport_issuer_seed),
        "--validity-days",
        "30",
        "--receipt-log-url",
        "https://trust.proofworks.local/receipts",
    ])
    passport = json.loads(passport_path.read_text(encoding="utf-8"))
    issuer = passport["credentials"][0]["issuer"]
    composite = passport["credentials"][0]["credentialSubject"]["metrics"]["composite_score"]["value"]
    verifier_policy_path.write_text(
        "\n".join([
            "issuerAllowlist:",
            f'  - "{issuer}"',
            f"minCompositeScore: {max(0.0, float(composite) - 0.01):.4f}",
            "minReceiptCount: 4",
            "minLineageRecords: 1",
            "",
        ]),
        encoding="utf-8",
    )
    verify = _run_chio(["passport", "verify", "--input", str(passport_path)])
    challenge_args = [
        "passport",
        "challenge",
        "create",
        "--output",
        str(challenge_path),
        "--verifier",
        federation_control_url or "Meridian Federation Verifier",
        "--policy",
        str(verifier_policy_path),
        "--verifier-challenge-db",
        str(challenge_db),
    ]
    challenge_create = _run_chio(challenge_args)
    respond = _run_chio([
        "passport",
        "challenge",
        "respond",
        "--input",
        str(passport_path),
        "--challenge",
        str(challenge_path),
        "--holder-seed-file",
        str(holder_seed),
        "--output",
        str(response_path),
    ])
    challenge_verify = _run_chio([
        "passport",
        "challenge",
        "verify",
        "--input",
        str(response_path),
        "--challenge",
        str(challenge_path),
        "--verifier-challenge-db",
        str(challenge_db),
    ])
    challenge = json.loads(challenge_path.read_text(encoding="utf-8"))
    presentation = json.loads(response_path.read_text(encoding="utf-8"))
    passport_verdict = {
        "schema": "chio.example.ioa-web3.passport-verdict.v1",
        "source": "chio-cli",
        "passportId": passport.get("passportId", passport.get("subject")),
        "verdict": "pass" if verify.get("accepted") is not False else "fail",
        "commandResult": verify,
    }
    presentation_verdict = {
        "schema": "chio.example.ioa-web3.presentation-verdict.v1",
        "source": "chio-cli",
        "presentationId": presentation.get("responseId", presentation.get("presentationId")),
        "challengeId": challenge.get("challengeId"),
        "verdict": "pass" if challenge_verify.get("accepted") is not False else "fail",
        "commandResult": challenge_verify,
    }
    store.write_json("identity/passports/proofworks-provider-passport-verdict.json", passport_verdict)
    store.write_json("identity/presentations/provider-presentation-verdict.json", presentation_verdict)
    store.write_json(provenance_path, {
        "schema": "chio.example.ioa-web3.chio-cli-provenance.v1",
        "source": "chio-cli",
        "commands": {
            "passportCreate": create.get("command"),
            "passportVerify": verify.get("command"),
            "challengeCreate": challenge_create.get("command"),
            "challengeRespond": respond.get("command"),
            "challengeVerify": challenge_verify.get("command"),
        },
        "receiptDb": str(receipt_db),
        "budgetDb": str(budget_db),
        "serviceTokenUsed": bool(service_token),
    })
    return (
        ChioPassportWorkflow(
            passport=passport,
            passport_verdict=passport_verdict,
            challenge=challenge,
            presentation=presentation,
            presentation_verdict=presentation_verdict,
        ),
        ledger,
    )


def run_provider_reputation_workflow(
    *,
    store: ArtifactStore,
    provider_identity: Any,
    passport: Json,
    minimum_score: float = 0.60,
) -> ChioReputationWorkflow:
    state_dir = store.root / "state"
    receipt_db = state_dir / "provider-receipts.sqlite3"
    budget_db = state_dir / "provider-budgets.sqlite3"
    passport_issuer_seed = state_dir / "chio-cli-seeds/passport-issuer.seed"
    passport_path = store.root / "identity/passports/proofworks-provider-passport.json"
    local = _run_chio([
        "--authority-seed-file",
        str(passport_issuer_seed),
        "--receipt-db",
        str(receipt_db),
        "--budget-db",
        str(budget_db),
        "reputation",
        "local",
        "--subject-public-key",
        provider_identity.public_key,
    ])
    compare = _run_chio([
        "--authority-seed-file",
        str(passport_issuer_seed),
        "--receipt-db",
        str(receipt_db),
        "--budget-db",
        str(budget_db),
        "reputation",
        "compare",
        "--subject-public-key",
        provider_identity.public_key,
        "--passport",
        str(passport_path),
    ])
    score = float(local.get("effectiveScore", local.get("scorecard", {}).get("composite_score", {}).get("value", 0.0)))
    report = {
        "schema": "chio.reputation.local-report.v1",
        "source": "chio-cli",
        "subject": passport["subject"],
        "subjectPublicKey": provider_identity.public_key,
        "minimumScore": minimum_score,
        "computedScore": score,
        "commandResult": local,
    }
    comparison = {
        "schema": "chio.reputation.passport-comparison.v1",
        "source": "chio-cli",
        "subject": passport["subject"],
        "subjectMatches": compare.get("subjectMatches"),
        "commandResult": compare,
    }
    verdict = {
        "schema": "chio.example.ioa-web3.reputation-verdict.v1",
        "source": "chio-cli",
        "subject": passport["subject"],
        "verdict": "pass" if score >= minimum_score and compare.get("subjectMatches") is True else "fail",
        "minimumScore": minimum_score,
        "computedScore": score,
    }
    store.write_json("reputation/provider-local-report.json", report)
    store.write_json("reputation/provider-passport-comparison.json", comparison)
    store.write_json("reputation/provider-reputation-verdict.json", verdict)
    return ChioReputationWorkflow(report=report, comparison=comparison, verdict=verdict)


def run_provider_federation_workflow(
    *,
    store: ArtifactStore,
    passport_workflow: ChioPassportWorkflow,
    reputation_verdict: Json,
    provider_capability: Json,
    federation_control_url: str | None,
    service_token: str,
) -> ChioFederationWorkflow:
    state_dir = store.root / "state"
    receipt_db = state_dir / "provider-receipts.sqlite3"
    live_federation_seed = state_dir / "federation-authority.seed"
    federation_seed = live_federation_seed if live_federation_seed.exists() else state_dir / "chio-cli-seeds/federation-policy.seed"
    delegation_seed = live_federation_seed if live_federation_seed.exists() else state_dir / "chio-cli-seeds/federated-delegation.seed"
    policy_path = store.root / "federation/bilateral-evidence-policy.json"
    export_dir = store.root / "federation/evidence-export-package"
    capability_policy = state_dir / "federated-provider-capability-policy.yaml"
    delegation_capability_policy = state_dir / "federated-provider-delegation-ceiling.yaml"
    delegation_policy = store.root / "federation/federated-delegation-policy.json"
    response_path = store.root / "identity/presentations/provider-presentation.json"
    challenge_path = store.root / "identity/presentations/provider-challenge.json"

    if not live_federation_seed.exists():
        _write_seed(federation_seed, hashlib.sha256(b"meridian-federation-policy").hexdigest())
        _write_seed(delegation_seed, hashlib.sha256(b"meridian-federated-delegation").hexdigest())
    if export_dir.exists():
        shutil.rmtree(export_dir)
    _run_chio([
        "evidence",
        "federation-policy",
        "create",
        "--output",
        str(policy_path),
        "--signing-seed-file",
        str(federation_seed),
        "--issuer",
        "ProofWorks Provider",
        "--partner",
        "Meridian Federation Verifier",
        "--capability",
        provider_capability["id"],
        "--tenant",
        IOA_WEB3_TENANT_ID,
        "--expires-at",
        str(now_epoch() + 86400),
        "--purpose",
        "ioa-web3-provider-admission",
    ])
    export = _run_chio([
        "--receipt-db",
        str(receipt_db),
        "evidence",
        "export",
        "--output",
        str(export_dir),
        "--federation-policy",
        str(policy_path),
        "--tenant",
        IOA_WEB3_TENANT_ID,
    ])
    import_args = ["evidence", "import", "--input", str(export_dir)]
    if federation_control_url:
        import_args = [
            "--control-url",
            federation_control_url,
            "--control-token",
            service_token,
            *import_args,
        ]
    imported = _run_chio(import_args)
    capability_policy.write_text(
        "\n".join([
            "kernel:",
            "  max_capability_ttl: 3600",
            "capabilities:",
            "  default:",
            "    tools:",
            '      - server: "provider-review"',
            '        tool: "issue_review_attestation"',
            "        operations: [invoke]",
            "        ttl: 300",
            "",
        ]),
        encoding="utf-8",
    )
    delegation_capability_policy.write_text(
        "\n".join([
            "kernel:",
            "  max_capability_ttl: 3600",
            "capabilities:",
            "  default:",
            "    tools:",
            '      - server: "provider-review"',
            '        tool: "issue_review_attestation"',
            "        operations: [invoke]",
            "        ttl: 900",
            "",
        ]),
        encoding="utf-8",
    )
    _run_chio([
        "trust",
        "federated-delegation-policy-create",
        "--output",
        str(delegation_policy),
        "--signing-seed-file",
        str(delegation_seed),
        "--issuer",
        "Meridian Federation Verifier",
        "--partner",
        "ProofWorks Provider",
        "--verifier",
        federation_control_url or "local",
        "--capability-policy",
        str(delegation_capability_policy),
        "--expires-at",
        str(now_epoch() + 86400),
        "--purpose",
        "ioa-web3-provider-federated-issue",
    ])
    federated_args = [
        "trust",
        "federated-issue",
        "--presentation-response",
        str(response_path),
        "--challenge",
        str(challenge_path),
        "--capability-policy",
        str(capability_policy),
        "--delegation-policy",
        str(delegation_policy),
    ]
    if federation_control_url:
        federated_args = [
            "--control-url",
            federation_control_url,
            "--control-token",
            service_token,
            *federated_args,
        ]
    federated = _run_chio(federated_args)
    manifest = json.loads((export_dir / "manifest.json").read_text(encoding="utf-8"))
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    evidence_export = {
        "schema": "chio.federation.evidence-export.v1",
        "source": "chio-cli",
        "package": "federation/evidence-export-package",
        "manifest": manifest,
        "commandResult": export,
    }
    evidence_import = {
        "schema": "chio.federation.evidence-import.v1",
        "source": "chio-cli" if not federation_control_url else "chio-trust-control",
        "accepted": True,
        "commandResult": imported,
    }
    admission = {
        "schema": "chio.federation.open-admission-evaluation.v1",
        "source": "chio-trust-control" if federation_control_url else "chio-cli",
        "subject": passport_workflow.passport["subject"],
        "verdict": "pass" if federated.get("verification", {}).get("accepted") is not False else "fail",
        "policyId": policy.get("policyId", policy.get("id")),
        "checks": [
            {"id": "passport-presentation", "outcome": "pass"},
            {"id": "reputation-threshold", "outcome": reputation_verdict["verdict"]},
            {"id": "federated-issue", "outcome": "pass"},
        ],
        "commandResult": federated,
    }
    federated_capability = {
        "schema": "chio.federated-provider-capability.v1",
        "source": "chio-trust-control" if federation_control_url else "chio-cli",
        "subject": federated.get("subjectPublicKey"),
        "parentCapabilityId": provider_capability["id"],
        "capability": federated.get("capability"),
        "verification": federated.get("verification"),
    }
    store.write_json("federation/evidence-export.json", evidence_export)
    store.write_json("federation/evidence-import.json", evidence_import)
    store.write_json("federation/open-admission-evaluation.json", admission)
    store.write_json("federation/federated-provider-capability.json", federated_capability)
    return ChioFederationWorkflow(
        policy=policy,
        evidence_export=evidence_export,
        evidence_import=evidence_import,
        admission=admission,
        federated_capability=federated_capability,
    )
