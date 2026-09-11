"""Exercise actual HTTP, MCP, storage, approval and revocation boundaries."""

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from chio.invariants import (
    canonicalize_json,
    sha256_hex_utf8,
    verify_http_receipt_with_trusted_signers,
    verify_receipt_with_trusted_signers,
)
from commerce_network.chio import TrustControl
from run import request


def qualify(state, run, endpoints):
    observations = []
    trust = TrustControl(endpoints["control"], endpoints["service_token"])
    cap = trust.issue_capability(
        subject_pk=endpoints["signers"]["caller"],
        ttl=900,
        scope={
            "grants": [
                {
                    "server_id": "chio_http_authority",
                    "tool_name": "authorize_http_request",
                    "operations": ["invoke"],
                    "constraints": [],
                }
            ],
            "resource_grants": [],
            "prompt_grants": [],
        },
    )

    def call(case, path, body=None, expected=202, headers=None, grant=cap):
        status, response_headers, output = request(
            endpoints["buyer"] + path, body, capability=grant, headers=headers
        )
        if status != expected:
            raise AssertionError(f"{case}: HTTP {status}: {output}")
        identity = response_headers.get("X-Chio-Receipt-Id")
        if not identity:
            raise AssertionError(f"{case}: missing HTTP receipt association")
        with sqlite3.connect(
            (state / "buyer-receipts.sqlite3").resolve().as_uri() + "?mode=ro", uri=True
        ) as db:
            row = db.execute(
                "SELECT receipt_json FROM http_receipts WHERE id=?", (identity,)
            ).fetchone()
        if not row:
            raise AssertionError(f"{case}: missing retained HTTP receipt")
        receipt = json.loads(row[0])
        checks = verify_http_receipt_with_trusted_signers(receipt, [endpoints["signers"]["buyer"]])
        binding = {
            "method": "GET" if body is None else "POST",
            "path": path,
            "query": {},
            "route_pattern": receipt["route_pattern"],
            "body_hash": hashlib.sha256(json.dumps(body).encode()).hexdigest()
            if body is not None
            else None,
        }
        if (
            not checks["ok"]
            or sha256_hex_utf8(canonicalize_json(binding)) != receipt["content_hash"]
            or receipt["response_status"] != status
        ):
            raise AssertionError(f"{case}: receipt does not verify for this actual request")
        observations.append(
            {
                "case": case,
                "request": binding,
                "body": body,
                "status": status,
                "receipt": receipt,
                "verification": checks,
                "output": output,
            }
        )
        return output

    def quote(case, scope="hotfix-review"):
        return call(
            case,
            "/procurement/quote-requests",
            {
                "service_family": "security-review",
                "requested_scope": scope,
                "target": "payments-api",
            },
        )["quote"]

    def terms(value, **changes):
        return {
            "quote_id": value["quote_id"],
            "provider_id": "vanguard-security",
            "service_family": "security-review",
            **changes,
        }

    def snapshot():
        with sqlite3.connect((state / "buyer.db").resolve().as_uri() + "?mode=ro", uri=True) as db:
            return {
                "jobs": db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                "ledger": db.execute(
                    "SELECT COUNT(*), COALESCE(SUM(amount),0) FROM ledger"
                ).fetchone(),
                "committed": db.execute(
                    "SELECT COALESCE(SUM(amount),0) FROM positions WHERE status IN ('reserved','settled')"
                ).fetchone()[0],
            }

    q = quote("quote actual source review")
    call(
        "provider substitution refused",
        "/procurement/jobs",
        terms(q, provider_id="unapproved-provider"),
        expected=409,
    )
    call("negative budget refused", "/procurement/jobs", terms(q, budget_minor=-1), expected=422)
    call(
        "caller cannot raise operator ceiling",
        "/procurement/jobs",
        terms(q, budget_minor=500_001),
        expected=409,
    )
    denied = call("zero budget stays zero", "/procurement/jobs", terms(q, budget_minor=0))
    assert denied["status"] == "denied_budget" and snapshot()["committed"] == 0
    q = quote("quote completed work")
    job = call("accept completed work", "/procurement/jobs", terms(q))
    assert job["status"] == "fulfilled" and job["settlement"]["settled_amount_minor"] == 45_000
    for artifact in job["fulfillment"]["artifacts"]:
        assert hashlib.sha256(artifact["content"].encode()).hexdigest() == artifact["sha256"]
    settled = snapshot()
    call("quote replay refused", "/procurement/jobs", terms(q), expected=409)
    assert snapshot() == settled

    expensive = quote("quote independently approved work", "release-review")
    pending = call("reserve approval budget", "/procurement/jobs", terms(expensive))
    assert pending["status"] == "pending_approval" and pending["fulfillment"] is None
    approval = {"approver": "application-operator", "reason": "Reviewed scope and remaining budget"}
    approval_path = "/procurement/jobs/" + pending["job_id"] + "/approve"
    waiting = snapshot()
    call("agent credential cannot approve", approval_path, approval, expected=403)
    assert snapshot() == waiting
    approved = call(
        "independent operator approves",
        approval_path,
        approval,
        expected=200,
        headers={"X-Buyer-Approval": endpoints["approval_token"]},
    )
    assert (
        approved["status"] == "fulfilled"
        and approved["settlement"]["settled_amount_minor"] == 125_000
    )
    call(
        "approval replay refused",
        approval_path,
        approval,
        expected=409,
        headers={"X-Buyer-Approval": endpoints["approval_token"]},
    )

    # Eight simultaneous purchases compete for the 330000 remaining units.
    # Each costs 45000: exactly seven can reserve and settle.
    quotes = [quote(f"concurrent quote {index}") for index in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = list(
            pool.map(
                lambda value: call("concurrent purchase", "/procurement/jobs", terms(value)), quotes
            )
        )
    assert sum(item["status"] == "fulfilled" for item in jobs) == 7
    assert sum(item["status"] == "denied_budget" for item in jobs) == 1
    assert snapshot()["committed"] == 485_000 and snapshot()["ledger"][1] == 0

    before = snapshot()
    revoked_status, _, _ = request(
        endpoints["control"] + "/v1/revocations",
        {"capabilityId": cap["id"]},
        token=endpoints["service_token"],
    )
    assert revoked_status == 200
    call(
        "revoked caller refused before provider work",
        "/procurement/quote-requests",
        {
            "service_family": "security-review",
            "requested_scope": "hotfix-review",
            "target": "payments-api",
        },
        expected=403,
    )
    assert snapshot() == before

    # Directly exercise the buyer's provider boundary with a new low-cost
    # quote. The operator-owned test ledger is independent of user state.
    # An unavailable provider must return a visible error, never a fake quote.
    fresh = trust.issue_capability(
        subject_pk=endpoints["signers"]["caller"], ttl=900, scope=cap["scope"]
    )
    endpoints["provider_process"].terminate()
    endpoints["provider_process"].wait(timeout=10)
    call(
        "provider unavailable",
        "/procurement/quote-requests",
        {
            "service_family": "security-review",
            "requested_scope": "hotfix-review",
            "target": "payments-api",
        },
        expected=502,
        grant=fresh,
    )
    assert snapshot() == before

    tools = {}
    for observation in observations:
        for key in ("provider_trace", "quote_provider_trace", "fulfillment_trace"):
            trace = observation["output"].get(key)
            if not trace:
                continue
            receipt = trace["receipt"]
            check = verify_receipt_with_trusted_signers(receipt, [endpoints["signers"]["provider"]])
            assert check["ok"] and receipt["id"] == trace["receipt_id"]
            assert receipt["metadata"]["receipt_context"]["request_id"] == trace["request_id"]
            assert receipt["action"]["parameters"] == trace["arguments"]
            assert sha256_hex_utf8(canonicalize_json(trace["result"])) == receipt["content_hash"]
            tools[receipt["id"]] = {"association": trace, "receipt": receipt, "verification": check}
    output = {
        "ok": True,
        "operator_budget_minor": 500_000,
        "ledger": snapshot(),
        "http": observations,
        "mcp": list(tools.values()),
    }
    (run / "verification.json").write_text(json.dumps(output, indent=2) + "\n")
    print(
        f"Passed {len(observations)} actual HTTP operations and {len(tools)} signed provider operations.\nEvidence: {run}"
    )
