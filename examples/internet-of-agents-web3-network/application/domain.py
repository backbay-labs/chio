"""Work-order policy and retained work. Invoked only by the installed kernel host."""

import datetime as dt
import hashlib
import http.client
import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from evidence import canonical, digest, read, verify_result, verify_signed
from nacl.signing import VerifyKey
from native_trust import verify_presentation

HERE = Path(__file__).resolve().parent


class Refused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def connect(directory):
    database = sqlite3.connect(directory / "business.db", timeout=10, isolation_level=None)
    database.execute("PRAGMA journal_mode=WAL")
    database.execute("PRAGMA synchronous=FULL")
    database.executescript("""
      CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, binding TEXT NOT NULL, request TEXT NOT NULL, state TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, provider TEXT NOT NULL, amount INTEGER NOT NULL, invoice TEXT NOT NULL, state TEXT NOT NULL, result TEXT);
      CREATE TABLE IF NOT EXISTS native_admissions(id TEXT PRIMARY KEY, presentation_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY, input_hash TEXT NOT NULL, output TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL, tool TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL, time INTEGER NOT NULL);
    """)
    return database


def check_identity(directory, request, config):
    auth = request["arguments"]["auth"]
    body = auth["body"]
    subject = request["capability"]["subject"]
    VerifyKey(bytes.fromhex(subject)).verify(canonical(body), bytes.fromhex(auth["signature"]))
    require(body["host"] == config["name"] == request["server_id"], "Wrong request audience")
    require(body["request_id"] == request["request_id"], "Request ID changed")
    require(body["tool"] == request["tool_name"], "Requested operation changed")
    require(body["capability_id"] == request["capability"]["id"], "Capability binding changed")
    require(body["data"] == request["arguments"]["data"], "Signed business input changed")
    require(abs(time.time() - body["issued_at"]) <= 60, "Request signature is stale")
    require(request["agent_id"] == subject, "Caller is not the capability holder")
    trusted = read(directory / "trust.json")
    certificate = x509.load_pem_x509_certificate(auth["certificate"].encode())
    ca = x509.load_pem_x509_certificate(trusted["workload_ca"].encode())
    ca.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes)
    require(certificate.issuer == ca.subject, "Unknown workload issuer")
    now = dt.datetime.now(dt.UTC)
    require(
        certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc,
        "Expired workload certificate",
    )
    require(
        certificate.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
        == subject,
        "Workload certificate belongs to another key",
    )
    uris = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier)
    require(
        uris == [trusted["workloads"].get(subject)], "SPIFFE workload identity is not admitted here"
    )
    appraisal = verify_signed(read(directory / "runtime.json"), trusted["runtime_issuer"])
    require(
        appraisal["host"] == config["name"] and appraisal["status"] == "ready",
        "Workload is quarantined",
    )
    require(appraisal["expires_at"] >= time.time(), "Runtime appraisal expired")
    require(
        appraisal["code_hash"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "Running work-order code differs from its appraisal",
    )
    return trusted


def result_evidence(result, host, tool, trusted, order_id=None):
    receipt = verify_result(result, trusted["kernels"][host])
    require(
        receipt["tool_server"] == host and receipt["tool_name"] == tool,
        "Evidence is from the wrong responsibility",
    )
    require(
        receipt["decision"]["verdict"] == "allow" and result["output"] is not None,
        "Evidence is not a completed permitted operation",
    )
    if order_id is not None:
        require(result["output"]["order_id"] == order_id, "Evidence belongs to another work order")
    return result["output"]


def fetch_record(directory, reference):
    host = reference["host"]
    peers = read(directory / "peers.json")
    require(host in peers, "Audit names an unconfigured peer")
    peer = peers[host]
    match = re.fullmatch(r"http://127\.0\.0\.1:(\d+)", peer["endpoint"])
    require(match is not None, "This local application only contacts its configured loopback peers")
    receipt_id = reference["receipt_id"]
    require(re.fullmatch(r"[0-9a-f]{64}", receipt_id) is not None, "Invalid receipt content ID")
    connection = http.client.HTTPConnection("127.0.0.1", int(match[1]), timeout=5)
    try:
        connection.request(
            "GET", "/records/" + receipt_id, headers={"Authorization": "Bearer " + peer["token"]}
        )
        response = connection.getresponse()
        require(response.status == 200, "Peer could not supply the retained operation")
        body = response.read(2097153)
        require(len(body) <= 2097152, "Peer record exceeds the allowed size")
        operation = json.loads(body)
        require(
            digest(operation) == reference["record_hash"],
            "Peer record differs from its pinned content hash",
        )
        require(
            operation["result"]["receipt"]["id"] == receipt_id
            and operation["result"]["receipt"]["tool_server"] == host,
            "Peer substituted a different receipt or responsibility",
        )
        return operation
    finally:
        connection.close()


def review(data):
    # Validate concrete escrow obligations supplied as data. Never execute prose,
    # caller code, filesystem paths, or commands from a provider's work packet.
    spec = data["specification"]
    required = {
        "chain_id",
        "token_decimals",
        "amount",
        "deadline_seconds",
        "beneficiary",
        "required_leaf_fields",
    }
    require(set(spec) == required, "Unknown or missing settlement specification field")
    require(
        type(spec["chain_id"]) is int and spec["chain_id"] == 31337,
        "Only the local Chio escrow rail is installed",
    )
    require(
        spec["token_decimals"] == 6
        and type(spec["amount"]) is int
        and 0 < spec["amount"] <= 300000,
        "Invalid token amount or denomination",
    )
    require(
        type(spec["deadline_seconds"]) is int and 60 <= spec["deadline_seconds"] <= 3600,
        "Unsafe escrow deadline",
    )
    require(
        isinstance(spec["beneficiary"], str)
        and re.fullmatch(r"0x[0-9a-fA-F]{40}", spec["beneficiary"]) is not None,
        "Invalid beneficiary",
    )
    expected = [
        "chainId",
        "escrow",
        "escrowId",
        "token",
        "beneficiary",
        "operatorKeyHash",
        "receiptHash",
        "amount",
        "partial",
    ]
    fields = spec["required_leaf_fields"]
    require(
        isinstance(fields, list)
        and len(fields) <= 32
        and all(isinstance(field, str) for field in fields)
        and len(set(fields)) == len(fields),
        "Proof fields must be distinct names",
    )
    missing = sorted(set(expected) - set(spec["required_leaf_fields"]))
    extra = sorted(set(spec["required_leaf_fields"]) - set(expected))
    return {
        "order_id": data["order_id"],
        "specification_hash": digest(spec),
        "complete": not missing and not extra,
        "missing_leaf_fields": missing,
        "unknown_leaf_fields": extra,
        "checked_fields": expected,
        "amount": spec["amount"],
    }


def business_policy(directory, db, tool, request, trusted):
    config = read(directory / "config.json")
    host = config["name"]
    data = request["arguments"]["data"]
    require(isinstance(data, dict), "Business input must be an object")
    order_id = data.get("order_id", "")
    require(
        isinstance(order_id, str)
        and 1 <= len(order_id) <= 80
        and all(c.isascii() and (c.isalnum() or c == "-") for c in order_id),
        "A bounded work order ID is required",
    )
    if host in ("proofworks", "cipherworks") and tool == "review":
        require(
            set(data) <= {"order_id", "specification", "specialist"},
            "Unrecognized review instruction",
        )
        output = review(data)
        if host == "proofworks" and "specialist" in data:
            specialist = result_evidence(
                data["specialist"], "cipherworks", "review", trusted, order_id
            )
            require(
                specialist["specification_hash"] == output["specification_hash"],
                "Subcontractor reviewed different input",
            )
        return {"output": output}
    if host == "meridian" and tool == "admit":
        profile = verify_signed(data["provider"], trusted["membership_issuer"])
        require(profile["provider_id"] in trusted["members"], "Provider is not a federation member")
        require(profile["expires_at"] > time.time(), "Provider membership expired")
        require(
            profile["price"] <= data["budget"] <= 300000, "Provider quote exceeds the order budget"
        )
        receipts = data["history"]
        require(1 <= len(receipts) <= 20, "Provider needs actual completed work before admission")
        outcomes = []
        for item in receipts:
            output = result_evidence(item, "proofworks", "review", trusted)
            require(profile["provider_id"] == "proofworks", "History belongs to another provider")
            outcomes.append(output["complete"])
        # Every sample is an actual signed work result. No backdating or synthetic
        # receipts are inserted to manufacture a reputation score.
        require(
            len({item["receipt"]["id"] for item in receipts}) == len(receipts),
            "Repeated history receipt",
        )
        score = sum(outcomes) / len(outcomes)
        require(score >= 0.8, "Completed-work quality is below the admission threshold")
        require(
            db.execute("SELECT 1 FROM native_admissions WHERE id=?", (order_id,)).fetchone()
            is None,
            "This order already consumed its native presentation",
        )
        native = verify_presentation(directory, data)
        return {
            "output": {
                "native_passport": native,
                "order_id": order_id,
                "provider_id": profile["provider_id"],
                "price": profile["price"],
                "admitted": True,
                "sample_count": len(outcomes),
                "success_count": sum(outcomes),
                "quality_ratio": score,
                "history_receipts": [item["receipt"]["id"] for item in receipts],
                "profile_hash": digest(data["provider"]),
            }
        }
    if host == "atlas" and tool == "quote":
        admission = result_evidence(data["admission"], "meridian", "admit", trusted, order_id)
        amount = admission["price"]
        invoice = {
            "order_id": order_id,
            "provider_id": admission["provider_id"],
            "amount": amount,
            "currency": "wUSD",
            "rail": "chio-local-escrow",
            "admission_receipt": data["admission"]["receipt"]["id"],
        }
        return {
            "output": {
                **invoice,
                "invoice_hash": digest(invoice),
                "payment_required": True,
                "http_semantics": "application payment challenge",
                "scheme": "chio-escrow-receipt",
                "expires_at": int(time.time()) + 300,
            }
        }
    if host == "atlas" and tool == "reserve":
        quote = result_evidence(data["quote"], "atlas", "quote", trusted, order_id)
        require(quote["expires_at"] > time.time(), "Quote expired")
        require(data["invoice_hash"] == quote["invoice_hash"], "Invoice was changed after quote")
        require(data["amount"] == quote["amount"], "Invoice amount was changed after quote")
        require(data["rail"] == quote["rail"] == "chio-local-escrow", "Uninstalled settlement rail")
        approval = verify_signed(data["approval"], trusted["approval_issuer"])
        expected = {
            "order_id": order_id,
            "invoice_hash": quote["invoice_hash"],
            "amount": quote["amount"],
            "rail": quote["rail"],
            "approved": True,
        }
        require(
            all(approval.get(key) == value for key, value in expected.items()),
            "Approval does not bind this exact order, invoice and amount",
        )
        require(approval["expires_at"] > time.time(), "Independent approval expired")
        require(
            db.execute("SELECT 1 FROM orders WHERE id=?", (order_id,)).fetchone() is None,
            "Order already reserved; inspect status",
        )
        exposure = db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM orders WHERE state NOT IN ('refunded','released')"
        ).fetchone()[0]
        require(
            exposure + quote["amount"] <= trusted["treasury_limit"],
            "Treasury exposure would exceed its durable limit",
        )
        return {"quote": quote}
    if host == "atlas" and tool == "settle":
        order = db.execute(
            "SELECT provider,amount,invoice,state FROM orders WHERE id=?", (order_id,)
        ).fetchone()
        require(order is not None, "Work order has no reserved escrow")
        require(order[3] == "funded", "Work order is not awaiting settlement")
        provider = result_evidence(data["review"], "proofworks", "review", trusted, order_id)
        specialist = result_evidence(data["specialist"], "cipherworks", "review", trusted, order_id)
        specification = data["review"]["receipt"]["action"]["parameters"]["data"]["specification"]
        chain_config = read(directory / "chain.json")
        require(
            specification["amount"] == order[1]
            and specification["beneficiary"] == chain_config["beneficiary"]
            and specification["chain_id"] == chain_config["chain_id"],
            "Reviewed escrow terms differ from the reserved order",
        )
        require(
            provider["specification_hash"] == specialist["specification_hash"],
            "Review and subcontractor disagree on input",
        )
        require(
            data["review"]["receipt"]["action"]["parameters"]["data"]["specialist"]["receipt"]["id"]
            == data["specialist"]["receipt"]["id"],
            "Provider receipt does not bind this subcontract",
        )
        amount = data["amount"]
        require(
            type(amount) is int and 0 < amount <= order[1], "Settlement exceeds reserved amount"
        )
        if not provider["complete"] or not specialist["complete"] or amount < order[1]:
            approval = verify_signed(data["dispute_approval"], trusted["approval_issuer"])
            require(
                approval["order_id"] == order_id
                and approval["amount"] == amount
                and approval["review_receipt"] == data["review"]["receipt"]["id"]
                and approval["expires_at"] > time.time(),
                "Partial acceptance needs a separate exact review approval",
            )
        require(data["rail"] == "chio-local-escrow", "Uninstalled settlement rail")
        return {"receipt_id": data["review"]["receipt"]["id"], "amount": amount}
    if host == "atlas" and tool == "refund":
        order = db.execute(
            "SELECT amount,state,result FROM orders WHERE id=?", (order_id,)
        ).fetchone()
        require(
            order is not None and order[1] == "partial", "Order has no accepted partial settlement"
        )
        settled = json.loads(order[2])
        remaining = order[0] - settled["release"]["amount"]
        approval = verify_signed(data["approval"], trusted["approval_issuer"])
        require(
            approval["order_id"] == order_id
            and approval["amount"] == remaining
            and approval["escrow_id"] == settled["escrow_id"]
            and approval["action"] == "refund"
            and approval["expires_at"] > time.time(),
            "Refund approval does not match this escrow and remaining balance",
        )
        require(
            data.get("advance_local_clock") is True,
            "The local-chain refund demonstration requires explicit clock advancement",
        )
        return {}
    if host == "atlas" and tool == "recover":
        require(set(data) == {"order_id"}, "Recovery only resumes the retained exact intent")
        state = db.execute("SELECT state FROM orders WHERE id=?", (order_id,)).fetchone()
        require(
            state is not None and state[0] in ("funding", "releasing", "refunding"),
            "Order has no unfinished publication to recover",
        )
        return {}
    if host == "atlas" and tool == "status":
        require(
            db.execute("SELECT 1 FROM orders WHERE id=?", (order_id,)).fetchone() is not None,
            "Unknown order",
        )
        return {}
    if host == "meridian" and tool == "audit":
        references = data["records"]
        require(1 <= len(references) <= 100, "Audit requires a bounded receipt-reference list")
        operations = [fetch_record(directory, reference) for reference in references]
        require(1 <= len(operations) <= 100, "Audit requires a bounded real operation list")
        for operation in operations:
            receipt = operation["result"]["receipt"]
            verify_result(
                operation["result"],
                trusted["kernels"][receipt["tool_server"]],
                operation["request"],
            )
        require(
            data["trusted_kernels"] == trusted["kernels"],
            "Audit changed the selected serving identities",
        )
        capabilities = data["capabilities"]
        require(
            set(capabilities) == {"root", "provider", "specialist", "buyer", "auditor"},
            "Audit capability catalog changed",
        )
        require(
            capabilities["root"] == config["root"]
            and capabilities["provider"] == config["parents"][1],
            "Audit ancestor snapshots differ from operator configuration",
        )
        for role in ("specialist", "buyer"):
            require(
                any(
                    operation["request"]["capability"] == capabilities[role]
                    and operation["result"]["receipt"]["decision"]["verdict"] == "allow"
                    for operation in operations
                ),
                "Capability has no matching admitted work: " + role,
            )
        require(
            capabilities["auditor"] == request["capability"], "Audit capability was substituted"
        )
        ids = [item["result"]["receipt"]["id"] for item in operations]
        require(len(set(ids)) == len(ids), "Audit receipt is duplicated")
        return {
            "output": {
                "order_id": order_id,
                "verified_receipts": ids,
                "allowed": sum(
                    item["result"]["receipt"]["decision"]["verdict"] == "allow"
                    for item in operations
                ),
                "incomplete": sum(
                    item["result"]["receipt"]["decision"]["verdict"] == "incomplete"
                    for item in operations
                ),
                "refused": sum(
                    item["result"]["receipt"]["decision"]["verdict"] == "deny"
                    for item in operations
                ),
            }
        }
    raise Refused("No installed work-order responsibility matches this request")


def chain(directory, payload):
    result = subprocess.run(
        ["node", str(HERE / "chain.mjs"), "execute", str(directory)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=45,
    )
    if result.returncode:
        raise RuntimeError(
            "Escrow operation failed; inspect retained intent: " + result.stderr[-1000:]
        )
    return json.loads(result.stdout)


def check(directory, tool, value):
    db = connect(directory)
    request = value["request"]
    try:
        db.execute("BEGIN IMMEDIATE")
        trusted = check_identity(directory, request, read(directory / "config.json"))
        require(
            db.execute("SELECT 1 FROM requests WHERE id=?", (request["request_id"],)).fetchone()
            is None,
            "Request was already admitted; use a new request to inspect status",
        )
        business_policy(directory, db, tool, request, trusted)
        db.execute(
            "INSERT INTO requests VALUES(?,?,?,?)",
            (request["request_id"], digest(request["arguments"]), json.dumps(request), "prepared"),
        )
        db.execute(
            "INSERT INTO observations(request_id,tool,verdict,reason,time) VALUES(?,?,?,?,?)",
            (
                request["request_id"],
                tool,
                "allow",
                "Authenticated holder, workload and business policy",
                int(time.time()),
            ),
        )
        db.commit()
        return {"allowed": True, "policy": "work-order.v1", "request_id": request["request_id"]}
    except Exception as error:
        db.rollback()
        db.execute(
            "INSERT INTO observations(request_id,tool,verdict,reason,time) VALUES(?,?,?,?,?)",
            (request["request_id"], tool, "deny", str(error), int(time.time())),
        )
        return {"allowed": False, "reason": str(error)[:1024], "request_id": request["request_id"]}
    finally:
        db.close()


def execute(directory, tool, arguments):
    db = connect(directory)
    request_id = arguments["auth"]["body"]["request_id"]
    try:
        db.execute("BEGIN IMMEDIATE")
        record = db.execute(
            "SELECT binding,request,state FROM requests WHERE id=?", (request_id,)
        ).fetchone()
        require(
            record is not None and record[2] == "prepared" and record[0] == digest(arguments),
            "No exact unconsumed kernel admission",
        )
        request = json.loads(record[1])
        trusted = check_identity(directory, request, read(directory / "config.json"))
        decision = business_policy(directory, db, tool, request, trusted)
        data = arguments["data"]
        order_id = data["order_id"]
        db.execute("UPDATE requests SET state='consumed' WHERE id=?", (request_id,))
        host = read(directory / "config.json")["name"]
        if host == "meridian" and tool == "admit":
            decision["output"]["native_passport"] = verify_presentation(
                directory, data, consume=True
            )
            db.execute(
                "INSERT INTO native_admissions VALUES(?,?)",
                (order_id, digest(data["presentation"])),
            )
        if tool == "review":
            output = decision["output"]
            db.execute(
                "INSERT INTO reviews VALUES(?,?,?)",
                (request_id, output["specification_hash"], json.dumps(output)),
            )
            db.commit()
            return output
        if host == "atlas" and tool == "reserve":
            quote = decision["quote"]
            db.execute(
                "INSERT INTO orders VALUES(?,?,?,?,?,NULL)",
                (order_id, quote["provider_id"], quote["amount"], quote["invoice_hash"], "funding"),
            )
            db.commit()
            result = chain(
                directory,
                {
                    "action": "fund",
                    "order_id": order_id,
                    "amount": quote["amount"],
                    "capability_id": request["capability"]["id"],
                },
            )
            db.execute(
                "UPDATE orders SET state='funded',result=? WHERE id=?",
                (json.dumps(result), order_id),
            )
            return {
                "order_id": order_id,
                "escrow": result,
                "payment_proof": {
                    "scheme": "chio-escrow-receipt",
                    "invoice_hash": quote["invoice_hash"],
                    "funding_transaction": result["transactions"][-1]["transaction_hash"],
                },
            }
        if host == "atlas" and tool == "settle":
            db.execute("UPDATE orders SET state='releasing' WHERE id=?", (order_id,))
            db.commit()
            result = chain(directory, {"action": "release", "order_id": order_id, **decision})
            db.execute(
                "UPDATE orders SET state=?,result=? WHERE id=?",
                (result["state"], json.dumps(result), order_id),
            )
            return {"order_id": order_id, "escrow": result}
        if host == "atlas" and tool == "refund":
            db.execute("UPDATE orders SET state='refunding' WHERE id=?", (order_id,))
            db.commit()
            result = chain(directory, {"action": "refund", "order_id": order_id})
            db.execute(
                "UPDATE orders SET state='refunded',result=? WHERE id=?",
                (json.dumps(result), order_id),
            )
            return {"order_id": order_id, "escrow": result}
        if host == "atlas" and tool == "recover":
            db.commit()
            result = chain(directory, {"action": "recover", "order_id": order_id})
            db.execute(
                "UPDATE orders SET state=?,result=? WHERE id=?",
                (result["state"], json.dumps(result), order_id),
            )
            return {"order_id": order_id, "escrow": result}
        if host == "atlas" and tool == "status":
            db.commit()
            return {
                "order_id": order_id,
                "escrow": chain(directory, {"action": "status", "order_id": order_id}),
            }
        db.commit()
        return decision["output"]
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    phase, location, tool = sys.argv[1:]
    directory = Path(location)
    value = json.loads(sys.stdin.buffer.read(2097153))
    try:
        result = (
            check(directory, tool, value) if phase == "check" else execute(directory, tool, value)
        )
        print(json.dumps(result))
    except Exception as error:
        print(str(error)[:2048], file=sys.stderr)
        raise SystemExit(1)
