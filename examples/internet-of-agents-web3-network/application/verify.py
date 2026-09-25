"""Verify an execution capture against an independently selected auditor key."""

import argparse
from pathlib import Path

from evidence import digest, read, verify_result


def verify(capture, auditor_key):
    audit = capture["audit"]
    verify_result(audit, auditor_key)
    if audit["receipt"]["tool_server"] != "meridian" or audit["receipt"]["tool_name"] != "audit":
        raise ValueError("Selected auditor did not sign a work-order audit")
    if audit["receipt"]["decision"]["verdict"] != "allow":
        raise ValueError("The auditor refused this capture")
    operations = capture["operations"]
    if not operations or operations[-1]["result"] != audit:
        raise ValueError("Final operation differs from the signed audit")
    verify_result(audit, auditor_key, operations[-1]["request"])
    audited_input = audit["receipt"]["action"]["parameters"]["data"]
    for field in ["trusted_kernels", "capabilities"]:
        if capture[field] != audited_input[field]:
            raise ValueError("Published " + field + " differs from the auditor's verified input")
    references = audited_input["records"]
    if len(references) != len(operations) - 1:
        raise ValueError("An operation was added or omitted after the audit")
    for operation, reference in zip(operations[:-1], references, strict=True):
        receipt = operation["result"]["receipt"]
        if digest(operation) != reference["record_hash"]:
            raise ValueError("Retained operation differs from the auditor's pinned record")
        if reference["receipt_id"] != receipt["id"] or reference["host"] != receipt["tool_server"]:
            raise ValueError("Audited receipt or serving host was substituted")
        # The selected auditor binds this exact record, including its signed
        # kernel identity. The capture cannot substitute its own trust list.
        verify_result(operation["result"], receipt["kernel_key"], operation["request"])
    receipts = [operation["result"]["receipt"]["id"] for operation in operations[:-1]]
    if audit["output"]["verified_receipts"] != receipts or len(set(receipts)) != len(receipts):
        raise ValueError("Auditor output does not match the complete operation sequence")
    by_id = {operation["result"]["receipt"]["id"]: operation["result"] for operation in operations}
    for field, state in [
        ("full_release_receipt", "released"),
        ("partial_release_receipt", "partial"),
        ("refund_receipt", "refunded"),
    ]:
        result = by_id[capture[field]]
        if (
            result["receipt"]["decision"]["verdict"] != "allow"
            or result["output"]["escrow"]["state"] != state
        ):
            raise ValueError("Settlement summary is not bound to its actual signed result")
    payment = by_id[capture["x402_receipt"]]
    if (
        payment["receipt"]["tool_name"] != "buy_report"
        or payment["receipt"]["decision"]["verdict"] != "allow"
    ):
        raise ValueError("x402 summary is not bound to a permitted purchase")
    result = payment["output"]["payment"]
    if (
        result["protocol"] != "x402"
        or result["scheme"] != "exact"
        or result["deliveries"] != 1
        or not result["settlement"]["success"]
    ):
        raise ValueError("x402 purchase did not settle and deliver once")
    if (
        digest(result["report"]) != result["report_hash"]
        or int(result["before"]["payer"]) - int(result["after"]["payer"]) != 10000
    ):
        raise ValueError("x402 report or payment does not match its signed evidence")
    status = [
        operation["result"]["output"]
        for operation in operations
        if operation["request"]["tool_name"] == "status"
        and operation["result"]["receipt"]["decision"]["verdict"] == "allow"
    ]
    if not status or capture["balances"] != status[-1]["escrow"]:
        raise ValueError("Published balances differ from the signed final observation")
    if capture["chain_source_hash"] != capture["balances"]["source_hash"]:
        raise ValueError("Contract source hash differs from the signed chain observation")
    full = by_id[capture["full_release_receipt"]]["output"]["order_id"]
    partial = by_id[capture["partial_release_receipt"]]["output"]["order_id"]
    refunded = by_id[capture["refund_receipt"]]["output"]["order_id"]
    if capture["orders"] != [full, partial] or full == partial or partial != refunded:
        raise ValueError("Order summary differs from the signed settlements")
    if (
        int(capture["balances"]["buyer_balance"])
        + int(capture["balances"]["beneficiary_balance"])
        + int(capture["balances"]["escrow_balance"])
        != 1_000_000
    ):
        raise ValueError("Local token balances do not reconcile")
    return {
        "verified_operations": len(operations),
        "auditor_receipt": audit["receipt"]["id"],
        "allowed": audit["output"]["allowed"],
        "refused": audit["output"]["refused"],
        "incomplete": audit["output"]["incomplete"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument(
        "--auditor-key", required=True, help="Selected independently of the capture being verified"
    )
    args = parser.parse_args()
    print(verify(read(args.capture), args.auditor_key))
