#!/usr/bin/env python3
import argparse, json, sys


def find_financial_metadata(node):
    """Locate the FinancialReceiptMetadata object anywhere in the receipt tree.

    It is the object carrying a settlement_status field. Confirm the concrete
    wrapper key against a real dump in Step 4; this walk avoids hard-coding it.
    """
    if isinstance(node, dict):
        if "settlement_status" in node and ("payment_reference" in node or "currency" in node):
            return node
        for value in node.values():
            found = find_financial_metadata(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = find_financial_metadata(value)
            if found is not None:
                return found
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--deny-rc", type=int, required=True)
    ap.add_argument("--deny-out", required=True)
    args = ap.parse_args()

    checks = 0

    with open(args.receipt) as fh:
        receipt = json.load(fh)
    # FinancialReceiptMetadata has no serde rename_all, so its JSON keys are
    # snake_case (payment_reference, settlement_status, cost_breakdown) and
    # SettlementStatus serializes snake_case (settled/pending). Confirm the
    # parent receipt key that holds the financial metadata against a real dump
    # in Step 4 and adjust the lookup below if the wrapper key differs.
    fin = find_financial_metadata(receipt)
    assert fin is not None, "no FinancialReceiptMetadata found in receipt bundle"

    pay_ref = fin.get("payment_reference") or ""
    assert pay_ref.startswith("sim-"), f"expected sim payment reference, got {pay_ref!r}"
    checks += 1

    status = fin.get("settlement_status")
    assert status == "settled", (
        "positive governed-x402-sim lane must prove settlement: SimPaymentAdapter "
        f"captures after execution, so settlement_status must be settled, got {status!r}"
    )
    checks += 1

    # Governed binding round-trips into the payment breakdown (exact nesting
    # confirmed against a real dump in Step 4).
    breakdown = json.dumps(fin.get("cost_breakdown") or {})
    assert "intent_hash" in breakdown or "intentHash" in breakdown, "governed intent hash missing"
    checks += 1

    # Negative: adapter-absent MustPrepay must be denied (nonzero rc, no exec receipt).
    assert args.deny_rc != 0, "adapter-absent MustPrepay must be denied"
    checks += 1

    # No false green: we must have run assertions.
    assert checks > 0, "no assertions executed"
    print(f"assert_receipt: OK ({checks} assertions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
