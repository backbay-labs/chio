#!/usr/bin/env python3
"""Deterministic guardrails for the formal Apalache slice."""

from pathlib import Path
import re
import sys


REPO = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def body(text: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}\b.*?(?=^[A-Za-z][A-Za-z0-9_]*\b.*?==|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"missing definition: {name}")
    return match.group(0)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_receipt_before_allow() -> None:
    text = read("formal/apalache/ReceiptBeforeAllow.tla")
    persist = body(text, "PersistAllowReceipt")
    publish = body(text, "PublishAllow")
    invariant = body(text, "ReceiptBeforeAllow")
    next_body = body(text, "Next")

    require(
        "allow_recorded" not in text,
        "ReceiptBeforeAllow must derive receipt evidence from receipt_log, not allow_recorded",
    )
    require(
        "Append(@" in persist and 'verdict |-> "allow"' in persist,
        "PersistAllowReceipt must append an allow receipt",
    )
    require(
        "allowed' =" not in persist,
        "PersistAllowReceipt must not publish the allow decision in the receipt write step",
    )
    require(
        "receipt_log' =" not in publish and "allowed' =" in publish,
        "PublishAllow must publish without writing the receipt log",
    )
    require(
        "HasAllowReceipt(a, c)" in publish,
        "PublishAllow must require a prior allow receipt",
    )
    require(
        "allow_recorded" not in invariant and "HasAllowReceipt" in invariant,
        "ReceiptBeforeAllow invariant must cite receipt_log evidence",
    )
    require(
        "PersistAllowReceipt(a, c)" in next_body and "PublishAllow(a, c)" in next_body,
        "Next must expose receipt persistence and allow publication as separate actions",
    )


def check_revocation_cut() -> None:
    text = read("formal/apalache/RevocationCutCompleteness.tla")
    descends = body(text, "DescendsFrom")
    delegate = body(text, "Delegate")
    revoke = body(text, "Revoke")
    invariant = body(text, "RevocationCutCompleteness")

    require(
        "descendants" in text and "DescendantsOK" in text,
        "RevocationCutCompleteness must carry a bounded transitive descendant closure",
    )
    require(
        "child \\in descendants[root]" in descends,
        "DescendsFrom must use the transitive descendant closure",
    )
    require(
        "parent[child] = root" not in descends,
        "DescendsFrom must not be the old direct-parent-only predicate",
    )
    require(
        "root \\notin revoked" not in delegate,
        "Delegate must not check only direct root revocation",
    )
    require(
        "NoRevokedAncestor(root)" in delegate,
        "Delegate must reject delegation below any revoked ancestor",
    )
    require(
        "descendants' =" in delegate and "root \\in descendants[ancestor]" in delegate,
        "Delegate must update every ancestor's descendant closure transitively",
    )
    require(
        "DescendsFrom(c, root)" in revoke and "DescendsFrom(c, r)" in invariant,
        "Revoke and the invariant must both use the transitive descendant predicate",
    )


def check_temporal_workflow() -> None:
    text = read(".github/workflows/apalache-temporal.yml")
    cfg = read("formal/tla/MCRevocationPropagationTemporal.cfg")

    require(
        "continue-on-error" not in text,
        "apalache-temporal must be fail-closed, not continue-on-error advisory",
    )
    require(
        "advisory" not in text.lower(),
        "apalache-temporal must not describe the liveness lane as advisory",
    )
    require(
        "RevocationEventuallySeen" in text and "--temporal=RevocationEventuallySeen" in text,
        "apalache-temporal must run the named RevocationEventuallySeen liveness property",
    )
    require(
        "schedule:" in text and "workflow_dispatch:" in text,
        "apalache-temporal must remain a scheduled/manual nightly liveness lane",
    )
    require(
        re.search(r"(?m)^INVARIANT\s*\n\s*SafetyInv\b", cfg) is not None,
        "MCRevocationPropagationTemporal.cfg must check SafetyInv at the nightly length bound",
    )


def check_safety_workflow_paths() -> None:
    text = read(".github/workflows/apalache-safety.yml")

    require(
        '- "scripts/check-apalache-formal-slice.py"' in text,
        "apalache-safety paths must include scripts/check-apalache-formal-slice.py",
    )
    require(
        '- ".github/workflows/apalache-temporal.yml"' in text,
        "apalache-safety paths must keep .github/workflows/apalache-temporal.yml",
    )
    require(
        "formal/tla/MCRevocationPropagation.cfg|formal/tla/RevocationPropagation.tla"
        in text,
        "apalache-safety must keep RevocationPropagation safety coverage",
    )
    require(
        "formal/tla/MCDelegationDepthBound.cfg|formal/tla/DelegationDepthBound.tla"
        in text,
        "apalache-safety must keep DelegationDepthBound safety coverage",
    )


def main() -> int:
    checks = (
        check_receipt_before_allow,
        check_revocation_cut,
        check_temporal_workflow,
        check_safety_workflow_paths,
    )
    failures: list[str] = []
    for check in checks:
        try:
            check()
        except AssertionError as exc:
            failures.append(f"{check.__name__}: {exc}")
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("check-apalache-formal-slice: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
