#!/usr/bin/env python3
"""Deterministic guardrails for the formal Apalache slice."""

from pathlib import Path
import re
import sys
import tomllib


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
        "DescendsFrom must not be a direct-parent-only predicate",
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


def check_post_admission_drop_guard() -> None:
    text = read("formal/apalache/PostAdmissionDropGuard.tla")
    config = read("formal/apalache/MCPostAdmissionDropGuard.cfg")
    next_body = body(text, "Next")
    admit = body(text, "Admit")
    admission_profiles = body(text, "AdmissionProfiles")
    pre_drop = body(text, "DropPreDispatch")
    post_drop = body(text, "DropPostDispatch")
    resolve_post_drop = body(text, "ResolvePostDispatch")
    retained = body(text, "RetainedIffAborted")
    safety = body(text, "SafetyInv")

    require(
        "DropPreDispatch(i)" in next_body and "DropPostDispatch(i)" in next_body,
        "Next must expose both pre-dispatch and post-dispatch drop actions",
    )
    require(
        "resources \\in AdmissionProfilesFor(i)" in admit
        and '    {},' in admission_profiles
        and "IF i = 1" in body(text, "AdmissionProfilesFor")
        and '{{"slot", "lease", "child"}}' in body(text, "AdmissionProfilesFor")
        and '{"hold", "slot"}' not in admission_profiles,
        "admission must keep the valid budget, lease, and child profiles",
    )
    required_profiles = (
        '{"lease"}',
        '{"child"}',
        '{"lease", "child"}',
        '{"hold"}',
        '{"slot"}',
        '{"hold", "lease"}',
        '{"slot", "lease"}',
        '{"hold", "child"}',
        '{"slot", "child"}',
        '{"hold", "lease", "child"}',
        '{"slot", "lease", "child"}',
    )
    require(
        all(profile in admission_profiles for profile in required_profiles)
        and "CleanupFailureProfiles == AdmissionProfiles" in text,
        "cleanup failures must range over every valid admitted-resource subset",
    )
    require(
        "i = 1" in pre_drop
        and 'phase[i] = "admitted"' in pre_drop
        and 'phase[i] \\in {"dispatch_started", "streaming"}' in post_drop,
        "drop actions must cover every armed non-terminal phase",
    )
    for local_action in ("CompleteOk", "DenyPostInvocation", "IncompleteStream"):
        require(
            "i = 1" in body(text, local_action),
            f"{local_action} must stay on the local-branch invocation",
        )
    require(
        "failed \\in CleanupFailureSets(i)" in pre_drop
        and "CleanupFailureProfiles" in body(text, "CleanupFailureSets")
        and "failed \\subseteq admitted_resources[i]" in pre_drop
        and 'parent_kind_logged EXCEPT ![i] = "fault"' in pre_drop
        and "parent_receipts EXCEPT ![i] = @ + 1" in pre_drop,
        "pre-dispatch cleanup must model independent failures and a fault receipt",
    )
    require(
        "flushed_count" in post_drop
        and "child_logged'" in post_drop
        and "parent_receipts'" in post_drop
        and "children_before_parent'" in post_drop
        and post_drop.index("child_logged'") < post_drop.index("parent_receipts'"),
        "post-dispatch drop must account for child receipts before the parent cancellation",
    )
    require(
        "monetary_unwind_failed" in post_drop
        and "MonetaryUnwindOutcomes(i)" in post_drop
        and "monetary_unwind_failed" in resolve_post_drop
        and 'THEN "retained"' in resolve_post_drop,
        "post-dispatch monetary unwind failure must leave the hold retained",
    )
    require(
        "<=>" in retained
        and 'terminal_kind[i] \\in {"deny", "incomplete", "cancel"}' in retained,
        "RetainedIffAborted must remain a biconditional over abort terminals",
    )
    invariant_names = (
        "ReservationConservation",
        "TerminalReceiptExactlyOne",
        "ChildReceiptsFlushed",
        "RetainedIffAborted",
    )
    require(
        all(name in safety for name in invariant_names),
        "SafetyInv must retain every drop-guard invariant",
    )
    require(
        "Invocations = {1, 2}" in config
        and "ChildMax = 1" in config
        and 'Mutation = "none"' in config,
        "positive drop-guard config must keep the documented bounds and disable mutations",
    )
    for anchor in (
        "kernel_drop_guard.rs:86-109",
        "kernel_drop_guard.rs:180-308,385-392",
        "kernel_drop_guard.rs:379-438",
        "responses/finalization.rs:36-51",
        "responses/finalization.rs:70-85",
    ):
        require(anchor in text, f"drop-guard ground-truth header is missing {anchor}")


def check_negative_registry() -> None:
    registry_path = REPO / "formal/apalache/_negative_tests/REGISTRY.toml"
    with registry_path.open("rb") as handle:
        registry = tomllib.load(handle)

    require(
        registry.get("schema") == "chio.apalache-negative.v1",
        "negative registry schema must remain versioned",
    )
    entries = registry.get("negative", [])
    expected = {
        "ReceiptBeforeAllowBroken",
        "RevocationCutCompletenessBroken",
        "DropGuardDiscardChildBufferBroken",
        "DropGuardSkipChildBudgetReleaseBroken",
        "DropGuardSkipInvocationReversalBroken",
        "DropGuardNoFaultReceiptBroken",
        "DropGuardReleaseOnIncompleteStreamBroken",
        "DropGuardNoRetainOnPostInvocationDenyBroken",
        "DropGuardReleaseOnPostDispatchAbortBroken",
    }
    actual = {Path(entry["spec"]).stem for entry in entries}
    require(actual == expected, "negative registry must contain the exact nine calibrated models")

    mapping = read("formal/MAPPING.md")
    for entry in entries:
        require(
            f"`{entry['falsifies']}`" in mapping,
            f"negative registry property is not mapped: {entry['falsifies']}",
        )

    mutation_by_stem = {
        "DropGuardDiscardChildBufferBroken": "discard-child-buffer",
        "DropGuardSkipChildBudgetReleaseBroken": "skip-child-release",
        "DropGuardSkipInvocationReversalBroken": "skip-slot-release",
        "DropGuardNoFaultReceiptBroken": "omit-fault-receipt",
        "DropGuardReleaseOnIncompleteStreamBroken": "release-incomplete-lease",
        "DropGuardNoRetainOnPostInvocationDenyBroken": "skip-deny-retention",
        "DropGuardReleaseOnPostDispatchAbortBroken": "release-post-dispatch-lease",
    }
    for stem, mutation in mutation_by_stem.items():
        module = read(f"formal/apalache/_negative_tests/{stem}.tla")
        config = read(f"formal/apalache/_negative_tests/MC{stem}.cfg")
        require(
            "EXTENDS PostAdmissionDropGuard" in module,
            f"{stem} must reuse the production model semantics",
        )
        require(
            f'Mutation = "{mutation}"' in config,
            f"{stem} config must select only its calibrated mutation",
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

    required_paths = (
        "formal/MAPPING.md",
        "formal/proof-manifest.toml",
        "crates/kernel/chio-kernel-core/src/evaluate.rs",
        "crates/kernel/chio-kernel-core/src/revocation_view.rs",
        "crates/kernel/chio-kernel/src/budget_store.rs",
        "crates/kernel/chio-kernel/src/receipt_store.rs",
        "crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs",
        "crates/kernel/chio-kernel/src/kernel/dispatch.rs",
        "crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs",
        "crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs",
        "crates/kernel/chio-kernel/src/kernel/responses/finalization.rs",
        "crates/kernel/chio-kernel/src/kernel/validation.rs",
        "crates/kernel/chio-kernel/src/kernel/tests/chio_runtime.rs",
        "scripts/check-apalache-formal-slice.py",
        ".github/workflows/apalache-temporal.yml",
    )
    for path in required_paths:
        require(
            f'- "{path}"' in text,
            f"apalache-safety paths must include {path}",
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
    require(
        "formal/apalache/MCPostAdmissionDropGuard.cfg|formal/apalache/PostAdmissionDropGuard.tla|8|1800"
        in text,
        "apalache-safety must run the drop-guard model at length 8",
    )
    require(
        'while IFS="|" read -r cfg spec length timeout_secs' in text
        and 'timeout "${timeout_secs}" apalache-mc check' in text,
        "each positive Apalache row must carry an enforced length and timeout",
    )
    require(
        "apalache-negative:" in text
        and "./scripts/check-apalache-negative.sh" in text
        and "./scripts/tests/check-apalache-negative.test.sh" in text,
        "apalache-safety must keep the negative suite as a separate checked job",
    )
    require(
        "fetch-depth: 0" in text,
        "apalache-negative must fetch commit objects named by its registry",
    )
    require(
        "CHIO_APALACHE_NEGATIVE_OUTPUT_DIR: target/apalache-negative" in text,
        "apalache-negative artifacts must stay below the checked output root",
    )


def check_negative_gate_boundary() -> None:
    with (REPO / "formal/proof-manifest.toml").open("rb") as handle:
        manifest = tomllib.load(handle)

    require(
        "./scripts/check-apalache-negative.sh" not in manifest.get("gate_commands", []),
        "the pinned Apalache negative lane must not enter unprovisioned aggregate gates",
    )


def main() -> int:
    checks = (
        check_receipt_before_allow,
        check_revocation_cut,
        check_post_admission_drop_guard,
        check_negative_registry,
        check_temporal_workflow,
        check_safety_workflow_paths,
        check_negative_gate_boundary,
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
