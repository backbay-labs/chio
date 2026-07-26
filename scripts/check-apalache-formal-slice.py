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


def workflow_job(source: str, name: str, next_name: str | None) -> str:
    start_marker = f"\n  {name}:\n"
    start = source.index(start_marker) + 1
    if next_name is None:
        return source[start:]
    end = source.index(f"\n  {next_name}:\n", start)
    return source[start:end]


def workflow_pull_request_paths(source: str) -> tuple[str, ...]:
    match = re.search(
        r'(?m)^    paths:\n((?:      - "[^"]+"\n)+)',
        source,
    )
    require(match is not None, "workflow pull_request.paths block was not found")
    return tuple(re.findall(r'(?m)^      - "([^"]+)"$', match.group(1)))


def workflow_path_covers(source_path: str, workflow_paths: tuple[str, ...]) -> bool:
    for pattern in workflow_paths:
        if pattern == source_path:
            return True
        if pattern.endswith("/**") and source_path.startswith(f"{pattern[:-3]}/"):
            return True
    return False


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
        "HasAllowReceipt(a, c, r)" in publish,
        "PublishAllow must require the matching call receipt",
    )
    require(
        "allow_recorded" not in invariant and "HasAllowReceipt" in invariant,
        "ReceiptBeforeAllow invariant must cite receipt_log evidence",
    )
    require(
        "PersistAllowReceipt(a, c, r)" in next_body
        and "PublishAllow(a, c, r)" in next_body,
        "Next must expose receipt persistence and allow publication as separate actions",
    )
    require(
        "CallDecision(r, c) \\notin allowed[a]" in publish,
        "PublishAllow must publish each call at most once",
    )
    require(
        "decision.call" in invariant and "decision.cap" in invariant,
        "ReceiptBeforeAllow must bind receipt evidence to the published call",
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
    active_child_shares = body(text, "ActiveChildShares")
    child_splits_bounded = body(text, "ChildSplitsBounded")
    pre_drop = body(text, "DropPreDispatch")
    post_drop = body(text, "DropPostDispatch")
    server_error = body(text, "ServerErrorPostDispatch")
    resolve_returned = body(text, "ResolveReturnedOutput")
    resolve_post_drop = body(text, "ResolvePostDispatch")
    parent_append_outcomes = body(text, "ParentAppendOutcomes")
    parent_persistence_outcomes = body(text, "ParentPersistenceOutcomes")
    server_error_kinds = body(text, "ServerErrorKinds")
    server_error_receipt_kind = body(text, "ServerErrorReceiptKind")
    terminal_receipt = body(text, "TerminalReceiptExactlyOne")
    retained = body(text, "RetainedIffAborted")
    safety = body(text, "SafetyInv")

    require(
        "DropPreDispatch(i)" in next_body
        and "ServerErrorPostDispatch(i)" in next_body
        and "DropPostDispatch(i)" in next_body,
        "Next must expose pre-dispatch, server-error, and drop actions",
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
        and 'phase[i] \\in {"dispatch_started", "streaming"}' in server_error
        and 'phase[i] \\in {"dispatch_started", "streaming"}' in post_drop,
        "terminal actions must cover every armed non-terminal phase",
    )
    require(
        'ParentAppendStates == {"not-attempted", "outcome-unknown", "committed"}'
        in text
        and 'THEN {"outcome-unknown", "committed"}' in parent_append_outcomes
        and 'ELSE {"committed"}' in parent_append_outcomes
        and 'append_outcome = "committed"' in parent_persistence_outcomes
        and "ELSE BOOLEAN" in parent_persistence_outcomes,
        "parent append must distinguish not-attempted, outcome-unknown, and committed",
    )
    require(
        'ledger[i]["child"] \\notin {"none", "released"}' in active_child_shares
        and "Cardinality" in active_child_shares
        and "ActiveChildShares <= ChildMax" in child_splits_bounded
        and "BudgetMax" not in child_splits_bounded,
        "child-share conservation must count active shared capacity against ChildMax",
    )
    require(
        'IF "child" \\in resources' in admit
        and "ActiveChildShares < ChildMax" in admit
        and 'Mutation = "skip-child-capacity-guard"' in admit,
        "child admission must enforce shared capacity with one calibrated mutation",
    )
    for local_action in (
        "CompleteOk",
        "DenyPostInvocation",
        "IncompleteStream",
        "ServerErrorPostDispatch",
    ):
        local_body = body(text, local_action)
        require(
            "i = 1" in local_body,
            f"{local_action} must stay on the local-branch invocation",
        )
        require(
            'parent_append_state[i] = "not-attempted"' in local_body
            and "append_outcome \\in ParentAppendOutcomes(i)" in local_body
            and "append_persisted \\in ParentPersistenceOutcomes(append_outcome)"
            in local_body
            and "parent_append_attempts'" in local_body
            and "parent_append_state'" in local_body
            and "parent_receipts'" in local_body
            and local_body.index("child_logged'") < local_body.index("parent_receipts'"),
            f"{local_action} must append once after flushing children and model ambiguity",
        )
    require(
        "failed \\in CleanupFailureSets(i)" in pre_drop
        and "CleanupFailureProfiles" in body(text, "CleanupFailureSets")
        and "failed \\subseteq admitted_resources[i]" in pre_drop
        and "parent_kind_logged'" in pre_drop
        and 'IF append_persisted THEN "fault" ELSE "none"' in pre_drop
        and 'parent_append_state[i] = "not-attempted"' in pre_drop
        and "parent_append_attempts'" in pre_drop
        and "parent_receipts'" in pre_drop,
        "pre-dispatch cleanup must model independent failures and one ambiguity-aware fault append",
    )
    require(
        "flushed_count" in post_drop
        and 'parent_append_state[i] = "not-attempted"' in post_drop
        and "append_outcome \\in ParentAppendOutcomes(i)" in post_drop
        and "append_persisted \\in ParentPersistenceOutcomes(append_outcome)"
        in post_drop
        and "child_logged'" in post_drop
        and "parent_append_attempts'" in post_drop
        and "parent_append_state'" in post_drop
        and "parent_receipts'" in post_drop
        and "children_before_parent'" in post_drop
        and post_drop.index("child_logged'") < post_drop.index("parent_receipts'"),
        "post-dispatch drop must flush children before one ambiguity-aware parent append",
    )
    require(
        'parent_append_state[i] = "not-attempted" =>' in terminal_receipt
        and 'parent_append_state[i] = "committed" =>' in terminal_receipt
        and 'parent_append_state[i] = "outcome-unknown" =>' in terminal_receipt
        and "parent_append_attempts[i] = 0" in terminal_receipt
        and "parent_append_attempts[i] = 1" in terminal_receipt
        and "parent_receipts[i] = 1" in terminal_receipt
        and "parent_receipts[i] \\in 0..1" in terminal_receipt,
        "TerminalReceiptExactlyOne must scope exactly-one to committed availability and bound ambiguity",
    )
    require(
        "monetary_unwind_failed" not in text
        and "MonetaryUnwindOutcomes" not in text
        and 'resource = "lease"' in resolve_returned
        and 'resource \\in {"lease", "hold"}' not in resolve_returned
        and 'ELSE "committed"' in resolve_returned
        and 'resource \\in {"lease", "hold"}' in resolve_post_drop
        and 'Mutation = "release-post-dispatch-state"' in resolve_post_drop
        and 'ELSE "retained"' in resolve_post_drop
        and 'ResolveReturnedOutput(@, "deny")' in body(text, "DenyPostInvocation")
        and 'ResolveReturnedOutput(@, "incomplete")'
        in body(text, "IncompleteStream")
        and server_error.count("ResolvePostDispatch(@)") == 1
        and "ResolvePostDispatch(@)" in post_drop,
        "known outputs must commit holds while unknown outcomes retain them",
    )
    for returned_action in ("DenyPostInvocation", "IncompleteStream"):
        returned_body = body(text, returned_action)
        require(
            "post_dispatch_outcome_unknown," in returned_body
            and "post_dispatch_outcome_unknown'" not in returned_body,
            f"{returned_action} must remain a known returned-output path",
        )
    require(
        'ServerErrorKinds == {"deny", "incomplete", "cancel", "url"}'
        in server_error_kinds
        and 'error_kind = "url"' in server_error_receipt_kind
        and 'THEN "incomplete"' in server_error_receipt_kind
        and "error_kind \\in ServerErrorKinds" in server_error
        and "nested_bridge_active \\in BOOLEAN" in server_error
        and "ServerErrorReceiptKind(error_kind)" in server_error
        and 'IF append_persisted THEN receipt_kind ELSE "none"' in server_error
        and "post_dispatch_outcome_unknown'" in server_error
        and "server_error_kind'" in server_error
        and "nested_bridge_active_at_error'" in server_error
        and "post_dispatch_outcome_unknown'" in post_drop
        and "![i] = TRUE" in server_error
        and "![i] = TRUE" in post_drop
        and "ResolvePostDispatch(@)" in server_error
        and "ResolvePreDispatch" not in server_error
        and "IF nested_bridge_active" not in server_error,
        "every URL and non-URL server error must use the same unknown resolver",
    )
    require(
        "A returned output reaches finalization after" in text
        and "budget reconciliation, so its hold is committed." in text
        and "Every Err returned after polling any invoke path is outcome-unknown."
        in text
        and "URL elicitation follows this rule regardless of nested bridge activity."
        in text
        and "Only a kernel error before polling invoke is pre-dispatch and reversible."
        in text,
        "the model must classify all server-returned errors as outcome-unknown",
    )
    require(
        retained.count("<=>") == 2
        and 'ledger[i]["lease"] = "retained"' in retained
        and 'ledger[i]["hold"] = "retained"' in retained
        and 'terminal_kind[i] \\in {"deny", "incomplete", "cancel"}' in retained
        and "post_dispatch_outcome_unknown[i]" in retained
        and 'server_error_kind[i] = "url"' in retained
        and 'terminal_kind[i] = "incomplete"' in retained
        and 'phase[i] = "terminal_denied"' in retained,
        "RetainedIffAborted must distinguish known output from unknown outcome",
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
        "evaluate_tool_call_async_with_session_context",
        "evaluate_tool_call_with_nested_flow_client_async",
        "PostAdmissionDropGuard::new",
        "PostAdmissionDropGuard::child_receipts_mut",
        "record_buffered_child_receipts",
        "PostAdmissionDropGuard::mark_dispatch_started",
        "PostAdmissionDropGuard::disarm",
        "record_chio_receipt_with_mode",
        "finalize_tool_output_with_metadata_and_payee_binding",
        "retained_admission_receipt_metadata",
        "ambiguous_dispatch_receipt_metadata",
        "PostAdmissionDropGuard::handle_pre_dispatch_drop",
        "record_pre_dispatch_cleanup_fault_receipt",
        "PostAdmissionDropGuard::drop",
        "flush_buffered_child_receipts_from_drop",
        "evaluate_runtime_admission_tracked",
        "ChioRuntimeAdmissionHook::release_reservations",
        "ChioRuntimeAdmissionHook::release_reserved",
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
        "DropGuardChildOversubscriptionBroken",
        "DropGuardSkipInvocationReversalBroken",
        "DropGuardNoFaultReceiptBroken",
        "DropGuardReleaseOnIncompleteStreamBroken",
        "DropGuardNoRetainOnPostInvocationDenyBroken",
        "DropGuardReleaseOnPostDispatchAbortBroken",
        "DistributedRevocationRevocationGateBroken",
        "DistributedRevocationSignerPinBroken",
        "DistributedRevocationSkewBroken",
        "DistributedRevocationPartitionBroken",
        "DistributedRevocationFreshnessBroken",
        "DistributedRevocationEvaluationCountWitness",
    }
    actual = {Path(entry["spec"]).stem for entry in entries}
    require(actual == expected, "negative registry must contain the exact calibrated models")

    mapping = read("formal/MAPPING.md")
    for entry in entries:
        require(
            f"`{entry['falsifies']}`" in mapping,
            f"negative registry property is not mapped: {entry['falsifies']}",
        )

    mutation_by_stem = {
        "DropGuardDiscardChildBufferBroken": "discard-child-buffer",
        "DropGuardSkipChildBudgetReleaseBroken": "skip-child-release",
        "DropGuardChildOversubscriptionBroken": "skip-child-capacity-guard",
        "DropGuardSkipInvocationReversalBroken": "skip-slot-release",
        "DropGuardNoFaultReceiptBroken": "omit-fault-receipt",
        "DropGuardReleaseOnIncompleteStreamBroken": "release-incomplete-lease",
        "DropGuardNoRetainOnPostInvocationDenyBroken": "skip-deny-retention",
        "DropGuardReleaseOnPostDispatchAbortBroken": "release-post-dispatch-state",
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

    distributed_mutations = {
        "DistributedRevocationRevocationGateBroken": "skip-revocation",
        "DistributedRevocationSignerPinBroken": "accept-forged",
        "DistributedRevocationSkewBroken": "unbounded-skew",
        "DistributedRevocationPartitionBroken": "cross-partition-catchup",
        "DistributedRevocationFreshnessBroken": "skip-freshness",
    }
    for stem, mutation in distributed_mutations.items():
        module = read(f"formal/apalache/_negative_tests/{stem}.tla")
        config = read(f"formal/apalache/_negative_tests/MC{stem}.cfg")
        require(
            "EXTENDS DistributedRevocation" in module,
            f"{stem} must reuse the distributed production model semantics",
        )
        require(
            f'Mutation = "{mutation}"' in config,
            f"{stem} config must select only its calibrated mutation",
        )
    witness = read(
        "formal/apalache/_negative_tests/DistributedRevocationEvaluationCountWitness.tla"
    )
    witness_config = read(
        "formal/apalache/_negative_tests/MCDistributedRevocationEvaluationCountWitness.cfg"
    )
    require(
        "EXTENDS DistributedRevocation" in witness,
        "the rejected count-bound witness must reuse distributed semantics",
    )
    require(
        'Mutation = "none"' in witness_config,
        "the rejected count-bound witness must not depend on a broken mutation",
    )


def check_temporal_workflow() -> None:
    text = read(".github/workflows/apalache-temporal.yml")
    positive_gate = read("scripts/check-apalache-positive.sh")
    cfg = read("formal/tla/MCRevocationPropagationTemporal.cfg")
    distributed_temporal = read("formal/tla/DistributedRevocationTemporal.tla")
    temporal_gate = read("scripts/check-distributed-revocation-temporal.sh")
    refinement = read("formal/tla/DistributedRevocationTemporalRefinement.tla")
    refinement_cfg = read("formal/tla/MCDistributedRevocationTemporalRefinement.cfg")
    witness = read("formal/tla/DistributedRevocationTemporalWitness.tla")
    legacy_job = workflow_job(
        text,
        "revocation_eventually_seen",
        "distributed_revocation_temporal",
    )
    verdict_job = workflow_job(text, "temporal_verdict", None)

    outer_timeout = re.search(r"(?m)^    timeout-minutes: ([0-9]+)$", legacy_job)
    inner_timeout = re.search(r"--timeout-seconds ([0-9]+)", legacy_job)
    require(
        outer_timeout is not None and inner_timeout is not None,
        "legacy temporal job must declare both outer and inner timeouts",
    )
    require(
        int(inner_timeout.group(1)) == 3600,
        "legacy temporal evidence must retain its 3600-second model-check budget",
    )
    require(
        int(outer_timeout.group(1)) * 60 == int(inner_timeout.group(1)) + 900,
        "legacy temporal job must reserve exactly 900 seconds for setup and teardown",
    )
    require(
        "if: ${{ always() }}" in verdict_job,
        "temporal verdict must run even when an upstream temporal job fails",
    )
    for dependency in ("revocation_eventually_seen", "distributed_revocation_temporal"):
        require(
            f"      - {dependency}" in verdict_job,
            f"temporal verdict must depend on {dependency}",
        )
    require(
        '[[ "${LEGACY_RESULT}" != "success" || "${DISTRIBUTED_RESULT}" != "success" ]]'
        in verdict_job,
        "temporal verdict must fail unless both temporal jobs succeed",
    )

    require(
        "continue-on-error" not in text,
        "apalache-temporal must be fail-closed, not continue-on-error advisory",
    )
    require(
        "advisory" not in text.lower(),
        "apalache-temporal must not describe the liveness lane as advisory",
    )
    require(
        "RevocationEventuallySeen" in text and "--temporal RevocationEventuallySeen" in text,
        "apalache-temporal must run the named RevocationEventuallySeen liveness property",
    )
    require(
        "./scripts/check-distributed-revocation-temporal.sh" in text,
        "apalache-temporal must run the strict distributed temporal gate",
    )
    for marker in (
        "--temporal TemporalProjectionRefines",
        "--length 5",
        "--config formal/tla/MCDistributedRevocationTemporalRefinement.cfg",
        "--config formal/tla/MCDistributedRevocationTemporalWitness.cfg",
        "--temporal RevocationEventuallyObservedDistributed",
        "--config formal/tla/MCDistributedRevocationTemporal.cfg",
        "--no-deadlock",
    ):
        require(marker in temporal_gate, f"distributed temporal gate is missing {marker}")
    for marker in (
        '[[ "${version}" != "0.50.1" ]]',
        "scripts/lib/apalache_evidence.py positive",
        '--out-dir="${out_dir}"',
        '--run-dir="${run_dir}"',
    ):
        require(marker in positive_gate, f"positive Apalache gate is missing {marker}")
    require(
        "RevocationEventuallyObservedDistributed" in distributed_temporal
        and "ObserveWeakFair" in distributed_temporal
        and "HealWeakFair" in distributed_temporal,
        "distributed temporal projection must retain conditional weak fairness",
    )
    require(
        "Scalar!Spec" in refinement
        and "originEpoch <- originEpoch[SelectedOrigin]" in refinement
        and "observedEpoch <- hwm[SelectedReceiver][SelectedOrigin]" in refinement
        and "partitioned <- ~IsConnected(SelectedReceiver, SelectedOrigin)" in refinement
        and "cutUsed <- <<SelectedReceiver, SelectedOrigin>> \\in cutUsed" in refinement,
        "bounded temporal refinement must map the selected full-model pair exactly",
    )
    require(
        "SPECIFICATION TemporalSpec" in refinement_cfg
        and "SelectedOrigin = 1" in refinement_cfg
        and "SelectedReceiver = 2" in refinement_cfg,
        "bounded temporal refinement config must select a distinct checked pair",
    )
    require(
        "AnyOriginEpochIssued" in witness
        and "AllIssuedEpochsObserved" in witness
        and "~ObserveEnabled" in witness
        and "~HealEnabled" in witness
        and "Stutter" in witness,
        "temporal non-vacuity witness must reach observation and a fair stutter suffix",
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
    distributed_cfg = read("formal/tla/MCDistributedRevocation.cfg")
    distributed_domains_cfg = read("formal/tla/MCDistributedRevocationDomains.cfg")

    required_paths = (
        "formal/MAPPING.md",
        "formal/proof-manifest.toml",
        "crates/trust/chio-revocation-oracle/src/**",
        "crates/kernel/chio-kernel-core/src/evaluate.rs",
        "crates/kernel/chio-kernel-core/src/revocation_view.rs",
        "crates/kernel/chio-kernel/src/budget_store.rs",
        "crates/kernel/chio-kernel/src/receipt_store.rs",
        "crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs",
        "crates/kernel/chio-kernel/src/kernel/kernel_scopes.rs",
        "crates/kernel/chio-kernel/src/kernel/dispatch.rs",
        "crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs",
        "crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs",
        "crates/kernel/chio-kernel/src/kernel/responses/finalization.rs",
        "crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs",
        "crates/kernel/chio-kernel/src/kernel/validation.rs",
        "crates/kernel/chio-kernel/src/kernel/tests/chio_runtime.rs",
        "crates/kernel/chio-runtime-core/src/admission.rs",
        "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        "crates/kernel/chio-runtime-core/src/admission_hook/**",
        "scripts/check-apalache-formal-slice.py",
        "scripts/check-apalache-positive.sh",
        ".github/workflows/apalache-temporal.yml",
    )
    for path in required_paths:
        require(
            f'- "{path}"' in text,
            f"apalache-safety paths must include {path}",
        )

    with (REPO / "formal/proof-manifest.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    mirror_sources = {
        mirror["rust_source"]
        for mirror in manifest.get("mirror", [])
        if mirror.get("model_file", "").startswith(("formal/apalache/", "formal/tla/"))
    }
    workflow_paths = workflow_pull_request_paths(text)
    uncovered_sources = sorted(
        source
        for source in mirror_sources
        if not workflow_path_covers(source, workflow_paths)
    )
    require(
        not uncovered_sources,
        "apalache-safety paths omit registered TLA/Apalache mirror sources: "
        + ", ".join(uncovered_sources),
    )

    def has_matrix_row(
        config: str, spec: str, length: int, timeout_seconds: int, invariant: str
    ) -> bool:
        pattern = (
            rf"config: {re.escape(config)}\s+"
            rf"spec: {re.escape(spec)}\s+"
            rf"length: {length}\s+"
            rf"timeout_seconds: {timeout_seconds}\s+"
            rf"invariant: {re.escape(invariant)}"
        )
        return re.search(pattern, text) is not None

    require(
        has_matrix_row(
            "formal/tla/MCRevocationPropagation.cfg",
            "formal/tla/RevocationPropagation.tla",
            6,
            10800,
            "SafetyInv",
        ),
        "apalache-safety must keep RevocationPropagation length and timeout coverage",
    )
    require(
        has_matrix_row(
            "formal/tla/MCDistributedRevocationDomains.cfg",
            "formal/tla/DistributedRevocation.tla",
            0,
            600,
            "DistributedDomainsOK",
        ),
        "apalache-safety must check exact distributed domains at initialization",
    )
    require(
        re.search(r"(?m)^\s*BehavioralSafetyInv\s*$", distributed_cfg) is not None,
        "distributed PR config must select the behavioral safety aggregate",
    )
    require(
        "SPECIFICATION Spec" in distributed_domains_cfg
        and re.search(
            r"(?m)^\s*DistributedDomainsOK\s*$", distributed_domains_cfg
        )
        is not None,
        "distributed domain config must check exact initial domains",
    )
    require(
        has_matrix_row(
            "formal/tla/MCDistributedRevocation.cfg",
            "formal/tla/DistributedRevocation.tla",
            6,
            1800,
            "BehavioralSafetyInv",
        ),
        "apalache-safety must check distributed revocation safety",
    )
    require(
        re.search(
            r"--length 6\s+\\\s*\n\s*--timeout-seconds 3600\s+\\\s*\n\s*"
            r"--config formal/tla/MCDistributedRevocationNightly\.cfg",
            text,
        )
        is not None,
        "scheduled distributed safety must expand constants at calibrated length 6",
    )
    require(
        has_matrix_row(
            "formal/tla/MCDelegationDepthBound.cfg",
            "formal/tla/DelegationDepthBound.tla",
            6,
            1800,
            "SafetyInv",
        ),
        "apalache-safety must keep DelegationDepthBound safety coverage",
    )
    require(
        has_matrix_row(
            "formal/apalache/MCPostAdmissionDropGuard.cfg",
            "formal/apalache/PostAdmissionDropGuard.tla",
            8,
            10800,
            "SafetyInv",
        ),
        "apalache-safety must run the drop-guard model at length 8",
    )
    require(
        "./scripts/check-apalache-positive.sh" in text
        and '--invariant "${{ matrix.invariant }}"' in text
        and '--length "${{ matrix.length }}"' in text
        and '--timeout-seconds "${{ matrix.timeout_seconds }}"' in text,
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


def check_distributed_trace_gate() -> None:
    gate = read("scripts/check-distributed-revocation-refinement.sh")
    validator = read("scripts/validate-distributed-revocation-trace.py")
    projection = read("formal/tla/trace/TraceCheckDistributedRevocation.tla")
    rust_trace = read(
        "crates/trust/chio-federation/tests/distributed_revocation_refinement.rs"
    )

    for marker in (
        'cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"',
        'Trace*Itf.tla',
        '--init=TraceInit',
        '--next=TraceNext',
        '--inv=TraceSafety',
    ):
        require(marker in gate, f"distributed trace gate is missing {marker}")
    require(
        "write_tla_projection" in validator and "ConcreteTrace" in validator,
        "distributed trace validator must generate exact concrete TLA projections",
    )
    require(
        "ProjectionStep ==" in projection
        and "ProjectionSafety ==" in projection
        and "RootIssuedAt" in projection,
        "distributed trace TLA must check projected states and adjacent steps",
    )
    require(
        "ROOT_ISSUED_AT_BASE" in rust_trace
        and "state.view_issued_at = newest.signed_root.root.issued_at_unix_ms" in rust_trace
        and "state.view_issued_at = latest_issued_at" in rust_trace,
        "production traces must emit installed signed-root timestamps",
    )
    require(
        "ROOT_ISSUED_AT_BASE + current[\"viewEpoch\"]" in validator
        and "does not bind the view to its signed root timestamp" in validator,
        "distributed trace validator must bind view epochs to emitted root timestamps",
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
        check_distributed_trace_gate,
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
