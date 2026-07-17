"""Unit tests for :class:`chio_iac.PlanReviewGuard`.

The tests cover the three plan shapes the guard understands
(Terraform ``resource_changes``, Pulumi ``steps``, Pulumi
``resources``), the allowlist / denylist precedence rules, and the
destroy-is-special-by-default behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chio_iac import (
    ChioIACConfigError,
    ChioIACPlanReviewError,
    PlanReviewGuard,
    PlanReviewVerdict,
    ResourceTypeAllowlist,
    ResourceTypeDenylist,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tf_plan(*changes: tuple[str, list[str], str]) -> dict:
    """Build a Terraform ``show -json`` shaped plan from ``(type, actions, address)``."""
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": address,
                "type": type_,
                "name": address.split(".")[-1],
                "change": {"actions": list(actions)},
            }
            for type_, actions, address in changes
        ],
    }


def _pulumi_plan(*resources: tuple[str, str, str]) -> dict:
    """Build a Pulumi ``resources``-shape plan from ``(type, urn, action)``."""
    return {
        "resources": [
            {"type": type_, "urn": urn, "action": action}
            for type_, urn, action in resources
        ]
    }


def _pulumi_steps_plan(*steps: tuple[str, str, str]) -> dict:
    """Build a Pulumi ``steps``-shape plan from ``(op, type, urn)``."""
    return {
        "steps": [
            {
                "op": op,
                "newState": {"type": type_, "urn": urn},
            }
            for op, type_, urn in steps
        ]
    }


# ---------------------------------------------------------------------------
# Allowlist / Denylist primitives
# ---------------------------------------------------------------------------


class TestAllowlistMatching:
    def test_exact_match(self) -> None:
        allowlist = ResourceTypeAllowlist(patterns=["aws_db_instance"])
        assert allowlist.matches("aws_db_instance")
        assert not allowlist.matches("aws_iam_role")

    def test_glob_prefix(self) -> None:
        allowlist = ResourceTypeAllowlist(patterns=["aws_db_*", "aws_elasticache_*"])
        assert allowlist.matches("aws_db_instance")
        assert allowlist.matches("aws_db_cluster")
        assert allowlist.matches("aws_elasticache_cluster")
        assert not allowlist.matches("aws_s3_bucket")

    def test_wildcard_matches_all(self) -> None:
        allowlist = ResourceTypeAllowlist(patterns=["*"])
        assert allowlist.matches("aws_anything")
        assert allowlist.matches("google_sql_database_instance")
        assert allowlist.matches("kubernetes_deployment_v1")

    def test_empty_allowlist_matches_nothing(self) -> None:
        allowlist = ResourceTypeAllowlist()
        assert not allowlist.matches("aws_db_instance")

    def test_case_insensitive(self) -> None:
        allowlist = ResourceTypeAllowlist(patterns=["AWS_DB_*"])
        assert allowlist.matches("aws_db_instance")

    def test_denylist_matches(self) -> None:
        denylist = ResourceTypeDenylist(patterns=["aws_iam_*"])
        assert denylist.matches("aws_iam_role")
        assert denylist.matches("aws_iam_policy_attachment")
        assert not denylist.matches("aws_db_instance")


# ---------------------------------------------------------------------------
# Terraform plan shape
# ---------------------------------------------------------------------------


class TestTerraformPlanReview:
    def test_in_scope_plan_is_allowed(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
        )
        plan = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
            ("aws_db_parameter_group", ["create"], "aws_db_parameter_group.pg"),
        )
        verdict = guard.review(plan)
        assert verdict.allowed
        assert verdict.violations == []
        assert len(verdict.resources) == 2

    def test_out_of_scope_resource_is_denied(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
        )
        plan = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
            ("aws_iam_role", ["create"], "aws_iam_role.db_access"),
        )
        verdict = guard.review(plan)
        assert not verdict.allowed
        assert len(verdict.violations) == 1
        assert verdict.violations[0]["resource_type"] == "aws_iam_role"
        assert "not on the allowlist" in verdict.violations[0]["reason"]

    def test_denylist_wins_over_allowlist(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_*"]),
            denylist=ResourceTypeDenylist(patterns=["aws_iam_*"]),
        )
        plan = _tf_plan(
            ("aws_iam_role", ["create"], "aws_iam_role.r"),
        )
        verdict = guard.review(plan)
        assert not verdict.allowed
        assert "denylist" in verdict.violations[0]["reason"]

    def test_no_op_resources_do_not_trigger_review(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
        )
        plan = _tf_plan(
            ("aws_iam_role", ["no-op"], "aws_iam_role.unchanged"),
        )
        verdict = guard.review(plan)
        assert verdict.allowed
        # No mutating resources so no violations even though type is
        # out of scope.
        assert verdict.violations == []

    def test_unknown_plan_shape_is_denied(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["*"]),
        )
        verdict = guard.review({"format_version": "1.2"})
        assert not verdict.allowed
        assert verdict.resources == []
        assert verdict.violations[0]["resource_type"] == "unknown"
        assert "did not match" in verdict.violations[0]["reason"]

    def test_destroy_blocked_by_default(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
        )
        plan = _tf_plan(
            ("aws_db_instance", ["delete"], "aws_db_instance.primary"),
        )
        verdict = guard.review(plan)
        assert not verdict.allowed
        assert "destroys are disabled" in verdict.violations[0]["reason"]

    def test_destroy_allowed_when_opted_in(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
            allow_destroy=True,
        )
        plan = _tf_plan(
            ("aws_db_instance", ["delete"], "aws_db_instance.primary"),
        )
        verdict = guard.review(plan)
        assert verdict.allowed

    def test_replace_is_treated_as_destroy(self) -> None:
        # replace = delete + create; same blast radius as a raw delete.
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
        )
        plan = _tf_plan(
            ("aws_db_instance", ["delete", "create"], "aws_db_instance.primary"),
        )
        verdict = guard.review(plan)
        assert not verdict.allowed
        assert verdict.violations[0]["action"] == "replace"

    def test_resource_types_lists_mutating_only(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["*"]),
        )
        plan = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
            ("aws_iam_role", ["no-op"], "aws_iam_role.unchanged"),
            ("aws_s3_bucket", ["update"], "aws_s3_bucket.logs"),
        )
        assert guard.resource_types(plan) == ["aws_db_instance", "aws_s3_bucket"]


# ---------------------------------------------------------------------------
# Pulumi plan shape
# ---------------------------------------------------------------------------


class TestPulumiPlanReview:
    def test_pulumi_resources_shape(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
        )
        plan = _pulumi_plan(
            ("aws:rds/instance:Instance", "urn:pulumi:dev::project::db", "create"),
            ("aws:iam/role:Role", "urn:pulumi:dev::project::role", "create"),
        )
        verdict = guard.review(plan)
        assert not verdict.allowed
        types = {v["resource_type"] for v in verdict.violations}
        assert types == {"aws:iam/role:Role"}

    def test_pulumi_steps_shape(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
        )
        plan = _pulumi_steps_plan(
            ("create", "aws:rds/instance:Instance", "urn:pulumi:dev::project::db"),
            ("create", "aws:iam/role:Role", "urn:pulumi:dev::project::role"),
        )
        verdict = guard.review(plan)
        assert not verdict.allowed
        types = {v["resource_type"] for v in verdict.violations}
        assert types == {"aws:iam/role:Role"}

    def test_pulumi_same_op_is_not_mutating(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
        )
        plan = _pulumi_steps_plan(
            ("same", "aws:iam/role:Role", "urn:pulumi:dev::project::role"),
        )
        verdict = guard.review(plan)
        assert verdict.allowed


# ---------------------------------------------------------------------------
# File / JSON convenience
# ---------------------------------------------------------------------------


class TestReviewFileIo:
    def test_review_file_roundtrip(self, tmp_path: Path) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
        )
        plan = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )
        plan_file = tmp_path / "plan.json"
        plan_file.write_text(json.dumps(plan), encoding="utf-8")

        verdict = guard.review_file(plan_file)
        assert verdict.allowed

    def test_review_file_missing_raises_config_error(self, tmp_path: Path) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["*"]),
        )
        with pytest.raises(ChioIACConfigError) as exc_info:
            guard.review_file(tmp_path / "missing.json")
        assert "does not exist" in str(exc_info.value)

    def test_review_json_rejects_non_object(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["*"]),
        )
        with pytest.raises(ChioIACConfigError):
            guard.review_json("[1, 2, 3]")

    def test_review_json_rejects_invalid_json(self) -> None:
        guard = PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["*"]),
        )
        with pytest.raises(ChioIACConfigError):
            guard.review_json("{not json}")


# ---------------------------------------------------------------------------
# PlanReviewVerdict helpers
# ---------------------------------------------------------------------------


class TestVerdictHelpers:
    def test_raise_for_violations_on_allow_is_noop(self) -> None:
        verdict = PlanReviewVerdict(allowed=True)
        # Must not raise.
        verdict.raise_for_violations(subcommand="apply", capability_id="cap")

    def test_raise_for_violations_on_deny(self) -> None:
        verdict = PlanReviewVerdict(
            allowed=False,
            violations=[
                {
                    "resource_type": "aws_iam_role",
                    "address": "aws_iam_role.r",
                    "action": "create",
                    "reason": "not on allowlist",
                }
            ],
        )
        with pytest.raises(ChioIACPlanReviewError) as exc_info:
            verdict.raise_for_violations(subcommand="apply", capability_id="cap-1")
        err = exc_info.value
        assert err.subcommand == "apply"
        assert err.capability_id == "cap-1"
        assert err.guard == "PlanReviewGuard"
        assert err.violations[0]["resource_type"] == "aws_iam_role"
        assert "aws_iam_role" in str(err)
