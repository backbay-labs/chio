"""Tests for Chio SDK error types.

Covers the structured-context enrichment of ``ChioDeniedError``: the error surfaces
structured deny context (tool name, scopes, guard, reason code, hint) and
the human-readable ``str(err)`` output includes every populated field.
Back-compat for the single-argument constructor is verified explicitly so
existing call sites keep working.
"""

from __future__ import annotations

import pytest

from chio_sdk.errors import (
    ChioConnectionError,
    ChioDeniedError,
    ChioError,
    ChioTimeoutError,
    ChioValidationError,
)


# ---------------------------------------------------------------------------
# Base behavior
# ---------------------------------------------------------------------------


class TestChioErrorHierarchy:
    def test_denied_is_chio_error(self) -> None:
        err = ChioDeniedError("nope")
        assert isinstance(err, ChioError)
        assert err.code == "DENIED"

    def test_connection_code(self) -> None:
        assert ChioConnectionError("x").code == "CONNECTION_ERROR"

    def test_timeout_code(self) -> None:
        assert ChioTimeoutError("x").code == "TIMEOUT"

    def test_validation_code(self) -> None:
        assert ChioValidationError("x").code == "VALIDATION_ERROR"


# ---------------------------------------------------------------------------
# Back-compat: single-arg and legacy kwargs-only construction
# ---------------------------------------------------------------------------


class TestChioDeniedErrorBackCompat:
    def test_message_only_positional(self) -> None:
        """Legacy call sites pass a single positional message."""
        err = ChioDeniedError("denied")
        assert str(err) == "denied"
        assert err.message == "denied"
        assert err.guard is None
        assert err.reason is None
        assert err.tool_name is None
        assert err.required_scope is None
        assert err.granted_scope is None
        assert err.hint is None

    def test_legacy_guard_and_reason_kwargs(self) -> None:
        """client.py and testing.py both pass these two keyword fields."""
        err = ChioDeniedError(
            "request blocked",
            guard="CapabilityGuard",
            reason="no capability token provided",
        )
        assert err.guard == "CapabilityGuard"
        assert err.reason == "no capability token provided"
        # Both fields populated, so the multi-line formatter kicks in.
        rendered = str(err)
        assert "Chio DENIED" in rendered
        assert "CapabilityGuard" in rendered
        assert "no capability token provided" in rendered

    def test_can_be_raised_and_caught(self) -> None:
        with pytest.raises(ChioDeniedError) as excinfo:
            raise ChioDeniedError("denied")
        assert excinfo.value.code == "DENIED"


# ---------------------------------------------------------------------------
# Enriched fields
# ---------------------------------------------------------------------------


def _full_error() -> ChioDeniedError:
    return ChioDeniedError(
        "tool call denied by path-constraint guard",
        guard="path-constraint",
        reason='path ".env" matches deny pattern',
        tool_name="write_file",
        tool_server="filesystem",
        requested_action='write_file(path=".env", content="SECRET=x")',
        required_scope=(
            'ToolGrant(server_id="filesystem", tool_name="write_file", '
            "operations=[Invoke], constraints=[])"
        ),
        granted_scope=(
            'ToolGrant(server_id="filesystem", tool_name="write_file", '
            'operations=[Invoke], constraints=[path_prefix("."), '
            'regex_match("^(?!.*(.env))")])'
        ),
        reason_code="guard.path_constraint",
        receipt_id="chio-receipt-7f3a9b2c",
        hint=(
            "Remove the path_prefix constraint from your policy, or call "
            "write_file with a path inside the project root."
        ),
        docs_url="https://docs.chio-protocol.dev/errors/CHIO-DENIED",
    )


class TestChioDeniedErrorEnriched:
    def test_all_fields_round_trip_on_instance(self) -> None:
        err = _full_error()
        assert err.tool_name == "write_file"
        assert err.tool_server == "filesystem"
        assert err.requested_action.startswith("write_file(")
        assert "ToolGrant" in err.required_scope
        assert "path_prefix" in err.granted_scope
        assert err.guard == "path-constraint"
        assert err.reason_code == "guard.path_constraint"
        assert err.receipt_id == "chio-receipt-7f3a9b2c"
        assert err.hint.startswith("Remove the path_prefix")
        assert err.docs_url.startswith("https://")

    def test_str_contains_every_field_label_and_value(self) -> None:
        err = _full_error()
        rendered = str(err)

        # Header includes the tool identity.
        assert 'tool "write_file"' in rendered
        assert 'server "filesystem"' in rendered

        # Each section label is present.
        for label in [
            "What was denied:",
            "Why it was denied:",
            "What scope was needed:",
            "What scope was granted:",
            "Guard that denied:",
            "Reason code:",
            "Receipt ID:",
            "Next steps:",
            "Docs:",
        ]:
            assert label in rendered, f"missing label: {label}"

        # Each field value is present.
        assert 'write_file(path=".env"' in rendered
        assert 'path ".env" matches deny pattern' in rendered
        assert "path-constraint" in rendered
        assert "guard.path_constraint" in rendered
        assert "chio-receipt-7f3a9b2c" in rendered
        assert "Remove the path_prefix" in rendered
        assert "https://docs.chio-protocol.dev/errors/CHIO-DENIED" in rendered

    def test_to_dict_includes_only_populated_fields(self) -> None:
        err = ChioDeniedError(
            "denied",
            tool_name="read_file",
            required_scope="ToolGrant(server_id=fs, tool_name=read_file)",
            reason_code="scope.missing",
        )
        payload = err.to_dict()
        assert payload["code"] == "DENIED"
        assert payload["message"] == "denied"
        assert payload["tool_name"] == "read_file"
        assert payload["required_scope"].startswith("ToolGrant(")
        assert payload["reason_code"] == "scope.missing"
        # Unpopulated fields must not appear in the payload.
        for absent in [
            "tool_server",
            "guard",
            "reason",
            "granted_scope",
            "receipt_id",
            "hint",
            "docs_url",
            "requested_action",
        ]:
            assert absent not in payload, f"unexpected field in dict: {absent}"

    def test_to_dict_full(self) -> None:
        err = _full_error()
        payload = err.to_dict()
        expected = {
            "code",
            "message",
            "tool_name",
            "tool_server",
            "requested_action",
            "required_scope",
            "granted_scope",
            "guard",
            "reason",
            "reason_code",
            "receipt_id",
            "hint",
            "docs_url",
        }
        assert set(payload.keys()) == expected


# ---------------------------------------------------------------------------
# Wire format parsing
# ---------------------------------------------------------------------------


class TestChioDeniedErrorFromWire:
    def test_parses_full_sidecar_payload(self) -> None:
        body = {
            "code": "Chio-DENIED",
            "message": "write_file blocked by path-constraint",
            "tool_name": "write_file",
            "tool_server": "filesystem",
            "reason": 'path ".env" matches deny pattern',
            "guard": "path-constraint",
            "required_scope": 'ToolGrant(server_id="filesystem")',
            "granted_scope": 'ToolGrant(server_id="filesystem", constraints=[...])',
            "reason_code": "guard.path_constraint",
            "receipt_id": "chio-receipt-7f3a9b2c",
            "hint": "Update your policy to remove the path constraint.",
            "docs_url": "https://docs.chio-protocol.dev/errors/CHIO-DENIED",
        }
        err = ChioDeniedError.from_wire(body)
        assert err.tool_name == "write_file"
        assert err.tool_server == "filesystem"
        assert err.guard == "path-constraint"
        assert err.reason_code == "guard.path_constraint"
        assert err.receipt_id == "chio-receipt-7f3a9b2c"
        assert err.hint.startswith("Update your policy")
        assert err.docs_url.startswith("https://")
        # Human-readable output surfaces the full structure.
        rendered = str(err)
        assert "write_file" in rendered
        assert "filesystem" in rendered
        assert "Next steps:" in rendered

    def test_accepts_suggested_fix_as_hint_alias(self) -> None:
        """The CLI-style key ``suggested_fix`` is accepted as an alias for hint."""
        err = ChioDeniedError.from_wire(
            {
                "message": "denied",
                "suggested_fix": "Request scope fs::write_file from the authority.",
            }
        )
        assert err.hint == "Request scope fs::write_file from the authority."

    def test_falls_back_to_reason_then_literal(self) -> None:
        err = ChioDeniedError.from_wire({"reason": "scope missing"})
        assert err.message == "scope missing"
        err2 = ChioDeniedError.from_wire({})
        assert err2.message == "denied"

    def test_ignores_unknown_fields(self) -> None:
        err = ChioDeniedError.from_wire(
            {"message": "denied", "not_a_field": "ignored"}
        )
        assert err.message == "denied"
