"""Unit tests for :class:`chio_dagster.ChioIOManager`.

The :class:`ChioIOManager` wraps an inner :class:`dagster.IOManager` and
evaluates a Chio capability before each :meth:`load_input` /
:meth:`handle_output`. These tests exercise the manager directly with a
fake :class:`dagster.IOManager` and a fake context object so we cover
the allow, deny, and partition-scoping paths without needing Dagster's
full execution harness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from chio_sdk.testing import MockChioClient, MockVerdict, allow_all, deny_all

from chio_dagster import ChioDagsterConfigError, ChioIOManager

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeInnerManager:
    """Minimal :class:`dagster.IOManager`-shaped fake.

    The real wrapper delegates :meth:`handle_output` / :meth:`load_input`
    to an inner manager. Using a fake keeps the tests focused on the
    Chio evaluation path and avoids pulling in Dagster's filesystem
    managers.
    """

    def __init__(self) -> None:
        self.written: list[tuple[Any, Any]] = []
        self.load_value: Any = "loaded-value"
        self.load_calls: list[Any] = []

    def handle_output(self, context: Any, obj: Any) -> None:
        self.written.append((context, obj))

    def load_input(self, context: Any) -> Any:
        self.load_calls.append(context)
        return self.load_value


class _FakeAssetKey:
    def __init__(self, name: str) -> None:
        self._name = name

    def to_user_string(self) -> str:
        return self._name


@dataclass
class _FakeOutputContext:
    """Shape-compatible stand-in for :class:`dagster.OutputContext`."""

    asset_key: _FakeAssetKey | None = None
    _partition_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_partition_key(self) -> bool:
        return self._partition_key is not None

    @property
    def partition_key(self) -> str | None:
        return self._partition_key

    @property
    def has_asset_partitions(self) -> bool:
        return self._partition_key is not None

    @property
    def asset_partition_key(self) -> str | None:
        return self._partition_key


@dataclass
class _FakeInputContext:
    """Shape-compatible stand-in for :class:`dagster.InputContext`."""

    asset_key: _FakeAssetKey | None = None
    _partition_key: str | None = None

    @property
    def has_partition_key(self) -> bool:
        return self._partition_key is not None

    @property
    def partition_key(self) -> str | None:
        return self._partition_key

    @property
    def has_asset_partitions(self) -> bool:
        return self._partition_key is not None

    @property
    def asset_partition_key(self) -> str | None:
        return self._partition_key


# ---------------------------------------------------------------------------
# (a) Config
# ---------------------------------------------------------------------------


class TestConfig:
    def test_missing_inner_raises(self) -> None:
        with pytest.raises(ChioDagsterConfigError):
            ChioIOManager(None, capability_id="cap-1")  # type: ignore[arg-type]

    def test_missing_capability_id_raises(self) -> None:
        with pytest.raises(ChioDagsterConfigError):
            ChioIOManager(_FakeInnerManager(), capability_id="")

    def test_inner_missing_required_methods_raises(self) -> None:
        class NotAnIOManager:
            pass

        with pytest.raises(ChioDagsterConfigError):
            ChioIOManager(NotAnIOManager(), capability_id="cap-1")


# ---------------------------------------------------------------------------
# (b) Allow path -- evaluate, then delegate.
# ---------------------------------------------------------------------------


class TestAllowPath:
    def test_handle_output_evaluates_then_delegates(self) -> None:
        chio = allow_all()
        inner = _FakeInnerManager()
        manager = ChioIOManager(
            inner,
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=chio,
        )
        context = _FakeOutputContext(asset_key=_FakeAssetKey("my_asset"))

        manager.handle_output(context, {"hello": "world"})

        assert inner.written == [(context, {"hello": "world"})]
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        call = evaluate_calls[0]
        assert call.tool_name == "io:write"
        assert call.tool_server == "chio_data"
        assert call.parameters["operation"] == "write"
        assert call.parameters["asset"] == "my_asset"
        assert call.parameters["destination"] == "_FakeInnerManager"

    def test_load_input_evaluates_then_delegates(self) -> None:
        chio = allow_all()
        inner = _FakeInnerManager()
        manager = ChioIOManager(
            inner,
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=chio,
        )
        context = _FakeInputContext(asset_key=_FakeAssetKey("my_asset"))

        value = manager.load_input(context)

        assert value == "loaded-value"
        assert inner.load_calls == [context]
        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        assert evaluate_calls[0].tool_name == "io:read"
        assert evaluate_calls[0].parameters["operation"] == "read"


# ---------------------------------------------------------------------------
# (c) Deny path -- PermissionError, inner is NOT called.
# ---------------------------------------------------------------------------


class TestDenyPath:
    def test_handle_output_denies_before_delegating(self) -> None:
        chio = deny_all(
            reason="destination not allowed",
            guard="DataResidencyGuard",
            raise_on_deny=False,
        )
        inner = _FakeInnerManager()
        manager = ChioIOManager(
            inner,
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=chio,
        )
        context = _FakeOutputContext(asset_key=_FakeAssetKey("my_asset"))

        with pytest.raises(PermissionError) as exc_info:
            manager.handle_output(context, {"hello": "world"})

        assert "Chio capability denied" in str(exc_info.value)
        chio_error = getattr(exc_info.value, "chio_error", None)
        assert chio_error is not None
        assert chio_error.reason == "destination not allowed"
        assert chio_error.guard == "DataResidencyGuard"
        # Inner manager must not have been invoked when Chio denies.
        assert inner.written == []

    def test_handle_output_denies_via_http_403_path(self) -> None:
        # Default raise_on_deny=True: the mock raises ChioDeniedError;
        # the manager translates it to PermissionError.
        chio = deny_all(reason="no write perms", guard="CapabilityGuard")
        inner = _FakeInnerManager()
        manager = ChioIOManager(
            inner,
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=chio,
        )
        context = _FakeOutputContext(asset_key=_FakeAssetKey("my_asset"))

        with pytest.raises(PermissionError):
            manager.handle_output(context, {"hello": "world"})
        assert inner.written == []

    def test_load_input_denies_before_delegating(self) -> None:
        chio = deny_all(
            reason="read denied",
            guard="ScopeGuard",
            raise_on_deny=False,
        )
        inner = _FakeInnerManager()
        manager = ChioIOManager(
            inner,
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=chio,
        )
        context = _FakeInputContext(asset_key=_FakeAssetKey("my_asset"))

        with pytest.raises(PermissionError):
            manager.load_input(context)
        assert inner.load_calls == []


# ---------------------------------------------------------------------------
# (d) Partition propagation in IO context.
# ---------------------------------------------------------------------------


class TestPartitionScoping:
    def test_partition_key_reaches_capability_payload(self) -> None:
        chio = allow_all()
        inner = _FakeInnerManager()
        manager = ChioIOManager(
            inner,
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=chio,
        )
        context = _FakeOutputContext(
            asset_key=_FakeAssetKey("regional_analytics"),
            _partition_key="eu-west",
        )

        manager.handle_output(context, {"rows": 10})

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        params = evaluate_calls[0].parameters
        assert params["partition_key"] == "eu-west"
        assert params["partition"]["partition_key"] == "eu-west"

    def test_partition_scoped_policy_gates_write(self) -> None:
        """A guard can deny writes for unauthorised partitions only."""

        def policy(
            tool_name: str,
            _scope: dict[str, Any],
            context: dict[str, Any],
        ) -> MockVerdict:
            partition = context["parameters"].get("partition_key")
            if partition == "eu-west":
                return MockVerdict.allow_verdict()
            return MockVerdict.deny_verdict(
                f"write to {partition!r} not permitted",
                guard="DataResidencyGuard",
            )

        chio = MockChioClient(policy=policy, raise_on_deny=False)
        inner = _FakeInnerManager()
        manager = ChioIOManager(
            inner,
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=chio,
        )

        # Allowed partition
        manager.handle_output(
            _FakeOutputContext(
                asset_key=_FakeAssetKey("r"),
                _partition_key="eu-west",
            ),
            "ok",
        )
        # Denied partition
        with pytest.raises(PermissionError):
            manager.handle_output(
                _FakeOutputContext(
                    asset_key=_FakeAssetKey("r"),
                    _partition_key="us-east",
                ),
                "nope",
            )

        assert len(inner.written) == 1
        assert inner.written[0][1] == "ok"


# ---------------------------------------------------------------------------
# (e) Dagster IOManager adapter hook.
# ---------------------------------------------------------------------------


class TestAdapterIntegration:
    def test_as_io_manager_returns_real_dagster_io_manager(self) -> None:
        from dagster import IOManager as DagsterIOManager

        manager = ChioIOManager(
            _FakeInnerManager(),
            capability_id="cap-1",
            tool_server="chio_data",
            chio_client=allow_all(),
        )
        adapter = manager.as_io_manager()
        assert isinstance(adapter, DagsterIOManager)
