"""Behavioural tests for :mod:`chio_adapter_base.filters`."""

from __future__ import annotations

from chio_adapter_base.filters import (
    filter_diff_output,
    filter_directory_entries,
    filter_status_output,
    forbidden_path_filter,
)


def _is_forbidden(name: str) -> bool:
    return name in {".env", "secrets.key"}


def test_forbidden_path_filter_partitions() -> None:
    kept, dropped = forbidden_path_filter(
        ["a.py", ".env", "b.py", "secrets.key"],
        is_forbidden=_is_forbidden,
    )
    assert kept == ["a.py", "b.py"]
    assert dropped == [".env", "secrets.key"]


def test_forbidden_path_filter_preserves_order() -> None:
    kept, dropped = forbidden_path_filter(
        ["d", "a", "c", "b"],
        is_forbidden=lambda p: p in {"a"},
    )
    assert kept == ["d", "c", "b"]
    assert dropped == ["a"]


def test_forbidden_path_filter_empty_input() -> None:
    kept, dropped = forbidden_path_filter([], is_forbidden=lambda _p: False)
    assert kept == []
    assert dropped == []


def test_forbidden_path_filter_propagates_exceptions() -> None:
    def _bang(_p: str) -> bool:
        raise RuntimeError("boom")

    try:
        forbidden_path_filter(["x"], is_forbidden=_bang)
    except RuntimeError as exc:
        assert str(exc) == "boom"
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")


def test_filter_directory_entries_drops_dotenv() -> None:
    raw = {
        "path": "/repo",
        "entries": [".env", "README.md", "src"],
    }
    filtered = filter_directory_entries(
        raw, is_forbidden=lambda p: p.endswith(".env")
    )
    assert ".env" not in filtered["entries"]
    assert "README.md" in filtered["entries"]
    assert filtered["forbidden_paths_filtered"] == [".env"]


def test_filter_directory_entries_no_op_when_clean() -> None:
    raw = {"path": "/repo", "entries": ["a", "b"]}
    out = filter_directory_entries(raw, is_forbidden=lambda _p: False)
    assert out is raw


def test_filter_directory_entries_handles_no_entries_key() -> None:
    raw: dict[str, object] = {"path": "/repo"}
    out = filter_directory_entries(raw, is_forbidden=lambda _p: True)
    assert out is raw


def test_filter_directory_entries_treats_exceptions_as_forbidden() -> None:
    def _bang(_p: str) -> bool:
        raise RuntimeError("boom")

    raw = {"path": "/repo", "entries": ["a"]}
    out = filter_directory_entries(raw, is_forbidden=_bang)
    assert out["entries"] == []
    assert out["forbidden_paths_filtered"] == ["a"]


def test_filter_diff_output_drops_forbidden_hunks() -> None:
    diff_text = (
        "diff --git a/.env b/.env\n"
        "--- a/.env\n"
        "+++ b/.env\n"
        "+SECRET=topsecret\n"
        "diff --git a/src/main.py b/src/main.py\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "+x = 2\n"
    )
    raw = {"stdout": diff_text, "returncode": 0}
    filtered = filter_diff_output(
        raw, is_forbidden=lambda p: p == ".env"
    )
    assert "SECRET=topsecret" not in filtered["stdout"]
    assert "x = 2" in filtered["stdout"]
    assert ".env" in filtered["forbidden_paths_filtered"]


def test_filter_diff_output_drops_malformed_header_hunks() -> None:
    diff_text = (
        "diff --git only-two-tokens\n"
        "--- a/.env\n"
        "+++ b/.env\n"
        "+SECRET=topsecret\n"
        "diff --git a/src/main.py b/src/main.py\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "+x = 2\n"
    )
    raw = {"stdout": diff_text, "returncode": 0}
    filtered = filter_diff_output(raw, is_forbidden=lambda _p: False)
    assert "SECRET=topsecret" not in filtered["stdout"]
    assert "x = 2" in filtered["stdout"]
    assert "<malformed-diff-header>" in filtered["forbidden_paths_filtered"]


def test_filter_diff_output_no_op_on_clean_diff() -> None:
    raw = {
        "stdout": (
            "diff --git a/src/main.py b/src/main.py\n"
            "--- a/src/main.py\n"
            "+++ b/src/main.py\n"
            "+x = 1\n"
        ),
        "returncode": 0,
    }
    out = filter_diff_output(raw, is_forbidden=lambda _p: False)
    assert "forbidden_paths_filtered" not in out
    assert out is raw


def test_filter_diff_output_drops_malformed_diff_header() -> None:
    raw = {
        "stdout": (
            "diff --git a/.env\n"
            "--- a/.env\n"
            "+++ b/.env\n"
            "+SECRET=topsecret\n"
        ),
        "returncode": 0,
    }
    filtered = filter_diff_output(raw, is_forbidden=lambda _p: False)
    assert "SECRET=topsecret" not in filtered["stdout"]
    assert filtered["forbidden_paths_filtered"] == ["<malformed-diff-header>"]


def test_filter_diff_output_handles_empty_stdout() -> None:
    raw = {"stdout": "", "returncode": 0}
    out = filter_diff_output(raw, is_forbidden=lambda _p: True)
    assert out is raw


def test_filter_diff_output_no_diff_header_returns_input() -> None:
    raw = {"stdout": "no diff in here\n", "returncode": 0}
    out = filter_diff_output(raw, is_forbidden=lambda _p: True)
    assert out is raw


def test_filter_status_output_drops_forbidden_rows() -> None:
    raw = {
        "stdout": " M src/main.py\n?? .env\n M README.md\n",
        "returncode": 0,
    }
    filtered = filter_status_output(
        raw, is_forbidden=lambda p: p == ".env"
    )
    assert ".env" not in filtered["stdout"]
    assert "src/main.py" in filtered["stdout"]
    assert "README.md" in filtered["stdout"]
    assert ".env" in filtered["forbidden_paths_filtered"]


def test_filter_status_output_handles_renames() -> None:
    raw = {
        "stdout": "R  README.md -> .env\n M src/main.py\n",
        "returncode": 0,
    }
    filtered = filter_status_output(
        raw, is_forbidden=lambda p: p == ".env"
    )
    assert ".env" not in filtered["stdout"]
    assert "src/main.py" in filtered["stdout"]


def test_filter_status_output_no_op_when_clean() -> None:
    raw = {"stdout": " M src/main.py\n", "returncode": 0}
    out = filter_status_output(raw, is_forbidden=lambda _p: False)
    assert "forbidden_paths_filtered" not in out
    assert out is raw


def test_filter_status_output_strips_quoted_paths() -> None:
    raw = {
        "stdout": ' M "with space.py"\n?? ".env"\n',
        "returncode": 0,
    }
    filtered = filter_status_output(
        raw, is_forbidden=lambda p: p == ".env"
    )
    assert ".env" not in filtered["stdout"]
    assert "with space.py" in filtered["stdout"]
