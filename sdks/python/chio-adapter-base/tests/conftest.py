"""Pytest configuration for chio-adapter-base.

Phase 1 ships no fixtures; the smoke test (``test_imports.py``) only
asserts that the public API surface imports cleanly. Phase 2 will add
shared fixtures (workspace tmpdir, sample receipt records, mock
subprocess) here as the per-primitive test files come online.
"""

from __future__ import annotations
