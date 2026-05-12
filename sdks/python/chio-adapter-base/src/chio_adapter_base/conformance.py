"""Shared pytest helpers for sibling adapters.

Phase 1 ships an empty namespace. Phase 2 populates it with the actual
conformance assertions once the migration of the first sibling adapter
(planned: chio-langchain) reveals which assertions are reusable across
the family.

The intent of this module is so that an adapter test like
``chio-langchain/tests/test_conformance.py`` can do::

    from chio_adapter_base.conformance import (
        assert_redacts_secrets,
        assert_subprocess_capped,
    )

    def test_chio_langchain_conformance():
        assert_redacts_secrets(
            adapter_under_test=chio_langchain.tool.LangchainChioTool,
            secret_field="content",
        )

instead of every adapter re-deriving the same assertions.
"""

from __future__ import annotations

__all__: list[str] = []
