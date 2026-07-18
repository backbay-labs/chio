import inspect

from chio_sdk import client as chio_client


def test_id_only_tool_call_default_fails_closed_signature():
    """The id-only default must run advisory evaluation then fail closed.

    The wrappers hold a capability id, not a signed capability token, so
    ``evaluate_tool_call`` cannot obtain an authoritative allow. It must
    delegate to the advisory route for its audit receipt and integrity check,
    never post an id-only stub to the token-requiring kernel-mediated
    ``/v1/evaluate`` route, and never return a permissive receipt that a
    wrapper could treat as "not denied".
    """
    signature = inspect.signature(chio_client.ChioClient.evaluate_tool_call)
    assert "capability_id" in signature.parameters
    assert "capability" not in signature.parameters

    eval_src = inspect.getsource(chio_client.ChioClient.evaluate_tool_call)
    assert "evaluate_tool_call_advisory" in eval_src
    assert '"/v1/evaluate"' not in eval_src
    # Fail closed: the body must raise a deny rather than return a receipt.
    assert "raise ChioDeniedError" in eval_src
    assert "return receipt" not in eval_src

    # The mediated route stays available as an explicit full-token helper.
    mediated_src = inspect.getsource(
        chio_client.ChioClient.evaluate_tool_call_mediated
    )
    assert '"/v1/evaluate"' in mediated_src


def test_id_only_tool_call_default_is_marked_noreturn():
    """The default never returns a value; it always raises to fail closed."""
    annotation = inspect.signature(
        chio_client.ChioClient.evaluate_tool_call
    ).return_annotation
    # ``from __future__ import annotations`` keeps this as the source string.
    assert annotation == "NoReturn"


def test_advisory_helper_remains_available_for_deliberate_callers():
    """The advisory helper stays a distinct entry point for observers."""
    assert hasattr(chio_client.ChioClient, "evaluate_tool_call_advisory")
    advisory_src = inspect.getsource(
        chio_client.ChioClient.evaluate_tool_call_advisory
    )
    # The advisory helper returns its non-authoritative receipt unchanged.
    assert "return receipt" in advisory_src
