"""Native-history cache must not trust changed result bytes with an old proof."""
import copy
import io
import json
import threading
from types import SimpleNamespace

import pytest

from chio_hermes.gateway_transport import GatewayTransport


def test_changed_result_with_already_confirmed_proof_is_revalidated() -> None:
    transport = object.__new__(GatewayTransport)
    transport._lock = threading.Lock()
    transport._counter = 0
    transport._confirmed = set()
    transport.events = []
    transport.outcomes = {}
    transport.process = SimpleNamespace(stdin=io.StringIO())
    replies = iter([{"id": 1, "result": {"acknowledged": True}},
                    {"error": "received result differs from signed receipt"}])
    transport._read = lambda: next(replies)
    outcome = {"state": "completed", "evidence": "verified", "requestId": "original",
               "delivery": {"acknowledgement": "unchanged-proof"}, "result": {"text": "original bytes"}}

    def message(value):
        return [{"role": "tool", "tool_call_id": "native-call", "content": json.dumps(value)}]

    transport.receive_host_results(message(outcome))
    transport.receive_host_results(message(outcome))
    assert transport._counter == 1
    changed = copy.deepcopy(outcome)
    changed["result"]["text"] = "substituted after acknowledgement"
    with pytest.raises(ValueError, match="unresolved"):
        transport.receive_host_results(message(changed))
    requests = [json.loads(line) for line in transport.process.stdin.getvalue().splitlines()]
    assert len(requests) == 2
    assert requests[-1]["outcome"] == changed
    assert len(transport.events) == 1
