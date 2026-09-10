#!/usr/bin/env python3
"""Check Python/Rust signature interoperability against an isolated Chio service.

This writes uniquely named capability snapshots. It checks signature and lineage
serialization, not application admission or scope-subset enforcement.
"""
from __future__ import annotations

import argparse
import copy
import json
import uuid

import httpx

from incident_network.capabilities import cap_body, delegate, gen_identity


def check_lineage(url: str, token: str) -> None:
    owner, child = gen_identity("owner"), gen_identity("child")
    grant = {
        "server_id": "regression",
        "tool_name": "read",
        "operations": ["invoke", "delegate"],
        "max_invocations": 3,
        "max_total_cost": {"units": 30, "currency": "USD"},
    }
    with httpx.Client(
        base_url=url, headers={"Authorization": "Bearer " + token}, timeout=15
    ) as client:
        response = client.post("/v1/capabilities/issue", json={
            "subjectPublicKey": owner.pk,
            "scope": {"grants": [grant]},
            "ttlSeconds": 120,
        })
        response.raise_for_status()
        parent = response.json()["capability"]
        scope = {
            "grants": [{
                **grant,
                "operations": ["invoke"],
                "constraints": [],
                "max_invocations": 1,
                "max_total_cost": {"units": 10, "currency": "USD"},
            }],
            "resource_grants": [],
            "prompt_grants": [],
        }
        capability = delegate(
            parent=parent, delegator=owner, delegatee=child, scope=scope,
            ttl=60, cap_id="lineage-é-" + uuid.uuid4().hex,
        )

        # Original failure: Python signs empty arrays that Rust omits on decode.
        malformed = copy.deepcopy(capability)
        malformed["id"] = "old-" + uuid.uuid4().hex
        malformed["scope"] = scope
        body = cap_body(malformed)
        body["scope"] = scope
        malformed["signature"] = owner.sign(body)
        response = client.post("/v1/lineage", json={
            "capability": malformed, "parentCapabilityId": parent["id"],
        })
        assert response.status_code >= 400, response.text
        assert "signature" in response.text.lower(), response.text

        response = client.post("/v1/lineage", json={
            "capability": capability, "parentCapabilityId": parent["id"],
        })
        assert response.is_success, response.text
        response = client.get("/v1/lineage/" + capability["id"])
        response.raise_for_status()
        serialized = json.dumps(response.json(), ensure_ascii=False)
        assert capability["id"] in serialized and parent["id"] in serialized
        assert "max_total_cost" in serialized and "max_invocations" in serialized

        # Changing a signed limit must fail native verification as well.
        changed = copy.deepcopy(capability)
        changed["scope"]["grants"][0]["max_total_cost"]["units"] = 11
        response = client.post("/v1/lineage", json={
            "capability": changed, "parentCapabilityId": parent["id"],
        })
        assert response.status_code >= 400, response.text
        assert "signature" in response.text.lower(), response.text

    print("PASS: original failure reproduced; UTF-8 delegated signature and "
          "bounded monetary fields retained; tampering refused")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    check_lineage(args.url, args.token)
