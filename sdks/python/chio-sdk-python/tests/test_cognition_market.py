from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

import chio_sdk.cognition_market as cognition_market
from chio_sdk.cognition_market import (
    CognitionMarketBuyer,
    CognitionMarketError,
    CognitionMarketSeller,
    PurchasedVerifiedFix,
    VerifiedFindingProof,
    _canonical_json,
    _request_id,
)


def buyer_profile(path: Path) -> Path:
    status_authority = {
        "authorityId": "status-operator",
        "keyEpoch": 1,
        "keyHex": "a" * 64,
        "revocationStatusRef": "local/revocations/status",
        "validFrom": 1,
        "validUntil": 2_000_000_000,
    }
    value = {
        "bearerToken": "buyer-secret",
        "endpoint": "http://operator.local",
        "market": {
            "statusFeedOperator": {
                "authority": status_authority,
                "feedId": "finding-status/local",
                "revokedFrom": None,
                "role": "finding_status_operator",
                "rotationPolicyRef": "local/rotation/status",
            },
            "statusFeedServiceBond": {
                "bond_id": "status-bond",
                "currency": "USD",
                "equivocation_slash_units": 100,
                "evidence_sha256": "b" * 64,
                "feed_id": "finding-status/local",
                "inclusion_sla_secs": 300,
                "locked_units": 100,
                "missed_inclusion_slash_units": 10,
                "operator_id": "status-operator",
                "valid_from": 1,
                "valid_until": 2_000_000_000,
            },
            "statusMaxEpochAgeSecs": 300,
        },
        "payer": "9" * 64,
        "payoutDestination": "0x" + "1" * 40,
        "principalId": "buyer-1",
        "schema": "chio.finding.buyer-client.v1",
        "signingSeed": "2" * 64,
    }
    path.write_bytes(_canonical_json(value))
    return path


def seller_profile(path: Path) -> Path:
    value = {
        "bearerToken": "seller-secret",
        "endpoint": "http://operator.local",
        "market": {"statusFeedOperator": {"feedId": "finding-status/local"}},
        "payoutDestination": "0x" + "3" * 40,
        "principalId": "seller-1",
        "schema": "chio.finding.seller-client.v1",
    }
    path.write_bytes(_canonical_json(value))
    return path


def test_purchase_request_identity_is_scoped_to_the_buyer() -> None:
    first_id, first = _request_id("a" * 64, 300, "USD", "1" * 64, 600)
    second_id, second = _request_id("a" * 64, 300, "USD", "2" * 64, 600)
    assert first_id != second_id
    assert first["payer"] == "1" * 64
    assert second["payer"] == "2" * 64


@pytest.mark.asyncio
async def test_buyer_runs_search_proof_status_and_purchase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = "a" * 64
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.headers["authorization"] == "Bearer buyer-secret"
        if request.url.path.endswith("/proof"):
            return httpx.Response(200, content=b'{"schema":"proof"}')
        if request.url.path.endswith(f"/purchase"):
            body = json.loads(request.content)
            assert body["schema"] == "chio.finding.purchase-request.v1"
            assert len(body["requestId"]) == 64
            assert body["payer"] == "9" * 64
            return httpx.Response(200, json={"verdict": "allow"})
        return httpx.Response(200, json={"count": 1, "results": []})

    def successful_status(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[0]
        assert isinstance(command, list)
        if command[1:3] == ["finding", "verify-bundle"]:
            assert "--purchase-request" in command
            assert "--purchase-result" in command
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=_canonical_json({"purchaseTerminalVerified": True}),
                stderr=b"",
            )
        assert command[1:3] == ["finding", "status"]
        assert kwargs["env"]["CHIO_CONTROL_TOKEN"] == "buyer-secret"
        authorization_path = Path(command[command.index("--operator-authorization") + 1])
        authorization = json.loads(authorization_path.read_bytes())
        assert authorization["operator"]["key"] == "a" * 64
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=_canonical_json(
                {"finding_id": finding_id, "proof_kind": "non_inclusion"}
            ),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", successful_status)

    buyer = CognitionMarketBuyer(
        buyer_profile(tmp_path / "buyer.json"),
        transport=httpx.MockTransport(handler),
    )
    try:
        assert (await buyer.search(topic_prefix="rust"))["count"] == 1
        assert await buyer.proof(finding_id) == b'{"schema":"proof"}'
        assert (await buyer.status(finding_id))["status"] == "live"
        verified = VerifiedFindingProof(finding_id, b"proof", {"findingId": finding_id})
        assert (
            await buyer.purchase(verified, max_price_units=300, deadline_secs=600)
        )["verdict"] == "allow"
    finally:
        await buyer.close()
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_buyer_purchase_rejects_an_unverified_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = "a" * 64

    def rejected_verification(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=_canonical_json({"purchaseTerminalVerified": False}),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", rejected_verification)
    buyer = CognitionMarketBuyer(
        buyer_profile(tmp_path / "buyer.json"),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"verdict": "allow"})
        ),
    )
    verified = VerifiedFindingProof(finding_id, b"proof", {"findingId": finding_id})
    try:
        with pytest.raises(CognitionMarketError, match="did not authorize"):
            await buyer.purchase(verified, max_price_units=300)
    finally:
        await buyer.close()


@pytest.mark.asyncio
async def test_proof_verification_is_a_rust_subprocess_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = "b" * 64
    profile = buyer_profile(tmp_path / "buyer.json")

    def successful_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["input"] == b"proof"
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=_canonical_json(
                {
                    "findingId": finding_id,
                    "requiredFacetsVerified": True,
                }
            ),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", successful_run)
    buyer = CognitionMarketBuyer(profile, transport=httpx.MockTransport(lambda _: httpx.Response(500)))
    try:
        verified = await buyer.verify_proof(b"proof")
        assert verified.finding_id == finding_id
    finally:
        await buyer.close()


@pytest.mark.asyncio
async def test_altered_proof_is_not_relabelled_as_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = buyer_profile(tmp_path / "buyer.json")

    def failed_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout=b"",
            stderr=b"signature mismatch",
        )

    monkeypatch.setattr(subprocess, "run", failed_run)
    buyer = CognitionMarketBuyer(profile, transport=httpx.MockTransport(lambda _: httpx.Response(500)))
    try:
        with pytest.raises(CognitionMarketError, match="Rust proof verification failed"):
            await buyer.verify_proof(b"altered")
    finally:
        await buyer.close()


@pytest.mark.asyncio
async def test_seller_uses_only_scoped_credential_for_package_and_admission(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer seller-secret"
        assert request.url.path == "/v1/findings/operator/verified-fixes"
        body = json.loads(request.content)
        assert body["repository"] == str(repository.resolve())
        assert len(body["requestId"]) == 64
        return httpx.Response(
            200,
            json={
                "activation": {"outcome": "activated"},
                "findingId": "c" * 64,
                "proofBundle": "/operator/proof.json",
                "requestId": body["requestId"],
                "schema": "chio.finding.verified-fix-submission-result.v1",
                "sellerPrincipal": "seller-1",
            },
        )

    seller = CognitionMarketSeller(
        seller_profile(tmp_path / "seller.json"),
        transport=httpx.MockTransport(handler),
    )
    try:
        package = await seller.package_verified_fix(
            repository=repository,
            base="base",
            candidate="candidate",
            tests=["./check.sh"],
            topic="rust/fix",
        )
        result = await seller.admit(package)
        assert result["findingId"] == "c" * 64
    finally:
        await seller.close()


@pytest.mark.asyncio
async def test_seller_retracts_with_the_same_scoped_credential(tmp_path: Path) -> None:
    finding_id = "d" * 64

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer seller-secret"
        assert request.url.path == "/v1/findings/operator/retractions"
        body = json.loads(request.content)
        assert body["findingId"] == finding_id
        assert len(body["requestId"]) == 64
        return httpx.Response(200, json={"findingId": finding_id, "status": "retracted"})

    seller = CognitionMarketSeller(
        seller_profile(tmp_path / "seller.json"),
        transport=httpx.MockTransport(handler),
    )
    try:
        assert (await seller.retract(finding_id))["status"] == "retracted"
    finally:
        await seller.close()


@pytest.mark.asyncio
async def test_seller_accepts_an_operator_side_repository_coordinate(tmp_path: Path) -> None:
    coordinate = "/srv/operator-repositories/remote-project"
    seller = CognitionMarketSeller(seller_profile(tmp_path / "seller.json"))
    try:
        package = await seller.package_verified_fix(
            repository=coordinate,
            base="base",
            candidate="candidate",
            tests=["./check.sh"],
            topic="rust/fix",
        )
        assert package["repository"] == coordinate
    finally:
        await seller.close()


@pytest.mark.asyncio
async def test_buyer_builds_and_files_challenge_with_scoped_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = "e" * 64
    payer_key = "f" * 64
    admission = {
        "backing_envelope_sha256": "1" * 64,
        "challenge_administration_pool": {
            "principal_id": "challenge-pool",
            "rail_destination": "0x" + "2" * 40,
        },
        "fee_schedule_envelope_sha256": "3" * 64,
        "listing_id": "listing-1",
        "profile_envelope_sha256": "4" * 64,
        "terms_envelope_sha256": "5" * 64,
    }
    proof = {
        "bundle": {
            "admission": {"body": admission, "signature": "admission-signature"},
            "finding": {"evidence_checkpoint_ref": "committed-checkpoint-7"},
            "feeSchedule": {"body": {"disputeFee": {"currency": "USD", "units": 10}}},
            "marketTerms": {
                "body": {
                    "challenge_bond_limits": [
                        {
                            "guarantee_class": "deterministic_replay",
                            "min_bond": {"currency": "USD", "units": 10},
                        }
                    ]
                }
            },
        },
        "evidenceCheckpoint": {"body": {"checkpoint_seq": 7}},
        "evidenceReceipts": [{"receipt": {"id": "evidence-1"}}],
    }
    purchase_record = {"body": {"purchase_key": "purchase-1"}, "signature": "purchase"}
    purchase = {
        "deliveryReceipt": {"id": "delivery-1"},
        "payer": "buyer-1",
        "payerKey": payer_key,
        "purchaseRecord": purchase_record,
    }
    _, request = _request_id(finding_id, 300, "USD", "9" * 64, 3600)
    purchased = PurchasedVerifiedFix(
        finding_id=finding_id,
        repository="https://example.com/repo.git",
        base_revision="base",
        candidate_revision="candidate",
        patch="diff --git a/file b/file\n",
        request=request,
        purchase=purchase,
    )

    def successful_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[0]
        assert isinstance(command, list)
        if command[1:3] == ["finding", "verify-bundle"]:
            assert "--purchase-request" in command
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=_canonical_json({"purchaseTerminalVerified": True}),
                stderr=b"",
            )
        assert command[1:3] == ["finding", "challenge"]
        assert kwargs["env"]["CHIO_CONTROL_TOKEN"] == "buyer-secret"
        key_path = Path(command[command.index("--challenger-key") + 1])
        evidence_path = Path(command[command.index("--evidence") + 1])
        assert key_path.read_text(encoding="ascii") == "2" * 64
        assert os.stat(key_path).st_mode & 0o077 == 0
        evidence = json.loads(evidence_path.read_bytes())
        assert evidence["filed_at"] == 1_800_000_000
        assert evidence["authorization"]["buyer_submission"]["challenger"] == payer_key
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=_canonical_json({"challengeId": "6" * 64}),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", successful_run)
    buyer = CognitionMarketBuyer(
        buyer_profile(tmp_path / "buyer.json"),
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    )
    try:
        verified = VerifiedFindingProof(finding_id, _canonical_json(proof), {"findingId": finding_id})
        result = await buyer.challenge_evidence_invalid(
            verified,
            purchased,
            filed_at=1_800_000_000,
        )
        assert result["challengeId"] == "6" * 64
    finally:
        await buyer.close()


def test_profile_rejects_missing_market_pins(tmp_path: Path) -> None:
    path = tmp_path / "buyer.json"
    path.write_bytes(
        _canonical_json(
            {
                "bearerToken": "buyer-secret",
                "endpoint": "http://operator.local",
                "market": {},
                "payer": "9" * 64,
                "payoutDestination": "0x" + "1" * 40,
                "principalId": "buyer-1",
                "schema": "chio.finding.buyer-client.v1",
                "signingSeed": "2" * 64,
            }
        )
    )
    with pytest.raises(CognitionMarketError, match="status feed pin"):
        CognitionMarketBuyer(path)


def test_profile_rejects_ephemeral_operator_port(tmp_path: Path) -> None:
    path = buyer_profile(tmp_path / "buyer.json")
    value = json.loads(path.read_bytes())
    value["endpoint"] = "http://127.0.0.1:0"
    path.write_bytes(_canonical_json(value))
    with pytest.raises(CognitionMarketError, match="endpoint is invalid"):
        CognitionMarketBuyer(path)


@pytest.mark.asyncio
async def test_buyer_returns_patch_without_applying_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = "7" * 64
    payload = {
        "baseRevision": "base",
        "baseline": [{"exitCode": 1}],
        "candidate": [{"exitCode": 0}],
        "candidateRevision": "candidate",
        "patch": "diff --git a/example.py b/example.py\n",
        "repository": "/srv/example",
        "schema": "chio.finding.verified-fix-payload.v1",
    }

    payload_b64 = base64.b64encode(_canonical_json(payload)).decode("ascii")
    commitment = hashlib.sha256(
        _canonical_json(
            {
                "media_type": "application/vnd.chio.verified-fix+json",
                "payload_b64": payload_b64,
            }
        )
    ).hexdigest()
    proof = _canonical_json(
        {"bundle": {"finding": {"payload_sha256": commitment}}}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/purchase")
        return httpx.Response(
            200,
            json={
                "findingId": finding_id,
                "output": {
                    "mediaType": "application/vnd.chio.verified-fix+json",
                    "payloadB64": payload_b64,
                },
                "settlement": "captured",
                "verdict": "allow",
            },
        )

    def successful_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        command = args[0]
        assert isinstance(command, list)
        assert "--purchase-request" in command
        assert "--purchase-result" in command
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=_canonical_json({"purchaseTerminalVerified": True}),
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", successful_run)

    buyer = CognitionMarketBuyer(
        buyer_profile(tmp_path / "buyer.json"),
        transport=httpx.MockTransport(handler),
    )
    try:
        verified = VerifiedFindingProof(finding_id, proof, {"findingId": finding_id})
        purchased = await buyer.purchase_verified_fix(verified, max_price_units=300)
        assert purchased.patch == payload["patch"]
        assert purchased.base_revision == "base"
        assert purchased.request["payer"] == "9" * 64
    finally:
        await buyer.close()


def test_seller_profile_rejects_a_market_signing_seed(tmp_path: Path) -> None:
    path = seller_profile(tmp_path / "seller.json")
    value = json.loads(path.read_bytes())
    value["signingSeed"] = "4" * 64
    path.write_bytes(_canonical_json(value))
    with pytest.raises(CognitionMarketError, match="must not contain"):
        CognitionMarketSeller(path)


@pytest.mark.asyncio
async def test_seller_rejects_price_above_operator_exposure(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    seller = CognitionMarketSeller(seller_profile(tmp_path / "seller.json"))
    try:
        with pytest.raises(CognitionMarketError, match="sale exposure"):
            await seller.package_verified_fix(
                repository=repository,
                base="base",
                candidate="candidate",
                tests=["./check.sh"],
                topic="rust/fix",
                price=451,
            )
    finally:
        await seller.close()


@pytest.mark.asyncio
async def test_buyer_stops_streaming_an_oversized_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding_id = "8" * 64
    chunks_read = 0

    class ChunkedResponse(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            nonlocal chunks_read
            for chunk in (b"123456", b"789"):
                chunks_read += 1
                yield chunk

    monkeypatch.setattr(cognition_market, "PROOF_RESPONSE_MAX_BYTES", 8)
    buyer = CognitionMarketBuyer(
        buyer_profile(tmp_path / "buyer.json"),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, stream=ChunkedResponse())
        ),
    )
    try:
        with pytest.raises(CognitionMarketError, match="exceeds the SDK size bound"):
            await buyer.proof(finding_id)
    finally:
        await buyer.close()
    assert chunks_read == 2


@pytest.mark.asyncio
async def test_buyer_applies_an_absolute_stream_deadline(tmp_path: Path) -> None:
    finding_id = "7" * 64

    class SlowDripResponse(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            for _ in range(3):
                await asyncio.sleep(0.04)
                yield b"x"

    buyer = CognitionMarketBuyer(
        buyer_profile(tmp_path / "buyer.json"),
        timeout=0.08,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, stream=SlowDripResponse())
        ),
    )
    try:
        with pytest.raises(CognitionMarketError, match="absolute request deadline"):
            await buyer.proof(finding_id)
    finally:
        await buyer.close()
