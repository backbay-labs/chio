"""Single-operator cognition-market buyer and seller clients.

Cryptographic proof verification is delegated to the installed Rust `chio`
binary. This module never upgrades a local JSON or digest check into a claim of
full Finding verification.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

BUYER_SCHEMA = "chio.finding.buyer-client.v1"
SELLER_SCHEMA = "chio.finding.seller-client.v1"
PURCHASE_SCHEMA = "chio.finding.purchase-request.v1"
VERIFIED_FIX_SUBMISSION_SCHEMA = "chio.finding.verified-fix-submission.v1"
PURCHASE_DOMAIN = b"chio.finding.public-purchase-request.v1\0"
VERIFIED_FIX_SUBMISSION_DOMAIN = b"chio.finding.verified-fix-submission-id.v1\0"
VOLUNTARY_RETRACTION_DOMAIN = b"chio.finding.voluntary-retraction-request-id.v1\0"
VERIFIED_FIX_PAYLOAD_SCHEMA = "chio.finding.verified-fix-payload.v1"
VERIFIED_FIX_MEDIA_TYPE = "application/vnd.chio.verified-fix+json"


class CognitionMarketError(RuntimeError):
    """A fail-closed market transport, profile, or verification error."""


@dataclass(frozen=True)
class VerifiedFindingProof:
    """Proof bytes accepted by the Rust reference verifier."""

    finding_id: str
    proof: bytes
    verification: dict[str, Any]


@dataclass(frozen=True)
class PurchasedVerifiedFix:
    """Verified patch payload returned without applying it to a workspace."""

    finding_id: str
    repository: str
    base_revision: str
    candidate_revision: str
    patch: str
    purchase: dict[str, Any]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _load_profile(path: str | Path, schema: str) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    if not raw or len(raw) > 1024 * 1024:
        raise CognitionMarketError("client profile is empty or oversized")
    try:
        profile = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CognitionMarketError("client profile is not valid JSON") from error
    if not isinstance(profile, dict) or profile.get("schema") != schema:
        raise CognitionMarketError("client profile schema is unsupported")
    if _canonical_json(profile) != raw:
        raise CognitionMarketError("client profile is not strict canonical JSON")
    endpoint = profile.get("endpoint")
    token = profile.get("bearerToken")
    if not isinstance(endpoint, str):
        raise CognitionMarketError("client profile endpoint is invalid")
    parsed_endpoint = urlsplit(endpoint)
    if (
        parsed_endpoint.scheme != "http"
        or not parsed_endpoint.hostname
        or parsed_endpoint.username is not None
        or parsed_endpoint.password is not None
        or parsed_endpoint.query
        or parsed_endpoint.fragment
        or parsed_endpoint.path not in ("", "/")
    ):
        raise CognitionMarketError("client profile endpoint is invalid")
    if not isinstance(token, str) or not token or token.strip() != token or len(token) > 4096:
        raise CognitionMarketError("client profile bearer token is invalid")
    principal = profile.get("principalId")
    seed = profile.get("signingSeed")
    payout = profile.get("payoutDestination")
    market = profile.get("market")
    if not isinstance(principal, str) or not principal or principal.strip() != principal:
        raise CognitionMarketError("client profile principal is invalid")
    if not isinstance(seed, str) or len(seed) != 64 or any(
        character not in "0123456789abcdef" for character in seed
    ):
        raise CognitionMarketError("client profile signing seed is invalid")
    if not isinstance(payout, str) or len(payout) != 42 or not payout.startswith("0x") or any(
        character not in "0123456789abcdef" for character in payout[2:]
    ):
        raise CognitionMarketError("client profile payout destination is invalid")
    if not isinstance(market, dict):
        raise CognitionMarketError("client profile market pin is invalid")
    status_operator = market.get("statusFeedOperator")
    if not isinstance(status_operator, dict):
        raise CognitionMarketError("client profile status feed pin is invalid")
    feed_id = status_operator.get("feedId")
    if not isinstance(feed_id, str) or not feed_id or feed_id.strip() != feed_id:
        raise CognitionMarketError("client profile status feed pin is invalid")
    return profile


def _request_id(
    finding_id: str,
    max_price_units: int,
    currency: str,
    payer: str | None,
    deadline_secs: int | None,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(max_price_units, int) or isinstance(max_price_units, bool) or max_price_units <= 0:
        raise CognitionMarketError("max_price_units must be a positive integer")
    if not isinstance(currency, str) or not currency or len(currency) > 16:
        raise CognitionMarketError("currency is invalid")
    identity: dict[str, Any] = {
        "findingId": finding_id,
        "maxPrice": {"currency": currency, "units": max_price_units},
        "payer": payer,
        "schema": PURCHASE_SCHEMA,
        "deadlineSecs": deadline_secs,
    }
    request_id = hashlib.sha256(PURCHASE_DOMAIN + _canonical_json(identity)).hexdigest()
    request = {key: value for key, value in identity.items() if value is not None}
    request["requestId"] = request_id
    return request_id, request


class CognitionMarketBuyer:
    """Buyer workflow over one scoped client credential."""

    def __init__(
        self,
        profile_path: str | Path,
        *,
        chio_binary: str | Path = "chio",
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.profile_path = Path(profile_path)
        self.profile = _load_profile(self.profile_path, BUYER_SCHEMA)
        self.chio_binary = str(chio_binary)
        self._client = httpx.AsyncClient(
            base_url=self.profile["endpoint"].rstrip("/"),
            headers={"authorization": f"Bearer {self.profile['bearerToken']}"},
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> CognitionMarketBuyer:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def search(
        self,
        *,
        topic_prefix: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str | int] = {"limit": limit}
        if topic_prefix is not None:
            params["topicPrefix"] = topic_prefix
        if cursor is not None:
            params["cursor"] = cursor
        return await self._json_request("GET", "/v1/findings/search", params=params)

    async def proof(self, finding_id: str) -> bytes:
        _require_hex64(finding_id, "finding_id")
        response = await self._client.get(f"/v1/findings/{finding_id}/proof")
        self._raise_for_status(response)
        if not response.content or len(response.content) > 24 * 1024 * 1024:
            raise CognitionMarketError("proof bundle is empty or exceeds the SDK size bound")
        return response.content

    async def verify_proof(self, proof: bytes) -> VerifiedFindingProof:
        if not proof or len(proof) > 24 * 1024 * 1024:
            raise CognitionMarketError("proof bundle is empty or oversized")
        command = [
            self.chio_binary,
            "finding",
            "verify-bundle",
            "--profile",
            str(self.profile_path),
            "--input",
            "-",
            "--json",
        ]

        def run() -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                command,
                input=proof,
                capture_output=True,
                check=False,
                timeout=60,
            )

        completed = await asyncio.to_thread(run)
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").strip()
            raise CognitionMarketError(f"Rust proof verification failed: {message}")
        try:
            report = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CognitionMarketError("Rust verifier returned invalid JSON") from error
        finding_id = report.get("findingId")
        if not isinstance(finding_id, str):
            raise CognitionMarketError("Rust verifier omitted the Finding id")
        return VerifiedFindingProof(finding_id=finding_id, proof=proof, verification=report)

    async def verified_proof(self, finding_id: str) -> VerifiedFindingProof:
        verified = await self.verify_proof(await self.proof(finding_id))
        if verified.finding_id != finding_id:
            raise CognitionMarketError("verified proof names a different Finding")
        return verified

    async def purchase(
        self,
        verified: VerifiedFindingProof,
        *,
        max_price_units: int,
        currency: str = "USD",
        deadline_secs: int | None = 3600,
    ) -> dict[str, Any]:
        _, request = _request_id(
            verified.finding_id,
            max_price_units,
            currency,
            None,
            deadline_secs,
        )
        return await self._json_request(
            "POST",
            f"/v1/findings/{verified.finding_id}/purchase",
            content=_canonical_json(request),
            headers={"content-type": "application/json"},
        )

    async def purchase_verified_fix(
        self,
        verified: VerifiedFindingProof,
        *,
        max_price_units: int,
        currency: str = "USD",
        deadline_secs: int | None = 3600,
    ) -> PurchasedVerifiedFix:
        """Purchase and decode a verified patch without applying it."""
        purchase = await self.purchase(
            verified,
            max_price_units=max_price_units,
            currency=currency,
            deadline_secs=deadline_secs,
        )
        return _purchased_verified_fix(verified, purchase)

    async def status(self, finding_id: str) -> dict[str, Any]:
        _require_hex64(finding_id, "finding_id")
        feed = self.profile.get("market", {}).get("statusFeedOperator", {}).get("feedId")
        if not isinstance(feed, str) or not feed:
            raise CognitionMarketError("client profile has no status feed id")
        path = f"/v1/findings/status/{quote(feed, safe='')}/proof/{finding_id}"
        return await self._json_request("GET", path)

    async def challenge(self, finding_id: str, signed_challenge: bytes) -> dict[str, Any]:
        _require_hex64(finding_id, "finding_id")
        if not signed_challenge or len(signed_challenge) > 1024 * 1024:
            raise CognitionMarketError("signed challenge is empty or oversized")
        return await self._json_request(
            "POST",
            f"/v1/findings/{finding_id}/challenges",
            content=signed_challenge,
            headers={"content-type": "application/json"},
        )

    async def challenge_evidence_invalid(
        self,
        verified: VerifiedFindingProof,
        purchase_result: dict[str, Any],
        *,
        filed_at: int | None = None,
    ) -> dict[str, Any]:
        """File an evidence-invalid challenge from one verified proof and purchase."""
        evidence = _evidence_invalid_document(
            self.profile,
            verified,
            purchase_result,
            filed_at=filed_at or int(time.time()),
        )

        def run() -> subprocess.CompletedProcess[bytes]:
            with tempfile.TemporaryDirectory(prefix="chio-market-challenge-") as directory:
                root = Path(directory)
                evidence_path = root / "evidence.json"
                key_path = root / "challenger.seed"
                evidence_path.write_bytes(_canonical_json(evidence))
                key_path.write_text(self.profile["signingSeed"], encoding="ascii")
                key_path.chmod(0o600)
                environment = dict(__import__("os").environ)
                environment["CHIO_CONTROL_TOKEN"] = self.profile["bearerToken"]
                return subprocess.run(
                    [
                        self.chio_binary,
                        "finding",
                        "challenge",
                        "--finding",
                        verified.finding_id,
                        "--class",
                        "evidence-invalid",
                        "--evidence",
                        str(evidence_path),
                        "--challenger-key",
                        str(key_path),
                        "--control-url",
                        self.profile["endpoint"],
                        "--json",
                    ],
                    capture_output=True,
                    check=False,
                    timeout=60,
                    env=environment,
                )

        completed = await asyncio.to_thread(run)
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").strip()
            raise CognitionMarketError(f"challenge filing failed: {message}")
        try:
            value = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CognitionMarketError("challenge command returned invalid JSON") from error
        if not isinstance(value, dict):
            raise CognitionMarketError("challenge command response is not an object")
        return value

    async def _json_request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = await self._client.request(method, path, **kwargs)
        self._raise_for_status(response)
        try:
            value = response.json()
        except json.JSONDecodeError as error:
            raise CognitionMarketError("operator returned invalid JSON") from error
        if not isinstance(value, dict):
            raise CognitionMarketError("operator JSON response is not an object")
        return value

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.is_success:
            return
        body = response.text[:4096]
        raise CognitionMarketError(f"operator returned HTTP {response.status_code}: {body}")


class CognitionMarketSeller:
    """Seller workflow over one admission-only credential."""

    def __init__(
        self,
        credential_path: str | Path,
        *,
        timeout: float = 300.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.credential = _load_profile(credential_path, SELLER_SCHEMA)
        self._client = httpx.AsyncClient(
            base_url=self.credential["endpoint"].rstrip("/"),
            headers={"authorization": f"Bearer {self.credential['bearerToken']}"},
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> CognitionMarketSeller:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def package_verified_fix(
        self,
        *,
        repository: str | Path,
        base: str,
        candidate: str,
        tests: list[str],
        topic: str,
        price: int = 300,
        output: str | Path | None = None,
    ) -> dict[str, Any]:
        if output is not None:
            raise CognitionMarketError(
                "scoped seller packages are operator-owned and do not accept a local output path"
            )
        repository_path = str(Path(repository).resolve(strict=True))
        identity: dict[str, Any] = {
            "baseRevision": base,
            "candidateRevision": candidate,
            "priceUnits": price,
            "repository": repository_path,
            "schema": VERIFIED_FIX_SUBMISSION_SCHEMA,
            "tests": tests,
            "topic": topic,
        }
        request_id = hashlib.sha256(
            VERIFIED_FIX_SUBMISSION_DOMAIN + _canonical_json(identity)
        ).hexdigest()
        return {**identity, "requestId": request_id}

    async def admit(self, package: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post(
            "/v1/findings/operator/verified-fixes",
            content=_canonical_json(package),
            headers={"content-type": "application/json"},
        )
        CognitionMarketBuyer._raise_for_status(response)
        try:
            value = response.json()
        except json.JSONDecodeError as error:
            raise CognitionMarketError("operator returned invalid JSON") from error
        if not isinstance(value, dict):
            raise CognitionMarketError("operator JSON response is not an object")
        return value

    async def retract(self, finding_id: str) -> dict[str, Any]:
        _require_hex64(finding_id, "finding_id")
        request = {
            "findingId": finding_id,
            "requestId": hashlib.sha256(
                VOLUNTARY_RETRACTION_DOMAIN + finding_id.encode("ascii")
            ).hexdigest(),
            "schema": "chio.finding.voluntary-retraction-request.v1",
        }
        response = await self._client.post(
            "/v1/findings/operator/retractions",
            content=_canonical_json(request),
            headers={"content-type": "application/json"},
        )
        CognitionMarketBuyer._raise_for_status(response)
        try:
            value = response.json()
        except json.JSONDecodeError as error:
            raise CognitionMarketError("operator returned invalid JSON") from error
        if not isinstance(value, dict):
            raise CognitionMarketError("operator JSON response is not an object")
        return value


def _require_hex64(value: str, field: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise CognitionMarketError(f"{field} must be canonical lowercase 64-hex")


def _purchased_verified_fix(
    verified: VerifiedFindingProof,
    purchase: dict[str, Any],
) -> PurchasedVerifiedFix:
    if purchase.get("findingId") != verified.finding_id:
        raise CognitionMarketError("purchase result names a different Finding")
    if purchase.get("verdict") != "allow" or purchase.get("settlement") != "captured":
        raise CognitionMarketError("purchase did not return a captured allow terminal")
    output = purchase.get("output")
    if not isinstance(output, dict) or output.get("mediaType") != VERIFIED_FIX_MEDIA_TYPE:
        raise CognitionMarketError("purchase did not return a verified-fix payload")
    encoded = output.get("payloadB64")
    if not isinstance(encoded, str) or not encoded:
        raise CognitionMarketError("verified-fix payload is missing")
    try:
        raw = base64.b64decode(encoded, validate=True)
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CognitionMarketError("verified-fix payload is invalid") from error
    if not isinstance(payload, dict) or payload.get("schema") != VERIFIED_FIX_PAYLOAD_SCHEMA:
        raise CognitionMarketError("verified-fix payload schema is unsupported")
    required = ("repository", "baseRevision", "candidateRevision", "patch")
    if any(not isinstance(payload.get(field), str) or not payload[field] for field in required):
        raise CognitionMarketError("verified-fix payload is incomplete")
    if payload["baseRevision"] == payload["candidateRevision"]:
        raise CognitionMarketError("verified-fix payload does not change a revision")
    return PurchasedVerifiedFix(
        finding_id=verified.finding_id,
        repository=payload["repository"],
        base_revision=payload["baseRevision"],
        candidate_revision=payload["candidateRevision"],
        patch=payload["patch"],
        purchase=purchase,
    )


def _evidence_invalid_document(
    profile: dict[str, Any],
    verified: VerifiedFindingProof,
    purchase: dict[str, Any],
    *,
    filed_at: int,
) -> dict[str, Any]:
    try:
        proof = json.loads(verified.proof)
        bundle = proof["bundle"]
        admission = bundle["admission"]["body"]
        schedule = bundle["feeSchedule"]["body"]
        terms = bundle["marketTerms"]["body"]
        evidence_receipt = proof["evidenceReceipts"][0]["receipt"]
        checkpoint_body = proof["evidenceCheckpoint"]["body"]
        delivery = purchase["deliveryReceipt"]
        purchase_record = purchase["purchaseRecord"]
        purchase_body = purchase_record["body"]
        payer_key = purchase["payerKey"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        raise CognitionMarketError(
            "proof or purchase result lacks challenge evidence"
        ) from error
    if payer_key != _public_key_from_profile_purchase(profile, purchase):
        raise CognitionMarketError("purchase payer does not match the scoped buyer")
    checkpoint_sha256 = hashlib.sha256(_canonical_json(checkpoint_body)).hexdigest()
    checkpoint_ref = f"checkpoint:{checkpoint_body['checkpoint_seq']}"
    purchase_digest = hashlib.sha256(_canonical_json(purchase_record)).hexdigest()
    fee_schedule_digest = admission["fee_schedule_envelope_sha256"]
    challenge_pool = admission["challenge_administration_pool"]
    bond = next(
        item
        for item in terms["challenge_bond_limits"]
        if item["guarantee_class"] == "deterministic_replay"
    )["min_bond"]
    lock_id = hashlib.sha256(
        b"chio.finding.sdk-dispute-lock.v1\0"
        + verified.finding_id.encode("ascii")
        + purchase_body["purchase_key"].encode("ascii")
    ).hexdigest()
    return {
        "affected_deliveries": [
            {
                "checkpoint_ref": checkpoint_ref,
                "checkpoint_sha256": checkpoint_sha256,
                "receipt_id": delivery["id"],
                "receipt_sha256": hashlib.sha256(_canonical_json(delivery)).hexdigest(),
            }
        ],
        "authorization": {
            "buyer_submission": {
                "challenger": payer_key,
                "dispute_fee_terminal": {
                    "amount": schedule["disputeFee"],
                    "beneficiary_pool_principal_id": challenge_pool["principal_id"],
                    "event": "challenge_filing",
                    "fee_schedule_envelope_sha256": fee_schedule_digest,
                    "payer": payer_key,
                    "rail_destination": challenge_pool["rail_destination"],
                },
                "dispute_lock_ref": {
                    "amount": bond,
                    "class": "dispute",
                    "expiry": filed_at + 600,
                    "fee_schedule_envelope_sha256": fee_schedule_digest,
                    "lock_id": lock_id,
                },
                "standing": {
                    "finalized_purchase": {
                        "purchase_key": purchase_body["purchase_key"],
                        "purchase_record_envelope_sha256": purchase_digest,
                    }
                },
            }
        },
        "evidence": {
            "evidence_invalid": {
                "challenged_checkpoint_ref": {
                    "checkpoint_ref": checkpoint_ref,
                    "checkpoint_sha256": checkpoint_sha256,
                },
                "challenged_evidence_receipt_refs": [
                    {
                        "receipt_id": evidence_receipt["id"],
                        "receipt_sha256": hashlib.sha256(
                            _canonical_json(evidence_receipt)
                        ).hexdigest(),
                    }
                ],
                "purchase_record_envelope_sha256": purchase_digest,
            }
        },
        "filed_at": filed_at,
        "listing": {
            "backing_envelope_sha256": admission["backing_envelope_sha256"],
            "listing_id": admission["listing_id"],
            "profile_envelope_sha256": admission["profile_envelope_sha256"],
            "terms_envelope_sha256": admission["terms_envelope_sha256"],
            "venue_admission_envelope_sha256": hashlib.sha256(
                _canonical_json(bundle["admission"])
            ).hexdigest(),
        },
    }


def _public_key_from_profile_purchase(
    profile: dict[str, Any], purchase: dict[str, Any]
) -> str:
    principal = profile.get("principalId")
    if purchase.get("payer") != principal and purchase.get("payer") != purchase.get("payerKey"):
        raise CognitionMarketError("purchase principal is not the scoped buyer")
    payer_key = purchase.get("payerKey")
    if not isinstance(payer_key, str):
        raise CognitionMarketError("purchase result omitted payerKey")
    return payer_key
