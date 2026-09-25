import copy
import json
from pathlib import Path

from chio.invariants import (
    canonicalize_json,
    sha256_hex_utf8,
    verify_http_receipt_with_trusted_signers,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "http-receipts.json").read_text())


def test_rust_http_records_verify_without_confusing_denial_with_authorization():
    results = [
        verify_http_receipt_with_trusted_signers(receipt, FIXTURE["trusted_signers"])
        for receipt in FIXTURE["receipts"]
    ]
    assert all(result["ok"] for result in results)
    assert [result["authorized"] for result in results] == [True, False]


def test_untrusted_receipt_signer_is_refused_even_when_signature_is_valid():
    result = verify_http_receipt_with_trusted_signers(FIXTURE["receipts"][0], ["ab" * 32])
    assert result["signature_valid"]
    assert not result["signer_trusted"]
    assert not result["ok"]


def test_tampered_status_fails_even_when_attacker_rehashes_id():
    receipt = copy.deepcopy(FIXTURE["receipts"][1])
    receipt["response_status"] = 200
    receipt["verdict"] = {"verdict": "allow"}
    receipt["id"] = sha256_hex_utf8(
        canonicalize_json(
            {key: value for key, value in receipt.items() if key not in {"signature", "id"}}
        )
    )
    result = verify_http_receipt_with_trusted_signers(receipt, FIXTURE["trusted_signers"])
    assert result["receipt_id_valid"]
    assert not result["signature_valid"]
    assert not result["authorized"]


def test_malformed_and_empty_trust_inputs_fail_closed():
    for receipt in [{}, {"kernel_key": 12}, dict(FIXTURE["receipts"][0], signature=None)]:
        assert not verify_http_receipt_with_trusted_signers(receipt, FIXTURE["trusted_signers"])[
            "ok"
        ]
    assert not verify_http_receipt_with_trusted_signers(FIXTURE["receipts"][0], [])["ok"]
