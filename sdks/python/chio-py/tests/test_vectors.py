from __future__ import annotations

import json
import unittest
from pathlib import Path

from chio.invariants import (
    capability_body_canonical_json,
    canonicalize_json_string,
    parse_capability_json,
    parse_receipt_json,
    parse_signed_manifest_json,
    receipt_body_canonical_json,
    receipt_signing_body_canonical_json,
    sha256_hex_utf8,
    sign_json_string_ed25519,
    sign_utf8_message_ed25519,
    signed_manifest_body_canonical_json,
    verify_capability,
    verify_json_string_signature_ed25519,
    verify_receipt,
    verify_receipt_with_trusted_signers,
    verify_signed_manifest,
    verify_utf8_message_ed25519,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
VECTORS_ROOT = REPO_ROOT / "tests" / "bindings" / "vectors"


def load_vector(name: str) -> dict:
    return json.loads((VECTORS_ROOT / name / "v1.json").read_text())


class VectorTests(unittest.TestCase):
    def test_canonical_vectors(self) -> None:
        fixture = load_vector("canonical")
        for case in fixture["cases"]:
            self.assertEqual(
                canonicalize_json_string(case["input_json"]),
                case["canonical_json"],
                case["id"],
            )

    def test_hashing_vectors(self) -> None:
        fixture = load_vector("hashing")
        for case in fixture["cases"]:
            self.assertEqual(
                sha256_hex_utf8(case["input_utf8"]),
                case["sha256_hex"],
                case["id"],
            )

    def test_signing_vectors(self) -> None:
        fixture = load_vector("signing")
        signed_utf8 = sign_utf8_message_ed25519(
            fixture["utf8_cases"][0]["input_utf8"],
            fixture["signing_key_seed_hex"],
        )
        self.assertEqual(signed_utf8["public_key_hex"], fixture["utf8_cases"][0]["public_key_hex"])
        self.assertEqual(signed_utf8["signature_hex"], fixture["utf8_cases"][0]["signature_hex"])

        signed_json = sign_json_string_ed25519(
            fixture["json_cases"][0]["input_json"],
            fixture["signing_key_seed_hex"],
        )
        self.assertEqual(signed_json["canonical_json"], fixture["json_cases"][0]["canonical_json"])
        self.assertEqual(signed_json["public_key_hex"], fixture["json_cases"][0]["public_key_hex"])
        self.assertEqual(signed_json["signature_hex"], fixture["json_cases"][0]["signature_hex"])

        for case in fixture["utf8_cases"]:
            self.assertEqual(
                verify_utf8_message_ed25519(
                    case["input_utf8"],
                    case["public_key_hex"],
                    case["signature_hex"],
                ),
                case["expected_verify"],
                case["id"],
            )

        for case in fixture["json_cases"]:
            self.assertEqual(
                verify_json_string_signature_ed25519(
                    case["input_json"],
                    case["public_key_hex"],
                    case["signature_hex"],
                ),
                case["expected_verify"],
                case["id"],
            )

    def test_receipt_vectors(self) -> None:
        fixture = load_vector("receipt")
        for case in fixture["cases"]:
            receipt = parse_receipt_json(json.dumps(case["receipt"]))
            self.assertEqual(receipt_body_canonical_json(receipt), case["receipt_body_canonical_json"])
            self.assertEqual(verify_receipt(receipt), case["expected"], case["id"])

    def test_receipt_vectors_support_trusted_signers(self) -> None:
        fixture = load_vector("receipt")
        case = next(item for item in fixture["cases"] if item["id"] == "allow_receipt")
        receipt = parse_receipt_json(json.dumps(case["receipt"]))
        verification = verify_receipt_with_trusted_signers(receipt, [receipt["kernel_key"]])
        self.assertTrue(verification["signer_trusted"])
        self.assertTrue(verification["ok"])
        self.assertTrue(verification["authorized"])

    def test_receipt_semantics_ignore_legacy_metadata_payloads(self) -> None:
        fixture = load_vector("receipt")
        case = next(item for item in fixture["cases"] if item["id"] == "allow_receipt")
        receipt = parse_receipt_json(json.dumps(case["receipt"]))
        receipt["metadata"] = {
            "receipt_semantics": {
                "receiptKind": "trace_observation",
                "boundaryClass": "detect_only",
            }
        }
        verification = verify_receipt_with_trusted_signers(receipt, [receipt["kernel_key"]])
        self.assertEqual(verification["receipt_kind"], "mediated_decision")
        self.assertEqual(verification["boundary_class"], "prevent")
        self.assertFalse(verification["receipt_id_valid"])
        self.assertFalse(verification["signature_valid"])
        self.assertFalse(verification["authorized"])

    def test_receipt_signature_valid_fails_when_content_addressed_id_mismatches(self) -> None:
        fixture = load_vector("receipt")
        case = next(item for item in fixture["cases"] if item["id"] == "allow_receipt")
        receipt = parse_receipt_json(json.dumps(case["receipt"]))
        receipt["id"] = "0000000000000000000000000000000000000000000000000000000000000000"
        receipt["signature"] = sign_json_string_ed25519(
            receipt_signing_body_canonical_json(receipt),
            fixture["signing_key_seed_hex"],
        )["signature_hex"]
        verification = verify_receipt(receipt)
        self.assertFalse(verification["receipt_id_valid"])
        self.assertFalse(verification["signature_valid"])
        self.assertFalse(verification["ok"])

    def test_capability_vectors(self) -> None:
        fixture = load_vector("capability")
        for case in fixture["cases"]:
            capability = parse_capability_json(json.dumps(case["capability"]))
            self.assertEqual(
                capability_body_canonical_json(capability),
                case["capability_body_canonical_json"],
                case["id"],
            )
            self.assertEqual(
                verify_capability(capability, case["verify_at"]),
                case["expected"],
                case["id"],
            )

    def test_manifest_vectors(self) -> None:
        fixture = load_vector("manifest")
        for case in fixture["cases"]:
            signed_manifest = parse_signed_manifest_json(json.dumps(case["signed_manifest"]))
            self.assertEqual(
                signed_manifest_body_canonical_json(signed_manifest),
                case["manifest_body_canonical_json"],
                case["id"],
            )
            self.assertEqual(
                verify_signed_manifest(signed_manifest),
                case["expected"],
                case["id"],
            )


if __name__ == "__main__":
    unittest.main()
