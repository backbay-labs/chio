from __future__ import annotations

from typing import Any

from chio.invariants import verify_signed_manifest


def priced_signed_manifest() -> dict[str, Any]:
    return {
        "manifest": {
            "schema": "chio.manifest.v1",
            "server_id": "srv-priced",
            "name": "Priced Server",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "greet",
                    "description": "Returns a greeting",
                    "input_schema": {"type": "object"},
                    "pricing": {
                        "pricing_model": "per_invocation",
                        "unit_price": {"units": 25, "currency": "USD"},
                        "billing_unit": "invocation",
                    },
                    "has_side_effects": False,
                }
            ],
            "public_key": "22" * 32,
        },
        "signature": "33" * 64,
        "signer_key": "11" * 32,
    }


def test_manifest_structure_does_not_include_embedded_public_key_validity() -> None:
    signed_manifest = priced_signed_manifest()
    signed_manifest["manifest"]["public_key"] = "demo-placeholder"

    verification = verify_signed_manifest(signed_manifest)

    assert verification["structure_valid"] is True
    assert verification["embedded_public_key_valid"] is False
    assert verification["embedded_public_key_matches_signer"] is False


def test_manifest_structure_rejects_empty_or_padded_identity_fields() -> None:
    cases = [
        ("server_id", ""),
        ("server_id", " srv-priced"),
        ("server_id", "srv-priced "),
        ("server_id", "srv\npriced"),
        ("name", ""),
        ("name", " Priced Server"),
        ("name", "Priced Server "),
        ("version", ""),
        ("version", " 1.0.0"),
        ("version", "1.0.0 "),
    ]
    for field, value in cases:
        signed_manifest = priced_signed_manifest()
        signed_manifest["manifest"][field] = value

        verification = verify_signed_manifest(signed_manifest)

        assert verification["structure_valid"] is False, f"{field} {value!r}"
        assert verification["signature_valid"] is False
        assert verification["embedded_public_key_valid"] is True


def test_manifest_structure_rejects_empty_or_padded_tool_names() -> None:
    for name in ["", " greet", "greet "]:
        signed_manifest = priced_signed_manifest()
        signed_manifest["manifest"]["tools"][0]["name"] = name

        assert verify_signed_manifest(signed_manifest)["structure_valid"] is False


def test_manifest_structure_rejects_non_object_tool_schemas() -> None:
    bad_input_schema = priced_signed_manifest()
    bad_input_schema["manifest"]["tools"][0]["input_schema"] = []
    assert verify_signed_manifest(bad_input_schema)["structure_valid"] is False

    bad_output_schema = priced_signed_manifest()
    bad_output_schema["manifest"]["tools"][0]["output_schema"] = "not an object"
    assert verify_signed_manifest(bad_output_schema)["structure_valid"] is False


def test_manifest_structure_rejects_malformed_pricing_metadata() -> None:
    cases = [
        (
            "per_invocation missing unit_price",
            {"pricing_model": "per_invocation", "billing_unit": "invocation"},
        ),
        (
            "per_unit missing billing_unit",
            {"pricing_model": "per_unit", "unit_price": {"units": 25, "currency": "USD"}},
        ),
        (
            "hybrid missing base_price",
            {
                "pricing_model": "hybrid",
                "unit_price": {"units": 25, "currency": "USD"},
                "billing_unit": "document",
            },
        ),
        (
            "padded billing_unit",
            {
                "pricing_model": "per_invocation",
                "unit_price": {"units": 25, "currency": "USD"},
                "billing_unit": " invocation",
            },
        ),
        (
            "invalid currency",
            {
                "pricing_model": "per_invocation",
                "unit_price": {"units": 25, "currency": "usd"},
                "billing_unit": "invocation",
            },
        ),
        (
            "units above u64 max",
            {
                "pricing_model": "per_invocation",
                "unit_price": {"units": 2**64, "currency": "USD"},
                "billing_unit": "invocation",
            },
        ),
    ]
    for label, pricing in cases:
        signed_manifest = priced_signed_manifest()
        signed_manifest["manifest"]["tools"][0]["pricing"] = pricing

        assert (
            verify_signed_manifest(signed_manifest)["structure_valid"] is False
        ), label


def test_manifest_structure_accepts_u64_max_pricing_units() -> None:
    signed_manifest = priced_signed_manifest()
    signed_manifest["manifest"]["tools"][0]["pricing"]["unit_price"]["units"] = 2**64 - 1

    assert verify_signed_manifest(signed_manifest)["structure_valid"] is True


def test_signed_manifest_envelope_rejects_unknown_top_level_fields() -> None:
    signed_manifest = priced_signed_manifest()
    signed_manifest["unsigned_policy_hint"] = {"allow": True}

    assert verify_signed_manifest(signed_manifest)["structure_valid"] is False


def test_manifest_structure_accepts_valid_required_permissions() -> None:
    signed_manifest = priced_signed_manifest()
    signed_manifest["manifest"]["required_permissions"] = {
        "read_paths": ["/tmp/in"],
        "write_paths": ["/tmp/out"],
        "network_hosts": ["api.example.com"],
        "environment_variables": ["TOKEN"],
    }

    verification = verify_signed_manifest(signed_manifest)

    assert verification["structure_valid"] is True
    assert verification["signature_valid"] is False
    assert verification["embedded_public_key_valid"] is True


def test_manifest_structure_rejects_invalid_required_permissions() -> None:
    cases = [
        ("read_paths", [""]),
        ("write_paths", [" /tmp/out"]),
        ("network_hosts", ["api.example.com "]),
        ("environment_variables", ["TOKEN", "TOKEN"]),
        ("read_paths", ["/tmp/in\nbad"]),
        ("read_paths", [123]),
    ]
    for field, values in cases:
        signed_manifest = priced_signed_manifest()
        signed_manifest["manifest"]["required_permissions"] = {field: values}

        verification = verify_signed_manifest(signed_manifest)

        assert verification["structure_valid"] is False, f"{field} {values!r}"
        assert verification["signature_valid"] is False
        assert verification["embedded_public_key_valid"] is True


def test_manifest_structure_rejects_malformed_required_permissions_object() -> None:
    unknown_field = priced_signed_manifest()
    unknown_field["manifest"]["required_permissions"] = {"unknown": ["/tmp"]}
    assert verify_signed_manifest(unknown_field)["structure_valid"] is False

    non_array_values = priced_signed_manifest()
    non_array_values["manifest"]["required_permissions"] = {"read_paths": "/tmp"}
    assert verify_signed_manifest(non_array_values)["structure_valid"] is False


def test_signed_manifest_verification_is_fail_soft_for_malformed_envelopes() -> None:
    cases = [
        {},
        {"manifest": None, "signature": "", "signer_key": ""},
    ]
    for signed_manifest in cases:
        verification = verify_signed_manifest(signed_manifest)

        assert verification["structure_valid"] is False
        assert verification["signature_valid"] is False
        assert verification["embedded_public_key_valid"] is False
        assert verification["embedded_public_key_matches_signer"] is False


def test_manifest_structure_rejects_missing_required_tool_fields_and_unknown_nested_fields() -> None:
    missing_description = priced_signed_manifest()
    del missing_description["manifest"]["tools"][0]["description"]
    assert verify_signed_manifest(missing_description)["structure_valid"] is False

    missing_side_effects = priced_signed_manifest()
    del missing_side_effects["manifest"]["tools"][0]["has_side_effects"]
    assert verify_signed_manifest(missing_side_effects)["structure_valid"] is False

    unknown_manifest_field = priced_signed_manifest()
    unknown_manifest_field["manifest"]["unsigned_policy_hint"] = True
    assert verify_signed_manifest(unknown_manifest_field)["structure_valid"] is False

    unknown_tool_field = priced_signed_manifest()
    unknown_tool_field["manifest"]["tools"][0]["annotations"] = {}
    assert verify_signed_manifest(unknown_tool_field)["structure_valid"] is False

    unknown_pricing_field = priced_signed_manifest()
    unknown_pricing_field["manifest"]["tools"][0]["pricing"]["experimental_discount"] = 10
    assert verify_signed_manifest(unknown_pricing_field)["structure_valid"] is False


def test_manifest_structure_validates_server_tools_and_latency_hint_values() -> None:
    valid = priced_signed_manifest()
    valid["manifest"]["server_tools"] = ["bash", "text_editor"]
    valid["manifest"]["tools"][0]["latency_hint"] = "fast"
    assert verify_signed_manifest(valid)["structure_valid"] is True

    duplicate_server_tool = priced_signed_manifest()
    duplicate_server_tool["manifest"]["server_tools"] = ["bash", "bash"]
    assert verify_signed_manifest(duplicate_server_tool)["structure_valid"] is False

    unknown_server_tool = priced_signed_manifest()
    unknown_server_tool["manifest"]["server_tools"] = ["database"]
    assert verify_signed_manifest(unknown_server_tool)["structure_valid"] is False

    invalid_latency_hint = priced_signed_manifest()
    invalid_latency_hint["manifest"]["tools"][0]["latency_hint"] = "immediate"
    assert verify_signed_manifest(invalid_latency_hint)["structure_valid"] is False
