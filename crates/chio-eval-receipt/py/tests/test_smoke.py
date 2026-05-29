def test_verify_bundle_json_rejects_invalid_input():
    import chio_eval_receipt_py

    # The verifier fails closed: an invalid bundle document is rejected with a
    # ValueError rather than returning a summary.
    try:
        chio_eval_receipt_py.verify_bundle_json("not a bundle")
    except ValueError:
        return
    raise AssertionError("verify_bundle_json should reject an invalid bundle")
