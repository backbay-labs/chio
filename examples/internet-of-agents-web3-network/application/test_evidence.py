"""Adversarial artifact checks against an actual completed application capture."""

import copy
import os
import unittest
from pathlib import Path

from evidence import read
from verify import verify


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Qualification supplies the selected host key separately from the file.
        cls.capture = read(Path(os.environ["WORK_ORDER_CAPTURE"]))
        cls.key = os.environ["WORK_ORDER_AUDITOR_KEY"]

    def test_complete_capture(self):
        self.assertGreater(verify(self.capture, self.key)["verified_operations"], 30)

    def test_tampered_request_result_identity_order_and_summary_are_refused(self):
        for mutation in [
            "input",
            "output",
            "signer",
            "omitted",
            "reordered",
            "balance",
            "settlement",
            "audit",
            "capability",
            "contract_source",
            "order",
            "trust_list",
        ]:
            with self.subTest(mutation=mutation):
                capture = copy.deepcopy(self.capture)
                if mutation == "input":
                    capture["operations"][0]["request"]["arguments"]["data"]["order_id"] = (
                        "substituted"
                    )
                elif mutation == "output":
                    capture["operations"][0]["result"]["output"]["complete"] = False
                elif mutation == "signer":
                    capture["operations"][0]["result"]["receipt"]["kernel_key"] = "01" * 32
                elif mutation == "omitted":
                    capture["operations"].pop(1)
                elif mutation == "reordered":
                    capture["operations"][0], capture["operations"][1] = (
                        capture["operations"][1],
                        capture["operations"][0],
                    )
                elif mutation == "balance":
                    capture["balances"]["beneficiary_balance"] = "999999"
                elif mutation == "settlement":
                    capture["full_release_receipt"] = capture["operations"][0]["result"]["receipt"][
                        "id"
                    ]
                elif mutation == "capability":
                    capture["capabilities"]["root"]["scope"]["grants"][0]["max_invocations"] = 9000
                elif mutation == "contract_source":
                    capture["chain_source_hash"] = "00" * 32
                elif mutation == "order":
                    capture["orders"].reverse()
                elif mutation == "trust_list":
                    capture["trusted_kernels"]["atlas"] = "01" * 32
                else:
                    capture["audit"]["output"]["refused"] = 0
                with self.assertRaises((ValueError, KeyError)):
                    verify(capture, self.key)

    def test_capture_cannot_choose_a_new_auditor(self):
        with self.assertRaises(ValueError):
            verify(self.capture, "01" * 32)
