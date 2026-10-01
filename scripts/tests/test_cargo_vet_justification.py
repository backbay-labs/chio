import importlib.util
from pathlib import Path
import subprocess
import unittest

spec = importlib.util.spec_from_file_location(
    "justification", Path(__file__).parents[1] / "check-cargo-vet-justification.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReviewerPermission(unittest.TestCase):
    def evaluate(self, permission, association="CONTRIBUTOR", body=None, location="issues"):
        comment = {
            "id": 42, "author_association": association,
            "user": {"login": "reviewer"},
            "body": body if body is not None else gate.PREFIX + " bounded change",
        }

        def api(endpoint, paginated=False):
            if endpoint.endswith("/permission"):
                if isinstance(permission, Exception):
                    raise permission
                return {"permission": permission}
            matches = "/issues/" in endpoint if location == "issues" else endpoint.endswith("/" + location)
            return [[], [comment]] if matches else [[]]

        return gate.authorized_justification("owner/repo", 1, api)

    def test_private_member_admin_is_accepted(self):
        self.assertEqual(self.evaluate("admin"), 42)

    def test_writer_is_accepted_at_every_review_location(self):
        for location in ["issues", "comments", "reviews"]:
            with self.subTest(location=location):
                self.assertEqual(self.evaluate("write", location=location), 42)

    def test_association_does_not_grant_write_authority(self):
        for association in ["OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR"]:
            for permission in ["read", "none", None]:
                with self.subTest(association=association, permission=permission):
                    self.assertIsNone(self.evaluate(permission, association))

    def test_prefix_is_required_and_case_insensitive(self):
        self.assertEqual(self.evaluate("write", body=gate.PREFIX.upper() + " reason"), 42)
        self.assertIsNone(self.evaluate("write", body="Quoted: " + gate.PREFIX))
        self.assertIsNone(self.evaluate("write", body=""))

    def test_permission_lookup_error_is_not_approval(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.evaluate(subprocess.CalledProcessError(1, ["gh", "api"]))


if __name__ == "__main__":
    unittest.main()
