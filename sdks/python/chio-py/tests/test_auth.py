from __future__ import annotations

import unittest

from chio.auth import authorization_server_metadata_url, pkce_challenge


class AuthTests(unittest.TestCase):
    def test_pkce_challenge_matches_expected_value(self) -> None:
        self.assertEqual(
            pkce_challenge("abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
        )

    def test_authorization_server_metadata_url_handles_root_and_path_issuers(self) -> None:
        self.assertEqual(
            authorization_server_metadata_url("http://127.0.0.1:8080", "https://issuer.example"),
            "http://127.0.0.1:8080/.well-known/oauth-authorization-server",
        )
        self.assertEqual(
            authorization_server_metadata_url(
                "http://127.0.0.1:8080",
                "https://issuer.example/tenant-a",
            ),
            "http://127.0.0.1:8080/.well-known/oauth-authorization-server/tenant-a",
        )


if __name__ == "__main__":
    unittest.main()
