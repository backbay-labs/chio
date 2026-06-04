from __future__ import annotations

from django.test import SimpleTestCase, override_settings


@override_settings(MIDDLEWARE=[])
class DjangoRouteTests(SimpleTestCase):
    def test_healthz(self) -> None:
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_hello_without_middleware_receipt(self) -> None:
        response = self.client.get("/hello")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"message": "hello from django", "receipt_id": None},
        )

    def test_echo_defaults_count(self) -> None:
        response = self.client.post(
            "/echo",
            data='{"message":"hello"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "message": "hello",
                "count": 1,
                "receipt_id": None,
                "body_cached": True,
            },
        )

    def test_echo_requires_json_object(self) -> None:
        response = self.client.post(
            "/echo",
            data='["hello"]',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "body must be a JSON object")

    def test_echo_rejects_empty_message(self) -> None:
        response = self.client.post(
            "/echo",
            data='{"message":"","count":1}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["error"],
            "message must be a non-empty string",
        )

    def test_echo_rejects_coerced_count(self) -> None:
        response = self.client.post(
            "/echo",
            data='{"message":"hello","count":"2"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["error"],
            "count must be an integer greater than or equal to 1",
        )

    def test_echo_rejects_boolean_count(self) -> None:
        response = self.client.post(
            "/echo",
            data='{"message":"hello","count":true}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["error"],
            "count must be an integer greater than or equal to 1",
        )

    def test_echo_rejects_extra_fields(self) -> None:
        response = self.client.post(
            "/echo",
            data='{"message":"hello","count":1,"admin":true}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "unexpected fields: admin")

    def test_echo_rejects_malformed_json(self) -> None:
        response = self.client.post(
            "/echo",
            data='{"message":',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertTrue(response.json()["error"])
