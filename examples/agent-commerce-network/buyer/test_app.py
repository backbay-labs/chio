from __future__ import annotations

import hashlib
import json
import unittest
import uuid
from copy import deepcopy
from unittest.mock import patch

import httpx
from app import ProviderReviewClient, create_app
from fastapi.testclient import TestClient


class FakeProvider:
    def __init__(self, *, price_minor: int, approval_required: bool) -> None:
        self.price_minor = price_minor
        self.approval_required = approval_required
        self.executions: list[dict] = []
        self.disputes: list[dict] = []

    def request_quote(self, payload: dict) -> dict:
        return {
            "quote_id": "quote_" + uuid.uuid4().hex,
            "request_id": payload["request_id"],
            "service_family": payload["service_family"],
            "offer_id": payload["requested_scope"],
            "provider_id": "vanguard-security",
            "target": payload["target"],
            "price_minor": self.price_minor,
            "currency": "USD",
            "approval_required": self.approval_required,
            "estimated_delivery_hours": 48,
            "pricing_basis": "test quote",
        }

    def execute_review(self, payload: dict) -> dict:
        self.executions.append(deepcopy(payload))
        return {
            "fulfillment_id": "fulfillment_test_001",
            "quote_id": payload["quote_id"],
            "requested_scope": payload["requested_scope"],
            "target": payload["target"],
            "job_id": payload["job_id"],
            "service_family": payload["service_family"],
            "deliverables": ["executive-summary.md"],
            "artifacts": [
                {
                    "name": "executive-summary.md",
                    "content": "Test review",
                    "sha256": hashlib.sha256(b"Test review").hexdigest(),
                }
            ],
            "status": "completed_with_findings",
            "severity_summary": {"critical": 0, "high": 1, "medium": 2, "low": 0},
        }

    def open_dispute(self, payload: dict) -> dict:
        self.disputes.append(deepcopy(payload))
        return {
            "dispute_id": "dispute_test_001",
            "job_id": payload["job_id"],
            "reason_code": payload["reason_code"],
            "summary": payload["summary"],
            "status": "opened",
            "requested_resolution": "partial_reversal",
        }


class BuyerApiTests(unittest.TestCase):
    def make_client(
        self, *, price_minor: int, approval_required: bool
    ) -> tuple[TestClient, FakeProvider]:
        auth = patch.dict("os.environ", {"BUYER_APPROVAL_TOKEN": "operator-only-test-credential"})
        auth.start()
        self.addCleanup(auth.stop)
        provider = FakeProvider(price_minor=price_minor, approval_required=approval_required)
        return self.enterContext(TestClient(create_app(provider=provider))), provider

    def test_quote_request_returns_provider_quote(self) -> None:
        client, _provider = self.make_client(price_minor=45_000, approval_required=False)
        response = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "hotfix-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        )
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "quoted")
        self.assertEqual(body["quote"]["price_minor"], 45_000)

    def test_job_auto_executes_when_approval_not_required(self) -> None:
        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "hotfix-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        response = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 90_000,
            },
        )
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "fulfilled")
        self.assertIsNotNone(body["fulfillment"])
        self.assertEqual(len(provider.executions), 1)

    def test_job_waits_for_approval_then_executes(self) -> None:
        client, provider = self.make_client(price_minor=125_000, approval_required=True)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "release-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        create_response = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 150_000,
            },
        )
        self.assertEqual(create_response.status_code, 202)
        created = create_response.json()
        self.assertEqual(created["status"], "pending_approval")
        self.assertEqual(len(provider.executions), 0)

        approve_response = client.post(
            f"/procurement/jobs/{created['job_id']}/approve",
            json={"approver": "alice@lattice.example", "reason": "release risk accepted"},
            headers={"X-Buyer-Approval": "operator-only-test-credential"},
        )
        self.assertEqual(approve_response.status_code, 200)
        approved = approve_response.json()
        self.assertEqual(approved["status"], "fulfilled")
        self.assertEqual(len(provider.executions), 1)

    def test_budget_deny_is_recorded_without_execution(self) -> None:
        client, provider = self.make_client(price_minor=125_000, approval_required=False)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "release-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        response = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 50_000,
            },
        )
        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "denied_budget")
        self.assertEqual(len(provider.executions), 0)

    def test_dispute_updates_job_state(self) -> None:
        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        quote = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "hotfix-review",
                "release_window": "2026-05-01T16:00:00Z",
            },
        ).json()
        job = client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote["quote"]["quote_id"],
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 90_000,
            },
        ).json()
        dispute_response = client.post(
            f"/procurement/jobs/{job['job_id']}/disputes",
            json={"reason_code": "quality_issue", "summary": "Findings lacked repro steps"},
        )
        self.assertEqual(dispute_response.status_code, 202)
        disputed = dispute_response.json()
        self.assertEqual(disputed["status"], "disputed")
        self.assertEqual(disputed["settlement"]["status"], "reversal_pending")
        self.assertEqual(len(provider.disputes), 1)

    def quote(self, client):
        response = client.post(
            "/procurement/quote-requests",
            json={
                "service_family": "security-review",
                "target": "payments-api",
                "requested_scope": "hotfix-review",
            },
        )
        self.assertEqual(response.status_code, 202)
        return response.json()["quote"]["quote_id"]

    def job(self, client, quote_id, **changes):
        return client.post(
            "/procurement/jobs",
            json={
                "quote_id": quote_id,
                "provider_id": "vanguard-security",
                "service_family": "security-review",
                "budget_minor": 90_000,
                **changes,
            },
        )

    def test_zero_negative_and_increased_caller_budgets_never_execute(self):
        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        zero = self.job(client, self.quote(client), budget_minor=0)
        self.assertEqual(zero.json()["status"], "denied_budget")
        self.assertEqual(self.job(client, self.quote(client), budget_minor=-1).status_code, 422)
        self.assertEqual(
            self.job(client, self.quote(client), budget_minor=999_999).status_code, 409
        )
        self.assertEqual(provider.executions, [])

    def test_quote_replay_and_changed_provider_cannot_dispatch_twice(self):
        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        quote = self.quote(client)
        self.assertEqual(self.job(client, quote, provider_id="another-provider").status_code, 409)
        self.assertEqual(self.job(client, quote).json()["status"], "fulfilled")
        self.assertEqual(self.job(client, quote).status_code, 409)
        self.assertEqual(len(provider.executions), 1)

    def test_budget_is_shared_across_concurrent_jobs(self):
        from concurrent.futures import ThreadPoolExecutor

        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        quotes = [self.quote(client) for _ in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda quote: self.job(client, quote).json(), quotes))
        self.assertEqual(sum(job["status"] == "fulfilled" for job in results), 3)
        self.assertEqual(sum(job["status"] == "denied_budget" for job in results), 5)
        self.assertEqual(len(provider.executions), 3)
        db = client.app.state.procurement_service.store.db
        self.assertEqual(db.execute("SELECT SUM(amount) FROM ledger").fetchone()[0], 0)
        self.assertEqual(db.execute("SELECT SUM(amount) FROM positions").fetchone()[0], 135_000)

    def test_agent_credential_cannot_approve_pending_work(self):
        client, provider = self.make_client(price_minor=125_000, approval_required=True)
        job = self.job(client, self.quote(client), budget_minor=150_000).json()
        response = client.post(
            "/procurement/jobs/" + job["job_id"] + "/approve",
            json={"approver": "agent", "reason": "I approve myself"},
            headers={"Authorization": "Bearer agent-token"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(provider.executions, [])
        self.assertEqual(
            client.get("/procurement/jobs/" + job["job_id"]).json()["status"], "pending_approval"
        )

    def test_missing_work_product_never_settles_or_retries(self):
        client, provider = self.make_client(price_minor=45_000, approval_required=False)
        with patch.object(
            provider, "execute_review", return_value={"job_id": "wrong-job", "status": "completed"}
        ) as execute:
            quote = self.quote(client)
            job = self.job(client, quote).json()
            self.assertEqual(job["status"], "outcome_unknown")
            self.assertIsNone(job["settlement"])
            self.assertEqual(self.job(client, quote).status_code, 409)
            self.assertEqual(execute.call_count, 1)
        self.assertEqual(
            client.app.state.procurement_service.store.db.execute(
                "SELECT COUNT(*) FROM ledger"
            ).fetchone()[0],
            0,
        )

    def test_restart_retains_consumed_quote_budget_and_settlement(self):
        import tempfile
        from pathlib import Path

        from app import CreateJobPayload, ProcurementService, QuoteRequestPayload

        provider = FakeProvider(price_minor=45_000, approval_required=False)
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "buyer.db")
            service = ProcurementService(provider, database=database)
            quote = service.submit_quote_request(
                QuoteRequestPayload(
                    service_family="security-review",
                    target="payments-api",
                    requested_scope="hotfix-review",
                )
            )["quote"]
            payload = CreateJobPayload(
                quote_id=quote["quote_id"],
                provider_id="vanguard-security",
                service_family="security-review",
            )
            job = service.create_job(payload)
            service.store.db.close()
            reopened = ProcurementService(provider, database=database)
            self.assertEqual(reopened.get_job(job["job_id"]), job)
            with self.assertRaises(ValueError):
                reopened.create_job(payload)
            self.assertEqual(len(provider.executions), 1)
            reopened.store.db.close()

    def test_operator_allocation_preserves_jobs_and_increases_available_budget(self):
        from store import ProcurementStore

        store = ProcurementStore(":memory:", 150000)
        self.addCleanup(store.db.close)
        with store.transaction() as db:
            db.execute("INSERT INTO positions VALUES('existing',45000,'settled')")
            db.execute(
                "INSERT INTO allocations(id,amount,reason) VALUES('operator-addition',200000,'Explicit allowance')"
            )
            self.assertEqual(store.capacity(db), 350000)
            self.assertEqual(store.available(db), 305000)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM positions").fetchone()[0], 1)

    def test_provider_review_client_calls_wrapped_mcp_edge(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if (
                request.method == "GET"
                and request.url.path == "/admin/sessions/session_test_001/trust"
            ):
                return httpx.Response(
                    200,
                    json={"capabilities": [{"capabilityId": "cap_test_001"}]},
                )
            payload = json.loads(request.content.decode("utf-8"))
            session_id = request.headers.get("MCP-Session-Id")
            if payload["method"] == "initialize":
                return httpx.Response(
                    200,
                    headers={
                        "MCP-Session-Id": "session_test_001",
                        "content-type": "text/event-stream",
                    },
                    text='data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\n\n',
                )
            if payload["method"] == "notifications/initialized":
                self.assertEqual(session_id, "session_test_001")
                return httpx.Response(202, text="")
            if payload["method"] == "tools/call":
                self.assertEqual(session_id, "session_test_001")
                self.assertEqual(payload["params"]["name"], "request_quote")
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    text=(
                        'data: {"jsonrpc":"2.0","id":2,"result":{"_meta":{"chioReceipt":{"receiptId":"receipt_test_001","requestId":"request_test_001"}},"structuredContent":'
                        '{"quote_id":"quote_edge_001","price_minor":125000,"currency":"USD","approval_required":true}}}\n\n'
                    ),
                )
            raise AssertionError(f"unexpected MCP payload: {payload}")

        transport = httpx.MockTransport(handler)
        client = ProviderReviewClient(
            base_url="http://provider-edge.test",
            auth_token="demo-token",
            client=httpx.Client(transport=transport),
        )

        verification = patch.object(
            client,
            "_verified_receipt",
            return_value={"id": "receipt_test_001", "capability_id": "cap_test_001"},
        )
        verification.start()
        self.addCleanup(verification.stop)
        quote = client.request_quote(
            {
                "request_id": "quote_req_test_001",
                "buyer_id": "lattice-platform-security",
                "service_family": "security-review",
                "target": "git://lattice.example/payments-api",
                "requested_scope": "release-review",
            }
        )

        self.assertEqual(quote["quote_id"], "quote_edge_001")
        self.assertEqual(quote["price_minor"], 125000)
        self.assertEqual(client.last_trace["capability_id"], "cap_test_001")


if __name__ == "__main__":
    unittest.main()
