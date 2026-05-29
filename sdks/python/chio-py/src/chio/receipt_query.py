from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any, TypedDict, cast

from .errors import ChioQueryError, ChioTransportError, parse_json_text


class ReceiptQueryParams(TypedDict, total=False):
    capabilityId: str
    toolServer: str
    toolName: str
    outcome: str
    since: int
    until: int
    minCost: int
    maxCost: int
    agentSubject: str
    cursor: int
    limit: int


class ReceiptQueryResponse(TypedDict, total=False):
    totalCount: int
    nextCursor: int
    receipts: list[dict[str, Any]]


class ReceiptQueryClient:
    def __init__(
        self,
        base_url: str,
        auth_token: str,
        *,
        client: Any | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self._client = client

    def query(self, params: ReceiptQueryParams | None = None) -> ReceiptQueryResponse:
        url = self._build_url(params or {})
        headers = {"Authorization": f"Bearer {self.auth_token}"}

        if self._client is not None:
            try:
                response = self._client.get(url, headers=headers, timeout=5.0)
            except Exception as exc:
                raise ChioTransportError("failed to fetch receipts") from exc
            if response.status_code < 200 or response.status_code >= 300:
                raise ChioQueryError(
                    f"receipt query failed with status {response.status_code}",
                    status=response.status_code,
                )
            return self._parse_payload(response.text)

        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return self._parse_payload(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ChioQueryError(
                f"receipt query failed with status {exc.code}",
                status=exc.code,
            ) from exc
        except OSError as exc:
            raise ChioTransportError("failed to fetch receipts") from exc

    def paginate(self, params: ReceiptQueryParams | None = None) -> Iterator[list[dict[str, Any]]]:
        query_params = dict(params or {})
        cursor = cast(int | None, query_params.get("cursor"))
        while True:
            if cursor is not None:
                query_params["cursor"] = cursor
            response = self.query(cast(ReceiptQueryParams, query_params))
            receipts = response.get("receipts", [])
            if receipts:
                yield receipts
            next_cursor = response.get("nextCursor")
            if next_cursor is None:
                break
            cursor = next_cursor

    def _build_url(self, params: ReceiptQueryParams) -> str:
        query = urllib.parse.urlencode(
            {
                key: str(value)
                for key, value in params.items()
                if value is not None
            }
        )
        base = f"{self.base_url}/v1/receipts/query"
        return f"{base}?{query}" if query else base

    def _parse_payload(self, payload: str) -> ReceiptQueryResponse:
        parsed = parse_json_text(payload)
        if not isinstance(parsed, dict):
            raise ChioTransportError("receipt query response was not a JSON object")
        return cast(ReceiptQueryResponse, parsed)
