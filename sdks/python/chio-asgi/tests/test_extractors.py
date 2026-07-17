"""Tests for ASGI identity extractors."""

from __future__ import annotations

import hashlib

from chio_asgi.extractors import (
    ApiKeyExtractor,
    BearerTokenExtractor,
    CompositeExtractor,
    CookieExtractor,
)


def _sha256(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()


def _make_scope(headers: dict[str, str] | None = None) -> dict:
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append(
                (k.lower().encode("latin-1"), v.encode("latin-1"))
            )
    return {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": raw_headers,
    }


class TestBearerTokenExtractor:
    def test_extracts_bearer(self) -> None:
        scope = _make_scope({"authorization": "Bearer my-secret-token"})
        extractor = BearerTokenExtractor()
        identity = extractor.extract(scope)
        assert identity is not None
        assert identity.auth_method.method == "bearer"
        assert identity.auth_method.token_hash == _sha256("my-secret-token")
        assert identity.subject == _sha256("my-secret-token")

    def test_returns_none_for_no_auth(self) -> None:
        scope = _make_scope({})
        assert BearerTokenExtractor().extract(scope) is None

    def test_returns_none_for_non_bearer(self) -> None:
        scope = _make_scope({"authorization": "Basic dXNlcjpwYXNz"})
        assert BearerTokenExtractor().extract(scope) is None

    def test_returns_none_for_empty_bearer(self) -> None:
        scope = _make_scope({"authorization": "Bearer "})
        assert BearerTokenExtractor().extract(scope) is None


class TestApiKeyExtractor:
    def test_extracts_default_header(self) -> None:
        scope = _make_scope({"x-api-key": "my-key"})
        identity = ApiKeyExtractor().extract(scope)
        assert identity is not None
        assert identity.auth_method.method == "api_key"
        assert identity.auth_method.key_hash == _sha256("my-key")

    def test_custom_header(self) -> None:
        scope = _make_scope({"x-custom-key": "abc"})
        identity = ApiKeyExtractor("X-Custom-Key").extract(scope)
        assert identity is not None
        assert identity.auth_method.key_name == "x-custom-key"

    def test_returns_none_for_missing(self) -> None:
        scope = _make_scope({})
        assert ApiKeyExtractor().extract(scope) is None


class TestCookieExtractor:
    def test_extracts_session_cookie(self) -> None:
        scope = _make_scope({"cookie": "session=abc123; other=xyz"})
        identity = CookieExtractor().extract(scope)
        assert identity is not None
        assert identity.auth_method.method == "cookie"
        assert identity.auth_method.cookie_hash == _sha256("abc123")

    def test_extracts_session_cookie_from_split_cookie_headers(self) -> None:
        scope = _make_scope()
        scope["headers"] = [
            (b"cookie", b"session=abc123"),
            (b"cookie", b"other=xyz"),
        ]
        identity = CookieExtractor().extract(scope)
        assert identity is not None
        assert identity.auth_method.method == "cookie"
        assert identity.auth_method.cookie_hash == _sha256("abc123")

    def test_custom_cookie_name(self) -> None:
        scope = _make_scope({"cookie": "sid=my-session"})
        identity = CookieExtractor("sid").extract(scope)
        assert identity is not None
        assert identity.auth_method.cookie_name == "sid"

    def test_returns_none_for_missing_cookie(self) -> None:
        scope = _make_scope({"cookie": "other=val"})
        assert CookieExtractor().extract(scope) is None

    def test_returns_none_for_no_cookie_header(self) -> None:
        scope = _make_scope({})
        assert CookieExtractor().extract(scope) is None


class TestCompositeExtractor:
    def test_bearer_wins(self) -> None:
        scope = _make_scope({
            "authorization": "Bearer tok",
            "x-api-key": "key",
        })
        identity = CompositeExtractor().extract(scope)
        assert identity.auth_method.method == "bearer"

    def test_api_key_fallback(self) -> None:
        scope = _make_scope({"x-api-key": "key"})
        identity = CompositeExtractor().extract(scope)
        assert identity.auth_method.method == "api_key"

    def test_cookie_fallback(self) -> None:
        scope = _make_scope({"cookie": "session=val"})
        identity = CompositeExtractor().extract(scope)
        assert identity.auth_method.method == "cookie"

    def test_anonymous_fallback(self) -> None:
        scope = _make_scope({})
        identity = CompositeExtractor().extract(scope)
        assert identity.auth_method.method == "anonymous"
        assert identity.subject == "anonymous"
