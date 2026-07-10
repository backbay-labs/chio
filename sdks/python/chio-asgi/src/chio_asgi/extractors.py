"""Identity extractors for ASGI request scopes.

Each extractor examines the ASGI scope/headers and returns a ``CallerIdentity``
if it can identify the caller. Extractors are composable via
``CompositeExtractor`` which tries each extractor in order and returns the
first successful match (or anonymous).
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any

from chio_sdk.models import AuthMethod, CallerIdentity


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _get_headers(scope: dict[str, Any]) -> dict[str, str]:
    """Extract headers from an ASGI scope as a lowercase-keyed dict."""
    raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    headers: dict[str, str] = {}
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if name == "cookie" and name in headers:
            headers[name] = f"{headers[name]}; {value}"
        else:
            headers[name] = value
    return headers


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse a Cookie header into a dict."""
    cookies: dict[str, str] = {}
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _, value = pair.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


class IdentityExtractor(ABC):
    """Base class for caller identity extractors."""

    @abstractmethod
    def extract(self, scope: dict[str, Any]) -> CallerIdentity | None:
        """Try to extract a caller identity from the ASGI scope.

        Returns None if this extractor does not recognize the request.
        """
        ...


class BearerTokenExtractor(IdentityExtractor):
    """Extract caller identity from a Bearer token in the Authorization header.

    The token value is hashed (never stored raw). The ``subject`` is set to
    the token hash as a stable identifier; downstream guards or the sidecar
    can resolve a richer subject from the JWT claims.
    """

    def extract(self, scope: dict[str, Any]) -> CallerIdentity | None:
        headers = _get_headers(scope)
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return None
        token = auth[7:].strip()
        if not token:
            return None
        token_hash = _sha256_hex(token)
        return CallerIdentity(
            subject=token_hash,
            auth_method=AuthMethod.bearer(token_hash=token_hash),
            verified=False,
        )


class ApiKeyExtractor(IdentityExtractor):
    """Extract caller identity from an API key header.

    Parameters
    ----------
    header_name:
        Name of the header carrying the API key (default ``X-API-Key``).
    """

    def __init__(self, header_name: str = "x-api-key") -> None:
        self._header_name = header_name.lower()

    def extract(self, scope: dict[str, Any]) -> CallerIdentity | None:
        headers = _get_headers(scope)
        key_value = headers.get(self._header_name, "")
        if not key_value:
            return None
        key_hash = _sha256_hex(key_value)
        return CallerIdentity(
            subject=key_hash,
            auth_method=AuthMethod.api_key(
                key_name=self._header_name, key_hash=key_hash
            ),
            verified=False,
        )


class CookieExtractor(IdentityExtractor):
    """Extract caller identity from a session cookie.

    Parameters
    ----------
    cookie_name:
        Name of the session cookie (default ``session``).
    """

    def __init__(self, cookie_name: str = "session") -> None:
        self._cookie_name = cookie_name

    def extract(self, scope: dict[str, Any]) -> CallerIdentity | None:
        headers = _get_headers(scope)
        cookie_header = headers.get("cookie", "")
        if not cookie_header:
            return None
        cookies = _parse_cookies(cookie_header)
        value = cookies.get(self._cookie_name, "")
        if not value:
            return None
        cookie_hash = _sha256_hex(value)
        return CallerIdentity(
            subject=cookie_hash,
            auth_method=AuthMethod.cookie(
                cookie_name=self._cookie_name, cookie_hash=cookie_hash
            ),
            verified=False,
        )


class CompositeExtractor(IdentityExtractor):
    """Try multiple extractors in order, returning the first successful match.

    Falls back to anonymous if none match.
    """

    def __init__(self, extractors: list[IdentityExtractor] | None = None) -> None:
        self._extractors = extractors or [
            BearerTokenExtractor(),
            ApiKeyExtractor(),
            CookieExtractor(),
        ]

    def extract(self, scope: dict[str, Any]) -> CallerIdentity:
        for extractor in self._extractors:
            identity = extractor.extract(scope)
            if identity is not None:
                return identity
        return CallerIdentity.anonymous()
