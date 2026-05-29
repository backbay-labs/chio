from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable
import urllib.parse
import urllib.request


@dataclass(frozen=True)
class StaticBearerAuth:
    auth_token: str


def static_bearer_auth(auth_token: str) -> StaticBearerAuth:
    return StaticBearerAuth(auth_token=auth_token)


TranscriptHook = Callable[[dict[str, Any]], None]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    def http_error_303(self, req, fp, code, msg, headers):
        return fp

    def http_error_307(self, req, fp, code, msg, headers):
        return fp

    def http_error_308(self, req, fp, code, msg, headers):
        return fp


def get_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        return {
            "status": response.status,
            "headers": {key.lower(): value for key, value in response.headers.items()},
            "body": json.loads(response.read().decode("utf-8")),
        }


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def authorization_server_metadata_url(base_url: str, issuer: str) -> str:
    parsed = urllib.parse.urlparse(issuer)
    trimmed_path = parsed.path.strip("/")
    if trimmed_path:
        return f"{base_url}/.well-known/oauth-authorization-server/{trimmed_path}"
    return f"{base_url}/.well-known/oauth-authorization-server"


def discover_oauth_metadata(
    base_url: str,
    emit: TranscriptHook | None = None,
) -> dict[str, Any]:
    protected_resource = get_json(f"{base_url}/.well-known/oauth-protected-resource/mcp")
    if emit is not None:
        emit(
            {
                "step": "auth/protected-resource-metadata",
                "httpStatus": protected_resource["status"],
                "headers": protected_resource["headers"],
                "body": protected_resource["body"],
            }
        )
    issuer = protected_resource["body"].get("authorization_servers", [None])[0]
    if not issuer:
        raise RuntimeError("protected resource metadata did not advertise an authorization server")

    authorization_server = get_json(authorization_server_metadata_url(base_url, issuer))
    if emit is not None:
        emit(
            {
                "step": "auth/authorization-server-metadata",
                "httpStatus": authorization_server["status"],
                "headers": authorization_server["headers"],
                "body": authorization_server["body"],
            }
        )
    return {
        "protected_resource_metadata": protected_resource["body"],
        "authorization_server_metadata": authorization_server["body"],
    }


def perform_authorization_code_flow(
    *,
    base_url: str,
    auth_scope: str,
    authorization_server_metadata: dict[str, Any],
    emit: TranscriptHook | None = None,
    code_verifier: str = "chio-sdk-verifier",
    redirect_uri: str = "http://localhost:7777/callback",
    state: str = "chio-sdk-state",
    client_id: str = "https://client.example/app",
) -> str:
    resource = f"{base_url}/mcp"
    authorization_endpoint = authorization_server_metadata.get(
        "authorization_endpoint",
        f"{base_url}/oauth/authorize",
    )
    token_endpoint = authorization_server_metadata.get(
        "token_endpoint",
        f"{base_url}/oauth/token",
    )
    challenge = pkce_challenge(code_verifier)

    authorize_query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "resource": resource,
            "scope": auth_scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    authorize_request = urllib.request.Request(
        f"{authorization_endpoint}?{authorize_query}",
        method="GET",
    )
    with urllib.request.urlopen(authorize_request, timeout=5) as response:
        authorize_page = response.read().decode("utf-8")
        if emit is not None:
            emit(
                {
                    "step": "auth/authorize-page",
                    "httpStatus": response.status,
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "body": authorize_page,
                }
            )
        if response.status != 200 or "Approve" not in authorize_page:
            raise RuntimeError("authorization endpoint did not return an approval page")

    approval_request = urllib.request.Request(
        authorization_endpoint,
        data=urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "resource": resource,
                "scope": auth_scope,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "decision": "approve",
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    approval_opener = urllib.request.build_opener(NoRedirectHandler())
    with approval_opener.open(approval_request, timeout=5) as response:
        if emit is not None:
            emit(
                {
                    "step": "auth/authorize-approve",
                    "httpStatus": response.status,
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                }
            )
        if response.status < 300 or response.status >= 400:
            raise RuntimeError("authorization approval did not redirect with a code")
        location = response.headers.get("Location")
        if not location:
            raise RuntimeError("authorization approval did not provide a redirect location")

    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("code", [None])[0]
    if not code:
        raise RuntimeError("authorization approval redirect did not include a code")

    token_request = urllib.request.Request(
        token_endpoint,
        data=urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
                "resource": resource,
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(token_request, timeout=5) as response:
        body = json.loads(response.read().decode("utf-8"))
        if emit is not None:
            emit(
                {
                    "step": "auth/token",
                    "httpStatus": response.status,
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "body": body,
                }
            )
        if response.status != 200 or not isinstance(body.get("access_token"), str):
            raise RuntimeError("authorization code exchange did not return an access token")
        return body["access_token"]


def exchange_access_token(
    *,
    base_url: str,
    auth_scope: str,
    authorization_server_metadata: dict[str, Any],
    access_token: str,
    emit: TranscriptHook | None = None,
) -> str:
    token_endpoint = authorization_server_metadata.get(
        "token_endpoint",
        f"{base_url}/oauth/token",
    )
    request = urllib.request.Request(
        token_endpoint,
        data=urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": access_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "resource": f"{base_url}/mcp",
                "scope": auth_scope,
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        body = json.loads(response.read().decode("utf-8"))
        if emit is not None:
            emit(
                {
                    "step": "auth/token-exchange",
                    "httpStatus": response.status,
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "body": body,
                }
            )
        if response.status != 200 or not isinstance(body.get("access_token"), str):
            raise RuntimeError("token exchange did not return an access token")
        return body["access_token"]


def resolve_oauth_access_token(
    *,
    base_url: str,
    auth_scope: str,
    emit: TranscriptHook | None = None,
) -> dict[str, Any]:
    metadata = discover_oauth_metadata(base_url, emit)
    access_token = perform_authorization_code_flow(
        base_url=base_url,
        auth_scope=auth_scope,
        authorization_server_metadata=metadata["authorization_server_metadata"],
        emit=emit,
        code_verifier="chio-conformance-python-verifier",
        state="chio-python-state",
    )
    return {
        "access_token": access_token,
        "protected_resource_metadata": metadata["protected_resource_metadata"],
        "authorization_server_metadata": metadata["authorization_server_metadata"],
    }
