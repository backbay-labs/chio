"""Private transport for the two scoped required-agent operator commands."""

import http.client
import ipaddress
import json
import math
import os
import re
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request

MAX_JSON_BYTES = 1024 * 1024
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*\Z")


class OperatorError(Exception):
    """Only fixed diagnostic codes and HTTP status may leave this module."""

    def __init__(self, code, http_status=None):
        super().__init__(code)
        self.code = code
        self.http_status = http_status

    def record(self):
        result = {"ok": False, "error": self.code}
        if self.http_status is not None:
            result["httpStatus"] = self.http_status
        return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("non-finite JSON number")


def finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


def decode_object(data):
    try:
        value = json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise OperatorError("invalid_json_object") from error


def private_operator(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > 65536
            ):
                raise OperatorError("operator_file_must_be_private_owned_regular_json")
            data = handle.read(65537)
        if len(data) > 65536:
            raise OperatorError("operator_file_too_large")
        value = decode_object(data)
        token = value.get("adminToken")
        if not isinstance(token, str) or len(token) > 4096 or not BEARER.fullmatch(token):
            raise OperatorError("invalid_admin_token")
        if any(value.get(key) == token for key in ("agentToken", "bearerToken", "authToken")):
            raise OperatorError("admin_token_must_be_distinct")
        return value
    except OSError as error:
        raise OperatorError("cannot_read_private_operator_file") from error


def origin(base_url, operator):
    if base_url is None:
        port = operator.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise OperatorError("invalid_operator_port")
        return f"http://127.0.0.1:{port}"
    try:
        if (
            not isinstance(base_url, str)
            or not base_url
            or any(ord(c) < 33 or ord(c) > 126 for c in base_url)
            or any(c in base_url for c in "\\?#%")
        ):
            raise ValueError("ambiguous origin")
        parsed = urllib.parse.urlsplit(base_url)
        host, port = parsed.hostname, parsed.port
        if (
            parsed.scheme not in ("https", "http")
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.netloc.endswith(":")
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("origin required")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
            labels = host.split(".")
            if len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
            ):
                raise ValueError("invalid hostname") from None
        if parsed.scheme == "http":
            if host == "localhost":
                host = "127.0.0.1"  # Avoid DNS/proxy-dependent localhost routing.
            elif address is None or not address.is_loopback:
                raise ValueError("plaintext admin origin must be loopback")
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority += f":{port}"
        return f"{parsed.scheme}://{authority}"
    except ValueError as error:
        raise OperatorError("origin_requires_trusted_https_or_literal_loopback_http") from error


def identifier(value, operator):
    if (
        not isinstance(value, str)
        or not IDENTIFIER.fullmatch(value)
        or any(
            value == token
            for key, token in operator.items()
            if "token" in key.lower() and isinstance(token, str)
        )
    ):
        raise OperatorError("invalid_explicit_identifier")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(base, route, operator, data=None, timeout=30):
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise OperatorError("timeout_must_be_between_zero_and_60_seconds")
    request = urllib.request.Request(
        base + route,
        data=None if data is None else json.dumps(data).encode(),
        headers={
            "Authorization": "Bearer " + operator["adminToken"],
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise OperatorError("unexpected_http_status", response.status)
            if response.headers.get_content_type() != "application/json":
                raise OperatorError("response_is_not_json", response.status)
            payload = response.read(MAX_JSON_BYTES + 1)
            if len(payload) > MAX_JSON_BYTES:
                raise OperatorError("response_too_large", response.status)
            return decode_object(payload)
    except urllib.error.HTTPError as error:
        error.close()
        code = "redirect_refused" if 300 <= error.code < 400 else "http_error"
        raise OperatorError(code, error.code) from error
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise OperatorError("transport_failed") from error
