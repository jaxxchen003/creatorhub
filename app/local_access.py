"""Lightweight boundaries for a single-user, local-only workbench. No login."""
from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse


def loopback(host: str) -> bool:
    host = str(host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        address = ip_address(host)
        return address.is_loopback or bool(
            getattr(address, "ipv4_mapped", None) and address.ipv4_mapped.is_loopback)
    except ValueError:
        return False


def local_request(request: Request) -> bool:
    # Both the peer and Host matter: a DNS-rebinding Host or a local reverse
    # proxy does not turn an arbitrary remote page into the local workbench.
    return bool(request.client and loopback(request.client.host)
                and loopback(request.url.hostname or ""))


def same_origin(request: Request, value: str) -> bool:
    """True when an Origin/Referer-style value may be trusted for this request.

    Two cases are accepted:

    1. The value is a strict origin (no credentials, path, query or fragment)
       whose scheme/host/port equal the request's own.
    2. The value omits its port while the browser reports
       ``Sec-Fetch-Site: same-origin`` for the request. Several Chromium builds
       and proxy extensions strip a non-default port from ``Origin`` (e.g.
       ``Origin: http://127.0.0.1`` for a page served from
       ``http://127.0.0.1:8000``). ``Sec-Fetch-Site`` is set by the browser and
       cannot be forged by page script, so honouring it keeps the CSRF boundary
       intact while letting those clients through.

    Anything else — foreign hosts, explicit non-default ports, ``null``
    origins, userinfo, or paths — is rejected.
    """
    try:
        origin, target = urlsplit(value), urlsplit(str(request.url))
        def identity(url):
            return (url.scheme, (url.hostname or "").lower(),
                    url.port or (443 if url.scheme == "https" else 80))
        if not (not origin.username and not origin.password
                and origin.scheme in {"http", "https"}
                and origin.path in {"", "/"} and not origin.query and not origin.fragment):
            return False
        if identity(origin) == identity(target):
            return True
        return (not origin.port
                and request.headers.get("sec-fetch-site", "").lower() == "same-origin"
                and origin.scheme == target.scheme
                and (origin.hostname or "").lower() == (target.hostname or "").lower())
    except ValueError:
        return False


# Kept for callers that imported the older private name.
_same_origin = same_origin


class LocalAccessMiddleware:
    """Protect local data/actions, without users, passwords, sessions or roles."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        path = scope.get("path", "")
        api = path == "/api" or path.startswith("/api/")
        error = None
        try:
            valid_local = local_request(request) and len(request.headers.getlist("host")) == 1
            request.url.port
        except ValueError:
            valid_local = False
        if not valid_local:
            error = "当前工作台仅供本机使用，请通过 127.0.0.1 或 localhost 访问"
        elif api and (request.headers.get("sec-fetch-site", "") in {"cross-site", "same-site"}
                      or ("origin" in request.headers and not same_origin(request, request.headers["origin"]))):
            error = "请从 CreatorHub 同源页面发起请求"
        if error:
            await JSONResponse({"detail": error}, status_code=403,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)
            return

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers += [(b"x-content-type-options", b"nosniff"),
                            (b"x-frame-options", b"DENY"),
                            (b"referrer-policy", b"no-referrer")]
                if not path.startswith("/static/"):
                    headers = [(k, v) for k, v in headers if k.lower() != b"cache-control"]
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)
        # Pure ASGI: do not buffer media, exports or SSE streams.
        await self.app(scope, receive, secure_send)
