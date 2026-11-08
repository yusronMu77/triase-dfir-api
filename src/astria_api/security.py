"""Middleware ASGI murni: batas ukuran badan, pemeriksaan Origin dan Content-Type (CSRF), dan header keamanan.

Berlaku untuk jalur `/api/` (dasbor) dan `/svc/` (gateway, collector). Penolakan dibuat di sini sebelum badan
dibaca. Middleware ini dipasang setelah `create_app`, jadi menjadi lapisan terluar; galat buatannya membawa
`X-Trace-Id` sendiri.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

from astria_common.errors import error_body
from astria_common.tracing import new_trace_id, trace_id_from_headers
from prometheus_client import Counter

from astria_api.errors import ApiError

REJECTED = Counter("astria_api_rejected_total", "Permintaan ditolak middleware keamanan", ["reason"])

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
# Unggahan arsip dialirkan ke ingest; batas ukurannya ada di ingest (note api bagian 3.3).
STREAMING_PREFIX = "/svc/v1/collector/acquisitions/"

SECURITY_HEADERS = [
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
]


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


class SecurityMiddleware:
    def __init__(self, app: Any, *, public_origin: str | None, max_body_bytes: int) -> None:
        self.app = app
        self._public_origin = _origin_of(public_origin) if public_origin else None
        self._max_body = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(("/api/", "/svc/")):
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        method, path = scope["method"], scope["path"]

        if path.startswith("/api/") and method in UNSAFE:
            allowed = self._public_origin or f"{scope.get('scheme', 'http')}://{headers.get('host', '')}"
            if headers.get("origin") != allowed:
                await self._reject(scope, send, "origin", 403, "DILARANG", "asal permintaan tidak diizinkan")
                return
            has_body = headers.get("content-length", "0") != "0" or "transfer-encoding" in headers
            if has_body and headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
                await self._reject(
                    scope, send, "content_type", 415, "TIPE_TIDAK_DIDUKUNG", "Content-Type harus application/json"
                )
                return

        if not path.startswith(STREAMING_PREFIX):
            declared = headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > self._max_body:
                await self._reject(scope, send, "body_size", 413, "TERLALU_BESAR", "badan permintaan terlalu besar")
                return
            receive = self._limited(receive)

        async def send_with_headers(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                present = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = [
                    *message.get("headers", []),
                    *(h for h in SECURITY_HEADERS if h[0] not in present),
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)

    def _limited(self, receive: Receive) -> Receive:
        seen = 0
        limit = self._max_body

        async def wrapper() -> MutableMapping[str, Any]:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    REJECTED.labels("body_size").inc()
                    raise ApiError("TERLALU_BESAR", "badan permintaan terlalu besar", 413)
            return message

        return wrapper

    async def _reject(self, scope: Scope, send: Send, reason: str, status: int, code: str, message: str) -> None:
        REJECTED.labels(reason).inc()
        incoming = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        trace_id = trace_id_from_headers(incoming.get("traceparent"), incoming.get("x-trace-id")) or new_trace_id()
        body = error_body(code, message)
        body["error"]["trace_id"] = trace_id
        raw = json.dumps(body).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode()),
                    (b"x-trace-id", trace_id.encode()),
                    *SECURITY_HEADERS,
                ],
            }
        )
        await send({"type": "http.response.body", "body": raw})
