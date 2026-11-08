"""Fixture bersama: dunia tiruan (layanan lain lewat `httpx.MockTransport`), token tiruan, dan pembuat aplikasi."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from astria_common.audit_client import AuditUnavailable
from astria_common.hmac_auth import signed_headers
from fastapi.testclient import TestClient

from astria_api.main import build_app
from astria_api.settings import UPSTREAMS, Settings

SVC_KEY = bytes.fromhex("aa" * 32)
COLLECTOR_KEY = bytes.fromhex("bb" * 32)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _clean_astria_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Uji tidak boleh membaca ASTRIA_* milik kontainer dev."""
    for key in list(os.environ):
        if key.startswith("ASTRIA_") and not key.startswith("ASTRIA_TEST_"):
            monkeypatch.delenv(key, raising=False)


class FakeTokens:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def auth_headers(self, audience: str, act: dict[str, Any] | None = None) -> dict[str, str]:
        self.calls.append((audience, act))
        return {"Authorization": f"Bearer fake-{audience}"}


class FakeAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.fail = False

    async def record(self, record: Any, *, act: dict[str, Any] | None = None) -> Any:
        if self.fail:
            raise AuditUnavailable("tiruan mati")
        self.records.append(dict(record))
        return {"seq": len(self.records)}

    def actions(self) -> list[str]:
        return [r["action"] for r in self.records]


@dataclass
class Call:
    service: str
    method: str
    path: str
    params: dict[str, str]
    body: Any
    headers: dict[str, str]


@dataclass
class World:
    """Semua layanan tujuan tiruan. `on` mendaftarkan jawaban; sisanya 200 `{}` (longgar) atau 599 (ketat)."""

    strict: bool = False
    calls: list[Call] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    _routes: dict[tuple[str, str, str], Callable[[httpx.Request], httpx.Response]] = field(default_factory=dict)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    users: dict[str, dict[str, Any]] = field(default_factory=dict)

    def on(
        self,
        service: str,
        method: str,
        path: str,
        json: Any = None,
        status: int = 200,
        *,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        fn: Callable[[httpx.Request], httpx.Response] | None = None,
        exc: Exception | None = None,
    ) -> None:
        def respond(request: httpx.Request) -> httpx.Response:
            if exc is not None:
                raise exc
            if fn is not None:
                return fn(request)
            if content is not None:
                return httpx.Response(status, content=content, headers=headers)
            return httpx.Response(status, json=json if json is not None else {}, headers=headers)

        self._routes[(service, method, path)] = respond

    def session(self, token: str, user_id: str, roles: list[str], *, session_id: str | None = None) -> None:
        self.sessions[token] = {
            "active": True,
            "user_id": user_id,
            "roles": roles,
            "reauth_at": None,
            "session_id": session_id or f"ses_{user_id}",
        }

    def handler(self, service: str) -> Callable[[httpx.Request], httpx.Response]:
        def handle(request: httpx.Request) -> httpx.Response:
            body: Any = None
            if request.content:
                try:
                    body = json.loads(request.content)
                except ValueError:
                    body = request.content
            call = Call(
                service,
                request.method,
                request.url.path,
                dict(request.url.params),
                body,
                {k.lower(): v for k, v in request.headers.items()},
            )
            self.calls.append(call)
            override = self._routes.get((service, request.method, request.url.path))
            if override is not None:
                return override(request)
            if service == "identity" and request.url.path == "/internal/v1/sessions/introspect":
                return httpx.Response(200, json=self.sessions.get(body["token"], {"active": False}))
            if service == "identity" and request.url.path.startswith("/internal/v1/users/"):
                user = self.users.get(request.url.path.rsplit("/", 1)[-1])
                return httpx.Response(200, json=user) if user else httpx.Response(404, json={})
            route = self._routes.get((service, request.method, request.url.path))
            if route is not None:
                return route(request)
            if self.strict:
                self.unexpected.append(f"{service} {request.method} {request.url.path}")
                return httpx.Response(599, json={})
            return httpx.Response(200, json={})

        return handle

    def clients(self) -> dict[str, httpx.AsyncClient]:
        return {
            name: httpx.AsyncClient(
                base_url=f"http://{name}.test", transport=httpx.MockTransport(self.handler(name)), timeout=2.0
            )
            for name in UPSTREAMS
        }

    def calls_to(self, service: str) -> list[Call]:
        return [c for c in self.calls if c.service == service]


@dataclass
class Env:
    app: Any
    client: TestClient
    world: World
    audit: FakeAudit
    tokens: FakeTokens

    def as_user(self, token: str) -> TestClient:
        self.client.cookies.clear()
        self.client.cookies.set("astria_session", token)
        return self.client

    def write(self, method: str, path: str, token: str | None = None, **kwargs: Any) -> httpx.Response:
        """Permintaan ubah dengan Origin dan Content-Type JSON yang sah."""
        if token is not None:
            self.as_user(token)
        headers = {"Origin": "http://testserver"} | kwargs.pop("headers", {})
        return self.client.request(method, path, headers=headers, **kwargs)


def make_env(tmp_path: Any, *, strict: bool = False, **settings: Any) -> Env:
    world = World(strict=strict)
    keys = tmp_path / "svc_keys.json"
    keys.write_text(json.dumps({"gateway": SVC_KEY.hex(), "collector": COLLECTOR_KEY.hex()}), encoding="utf-8")
    audit = FakeAudit()
    tokens = FakeTokens()
    app = build_app(
        Settings(env="test", svc_keys_file=keys, rate_user_per_min=10_000, **settings),
        token_source=tokens,
        upstream_clients=world.clients(),
        audit_sink=audit,
    )
    return Env(app, TestClient(app), world, audit, tokens)


@pytest.fixture
def env(tmp_path: Any) -> Env:
    environment = make_env(tmp_path)
    for token, user, roles in [
        ("tok-analis", "usr_ana", ["analis"]),
        ("tok-dfir", "usr_dfir", ["dfir"]),
        ("tok-pimpinan", "usr_pim", ["pimpinan"]),
        ("tok-admin", "usr_adm", ["admin"]),
        ("tok-ngawur", "usr_xxx", ["superuser"]),
        ("tok-kosong", "usr_none", []),
    ]:
        environment.world.session(token, user, roles)
    return environment


def sign(
    method: str,
    path: str,
    body: bytes = b"",
    *,
    service: str = "gateway",
    key: bytes = SVC_KEY,
    now: float | None = None,
) -> dict[str, str]:
    return signed_headers(service, key, method, path, body, now=now)
