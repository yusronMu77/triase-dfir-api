"""Rakit aplikasi api: komponen (NATS bila dikonfigurasi, audit, probe, langganan event), middleware keamanan,
router `/api/v1` dan `/svc/v1`, dan pemeriksa kebijakan akses per rute.

Dev memakai `uvicorn astria_api.main:build_app --factory --reload`; image memakai `astria-api`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
from astria_common.app import create_app
from astria_common.audit_client import AuditClient
from astria_common.auth import ServiceTokenClient
from astria_common.component import Check, Component
from astria_common.errors import AstriaError
from astria_common.hmac_auth import NonceCache
from astria_common.service import standard_runtime
from fastapi import FastAPI

from astria_api import errors
from astria_api.audit import AuditSink, AuditWriter
from astria_api.auth import SessionStore
from astria_api.cache import TTLCache  # noqa: F401 - diekspor untuk uji
from astria_api.compose import ConfigCache
from astria_api.events import EventHub, EventRouter, NatsEventSource
from astria_api.health import UpstreamProbe
from astria_api.ratelimit import TokenBucket
from astria_api.routes import api_v1
from astria_api.routing import assert_all_routes_protected
from astria_api.security import SecurityMiddleware
from astria_api.settings import UPSTREAMS, Settings
from astria_api.svc import svc_v1
from astria_api.svc.signing import load_keys
from astria_api.upstream import TokenSource, Upstreams


class _NoTokens:
    """Dipakai hanya bila kunci layanan tidak diisi (ASTRIA_ENV=test): setiap panggilan upstream gagal tertutup."""

    async def auth_headers(self, audience: str, act: dict[str, Any] | None = None) -> dict[str, str]:
        raise AstriaError("TOKEN_DITOLAK", "kunci layanan tidak dikonfigurasi", 503)


class _Closer:
    """Menutup klien HTTP saat berhenti (dihentikan terakhir karena dipasang pertama)."""

    name = "http_clients"
    required = False

    def __init__(self, *closers: Any) -> None:
        self._closers = closers

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        for closer in self._closers:
            await closer()

    async def check(self) -> Check:
        return Check("ok")


def build_app(
    settings: Settings | None = None,
    *,
    token_source: TokenSource | None = None,
    upstream_clients: Mapping[str, httpx.AsyncClient] | None = None,
    audit_sink: AuditSink | None = None,
) -> FastAPI:
    """`token_source`, `upstream_clients`, dan `audit_sink` hanya untuk uji; produksi memakai klien sungguhan."""
    settings = settings or Settings()
    runtime = standard_runtime(settings)

    closers: list[Any] = []
    tokens: Any = token_source
    if tokens is None:
        key = settings.service_key_bytes()
        if key is None:
            tokens = _NoTokens()
        else:
            tokens = ServiceTokenClient(settings.service_name, key, settings.identity_url)
            closers.append(tokens.aclose)

    upstreams = Upstreams(
        {name: settings.upstream_url(name) for name in UPSTREAMS},
        tokens,
        timeout=settings.upstream_timeout_seconds,
        clients=upstream_clients,
    )
    closers.append(upstreams.aclose)

    if audit_sink is None:
        client = AuditClient(tokens, settings.audit_url)
        closers.append(client.aclose)
        audit_sink = client
    audit = AuditWriter(audit_sink)
    sessions = SessionStore(upstreams.identity, settings.cache_session_seconds)
    config_cache = ConfigCache(
        upstreams.config, catalog_ttl=settings.cache_catalog_seconds, settings_ttl=settings.cache_settings_seconds
    )
    hub = EventHub(settings.sse_max_per_user)
    events = EventRouter(
        hub,
        revoke_user=sessions.revoke_user,
        revoke_session=sessions.revoke_session,
        invalidate=config_cache.invalidate,
    )
    probe = UpstreamProbe(upstreams)

    components: list[Component] = [_Closer(*closers), *runtime.components, audit, probe]
    if runtime.bus is not None:
        components.append(NatsEventSource(runtime.bus, events))
    if settings.env == "test":
        probe.start = _noop  # type: ignore[method-assign]  # uji memanggil probe_once sendiri
        audit.start = _noop  # type: ignore[method-assign]

    app = create_app(settings, components=components, routers=[api_v1, svc_v1], title="Astria api")
    errors.install(app)
    app.add_middleware(SecurityMiddleware, public_origin=settings.public_origin, max_body_bytes=settings.max_body_bytes)

    state = app.state
    state.upstreams = upstreams
    state.sessions = sessions
    state.config_cache = config_cache
    state.audit = audit
    state.hub = hub
    state.events = events
    state.probe = probe
    state.user_limiter = TokenBucket(settings.rate_user_per_min)
    state.login_limiter = TokenBucket(settings.rate_login_per_min)
    state.cmd_limiter = TokenBucket(settings.rate_cmd_per_min)
    state.global_cmd_limiter = TokenBucket(settings.rate_global_cmd_per_min)
    state.svc_keys = load_keys(settings.svc_keys_file)
    state.nonces = NonceCache()

    assert_all_routes_protected(api_v1, svc_v1)
    return app


async def _noop() -> None:
    return None
