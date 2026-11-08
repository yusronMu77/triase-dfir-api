"""Sesi dan otorisasi.

Alur tiap permintaan dasbor: cookie -> introspeksi identity (cache singkat) -> pembatas laju per pengguna ->
pemeriksaan izin RBAC (`permissions.GRANTS`). Urutan itu disengaja: pembatas laju berjalan sebelum keputusan
izin supaya penebakan rute terlarang tetap dibatasi.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from prometheus_client import Counter
from structlog import get_logger

from astria_api.cache import TTLCache
from astria_api.errors import forbidden, too_many, unauthenticated, upstream_failed
from astria_api.permissions import Perm, allows
from astria_api.upstream import Actor, Upstream

log = get_logger(__name__)

AUTHZ_DENIED = Counter("astria_api_authz_denied_total", "Permintaan ditolak otorisasi", ["perm"])
RATE_LIMITED = Counter("astria_api_rate_limited_total", "Permintaan ditolak pembatas laju", ["bucket"])

INTROSPECT_PATH = "/internal/v1/sessions/introspect"


def session_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class Session:
    user_id: str
    roles: tuple[str, ...]
    session_id: str | None
    reauth_at: str | None
    token_hash: str

    @property
    def actor(self) -> Actor:
        return Actor(sub=self.user_id, roles=self.roles, session_id=self.session_id)


class SessionStore:
    """Introspeksi sesi ke identity dengan cache per `sha256(token)`; dibuang saat `identity.revoked`."""

    def __init__(self, identity: Upstream, ttl: float, *, clock: Callable[[], float] | None = None) -> None:
        self._identity = identity
        self._cache: TTLCache[str, Session] = TTLCache(ttl, **({"clock": clock} if clock else {}))

    async def resolve(self, token: str) -> Session:
        key = session_hash(token)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        data = await self._identity.json("POST", INTROSPECT_PATH, json={"token": token})
        if not isinstance(data, dict):
            raise upstream_failed("identity")
        if data.get("active") is not True:
            raise unauthenticated()
        user_id = data.get("user_id")
        roles = data.get("roles")
        if not isinstance(user_id, str) or not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise upstream_failed("identity")
        session = Session(
            user_id=user_id,
            roles=tuple(roles),
            session_id=data.get("session_id") if isinstance(data.get("session_id"), str) else None,
            reauth_at=data.get("reauth_at") if isinstance(data.get("reauth_at"), str) else None,
            token_hash=key,
        )
        self._cache.set(key, session)
        return session

    def forget(self, token: str) -> None:
        self._cache.pop(session_hash(token))

    def revoke_user(self, user_id: str) -> int:
        return self._cache.drop_where(lambda s: s.user_id == user_id)

    def revoke_session(self, session_id: str) -> int:
        return self._cache.drop_where(lambda s: s.session_id == session_id)


def authorize(perm: Perm) -> Callable[[Request], Awaitable[Session]]:
    """Dependensi rute: wajib sesi sah dan izin `perm`. Setiap rute `/api/v1` (kecuali yang publik) memakainya;
    `routing.assert_all_routes_protected` menggagalkan startup bila ada rute tanpa kebijakan."""

    async def dependency(request: Request) -> Session:
        state: Any = request.app.state
        token = request.cookies.get(state.settings.cookie_name)
        if not token:
            raise unauthenticated()
        session = await state.sessions.resolve(token)
        retry = state.user_limiter.take(f"user:{session.user_id}")
        if retry:
            RATE_LIMITED.labels("user").inc()
            raise too_many(retry)
        if not allows(session.roles, perm):
            AUTHZ_DENIED.labels(perm.value).inc()
            log.warning("rbac_ditolak", user_id=session.user_id, perm=perm.value, route=request.scope["route"].path)
            raise forbidden()
        request.state.session = session
        return session

    dependency.astria_perm = perm  # type: ignore[attr-defined]
    return dependency
