"""Klien HTTP ke layanan lain: token layanan dengan `act`, batas waktu per upstream, GET diulang satu kali,
dan pemetaan galat seragam tanpa membocorkan isi respons upstream (note api bagian 5.5)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from astria_common.errors import AstriaError
from astria_common.http import make_client
from prometheus_client import Histogram

from astria_api.errors import (
    ApiError,
    upstream_failed,
    upstream_timeout,
    upstream_unavailable,
)

UPSTREAM_SECONDS = Histogram("astria_api_upstream_seconds", "Lama panggilan api ke layanan lain", ["service", "result"])

RETRY_STATUS = {502, 503, 504}


class TokenSource(Protocol):
    async def auth_headers(self, audience: str, act: dict[str, Any] | None = None) -> dict[str, str]: ...


@dataclass(frozen=True)
class Actor:
    """Pengguna yang memicu panggilan (klaim `act` pada token layanan)."""

    sub: str
    roles: tuple[str, ...]
    session_id: str | None = None

    def act(self) -> dict[str, Any]:
        act: dict[str, Any] = {"sub": self.sub, "roles": list(self.roles)}
        if self.session_id:
            act["session_id"] = self.session_id
        return act


def _upstream_code(resp: httpx.Response) -> str | None:
    try:
        code = resp.json()["error"]["code"]
    except ValueError, KeyError, TypeError:
        return None
    return code if isinstance(code, str) and code.replace("_", "").isalnum() and len(code) <= 64 else None


def map_status(service: str, resp: httpx.Response) -> ApiError:
    """Petakan respons galat upstream ke galat api. Isi respons tidak pernah diteruskan."""
    status = resp.status_code
    if status in (400, 422):
        return ApiError("VALIDASI_GAGAL", "permintaan tidak valid", 400)
    if status == 403:
        return ApiError("DILARANG", "aksi ini tidak diizinkan", 403)
    if status == 404:
        return ApiError("TIDAK_DITEMUKAN", "data tidak ditemukan", 404)
    if status == 409:
        return ApiError(_upstream_code(resp) or "KONFLIK", "data berubah atau konflik; muat ulang", 409)
    if status == 410:
        return ApiError("KEDALUWARSA", "sudah kedaluwarsa", 410)
    if status == 429:
        retry = resp.headers.get("Retry-After", "")
        return ApiError(
            "TERLALU_BANYAK", "terlalu banyak permintaan", 429, {"Retry-After": retry} if retry.isdigit() else None
        )
    if status == 503:
        return upstream_unavailable(service)
    if status == 504:
        return upstream_timeout(service)
    return upstream_failed(service)


class Upstream:
    def __init__(self, name: str, http: httpx.AsyncClient, tokens: TokenSource) -> None:
        self.name = name
        self.audience = f"svc:{name}"
        self.http = http
        self._tokens = tokens

    async def send(
        self,
        method: str,
        path: str,
        *,
        actor: Actor | None = None,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
        content: Any = None,
        headers: Mapping[str, str] | None = None,
        ok_statuses: frozenset[int] = frozenset(),
        timeout: float | None = None,
    ) -> httpx.Response:
        """Kirim permintaan; status >= 400 menjadi `ApiError`. Hanya GET yang diulang (satu kali)."""
        attempts = 2 if method == "GET" else 1
        started = time.perf_counter()
        for attempt in range(attempts):
            last = attempt + 1 == attempts
            try:
                auth = await self._tokens.auth_headers(self.audience, actor.act() if actor else None)
                resp = await self.http.request(
                    method,
                    path,
                    json=json,
                    params={k: v for k, v in (params or {}).items() if v is not None},
                    content=content,
                    headers={**(headers or {}), **auth},
                    **({"timeout": timeout} if timeout is not None else {}),
                )
            except httpx.TimeoutException:
                if last:
                    UPSTREAM_SECONDS.labels(self.name, "timeout").observe(time.perf_counter() - started)
                    raise upstream_timeout(self.name) from None
            except httpx.TransportError, AstriaError, httpx.HTTPError:
                if last:
                    UPSTREAM_SECONDS.labels(self.name, "unavailable").observe(time.perf_counter() - started)
                    raise upstream_unavailable(self.name) from None
            else:
                if resp.status_code in RETRY_STATUS and not last:
                    pass
                else:
                    break
            await asyncio.sleep(0.05)
        UPSTREAM_SECONDS.labels(self.name, "ok" if resp.status_code < 400 else "error").observe(
            time.perf_counter() - started
        )
        if resp.status_code >= 400 and resp.status_code not in ok_statuses:
            raise map_status(self.name, resp)
        return resp

    async def json(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = await self.send(method, path, **kwargs)
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            raise upstream_failed(self.name) from None

    async def aclose(self) -> None:
        await self.http.aclose()


class Upstreams:
    """Kumpulan klien per layanan. `clients` boleh diisi (uji) untuk mengganti transport."""

    def __init__(
        self,
        urls: Mapping[str, str],
        tokens: TokenSource,
        *,
        timeout: float = 2.0,
        clients: Mapping[str, httpx.AsyncClient] | None = None,
    ) -> None:
        self._by_name = {
            name: Upstream(name, (clients or {}).get(name) or make_client(url, timeout=timeout), tokens)
            for name, url in urls.items()
        }

    def __getattr__(self, name: str) -> Upstream:
        try:
            return self.__dict__["_by_name"][name]
        except KeyError:
            raise AttributeError(name) from None

    def get(self, name: str) -> Upstream:
        return self._by_name[name]

    def names(self) -> list[str]:
        return list(self._by_name)

    async def aclose(self) -> None:
        for upstream in self._by_name.values():
            await upstream.aclose()
