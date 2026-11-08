"""Probe kesehatan layanan tujuan di latar. `GET /api/v1/health` membaca snapshot, bukan memanggil per permintaan."""

from __future__ import annotations

import asyncio
from typing import Any

from astria_common.component import Check
from structlog import get_logger

from astria_api.upstream import Upstreams

log = get_logger(__name__)

HIJAU, KUNING, MERAH = "hijau", "kuning", "merah"
_FROM_STATUS = {"ok": HIJAU, "degraded": KUNING, "down": MERAH}


def overall(statuses: dict[str, str]) -> str:
    values = set(statuses.values())
    if MERAH in values:
        return MERAH
    if KUNING in values or "belum_dicek" in values:
        return KUNING
    return HIJAU


class UpstreamProbe:
    """Komponen tidak wajib: me-restart api tidak memperbaiki layanan lain, jadi /ready tidak bergantung padanya."""

    name = "upstream_probe"
    required = False

    def __init__(self, upstreams: Upstreams, interval: float = 10.0) -> None:
        self._upstreams = upstreams
        self._interval = interval
        self._status: dict[str, str] = {n: "belum_dicek" for n in upstreams.names()}
        self._task: asyncio.Task[None] | None = None

    def snapshot(self) -> dict[str, str]:
        return dict(self._status)

    async def probe_once(self) -> None:
        async def one(name: str) -> tuple[str, str]:
            try:
                resp = await self._upstreams.get(name).http.get("/health", timeout=2.0)
                if resp.status_code >= 500 and resp.status_code != 503:
                    return name, MERAH
                body: Any = resp.json()
                return name, _FROM_STATUS.get(body.get("status"), KUNING) if isinstance(body, dict) else KUNING
            except Exception:  # noqa: BLE001 - layanan tak terjangkau = merah
                return name, MERAH

        results = await asyncio.gather(*(one(n) for n in self._upstreams.names()))
        self._status = dict(results)

    async def _loop(self) -> None:
        while True:
            await self.probe_once()
            await asyncio.sleep(self._interval)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="upstream-probe")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()

    async def check(self) -> Check:
        state = overall(self._status)
        if state == HIJAU:
            return Check("ok")
        bad = sorted(n for n, s in self._status.items() if s != HIJAU)
        return Check("degraded", "layanan bermasalah: " + ", ".join(bad))
