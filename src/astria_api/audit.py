"""Penulis audit sinkron untuk aksi berisiko (hibrida, keputusan pemilik audit#2).

- `before`: ditulis sebelum aksi; gagal = `AuditUnavailable` (503) dan aksi tidak boleh jalan (fail-closed).
- `after`: ditulis setelah aksi; gagal tidak membatalkan aksi. Catatan masuk antrean di memori (dibatasi) dan
  dicoba ulang di latar. Antrean hilang bila proses restart (batasan tanpa basis data; lihat note api, Sisa).
"""

from __future__ import annotations

import asyncio
import collections
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from astria_common.audit_client import AuditUnavailable
from astria_common.component import Check
from prometheus_client import Gauge
from structlog import get_logger

log = get_logger(__name__)

AUDIT_PENDING = Gauge("astria_api_audit_pending", "Catatan audit penutup yang menunggu terkirim")


class AuditSink(Protocol):
    async def record(self, record: Mapping[str, Any], *, act: dict[str, Any] | None = None) -> Any: ...


def build_record(
    *,
    key: str,
    actor: str,
    actor_type: str,
    action: str,
    target_type: str,
    target_id: str,
    via: str,
    payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "idempotency_key": key[:200],
        "occurred_at": datetime.now(UTC).isoformat(),
        "actor": actor[:64],
        "actor_type": actor_type,
        "action": action,
        "target_type": target_type,
        "target_id": (target_id or "-")[:200],
        "via": via,
        "payload": dict(payload or {}),
    }


class AuditWriter:
    """Komponen: menjaga antrean catatan penutup dan mencobanya lagi."""

    name = "audit_writer"
    required = False

    def __init__(self, sink: AuditSink, *, max_pending: int = 1000, retry_seconds: float = 5.0) -> None:
        self._sink = sink
        self._pending: collections.deque[tuple[dict[str, Any], dict[str, Any] | None]] = collections.deque(
            maxlen=max_pending
        )
        self._retry_seconds = retry_seconds
        self._task: asyncio.Task[None] | None = None

    @property
    def pending(self) -> int:
        return len(self._pending)

    async def before(self, record: Mapping[str, Any], *, act: dict[str, Any] | None = None) -> None:
        try:
            await self._sink.record(record, act=act)
        except AuditUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - apa pun kegagalan sink berarti aksi tidak boleh jalan
            raise AuditUnavailable(type(exc).__name__) from exc

    async def after(self, record: Mapping[str, Any], *, act: dict[str, Any] | None = None) -> None:
        try:
            await self._sink.record(record, act=act)
        except Exception as exc:  # noqa: BLE001
            log.warning("audit_penutup_tertunda", error=type(exc).__name__, action=record.get("action"))
            self._pending.append((dict(record), act))
            AUDIT_PENDING.set(len(self._pending))

    async def flush(self) -> None:
        for _ in range(len(self._pending)):
            record, act = self._pending[0]
            try:
                await self._sink.record(record, act=act)
            except Exception:  # noqa: BLE001 - dicoba lagi pada putaran berikutnya
                return
            self._pending.popleft()
            AUDIT_PENDING.set(len(self._pending))

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._retry_seconds)
            await self.flush()

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="audit-flush")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()

    async def check(self) -> Check:
        return Check("ok") if not self._pending else Check("degraded", f"{len(self._pending)} catatan audit tertunda")
