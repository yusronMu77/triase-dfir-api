"""Event masuk: invalidasi cache, pencabutan sesi, dan fan-out SSE dengan pemfilteran peran di server.

`contracts` belum memuat skema event-event ini, dan `astria_common.consumer.Consumer` butuh basis data, jadi
`api` memakai langganan JetStream sendiri (`NatsEventSource`) dan membaca amplop secara longgar: hanya `type`
dan `data` yang dipakai, yang tak dikenal dibuang. Pemrosesan (`EventRouter.handle`) idempoten: membuang cache
dua kali tidak merusak apa pun.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import orjson
from astria_common.component import Check
from prometheus_client import Gauge
from structlog import get_logger

from astria_api.errors import ApiError
from astria_api.permissions import EVENT_PERMS, allows

log = get_logger(__name__)

SSE_CONNECTIONS = Gauge("astria_api_sse_connections", "Koneksi SSE aktif")

# Jenis event yang dilanggan dari JetStream (subjek astria.<type>).
SUBSCRIBED_TYPES = (
    "identity.revoked",
    "config.changed",
    "ticket.updated",
    "ticket.sla_breached",
    "job.progress",
    "digest.published",
)
_ID_KEYS = ("card_id", "job_id", "digest_id", "id")


@dataclass(frozen=True)
class FeedEvent:
    type: str
    id: str
    status: str | None = None

    def payload(self) -> dict[str, str]:
        return {"type": self.type, "id": self.id} | ({"status": self.status} if self.status else {})


@dataclass(eq=False)  # identitas objek: dipakai sebagai elemen set
class Subscription:
    user_id: str
    session_id: str | None
    roles: tuple[str, ...]
    queue: asyncio.Queue[FeedEvent | None] = field(default_factory=lambda: asyncio.Queue(maxsize=100))
    resync: bool = False

    def close(self) -> None:
        # Sentinel menutup aliran; bila antrean penuh, kosongkan dulu agar sentinel pasti masuk.
        while True:
            try:
                self.queue.put_nowait(None)
                return
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    self.queue.get_nowait()


class EventHub:
    def __init__(self, max_per_user: int = 5) -> None:
        self._max_per_user = max_per_user
        self._subs: set[Subscription] = set()

    def subscribe(self, user_id: str, session_id: str | None, roles: tuple[str, ...]) -> Subscription:
        if sum(1 for s in self._subs if s.user_id == user_id) >= self._max_per_user:
            raise ApiError("TERLALU_BANYAK", "batas koneksi SSE per pengguna tercapai", 429, {"Retry-After": "5"})
        sub = Subscription(user_id, session_id, roles)
        self._subs.add(sub)
        SSE_CONNECTIONS.set(len(self._subs))
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        self._subs.discard(sub)
        SSE_CONNECTIONS.set(len(self._subs))

    def publish(self, event: FeedEvent) -> int:
        """Kirim ke pelanggan yang perannya berhak menerima jenis ini. Mengembalikan jumlah penerima."""
        perm = EVENT_PERMS.get(event.type)
        if perm is None:
            return 0
        delivered = 0
        for sub in self._subs:
            if not allows(sub.roles, perm):
                continue
            try:
                sub.queue.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                sub.resync = True  # klien lambat: kirim sinyal "ambil ulang", bukan replay
        return delivered

    def close_user(self, user_id: str) -> int:
        victims = [s for s in self._subs if s.user_id == user_id]
        for sub in victims:
            sub.close()
        return len(victims)

    def close_session(self, session_id: str) -> int:
        victims = [s for s in self._subs if s.session_id == session_id]
        for sub in victims:
            sub.close()
        return len(victims)

    def __len__(self) -> int:
        return len(self._subs)


class EventRouter:
    """Menerjemahkan event masuk ke efek di api: invalidasi cache, pencabutan sesi, atau publikasi SSE."""

    def __init__(
        self,
        hub: EventHub,
        *,
        revoke_user: Callable[[str], Any],
        revoke_session: Callable[[str], Any],
        invalidate: Callable[[str], Any],
    ) -> None:
        self._hub = hub
        self._revoke_user = revoke_user
        self._revoke_session = revoke_session
        self._invalidate = invalidate

    def handle(self, raw: bytes | dict[str, Any]) -> None:
        try:
            envelope = orjson.loads(raw) if isinstance(raw, bytes) else raw
        except orjson.JSONDecodeError:
            log.warning("event_tidak_terbaca")
            return
        if not isinstance(envelope, dict):
            return
        etype, data = envelope.get("type"), envelope.get("data")
        if not isinstance(etype, str) or not isinstance(data, dict):
            return
        if etype == "identity.revoked":
            user_id, session_id = data.get("user_id"), data.get("session_id")
            if isinstance(user_id, str):
                self._revoke_user(user_id)
                self._hub.close_user(user_id)
            if isinstance(session_id, str):
                self._revoke_session(session_id)
                self._hub.close_session(session_id)
        elif etype == "config.changed":
            scope = data.get("scope")
            self._invalidate(scope if isinstance(scope, str) else "all")
        elif etype in EVENT_PERMS:
            event_id = next((str(data[k]) for k in _ID_KEYS if isinstance(data.get(k), str)), None)
            if event_id is None:
                return
            status = data.get("status")
            self._hub.publish(FeedEvent(etype, event_id, status if isinstance(status, str) else None))


class NatsEventSource:
    """Komponen: langganan JetStream ephemeral (hanya pesan baru) untuk jenis di `SUBSCRIBED_TYPES`.

    Bila NATS belum siap, mencoba lagi di latar; `api` tetap melayani (cache dibatasi TTL, klien SSE memakai GET).
    """

    name = "event_feed"
    required = False

    def __init__(self, bus: Any, router: EventRouter) -> None:
        self._bus = bus
        self._router = router
        self._task: asyncio.Task[None] | None = None
        self._subscribed = False
        self.received = 0

    async def _on_message(self, msg: Any) -> None:
        self.received += 1
        self._router.handle(msg.data)

    async def _run(self) -> None:
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

        delay = 1.0
        while not self._subscribed:
            try:
                await self._bus.wait_connected()
                config = ConsumerConfig(deliver_policy=DeliverPolicy.NEW, ack_policy=AckPolicy.NONE)
                for etype in SUBSCRIBED_TYPES:
                    await self._bus.js.subscribe(
                        f"{self._bus.prefix}.{etype}", cb=self._on_message, stream=self._bus.stream, config=config
                    )
                self._subscribed = True
                log.info("langganan_event_siap", types=list(SUBSCRIBED_TYPES))
            except Exception as exc:  # noqa: BLE001 - dicoba ulang; status terlihat di /health
                log.warning("langganan_event_gagal", error=type(exc).__name__, retry_in=delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="event-feed")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()

    async def check(self) -> Check:
        return Check("ok") if self._subscribed else Check("degraded", "belum berlangganan event")
