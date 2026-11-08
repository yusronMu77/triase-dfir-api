"""Health publik dan SSE."""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.sse import EventSourceResponse, ServerSentEvent
from pydantic import BaseModel
from structlog import get_logger

from astria_api.auth import Session, authorize
from astria_api.errors import ERROR_RESPONSES, ApiError
from astria_api.events import EventHub, Subscription
from astria_api.health import overall
from astria_api.permissions import Perm
from astria_api.routing import public

log = get_logger(__name__)
router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    layanan: dict[str, str]
    audit_tertunda: int


@router.get(
    "/health", response_model=HealthResponse, tags=["health"], summary="Status ringkas (publik, tanpa detail internal)"
)
@public
async def health(request: Request) -> JSONResponse:
    state: Any = request.app.state
    layanan = state.probe.snapshot()
    body = {"status": overall(layanan), "layanan": layanan, "audit_tertunda": state.audit.pending}
    return JSONResponse(body)


async def subscribe_stream(
    request: Request, session: Annotated[Session, Depends(authorize(Perm.STREAM_READ))]
) -> AsyncIterator[Subscription]:
    """Mendaftar sebelum respons dimulai, supaya batas koneksi menjadi 429 (bukan galat di tengah aliran)."""
    hub: EventHub = request.app.state.hub
    sub = hub.subscribe(session.user_id, session.session_id, session.roles)
    try:
        yield sub
    finally:
        hub.unsubscribe(sub)


@router.get(
    "/stream",
    response_class=EventSourceResponse,
    tags=["stream"],
    summary="Status real-time (SSE): hanya jenis, ID, dan status",
    responses=ERROR_RESPONSES,
)
async def stream(
    request: Request,
    session: Annotated[Session, Depends(authorize(Perm.STREAM_READ))],
    sub: Annotated[Subscription, Depends(subscribe_stream)],
) -> AsyncIterator[ServerSentEvent]:
    state: Any = request.app.state
    token = request.cookies.get(state.settings.cookie_name, "")
    counter = itertools.count(1)
    check_every = state.settings.sse_session_check_seconds
    loop = asyncio.get_running_loop()
    next_check = loop.time() + check_every
    try:
        # Klien yang menyambung ulang (Last-Event-ID) mendapat sinyal "ambil ulang"; api tidak menyimpan riwayat.
        if request.headers.get("last-event-id"):
            yield ServerSentEvent(data={"type": "resync"}, event="resync", id=str(next(counter)))
        while True:
            if await request.is_disconnected():
                return
            try:
                event = await asyncio.wait_for(sub.queue.get(), timeout=1.0)
            except TimeoutError:
                event = False
            if event is None:  # dicabut (identity.revoked) atau logout
                return
            if sub.resync:
                sub.resync = False
                yield ServerSentEvent(data={"type": "resync"}, event="resync", id=str(next(counter)))
            if event:
                yield ServerSentEvent(data=event.payload(), event=event.type, id=str(next(counter)))
            if loop.time() >= next_check:
                next_check = loop.time() + check_every
                try:
                    await state.sessions.resolve(token)
                except ApiError:
                    return
    finally:
        state.hub.unsubscribe(sub)
