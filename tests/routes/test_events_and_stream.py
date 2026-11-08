"""Hub event, pemfilteran peran, pencabutan, batas koneksi, dan aliran SSE."""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import pytest

from astria_api.errors import ApiError
from astria_api.events import EventHub, EventRouter, FeedEvent, NatsEventSource


def hub_with(roles_by_user: dict[str, tuple[str, ...]]):
    hub = EventHub(max_per_user=2)
    return hub, {u: hub.subscribe(u, f"ses_{u}", r) for u, r in roles_by_user.items()}


def drain(sub: Any) -> list[FeedEvent]:
    out = []
    while not sub.queue.empty():
        item = sub.queue.get_nowait()
        if item is not None:
            out.append(item)
    return out


def test_events_are_filtered_by_role_on_the_server() -> None:
    hub, subs = hub_with({"a": ("analis",), "p": ("pimpinan",), "d": ("dfir",), "x": ("admin",)})
    hub.publish(FeedEvent("ticket.updated", "IC-1", "ditinjau"))
    hub.publish(FeedEvent("digest.published", "d1"))
    hub.publish(FeedEvent("job.progress", "j1", "jalan"))
    hub.publish(FeedEvent("config.changed", "x"))  # tidak pernah ke klien
    assert [e.type for e in drain(subs["a"])] == ["ticket.updated", "digest.published", "job.progress"]
    assert [e.type for e in drain(subs["p"])] == ["digest.published"]  # pimpinan: hanya digest
    assert [e.type for e in drain(subs["d"])] == ["ticket.updated", "digest.published"]
    assert [e.type for e in drain(subs["x"])] == ["digest.published", "job.progress"]


def test_payload_is_minimal() -> None:
    assert FeedEvent("ticket.updated", "IC-1", "ditinjau").payload() == {
        "type": "ticket.updated",
        "id": "IC-1",
        "status": "ditinjau",
    }
    assert FeedEvent("digest.published", "d1").payload() == {"type": "digest.published", "id": "d1"}


def test_connection_limit_per_user() -> None:
    hub = EventHub(max_per_user=2)
    first, _second = hub.subscribe("u", None, ("analis",)), hub.subscribe("u", None, ("analis",))
    with pytest.raises(ApiError) as exc:
        hub.subscribe("u", None, ("analis",))
    assert exc.value.status == 429
    hub.unsubscribe(first)
    hub.subscribe("u", None, ("analis",))
    hub.subscribe("other", None, ("analis",))


def test_revoke_closes_matching_streams_only() -> None:
    hub, subs = hub_with({"a": ("analis",), "b": ("analis",)})
    assert hub.close_user("a") == 1
    assert subs["a"].queue.get_nowait() is None and subs["b"].queue.empty()
    assert hub.close_session("ses_b") == 1


def test_slow_client_gets_resync_instead_of_unbounded_memory() -> None:
    hub, subs = hub_with({"a": ("analis",)})
    for i in range(150):
        hub.publish(FeedEvent("ticket.updated", f"IC-{i}"))
    assert subs["a"].queue.qsize() == 100 and subs["a"].resync is True


def test_router_handles_loose_or_hostile_envelopes_safely() -> None:
    hub, subs = hub_with({"a": ("analis",)})
    router = EventRouter(hub, revoke_user=lambda u: None, revoke_session=lambda s: None, invalidate=lambda s: None)
    for raw in (
        b"bukan json",
        b"[]",
        b"{}",
        json.dumps({"type": 5, "data": {}}).encode(),
        {"type": "ticket.updated", "data": {}},
        {"type": "x.y", "data": {"card_id": "IC-1"}},
    ):
        router.handle(raw)
    assert drain(subs["a"]) == []
    router.handle(
        json.dumps(
            {"id": "e1", "type": "ticket.updated", "data": {"card_id": "IC-9", "status": "baru", "isi": "x"}}
        ).encode()
    )
    assert [e.payload() for e in drain(subs["a"])] == [{"type": "ticket.updated", "id": "IC-9", "status": "baru"}]


def test_identity_revoked_by_session_id_and_config_scopes() -> None:
    seen: dict[str, list[str]] = {"user": [], "session": [], "scope": []}
    hub = EventHub()
    router = EventRouter(
        hub, revoke_user=seen["user"].append, revoke_session=seen["session"].append, invalidate=seen["scope"].append
    )
    router.handle({"type": "identity.revoked", "data": {"user_id": "usr_1", "session_id": "ses_1"}})
    router.handle({"type": "config.changed", "data": {"scope": "channel_policy"}})
    router.handle({"type": "config.changed", "data": {}})
    assert seen == {"user": ["usr_1"], "session": ["ses_1"], "scope": ["channel_policy", "all"]}


@pytest.mark.anyio
async def test_nats_source_forwards_message_data_to_router() -> None:
    received: list[bytes] = []

    class Router:
        def handle(self, raw: bytes) -> None:
            received.append(raw)

    source = NatsEventSource(bus=object(), router=Router())  # type: ignore[arg-type]
    msg = type("Msg", (), {"data": b'{"type":"ticket.updated"}'})()
    await source._on_message(msg)
    assert received == [b'{"type":"ticket.updated"}'] and source.received == 1
    assert (await source.check()).status == "degraded"


# --- aliran SSE sungguhan ---


def _publish_later(env: Any, events: list[dict[str, Any]], delay: float = 0.3) -> threading.Thread:
    def run() -> None:
        time.sleep(delay)
        for event in events:
            env.app.state.events.handle(event)
            time.sleep(0.05)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _read_stream(env: Any, token: str, headers: dict[str, str] | None = None) -> tuple[int, list[str]]:
    lines: list[str] = []
    with env.as_user(token).stream("GET", "/api/v1/stream", headers=headers or {}) as response:
        for line in response.iter_lines():
            lines.append(line)
    return response.status_code, lines


def test_stream_delivers_role_filtered_events_and_closes_on_revocation(env: Any) -> None:
    thread = _publish_later(
        env,
        [
            {"type": "ticket.updated", "data": {"card_id": "IC-1", "status": "ditinjau"}},
            {"type": "digest.published", "data": {"digest_id": "d1"}},
            {"type": "identity.revoked", "data": {"user_id": "usr_pim"}},
        ],
    )
    status, lines = _read_stream(env, "tok-pimpinan")
    thread.join()
    assert status == 200
    data = [json.loads(line[6:]) for line in lines if line.startswith("data:")]
    assert data == [{"type": "digest.published", "id": "d1"}]  # pimpinan tidak menerima event tiket


def test_stream_for_analyst_gets_ticket_events_with_event_names(env: Any) -> None:
    thread = _publish_later(
        env,
        [
            {"type": "ticket.updated", "data": {"card_id": "IC-1", "status": "ditinjau"}},
            {"type": "identity.revoked", "data": {"session_id": "ses_usr_ana"}},
        ],
    )
    _status, lines = _read_stream(env, "tok-analis")
    thread.join()
    assert "event: ticket.updated" in lines
    assert any('"id":"IC-1"' in line.replace(" ", "") for line in lines if line.startswith("data:"))


def test_stream_reconnect_gets_resync_signal(env: Any) -> None:
    thread = _publish_later(env, [{"type": "identity.revoked", "data": {"user_id": "usr_ana"}}])
    _status, lines = _read_stream(env, "tok-analis", {"Last-Event-ID": "7"})
    thread.join()
    assert "event: resync" in lines


def test_stream_requires_session_and_limits_connections(env: Any) -> None:
    env.client.cookies.clear()
    assert env.client.get("/api/v1/stream").status_code == 401
    hub = env.app.state.hub
    for _ in range(5):
        hub.subscribe("usr_ana", None, ("analis",))
    assert env.as_user("tok-analis").get("/api/v1/stream").status_code == 429


def test_stream_closes_when_session_dies_at_recheck(tmp_path: Any) -> None:
    from conftest import make_env

    env = make_env(tmp_path, sse_session_check_seconds=0.2)
    env.world.session("t", "usr_a", ["analis"], session_id="ses_a")
    env.app.state.sessions._cache._ttl = 0.01
    killer = threading.Timer(0.1, lambda: env.world.sessions.update({"t": {"active": False}}))
    killer.start()
    started = time.time()
    status, _lines = _read_stream(env, "t")
    assert status == 200 and time.time() - started < 5
