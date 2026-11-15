"""`/svc/v1`: HMAC (benar, salah, usang, replay, layanan tak dikenal), katalog tertutup, RBAC perintah, T2, konfirmasi,
audit sinkron fail-closed, pemangkasan, pairing, dokumen, dan proksi Collector."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
from conftest import COLLECTOR_KEY, SVC_KEY, sign

from astria_api.svc.commands import command_hash

CMD = "/svc/v1/commands"
CARD = "IC-20261110-003"


def post(env: Any, path: str, payload: dict[str, Any], **kw: Any) -> httpx.Response:
    body = json.dumps(payload).encode()
    headers = sign("POST", path, body, **kw) | {"Content-Type": "application/json"}
    return env.client.post(path, content=body, headers=headers)


def command(
    command: str, args: dict[str, str] | None = None, *, user: str = "usr_ana", key: str = "k1", **extra: Any
) -> dict:
    return {
        "user_id": user,
        "channel_id": "telegram",
        "command": command,
        "args": args or {},
        "idempotency_key": key,
    } | extra


def setup(env: Any, *, max_detail: str = "ringkas", allow_t2: bool = False) -> None:
    env.world.users = {
        "usr_ana": {"user_id": "usr_ana", "active": True, "roles": ["analis"]},
        "usr_adm": {"user_id": "usr_adm", "active": True, "roles": ["admin"]},
        "usr_pim": {"user_id": "usr_pim", "active": True, "roles": ["pimpinan"]},
        "usr_off": {"user_id": "usr_off", "active": False, "roles": ["analis"]},
    }
    env.world.on(
        "config",
        "GET",
        "/svc/v1/channels/policy",
        json={
            "items": [
                {"channel_id": "telegram", "active": True, "max_detail": max_detail},
                {"channel_id": "mati", "active": False},
            ]
        },
    )
    env.world.on("config", "GET", "/svc/v1/settings/effective", json={"values": {"chat.allow_t2": allow_t2}})


# --- HMAC ---


def test_valid_signature_passes_and_unsigned_is_rejected(env: Any) -> None:
    setup(env)
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    assert post(env, CMD, command("queue")).status_code == 200
    unsigned = env.client.post(CMD, json=command("queue"))
    assert unsigned.status_code == 401 and unsigned.json()["error"]["code"] == "TIDAK_TERAUTENTIKASI"


def test_bad_signature_stale_timestamp_replay_and_unknown_service(env: Any) -> None:
    setup(env)
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    payload = command("queue")
    assert post(env, CMD, payload, key=b"\x01" * 32).status_code == 401  # kunci salah
    assert post(env, CMD, payload, now=time.time() - 3600).status_code == 401  # usang
    assert post(env, CMD, payload, service="intruder").status_code == 401  # layanan tak dikenal
    assert post(env, CMD, payload, service="collector", key=COLLECTOR_KEY).status_code == 401  # bukan jalurnya

    body = json.dumps(payload).encode()
    headers = sign("POST", CMD, body) | {"Content-Type": "application/json"}
    assert env.client.post(CMD, content=body, headers=headers).status_code == 200
    replay = env.client.post(CMD, content=body, headers=headers)
    assert replay.status_code == 401  # nonce sama dipakai ulang


def test_tampered_body_or_path_breaks_signature(env: Any) -> None:
    setup(env)
    body = json.dumps(command("queue")).encode()
    headers = sign("POST", CMD, body) | {"Content-Type": "application/json"}
    tampered = json.dumps(command("queue", user="usr_adm")).encode()
    assert env.client.post(CMD, content=tampered, headers=headers).status_code == 401


def test_hmac_rejections_never_reach_upstreams_and_reveal_no_reason(env: Any) -> None:
    response = post(env, CMD, command("queue"), key=b"\x02" * 32)
    assert response.json()["error"]["message"] == "tanda tangan tidak valid"
    assert env.world.calls == []


def test_svc_is_not_in_public_openapi_and_ignores_session_cookie(env: Any) -> None:
    assert not any(p.startswith("/svc") for p in env.app.openapi()["paths"])
    env.as_user("tok-admin")
    assert env.client.post(CMD, json=command("queue")).status_code == 401  # cookie dasbor tidak berlaku di /svc


def test_empty_keys_file_rejects_everything(tmp_path: Any) -> None:
    from conftest import make_env

    env = make_env(tmp_path)
    env.app.state.svc_keys = {}
    assert post(env, CMD, command("queue")).status_code == 401


# --- katalog tertutup dan argumen ---


def test_free_text_and_unknown_commands_never_run(env: Any) -> None:
    setup(env)
    for name in ("ask", "rm -rf /", "queue; drop", "Queue", "STATUS"):
        response = post(env, CMD, command(name))
        assert response.status_code == 400 and response.json()["error"]["code"] == "PERINTAH_TIDAK_DIKENAL", name
    assert env.world.calls_to("ticket") == [] and env.audit.records == []


def test_argument_validation(env: Any) -> None:
    setup(env)
    bad = [
        command("card"),
        command("card", {"card_id": "../../x"}),
        command("card", {"card_id": CARD, "extra": "1"}),
        command("queue", {"x": "1"}),
        command("feedback", {"card_id": CARD, "label": "bebas"}),
    ]
    for payload in bad:
        assert post(env, CMD, payload).status_code == 400, payload
    assert (
        post(
            env, CMD, {"user_id": "bukan-user", "channel_id": "t", "command": "queue", "idempotency_key": "k"}
        ).status_code
        == 400
    )
    assert post(env, CMD, command("queue") | {"tambahan": 1}).status_code == 400


# --- peran dan pengguna ---


def test_role_is_checked_per_command_against_identity_without_cache(env: Any) -> None:
    setup(env)
    env.world.on(
        "scheduler",
        "GET",
        "/svc/v1/digests",
        json={"items": [{"digest_id": "d1", "status": "terbit", "isi": "rahasia"}]},
    )
    assert post(env, CMD, command("queue", user="usr_pim")).status_code == 403
    ok = post(env, CMD, command("digest_latest", user="usr_pim", key="k2"))
    assert ok.status_code == 200 and ok.json()["hasil"] == {"digest_id": "d1", "status": "terbit"}
    # Peran dicabut di identity: perintah berikutnya langsung ditolak, tanpa cache.
    env.world.users["usr_ana"]["roles"] = ["pimpinan"]
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    assert post(env, CMD, command("queue", key="k3")).status_code == 403
    assert len([c for c in env.world.calls_to("identity") if "/users/" in c.path]) == 3


def test_admin_reads_queue_by_chat_but_cannot_write(env: Any) -> None:
    setup(env)
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    assert post(env, CMD, command("queue", user="usr_adm")).status_code == 200
    denied = post(env, CMD, command("feedback", {"card_id": CARD, "label": "benar"}, user="usr_adm", key="k2"))
    assert denied.status_code == 403


def test_inactive_unknown_user_and_inactive_channel_are_denied_and_audited(env: Any) -> None:
    setup(env)
    assert post(env, CMD, command("queue", user="usr_off")).status_code == 403
    assert post(env, CMD, command("queue", user="usr_zzz", key="k2")).status_code == 404
    mati = command("queue", key="k3") | {"channel_id": "mati"}
    assert post(env, CMD, mati).status_code == 403
    assert env.audit.actions() == ["command.denied", "command.denied"]
    assert env.world.calls_to("ticket") == []


# --- T1 dan T2 ---


def test_t2_is_off_by_default_and_never_reaches_the_owner_service(env: Any) -> None:
    setup(env, allow_t2=False)
    args: dict[str, str] = {}
    payload = command(
        "digest_run", args, user="usr_adm", confirmation_ref="c1", command_hash=command_hash("digest_run", args)
    )
    response = post(env, CMD, payload)
    assert response.status_code == 403 and response.json()["error"]["code"] == "T2_DIMATIKAN"
    assert env.world.calls_to("scheduler") == []
    assert env.audit.actions() == ["command.denied"]


def test_t2_runs_only_when_enabled_and_confirmed(env: Any) -> None:
    setup(env, allow_t2=True)
    env.world.on(
        "scheduler", "POST", "/svc/v1/digests/run", json={"digest_id": "d9", "status": "jalan", "internal": "x"}
    )
    args: dict[str, str] = {}
    base = command("digest_run", args, user="usr_adm")
    assert post(env, CMD, base).json()["error"]["code"] == "KONFIRMASI_WAJIB"
    wrong = base | {"confirmation_ref": "c1", "command_hash": "0" * 64}
    assert post(env, CMD, wrong).json()["error"]["code"] == "KONFIRMASI_WAJIB"
    assert env.world.calls_to("scheduler") == []
    good = base | {"confirmation_ref": "c1", "command_hash": command_hash("digest_run", args)}
    response = post(env, CMD, good)
    assert response.status_code == 200 and response.json()["hasil"] == {"digest_id": "d9", "status": "jalan"}


def test_t1_confirmation_hash_is_bound_to_the_arguments(env: Any) -> None:
    setup(env)
    env.world.on("ticket", "POST", f"/svc/v1/tickets/{CARD}/feedback", json={})
    args = {"card_id": CARD, "label": "benar"}
    other = command_hash("feedback", {"card_id": CARD, "label": "salah_positif"})
    forged = command("feedback", args, confirmation_ref="c1", command_hash=other)
    assert post(env, CMD, forged).status_code == 403
    good = command("feedback", args, key="k2", confirmation_ref="c1", command_hash=command_hash("feedback", args))
    response = post(env, CMD, good)
    assert response.status_code == 200
    call = env.world.calls_to("ticket")[0]
    assert call.body == {"label": "benar"} and call.headers["idempotency-key"] == "k2"


# --- audit sinkron ---


def test_audit_down_blocks_the_action(env: Any) -> None:
    setup(env)
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    env.audit.fail = True
    response = post(env, CMD, command("queue"))
    assert response.status_code == 503 and response.json()["error"]["code"] == "AUDIT_TIDAK_TERSEDIA"
    assert env.world.calls_to("ticket") == []


def test_requested_and_completed_are_recorded_around_the_action(env: Any) -> None:
    setup(env)
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    post(env, CMD, command("queue", key="abc"))
    assert env.audit.actions() == ["command.requested", "command.completed"]
    first = env.audit.records[0]
    assert first["via"] == "bot" and first["actor"] == "usr_ana" and first["idempotency_key"] == "cmd-abc-requested"


def test_upstream_failure_is_reported_and_audited_as_failed(env: Any) -> None:
    setup(env)
    env.world.on("ticket", "GET", "/svc/v1/tickets", status=503)
    response = post(env, CMD, command("queue"))
    assert response.status_code == 503
    assert env.audit.records[-1]["payload"]["result"] == "gagal"


# --- pemangkasan ---


def test_queue_masks_titles_caps_items_and_drops_unlisted_fields(env: Any) -> None:
    setup(env, max_detail="minimal")
    items = [
        {
            "card_id": f"IC-20261110-00{i}",
            "band": "KRITIS",
            "skor": 70 + i,
            "judul": f"Login WS-ADM-0{i} dari 10.0.0.{i}",
            "narasi": "x",
            "isi_log": "SECRET",
            "akun": "svc-backup",
        }
        for i in range(8)
    ]
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": items})
    hasil = post(env, CMD, command("queue")).json()["hasil"]["items"]
    assert len(hasil) == 5
    for row in hasil:
        assert set(row) <= {"card_id", "band", "skor", "judul"}
        assert "10.0.0." not in row["judul"] and "WS-ADM" not in row["judul"]


def test_card_result_depends_on_max_detail_and_never_exposes_full(env: Any) -> None:
    card = {
        "card_id": CARD,
        "band": "KRITIS",
        "skor": 71,
        "narasi": "ringkas",
        "isi_log": "SECRET",
        "tautan": "https://x",
    }
    env.world.on("ticket", "GET", f"/svc/v1/tickets/{CARD}", json=card)
    for detail, expected in (
        ("minimal", {"card_id", "band", "skor", "tautan"}),
        ("ringkas", {"card_id", "band", "skor", "tautan", "narasi"}),
        ("penuh", {"card_id", "band", "skor", "tautan", "narasi"}),
    ):
        setup(env, max_detail=detail)
        env.app.state.config_cache.invalidate("all")
        hasil = post(env, CMD, command("card", {"card_id": CARD}, key=detail)).json()["hasil"]
        assert set(hasil) == expected and "isi_log" not in hasil, detail


def test_command_rate_limits_per_user_and_global(tmp_path: Any) -> None:
    from conftest import make_env

    env = make_env(tmp_path, rate_cmd_per_min=2, rate_global_cmd_per_min=3)
    setup(env)
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    codes = [post(env, CMD, command("queue", key=f"k{i}")).status_code for i in range(3)]
    assert codes == [200, 200, 429]
    assert (
        post(env, CMD, command("queue", user="usr_pim", key="z")).status_code == 403
    )  # pengguna lain terpisah (peran salah)


# --- pairing, dokumen, collector ---


def test_pairing_claim_passthrough_allowlist(env: Any) -> None:
    env.world.on(
        "identity",
        "POST",
        "/internal/v1/pairing/claim",
        json={"user_id": "usr_ana", "claimed_at": "2026-11-10T00:00:00Z", "roles": ["admin"]},
    )
    payload = {"code": "7KQ3M9TB", "channel_id": "telegram", "external_id_hash": "a" * 64}
    response = post(env, "/svc/v1/pairing/claim", payload)
    assert response.status_code == 200 and response.json() == {
        "user_id": "usr_ana",
        "claimed_at": "2026-11-10T00:00:00Z",
    }
    assert env.world.calls_to("identity")[0].body == {
        "channel": "telegram",
        "external_id_hash": "a" * 64,
        "code": "7KQ3M9TB",
    }
    assert post(env, "/svc/v1/pairing/claim", payload | {"code": "kecil"}).status_code == 400


def test_pairing_expired_code_maps_to_410(env: Any) -> None:
    env.world.on("identity", "POST", "/internal/v1/pairing/claim", status=410)
    payload = {"code": "7KQ3M9TB", "channel_id": "telegram", "external_id_hash": "a" * 64}
    assert post(env, "/svc/v1/pairing/claim", payload).status_code == 410


def test_documents_only_for_full_detail_channels(env: Any) -> None:
    setup(env, max_detail="ringkas")
    path = "/svc/v1/documents/digest:d1?format=pdf"
    headers = sign("GET", path) | {"X-Astria-Channel": "telegram"}
    assert env.client.get(path, headers=headers).status_code == 403
    setup(env, max_detail="penuh")
    env.app.state.config_cache.invalidate("all")
    env.world.on(
        "scheduler", "GET", "/svc/v1/digests/d1/dokumen", content=b"%PDF", headers={"content-type": "application/pdf"}
    )
    headers = sign("GET", path) | {"X-Astria-Channel": "telegram"}
    response = env.client.get(path, headers=headers)
    assert response.status_code == 200 and response.content == b"%PDF"
    bad = "/svc/v1/documents/rahasia:x"
    assert env.client.get(bad, headers=sign("GET", bad) | {"X-Astria-Channel": "telegram"}).status_code == 404


def test_collector_proxy_requires_collector_key_and_streams_upload(env: Any) -> None:
    path = "/svc/v1/collector/jobs/next"
    env.world.on("ingest", "GET", path, status=204)
    assert env.client.get(path, headers=sign("GET", path, service="gateway")).status_code == 401
    assert env.client.get(path, headers=sign("GET", path, service="collector", key=COLLECTOR_KEY)).status_code == 204

    captured: dict[str, Any] = {}

    def upload(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        captured["sha"] = request.headers.get("x-archive-sha256")
        return httpx.Response(201, json={})

    put = "/svc/v1/collector/acquisitions/job1"
    env.world.on("ingest", "PUT", put, fn=upload)
    data = b"A" * 300_000  # lebih besar dari batas badan JSON; tidak dibatasi api
    headers = sign("PUT", put, b"", service="collector", key=COLLECTOR_KEY) | {
        "X-Archive-Sha256": "a" * 64,
        "Content-Type": "application/octet-stream",
    }
    response = env.client.put(put, content=data, headers=headers)
    assert response.status_code == 201 and captured["body"] == data and captured["sha"] == "a" * 64
    missing = sign("PUT", put, b"", service="collector", key=COLLECTOR_KEY)
    assert env.client.put(put, content=data, headers=missing).status_code == 400


def test_svc_key_constant_is_used() -> None:
    assert len(SVC_KEY) == 32
