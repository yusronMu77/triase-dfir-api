"""Komposisi kartu (respons parsial), bukti, penjelas, ingest, kasus, serta aksi berisiko dan kepemilikan identitas."""

from __future__ import annotations

from typing import Any

import httpx

TICKET = {
    "card_id": "IC-20261110-003",
    "status": "ditinjau",
    "row_version": 4,
    "rule_ids": ["R-1102", "R-4625"],
    "dokumen": {"kode": {"skor": 71}, "ringkasan": [{"klaim": "x", "bukti": ["EV-hb01-004217", "EV-hb01-004218"]}]},
}
CATALOG = {
    "catalog_version": 3,
    "content_hash": "abc",
    "entries": {"R-1102": {"judul": "Log dihapus"}, "R-9999": {"judul": "Tidak terkait"}},
}


def test_card_detail_merges_ticket_and_penjelas(env: Any) -> None:
    env.world.on("ticket", "GET", "/svc/v1/tickets/IC-20261110-003", json=TICKET)
    env.world.on("config", "GET", "/svc/v1/catalogs/alert_penjelasan/active", json=CATALOG)
    body = env.as_user("tok-analis").get("/api/v1/cards/IC-20261110-003").json()
    assert body["card_id"] == "IC-20261110-003" and body["row_version"] == 4
    assert body["penjelas"] == {"R-1102": {"judul": "Log dihapus"}}
    assert body["katalog"] == {"versi": 3, "content_hash": "abc"}
    assert body["bagian_tidak_tersedia"] == []


def test_card_detail_survives_config_outage(env: Any) -> None:
    env.world.on("ticket", "GET", "/svc/v1/tickets/IC-20261110-003", json=TICKET)
    env.world.on("config", "GET", "/svc/v1/catalogs/alert_penjelasan/active", exc=httpx.ConnectError("mati"))
    response = env.as_user("tok-analis").get("/api/v1/cards/IC-20261110-003")
    assert response.status_code == 200
    body = response.json()
    assert body["bagian_tidak_tersedia"] == ["penjelas"] and body["penjelas"] is None
    assert body["card_id"] == "IC-20261110-003"


def test_card_detail_fails_when_ticket_is_down(env: Any) -> None:
    env.world.on("ticket", "GET", "/svc/v1/tickets/IC-1", exc=httpx.ConnectError("mati"))
    env.world.on("config", "GET", "/svc/v1/catalogs/alert_penjelasan/active", json=CATALOG)
    response = env.as_user("tok-analis").get("/api/v1/cards/IC-1")
    assert response.status_code == 503
    assert "ticket" in response.json()["error"]["message"]


def test_catalog_is_cached_and_invalidated_by_config_changed(env: Any) -> None:
    env.world.on("ticket", "GET", "/svc/v1/tickets/IC-1", json=TICKET)
    env.world.on("config", "GET", "/svc/v1/catalogs/alert_penjelasan/active", json=CATALOG)
    for _ in range(3):
        env.as_user("tok-analis").get("/api/v1/cards/IC-1")
    assert len(env.world.calls_to("config")) == 1
    env.app.state.events.handle({"type": "config.changed", "data": {"scope": "catalog"}})
    env.as_user("tok-analis").get("/api/v1/cards/IC-1")
    assert len(env.world.calls_to("config")) == 2


def test_evidence_collects_ids_and_reports_missing(env: Any) -> None:
    env.world.on("ticket", "GET", "/svc/v1/tickets/IC-1", json=TICKET)
    env.world.on(
        "ingest",
        "POST",
        "/svc/v1/evidence:batch",
        json={"evidence": [{"evidence_id": "EV-hb01-004217", "sha256": "ab"}]},
    )
    body = env.as_user("tok-dfir").get("/api/v1/cards/IC-1/evidence").json()
    assert body["tidak_ditemukan"] == ["EV-hb01-004218"]
    assert env.world.calls_to("ingest")[0].body == {"ids": ["EV-hb01-004217", "EV-hb01-004218"]}


def test_explain_unknown_alert_is_404_and_known_one_resolves_rule(env: Any) -> None:
    env.world.on("ingest", "POST", "/svc/v1/alerts:batch", json={"alerts": []})
    assert env.as_user("tok-analis").get("/api/v1/alerts/AL-1/explain").status_code == 404
    env.world.on("ingest", "POST", "/svc/v1/alerts:batch", json={"alerts": [{"alert_id": "AL-1", "rule_id": "R-1102"}]})
    env.world.on("config", "GET", "/svc/v1/catalogs/alert_penjelasan/active", json=CATALOG)
    body = env.as_user("tok-analis").get("/api/v1/alerts/AL-1/explain").json()
    assert body["penjelas"] == {"judul": "Log dihapus"} and body["bagian_tidak_tersedia"] == []


def test_patch_forwards_body_and_user_act(env: Any) -> None:
    env.world.on("ticket", "PATCH", "/svc/v1/tickets/IC-1", json={"status": "selesai", "row_version": 5})
    response = env.write("PATCH", "/api/v1/cards/IC-1", "tok-analis", json={"status": "selesai", "if_row_version": 4})
    assert response.status_code == 200
    assert env.world.calls_to("ticket")[0].body == {"status": "selesai", "if_row_version": 4}


def test_deep_dive_builds_body_from_path_only(env: Any) -> None:
    env.world.on("dfir", "POST", "/internal/v1/cases", json={"case_id": "CS-1"}, status=202)
    response = env.write("POST", "/api/v1/cards/IC-1/deep-dive", "tok-dfir", json={"card_id": "IC-LAIN", "x": 1})
    assert response.status_code == 202
    assert env.world.calls_to("dfir")[0].body == {"card_id": "IC-1"}


def test_ingest_validates_and_rejects_traversal(env: Any) -> None:
    env.world.on("ingest", "POST", "/svc/v1/ingest/jobs", json={"job_id": "j1"}, status=202)
    bad = [
        {"adapter": "hayabusa", "path_ref": "../../etc/passwd"},
        {"adapter": "Hay abusa", "path_ref": "x"},
        {"adapter": "hayabusa", "path_ref": "x", "tambahan": 1},
        {"adapter": "hayabusa", "path_ref": "x", "expected_sha256": "nothex"},
    ]
    for body in bad:
        assert env.write("POST", "/api/v1/ingest", "tok-analis", json=body).status_code == 400, body
    assert env.world.calls_to("ingest") == []
    ok = env.write("POST", "/api/v1/ingest", "tok-analis", json={"adapter": "hayabusa", "path_ref": "inbox/a.jsonl"})
    assert ok.status_code == 202 and ok.json() == {"job_id": "j1"}


def test_report_passes_binary_through_with_upstream_content_type(env: Any) -> None:
    env.world.on(
        "dfir",
        "GET",
        "/internal/v1/cases/CS-1/report",
        content=b"%PDF-1.7",
        headers={"content-type": "application/pdf"},
    )
    response = env.as_user("tok-dfir").get("/api/v1/cases/CS-1/report?format=pdf")
    assert response.status_code == 200 and response.content == b"%PDF-1.7"
    assert response.headers["content-type"] == "application/pdf"
    assert env.world.calls_to("dfir")[0].params == {"format": "pdf"}


# --- aksi berisiko: audit sinkron fail-closed ---


def test_secret_write_is_audited_before_and_after_and_value_never_logged(env: Any) -> None:
    env.world.on("config", "PUT", "/v1/secrets/model.api_key", json={"terisi": True})
    response = env.write("PUT", "/api/v1/config/secrets/model.api_key", "tok-admin", json={"value": "sk-RAHASIA"})
    assert response.status_code == 200
    assert env.audit.actions() == ["config.secret_write_requested", "config.secret_write_completed"]
    assert "sk-RAHASIA" not in str(env.audit.records)
    assert env.audit.records[0]["actor"] == "usr_adm" and env.audit.records[0]["via"] == "ui"


def test_risky_action_is_blocked_when_audit_is_down(env: Any) -> None:
    env.audit.fail = True
    response = env.write("PUT", "/api/v1/config/secrets/model.api_key", "tok-admin", json={"value": "x"})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "AUDIT_TIDAK_TERSEDIA"
    assert env.world.calls_to("config") == []


def test_completion_audit_failure_does_not_undo_the_action(env: Any) -> None:
    calls = {"n": 0}
    original = env.audit.record

    async def flaky(record: Any, *, act: Any = None) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("audit mati setelah aksi")
        return await original(record, act=act)

    env.app.state.audit._sink = type("S", (), {"record": staticmethod(flaky)})()
    env.world.on("scheduler", "POST", "/svc/v1/digests/run", json={"digest_id": "d1"})
    response = env.write("POST", "/api/v1/digests/run", "tok-admin", json={})
    assert response.status_code == 200
    assert env.app.state.audit.pending == 1
    env.app.state.audit._sink = env.audit
    import asyncio

    asyncio.run(env.app.state.audit.flush())
    assert env.app.state.audit.pending == 0
    assert env.audit.actions()[-1] == "digest.run_completed"


# --- identitas kanal: admin semua, lainnya hanya miliknya ---

IDENTITIES = {
    "items": [
        {"id": "idn1", "user_id": "usr_ana", "channel": "telegram"},
        {"id": "idn2", "user_id": "usr_dfir", "channel": "telegram"},
    ]
}


def test_identity_list_is_filtered_by_ownership(env: Any) -> None:
    env.world.on("gateway", "GET", "/internal/v1/identities", json=IDENTITIES)
    assert [i["id"] for i in env.as_user("tok-analis").get("/api/v1/identities").json()["items"]] == ["idn1"]
    assert [i["id"] for i in env.as_user("tok-dfir").get("/api/v1/identities").json()["items"]] == ["idn2"]
    assert len(env.as_user("tok-admin").get("/api/v1/identities").json()["items"]) == 2
    assert env.as_user("tok-pimpinan").get("/api/v1/identities").json()["items"] == []


def test_identity_revoke_only_own_unless_admin(env: Any) -> None:
    env.world.on("gateway", "GET", "/internal/v1/identities", json=IDENTITIES)
    env.world.on("gateway", "DELETE", "/internal/v1/identities/idn1", status=204)
    env.world.on("gateway", "DELETE", "/internal/v1/identities/idn2", status=204)

    other = env.write("DELETE", "/api/v1/identities/idn2", "tok-analis")
    assert other.status_code == 404  # bukan 403: keberadaan ikatan orang lain tidak bocor
    assert [c for c in env.world.calls_to("gateway") if c.method == "DELETE"] == []
    assert env.audit.records == []

    own = env.write("DELETE", "/api/v1/identities/idn1", "tok-analis")
    assert own.status_code == 204
    assert env.audit.actions() == ["identity.binding_revoke_requested", "identity.binding_revoke_completed"]

    assert env.write("DELETE", "/api/v1/identities/idn2", "tok-admin").status_code == 204
    assert env.write("DELETE", "/api/v1/identities/ghaib", "tok-admin").status_code == 404


def test_identity_revoke_is_blocked_when_audit_is_down(env: Any) -> None:
    env.world.on("gateway", "GET", "/internal/v1/identities", json=IDENTITIES)
    env.audit.fail = True
    assert env.write("DELETE", "/api/v1/identities/idn1", "tok-analis").status_code == 503
    assert [c for c in env.world.calls_to("gateway") if c.method == "DELETE"] == []


def test_channels_list_is_partial_when_gateway_is_down(env: Any) -> None:
    env.world.on("config", "GET", "/v1/channels/policy", json={"items": [{"channel_id": "telegram"}]})
    env.world.on("gateway", "GET", "/internal/v1/status", exc=httpx.ConnectError("mati"))
    body = env.as_user("tok-admin").get("/api/v1/channels").json()
    assert body["bagian_tidak_tersedia"] == ["status_gateway"] and body["kebijakan"]["items"]
