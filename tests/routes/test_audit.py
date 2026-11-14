"""Regresi api#11: DFIR membaca audit; hanya admin memulai verifikasi, termasuk pada akun multi-peran."""

from typing import Any

import pytest


@pytest.mark.parametrize(
    ("roles", "can_verify"),
    [(["dfir"], False), (["dfir", "analis"], False), (["admin"], True), (["admin", "dfir"], True)],
)
def test_auth_responses_report_effective_audit_permissions(env: Any, roles: list[str], can_verify: bool) -> None:
    env.world.session("tok-audit", "usr_audit", roles)
    env.world.on(
        "identity",
        "POST",
        "/internal/v1/auth/login",
        json={"session_token": "tok-audit", "user": {"user_id": "usr_audit", "roles": roles}},
    )
    login = env.write("POST", "/api/v1/auth/login", json={"username": "audit-test", "password": "test-only"})
    assert login.status_code == 200
    me = env.client.get("/api/v1/auth/me")
    assert me.status_code == 200
    for user in (login.json()["user"], me.json()):
        assert user["roles"] == roles
        assert "audit:read" in user["permissions"]
        assert ("audit:verify" in user["permissions"]) is can_verify
    assert login.json()["user"]["permissions"] == me.json()["permissions"]


@pytest.mark.parametrize("roles", [["dfir"], ["dfir", "analis"], ["admin"], ["admin", "dfir"]])
def test_audit_read_reaches_upstream_with_actor(env: Any, roles: list[str]) -> None:
    env.world.session("tok-audit", "usr_audit", roles)
    records = {"items": [{"seq": 1, "action": "auth.login"}], "next_from_seq": 2}
    env.world.on("audit", "GET", "/internal/v1/records", json=records)
    response = env.as_user("tok-audit").get("/api/v1/audit", params={"from_seq": 1, "limit": 1})
    assert response.status_code == 200
    assert response.json() == records
    calls = env.world.calls_to("audit")
    assert len(calls) == 1
    assert calls[0].params == {"from_seq": "1", "limit": "1"}
    assert env.tokens.calls[-1][1]["roles"] == roles


@pytest.mark.parametrize(
    "roles",
    [["dfir"], ["dfir", "analis"], ["analis"], ["pimpinan"], [], ["ADMIN"], ["dfir", "audit:verify", "admin "]],
)
def test_verify_denied_before_calling_audit_even_with_forged_client_permissions(env: Any, roles: list[str]) -> None:
    env.world.session("tok-audit", "usr_audit", roles)
    response = env.write(
        "POST",
        "/api/v1/audit/verify",
        "tok-audit",
        headers={"X-Roles": "admin", "X-Permissions": "audit:verify"},
        json={"roles": ["admin"], "permissions": ["audit:verify"]},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "DILARANG"
    assert env.world.calls_to("audit") == []
    assert {call.service for call in env.world.calls} <= {"identity"}
    assert not any(audience == "svc:audit" for audience, _ in env.tokens.calls)


@pytest.mark.parametrize("token", [None, "invalid-session"])
def test_verify_requires_valid_session(env: Any, token: str | None) -> None:
    response = env.write("POST", "/api/v1/audit/verify", token, json={})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TIDAK_TERAUTENTIKASI"
    assert env.world.calls_to("audit") == []


@pytest.mark.parametrize("roles", [["admin"], ["admin", "dfir"]])
def test_admin_can_start_and_poll_verification(env: Any, roles: list[str]) -> None:
    env.world.session("tok-audit", "usr_audit", roles)
    started = {"job_id": "ver_test1", "status": "berjalan"}
    finished = {"job_id": "ver_test1", "status": "selesai", "ok": True}
    env.world.on("audit", "POST", "/internal/v1/verify-jobs", status=202, json=started)
    env.world.on("audit", "GET", "/internal/v1/verify-jobs/ver_test1", json=finished)
    response = env.write("POST", "/api/v1/audit/verify", "tok-audit", json={})
    assert response.status_code == 202
    assert response.json() == started
    polled = env.client.get("/api/v1/audit/verify/ver_test1")
    assert polled.status_code == 200
    assert polled.json() == finished
    assert [(call.method, call.path) for call in env.world.calls_to("audit")] == [
        ("POST", "/internal/v1/verify-jobs"),
        ("GET", "/internal/v1/verify-jobs/ver_test1"),
    ]
    assert env.tokens.calls[-1][1]["roles"] == roles
