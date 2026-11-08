"""Login, cookie, cache sesi, pencabutan, CSRF, header keamanan, batas ukuran, pembatas laju, galat upstream."""

from __future__ import annotations

import time
from typing import Any

import httpx
from astria_common.errors import AstriaError
from conftest import make_env

LOGIN = "/api/v1/auth/login"


def _identity_login(env: Any, status: int = 200) -> None:
    env.world.on(
        "identity",
        "POST",
        "/internal/v1/auth/login",
        status=status,
        json={
            "session_token": "s3cr3t-token",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "idle_expires_at": "2099-01-01T00:00:00+00:00",
            "user": {"user_id": "usr_ana", "username": "analis01", "roles": ["analis", "bogus"]},
        },
    )


def test_login_sets_strict_httponly_cookie_and_never_returns_the_token(env: Any) -> None:
    _identity_login(env)
    response = env.write("POST", LOGIN, json={"username": "analis01", "password": "rahasia-banget"})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "astria_session=s3cr3t-token" in cookie
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    assert "s3cr3t-token" not in response.text
    body = response.json()
    assert body["user"]["permissions"] == sorted(body["user"]["permissions"])
    assert "cards:read" in body["user"]["permissions"] and "config:write" not in body["user"]["permissions"]
    sent = env.world.calls_to("identity")[0].body
    assert sent["password"] == "rahasia-banget" and len(sent["client"]["ip_hash"]) == 64  # noqa: S105 - nilai uji
    assert "rahasia-banget" not in response.text


def test_login_wrong_credentials_is_generic_401(env: Any) -> None:
    _identity_login(env, status=401)
    response = env.write("POST", LOGIN, json={"username": "x", "password": "y"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TIDAK_TERAUTENTIKASI"
    assert "set-cookie" not in response.headers


def test_login_is_rate_limited_per_ip(tmp_path: Any) -> None:
    env = make_env(tmp_path, rate_login_per_min=3)
    _identity_login(env, status=401)
    codes = [env.write("POST", LOGIN, json={"username": "x", "password": "y"}).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    limited = env.write("POST", LOGIN, json={"username": "x", "password": "y"})
    assert int(limited.headers["retry-after"]) >= 1


def test_login_validation_error_does_not_echo_password(env: Any) -> None:
    response = env.write("POST", LOGIN, json={"username": "", "password": "p@ss-visible"})
    assert response.status_code == 400
    assert "p@ss-visible" not in response.text


def test_me_lists_roles_and_permissions(env: Any) -> None:
    body = env.as_user("tok-pimpinan").get("/api/v1/auth/me").json()
    assert body["roles"] == ["pimpinan"]
    assert "digests:read" in body["permissions"] and "cards:read" not in body["permissions"]


def test_logout_clears_cookie_and_forgets_session(env: Any) -> None:
    response = env.write("POST", "/api/v1/auth/logout", "tok-analis")
    assert response.status_code == 204
    assert "max-age=0" in response.headers["set-cookie"].lower()
    introspections = [c for c in env.world.calls if c.path.endswith("/sessions/introspect")]
    env.as_user("tok-analis").get("/api/v1/auth/me")
    assert len([c for c in env.world.calls if c.path.endswith("/sessions/introspect")]) == len(introspections) + 1


def test_session_introspection_is_cached_per_hash(env: Any) -> None:
    for _ in range(4):
        assert env.as_user("tok-analis").get("/api/v1/auth/me").status_code == 200
    assert len([c for c in env.world.calls if c.path.endswith("/sessions/introspect")]) == 1


def test_identity_revoked_event_drops_cache_immediately(env: Any) -> None:
    assert env.as_user("tok-analis").get("/api/v1/auth/me").status_code == 200
    env.world.sessions["tok-analis"] = {"active": False}
    assert env.as_user("tok-analis").get("/api/v1/auth/me").status_code == 200  # masih di cache
    env.app.state.events.handle({"type": "identity.revoked", "data": {"user_id": "usr_ana"}})
    assert env.as_user("tok-analis").get("/api/v1/auth/me").status_code == 401


def test_inactive_session_is_401(env: Any) -> None:
    env.world.sessions["tok-mati"] = {"active": False}
    assert env.as_user("tok-mati").get("/api/v1/cards").status_code == 401


def test_identity_down_gives_503_with_service_name_but_cached_sessions_survive(env: Any) -> None:
    assert env.as_user("tok-analis").get("/api/v1/auth/me").status_code == 200
    env.world.on("identity", "POST", "/internal/v1/sessions/introspect", exc=httpx.ConnectError("x"))
    assert env.as_user("tok-analis").get("/api/v1/auth/me").status_code == 200
    response = env.as_user("tok-admin").get("/api/v1/auth/me")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "LAYANAN_TIDAK_TERSEDIA"
    assert "identity" in response.json()["error"]["message"]


def test_per_user_rate_limit_is_429_with_retry_after(tmp_path: Any) -> None:
    env = make_env(tmp_path)
    env.app.state.user_limiter = type(env.app.state.user_limiter)(3)
    env.world.session("t", "usr_a", ["analis"])
    codes = [env.as_user("t").get("/api/v1/auth/me").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert "retry-after" in env.as_user("t").get("/api/v1/auth/me").headers


# --- CSRF, header, ukuran ---


def test_unsafe_requests_need_matching_origin(env: Any) -> None:
    env.as_user("tok-analis")
    no_origin = env.client.post("/api/v1/auth/logout")
    assert no_origin.status_code == 403
    wrong = env.client.post("/api/v1/auth/logout", headers={"Origin": "https://jahat.example"})
    assert wrong.status_code == 403
    assert wrong.json()["error"]["code"] == "DILARANG"
    assert env.client.post("/api/v1/auth/logout", headers={"Origin": "http://testserver"}).status_code == 204
    assert env.world.calls_to("ticket") == []


def test_public_origin_setting_is_the_only_allowed_origin(tmp_path: Any) -> None:
    env = make_env(tmp_path, public_origin="https://astria.example")
    env.world.session("t", "usr_a", ["analis"])
    env.as_user("t")
    assert env.client.post("/api/v1/auth/logout", headers={"Origin": "http://testserver"}).status_code == 403
    assert env.client.post("/api/v1/auth/logout", headers={"Origin": "https://astria.example"}).status_code == 204


def test_json_content_type_is_required_when_body_present(env: Any) -> None:
    env.as_user("tok-analis")
    response = env.client.post(
        "/api/v1/cards/x1/events",
        content=b"a=b",
        headers={"Origin": "http://testserver", "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 415


def test_get_is_not_subject_to_origin_check(env: Any) -> None:
    assert env.as_user("tok-analis").get("/api/v1/cards").status_code == 200


def test_security_headers_on_api_and_errors(env: Any) -> None:
    for response in (env.as_user("tok-analis").get("/api/v1/cards"), env.client.get("/api/v1/cards/x1", cookies={})):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    rejected = env.client.post("/api/v1/auth/logout")
    assert rejected.headers["cache-control"] == "no-store" and rejected.json()["error"]["trace_id"]


def test_oversized_body_is_413_before_reading(tmp_path: Any) -> None:
    env = make_env(tmp_path, max_body_bytes=100)
    env.world.session("t", "usr_a", ["analis"])
    response = env.write("PATCH", "/api/v1/cards/x1", "t", json={"catatan": "x" * 500})
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "TERLALU_BESAR"
    assert env.world.calls_to("ticket") == []


def test_path_params_reject_traversal(env: Any) -> None:
    for bad in ("..", "a%2Fb", "%2e%2e"):
        response = env.as_user("tok-analis").get(f"/api/v1/cards/{bad}")
        assert response.status_code in (400, 404), bad
    assert env.world.calls_to("ticket") == []


def test_unknown_query_params_are_not_forwarded(env: Any) -> None:
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    env.as_user("tok-analis").get("/api/v1/cards?status=baru&prioritas=P1&drop_table=1&limit=5")
    call = env.world.calls_to("ticket")[0]
    assert call.params == {"status": "baru", "priority": "P1", "limit": "5"}


# --- pemetaan galat upstream ---


def test_upstream_errors_are_mapped_without_leaking_bodies(env: Any) -> None:
    leak = {"error": {"code": "X", "message": "stack trace postgres://user:pw@db"}}
    cases = [
        (403, 403, "DILARANG"),
        (404, 404, "TIDAK_DITEMUKAN"),
        (422, 400, "VALIDASI_GAGAL"),
        (500, 502, "LAYANAN_GALAT"),
        (503, 503, "LAYANAN_TIDAK_TERSEDIA"),
        (504, 504, "LAYANAN_TIMEOUT"),
    ]
    for upstream_status, status, code in cases:
        env.world.on("ticket", "GET", "/svc/v1/tickets/IC-1", json=leak, status=upstream_status)
        response = env.as_user("tok-analis").get("/api/v1/cards/IC-1")
        assert response.status_code == status, upstream_status
        assert response.json()["error"]["code"] == code
        assert "postgres" not in response.text


def test_conflict_keeps_upstream_code_and_timeout_is_504(env: Any) -> None:
    env.world.on(
        "ticket",
        "PATCH",
        "/svc/v1/tickets/IC-1",
        status=409,
        json={"error": {"code": "ROW_VERSION_BERBEDA", "message": "m"}},
    )
    response = env.write("PATCH", "/api/v1/cards/IC-1", "tok-analis", json={"status": "ditinjau", "if_row_version": 3})
    assert response.status_code == 409 and response.json()["error"]["code"] == "ROW_VERSION_BERBEDA"
    env.world.on("ticket", "PATCH", "/svc/v1/tickets/IC-1", exc=httpx.ReadTimeout("lambat"))
    response = env.write("PATCH", "/api/v1/cards/IC-1", "tok-analis", json={"status": "ditinjau"})
    assert response.status_code == 504 and response.json()["error"]["code"] == "LAYANAN_TIMEOUT"


def test_get_is_retried_once_but_post_is_not(env: Any) -> None:
    attempts = {"n": 0}

    def flaky(_request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(503, json={}) if attempts["n"] == 1 else httpx.Response(200, json={"items": []})

    env.world.on("ticket", "GET", "/svc/v1/tickets", fn=flaky)
    assert env.as_user("tok-analis").get("/api/v1/cards").status_code == 200
    assert attempts["n"] == 2
    env.world.on("ticket", "POST", "/svc/v1/tickets/IC-1/events", status=503)
    assert env.write("POST", "/api/v1/cards/IC-1/events", "tok-analis", json={"tipe": "comment"}).status_code == 503
    assert len([c for c in env.world.calls_to("ticket") if c.method == "POST"]) == 1


def test_calls_carry_act_claim_of_the_user(env: Any) -> None:
    env.world.on("ticket", "GET", "/svc/v1/tickets", json={"items": []})
    env.as_user("tok-dfir").get("/api/v1/cards")
    audience, act = next(c for c in env.tokens.calls if c[0] == "svc:ticket")
    assert act == {"sub": "usr_dfir", "roles": ["dfir"], "session_id": "ses_usr_dfir"}


def test_token_failure_is_503_not_500(tmp_path: Any) -> None:
    env = make_env(tmp_path)

    async def broken(audience: str, act: Any = None) -> dict[str, str]:
        raise AstriaError("TOKEN_DITOLAK", "identity menolak", 503)

    env.world.session("t", "usr_a", ["analis"])
    env.app.state.upstreams.ticket._tokens = type("T", (), {"auth_headers": staticmethod(broken)})()
    response = env.as_user("t").get("/api/v1/cards")
    assert response.status_code == 503


def test_health_is_public_and_hides_internals(env: Any) -> None:
    import asyncio

    asyncio.run(env.app.state.probe.probe_once())
    body = env.client.get("/api/v1/health").json()
    assert set(body) == {"status", "layanan", "audit_tertunda"}
    assert "version" not in body and "env" not in body
    time.sleep(0)
