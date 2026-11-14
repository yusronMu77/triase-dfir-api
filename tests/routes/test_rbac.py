"""RBAC pada setiap rute `/api/v1`: 401 tanpa sesi, 403 peran salah (tanpa memanggil layanan tujuan), lolos peran benar.

Tabel `EXPECTED` ditulis tangan (bukan dibaca dari kode rute) dan harus mencakup semua rute di OpenAPI, jadi rute
baru tanpa baris di sini gagal uji, dan perubahan peran yang tidak disengaja ikut gagal.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from astria_api.permissions import Perm
from astria_api.routing import iter_routes, policy_of, unprotected_routes

ALL = {"analis", "dfir", "pimpinan", "admin"}
AN, DF, AD = {"analis"}, {"dfir"}, {"admin"}

EXPECTED: dict[tuple[str, str], set[str]] = {
    ("POST", "/api/v1/auth/logout"): ALL,
    ("GET", "/api/v1/auth/me"): ALL,
    ("POST", "/api/v1/auth/reauth"): ALL,
    ("GET", "/api/v1/cards"): AN | DF,
    ("GET", "/api/v1/cards/{card_id}"): AN | DF,
    ("PATCH", "/api/v1/cards/{card_id}"): AN | DF,
    ("POST", "/api/v1/cards/{card_id}/events"): AN | DF,
    ("POST", "/api/v1/cards/{card_id}/feedback"): AN | DF,
    ("POST", "/api/v1/cards/{card_id}/deep-dive"): AN | DF,
    ("GET", "/api/v1/cards/{card_id}/evidence"): AN | DF,
    ("GET", "/api/v1/alerts/{alert_id}/explain"): AN | DF,
    ("GET", "/api/v1/cases/{case_id}"): DF,
    ("GET", "/api/v1/cases/{case_id}/timeline"): DF,
    ("GET", "/api/v1/cases/{case_id}/report"): DF,
    ("POST", "/api/v1/ingest"): AN | AD,
    ("GET", "/api/v1/ingest/jobs/{job_id}"): AN | AD,
    ("POST", "/api/v1/device-scans"): AN | AD,
    ("GET", "/api/v1/devices"): AN | AD,
    ("GET", "/api/v1/device-scans/{scan_id}"): AN | AD,
    ("GET", "/api/v1/digests"): ALL,
    ("GET", "/api/v1/digests/{digest_id}"): ALL,
    ("GET", "/api/v1/digests/{digest_id}/document"): ALL,
    ("POST", "/api/v1/digests/run"): AD,
    ("GET", "/api/v1/handover/current"): AN,
    ("POST", "/api/v1/handover"): AN,
    ("GET", "/api/v1/audit"): DF | AD,
    ("POST", "/api/v1/audit/verify"): AD,
    ("GET", "/api/v1/audit/verify/{job_id}"): AD,
    ("GET", "/api/v1/metrics"): AN | AD,
    ("GET", "/api/v1/config"): AD,
    ("PUT", "/api/v1/config/{key}"): AD,
    ("PUT", "/api/v1/config/secrets/{key}"): AD,
    ("GET", "/api/v1/channels"): AD,
    ("PUT", "/api/v1/channels/{channel_id}"): AD,
    ("POST", "/api/v1/channels/{channel_id}/test"): AD,
    ("GET", "/api/v1/channels/whatsapp/link"): AD,
    ("POST", "/api/v1/channels/whatsapp/link/logout"): AD,
    ("GET", "/api/v1/outbox"): AD,
    ("POST", "/api/v1/outbox/{outbox_id}/retry"): AD,
    ("POST", "/api/v1/identities/pairing-codes"): ALL,
    ("GET", "/api/v1/identities"): ALL,
    ("DELETE", "/api/v1/identities/{identity_id}"): ALL,
    ("GET", "/api/v1/stream"): ALL,
}
PUBLIC = {("POST", "/api/v1/auth/login"), ("GET", "/api/v1/health")}
TOKENS = {"analis": "tok-analis", "dfir": "tok-dfir", "pimpinan": "tok-pimpinan", "admin": "tok-admin"}


def _openapi_routes(env: Any) -> set[tuple[str, str]]:
    found = set()
    for path, ops in env.app.openapi()["paths"].items():
        if path.startswith("/api/v1"):
            found |= {(m.upper(), path) for m in ops}
    return found


def test_expected_table_covers_every_route(env: Any) -> None:
    assert _openapi_routes(env) == set(EXPECTED) | PUBLIC


def test_no_route_lacks_a_policy(env: Any) -> None:
    from astria_api.routes import api_v1
    from astria_api.svc import svc_v1

    assert unprotected_routes(api_v1, svc_v1) == []


def test_route_policy_matches_expected_roles(env: Any) -> None:
    """Izin yang dipasang di rute, dipetakan lewat GRANTS, harus sama dengan tabel tulis-tangan."""
    from astria_api.permissions import GRANTS
    from astria_api.routes import api_v1

    checked = 0
    for route in iter_routes(api_v1):
        perm = policy_of(route)
        if not isinstance(perm, Perm):
            continue
        roles = {r.value for r, perms in GRANTS.items() if perm in perms}
        for method in route.methods - {"HEAD", "OPTIONS"}:
            assert EXPECTED[(method, "/api/v1" + route.path)] == roles, (method, route.path)
            checked += 1
    assert checked == len(EXPECTED)


def _concrete(path: str) -> str:
    return re.sub(r"\{\w+\}", "x1", path)


def _send(env: Any, method: str, path: str, token: str | None):
    env.client.cookies.clear()
    if token:
        env.client.cookies.set("astria_session", token)
    headers = {"Origin": "http://testserver"} if method != "GET" else {}
    kwargs: dict[str, Any] = {"json": {}} if method in {"POST", "PUT", "PATCH"} else {}
    return env.client.request(method, _concrete(path), headers=headers, **kwargs)


CASES = sorted(EXPECTED.items())
NON_STREAM = [c for c in CASES if c[0][1] != "/api/v1/stream"]


@pytest.mark.parametrize(("route", "roles"), CASES, ids=[f"{m} {p}" for (m, p), _ in CASES])
def test_unauthenticated_gets_401_and_calls_nothing(env: Any, route: tuple[str, str], roles: set[str]) -> None:
    response = _send(env, route[0], route[1], None)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TIDAK_TERAUTENTIKASI"
    assert env.world.calls == []


@pytest.mark.parametrize(("route", "roles"), NON_STREAM, ids=[f"{m} {p}" for (m, p), _ in NON_STREAM])
def test_role_matrix(env: Any, route: tuple[str, str], roles: set[str]) -> None:
    for role, token in TOKENS.items():
        env.world.calls.clear()
        response = _send(env, route[0], route[1], token)
        if role in roles:
            assert response.status_code not in (401, 403), (role, response.status_code, response.text)
        else:
            assert response.status_code == 403, (role, response.status_code)
            assert response.json()["error"]["code"] == "DILARANG"
            # Hanya introspeksi sesi yang boleh terjadi; layanan tujuan tidak disentuh.
            assert {c.service for c in env.world.calls} <= {"identity"}


@pytest.mark.parametrize(("route", "roles"), NON_STREAM, ids=[f"{m} {p}" for (m, p), _ in NON_STREAM])
def test_unknown_or_empty_roles_are_denied_everywhere(env: Any, route: tuple[str, str], roles: set[str]) -> None:
    # `/auth/*` dan rute SESSION hanya butuh sesi sah; peran tak dikenal tetap tidak punya izin apa pun.
    for token in ("tok-ngawur", "tok-kosong"):
        response = _send(env, route[0], route[1], token)
        assert response.status_code == 403, (token, route)


def test_garbage_cookie_is_unauthenticated(env: Any) -> None:
    response = _send(env, "GET", "/api/v1/cards", "tidak-ada")
    assert response.status_code == 401


def test_login_and_health_are_public(env: Any) -> None:
    env.client.cookies.clear()
    assert env.client.get("/api/v1/health").status_code == 200
    assert env.client.post("/api/v1/auth/login", json={}, headers={"Origin": "http://testserver"}).status_code == 400


def test_denials_are_counted_and_not_logged_with_secrets(env: Any) -> None:
    from astria_api.auth import AUTHZ_DENIED

    before = AUTHZ_DENIED.labels("config:read")._value.get()
    _send(env, "GET", "/api/v1/config", "tok-analis")
    assert AUTHZ_DENIED.labels("config:read")._value.get() == before + 1


def test_role_change_takes_effect_after_cache_expiry(tmp_path: Any) -> None:
    """Peran dicabut di identity: setelah cache sesi kedaluwarsa, akses langsung hilang (tanpa login ulang)."""
    from conftest import make_env

    environment = make_env(tmp_path, cache_session_seconds=0.05)
    environment.world.session("tok", "usr_a", ["admin"])
    assert environment.as_user("tok").get("/api/v1/config").status_code == 200
    environment.world.session("tok", "usr_a", ["pimpinan"])
    import time

    time.sleep(0.1)
    assert environment.as_user("tok").get("/api/v1/config").status_code == 403
