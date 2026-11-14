"""Pagar `ASTRIA_ENV` pada jalur start sungguhan `astria-api` (infra#9).

Kebijakan (`astria_common.settings` dan `astria_common.envguard`): `ASTRIA_ENV` wajib dan hanya `dev`, `demo`, `prod`,
atau `test` (huruf kecil persis, tanpa nilai bawaan); konfigurasi yang bertentangan dengan lingkungannya ditolak.
Uji memanggil titik masuk console script dari image dan memastikan server tidak pernah dijalankan bila pagar menolak.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from astria_api import __main__ as entry

SERVICE = "api"
INVALID_ENV = [None, "", "staging", "production", "PROD", " prod"]


def _db(name: str) -> str:
    return f"postgresql+psycopg://astria:x@postgres:5432/{name}"


def valid_config(env: str) -> dict[str, str]:
    """Konfigurasi sah minimum per lingkungan. api tidak punya basis data."""
    return {"ASTRIA_PUBLIC_ORIGIN": "https://astria.example"} if env in {"demo", "prod"} else {}


def start() -> None:
    entry.main()


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Ganti server dengan perekam: daftar lingkungan yang benar-benar sampai ke tahap membuka port."""
    calls: list[str] = []

    def fake_run(app: Any, settings: Any, *args: Any, **kwargs: Any) -> None:
        calls.append(settings.env if settings is not None and hasattr(settings, "env") else "?")

    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kwargs: fake_run(app, app.state.settings))

    monkeypatch.setenv("ASTRIA_SERVICE_KEY", "11" * 32)
    return calls


def _set(monkeypatch: pytest.MonkeyPatch, env: str | None, values: dict[str, str]) -> None:
    if env is None:
        monkeypatch.delenv("ASTRIA_ENV", raising=False)
    else:
        monkeypatch.setenv("ASTRIA_ENV", env)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize("value", INVALID_ENV)
def test_missing_or_unsupported_env_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, served: list[str], value: str | None
) -> None:
    _set(monkeypatch, value, valid_config("dev"))
    with pytest.raises(ValidationError) as info:
        start()
    assert any(err["loc"] == ("env",) for err in info.value.errors())
    assert served == []


@pytest.mark.parametrize("env", ["dev", "demo", "prod", "test"])
def test_supported_env_starts(monkeypatch: pytest.MonkeyPatch, served: list[str], env: str) -> None:
    _set(monkeypatch, env, valid_config(env))
    start()
    assert served == [env]


@pytest.mark.parametrize("env", ["demo", "prod"])
def test_public_env_without_origin_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, served: list[str], env: str
) -> None:
    _set(monkeypatch, env, {})
    with pytest.raises(ValidationError, match="ASTRIA_PUBLIC_ORIGIN"):
        start()
    assert served == []


def test_prod_with_database_refuses_to_start(monkeypatch: pytest.MonkeyPatch, served: list[str]) -> None:
    _set(monkeypatch, "prod", {**valid_config("prod"), "ASTRIA_DATABASE_URL": _db("api")})
    with pytest.raises(ValidationError):
        start()
    assert served == []
