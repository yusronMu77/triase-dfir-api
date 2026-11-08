import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from astria_api.main import build_app
from astria_api.settings import Settings


def test_health_and_ready_without_dependencies() -> None:
    with TestClient(build_app(Settings(env="test"))) as client:
        health = client.get("/health").json()
        assert health["service"] == "api"
        assert health["env"] == "test"
        assert client.get("/ready").status_code == 200
        assert "astria_service_info" in client.get("/metrics").text


def test_api_has_no_database() -> None:
    url = SecretStr("postgresql+psycopg://u:p@postgres:5432/astria_dev")
    with pytest.raises(ValidationError, match="tidak punya basis data"):
        Settings(env="dev", database_url=url)


def test_service_key_is_required_outside_test(tmp_path) -> None:
    with pytest.raises(ValidationError, match="ASTRIA_SERVICE_KEY"):
        Settings(env="dev")
    Settings(env="dev", service_key=SecretStr("aa" * 32))


def test_public_origin_is_required_in_demo_and_prod() -> None:
    key = SecretStr("aa" * 32)
    with pytest.raises(ValidationError, match="ASTRIA_PUBLIC_ORIGIN"):
        Settings(env="prod", service_key=key)
    assert Settings(env="prod", service_key=key, public_origin="https://astria.example").cookie_secure


def test_unknown_setting_is_rejected() -> None:
    # `extra="forbid"` berlaku untuk argumen eksplisit; env var bertipe ASTRIA_* yang salah ketik tidak
    # terdeteksi oleh pydantic-settings (hanya berkas dotenv yang diperiksa), jadi hanya jalur ini yang diuji.
    with pytest.raises(ValidationError):
        Settings(env="test", typo_setting=1)


def test_without_service_key_upstream_calls_fail_closed_with_503() -> None:
    app = build_app(Settings(env="test"))
    with TestClient(app) as client:
        client.cookies.set("astria_session", "apa-saja")
        assert client.get("/api/v1/cards").status_code == 503
