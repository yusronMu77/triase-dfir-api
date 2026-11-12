"""Konfigurasi api dari env `ASTRIA_*` (lihat note api bagian 5.6).

Layanan tujuan memakai port 8000 di jaringan `core`. `api` tidak punya basis data, jadi `ASTRIA_DATABASE_URL`
ditolak. Selain `test`, kunci layanan wajib ada (untuk meminta token ke identity); di `demo` dan `prod`,
`ASTRIA_PUBLIC_ORIGIN` juga wajib karena pemeriksaan Origin (CSRF) bergantung padanya.
"""

from __future__ import annotations

from pathlib import Path
from typing import Self

from astria_common.settings import AstriaSettings
from pydantic import model_validator

UPSTREAMS = ("identity", "config", "ticket", "ingest", "dfir", "scheduler", "audit", "narrative", "verifier", "gateway")


class Settings(AstriaSettings):
    service_name: str = "api"

    public_origin: str | None = None
    """Origin web yang sah, mis. https://astria.example. Kosong (dev, test) = Origin harus sama dengan Host."""
    trusted_proxy: str = ""
    """IP Caddy untuk proxy headers. Kosong = header X-Forwarded-* diabaikan."""
    svc_keys_file: Path | None = None
    """Berkas rahasia JSON {nama_layanan: kunci_hex} untuk /svc/v1. Kosong = /svc/v1 menolak semua."""

    config_url: str = "http://config:8000"
    ticket_url: str = "http://ticket:8000"
    ingest_url: str = "http://ingest:8000"
    dfir_url: str = "http://dfir:8000"
    scheduler_url: str = "http://scheduler:8000"
    narrative_url: str = "http://narrative:8000"
    verifier_url: str = "http://verifier:8000"
    gateway_url: str = "http://gateway:8080"
    """Listener internal Gateway (A10) di 8080 (Dockerfile gateway, GW bagian 3.1), bukan 8000 seperti layanan inti."""

    upstream_timeout_seconds: float = 2.0
    cache_session_seconds: float = 5.0
    cache_settings_seconds: float = 30.0
    cache_catalog_seconds: float = 60.0

    rate_user_per_min: int = 60
    rate_cmd_per_min: int = 20
    rate_global_cmd_per_min: int = 120
    rate_login_per_min: int = 10

    sse_max_per_user: int = 5
    sse_session_check_seconds: float = 60.0
    max_body_bytes: int = 1_048_576
    cookie_name: str = "astria_session"

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.database_url is not None:
            raise ValueError("api tidak punya basis data: ASTRIA_DATABASE_URL tidak boleh diisi")
        if self.env != "test" and self.service_key_bytes() is None:
            raise ValueError("ASTRIA_SERVICE_KEY atau ASTRIA_SERVICE_KEY_FILE wajib diisi")
        if self.env in {"demo", "prod"} and not self.public_origin:
            raise ValueError("ASTRIA_PUBLIC_ORIGIN wajib diisi di demo dan prod")
        return self

    @property
    def cookie_secure(self) -> bool:
        return bool(self.public_origin and self.public_origin.startswith("https://"))

    def upstream_url(self, name: str) -> str:
        if name == "identity":
            return self.identity_url
        if name == "audit":
            return self.audit_url
        return getattr(self, f"{name}_url")
