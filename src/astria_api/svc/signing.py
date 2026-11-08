"""Verifikasi HMAC untuk `/svc/v1` (format `astria_common.hmac_auth`) per layanan pemanggil yang diizinkan."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from astria_common import hmac_auth
from astria_common.hmac_auth import H_SERVICE, HmacError
from fastapi import Request
from prometheus_client import Counter
from structlog import get_logger

from astria_api.errors import ApiError

log = get_logger(__name__)

HMAC_REJECTIONS = Counter("astria_api_hmac_rejections_total", "Permintaan /svc ditolak", ["reason"])


def load_keys(path: Path | None) -> dict[str, bytes]:
    """Berkas rahasia JSON {layanan: kunci_hex}. Kosong atau tak ada = tidak ada pemanggil yang dikenal."""
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {str(name): bytes.fromhex(str(key).strip()) for name, key in raw.items()}


def _reject(reason: str) -> ApiError:
    HMAC_REJECTIONS.labels(reason).inc()
    log.warning("hmac_ditolak", reason=reason)
    # Tanpa rincian ke pemanggil; alasan hanya di log dan metrik.
    return ApiError("TIDAK_TERAUTENTIKASI", "tanda tangan tidak valid", 401)


def require_service_hmac(*allowed: str, signs_body: bool = True) -> Callable[[Request], Awaitable[str]]:
    """Dependensi `/svc`: hanya layanan di `allowed` dengan kunci dikenal. Mengembalikan nama layanan.

    `signs_body=False` untuk unggahan yang dialirkan: tanda tangan memakai hash badan kosong dan badan tidak dibaca.
    """
    permitted = frozenset(allowed)

    async def dependency(request: Request) -> str:
        state: Any = request.app.state
        service = request.headers.get(H_SERVICE, "")
        key = state.svc_keys.get(service)
        if service not in permitted or key is None:
            raise _reject("layanan_tidak_dikenal")
        body = await request.body() if signs_body else b""
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        try:
            hmac_auth.verify(key, request.method, path, request.headers, body, state.nonces)
        except HmacError as exc:
            raise _reject(exc.reason) from None
        return service

    dependency.astria_svc = tuple(sorted(permitted))  # type: ignore[attr-defined]
    return dependency
