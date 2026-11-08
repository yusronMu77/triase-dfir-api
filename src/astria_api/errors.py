"""Galat api di atas `AstriaError` (bentuk seragam `{"error": {code, message, trace_id}}`)."""

from __future__ import annotations

from collections.abc import Mapping

from astria_common.errors import AstriaError, error_body
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorDetail(BaseModel):
    code: str
    message: str
    trace_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


class ApiError(AstriaError):
    """Galat dengan header tambahan (mis. `Retry-After`)."""

    def __init__(self, code: str, message: str, status: int, headers: Mapping[str, str] | None = None) -> None:
        super().__init__(code, message, status)
        self.headers = dict(headers or {})


def unauthenticated() -> ApiError:
    return ApiError("TIDAK_TERAUTENTIKASI", "sesi tidak valid atau berakhir", 401)


def forbidden() -> ApiError:
    return ApiError("DILARANG", "peran Anda tidak boleh melakukan aksi ini", 403)


def too_many(retry_after: float) -> ApiError:
    seconds = max(1, int(retry_after + 0.999))
    return ApiError("TERLALU_BANYAK", "terlalu banyak permintaan", 429, {"Retry-After": str(seconds)})


def upstream_unavailable(service: str) -> ApiError:
    return ApiError("LAYANAN_TIDAK_TERSEDIA", f"layanan {service} tidak tersedia", 503)


def upstream_timeout(service: str) -> ApiError:
    return ApiError("LAYANAN_TIMEOUT", f"layanan {service} tidak menjawab tepat waktu", 504)


def upstream_failed(service: str) -> ApiError:
    return ApiError("LAYANAN_GALAT", f"layanan {service} mengembalikan jawaban yang tidak dapat dipakai", 502)


ERROR_RESPONSES: dict[int | str, dict] = {
    401: {"model": ErrorResponse, "description": "Sesi tidak ada atau berakhir"},
    403: {"model": ErrorResponse, "description": "Peran tidak diizinkan"},
    429: {"model": ErrorResponse, "description": "Terlalu banyak permintaan"},
    503: {"model": ErrorResponse, "description": "Layanan tujuan tidak tersedia"},
}


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_req: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(error_body(exc.code, exc.message), status_code=exc.status, headers=exc.headers)
