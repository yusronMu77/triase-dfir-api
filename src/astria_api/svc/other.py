"""Pairing, dokumen, dan proksi Collector di `/svc/v1`."""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from astria_api.errors import ApiError, upstream_failed
from astria_api.routing import SAFE_ID
from astria_api.svc.signing import require_service_hmac

router = APIRouter(prefix="/svc/v1", include_in_schema=False)

DOC_REF = re.compile(r"^digest:([A-Za-z0-9][A-Za-z0-9_.-]{0,127})$")
CHANNEL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


class PairingClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(pattern=r"^[A-Z0-9]{8}$")
    channel_id: str = Field(pattern=CHANNEL.pattern)
    external_id_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


@router.post("/pairing/claim")
async def pairing_claim(request: Request, _s: Annotated[str, Depends(require_service_hmac("gateway"))]) -> JSONResponse:
    state: Any = request.app.state
    try:
        claim = PairingClaim.model_validate_json(await request.body())
    except ValidationError:
        raise ApiError("VALIDASI_GAGAL", "permintaan pairing tidak valid", 400) from None
    data = await state.upstreams.identity.json(
        "POST",
        "/internal/v1/pairing/claim",
        json={"channel": claim.channel_id, "external_id_hash": claim.external_id_hash, "code": claim.code},
    )
    if not isinstance(data, dict) or not isinstance(data.get("user_id"), str):
        raise upstream_failed("identity")
    return JSONResponse({"user_id": data["user_id"], "claimed_at": data.get("claimed_at")})


@router.get("/documents/{ref}")
async def document(
    ref: Annotated[str, Path(max_length=200)],
    request: Request,
    _s: Annotated[str, Depends(require_service_hmac("gateway"))],
) -> Response:
    """Dokumen penuh hanya untuk kanal ber-`max_detail=penuh` (kanal dikirim gateway di `X-Astria-Channel`)."""
    state: Any = request.app.state
    channel = request.headers.get("x-astria-channel", "")
    match = DOC_REF.match(ref)
    if not CHANNEL.match(channel) or match is None:
        raise ApiError("TIDAK_DITEMUKAN", "data tidak ditemukan", 404)
    policy = await state.config_cache.channel_policy(channel)
    if policy is None or policy.get("active") is not True or policy.get("max_detail") != "penuh":
        raise ApiError("DILARANG", "kanal ini tidak boleh menerima dokumen penuh", 403)
    fmt = request.query_params.get("format", "pdf")
    if fmt not in {"pdf", "html"}:
        raise ApiError("VALIDASI_GAGAL", "format tidak didukung", 400)
    resp = await state.upstreams.scheduler.send(
        "GET", f"/svc/v1/digests/{match.group(1)}/dokumen", params={"format": fmt}
    )
    return Response(resp.content, media_type=resp.headers.get("content-type"))


# --- proksi Collector ke ingest ---

collector_auth = require_service_hmac("collector")
collector_stream_auth = require_service_hmac("collector", signs_body=False)


@router.get("/collector/jobs/next")
async def collector_next(request: Request, _s: Annotated[str, Depends(collector_auth)]) -> Response:
    resp = await request.app.state.upstreams.ingest.send("GET", "/svc/v1/collector/jobs/next")
    if resp.status_code == 204 or not resp.content:
        return Response(status_code=resp.status_code)
    return JSONResponse(resp.json())


@router.post("/collector/jobs/{job_id}/progress")
async def collector_progress(
    job_id: Annotated[str, Path(pattern=SAFE_ID)],
    request: Request,
    _s: Annotated[str, Depends(collector_auth)],
) -> Response:
    body = await request.body()
    resp = await request.app.state.upstreams.ingest.send(
        "POST",
        f"/svc/v1/collector/jobs/{job_id}/progress",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    return Response(status_code=resp.status_code)


@router.put("/collector/acquisitions/{job_id}")
async def collector_upload(
    job_id: Annotated[str, Path(pattern=SAFE_ID)],
    request: Request,
    _s: Annotated[str, Depends(collector_stream_auth)],
) -> Response:
    """Arsip dialirkan ke ingest tanpa dibaca; batas ukuran, hash, dan isi arsip diperiksa ingest."""
    sha = request.headers.get("x-archive-sha256", "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha) or "content-length" not in request.headers:
        raise ApiError("VALIDASI_GAGAL", "X-Archive-Sha256 dan Content-Length wajib", 400)
    resp = await request.app.state.upstreams.ingest.send(
        "PUT",
        f"/svc/v1/collector/acquisitions/{job_id}",
        content=request.stream(),
        headers={
            "X-Archive-Sha256": sha,
            "Content-Length": request.headers["content-length"],
            "Content-Type": request.headers.get("content-type", "application/octet-stream"),
        },
        timeout=300.0,
    )
    return Response(status_code=resp.status_code)
