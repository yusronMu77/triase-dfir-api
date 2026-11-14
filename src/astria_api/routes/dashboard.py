"""Rute dasbor: kartu, ingest, kasus, digest, serah terima, audit, metrik, konfigurasi, kanal, identitas, pindai.

Rute yang hanya memproksi dideklarasikan sebagai `ProxySpec` (izin RBAC per rute, jalur tujuan per note layanan).
Rute yang menyusun data atau memeriksa objek ditulis eksplisit di bawahnya.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from astria_api import compose
from astria_api.audit import build_record
from astria_api.auth import Session, authorize
from astria_api.errors import ERROR_RESPONSES, ApiError, upstream_failed
from astria_api.permissions import Perm, can_manage_identity
from astria_api.routing import SAFE_ID, ProxySpec, add_proxies

router = APIRouter(responses=ERROR_RESPONSES)

CARD_QUERY = ("status", "band", "host", "dari", "sampai", "pemilik", "prioritas=priority", "cursor", "limit")

SPECS = [
    # --- kartu (tiket) ---
    ProxySpec("GET", "/cards", Perm.CARDS_READ, "ticket", "/svc/v1/tickets", "Antrean kartu", query=CARD_QUERY),
    ProxySpec(
        "PATCH",
        "/cards/{card_id}",
        Perm.CARDS_WRITE,
        "ticket",
        "/svc/v1/tickets/{card_id}",
        "Ubah status, pemilik, atau prioritas",
        body=True,
    ),
    ProxySpec(
        "POST",
        "/cards/{card_id}/events",
        Perm.CARDS_WRITE,
        "ticket",
        "/svc/v1/tickets/{card_id}/events",
        "Tambah aktivitas",
        body=True,
        status=201,
    ),
    ProxySpec(
        "POST",
        "/cards/{card_id}/feedback",
        Perm.CARDS_WRITE,
        "ticket",
        "/svc/v1/tickets/{card_id}/feedback",
        "Feedback analis",
        body=True,
    ),
    ProxySpec(
        "POST",
        "/cards/{card_id}/deep-dive",
        Perm.CARDS_DEEP_DIVE,
        "dfir",
        "/internal/v1/cases",
        "Minta analisis DFIR",
        status=202,
        body_template={"card_id": "{card_id}"},
    ),
    # --- kasus DFIR ---
    ProxySpec(
        "GET", "/cases/{case_id}", Perm.CASES_READ, "dfir", "/internal/v1/cases/{case_id}", "Status dan ringkasan kasus"
    ),
    ProxySpec(
        "GET",
        "/cases/{case_id}/timeline",
        Perm.CASES_READ,
        "dfir",
        "/internal/v1/cases/{case_id}/timeline",
        "Linimasa kasus",
        query=("cursor", "limit"),
    ),
    ProxySpec(
        "GET",
        "/cases/{case_id}/custody",
        Perm.CASES_READ,
        "dfir",
        "/internal/v1/cases/{case_id}/custody",
        "Rantai custody berhash dan hasil cek keutuhan (chain_ok dihitung dfir)",
    ),
    ProxySpec(
        "GET",
        "/cases/{case_id}/report",
        Perm.CASES_READ,
        "dfir",
        "/internal/v1/cases/{case_id}/report",
        "Draf laporan (HTML atau PDF)",
        query=("format",),
        raw=True,
    ),
    # --- ingest dan pindai perangkat ---
    ProxySpec(
        "GET", "/ingest/jobs/{job_id}", Perm.INGEST_READ, "ingest", "/svc/v1/ingest/jobs/{job_id}", "Status ingest"
    ),
    ProxySpec(
        "POST",
        "/device-scans",
        Perm.DEVICE_SCANS,
        "ingest",
        "/svc/v1/device-scans",
        "Ajukan pemindaian perangkat",
        body=True,
        status=202,
    ),
    ProxySpec("GET", "/devices", Perm.DEVICE_SCANS, "ingest", "/svc/v1/devices", "Daftar perangkat"),
    ProxySpec(
        "GET",
        "/device-scans/{scan_id}",
        Perm.DEVICE_SCANS,
        "ingest",
        "/svc/v1/device-scans/{scan_id}",
        "Status pemindaian",
    ),
    # --- digest dan serah terima ---
    ProxySpec(
        "GET", "/digests", Perm.DIGESTS_READ, "scheduler", "/svc/v1/digests", "Daftar digest", query=("limit", "cursor")
    ),
    ProxySpec(
        "GET", "/digests/{digest_id}", Perm.DIGESTS_READ, "scheduler", "/svc/v1/digests/{digest_id}", "Metadata digest"
    ),
    ProxySpec(
        "GET",
        "/digests/{digest_id}/document",
        Perm.DIGESTS_READ,
        "scheduler",
        "/svc/v1/digests/{digest_id}/dokumen",
        "Isi digest (PDF atau HTML)",
        query=("format",),
        raw=True,
    ),
    ProxySpec(
        "POST",
        "/digests/run",
        Perm.DIGESTS_RUN,
        "scheduler",
        "/svc/v1/digests/run",
        "Jalankan digest manual",
        body=True,
        audit="digest.run",
        audit_target="digest",
    ),
    ProxySpec(
        "GET", "/handover/current", Perm.HANDOVER, "scheduler", "/svc/v1/handover/current", "Draf serah terima shift"
    ),
    ProxySpec(
        "POST",
        "/handover",
        Perm.HANDOVER,
        "scheduler",
        "/svc/v1/handover",
        "Simpan serah terima",
        body=True,
        status=201,
    ),
    # --- audit dan metrik ---
    ProxySpec(
        "GET", "/audit", Perm.AUDIT_READ, "audit", "/internal/v1/records", "Jejak audit", query=("from_seq", "limit")
    ),
    ProxySpec(
        "POST", "/audit/verify", Perm.AUDIT_VERIFY, "audit", "/internal/v1/verify-jobs", "Mulai verifikasi rantai hash"
    ),
    ProxySpec(
        "GET",
        "/audit/verify/{job_id}",
        Perm.AUDIT_VERIFY,
        "audit",
        "/internal/v1/verify-jobs/{job_id}",
        "Hasil verifikasi rantai hash",
    ),
    ProxySpec(
        "GET", "/metrics", Perm.METRICS_READ, "ticket", "/svc/v1/stats", "Metrik harian", query=("dari", "sampai")
    ),
    # --- konfigurasi dan rahasia (hanya admin; ditulis ke audit sebelum aksi) ---
    ProxySpec(
        "GET", "/config", Perm.CONFIG_READ, "config", "/v1/settings", "Pengaturan efektif (rahasia tidak tampil)"
    ),
    ProxySpec(
        "PUT",
        "/config/secrets/{key}",
        Perm.SECRETS_WRITE,
        "config",
        "/v1/secrets/{key}",
        "Tulis rahasia (tulis-saja)",
        body=True,
        audit="config.secret_write",
        audit_target="secret",
    ),
    ProxySpec(
        "PUT",
        "/config/{key}",
        Perm.CONFIG_WRITE,
        "config",
        "/v1/settings/{key}",
        "Ubah pengaturan",
        body=True,
        audit="config.setting_write",
        audit_target="setting",
    ),
    # --- kanal, log kirim, dan kode pairing ---
    ProxySpec(
        "PUT",
        "/channels/{channel_id}",
        Perm.CHANNELS_ADMIN,
        "config",
        "/v1/channels/policy/{channel_id}",
        "Ubah kebijakan kanal",
        body=True,
        audit="channel.policy_write",
        audit_target="channel",
    ),
    ProxySpec(
        "POST",
        "/channels/{channel_id}/test",
        Perm.CHANNELS_ADMIN,
        "gateway",
        "/internal/v1/channels/{channel_id}/test",
        "Uji koneksi kanal",
        audit="channel.test",
        audit_target="channel",
    ),
    ProxySpec(
        "GET",
        "/channels/whatsapp/link",
        Perm.CHANNELS_ADMIN,
        "gateway",
        "/internal/v1/whatsapp/link",
        "Status tautan bot WhatsApp dan QR untuk dipindai",
    ),
    ProxySpec(
        "POST",
        "/channels/whatsapp/link/logout",
        Perm.CHANNELS_ADMIN,
        "gateway",
        "/internal/v1/whatsapp/link/logout",
        "Putuskan tautan bot WhatsApp",
        audit="channel.whatsapp_unlink",
        audit_target="channel",
    ),
    ProxySpec(
        "GET", "/outbox", Perm.CHANNELS_ADMIN, "gateway", "/internal/v1/outbox", "Log pengiriman", query=("status",)
    ),
    ProxySpec(
        "POST",
        "/outbox/{outbox_id}/retry",
        Perm.CHANNELS_ADMIN,
        "gateway",
        "/internal/v1/outbox/{outbox_id}/retry",
        "Coba kirim ulang",
        audit="outbox.retry",
        audit_target="outbox",
    ),
    ProxySpec(
        "POST",
        "/identities/pairing-codes",
        Perm.IDENTITIES_OWN,
        "identity",
        "/internal/v1/pairing-codes",
        "Terbitkan kode pairing untuk diri sendiri",
        body=True,
        status=201,
    ),
]
add_proxies(router, SPECS)


# --- kartu: komposisi ---


@router.get("/cards/{card_id}", summary="Detail kartu dengan Penjelas Alert", tags=["cards"])
async def card_detail(
    card_id: Annotated[str, Path(pattern=SAFE_ID)],
    request: Request,
    session: Annotated[Session, Depends(authorize(Perm.CARDS_READ))],
) -> JSONResponse:
    state: Any = request.app.state
    return JSONResponse(await compose.card_detail(state.upstreams, state.config_cache, session.actor, card_id))


@router.get("/cards/{card_id}/evidence", summary="Daftar bukti dengan hash (tanpa isi mentah)", tags=["cards"])
async def card_evidence(
    card_id: Annotated[str, Path(pattern=SAFE_ID)],
    request: Request,
    session: Annotated[Session, Depends(authorize(Perm.CARDS_READ))],
) -> JSONResponse:
    return JSONResponse(await compose.card_evidence(request.app.state.upstreams, session.actor, card_id))


@router.get("/alerts/{alert_id}/explain", summary="Penjelas Alert", tags=["cards"])
async def alert_explain(
    alert_id: Annotated[str, Path(pattern=SAFE_ID)],
    request: Request,
    session: Annotated[Session, Depends(authorize(Perm.CARDS_READ))],
) -> JSONResponse:
    state: Any = request.app.state
    return JSONResponse(await compose.alert_explain(state.upstreams, state.config_cache, session.actor, alert_id))


# --- ingest dengan validasi tambahan ---


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    adapter: str = Field(pattern=r"^[a-z][a-z0-9_]{0,39}$")
    path_ref: str = Field(min_length=1, max_length=300)
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("path_ref")
    @classmethod
    def _no_traversal(cls, value: str) -> str:
        parts = re.split(r"[\\/]", value)
        if ".." in parts or "\x00" in value:
            raise ValueError("path_ref tidak boleh memuat '..'")
        return value


@router.post("/ingest", status_code=202, summary="Mulai ingest dari path yang diizinkan", tags=["ingest"])
async def start_ingest(
    body: IngestRequest,
    request: Request,
    session: Annotated[Session, Depends(authorize(Perm.INGEST_WRITE))],
) -> JSONResponse:
    resp = await request.app.state.upstreams.ingest.send(
        "POST", "/svc/v1/ingest/jobs", actor=session.actor, json=body.model_dump(exclude_none=True)
    )
    return JSONResponse(resp.json() if resp.content else {}, status_code=202)


# --- kanal: kebijakan (config) + status (gateway) ---


@router.get("/channels", summary="Kebijakan kanal dan status transport", tags=["channels"])
async def list_channels(
    request: Request, session: Annotated[Session, Depends(authorize(Perm.CHANNELS_ADMIN))]
) -> JSONResponse:
    state: Any = request.app.state
    policy = await state.upstreams.config.json("GET", "/v1/channels/policy", actor=session.actor)
    missing: list[str] = []
    status = None
    try:
        status = await state.upstreams.gateway.json("GET", "/internal/v1/status", actor=session.actor)
    except ApiError:
        missing.append("status_gateway")
        compose.PARTIAL.labels("status_gateway").inc()
    return JSONResponse({"kebijakan": policy, "status": status, "bagian_tidak_tersedia": missing})


# --- identitas kanal: admin semua, pengguna lain hanya miliknya ---


def _items(data: Any) -> list[dict[str, Any]]:
    items = data.get("items", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise upstream_failed("gateway")
    return [i for i in items if isinstance(i, dict)]


@router.get("/identities", summary="Ikatan kanal (admin: semua; lainnya: milik sendiri)", tags=["identities"])
async def list_identities(
    request: Request, session: Annotated[Session, Depends(authorize(Perm.IDENTITIES_OWN))]
) -> JSONResponse:
    data = await request.app.state.upstreams.gateway.json("GET", "/internal/v1/identities", actor=session.actor)
    items = [
        i
        for i in _items(data)
        if can_manage_identity(session.roles, caller_user_id=session.user_id, owner_user_id=i.get("user_id"))
    ]
    return JSONResponse({"items": items})


@router.delete("/identities/{identity_id}", status_code=204, summary="Cabut ikatan kanal", tags=["identities"])
async def revoke_identity(
    identity_id: Annotated[str, Path(pattern=SAFE_ID)],
    request: Request,
    session: Annotated[Session, Depends(authorize(Perm.IDENTITIES_OWN))],
) -> Response:
    state: Any = request.app.state
    data = await state.upstreams.gateway.json("GET", "/internal/v1/identities", actor=session.actor)
    target = next((i for i in _items(data) if str(i.get("id")) == identity_id), None)
    # Objek yang bukan milik pemanggil dijawab 404 (bukan 403) supaya keberadaan ikatan orang lain tidak bocor.
    if target is None or not can_manage_identity(
        session.roles, caller_user_id=session.user_id, owner_user_id=target.get("user_id")
    ):
        raise ApiError("TIDAK_DITEMUKAN", "data tidak ditemukan", 404)
    act = session.actor.act()
    key = f"api-identity-revoke-{identity_id}"
    await state.audit.before(
        build_record(
            key=key + "-req",
            actor=session.user_id,
            actor_type="user",
            action="identity.binding_revoke_requested",
            target_type="identity",
            target_id=identity_id,
            via="ui",
            payload={"owner": target.get("user_id") == session.user_id},
        ),
        act=act,
    )
    await state.upstreams.gateway.send("DELETE", f"/internal/v1/identities/{identity_id}", actor=session.actor)
    await state.audit.after(
        build_record(
            key=key + "-done",
            actor=session.user_id,
            actor_type="user",
            action="identity.binding_revoke_completed",
            target_type="identity",
            target_id=identity_id,
            via="ui",
            payload={},
        ),
        act=act,
    )
    return Response(status_code=204)
