"""Command Facade (`POST /svc/v1/commands`): katalog perintah tertutup, peran dicek ke identity tanpa cache,
T2 mati secara default, audit sinkron sebelum dan sesudah aksi, hasil dipangkas menurut `max_detail`.

Urutan (note api bagian 3.3 dan 5.3): HMAC -> katalog dan argumen -> pembatas laju -> pengguna dan peran
(identity) -> kebijakan kanal dan T2 (config) -> konfirmasi T1/T2 -> audit `requested` (fail-closed) -> aksi ->
audit `completed`. Penolakan setelah identitas diketahui dicatat sebagai `command.denied` (upaya terbaik).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from prometheus_client import Counter
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from astria_api import sanitize
from astria_api.audit import build_record
from astria_api.auth import RATE_LIMITED
from astria_api.compose import card_evidence
from astria_api.errors import ApiError, too_many, upstream_failed
from astria_api.permissions import COMMAND_ROLES, command_allowed
from astria_api.svc.signing import require_service_hmac
from astria_api.upstream import Actor

COMMANDS = Counter("astria_api_commands_total", "Perintah dari Gateway", ["command", "result"])

CARD_ID = re.compile(r"^IC-\d{8}-\d{3,6}$")
LABELS = frozenset({"benar", "salah_positif", "perlu_dfir"})
ARG_RULES: dict[str, dict[str, Any]] = {
    "status": {},
    "queue": {},
    "card": {"card_id": CARD_ID},
    "evidence_meta": {"card_id": CARD_ID},
    "digest_latest": {},
    "handover": {},
    "feedback": {"card_id": CARD_ID, "label": LABELS},
    "deep_dive": {"card_id": CARD_ID},
    "digest_run": {},
}
RESULT_ALLOW = {
    "digest_latest": ("digest_id", "periode", "status", "tautan"),
    "handover": ("serah_id", "jumlah_terbuka"),
    "deep_dive": ("case_id", "status"),
    "digest_run": ("digest_id", "status"),
}
EVIDENCE_FIELDS = ("evidence_id", "waktu", "sha256", "tautan")
QUEUE_MAX = 5

router = APIRouter(prefix="/svc/v1", include_in_schema=False)


class CommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str = Field(pattern=r"^usr_[A-Za-z0-9]+$")
    channel_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    command: str = Field(min_length=1, max_length=40)
    args: dict[str, str] = Field(default_factory=dict, max_length=5)
    idempotency_key: str = Field(min_length=1, max_length=200)
    confirmation_ref: str | None = Field(default=None, min_length=1, max_length=200)
    command_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


def command_hash(command: str, args: dict[str, str]) -> str:
    """Hash kanonik yang dihitung gateway dan api: sha256(command + "\\n" + JSON args terurut tanpa spasi)."""
    canonical = command + "\n" + json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_args(command: str, args: dict[str, str]) -> None:
    rules = ARG_RULES[command]
    if set(args) != set(rules):
        raise ApiError("ARGUMEN_TIDAK_VALID", "argumen perintah tidak sesuai", 400)
    for name, rule in rules.items():
        value = args[name]
        ok = value in rule if isinstance(rule, frozenset) else bool(rule.match(value))
        if not ok:
            raise ApiError("ARGUMEN_TIDAK_VALID", f"argumen {name} tidak valid", 400)


def _allow(item: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: item[k] for k in fields if isinstance(item, dict) and k in item}


async def _execute(state: Any, req: CommandRequest, actor: Actor, level: str) -> dict[str, Any]:
    ups = state.upstreams
    idem = {"Idempotency-Key": req.idempotency_key}
    cmd, args = req.command, req.args
    if cmd == "status":
        layanan = state.probe.snapshot()
        from astria_api.health import overall

        result: dict[str, Any] = {"status": overall(layanan)}
        if sanitize.effective_level(level) == "ringkas":
            result["layanan"] = layanan
        return result
    if cmd == "queue":
        data = await ups.ticket.json("GET", "/svc/v1/tickets", actor=actor, params={"limit": QUEUE_MAX})
        items = data.get("items", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            raise upstream_failed("ticket")
        out = []
        for item in items[:QUEUE_MAX]:
            row = sanitize.trim(item, level) if isinstance(item, dict) else {}
            if isinstance(item, dict) and isinstance(item.get("judul"), str):
                row["judul"] = sanitize.mask_title(item["judul"])
            out.append(row)
        return {"items": out}
    if cmd == "card":
        data = await ups.ticket.json("GET", f"/svc/v1/tickets/{args['card_id']}", actor=actor)
        return sanitize.trim(data, level) if isinstance(data, dict) else {}
    if cmd == "evidence_meta":
        data = await card_evidence(ups, actor, args["card_id"])
        return {
            "card_id": args["card_id"],
            "evidence": [_allow(e, EVIDENCE_FIELDS) for e in data["evidence"][:20]],
        }
    if cmd == "digest_latest":
        data = await ups.scheduler.json("GET", "/svc/v1/digests", actor=actor, params={"limit": 1})
        items = data.get("items", []) if isinstance(data, dict) else []
        return _allow(items[0] if isinstance(items, list) and items else {}, RESULT_ALLOW[cmd])
    if cmd == "handover":
        data = await ups.scheduler.json("GET", "/svc/v1/handover/current", actor=actor)
        return _allow(data, RESULT_ALLOW[cmd])
    if cmd == "feedback":
        await ups.ticket.send(
            "POST",
            f"/svc/v1/tickets/{args['card_id']}/feedback",
            actor=actor,
            json={"label": args["label"]},
            headers=idem,
        )
        return {"card_id": args["card_id"], "label": args["label"], "tercatat": True}
    if cmd == "deep_dive":
        data = await ups.dfir.json(
            "POST", "/internal/v1/cases", actor=actor, json={"card_id": args["card_id"]}, headers=idem
        )
        return _allow(data, RESULT_ALLOW[cmd])
    if cmd == "digest_run":
        data = await ups.scheduler.json("POST", "/svc/v1/digests/run", actor=actor, json={}, headers=idem)
        return _allow(data, RESULT_ALLOW[cmd])
    raise ApiError("PERINTAH_TIDAK_DIKENAL", "perintah tidak dikenal", 400)


@router.post("/commands")
async def run_command(
    request: Request, _service: Annotated[str, Depends(require_service_hmac("gateway"))]
) -> JSONResponse:
    state: Any = request.app.state
    try:
        req = CommandRequest.model_validate_json(await request.body())
    except ValidationError:
        COMMANDS.labels("tidak_valid", "ditolak").inc()
        raise ApiError("VALIDASI_GAGAL", "permintaan perintah tidak valid", 400) from None

    # Katalog tertutup: nama perintah dan argumen harus ada di tabel; teks bebas tidak pernah jadi perintah.
    if req.command not in COMMAND_ROLES:
        COMMANDS.labels("tidak_dikenal", "ditolak").inc()
        raise ApiError("PERINTAH_TIDAK_DIKENAL", "perintah tidak dikenal", 400)
    validate_args(req.command, req.args)
    tier = COMMAND_ROLES[req.command][0]

    for bucket, limiter in ((f"cmd:{req.user_id}", state.cmd_limiter), ("global:cmd", state.global_cmd_limiter)):
        retry = limiter.take(bucket)
        if retry:
            RATE_LIMITED.labels("cmd" if bucket != "global:cmd" else "global_cmd").inc()
            COMMANDS.labels(req.command, "dibatasi").inc()
            raise too_many(retry)

    async def denied(reason: str, error: ApiError, roles: list[str] | None = None) -> ApiError:
        COMMANDS.labels(req.command, reason).inc()
        await state.audit.after(
            build_record(
                key=f"cmd-{req.idempotency_key}-denied",
                actor=req.user_id,
                actor_type="user",
                action="command.denied",
                target_type="command",
                target_id=req.command,
                via="bot",
                payload={"reason": reason, "channel_id": req.channel_id, "tier": tier},
            )
        )
        return error

    # Pengguna dan peran saat ini, langsung dari identity (tanpa cache).
    user = await state.upstreams.identity.json("GET", f"/internal/v1/users/{req.user_id}")
    if not isinstance(user, dict) or not isinstance(user.get("roles"), list):
        raise upstream_failed("identity")
    roles = tuple(r for r in user["roles"] if isinstance(r, str))
    if user.get("active") is not True:
        raise await denied("pengguna_nonaktif", ApiError("DILARANG", "pengguna tidak aktif", 403))
    if not command_allowed(roles, req.command):
        raise await denied("peran", ApiError("DILARANG", "peran Anda tidak boleh menjalankan perintah ini", 403))

    policy = await state.config_cache.channel_policy(req.channel_id)
    if policy is None or policy.get("active") is not True:
        raise await denied("kanal_nonaktif", ApiError("DILARANG", "kanal tidak aktif", 403))
    if tier == "T2" and (await state.config_cache.setting("chat", "chat.allow_t2")) is not True:
        raise await denied("t2_dimatikan", ApiError("T2_DIMATIKAN", "perintah tingkat T2 dimatikan di kanal chat", 403))
    if tier in {"T1", "T2"}:
        expected = command_hash(req.command, req.args)
        if (
            req.confirmation_ref is None
            or req.command_hash is None
            or not hmac.compare_digest(req.command_hash, expected)
        ):
            raise await denied(
                "konfirmasi", ApiError("KONFIRMASI_WAJIB", "perintah ini memerlukan konfirmasi yang cocok", 403)
            )

    actor = Actor(sub=req.user_id, roles=roles)
    act = actor.act()
    target_id = req.args.get("card_id", req.command)
    base = {"channel_id": req.channel_id, "tier": tier, "command": req.command}
    await state.audit.before(
        build_record(
            key=f"cmd-{req.idempotency_key}-requested",
            actor=req.user_id,
            actor_type="user",
            action="command.requested",
            target_type="command",
            target_id=target_id,
            via="bot",
            payload=base,
        ),
        act=act,
    )
    try:
        result = await _execute(state, req, actor, str(policy.get("max_detail", "minimal")))
    except ApiError as exc:
        COMMANDS.labels(req.command, "gagal").inc()
        await state.audit.after(
            build_record(
                key=f"cmd-{req.idempotency_key}-completed",
                actor=req.user_id,
                actor_type="user",
                action="command.completed",
                target_type="command",
                target_id=target_id,
                via="bot",
                payload=base | {"result": "gagal", "code": exc.code},
            ),
            act=act,
        )
        raise
    COMMANDS.labels(req.command, "ok").inc()
    await state.audit.after(
        build_record(
            key=f"cmd-{req.idempotency_key}-completed",
            actor=req.user_id,
            actor_type="user",
            action="command.completed",
            target_type="command",
            target_id=target_id,
            via="bot",
            payload=base | {"result": "ok"},
        ),
        act=act,
    )
    return JSONResponse({"command": req.command, "ok": True, "hasil": result})
