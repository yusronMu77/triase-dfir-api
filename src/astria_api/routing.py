"""Pembantu rute: pembuat rute proksi deklaratif dan pemeriksa bahwa setiap rute punya kebijakan akses.

Rute proksi hanya meneruskan JSON (note api bagian 3.1): `api` menambahkan sesi, izin RBAC, token dengan `act`,
audit (bila diminta), dan galat seragam. Parameter jalur divalidasi ketat (anti path traversal) dan query hanya
diteruskan bila ada di daftar izin spec.
"""

from __future__ import annotations

import inspect
import re
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Annotated, Any

from astria_common.tracing import current_trace_id
from fastapi import APIRouter, Body, Depends, Path, Query, Request, Response
from fastapi.dependencies.models import Dependant
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from astria_api.audit import build_record
from astria_api.auth import Session, authorize
from astria_api.errors import ERROR_RESPONSES
from astria_api.permissions import Perm

PATH_PARAM = re.compile(r"\{(\w+)\}")
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"


@dataclass(frozen=True)
class ProxySpec:
    method: str
    path: str  # relatif ke /api/v1
    perm: Perm
    service: str
    target: str  # jalur di layanan tujuan; boleh memuat {param} dari path
    summary: str
    query: tuple[str, ...] = ()  # "nama" atau "nama_publik=nama_upstream"
    body: bool = False
    status: int | None = None  # None = salin status sukses upstream
    raw: bool = False  # respons biner atau HTML diteruskan apa adanya
    audit: str | None = None  # aksi audit sinkron sebelum aksi (fail-closed)
    audit_target: str = ""
    body_template: dict[str, str] | None = None  # badan dibangun dari parameter jalur, mis. {"card_id": "{card_id}"}


def _query_map(spec: ProxySpec) -> dict[str, str]:
    mapping = {}
    for item in spec.query:
        public, _, upstream = item.partition("=")
        mapping[public] = upstream or public
    return mapping


def add_proxy(router: APIRouter, spec: ProxySpec) -> None:
    path_names = PATH_PARAM.findall(spec.path)
    qmap = _query_map(spec)

    async def handler(request: Request, session: Session, **kwargs: Any) -> Response:
        state: Any = request.app.state
        values = {name: kwargs[name] for name in path_names}
        target = spec.target.format(**values)
        params = {up: kwargs.get(pub) for pub, up in qmap.items()}
        payload = kwargs.get("body")
        if spec.body_template is not None:
            payload = {k: v.format(**values) for k, v in spec.body_template.items()}
        headers = {}
        if key := request.headers.get("idempotency-key"):
            headers["Idempotency-Key"] = key[:200]
        act = session.actor.act()
        record_key = f"api-{current_trace_id() or uuid.uuid4().hex}-{spec.audit}" if spec.audit else ""
        if spec.audit:
            await state.audit.before(
                build_record(
                    key=record_key + "-req",
                    actor=session.user_id,
                    actor_type="user",
                    action=spec.audit + "_requested",
                    target_type=spec.audit_target or spec.service,
                    target_id=next(iter(values.values()), spec.audit_target or "-"),
                    via="ui",
                    payload={"route": spec.path, "method": spec.method},
                ),
                act=act,
            )
        resp = await state.upstreams.get(spec.service).send(
            spec.method, target, actor=session.actor, json=payload, params=params, headers=headers
        )
        if spec.audit:
            await state.audit.after(
                build_record(
                    key=record_key + "-done",
                    actor=session.user_id,
                    actor_type="user",
                    action=spec.audit + "_completed",
                    target_type=spec.audit_target or spec.service,
                    target_id=next(iter(values.values()), spec.audit_target or "-"),
                    via="ui",
                    payload={"route": spec.path, "status": resp.status_code},
                ),
                act=act,
            )
        status = spec.status or resp.status_code
        if resp.status_code == 204 or not resp.content:
            return Response(status_code=status)
        if spec.raw:
            extra = {k: v for k, v in resp.headers.items() if k.lower() == "content-disposition"}
            return Response(
                resp.content, status_code=status, media_type=resp.headers.get("content-type"), headers=extra
            )
        try:
            data = resp.json()
        except ValueError:
            from astria_api.errors import upstream_failed

            raise upstream_failed(spec.service) from None
        return JSONResponse(data, status_code=status)

    params: list[inspect.Parameter] = [
        inspect.Parameter(
            name, inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Annotated[str, Path(pattern=SAFE_ID)]
        )
        for name in path_names
    ]
    if spec.body:
        params.append(
            inspect.Parameter(
                "body", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Annotated[dict[str, Any], Body()]
            )
        )
    params.append(
        inspect.Parameter(
            "session",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=Annotated[Session, Depends(authorize(spec.perm))],
        )
    )
    params.append(inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request))
    params.extend(
        inspect.Parameter(
            name,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=Annotated[str | None, Query(max_length=200)],
            default=None,
        )
        for name in qmap
    )
    handler.__signature__ = inspect.Signature(params)  # type: ignore[attr-defined]
    handler.__name__ = f"{spec.method.lower()}_{re.sub(r'\W+', '_', spec.path).strip('_')}"
    router.add_api_route(
        spec.path,
        handler,
        methods=[spec.method],
        summary=spec.summary,
        status_code=spec.status or 200,
        response_model=None,
        responses=ERROR_RESPONSES,
    )


def add_proxies(router: APIRouter, specs: Iterable[ProxySpec]) -> None:
    for spec in specs:
        add_proxy(router, spec)


def _walk(dependant: Dependant) -> Iterable[Any]:
    for sub in dependant.dependencies:
        yield sub.call
        yield from _walk(sub)


def iter_routes(router: APIRouter) -> Iterator[APIRoute]:
    """Semua `APIRoute` milik router, termasuk yang dibungkus `include_router` (FastAPI 0.162 membungkusnya)."""
    for route in router.routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from iter_routes(inner)
        elif isinstance(route, APIRoute):
            yield route


def policy_of(route: APIRoute) -> Any:
    for call in _walk(route.dependant):
        for attr in ("astria_perm", "astria_svc"):
            if hasattr(call, attr):
                return getattr(call, attr)
    return None


def public(endpoint: Any) -> Any:
    """Tandai rute yang sengaja publik (login, health). Hanya rute bertanda ini yang boleh tanpa kebijakan."""
    endpoint.astria_public = True
    return endpoint


def unprotected_routes(*routers: APIRouter) -> list[str]:
    """Rute tanpa kebijakan akses (izin RBAC atau HMAC layanan), selain yang sengaja publik."""
    return [
        f"{sorted(route.methods)} {route.path}"
        for router in routers
        for route in iter_routes(router)
        if not getattr(route.endpoint, "astria_public", False) and policy_of(route) is None
    ]


def assert_all_routes_protected(*routers: APIRouter) -> None:
    """Gagal-tertutup saat startup: rute baru tanpa `authorize(...)` atau `require_service_hmac(...)` ditolak."""
    missing = unprotected_routes(*routers)
    if missing:
        raise RuntimeError("rute tanpa kebijakan akses: " + ", ".join(missing))
