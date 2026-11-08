"""Login, logout, me, reauth. Sesi dibuat dan dicabut oleh identity; api hanya menyetel cookie dan menerapkan RBAC."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from astria_api.auth import RATE_LIMITED, Session, authorize
from astria_api.errors import ERROR_RESPONSES, too_many, unauthenticated, upstream_failed
from astria_api.permissions import Perm, permissions_of
from astria_api.routing import public

router = APIRouter(prefix="/auth", tags=["auth"], responses=ERROR_RESPONSES)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=256)


class ReauthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    user_id: str
    username: str | None = None
    roles: list[str]
    permissions: list[str]


class LoginResponse(BaseModel):
    user: UserOut
    expires_at: str | None = None
    idle_expires_at: str | None = None


class MeResponse(BaseModel):
    user_id: str
    roles: list[str]
    permissions: list[str]
    reauth_at: str | None = None


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _max_age(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    try:
        seconds = int((datetime.fromisoformat(expires_at) - datetime.now(UTC)).total_seconds())
    except ValueError:
        return None
    return max(seconds, 0)


def _permissions(roles: list[str] | tuple[str, ...]) -> list[str]:
    return sorted(p.value for p in permissions_of(roles))


@router.post("/login", response_model=LoginResponse, summary="Masuk dan buka sesi")
@public
async def login(body: LoginRequest, request: Request, response: Response) -> LoginResponse:
    state: Any = request.app.state
    ip = request.client.host if request.client else "-"
    retry = state.login_limiter.take(f"ip:{ip}")
    if retry:
        RATE_LIMITED.labels("login").inc()
        raise too_many(retry)
    resp = await state.upstreams.identity.send(
        "POST",
        "/internal/v1/auth/login",
        json={
            "username": body.username,
            "password": body.password.get_secret_value(),
            "client": {"ip_hash": _hash(ip), "user_agent_hash": _hash(request.headers.get("user-agent", ""))},
        },
        ok_statuses=frozenset({401}),
    )
    if resp.status_code == 401:
        raise unauthenticated()
    data = resp.json()
    token, user = data.get("session_token"), data.get("user")
    if not isinstance(token, str) or not isinstance(user, dict) or not isinstance(user.get("roles"), list):
        raise upstream_failed("identity")
    response.set_cookie(
        state.settings.cookie_name,
        token,
        max_age=_max_age(data.get("expires_at")),
        httponly=True,
        samesite="strict",
        secure=state.settings.cookie_secure,
        path="/",
    )
    roles = [r for r in user["roles"] if isinstance(r, str)]
    return LoginResponse(
        user=UserOut(
            user_id=user["user_id"], username=user.get("username"), roles=roles, permissions=_permissions(roles)
        ),
        expires_at=data.get("expires_at"),
        idle_expires_at=data.get("idle_expires_at"),
    )


@router.post("/logout", status_code=204, summary="Tutup sesi")
async def logout(request: Request, session: Annotated[Session, Depends(authorize(Perm.SESSION))]) -> Response:
    state: Any = request.app.state
    token = request.cookies.get(state.settings.cookie_name, "")
    await state.upstreams.identity.send(
        "POST", "/internal/v1/auth/logout", actor=session.actor, json={"token": token}, ok_statuses=frozenset({401})
    )
    state.sessions.forget(token)
    if session.session_id:
        state.hub.close_session(session.session_id)
    response = Response(status_code=204)
    response.delete_cookie(state.settings.cookie_name, path="/")
    return response


@router.get("/me", response_model=MeResponse, summary="Pengguna, peran, dan izin")
async def me(session: Annotated[Session, Depends(authorize(Perm.SESSION))]) -> MeResponse:
    return MeResponse(
        user_id=session.user_id,
        roles=list(session.roles),
        permissions=_permissions(session.roles),
        reauth_at=session.reauth_at,
    )


@router.post("/reauth", summary="Konfirmasi ulang kata sandi untuk aksi sensitif")
async def reauth(
    body: ReauthRequest, request: Request, session: Annotated[Session, Depends(authorize(Perm.SESSION))]
) -> dict[str, Any]:
    state: Any = request.app.state
    token = request.cookies.get(state.settings.cookie_name, "")
    resp = await state.upstreams.identity.send(
        "POST",
        "/internal/v1/auth/reauth",
        actor=session.actor,
        json={"token": token, "password": body.password.get_secret_value()},
        ok_statuses=frozenset({401}),
    )
    if resp.status_code == 401:
        raise unauthenticated()
    state.sessions.forget(token)  # reauth_at berubah; ambil ulang pada permintaan berikutnya
    data = resp.json() if resp.content else {}
    return {"reauth_at": data.get("reauth_at")} if isinstance(data, dict) else {}
