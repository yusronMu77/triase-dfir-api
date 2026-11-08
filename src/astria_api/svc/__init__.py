"""Router `/svc/v1` (hanya untuk gateway dan collector; tidak pernah diteruskan Caddy ke internet)."""

from fastapi import APIRouter

from astria_api.svc import commands, other

svc_v1 = APIRouter()
svc_v1.include_router(commands.router)
svc_v1.include_router(other.router)
