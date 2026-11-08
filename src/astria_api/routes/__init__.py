"""Router `/api/v1`."""

from fastapi import APIRouter

from astria_api.routes import auth, dashboard, platform

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(auth.router)
api_v1.include_router(dashboard.router)
api_v1.include_router(platform.router)
