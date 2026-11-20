from fastapi import APIRouter, Depends

from app.api.dependencies.auth import get_current_user
from app.api.routes.v1 import (
    ai,
    assets,
    auth,
    reports,
    risk,
    scans,
    targets,
    users,
    vulnerabilities,
)

api_router = APIRouter()

# Public: account creation and session management only.
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

# Everything else requires a valid access token. Routes that need the
# caller's identity also declare get_current_user themselves; FastAPI
# resolves it once per request.
_protected = [Depends(get_current_user)]
api_router.include_router(
    users.router, prefix="/users", tags=["users"], dependencies=_protected
)
api_router.include_router(
    targets.router, prefix="/targets", tags=["targets"], dependencies=_protected
)
api_router.include_router(
    scans.router, prefix="/scans", tags=["scans"], dependencies=_protected
)
api_router.include_router(
    assets.router, prefix="/assets", tags=["assets"], dependencies=_protected
)
api_router.include_router(
    vulnerabilities.router,
    prefix="/vulnerabilities",
    tags=["vulnerabilities"],
    dependencies=_protected,
)
api_router.include_router(
    risk.router, prefix="/risk", tags=["risk"], dependencies=_protected
)
api_router.include_router(ai.router, prefix="/ai", tags=["ai"], dependencies=_protected)
api_router.include_router(
    reports.router, prefix="/reports", tags=["reports"], dependencies=_protected
)
