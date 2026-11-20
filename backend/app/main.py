import logging
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, asynccontextmanager, contextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api.middleware.exception_handler import setup_exception_handlers
from app.api.middleware.request_context import setup_request_context_middleware
from app.api.routes.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.database.session import SessionLocal, engine
from app.repositories.audit_repository import AuditRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.services.audit_service import AuditService
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)

SessionScope = Callable[[], AbstractContextManager[Session]]


@contextmanager
def _default_session_scope() -> Iterator[Session]:
    """Open a standalone DB session for startup work and always close it."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def recover_interrupted_scans(session_scope: SessionScope) -> None:
    """Fail scans orphaned by a previous server process.

    A failure here is logged and swallowed: startup must not be blocked by
    recovery, and the affected scans stay visible as PENDING/RUNNING.
    """
    try:
        with session_scope() as session:
            service = ScanService(
                scan_repository=ScanRepository(session),
                target_repository=TargetRepository(session),
                audit_service=AuditService(AuditRepository(session)),
            )
            service.recover_interrupted_scans()
    except Exception:
        logger.exception(
            "Startup scan recovery failed; orphaned scans may persist.",
            extra={"context": {"operation": "recover_interrupted_scans"}},
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events for the FastAPI application."""
    setup_logging()

    # Tests replace app.state.session_scope with their transactional session
    # so startup recovery never touches the database configured in .env.
    session_scope: SessionScope = getattr(
        app.state, "session_scope", _default_session_scope
    )
    recover_interrupted_scans(session_scope)

    yield

    # Cleanup on shutdown
    engine.dispose()


def create_app() -> FastAPI:
    """Application factory for FastAPI."""
    settings = get_settings()
    # Refuse to start without strong auth secrets (names only in the error).
    settings.validate_security_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Automated Vulnerability Assessment Platform API",
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS: an explicit origin list (never a wildcard) with credentials,
    # so the browser sends the httpOnly refresh cookie to /auth/refresh.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    # Register custom exception handlers
    setup_exception_handlers(app)

    # Assign/propagate a per-request correlation ID (used by audit logging)
    setup_request_context_middleware(app)

    # Include API routing
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/health", tags=["system"])
    async def health_check() -> dict[str, str]:
        """Simple health check endpoint."""
        return {"status": "healthy", "version": settings.app_version}

    return app


app = create_app()
