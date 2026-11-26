from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.api.dependencies.auth import get_current_user
from app.api.dependencies.database import get_db
from app.audit.context import ActorContext, AuditContext, RequestContext
from app.core.config import get_settings
from app.core.security import (
    CLIENT_IP_HEADER,
    PROXY_SECRET_HEADER,
    resolve_client_ip,
)
from app.models.user import User
from app.repositories.audit_repository import AuditRepository
from app.services.audit_service import AuditService


def _request_context(request: Request) -> RequestContext:
    """Correlation id and the client address.

    `source_ip` is the ASGI peer address, unless TRUSTED_PROXY_SECRET is set
    and the request carries that secret, in which case the proxy-supplied
    client IP is used. Generic forwarded headers (X-Forwarded-For,
    X-Real-IP) are never trusted.
    """
    request_id = getattr(request.state, "request_id", None)
    peer = request.client.host if request.client else None
    source_ip = resolve_client_ip(
        peer=peer,
        forwarded_ip=request.headers.get(CLIENT_IP_HEADER),
        presented_secret=request.headers.get(PROXY_SECRET_HEADER),
        expected_secret=get_settings().trusted_proxy_secret.get_secret_value(),
    )
    return RequestContext(request_id=request_id, source_ip=source_ip)


def get_anonymous_audit_context(request: Request) -> AuditContext:
    """Context for unauthenticated endpoints (register, login, refresh)."""
    return AuditContext(
        actor=ActorContext.anonymous(), request=_request_context(request)
    )


def get_audit_context(
    request: Request, current_user: User = Depends(get_current_user)
) -> AuditContext:
    """Context for authenticated endpoints: the verified user is the actor."""
    return AuditContext(
        actor=ActorContext.user(current_user.id), request=_request_context(request)
    )


def get_audit_service(db: Session = Depends(get_db)) -> AuditService:
    """Dependency to inject a fully constructed AuditService into routes."""
    return AuditService(AuditRepository(db))
