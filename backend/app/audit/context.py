"""Actor and request context abstractions for audit logging.

These are pure, framework-independent value objects. They express "who or
what triggered this action" and "which request does this belong to"
without passing FastAPI's `Request` object into business services.
"""

import uuid
from dataclasses import dataclass

from app.core.enums import AuditActorType

# Bounds mirror the AuditEvent column widths (see app/models/audit_event.py)
# and defend against oversized/malformed inbound values before they ever
# reach a service or the database.
MAX_ACTOR_ID_LENGTH = 100
MAX_REQUEST_ID_LENGTH = 100
MAX_SOURCE_IP_LENGTH = 45  # longest valid textual IPv6 representation


@dataclass(frozen=True)
class ActorContext:
    """Who (or what) triggered an audited action.

    `actor_id` is set only for USER, and only from a verified access token.
    It is always None for SYSTEM and ANONYMOUS, so a client can never
    supply an identity that is trusted as if it were authenticated.
    """

    actor_type: AuditActorType
    actor_id: str | None = None

    @classmethod
    def anonymous(cls) -> "ActorContext":
        """The default actor for any current, unauthenticated HTTP request."""
        return cls(actor_type=AuditActorType.ANONYMOUS, actor_id=None)

    @classmethod
    def system(cls) -> "ActorContext":
        """The actor for internal orchestration with no HTTP caller."""
        return cls(actor_type=AuditActorType.SYSTEM, actor_id=None)

    @classmethod
    def user(cls, user_id: uuid.UUID) -> "ActorContext":
        """An authenticated user, identified only by the verified token."""
        return cls(actor_type=AuditActorType.USER, actor_id=str(user_id))


@dataclass(frozen=True)
class RequestContext:
    """Request-scoped correlation context, safe to persist as audit evidence.

    `source_ip` is the direct ASGI connection address (`Request.client.host`)
    unless the request carries the configured TRUSTED_PROXY_SECRET, in which
    case it is the client IP that trusted proxy reports (see
    `app.core.security.resolve_client_ip`). `X-Forwarded-For`/`X-Real-IP`
    are never treated as authoritative.
    """

    request_id: str | None = None
    source_ip: str | None = None


@dataclass(frozen=True)
class AuditContext:
    """The complete actor + request context for one audited action."""

    actor: ActorContext
    request: RequestContext

    @classmethod
    def system(cls) -> "AuditContext":
        """Default context for service calls made outside an HTTP request
        (e.g. direct invocation in internal orchestration or tests)."""
        return cls(actor=ActorContext.system(), request=RequestContext())
