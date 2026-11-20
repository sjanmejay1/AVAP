import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent


class AuditRepository:
    """Append-only repository for AuditEvent persistence.

    Deliberately exposes no update(), delete(), or upsert() method for
    persisted events. `append()` only adds and flushes — it never commits;
    the calling service owns the transaction boundary so that SUCCESS/
    FAILURE audit semantics can be coordinated with the business
    transaction they document (see AuditService and each integrated
    service's transaction semantics).
    """

    def __init__(self, session: Session):
        self.session = session

    def append(self, event: AuditEvent) -> AuditEvent:
        """Persist a new audit event. Never updates an existing row."""
        self.session.add(event)
        self.session.flush()
        return event

    def get_by_id(self, event_id: uuid.UUID) -> AuditEvent | None:
        stmt = select(AuditEvent).where(AuditEvent.id == event_id)
        return self.session.execute(stmt).scalar_one_or_none()
