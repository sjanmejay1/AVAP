import uuid
from datetime import UTC, datetime

import pytest

from app.core.enums import (
    AuditActorType,
    AuditEventCategory,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
)
from app.models.audit_event import AuditEvent
from app.repositories.audit_repository import AuditRepository


@pytest.fixture
def repository(db_session):
    return AuditRepository(db_session)


def _event(
    event_type=AuditEventType.TARGET_CREATED,
    category=AuditEventCategory.TARGET,
    outcome=AuditOutcome.SUCCESS,
    actor_type=AuditActorType.ANONYMOUS,
    resource_type=AuditResourceType.TARGET,
    resource_id=None,
    scan_id=None,
    occurred_at=None,
    **kw,
):
    return AuditEvent(
        event_type=event_type,
        category=category,
        outcome=outcome,
        actor_type=actor_type,
        resource_type=resource_type,
        resource_id=resource_id or uuid.uuid4(),
        scan_id=scan_id,
        event_metadata=kw.pop("event_metadata", {}),
        occurred_at=occurred_at or datetime.now(UTC),
        **kw,
    )


# --- Append / get ---


def test_append_persists_event(repository):
    event = repository.append(_event())
    assert event.id is not None


def test_get_by_id_returns_event(repository):
    created = repository.append(_event())
    fetched = repository.get_by_id(created.id)
    assert fetched is not None
    assert fetched.id == created.id


def test_get_by_id_returns_none_when_absent(repository):
    assert repository.get_by_id(uuid.uuid4()) is None


# --- No mutation methods exist ---


def test_repository_exposes_no_update_method(repository):
    assert not hasattr(repository, "update")


def test_repository_exposes_no_delete_method(repository):
    assert not hasattr(repository, "delete")


def test_repository_exposes_no_upsert_method(repository):
    assert not hasattr(repository, "upsert")


# --- Repository does not commit ---


def test_append_does_not_commit(db_session, repository):
    repository.append(_event())
    db_session.rollback()
    remaining = db_session.query(AuditEvent).count()
    assert remaining == 0


# --- Filtering ---
