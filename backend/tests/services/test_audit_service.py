import uuid

import pytest
from sqlalchemy import select

from app.audit.context import ActorContext, AuditContext, RequestContext
from app.core.enums import (
    AuditActorType,
    AuditEventCategory,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
)
from app.core.exceptions import UnsafeAuditMetadataException
from app.models.audit_event import AuditEvent
from app.repositories.audit_repository import AuditRepository
from app.services.audit_service import AuditService


@pytest.fixture
def repository(db_session):
    return AuditRepository(db_session)


@pytest.fixture
def service(repository):
    return AuditService(repository)


def _anonymous_context(request_id="req-1", source_ip="203.0.113.7"):
    return AuditContext(
        actor=ActorContext.anonymous(),
        request=RequestContext(request_id=request_id, source_ip=source_ip),
    )


# --- Successful append ---


def test_append_event_persists_with_validated_actor_and_request_context(
    db_session, service
):
    context = _anonymous_context()
    event = service.append_event(
        event_type=AuditEventType.TARGET_CREATED,
        category=AuditEventCategory.TARGET,
        outcome=AuditOutcome.SUCCESS,
        context=context,
        resource_type=AuditResourceType.TARGET,
        resource_id=uuid.uuid4(),
        metadata={"target_type": "IPV4"},
    )
    db_session.commit()

    assert event.actor_type == AuditActorType.ANONYMOUS
    assert event.actor_id is None
    assert event.request_id == "req-1"
    assert event.source_ip == "203.0.113.7"
    assert event.occurred_at is not None


def test_append_event_uses_system_actor_context(db_session, service):
    event = service.append_event(
        event_type=AuditEventType.RISK_CALCULATION_COMPLETED,
        category=AuditEventCategory.RISK,
        outcome=AuditOutcome.SUCCESS,
        context=AuditContext.system(),
        resource_type=AuditResourceType.RISK_ASSESSMENT,
        resource_id=uuid.uuid4(),
    )
    db_session.commit()
    assert event.actor_type == AuditActorType.SYSTEM
    assert event.request_id is None


def test_append_event_defaults_metadata_to_empty_dict(db_session, service):
    event = service.append_event(
        event_type=AuditEventType.SCAN_CREATED,
        category=AuditEventCategory.SCAN,
        outcome=AuditOutcome.SUCCESS,
        context=AuditContext.system(),
        resource_type=AuditResourceType.SCAN,
        resource_id=uuid.uuid4(),
    )
    db_session.commit()
    assert event.event_metadata == {}


def test_occurred_at_is_server_generated_not_client_supplied(db_session, service):
    """append_event's signature has no occurred_at parameter at all — a
    caller cannot supply one even if it tried."""
    import inspect

    signature = inspect.signature(service.append_event)
    assert "occurred_at" not in signature.parameters


# --- Unsafe metadata rejected before persistence ---


def test_unsafe_metadata_rejected_and_never_persisted(db_session, service):
    with pytest.raises(UnsafeAuditMetadataException):
        service.append_event(
            event_type=AuditEventType.AI_RECOMMENDATION_GENERATED,
            category=AuditEventCategory.AI,
            outcome=AuditOutcome.SUCCESS,
            context=AuditContext.system(),
            resource_type=AuditResourceType.AI_RECOMMENDATION,
            resource_id=uuid.uuid4(),
            metadata={"api_key": "sk-should-not-be-here"},
        )
    assert db_session.query(AuditEvent).count() == 0


# --- record_failure_safely: never raises, best-effort durable ---


def test_record_failure_safely_persists_failure_event(db_session, service):
    service.record_failure_safely(
        session=db_session,
        event_type=AuditEventType.RISK_CALCULATION_FAILED,
        category=AuditEventCategory.RISK,
        context=AuditContext.system(),
        resource_type=AuditResourceType.SCAN,
        resource_id=uuid.uuid4(),
        metadata={"failure_category": "RuntimeError"},
    )
    events = (
        db_session.execute(
            select(AuditEvent).where(AuditEvent.outcome == AuditOutcome.FAILURE)
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].event_type == AuditEventType.RISK_CALCULATION_FAILED


def test_record_failure_safely_never_raises_on_unsafe_metadata(db_session, service):
    """Even if the metadata passed to a failure-recording call is unsafe,
    record_failure_safely must not raise — it logs and swallows, since
    raising here would replace the original business failure with an
    audit-subsystem error."""
    service.record_failure_safely(
        session=db_session,
        event_type=AuditEventType.REPORT_GENERATION_FAILED,
        category=AuditEventCategory.REPORT,
        context=AuditContext.system(),
        resource_type=AuditResourceType.SCAN,
        resource_id=uuid.uuid4(),
        metadata={"password": "leaked"},
    )
    # No exception raised, and no unsafe row was persisted either.
    assert db_session.query(AuditEvent).count() == 0


# --- Retrieval ---
