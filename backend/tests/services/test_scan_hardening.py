"""Batch 0 scan hardening: startup recovery (A1), honored scan profile (A2),
global concurrency cap (A4), and sanitized failure reasons."""

import uuid
from contextlib import contextmanager

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.enums import AuditEventType, ScanStatus, TargetType
from app.core.exceptions import TooManyRequestsException, ValidationException
from app.main import recover_interrupted_scans
from app.models.audit_event import AuditEvent
from app.models.scan_job import ScanJob
from app.models.target import Target
from app.repositories.audit_repository import AuditRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.scanners.interfaces import IScannerEngine
from app.schemas.scan import CreateScanRequest
from app.services.audit_service import AuditService
from app.services.scan_service import ScanService
from tests.auth_helpers import TEST_USER_ID


class _ExplodingScannerEngine(IScannerEngine):
    """Raises an unexpected error carrying internal detail."""

    def dispatch_scan(
        self, scan_id: uuid.UUID, target: str, scan_profile: str, scanner_type=None
    ):
        raise RuntimeError("driver failed at /srv/secret/path.conf")


def _build_service(db_session, scanner_engine=None) -> ScanService:
    return ScanService(
        ScanRepository(db_session),
        TargetRepository(db_session),
        AuditService(AuditRepository(db_session)),
        scanner_engine,
        session_factory=lambda: db_session,
        session_finalizer=lambda s: None,
    )


def _make_target(db_session, value: str) -> Target:
    return TargetRepository(db_session).create(
        Target(user_id=TEST_USER_ID, target=value, target_type=TargetType.IPV4)
    )


def _make_scan(db_session, target: Target, status: ScanStatus) -> ScanJob:
    return ScanRepository(db_session).create(
        ScanJob(
            user_id=TEST_USER_ID,
            target_id=target.id,
            scan_type="FULL",
            status=status,
        )
    )


def _audit_events(db_session, scan_id: uuid.UUID) -> list[AuditEvent]:
    stmt = select(AuditEvent).where(AuditEvent.scan_id == scan_id)
    return list(db_session.execute(stmt).scalars().all())


class TestRecoverInterruptedScans:
    def test_fails_pending_and_running_scans_with_audit_events(self, db_session):
        target = _make_target(db_session, "10.1.0.1")
        pending = _make_scan(db_session, target, ScanStatus.PENDING)
        running = _make_scan(db_session, target, ScanStatus.RUNNING)
        completed = _make_scan(db_session, target, ScanStatus.COMPLETED)

        recovered = _build_service(db_session).recover_interrupted_scans()

        assert recovered == 2
        for scan in (pending, running):
            db_session.refresh(scan)
            assert scan.status == ScanStatus.FAILED
            assert scan.completed_at is not None
            assert scan.failure_reason == "Scan aborted: backend server restarted."
            events = _audit_events(db_session, scan.id)
            assert [e.event_type for e in events] == [AuditEventType.SCAN_FAILED]
            assert events[0].event_metadata["failure_category"] == "ServerRestart"
        db_session.refresh(completed)
        assert completed.status == ScanStatus.COMPLETED

    def test_returns_zero_when_nothing_is_active(self, db_session):
        assert _build_service(db_session).recover_interrupted_scans() == 0

    def test_startup_hook_uses_the_given_session_scope(self, db_session):
        target = _make_target(db_session, "10.1.0.2")
        running = _make_scan(db_session, target, ScanStatus.RUNNING)

        @contextmanager
        def scope():
            yield db_session

        recover_interrupted_scans(scope)

        db_session.refresh(running)
        assert running.status == ScanStatus.FAILED

    def test_startup_hook_swallows_recovery_errors(self):
        @contextmanager
        def broken_scope():
            raise RuntimeError("database unreachable")
            yield  # pragma: no cover

        recover_interrupted_scans(broken_scope)


class TestScanProfileHandling:
    @pytest.mark.parametrize(
        ("requested", "stored"),
        [("full", "FULL"), ("discovery", "DISCOVERY"), ("Port_Scan", "PORT_SCAN")],
    )
    def test_profile_is_honored_and_stored_canonically(
        self, db_session, requested, stored
    ):
        target = _make_target(db_session, f"10.2.0.{len(requested)}")
        scan = _build_service(db_session).create_scan(
            TEST_USER_ID,
            CreateScanRequest(target_id=target.id, scan_profile=requested)
        )
        assert scan.scan_type == stored

    def test_unknown_profile_is_rejected_before_persisting(self, db_session):
        target = _make_target(db_session, "10.2.1.1")
        with pytest.raises(ValidationException):
            _build_service(db_session).create_scan(
                TEST_USER_ID,
                CreateScanRequest(target_id=target.id, scan_profile="ultra")
            )
        assert ScanRepository(db_session).count(TEST_USER_ID, target_id=target.id) == 0

    def test_unknown_profile_returns_422(self, client):
        target_id = client.post("/api/v1/targets", json={"target": "10.2.2.1"}).json()[
            "data"
        ]["id"]
        response = client.post(
            "/api/v1/scans", json={"target_id": target_id, "scan_profile": "ultra"}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


class TestConcurrencyCap:
    def test_rejects_new_scan_at_the_global_limit(self, db_session, monkeypatch):
        monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
        busy = _make_target(db_session, "10.3.0.1")
        _make_scan(db_session, busy, ScanStatus.RUNNING)
        idle = _make_target(db_session, "10.3.0.2")

        with pytest.raises(TooManyRequestsException):
            _build_service(db_session).create_scan(
                TEST_USER_ID,
                CreateScanRequest(target_id=idle.id)
            )

    def test_allows_scan_below_the_limit(self, db_session, monkeypatch):
        monkeypatch.setenv("MAX_CONCURRENT_SCANS", "2")
        busy = _make_target(db_session, "10.3.1.1")
        _make_scan(db_session, busy, ScanStatus.RUNNING)
        idle = _make_target(db_session, "10.3.1.2")

        scan = _build_service(db_session).create_scan(
            TEST_USER_ID,
            CreateScanRequest(target_id=idle.id)
        )
        assert scan.status == ScanStatus.PENDING

    def test_cap_returns_429(self, client, db_session, monkeypatch):
        monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
        # The client fixture's app startup already cached Settings.
        get_settings.cache_clear()
        busy = _make_target(db_session, "10.3.2.1")
        _make_scan(db_session, busy, ScanStatus.RUNNING)
        idle_id = client.post("/api/v1/targets", json={"target": "10.3.2.2"}).json()[
            "data"
        ]["id"]

        response = client.post("/api/v1/scans", json={"target_id": idle_id})

        assert response.status_code == 429
        assert response.json()["error"]["code"] == "TOO_MANY_REQUESTS"


def test_unexpected_error_does_not_leak_into_failure_reason(db_session):
    target = _make_target(db_session, "10.4.0.1")
    service = _build_service(db_session, _ExplodingScannerEngine())

    scan = service.create_scan(TEST_USER_ID, CreateScanRequest(target_id=target.id))
    assert service.last_scan_thread is not None
    service.last_scan_thread.join(timeout=5)
    db_session.refresh(scan)

    assert scan.status == ScanStatus.FAILED
    assert scan.failure_reason == "Scan failed due to an unexpected internal error."
    assert "/srv/secret" not in (scan.failure_reason or "")
