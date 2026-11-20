"""Raw output storage and per-host snapshots through the scan pipeline."""

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.core.enums import ScanStatus, TargetType
from app.core.exceptions import NotFoundException
from app.models.target import Target
from app.repositories.audit_repository import AuditRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.schemas.scan import CreateScanRequest
from app.services.audit_service import AuditService
from app.services.scan_service import ScanService
from app.storage.base import ObjectStorage, StorageError
from app.storage.factory import build_object_storage
from tests.auth_helpers import OTHER_USER_ID, TEST_USER_ID
from tests.services.test_scan_service import MockScannerEngine, _NoOpAIManager


class _MemoryStorage(ObjectStorage):
    def __init__(self, fail: bool = False):
        self.objects: dict[str, bytes] = {}
        self.deleted: list[str] = []
        self.fail = fail

    def put_file(self, key: str, path: Path, content_type: str) -> None:
        if self.fail:
            raise StorageError("S3 upload failed: AccessDenied")
        self.objects[key] = path.read_bytes()

    def open_stream(self, key: str) -> Iterator[bytes]:
        if key not in self.objects:
            raise StorageError("Object not found.")
        return iter([self.objects[key]])

    def delete(self, key: str) -> None:
        self.deleted.append(key)
        self.objects.pop(key, None)


def _service(db_session, storage: ObjectStorage) -> ScanService:
    return ScanService(
        ScanRepository(db_session),
        TargetRepository(db_session),
        AuditService(AuditRepository(db_session)),
        MockScannerEngine(),
        session_factory=lambda: db_session,
        session_finalizer=lambda s: None,
        ai_manager=_NoOpAIManager(),
        object_storage=storage,
    )


def _run_scan(db_session, storage: ObjectStorage, ip: str = "10.0.0.1"):
    target = TargetRepository(db_session).create(
        Target(user_id=TEST_USER_ID, target=ip, target_type=TargetType.IPV4)
    )
    service = _service(db_session, storage)
    scan = service.create_scan(TEST_USER_ID, CreateScanRequest(target_id=target.id))
    assert service.last_scan_thread is not None
    service.last_scan_thread.join(timeout=5)
    db_session.refresh(scan)
    return service, scan


def test_completed_scan_uploads_output_and_removes_local_file(db_session):
    storage = _MemoryStorage()
    _, scan = _run_scan(db_session, storage)

    assert scan.status == ScanStatus.COMPLETED
    expected_key = f"scans/{TEST_USER_ID}/{scan.id}/nmap.xml"
    assert scan.output_object_key == expected_key
    assert scan.output_file_path is None
    assert b"<nmaprun" in storage.objects[expected_key]


def test_storage_failure_keeps_local_file_and_still_completes(db_session):
    _, scan = _run_scan(db_session, _MemoryStorage(fail=True))

    assert scan.status == ScanStatus.COMPLETED
    assert scan.output_object_key is None
    assert scan.output_file_path is not None
    assert Path(scan.output_file_path).is_file()
    Path(scan.output_file_path).unlink()


def test_host_snapshot_is_recorded_per_scan(db_session):
    service, scan = _run_scan(db_session, _MemoryStorage())

    hosts = service.list_hosts(TEST_USER_ID, scan.id)
    assert len(hosts) == 1
    details = hosts[0].details
    assert hosts[0].asset.ipv4 == "10.0.0.1"
    assert details["services"][0]["port"] == 80
    assert details["services"][0]["product"] == "Apache httpd"
    assert details["services"][0]["version"] == "2.4.41"


def test_raw_output_is_owner_only(db_session):
    storage = _MemoryStorage()
    service, scan = _run_scan(db_session, storage)

    assert b"<nmaprun" in b"".join(service.open_raw_output(TEST_USER_ID, scan.id))
    with pytest.raises(NotFoundException):
        service.open_raw_output(OTHER_USER_ID, scan.id)
    with pytest.raises(NotFoundException):
        service.list_hosts(OTHER_USER_ID, scan.id)


def test_missing_raw_output_is_404(db_session):
    storage = _MemoryStorage()
    service, scan = _run_scan(db_session, storage)
    storage.objects.clear()
    with pytest.raises(NotFoundException):
        service.open_raw_output(TEST_USER_ID, scan.id)


def test_deleting_a_scan_deletes_its_stored_output(db_session):
    storage = _MemoryStorage()
    service, scan = _run_scan(db_session, storage)
    key = scan.output_object_key

    service.delete_scan(TEST_USER_ID, scan.id)

    assert storage.deleted == [key]


def test_hosts_and_raw_endpoints(client, db_session):
    storage = build_object_storage(get_settings())
    _, scan = _run_scan(db_session, storage, ip="10.0.0.9")

    hosts = client.get(f"/api/v1/scans/{scan.id}/hosts")
    assert hosts.status_code == 200
    host = hosts.json()["data"]["hosts"][0]
    # The mock scanner output always reports host 10.0.0.1.
    assert host["ipv4"] == "10.0.0.1"
    assert host["details"]["services"][0]["service_name"] == "http"

    raw = client.get(f"/api/v1/scans/{scan.id}/raw")
    assert raw.status_code == 200
    assert raw.headers["content-type"].startswith("application/xml")
    assert raw.headers["content-disposition"].startswith("attachment")
    assert raw.headers["x-content-type-options"] == "nosniff"
    assert b"<nmaprun" in raw.content

    assert client.get(f"/api/v1/scans/{uuid.uuid4()}/raw").status_code == 404
