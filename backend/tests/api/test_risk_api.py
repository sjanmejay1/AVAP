import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.enums import ScanStatus, TargetType
from app.models.asset import Asset
from app.models.scan_finding import ScanFinding
from app.models.scan_job import ScanJob
from app.models.service import NetworkService
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from tests.auth_helpers import TEST_USER_ID


@pytest.fixture
def scan_with_finding(db_session):
    target = Target(
        user_id=TEST_USER_ID,
        target="10.20.30.1",
        target_type=TargetType.IPV4,
    )
    db_session.add(target)
    db_session.flush()

    scan_job = ScanJob(
        user_id=TEST_USER_ID,
        target_id=target.id, status=ScanStatus.COMPLETED, scan_type="full"
    )
    db_session.add(scan_job)
    db_session.flush()

    asset = Asset(user_id=TEST_USER_ID, ipv4="10.20.30.1")
    db_session.add(asset)
    db_session.flush()

    service = NetworkService(
        asset_id=asset.id, port=443, protocol="tcp", service_name="https"
    )
    db_session.add(service)
    db_session.flush()

    vulnerability = Vulnerability(
        name="API Test Vuln", severity_score=7.2, severity_rating="High"
    )
    db_session.add(vulnerability)
    db_session.flush()

    finding = ScanFinding(
        scan_id=scan_job.id,
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        service_id=service.id,
    )
    db_session.add(finding)
    db_session.flush()

    return {"scan_job": scan_job, "asset": asset}


# --- Empty database ---


def test_list_risk_assessments_for_unknown_scan_returns_404(client: TestClient):
    response = client.get(f"/api/v1/risk?scan_id={uuid.uuid4()}")
    assert response.status_code == 404


def test_list_risk_assessments_requires_scan_id(client: TestClient):
    response = client.get("/api/v1/risk")
    assert response.status_code == 422


def test_calculate_risk_for_missing_scan_returns_404(client: TestClient):
    response = client.post(f"/api/v1/risk/scans/{uuid.uuid4()}/calculate")
    assert response.status_code == 404


def test_calculate_risk_for_scan(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    response = client.post(f"/api/v1/risk/scans/{scan_id}/calculate")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["scope"] == "SCAN"
    assert data["risk_score"] == 7.2
    assert data["risk_level"] == "HIGH"
    assert data["calculation_version"]


def test_calculate_risk_is_callable_repeatedly(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    first = client.post(f"/api/v1/risk/scans/{scan_id}/calculate").json()["data"]
    second = client.post(f"/api/v1/risk/scans/{scan_id}/calculate").json()["data"]
    assert first["id"] == second["id"]
    assert first["risk_score"] == second["risk_score"]


# --- Scan risk retrieval ---


def test_get_risk_by_scan_not_calculated_yet(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    response = client.get(f"/api/v1/risk/scans/{scan_id}")
    assert response.status_code == 404


def test_get_risk_by_scan_missing_scan(client: TestClient):
    response = client.get(f"/api/v1/risk/scans/{uuid.uuid4()}")
    assert response.status_code == 404


def test_get_risk_by_scan_after_calculation(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    client.post(f"/api/v1/risk/scans/{scan_id}/calculate")

    response = client.get(f"/api/v1/risk/scans/{scan_id}")
    assert response.status_code == 200
    assert response.json()["data"]["risk_score"] == 7.2


def test_get_risk_by_scan_invalid_uuid(client: TestClient):
    response = client.get("/api/v1/risk/scans/not-a-uuid")
    assert response.status_code == 422


# --- Asset risk retrieval ---


def test_get_risk_by_asset_missing_asset(client: TestClient):
    response = client.get(f"/api/v1/risk/assets/{uuid.uuid4()}")
    assert response.status_code == 404


def test_get_risk_by_asset_after_calculation(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    asset_id = scan_with_finding["asset"].id
    client.post(f"/api/v1/risk/scans/{scan_id}/calculate")

    response = client.get(f"/api/v1/risk/assets/{asset_id}")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["total"] == 1
    assert data["risk_assessments"][0]["risk_score"] == 7.2


# --- List with pagination and filters ---


def test_list_risk_assessments_after_calculation(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    client.post(f"/api/v1/risk/scans/{scan_id}/calculate")

    response = client.get(f"/api/v1/risk?scan_id={scan_id}")
    assert response.status_code == 200
    data = response.json()["data"]
    # VULNERABILITY + ASSET + SCAN + ASSESSMENT = 4 rows for one finding.
    # VULNERABILITY + ASSET + SCAN; the global ASSESSMENT row has no scan.
    assert data["total"] == 3


def test_list_risk_assessments_scope_filter(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    client.post(f"/api/v1/risk/scans/{scan_id}/calculate")

    response = client.get(f"/api/v1/risk?scan_id={scan_id}&scope=SCAN")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["total"] == 1
    assert data["risk_assessments"][0]["scope"] == "SCAN"


def test_list_risk_assessments_pagination(client: TestClient, scan_with_finding):
    scan_id = scan_with_finding["scan_job"].id
    client.post(f"/api/v1/risk/scans/{scan_id}/calculate")

    response = client.get(f"/api/v1/risk?scan_id={scan_id}&skip=0&limit=1")
    assert response.status_code == 200
    data = response.json()["data"]
    assert len(data["risk_assessments"]) == 1
    # VULNERABILITY + ASSET + SCAN; the global ASSESSMENT row has no scan.
    assert data["total"] == 3


# --- Summary ---
