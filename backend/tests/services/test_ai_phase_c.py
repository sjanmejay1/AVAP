"""Phase C/D: per-user Hugging Face key, advisory AI findings excluded from
risk, prompt data minimization, AI re-run, key test, and reports that work
without scored findings."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.ai.manager import AIManager
from app.ai.provider import AIProviderResponse
from app.core.config import Settings
from app.core.enums import AIKeyProvider, RiskLevel, ScanStatus, TargetType
from app.core.exceptions import AIKeyRequiredException, ConflictException
from app.models.scan_job import ScanJob
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.reporting.pdf import render_pdf
from app.repositories.ai_recommendation_repository import AIRecommendationRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.audit_repository import AuditRepository
from app.repositories.network_service_repository import NetworkServiceRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.scan import CreateScanRequest
from app.services.audit_service import AuditService
from app.services.report_service import ReportService
from app.services.scan_service import ScanService
from tests.auth_helpers import TEST_USER_ID
from tests.services.test_scan_output_and_hosts import _MemoryStorage
from tests.services.test_scan_service import MockScannerEngine

AI_FINDING = {
    "findings": [
        {
            "host": "host-1",
            "port": 80,
            "protocol": "tcp",
            "name": "Outdated Apache httpd",
            "cve": "CVE-2021-41773",
            "severity_rating": "High",
            "severity_score": 7.5,
            "description": "Apache 2.4.41 has known path traversal issues.",
        }
    ]
}


class _RecordingAIManager(AIManager):
    """Returns one canned finding and records every prompt it was sent."""

    def __init__(self) -> None:
        super().__init__(settings=Settings(_env_file=None), api_key="hf_fake")
        self.prompts: list = []

    def generate(self, prompt):
        self.prompts.append(prompt)
        return AIProviderResponse(
            content=json.dumps(AI_FINDING), provider="huggingface", model="m"
        )


def _scan_service(db_session, ai_manager=None, storage=None) -> ScanService:
    return ScanService(
        ScanRepository(db_session),
        TargetRepository(db_session),
        AuditService(AuditRepository(db_session)),
        MockScannerEngine(),
        session_factory=lambda: db_session,
        session_finalizer=lambda s: None,
        ai_manager=ai_manager,
        object_storage=storage or _MemoryStorage(),
    )


def _completed_scan(db_session, service: ScanService) -> ScanJob:
    target = TargetRepository(db_session).create(
        Target(user_id=TEST_USER_ID, target="10.0.0.1", target_type=TargetType.IPV4)
    )
    scan = service.create_scan(TEST_USER_ID, CreateScanRequest(target_id=target.id))
    assert service.last_scan_thread is not None
    service.last_scan_thread.join(timeout=5)
    db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    return scan


def _ai_vulnerabilities(db_session) -> list[Vulnerability]:
    stmt = select(Vulnerability).where(Vulnerability.source == "AI_INFERENCE")
    return list(db_session.execute(stmt).scalars().all())


class TestAdvisoryAI:
    def test_ai_findings_are_stored_but_do_not_score(self, db_session):
        manager = _RecordingAIManager()
        scan = _completed_scan(db_session, _scan_service(db_session, manager))

        assert [v.cve for v in _ai_vulnerabilities(db_session)] == ["CVE-2021-41773"]
        scan_risk = RiskRepository(db_session).get_by_scan(scan.id)
        assert scan_risk is not None
        assert scan_risk.risk_score == 0.0
        assert scan_risk.risk_level == RiskLevel.INFORMATIONAL

    def test_owner_can_opt_ai_findings_into_risk(self, db_session, monkeypatch):
        monkeypatch.setenv("AI_FINDINGS_IN_RISK", "true")
        scan = _completed_scan(
            db_session, _scan_service(db_session, _RecordingAIManager())
        )
        scan_risk = RiskRepository(db_session).get_by_scan(scan.id)
        assert scan_risk is not None
        assert scan_risk.risk_score > 0.0

    def test_prompt_contains_no_addresses_or_hostnames(self, db_session):
        manager = _RecordingAIManager()
        _completed_scan(db_session, _scan_service(db_session, manager))

        prompt = manager.prompts[0]
        assert "10.0.0.1" not in prompt.user
        assert "host-1" in prompt.user
        assert "Apache httpd" in prompt.user


class TestPerUserKey:
    def test_scan_without_a_saved_key_skips_ai_and_completes(self, db_session):
        with patch("app.ai.providers.huggingface.httpx.post") as post:
            _completed_scan(db_session, _scan_service(db_session, ai_manager=None))
        post.assert_not_called()
        assert _ai_vulnerabilities(db_session) == []

    def test_scan_uses_the_owners_saved_key(self, db_session, client):
        client.put(
            "/api/v1/users/me/api-keys/huggingface", json={"api_key": "hf_owner_key1"}
        )
        reply = MagicMock(status_code=200)
        reply.json.return_value = {
            "choices": [{"message": {"content": json.dumps(AI_FINDING)}}]
        }
        with patch(
            "app.ai.providers.huggingface.httpx.post", return_value=reply
        ) as post:
            _completed_scan(db_session, _scan_service(db_session, ai_manager=None))

        assert post.call_args.kwargs["headers"]["Authorization"] == (
            "Bearer hf_owner_key1"
        )
        assert len(_ai_vulnerabilities(db_session)) == 1


class TestAIRerun:
    def test_rerun_requires_a_key(self, db_session):
        service = _scan_service(db_session, ai_manager=None)
        scan = _completed_scan(db_session, service)
        with pytest.raises(AIKeyRequiredException):
            service.run_ai_analysis(TEST_USER_ID, scan.id)

    def test_rerun_requires_a_completed_scan(self, db_session):
        service = _scan_service(db_session, _RecordingAIManager())
        target = TargetRepository(db_session).create(
            Target(user_id=TEST_USER_ID, target="10.0.0.2", target_type=TargetType.IPV4)
        )
        pending = ScanRepository(db_session).create(
            ScanJob(
                user_id=TEST_USER_ID, target_id=target.id, status=ScanStatus.PENDING
            )
        )
        with pytest.raises(ConflictException):
            service.run_ai_analysis(TEST_USER_ID, pending.id)

    def test_rerun_reparses_stored_output_and_creates_findings(self, db_session):
        storage = _MemoryStorage()
        first = _scan_service(db_session, ai_manager=None, storage=storage)
        scan = _completed_scan(db_session, first)
        assert _ai_vulnerabilities(db_session) == []

        rerun = _scan_service(db_session, _RecordingAIManager(), storage=storage)
        assert rerun.run_ai_analysis(TEST_USER_ID, scan.id) == 1
        assert len(_ai_vulnerabilities(db_session)) == 1

    def test_rerun_endpoint_without_key_is_409(self, client, db_session):
        scan = _completed_scan(db_session, _scan_service(db_session))
        response = client.post(f"/api/v1/scans/{scan.id}/ai-analysis")
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "AI_KEY_REQUIRED"


class TestKeyCheck:
    def test_key_test_without_a_key_is_409(self, client):
        response = client.post("/api/v1/users/me/api-keys/huggingface/test")
        assert response.status_code == 409

    @pytest.mark.parametrize(
        ("status", "valid"), [(200, True), (401, False), (402, False)]
    )
    def test_key_test_reports_validity(self, client, status, valid):
        client.put(
            "/api/v1/users/me/api-keys/huggingface", json={"api_key": "hf_check_key1"}
        )
        reply = MagicMock(status_code=status)
        reply.json.return_value = {"choices": [{"message": {"content": "x"}}]}
        with patch("app.ai.providers.huggingface.httpx.post", return_value=reply):
            response = client.post("/api/v1/users/me/api-keys/huggingface/test")
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["valid"] is valid
        assert "hf_check_key1" not in response.text


def test_stale_ai_provider_fails_at_startup():
    with pytest.raises(ValueError, match="AI_PROVIDER"):
        Settings(_env_file=None, ai_provider="openrouter").validate_ai_settings()
    Settings(_env_file=None).validate_ai_settings()


def test_find_decrypted_key_returns_none_without_a_key(db_session):
    from app.api.dependencies.auth import get_api_key_service

    service = get_api_key_service(db_session)
    assert service.find_decrypted_key(TEST_USER_ID, AIKeyProvider.HUGGINGFACE) is None


class TestReportWithoutScoredFindings:
    def _report_service(self, db_session, tmp_path: Path) -> ReportService:
        return ReportService(
            session=db_session,
            report_repository=ReportRepository(db_session),
            scan_repository=ScanRepository(db_session),
            risk_repository=RiskRepository(db_session),
            asset_repository=AssetRepository(db_session),
            vulnerability_repository=VulnerabilityRepository(db_session),
            network_service_repository=NetworkServiceRepository(db_session),
            scan_finding_repository=ScanFindingRepository(db_session),
            ai_recommendation_repository=AIRecommendationRepository(db_session),
            audit_service=AuditService(AuditRepository(db_session)),
            settings=Settings(_env_file=None, report_output_directory=str(tmp_path)),
        )

    def test_report_has_hosts_and_advisory_section(self, db_session, tmp_path):
        scan = _completed_scan(
            db_session, _scan_service(db_session, _RecordingAIManager())
        )
        report = self._report_service(db_session, tmp_path).generate_report(
            TEST_USER_ID, scan.id
        )
        assert report.vulnerability_count == 0
        assert report.file_size_bytes > 0

    def test_report_data_and_pdf_include_hosts_and_advisory(self, db_session, tmp_path):
        from app.reporting.generator import build_report_data
        from app.repositories.scan_host_repository import ScanHostRepository

        scan = _completed_scan(
            db_session, _scan_service(db_session, _RecordingAIManager())
        )
        scan_risk = RiskRepository(db_session).get_by_scan(scan.id)
        assert scan_risk is not None
        data = build_report_data(
            scan_job=scan,
            scan_risk=scan_risk,
            generated_at=scan_risk.calculated_at,
            risk_repository=RiskRepository(db_session),
            asset_repository=AssetRepository(db_session),
            vulnerability_repository=VulnerabilityRepository(db_session),
            network_service_repository=NetworkServiceRepository(db_session),
            scan_finding_repository=ScanFindingRepository(db_session),
            ai_recommendation_repository=AIRecommendationRepository(db_session),
            scan_host_repository=ScanHostRepository(db_session),
        )

        assert data.findings == []
        assert [f.cve for f in data.advisory_findings] == ["CVE-2021-41773"]
        assert data.hosts[0].ipv4 == "10.0.0.1"
        assert data.hosts[0].services[0].product == "Apache httpd"

        hostile = (
            data.hosts[0]
            .services[0]
            .model_copy(
                update={"scripts": {"http-title": "<b>&nbsp;\x00</b> \"x\" 'y'"}}
            )
        )
        data.hosts[0].services[0] = hostile
        output = tmp_path / "report.pdf"
        render_pdf(data, output)
        assert output.read_bytes().startswith(b"%PDF")
