"""NSE-confirmed findings flow through parsing, inventory and risk scoring."""

import tempfile
import uuid
from pathlib import Path

from sqlalchemy import select

from app.core.enums import ExecutionStatus, RiskLevel, ScanStatus, TargetType
from app.models.target import Target
from app.models.vulnerability import Vulnerability
from app.repositories.audit_repository import AuditRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.scanners.interfaces import IScannerEngine
from app.scanners.scan_artifact import ScanArtifact
from app.schemas.scan import CreateScanRequest
from app.services.audit_service import AuditService
from app.services.scan_service import ScanService
from tests.auth_helpers import TEST_USER_ID
from tests.services.test_scan_output_and_hosts import _MemoryStorage

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX x.xml 10.0.0.7" version="7.94">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="OpenSSL" version="1.0.1f"/>
        <script id="ssl-heartbleed" output="VULNERABLE">
          <table key="CVE-2014-0160">
            <elem key="title">The Heartbleed Bug</elem>
            <elem key="state">VULNERABLE</elem>
            <table key="ids"><elem>CVE:CVE-2014-0160</elem></table>
            <table key="scores"><elem key="CVSSv2">7.5</elem></table>
          </table>
        </script>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="VULNERABLE">
        <table key="CVE-2017-0143">
          <elem key="title">Remote Code Execution vulnerability in SMBv1</elem>
          <elem key="state">VULNERABLE</elem>
          <table key="ids"><elem>CVE:CVE-2017-0143</elem></table>
          <elem key="risk_factor">HIGH</elem>
        </table>
      </script>
    </hostscript>
  </host>
</nmaprun>
"""


class _NseEngine(IScannerEngine):
    def dispatch_scan(
        self, scan_id: uuid.UUID, target: str, scan_profile: str, scanner_type=None
    ) -> ScanArtifact:
        with tempfile.NamedTemporaryFile(
            suffix=".xml", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(NMAP_XML)
        return ScanArtifact(
            scan_id=scan_id,
            execution_status=ExecutionStatus.SUCCESS,
            output_path=Path(tmp.name),
        )


def test_nse_findings_are_stored_as_scanner_evidence_and_score(db_session):
    target = TargetRepository(db_session).create(
        Target(user_id=TEST_USER_ID, target="10.0.0.7", target_type=TargetType.IPV4)
    )
    service = ScanService(
        ScanRepository(db_session),
        TargetRepository(db_session),
        AuditService(AuditRepository(db_session)),
        _NseEngine(),
        session_factory=lambda: db_session,
        session_finalizer=lambda s: None,
        ai_manager=None,
        object_storage=_MemoryStorage(),
    )
    scan = service.create_scan(TEST_USER_ID, CreateScanRequest(target_id=target.id))
    assert service.last_scan_thread is not None
    service.last_scan_thread.join(timeout=5)
    db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED

    vulns = db_session.execute(select(Vulnerability)).scalars().all()
    by_cve = {v.cve: v for v in vulns}
    assert set(by_cve) == {"CVE-2014-0160", "CVE-2017-0143"}
    assert {v.source for v in vulns} == {"NMAP_NSE"}
    assert by_cve["CVE-2017-0143"].severity_rating == "High"

    scan_risk = RiskRepository(db_session).get_by_scan(scan.id)
    assert scan_risk is not None
    assert scan_risk.risk_score > 0.0
    assert scan_risk.risk_level != RiskLevel.INFORMATIONAL
