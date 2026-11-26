"""Report Data Builder: assembles the validated, provider-neutral ReportData
contract from already-persisted Module 05/06/07 data.

This module performs only read-only repository queries. It never renders
PDF content, never queries the database for rendering purposes after
returning, and never calls an AI provider. Its output is a fully
constructed, immutable `ReportData` — the only input the PDF renderer
receives.
"""

import uuid
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime

from app.core.constants import SOURCE_AI_INFERENCE
from app.core.enums import RiskLevel, RiskScope
from app.core.exceptions import InternalException
from app.models.asset import Asset
from app.models.risk_assessment import RiskAssessment
from app.models.scan_host import ScanHost
from app.models.scan_job import ScanJob
from app.repositories.ai_recommendation_repository import AIRecommendationRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.network_service_repository import NetworkServiceRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_host_repository import ScanHostRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.report import (
    AdvisoryFinding,
    AffectedService,
    AssetSummary,
    ExecutiveSummary,
    FindingDetail,
    HostReport,
    RemediationGuidance,
    ReportData,
    ReportMetadata,
    ReportServiceDetail,
    SeverityDistribution,
)
from app.schemas.scan_host import ScanHostDetails

# Bump whenever the substance of the report structure/sections changes.
REPORT_TEMPLATE_VERSION = "2.0.0"

MAX_DESCRIPTION_LENGTH = 3000
MAX_SCRIPT_OUTPUT_LENGTH = 1500
_MAX_SCRIPTS_PER_SERVICE = 10
_MAX_OS_MATCHES = 3
_TRUNCATION_MARKER = "... [truncated]"


def _bounded_text(value: str | None, max_length: int) -> str | None:
    """Explicitly (never silently) truncate free text for layout safety."""
    if value is None or len(value) <= max_length:
        return value
    return value[: max_length - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


def build_report_data(
    scan_job: ScanJob,
    scan_risk: RiskAssessment,
    generated_at: datetime,
    risk_repository: RiskRepository,
    asset_repository: AssetRepository,
    vulnerability_repository: VulnerabilityRepository,
    network_service_repository: NetworkServiceRepository,
    scan_finding_repository: ScanFindingRepository,
    ai_recommendation_repository: AIRecommendationRepository,
    scan_host_repository: ScanHostRepository | None = None,
) -> ReportData:
    """Assemble the complete, validated report data contract for one scan.

    A scan with no scored findings still gets a report: its hosts and
    services, plus any AI-inferred findings as a separate advisory list.
    """
    findings = scan_finding_repository.get_by_scan(scan_job.id)
    vulnerable_findings = [f for f in findings if f.vulnerability_id is not None]

    vulnerability_risks = risk_repository.get_by_scan_and_scope(
        scan_job.id, RiskScope.VULNERABILITY
    )
    risk_by_key: dict[tuple, RiskAssessment] = {
        (r.asset_id, r.vulnerability_id, r.service_id): r for r in vulnerability_risks
    }

    asset_risks = risk_repository.get_by_scan_and_scope(scan_job.id, RiskScope.ASSET)
    asset_risk_by_id = {r.asset_id: r for r in asset_risks}

    findings_detail: list[FindingDetail] = []
    severity_counts: dict[RiskLevel, int] = defaultdict(int)
    asset_cache: dict[uuid.UUID, Asset] = {}
    asset_vuln_counts: dict[uuid.UUID, int] = defaultdict(int)
    advisory_findings: list[AdvisoryFinding] = []

    for finding in vulnerable_findings:
        if finding.vulnerability_id is None:
            raise InternalException(
                "Vulnerable finding unexpectedly has no vulnerability_id."
            )
        vulnerability = vulnerability_repository.get_by_id(finding.vulnerability_id)
        if not vulnerability:
            continue

        asset = asset_cache.get(finding.asset_id)
        if asset is None:
            asset = asset_repository.get_by_id(finding.asset_id)
            if asset is None:
                continue
            asset_cache[finding.asset_id] = asset

        affected_service = _affected_service(
            finding.service_id, network_service_repository
        )
        key = (finding.asset_id, finding.vulnerability_id, finding.service_id)
        finding_risk = risk_by_key.get(key)
        if not finding_risk:
            # Unscored. AI-inferred findings are reported as advisory; any
            # other finding without a deterministic risk cannot be represented
            # (the Reporting Engine never calculates risk itself).
            if vulnerability.source == SOURCE_AI_INFERENCE:
                advisory_findings.append(
                    AdvisoryFinding(
                        vulnerability_name=vulnerability.name,
                        cve=vulnerability.cve,
                        severity_rating=vulnerability.severity_rating,
                        description=_bounded_text(
                            vulnerability.description, MAX_DESCRIPTION_LENGTH
                        ),
                        asset_ipv4=asset.ipv4,
                        affected_service=affected_service,
                    )
                )
            continue

        asset_vuln_counts[asset.id] += 1
        severity_counts[finding_risk.risk_level] += 1

        remediation = None
        recommendation = ai_recommendation_repository.get_by_risk_assessment(
            finding_risk.id
        )
        # Mirrors Module 07's own freshness contract exactly: a recommendation
        # is current only if generated at or after its risk assessment's last
        # calculation. Never regenerated here — the Reporting Engine never
        # calls the AI provider.
        if recommendation and recommendation.generated_at >= finding_risk.calculated_at:
            remediation = RemediationGuidance(
                summary=recommendation.summary,
                explanation=recommendation.explanation,
                remediation_steps=recommendation.remediation_steps,
                validation_steps=recommendation.validation_steps,
                cautions=recommendation.cautions,
                provider=recommendation.provider,
                model=recommendation.model,
                generated_at=recommendation.generated_at,
            )

        findings_detail.append(
            FindingDetail(
                vulnerability_id=vulnerability.id,
                vulnerability_name=vulnerability.name,
                cve=vulnerability.cve,
                description=_bounded_text(
                    vulnerability.description, MAX_DESCRIPTION_LENGTH
                ),
                severity_rating=vulnerability.severity_rating,
                severity_score=vulnerability.severity_score,
                risk_score=finding_risk.risk_score,
                risk_level=finding_risk.risk_level,
                asset_ipv4=asset.ipv4,
                asset_hostname=asset.hostname,
                affected_service=affected_service,
                remediation=remediation,
            )
        )

    # Deterministic ordering: identical persisted state must always produce
    # an identical report, regardless of the underlying query's row order.
    findings_detail.sort(
        key=lambda f: (f.asset_ipv4, f.vulnerability_name, f.cve or "")
    )

    assets_summary = [
        AssetSummary(
            asset_id=asset.id,
            ipv4=asset.ipv4,
            hostname=asset.hostname,
            operating_system=asset.operating_system,
            risk_score=(
                asset_risk_by_id[asset.id].risk_score
                if asset.id in asset_risk_by_id
                else 0.0
            ),
            risk_level=(
                asset_risk_by_id[asset.id].risk_level
                if asset.id in asset_risk_by_id
                else RiskLevel.INFORMATIONAL
            ),
            vulnerability_count=asset_vuln_counts[asset.id],
        )
        for asset in asset_cache.values()
    ]
    assets_summary.sort(key=lambda a: a.ipv4)

    severity_distribution = SeverityDistribution(
        critical=severity_counts.get(RiskLevel.CRITICAL, 0),
        high=severity_counts.get(RiskLevel.HIGH, 0),
        medium=severity_counts.get(RiskLevel.MEDIUM, 0),
        low=severity_counts.get(RiskLevel.LOW, 0),
        informational=severity_counts.get(RiskLevel.INFORMATIONAL, 0),
    )

    executive_summary = ExecutiveSummary(
        overall_risk_score=scan_risk.risk_score,
        overall_risk_level=scan_risk.risk_level,
        total_assets=len(asset_cache),
        total_vulnerabilities=len(findings_detail),
        severity_distribution=severity_distribution,
    )

    target = scan_job.target
    metadata = ReportMetadata(
        scan_id=scan_job.id,
        target=target.target,
        target_type=target.target_type,
        scan_status=scan_job.status,
        scan_started_at=scan_job.started_at,
        scan_completed_at=scan_job.completed_at,
        generated_at=generated_at,
        report_template_version=REPORT_TEMPLATE_VERSION,
        risk_calculation_version=scan_risk.calculation_version,
        scan_profile=scan_job.scan_type,
    )
    advisory_findings.sort(key=lambda f: (f.asset_ipv4, f.vulnerability_name))
    hosts = (
        _host_reports(scan_host_repository.list_for_scan(scan_job.id))
        if scan_host_repository is not None
        else []
    )

    return ReportData(
        metadata=metadata,
        executive_summary=executive_summary,
        assets=assets_summary,
        findings=findings_detail,
        hosts=hosts,
        advisory_findings=advisory_findings,
    )


def _affected_service(
    service_id: uuid.UUID | None,
    network_service_repository: NetworkServiceRepository,
) -> AffectedService | None:
    if not service_id:
        return None
    service = network_service_repository.get_by_id(service_id)
    if not service:
        return None
    return AffectedService(
        port=service.port,
        protocol=service.protocol,
        service_name=service.service_name,
        product=service.product,
        version=service.version,
    )


def _host_reports(records: Sequence[ScanHost]) -> list[HostReport]:
    """Convert stored per-scan host snapshots into report sections."""
    reports = [_host_report(record) for record in records]
    reports.sort(key=lambda host: host.ipv4)
    return reports


def _host_report(record: ScanHost) -> HostReport:
    details = ScanHostDetails.model_validate(record.details)
    return HostReport(
        ipv4=record.asset.ipv4,
        hostname=record.asset.hostname,
        operating_system=record.asset.operating_system,
        os_matches=[
            _os_match_label(match.name, match.accuracy)
            for match in details.os_matches[:_MAX_OS_MATCHES]
        ],
        mac_address=details.mac_address,
        mac_vendor=details.mac_vendor,
        uptime_seconds=details.uptime_seconds,
        network_distance=details.network_distance,
        traceroute=[
            f"{hop.ttl}: {hop.ipaddr or 'no reply'}" for hop in details.traceroute
        ],
        closed_port_count=details.closed_port_count,
        filtered_port_count=details.filtered_port_count,
        services=[
            ReportServiceDetail(
                port=svc.port,
                protocol=svc.protocol,
                state=svc.state,
                service_name=svc.service_name[:50],
                product=(svc.product or "")[:100] or None,
                version=(svc.version or "")[:50] or None,
                scripts=_bounded_scripts(svc.scripts),
            )
            for svc in details.services
        ],
    )


def _os_match_label(name: str, accuracy: int | None) -> str:
    return f"{name} ({accuracy}%)" if accuracy is not None else name


def _bounded_scripts(scripts: dict[str, str]) -> dict[str, str]:
    """At most a few scripts per port, each explicitly truncated."""
    selected = list(scripts.items())[:_MAX_SCRIPTS_PER_SERVICE]
    return {
        name: _bounded_text(output, MAX_SCRIPT_OUTPUT_LENGTH) or ""
        for name, output in selected
    }
