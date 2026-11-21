import uuid

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.dependencies.audit import get_audit_context, get_audit_service
from app.api.dependencies.auth import get_current_user
from app.api.dependencies.database import get_db
from app.api.responses.api_response import SuccessResponse
from app.audit.context import AuditContext
from app.models.user import User
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.scanners.scanner_manager import ScannerManager
from app.schemas.scan import (
    AIAnalysisResponse,
    CreateScanRequest,
    ScanListResponse,
    ScanResponse,
    ScanStatusResponse,
)
from app.schemas.scan_host import (
    ScanHostDetails,
    ScanHostListResponse,
    ScanHostResponse,
)
from app.services.audit_service import AuditService
from app.services.scan_service import ScanService

router = APIRouter()


def get_scan_service(
    db: Session = Depends(get_db),
    audit_service: AuditService = Depends(get_audit_service),
) -> ScanService:
    scan_repo = ScanRepository(db)
    target_repo = TargetRepository(db)
    return ScanService(
        scan_repository=scan_repo,
        target_repository=target_repo,
        audit_service=audit_service,
        scanner_engine=ScannerManager(),
    )


@router.post(
    "",
    response_model=SuccessResponse[ScanResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan job",
)
def create_scan(
    request: CreateScanRequest,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    audit_context: AuditContext = Depends(get_audit_context),
) -> dict:
    """Create a new scan job for a validated target."""
    scan_job = service.create_scan(
        current_user.id, request, audit_context=audit_context
    )
    return {"data": ScanResponse.model_validate(scan_job)}


@router.get(
    "",
    response_model=SuccessResponse[ScanListResponse],
    summary="Get all scan jobs",
)
def list_scans(
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=200, description="Max records to return"),
    target_id: uuid.UUID | None = Query(
        None, description="Filter to scans of this target"
    ),
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Retrieve a paginated list of all scan jobs."""
    scans = service.get_all_scans(
        current_user.id, skip=skip, limit=limit, target_id=target_id
    )
    total = service.count_scans(current_user.id, target_id=target_id)
    scan_responses = [ScanResponse.model_validate(s) for s in scans]
    return {"data": ScanListResponse(scans=scan_responses, total=total)}


@router.get(
    "/{scan_id}",
    response_model=SuccessResponse[ScanResponse],
    summary="Get a single scan job",
)
def get_scan(
    scan_id: uuid.UUID,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Retrieve details of a specific scan job by its ID."""
    scan_job = service.get_scan(scan_id, current_user.id)
    return {"data": ScanResponse.model_validate(scan_job)}


@router.get(
    "/{scan_id}/status",
    response_model=SuccessResponse[ScanStatusResponse],
    summary="Get scan job status",
)
def get_scan_status(
    scan_id: uuid.UUID,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Retrieve the current execution status of a scan job."""
    scan_job = service.get_scan(scan_id, current_user.id)
    status_response = ScanStatusResponse(
        scan_id=scan_job.id,
        status=scan_job.status,
        updated_at=scan_job.updated_at,
    )
    return {"data": status_response}


@router.get(
    "/{scan_id}/hosts",
    response_model=SuccessResponse[ScanHostListResponse],
    summary="Per-host detail recorded by a scan",
)
def list_scan_hosts(
    scan_id: uuid.UUID,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
) -> dict:
    """OS matches, MAC/vendor, uptime, traceroute and per-port scripts for
    every host this scan saw."""
    records = service.list_hosts(current_user.id, scan_id)
    hosts = [
        ScanHostResponse(
            asset_id=record.asset_id,
            ipv4=record.asset.ipv4,
            hostname=record.asset.hostname,
            operating_system=record.asset.operating_system,
            details=ScanHostDetails.model_validate(record.details),
        )
        for record in records
    ]
    return {"data": ScanHostListResponse(hosts=hosts, total=len(hosts))}


@router.get(
    "/{scan_id}/raw",
    summary="Download the raw Nmap XML output",
    response_class=StreamingResponse,
)
def download_raw_output(
    scan_id: uuid.UUID,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Streamed through the API (never a public or pre-signed link), and
    served as an attachment so a browser never renders it."""
    stream = service.open_raw_output(current_user.id, scan_id)
    return StreamingResponse(
        stream,
        media_type="application/xml",
        headers={
            "Content-Disposition": f'attachment; filename="nmap-{scan_id}.xml"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post(
    "/{scan_id}/ai-analysis",
    response_model=SuccessResponse[AIAnalysisResponse],
    summary="Re-run AI vulnerability analysis with your own key",
)
def run_ai_analysis(
    scan_id: uuid.UUID,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    audit_context: AuditContext = Depends(get_audit_context),
) -> dict:
    """AI findings are advisory and excluded from the risk score by default.
    Returns 409 AI_KEY_REQUIRED when no OpenRouter key is saved."""
    created = service.run_ai_analysis(
        current_user.id, scan_id, audit_context=audit_context
    )
    return {"data": AIAnalysisResponse(findings_created=created)}


@router.post(
    "/{scan_id}/cancel",
    response_model=SuccessResponse[ScanResponse],
    summary="Cancel a running scan job",
)
def cancel_scan(
    scan_id: uuid.UUID,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    audit_context: AuditContext = Depends(get_audit_context),
) -> dict:
    """Request cancellation of a currently running scan job.

    The scan job transitions to CANCELLED asynchronously once the
    background execution thread notices the request; poll
    GET /scans/{scan_id}/status for the updated state.
    """
    scan_job = service.cancel_scan(
        current_user.id, scan_id, audit_context=audit_context
    )
    return {"data": ScanResponse.model_validate(scan_job)}


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan job",
)
def delete_scan(
    scan_id: uuid.UUID,
    service: ScanService = Depends(get_scan_service),
    current_user: User = Depends(get_current_user),
    audit_context: AuditContext = Depends(get_audit_context),
) -> None:
    """Delete a scan job."""
    service.delete_scan(current_user.id, scan_id, audit_context=audit_context)
