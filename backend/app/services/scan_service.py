import logging
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.ai.manager import AIManager
from app.audit.context import AuditContext
from app.auth.key_cipher import KeyCipher
from app.core.config import get_settings
from app.core.enums import (
    AIKeyProvider,
    AuditEventCategory,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    ExecutionStatus,
    ScannerType,
    ScanStatus,
)
from app.core.exceptions import (
    AIKeyRequiredException,
    ConflictException,
    InternalException,
    NotFoundException,
    ParserException,
    ScannerCancelledException,
    ScannerExecutionException,
    ScannerTimeoutException,
    TooManyRequestsException,
)
from app.database.session import SessionLocal
from app.models.scan_host import ScanHost
from app.models.scan_job import ScanJob
from app.parsers.models import AssessmentPackage
from app.parsers.parser_manager import ParserManager
from app.repositories.asset_repository import AssetRepository
from app.repositories.audit_repository import AuditRepository
from app.repositories.network_service_repository import NetworkServiceRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_host_repository import ScanHostRepository
from app.repositories.scan_repository import ScanRepository
from app.repositories.target_repository import TargetRepository
from app.repositories.user_api_key_repository import UserApiKeyRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.scanners.interfaces import IScannerEngine
from app.scanners.scan_artifact import ScanArtifact
from app.scanners.scan_runtime import ScanRuntimeRegistry
from app.scanners.scanner_manager import resolve_scan_profile
from app.schemas.scan import CreateScanRequest
from app.services.ai_vulnerability_discovery_service import (
    AIVulnerabilityDiscoveryService,
)
from app.services.api_key_service import ApiKeyService
from app.services.audit_service import AuditService
from app.services.inventory_service import InventoryService
from app.services.risk_service import RiskService
from app.storage.base import ObjectStorage, StorageError, raw_output_key
from app.storage.factory import build_object_storage
from app.storage.local import LocalObjectStorage

logger = logging.getLogger(__name__)

_SERVER_RESTART_FAILURE_REASON = "Scan aborted: backend server restarted."
_UNEXPECTED_FAILURE_REASON = "Scan failed due to an unexpected internal error."
_PARSE_FAILURE_REASON = "Scan output could not be parsed."
_RAW_OUTPUT_CONTENT_TYPE = "application/xml"


class ScanService:
    """Service layer for Scan Management business logic."""

    def __init__(
        self,
        scan_repository: ScanRepository,
        target_repository: TargetRepository,
        audit_service: AuditService,
        scanner_engine: IScannerEngine | None = None,
        session_factory: Callable[[], Session] | None = None,
        session_finalizer: Callable[[Session], None] | None = None,
        ai_manager: AIManager | None = None,
        object_storage: ObjectStorage | None = None,
    ):
        self.scan_repository = scan_repository
        self.target_repository = target_repository
        self.scanner_engine = scanner_engine
        self.audit_service = audit_service
        self.settings = get_settings()
        # Passed through to AIVulnerabilityDiscoveryService for the post-scan
        # discovery step. None means "let it construct its own default
        # AIManager()" (the real provider) — tests inject a fake here so the
        # suite never makes a real network call to an AI provider.
        self.ai_manager = ai_manager
        # Where raw scanner output is kept once a scan ends (S3 or a local
        # directory, per STORAGE_BACKEND).
        self.object_storage = object_storage or build_object_storage(self.settings)
        # Opens the background execution thread's own DB session — the
        # request-scoped session passed above is closed by the time that
        # thread runs. Defaults to the real session factory; tests override
        # this to reuse their transactional test session instead.
        self.session_factory: Callable[[], Session] = session_factory or SessionLocal
        # Closes the background session once the scan finishes. Tests that
        # inject their own shared transactional session override this to a
        # no-op — closing it there would tear down the session the test
        # itself still needs afterward.
        self.session_finalizer: Callable[[Session], None] = session_finalizer or (
            lambda s: s.close()
        )
        # Exposes the most recently spawned background scan thread so tests
        # can deterministically wait for it (`.join()`) instead of racing
        # it. Not read by any production code path.
        self.last_scan_thread: threading.Thread | None = None

    def _commit_with_audit(
        self,
        event_type: AuditEventType,
        resource_id: uuid.UUID,
        context: AuditContext,
        metadata: dict | None = None,
    ) -> None:
        """Append a SCAN-category audit event in the same transaction as the
        already-flushed scan mutation, then commit both atomically.

        Shared transaction (preferred pattern, see backend.md → "Audit
        event transaction pattern"): if the audit insert or its metadata
        validation fails, this raises before commit and the entire
        mutation (repository flush included) rolls back rather than being
        reported as successful.
        """
        try:
            self.audit_service.append_event(
                event_type=event_type,
                category=AuditEventCategory.SCAN,
                outcome=AuditOutcome.SUCCESS,
                context=context,
                resource_type=AuditResourceType.SCAN,
                resource_id=resource_id,
                scan_id=resource_id,
                metadata=metadata,
            )
            self.scan_repository.session.commit()
        except Exception:
            self.scan_repository.session.rollback()
            logger.error(
                "Scan mutation failed to commit; transaction rolled back.",
                extra={"event_type": event_type.value, "resource_id": str(resource_id)},
                exc_info=True,
            )
            raise

    def create_scan(
        self,
        user_id: uuid.UUID,
        request: CreateScanRequest,
        audit_context: AuditContext | None = None,
    ) -> ScanJob:
        """Create a new scan job and dispatch it to the scanner engine in
        the background.

        The HTTP request returns as soon as the job is persisted (status
        PENDING) — the actual scanner subprocess runs on a background
        thread with its own database session, since a scan can take
        minutes and must not block the request/response cycle. Callers
        should poll GET /scans/{id}/status (or /scans/{id}) for progress.
        """

        # Verify target exists
        target = self.target_repository.get_by_id(request.target_id, user_id)
        if not target:
            raise NotFoundException(f"Target with ID {request.target_id} not found.")

        # Resolve the requested profile before anything is persisted, so an
        # unknown profile is rejected with 422 instead of creating a job that
        # can only fail later on the background thread. The canonical enum
        # value ("FULL", not "full") is what gets stored and dispatched.
        scan_profile = resolve_scan_profile(request.scan_profile).value

        # Check for duplicate active scans (business rule). PENDING is
        # included alongside RUNNING to close the race where a second scan
        # is requested before the background thread has flipped the first
        # scan's status to RUNNING.
        running_scans = self.scan_repository.get_running_scans_for_target(
            request.target_id
        )
        if running_scans:
            raise ConflictException(
                f"A scan is already running for target {request.target_id}."
            )

        # Enforce global concurrent scan cap (across all targets).
        active_count = self.scan_repository.count_active_scans()
        if active_count >= self.settings.max_concurrent_scans:
            limit = self.settings.max_concurrent_scans
            raise TooManyRequestsException(
                f"Maximum concurrent scan limit reached ({limit}). "
                "Please wait for active scans to complete."
            )

        # Create scan job
        scan_job = ScanJob(
            target_id=target.id,
            user_id=user_id,
            scan_type=scan_profile,
            status=ScanStatus.PENDING,
        )
        scan_job = self.scan_repository.create(scan_job)

        self._commit_with_audit(
            event_type=AuditEventType.SCAN_CREATED,
            resource_id=scan_job.id,
            context=audit_context or AuditContext.system(),
            metadata={"scan_type": scan_job.scan_type, "status": scan_job.status.value},
        )

        if self.scanner_engine:
            thread = threading.Thread(
                target=self._run_scan_in_background,
                args=(scan_job.id, target.target, scan_profile),
                name=f"scan-{scan_job.id}",
                daemon=True,
            )
            self.last_scan_thread = thread
            thread.start()

        return scan_job

    def _run_scan_in_background(
        self, scan_id: uuid.UUID, target: str, scan_profile: str
    ) -> None:
        """Execute the scanner engine off the request thread and persist the outcome.

        Runs on its own DB session (the request-scoped session passed into
        this service is closed by the time the HTTP response is sent).
        Never raises — all failure paths are logged and reflected in the
        scan job's status instead, since there is no caller left to
        propagate an exception to.
        """
        session = self.session_factory()
        try:
            scan_repo = ScanRepository(session)
            audit_service = AuditService(AuditRepository(session))

            scan_job = scan_repo.get_by_id(scan_id)
            if scan_job is None:
                logger.error(
                    "Scan job vanished before background execution could start",
                    extra={"scan_id": str(scan_id)},
                )
                return

            scan_job.status = ScanStatus.RUNNING
            scan_job.started_at = datetime.now(UTC)
            scan_repo.update(scan_job)
            session.commit()
            monotonic_start = time.monotonic()

            try:
                if self.scanner_engine is None:
                    # create_scan only starts this background thread inside
                    # `if self.scanner_engine:`, so this is unreachable in
                    # practice — narrows the type for mypy across the thread
                    # boundary, and still routes through the same
                    # failure-handling path below rather than raising
                    # uncaught out of this method (see its docstring).
                    raise InternalException(
                        "Background scan execution started without a scanner engine."
                    )
                artifact = self.scanner_engine.dispatch_scan(
                    scan_id=scan_id, target=target, scan_profile=scan_profile
                )
            except ScannerCancelledException as exc:
                final_status = ScanStatus.CANCELLED
                failure_reason = "Scan was cancelled by user request."
                event_type = AuditEventType.SCAN_CANCELLED
                outcome = AuditOutcome.SUCCESS
                stdout = exc.details.get("stdout", "")
                stderr = exc.details.get("stderr", "")
                output_path = exc.details.get("output_path")
            except (ScannerTimeoutException, ScannerExecutionException) as exc:
                final_status = ScanStatus.FAILED
                failure_reason = exc.message
                event_type = AuditEventType.SCAN_FAILED
                outcome = AuditOutcome.FAILURE
                stdout = exc.details.get("stdout", "")
                stderr = exc.details.get("stderr", "")
                output_path = exc.details.get("output_path")
            except Exception:  # noqa: BLE001 - last-resort, must not crash the thread
                final_status = ScanStatus.FAILED
                # failure_reason is returned to API clients; the exception
                # text (paths, driver errors) goes to the log only.
                failure_reason = _UNEXPECTED_FAILURE_REASON
                event_type = AuditEventType.SCAN_FAILED
                outcome = AuditOutcome.FAILURE
                stdout, stderr, output_path = "", "", None
                logger.exception(
                    "Unhandled error during background scan execution",
                    extra={"scan_id": str(scan_id)},
                )
            else:
                # Dispatch succeeded: hand off to the parser/inventory/AI/risk
                # chain, which owns status + commit for this outcome — the
                # shared finalize block below is for CANCELLED/TIMEOUT/ERROR
                # paths only and must not run for a successful dispatch.
                self._process_successful_scan(
                    session,
                    scan_repo,
                    audit_service,
                    scan_id,
                    artifact,
                    monotonic_start,
                )
                return

            scan_job.status = final_status
            scan_job.completed_at = datetime.now(UTC)
            # Measured directly rather than by subtracting started_at from
            # completed_at: started_at round-trips through the DB (the
            # commit above expires it) and may come back timezone-naive
            # depending on the backend, while completed_at is always
            # timezone-aware — subtracting the two can raise TypeError.
            scan_job.execution_duration = time.monotonic() - monotonic_start
            scan_job.failure_reason = failure_reason
            self._store_raw_output(scan_job, output_path)
            scan_job.stdout_log = stdout
            scan_job.stderr_log = stderr
            scan_repo.update(scan_job)

            try:
                audit_service.append_event(
                    event_type=event_type,
                    category=AuditEventCategory.SCAN,
                    outcome=outcome,
                    context=AuditContext.system(),
                    resource_type=AuditResourceType.SCAN,
                    resource_id=scan_id,
                    scan_id=scan_id,
                    metadata={"status": final_status.value},
                )
                session.commit()
            except Exception:
                session.rollback()
                logger.error(
                    "Failed to commit scan completion audit event; scan job status "
                    "update was rolled back with it",
                    extra={"scan_id": str(scan_id)},
                    exc_info=True,
                )
        finally:
            self.session_finalizer(session)

    def _process_successful_scan(
        self,
        session: Session,
        scan_repo: ScanRepository,
        audit_service: AuditService,
        scan_id: uuid.UUID,
        artifact: ScanArtifact,
        monotonic_start: float,
    ) -> None:
        """Parse a successful scan's raw output into inventory, then
        best-effort run AI vulnerability discovery and risk scoring.

        InventoryService.process_assessment_package owns scan_job.status and
        commit for this outcome (COMPLETED on success, FAILED on its own
        internal failure) — this method only sets scan_job.status directly
        for a ParserException, where inventory never got a chance to run.
        """
        try:
            package = ParserManager().parse_artifact(artifact)
        except ParserException as exc:
            scan_job = scan_repo.get_by_id(scan_id)
            if scan_job is None:
                return
            scan_job.status = ScanStatus.FAILED
            scan_job.completed_at = datetime.now(UTC)
            scan_job.execution_duration = time.monotonic() - monotonic_start
            # Client-visible; the parser's detail is in the logs.
            scan_job.failure_reason = _PARSE_FAILURE_REASON
            logger.warning(
                "Scan output could not be parsed",
                extra={"context": {"scan_id": str(scan_id), "reason": str(exc)}},
            )
            self._store_raw_output(scan_job, artifact.output_path)
            scan_job.stdout_log = artifact.stdout
            scan_job.stderr_log = artifact.stderr
            scan_repo.update(scan_job)
            try:
                audit_service.append_event(
                    event_type=AuditEventType.SCAN_FAILED,
                    category=AuditEventCategory.SCAN,
                    outcome=AuditOutcome.FAILURE,
                    context=AuditContext.system(),
                    resource_type=AuditResourceType.SCAN,
                    resource_id=scan_id,
                    scan_id=scan_id,
                    metadata={
                        "status": ScanStatus.FAILED.value,
                        "failure_category": "ParserException",
                    },
                )
                session.commit()
            except Exception:
                session.rollback()
                logger.error(
                    "Failed to commit parser-failure audit event for scan",
                    extra={"scan_id": str(scan_id)},
                    exc_info=True,
                )
            return

        inventory_service = InventoryService(
            session,
            AssetRepository(session),
            VulnerabilityRepository(session),
            scan_repo,
            audit_service,
        )
        try:
            inventory_service.process_assessment_package(package, AuditContext.system())
        except Exception:
            logger.exception(
                "Inventory processing failed for scan; scan_job status was "
                "already handled internally by InventoryService",
                extra={"scan_id": str(scan_id)},
            )
            return

        scan_job = scan_repo.get_by_id(scan_id)
        if scan_job is None or scan_job.status != ScanStatus.COMPLETED:
            return

        # Raw scanner output fields aren't known to InventoryService — attach
        # them onto the now-COMPLETED scan job separately.
        self._store_raw_output(scan_job, artifact.output_path)
        scan_job.stdout_log = artifact.stdout
        scan_job.stderr_log = artifact.stderr
        scan_job.execution_duration = time.monotonic() - monotonic_start
        scan_repo.update(scan_job)
        session.commit()

        # Best-effort from here on: a failure in AI discovery or risk
        # calculation must never undo the COMPLETED scan or the asset/service
        # inventory already committed above.
        try:
            ai_manager = self._ai_manager_for(session, scan_job.user_id)
            if ai_manager is None:
                logger.info(
                    "AI analysis skipped: the scan owner has no AI provider key",
                    extra={"context": {"scan_id": str(scan_id)}},
                )
            else:
                AIVulnerabilityDiscoveryService(
                    session,
                    inventory_service,
                    AssetRepository(session),
                    NetworkServiceRepository(session),
                    audit_service,
                    ai_manager=ai_manager,
                ).discover_for_package(package, scan_job.user_id, AuditContext.system())
        except Exception:
            logger.exception(
                "AI vulnerability discovery failed for scan; scan results are "
                "otherwise unaffected",
                extra={"scan_id": str(scan_id)},
            )

        try:
            risk_service = RiskService(
                session,
                RiskRepository(session),
                scan_repo,
                AssetRepository(session),
                ScanFindingRepository(session),
                audit_service,
            )
            risk_service.calculate_risk_for_scan(scan_id, AuditContext.system())
        except Exception:
            logger.exception(
                "Automatic risk calculation failed for scan",
                extra={"scan_id": str(scan_id)},
            )

    def _ai_manager_for(
        self, session: Session, owner_id: uuid.UUID
    ) -> AIManager | None:
        """The AI manager for work done on behalf of `owner_id`.

        Uses the injected manager when one was given (tests); otherwise the
        owner's own saved key, or None when they have not saved one.
        """
        if self.ai_manager is not None:
            return self.ai_manager
        key = ApiKeyService(
            session=session,
            keys=UserApiKeyRepository(session),
            audit_service=AuditService(AuditRepository(session)),
            cipher=KeyCipher(self.settings.app_encryption_key.get_secret_value()),
        ).find_decrypted_key(owner_id, AIKeyProvider.HUGGINGFACE)
        return AIManager(self.settings, api_key=key) if key else None

    def run_ai_analysis(
        self,
        user_id: uuid.UUID,
        scan_id: uuid.UUID,
        audit_context: AuditContext | None = None,
    ) -> int:
        """Re-run AI vulnerability inference for a completed scan, using the
        user's own key, then recalculate deterministic risk.

        Returns the number of findings created.

        Raises:
            ConflictException: if the scan has not completed.
            AIKeyRequiredException: if the user has no AI provider key.
            NotFoundException: if the scan or its raw output is missing.
        """
        scan_job = self.get_scan(scan_id, user_id)
        if scan_job.status != ScanStatus.COMPLETED:
            raise ConflictException("AI analysis needs a completed scan.")
        session = self.scan_repository.session
        ai_manager = self._ai_manager_for(session, user_id)
        if ai_manager is None:
            raise AIKeyRequiredException(AIKeyProvider.HUGGINGFACE.value)

        package = self._reparse_raw_output(user_id, scan_job)
        audit_service = AuditService(AuditRepository(session))
        inventory_service = InventoryService(
            session,
            AssetRepository(session),
            VulnerabilityRepository(session),
            self.scan_repository,
            audit_service,
        )
        context = audit_context or AuditContext.system()
        created = AIVulnerabilityDiscoveryService(
            session,
            inventory_service,
            AssetRepository(session),
            NetworkServiceRepository(session),
            audit_service,
            ai_manager=ai_manager,
        ).discover_for_package(package, user_id, context)
        RiskService(
            session,
            RiskRepository(session),
            self.scan_repository,
            AssetRepository(session),
            ScanFindingRepository(session),
            audit_service,
        ).calculate_risk_for_scan(scan_id, context, owner_id=user_id)
        return created

    def _reparse_raw_output(
        self, user_id: uuid.UUID, scan_job: ScanJob
    ) -> AssessmentPackage:
        """Rebuild the parsed package from the stored raw XML."""
        chunks = self.open_raw_output(user_id, scan_job.id)
        with tempfile.TemporaryDirectory(prefix="avap-reparse-") as tmp:
            xml_path = Path(tmp) / "nmap.xml"
            with xml_path.open("wb") as handle:
                for chunk in chunks:
                    handle.write(chunk)
            artifact = ScanArtifact(
                scan_id=scan_job.id,
                scanner_type=ScannerType.NMAP,
                execution_status=ExecutionStatus.SUCCESS,
                output_path=xml_path,
            )
            try:
                return ParserManager().parse_artifact(artifact)
            except ParserException as exc:
                raise NotFoundException(
                    "The stored scan output could not be read for AI analysis."
                ) from exc

    def recover_interrupted_scans(
        self, audit_context: AuditContext | None = None
    ) -> int:
        """Fail every scan left PENDING or RUNNING by a previous server process.

        Scans run on in-process daemon threads, so a restart kills them while
        their rows stay active and block new scans of the same target. Called
        once at startup. Assumes a single uvicorn worker: with several
        workers, one worker's startup would fail another worker's live scans.

        Returns:
            The number of scans transitioned to FAILED.
        """
        active_scans = self.scan_repository.get_active_scans()
        if not active_scans:
            return 0

        context = audit_context or AuditContext.system()
        completed_at = datetime.now(UTC)
        try:
            for scan_job in active_scans:
                scan_job.status = ScanStatus.FAILED
                scan_job.completed_at = completed_at
                scan_job.failure_reason = _SERVER_RESTART_FAILURE_REASON
                self.scan_repository.update(scan_job)
                self.audit_service.append_event(
                    event_type=AuditEventType.SCAN_FAILED,
                    category=AuditEventCategory.SCAN,
                    outcome=AuditOutcome.FAILURE,
                    context=context,
                    resource_type=AuditResourceType.SCAN,
                    resource_id=scan_job.id,
                    scan_id=scan_job.id,
                    metadata={
                        "status": ScanStatus.FAILED.value,
                        "failure_category": "ServerRestart",
                    },
                )
            self.scan_repository.session.commit()
        except Exception:
            self.scan_repository.session.rollback()
            logger.error(
                "Startup scan recovery failed; transaction rolled back.",
                extra={"context": {"operation": "recover_interrupted_scans"}},
                exc_info=True,
            )
            raise

        logger.warning(
            "Startup recovery marked interrupted scans as FAILED.",
            extra={
                "context": {
                    "operation": "recover_interrupted_scans",
                    "recovered_count": len(active_scans),
                }
            },
        )
        return len(active_scans)

    def cancel_scan(
        self,
        user_id: uuid.UUID,
        scan_id: uuid.UUID,
        audit_context: AuditContext | None = None,
    ) -> ScanJob:
        """Request cancellation of a running scan job.

        This only flags the executing subprocess to stop; the scan job's
        status transitions to CANCELLED asynchronously once the background
        thread notices (within about a second) and persists whatever
        output the scanner had produced so far.
        """
        scan_job = self.get_scan(scan_id, user_id)
        if scan_job.status != ScanStatus.RUNNING:
            raise ConflictException(
                f"Scan {scan_id} is not running (current status: "
                f"{scan_job.status.value}); only running scans can be cancelled."
            )

        if not ScanRuntimeRegistry.request_cancel(scan_id):
            raise ConflictException(
                f"No active scanner process found for scan {scan_id}; it may have "
                "just finished, or the server was restarted after it started."
            )

        return scan_job

    def get_scan(self, scan_id: uuid.UUID, user_id: uuid.UUID) -> ScanJob:
        """Retrieve one of the user's scan jobs by its ID."""
        scan_job = self.scan_repository.get_owned(scan_id, user_id)
        if not scan_job:
            raise NotFoundException(f"Scan job with ID {scan_id} not found.")
        return scan_job

    def get_all_scans(
        self,
        user_id: uuid.UUID,
        skip: int = 0,
        limit: int = 100,
        target_id: uuid.UUID | None = None,
    ) -> Sequence[ScanJob]:
        """Retrieve the user's scan jobs, optionally scoped to one target."""
        return self.scan_repository.get_all(
            user_id=user_id, skip=skip, limit=limit, target_id=target_id
        )

    def count_scans(
        self, user_id: uuid.UUID, target_id: uuid.UUID | None = None
    ) -> int:
        """Count the user's scan jobs, optionally scoped to one target."""
        return self.scan_repository.count(user_id=user_id, target_id=target_id)

    def delete_scan(
        self,
        user_id: uuid.UUID,
        scan_id: uuid.UUID,
        audit_context: AuditContext | None = None,
    ) -> None:
        """Delete one of the user's scan jobs."""
        scan_job = self.get_scan(scan_id, user_id)
        # Note: Depending on business rules, we might not want to delete running scans
        if scan_job.status == ScanStatus.RUNNING:
            raise ConflictException("Cannot delete a running scan.")

        scan_type = scan_job.scan_type
        object_key = scan_job.output_object_key
        self.scan_repository.delete(scan_job)

        self._commit_with_audit(
            event_type=AuditEventType.SCAN_DELETED,
            resource_id=scan_id,
            context=audit_context or AuditContext.system(),
            metadata={"scan_type": scan_type},
        )
        if object_key:
            try:
                self.object_storage.delete(object_key)
            except StorageError:
                logger.warning(
                    "Stored scan output could not be deleted",
                    extra={"context": {"scan_id": str(scan_id)}},
                )

    def list_hosts(
        self, user_id: uuid.UUID, scan_id: uuid.UUID
    ) -> Sequence[ScanHost]:
        """Per-host detail snapshots recorded by one of the user's scans."""
        self.get_scan(scan_id, user_id)
        return ScanHostRepository(self.scan_repository.session).list_for_scan(scan_id)

    def open_raw_output(
        self, user_id: uuid.UUID, scan_id: uuid.UUID
    ) -> Iterator[bytes]:
        """Stream the raw scanner output of one of the user's scans.

        Raises:
            NotFoundException: if the scan isn't the user's or has no output.
        """
        scan_job = self.get_scan(scan_id, user_id)
        try:
            if scan_job.output_object_key:
                return self.object_storage.open_stream(scan_job.output_object_key)
            if scan_job.output_file_path:
                return self._open_local_fallback(scan_job.output_file_path)
        except StorageError as exc:
            logger.warning(
                "Stored scan output could not be read",
                extra={"context": {"scan_id": str(scan_id), "reason": str(exc)}},
            )
        raise NotFoundException("No raw output is available for this scan.")

    def _open_local_fallback(self, file_path: str) -> Iterator[bytes]:
        """Read output kept on disk after a failed upload, but only from
        inside the configured scanner output directory."""
        root = self.settings.scanner_output_path.resolve()
        candidate = Path(file_path).resolve()
        if not candidate.is_relative_to(root) or not candidate.is_file():
            raise StorageError("Local scan output is not available.")
        return LocalObjectStorage(root).open_stream(
            candidate.relative_to(root).as_posix().lower()
        )

    def _store_raw_output(self, scan_job: ScanJob, output_path: object) -> None:
        """Upload the scanner's output file and drop the local copy.

        A storage failure never fails the scan: the local path is kept so
        the output is still downloadable, and the error is logged.
        """
        if not output_path:
            return
        local_file = Path(str(output_path))
        if not local_file.is_file():
            return
        key = raw_output_key(scan_job.user_id, scan_job.id)
        try:
            self.object_storage.put_file(key, local_file, _RAW_OUTPUT_CONTENT_TYPE)
        except StorageError as exc:
            scan_job.output_file_path = str(local_file)
            logger.warning(
                "Raw scan output upload failed; keeping the local file",
                extra={"context": {"scan_id": str(scan_job.id), "reason": str(exc)}},
            )
            return
        scan_job.output_object_key = key
        scan_job.output_file_path = None
        local_file.unlink(missing_ok=True)
