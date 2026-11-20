import logging
import uuid

from app.core.enums import ScannerType, ScanProfile
from app.core.exceptions import ValidationException
from app.scanners.execution_validator import ExecutionValidator
from app.scanners.interfaces import IScannerEngine
from app.scanners.scan_artifact import ScanArtifact
from app.scanners.scanner_factory import ScannerFactory

logger = logging.getLogger(__name__)

_QUICK_ALIASES = {"QUICK", "FAST", "DISCOVERY", "PING", "PORT_SCAN", "PORT", "PORTS"}
_FULL_ALIASES = {"FULL", "DEEP", "ALL"}


def resolve_scan_profile(scan_profile: str) -> ScanProfile:
    """Map a case-insensitive profile identifier to the ScanProfile enum.

    Args:
        scan_profile: The string profile name (case-insensitive).

    Returns:
        The ScanProfile enum.

    Raises:
        ValidationException if the profile name is invalid.
    """
    norm_profile = scan_profile.strip().upper()

    # Older profile names from earlier API versions map to QUICK.
    if norm_profile in _QUICK_ALIASES:
        return ScanProfile.QUICK
    if norm_profile in _FULL_ALIASES:
        return ScanProfile.FULL

    try:
        return ScanProfile[norm_profile]
    except KeyError as exc:
        raise ValidationException(
            f"Invalid scan profile: '{scan_profile}'. "
            f"Supported profiles: {[p.name for p in ScanProfile]}"
        ) from exc


class ScannerManager(IScannerEngine):
    """Entry point for all scanner execution requests.

    Orchestrates validation, adapter lookup, execution, and artifact retrieval.
    """

    def __init__(
        self,
        factory: ScannerFactory | None = None,
        validator: ExecutionValidator | None = None,
    ):
        self.factory = factory or ScannerFactory()
        self.validator = validator or ExecutionValidator()

    def _parse_scan_profile(self, scan_profile: str) -> ScanProfile:
        """Map string profile identifier to ScanProfile enum.

        Delegates to `resolve_scan_profile`; see it for accepted spellings.
        """
        return resolve_scan_profile(scan_profile)

    def dispatch_scan(
        self,
        scan_id: uuid.UUID,
        target: str,
        scan_profile: str,
        scanner_type: ScannerType | None = None,
    ) -> ScanArtifact:
        """Validate and execute a scan against a target.

        Args:
            scan_id: The unique identifier of the scan job.
            target: The target IP, CIDR, or hostname.
            scan_profile: The scan profile (string).
            scanner_type: Optional scanner type (defaults to NMAP).

        Returns:
            A ScanArtifact containing the results of the execution.
        """
        # Resolve scanner type default
        resolved_scanner = scanner_type or ScannerType.NMAP

        # Parse profile
        resolved_profile = self._parse_scan_profile(scan_profile)

        logger.info(
            "Dispatching scan request",
            extra={
                "scan_id": str(scan_id),
                "target": target,
                "scanner_type": resolved_scanner.value,
                "profile": resolved_profile.value,
            },
        )

        # Validate request (target format, security constraints, compatibility)
        self.validator.validate_request(target, resolved_scanner, resolved_profile)

        # Resolve adapter via factory
        adapter = self.factory.get_adapter(resolved_scanner)

        # Execute scan via adapter
        artifact = adapter.execute(scan_id, target, resolved_profile)

        logger.info(
            "Scan dispatch completed",
            extra={
                "scan_id": str(scan_id),
                "status": artifact.execution_status.value,
                "duration": artifact.execution_duration_seconds,
            },
        )

        return artifact
