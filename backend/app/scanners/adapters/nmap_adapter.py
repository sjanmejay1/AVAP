import ctypes
import logging
import os
import shutil
import subprocess  # nosec B404 -- shell=False, fixed argv only (getcap probe)
import uuid

from app.core.config import get_settings
from app.core.enums import ScannerType, ScanProfile
from app.core.exceptions import ScannerExecutionException
from app.scanners.adapters.base_adapter import BaseScannerAdapter
from app.scanners.scan_artifact import ScanArtifact
from app.scanners.scanner_executor import ScannerExecutor

logger = logging.getLogger(__name__)

# Markers in nmap stderr indicating a privilege/permission failure.
# When NET_RAW capability is missing (e.g. cap_drop: ALL in container),
# Nmap cannot open raw network sockets and fails with one of these error strings.
_PRIVILEGE_ERROR_MARKERS = [
    "requires root privileges",
    "operation not permitted",
    "need to be root",
    "requires privileges",
    "privilege",
    "dnet: failed to open",
    "pcap_open_live",
    "permission denied",
]


# FULL runs NSE scripts that are safe and stay on the target: "broadcast"
# scripts would probe the whole local network and "external" scripts send
# data to third-party services, so both are excluded.
FULL_SCRIPT_SELECTION = (
    "(default or vuln or discovery) and safe and not (broadcast or external)"
)

_COMMON_TAIL = ["-Pn", "-T4", "--stats-every", "30s"]
_QUICK_COMMON = [
    "-sV",
    "--version-light",
    "--top-ports",
    "1000",
    "--max-retries",
    "1",
    "--host-timeout",
    "10m",
    *_COMMON_TAIL,
]
_FULL_COMMON = [
    "-sV",
    "--version-intensity",
    "7",
    "--script",
    FULL_SCRIPT_SELECTION,
    "-p-",
    "--max-retries",
    "2",
    "--host-timeout",
    "90m",
    *_COMMON_TAIL,
]

# Raw-socket variants: SYN scan plus OS detection.
_PRIVILEGED_FLAGS: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: ["-sS", "-O", "--osscan-limit", *_QUICK_COMMON],
    ScanProfile.FULL: ["-sS", "-O", "--osscan-guess", "--traceroute", *_FULL_COMMON],
}
# Fallbacks without raw sockets: TCP connect scan, no OS detection/traceroute.
_UNPRIVILEGED_FLAGS: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: ["-sT", *_QUICK_COMMON],
    ScanProfile.FULL: ["-sT", *_FULL_COMMON],
}


def detect_privileged_mode(settings=None) -> bool:
    """Detect whether Nmap has the privileges required for raw-socket features.

    Checks:
    - If NMAP_SCAN_MODE is 'privileged', returns True.
    - If NMAP_SCAN_MODE is 'unprivileged', returns False.
    - If 'auto':
      - On Windows: check if user is Administrator OR Npcap is installed.
      - On POSIX: check if euid == 0 OR nmap binary has cap_net_raw capabilities.
    """
    if settings is None:
        settings = get_settings()

    mode = (settings.nmap_scan_mode or "auto").strip().lower()
    if mode == "privileged":
        return True
    if mode == "unprivileged":
        return False

    # Mode is 'auto': probe the system environment
    if os.name == "nt":
        # 1. Check if process is elevated administrator
        try:
            if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                return True
        except Exception:
            logger.debug(
                "Windows admin check unavailable; assuming not elevated.",
                extra={"context": {"operation": "detect_privileged_mode"}},
            )

        # 2. Check for Npcap registry keys (allows raw packet operations via driver)
        try:
            import winreg

            npcap_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap"),
            ]
            for hive, key_path in npcap_keys:
                try:
                    k = winreg.OpenKey(hive, key_path)
                    winreg.CloseKey(k)
                    return True
                except OSError:
                    continue
        except Exception:
            logger.debug(
                "Npcap registry probe failed; assuming no raw-packet driver.",
                extra={"context": {"operation": "detect_privileged_mode"}},
            )

        return False

    # POSIX platform
    geteuid_fn = getattr(os, "geteuid", None)
    if geteuid_fn is not None and geteuid_fn() == 0:
        return True

    # Check for file capabilities using getcap
    nmap_path = settings.nmap_executable or shutil.which("nmap") or "nmap"
    getcap_bin = shutil.which("getcap") or "/usr/sbin/getcap"
    try:
        res = subprocess.run(  # noqa: S603 # nosec B603
            [getcap_bin, nmap_path],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if "cap_net_raw" in res.stdout:
            return True
    except Exception:
        logger.debug(
            "getcap probe failed; assuming nmap lacks cap_net_raw.",
            extra={"context": {"operation": "detect_privileged_mode"}},
        )

    return False


def _needs_privileged_flag() -> bool:
    """Check if --privileged flag should be added.

    Requirement: when mode is privileged and the process is non-root on Linux
    (capabilities path), add --privileged to the privileged command. Do not add
    it on Windows or when running as root.
    """
    if os.name == "nt":
        return False
    geteuid_fn = getattr(os, "geteuid", None)
    return not (geteuid_fn is not None and geteuid_fn() == 0)


def _is_privilege_error(stderr_output: str) -> bool:
    """Check if stderr contains an Nmap raw-socket / permission failure message."""
    if not stderr_output:
        return False
    lower_stderr = stderr_output.lower()
    return any(marker in lower_stderr for marker in _PRIVILEGE_ERROR_MARKERS)


class NmapAdapter(BaseScannerAdapter):
    """Adapter for Nmap port scanner.

    Translates high-level targets and profiles into secure Nmap command arguments
    and manages the execution via ScannerExecutor.
    """

    def __init__(self, executor: ScannerExecutor | None = None):
        self.settings = get_settings()
        self.executor = executor or ScannerExecutor()

    def get_scanner_type(self) -> ScannerType:
        return ScannerType.NMAP

    def _sanitize_target(self, target: str) -> str:
        """Sanitize target to prevent command-line option injection.

        Args:
            target: The raw target string.

        Returns:
            The sanitized target.
        """
        sanitized = target.strip()
        # Prevent target from starting with a hyphen, which could be
        # interpreted as an option
        if sanitized.startswith("-"):
            raise ScannerExecutionException(
                f"Invalid scan target: '{target}' cannot start with a hyphen."
            )
        return sanitized

    def build_command(
        self,
        target: str,
        scan_profile: ScanProfile,
        output_path: str,
        force_privileged: bool | None = None,
    ) -> list[str]:
        """Construct the secure command-line argument list for Nmap.

        Args:
            target: The normalized target IP/hostname/CIDR.
            scan_profile: The ScanProfile enum value.
            output_path: The file path where the scanner should write its XML output.
            force_privileged: Optional override for privileged mode detection.

        Returns:
            A list of command-line arguments starting with the Nmap executable.
        """
        sanitized_target = self._sanitize_target(target)
        executable = self.settings.nmap_executable

        # Default fallback if setting is empty
        if not executable:
            executable = "nmap"

        args = [executable]

        is_priv = (
            force_privileged
            if force_privileged is not None
            else detect_privileged_mode(self.settings)
        )
        if is_priv:
            if _needs_privileged_flag():
                args.append("--privileged")
            args.extend(_PRIVILEGED_FLAGS[scan_profile])
        else:
            logger.warning(
                "Running nmap unprivileged: SYN scan and OS detection are "
                "unavailable, using a TCP connect scan.",
                extra={"context": {"profile": scan_profile.value}},
            )
            args.extend(_UNPRIVILEGED_FLAGS[scan_profile])

        # Output to XML file
        args.extend(["-oX", output_path])

        # Append target at the very end
        args.append(sanitized_target)

        return args

    def execute(
        self, scan_id: uuid.UUID, target: str, scan_profile: ScanProfile
    ) -> ScanArtifact:
        """Execute the Nmap scan and return a standardized ScanArtifact.

        If a privileged scan fails with a privilege error, it retries once
        with the unprivileged variant and logs a warning.

        Args:
            scan_id: The unique scan job identifier.
            target: The normalized target IP/hostname/CIDR.
            scan_profile: The ScanProfile enum value.

        Returns:
            A standardized ScanArtifact containing execution details and results.
        """
        # Ensure output directory exists
        output_dir = self.settings.scanner_output_path
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build unique output file path
        filename = f"nmap_{scan_id}.xml"
        output_path = output_dir / filename

        is_privileged = detect_privileged_mode(self.settings)
        cmd_args = self.build_command(
            target, scan_profile, str(output_path), force_privileged=is_privileged
        )

        # Outer process deadline per profile: nmap's own --host-timeout plus a
        # buffer (FULL: 90m + 15m = 6300s; QUICK: 10m + 5m = 900s).
        exec_timeout = (
            self.settings.full_scan_timeout
            if scan_profile == ScanProfile.FULL
            else self.settings.scan_timeout
        )

        try:
            artifact = self.executor.run_scanner(
                scanner_type=ScannerType.NMAP,
                cmd_args=cmd_args,
                scan_id=scan_id,
                output_path=output_path,
                timeout=exec_timeout,
            )

            # Check if execution failed due to privilege/permission errors
            if (
                artifact.exit_code != 0
                and is_privileged
                and _is_privilege_error(artifact.stderr)
            ):
                logger.warning(
                    "Privileged Nmap scan failed due to privilege error. "
                    "Retrying with unprivileged variant.",
                    extra={"scan_id": str(scan_id), "stderr": artifact.stderr},
                )
                fallback_cmd = self.build_command(
                    target, scan_profile, str(output_path), force_privileged=False
                )
                artifact = self.executor.run_scanner(
                    scanner_type=ScannerType.NMAP,
                    cmd_args=fallback_cmd,
                    scan_id=scan_id,
                    output_path=output_path,
                    timeout=exec_timeout,
                )

            # If nmap returned non-zero (e.g. unprivileged fallback also failed,
            # or cap_drop ALL prevented socket creation), emit a clear error log.
            if artifact.exit_code != 0:
                logger.error(
                    "Nmap scanner execution failed with non-zero exit code: %s",
                    artifact.exit_code,
                    extra={
                        "scan_id": str(scan_id),
                        "exit_code": artifact.exit_code,
                        "stderr": artifact.stderr,
                    },
                )

            return artifact
        except Exception as e:
            logger.error(
                f"Failed to execute Nmap scan: {e}",
                extra={"scan_id": str(scan_id), "target": target},
            )
            raise
