import ctypes
import logging
import os
import shutil
import subprocess
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
        except Exception:  # noqa: S110
            pass

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
        except Exception:  # noqa: S110
            pass

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
    except Exception:  # noqa: S110
        pass

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
            force_privileged: Optional override for privileged mode in FULL profile.

        Returns:
            A list of command-line arguments starting with the Nmap executable.
        """
        sanitized_target = self._sanitize_target(target)
        executable = self.settings.nmap_executable

        # Default fallback if setting is empty
        if not executable:
            executable = "nmap"

        args = [executable]

        # Configure scan options based on profile
        if scan_profile == ScanProfile.DISCOVERY:
            args.extend(["-sn"])  # Ping scan (no port scan)
        elif scan_profile == ScanProfile.PORT_SCAN:
            args.extend(["-sT", "-F"])  # TCP Connect scan, Fast mode
        elif scan_profile == ScanProfile.FULL:
            is_priv = (
                force_privileged
                if force_privileged is not None
                else detect_privileged_mode(self.settings)
            )

            if is_priv:
                priv_flags = []
                if _needs_privileged_flag():
                    priv_flags.append("--privileged")
                priv_flags.extend(
                    [
                        "-sS",
                        "-sV",
                        "-O",
                        "--osscan-guess",
                        "-sC",
                        "--traceroute",
                        "-p-",
                        "-Pn",
                        "-T4",
                        "--version-intensity",
                        "7",
                        "--max-retries",
                        "2",
                        "--host-timeout",
                        "90m",
                        "--stats-every",
                        "30s",
                    ]
                )
                args.extend(priv_flags)
            else:
                logger.warning(
                    "Executing FULL scan in unprivileged mode: "
                    "OS detection and SYN scan unavailable. "
                    "Falling back to -sT."
                )
                args.extend(
                    [
                        "-sT",
                        "-sV",
                        "-sC",
                        "-p-",
                        "-Pn",
                        "-T4",
                        "--version-intensity",
                        "7",
                        "--max-retries",
                        "2",
                        "--host-timeout",
                        "90m",
                        "--stats-every",
                        "30s",
                    ]
                )
        else:
            # Fallback/default if unrecognized
            args.extend(["-sT"])

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

        is_privileged = (
            detect_privileged_mode(self.settings)
            if scan_profile == ScanProfile.FULL
            else False
        )
        cmd_args = self.build_command(
            target, scan_profile, str(output_path), force_privileged=is_privileged
        )

        # Determine outer timeout based on scan profile:
        # Full scans get extended timeout (90m host-timeout + 15m buffer = 6300s);
        # other profiles retain the standard default timeout (300s).
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
                and scan_profile == ScanProfile.FULL
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
