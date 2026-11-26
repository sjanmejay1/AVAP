import contextlib
import logging
import re
import xml.etree.ElementTree as ET  # nosec B405 -- XXE-safe, see call-site comment below
from pathlib import Path

from app.core.enums import ScannerType
from app.core.exceptions import ParserException
from app.parsers.base_parser import BaseParser
from app.parsers.models import (
    AssessmentPackage,
    ParsedHost,
    ParsedService,
    ParsedVulnerability,
)
from app.parsers.nse_vulns import extract_vulnerabilities
from app.scanners.scan_artifact import ScanArtifact

logger = logging.getLogger(__name__)

# Maximum length for script output stored in extra_info to avoid bloating rows.
_SCRIPT_OUTPUT_MAX_CHARS = 4000

# Control-character pattern: strip 0x00-0x1F except \t (0x09) and \n (0x0A).
_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f]")


def _sanitize_script_output(raw: str) -> str:
    """Strip control characters and cap length for safe DB storage."""
    cleaned = _CTRL_CHARS_RE.sub("", raw)
    if len(cleaned) > _SCRIPT_OUTPUT_MAX_CHARS:
        cleaned = cleaned[:_SCRIPT_OUTPUT_MAX_CHARS] + "…[truncated]"
    return cleaned


class NmapParser(BaseParser):
    """Secure parser for Nmap XML output files."""

    def parse(self, artifact: ScanArtifact) -> AssessmentPackage:
        """Parse Nmap XML output from the given artifact.

        Args:
            artifact: The ScanArtifact containing Nmap results.

        Returns:
            A populated AssessmentPackage.
        """
        if not artifact.output_path:
            raise ParserException("Scan artifact has no output path specified.")

        output_path = Path(artifact.output_path)
        if not output_path.exists():
            raise ParserException(f"Nmap output file not found at: {output_path}")

        logger.info(
            "Parsing Nmap XML output",
            extra={"scan_id": str(artifact.scan_id), "file_path": str(output_path)},
        )

        try:
            # Secure XML parsing: xml.etree.ElementTree's bundled expat parser
            # never resolves external entities (XXE-safe by default) and, on all
            # currently supported CPython versions, rejects entity-expansion
            # ("billion laughs") attacks via its built-in amplification limit.
            # No custom parser configuration or third-party library is required.
            tree = ET.parse(output_path)  # noqa: S314 # nosec B314 -- justified above, stdlib ET is XXE-safe
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(
                f"XML parse error in Nmap output: {e}",
                extra={"scan_id": str(artifact.scan_id), "file_path": str(output_path)},
            )
            raise ParserException(f"Failed to parse Nmap XML report: {e}") from e
        except Exception as e:
            logger.exception(
                f"Unexpected error reading Nmap output file: {e}",
                extra={"scan_id": str(artifact.scan_id)},
            )
            raise ParserException(f"Failed to read Nmap output file: {e}") from e

        parsed_hosts: list[ParsedHost] = []

        # Parse every <host> element in the XML
        for host_node in root.findall("host"):
            # 1. Find IPv4 / MAC addresses
            ipv4_addr = None
            mac_address = None
            mac_vendor = None
            for addr_node in host_node.findall("address"):
                addrtype = addr_node.get("addrtype", "")
                if addrtype == "ipv4":
                    ipv4_addr = addr_node.get("addr")
                elif addrtype == "mac":
                    mac_address = addr_node.get("addr")
                    mac_vendor = addr_node.get("vendor")  # may be None

            # If no IP, skip (Nmap should always provide one)
            if not ipv4_addr:
                logger.warning(
                    "Skipping host element with missing IPv4 address in Nmap report",
                    extra={"scan_id": str(artifact.scan_id)},
                )
                continue

            # 2. Host status — only parse hosts that are "up"
            status_node = host_node.find("status")
            if status_node is not None and status_node.get("state") != "up":
                continue

            # 3. Hostnames — collect all, pick best primary
            all_hostnames: list[dict[str, str]] = []
            hostname: str | None = None
            hostnames_node = host_node.find("hostnames")
            if hostnames_node is not None:
                for hn in hostnames_node.findall("hostname"):
                    name = hn.get("name", "")
                    htype = hn.get("type", "")
                    if name:
                        all_hostnames.append({"name": name, "type": htype})
                # Prefer PTR first, then user-supplied, then first available
                for entry in all_hostnames:
                    if entry["type"] == "PTR":
                        hostname = entry["name"]
                        break
                if hostname is None:
                    for entry in all_hostnames:
                        if entry["type"] == "user":
                            hostname = entry["name"]
                            break
                if hostname is None and all_hostnames:
                    hostname = all_hostnames[0]["name"]

            # 4. OS detection — collect all osmatches + classes
            os_name: str | None = None
            os_matches: list[dict] = []
            os_node = host_node.find("os")
            if os_node is not None:
                for osmatch in os_node.findall("osmatch"):
                    match_name = osmatch.get("name", "")
                    match_accuracy = osmatch.get("accuracy", "0")
                    match_line = osmatch.get("line", "")
                    match_cpes: list[str] = [
                        cpe.text or "" for cpe in osmatch.findall("cpe") if cpe.text
                    ]
                    classes: list[dict] = []
                    for osclass in osmatch.findall("osclass"):
                        class_cpes: list[str] = [
                            c.text or "" for c in osclass.findall("cpe") if c.text
                        ]
                        classes.append(
                            {
                                "type": osclass.get("type", ""),
                                "vendor": osclass.get("vendor", ""),
                                "osfamily": osclass.get("osfamily", ""),
                                "osgen": osclass.get("osgen", ""),
                                "accuracy": osclass.get("accuracy", ""),
                                "cpes": class_cpes,
                            }
                        )
                    os_matches.append(
                        {
                            "name": match_name,
                            "accuracy": match_accuracy,
                            "line": match_line,
                            "cpes": match_cpes,
                            "classes": classes,
                        }
                    )
                # Best match = highest accuracy (first in Nmap output ordering)
                if os_matches:
                    os_name = os_matches[0]["name"] or None

            # 5. Uptime
            uptime_seconds: int | None = None
            uptime_last_boot: str | None = None
            uptime_node = host_node.find("uptime")
            if uptime_node is not None:
                with contextlib.suppress(ValueError, TypeError):
                    uptime_seconds = int(uptime_node.get("seconds", ""))
                uptime_last_boot = uptime_node.get("lastboot")

            # 6. Network distance
            network_distance: int | None = None
            distance_node = host_node.find("distance")
            if distance_node is not None:
                with contextlib.suppress(ValueError, TypeError):
                    network_distance = int(distance_node.get("value", ""))

            # 7. Traceroute hops
            traceroute_hops: list[dict[str, str]] = []
            trace_node = host_node.find("trace")
            if trace_node is not None:
                for hop in trace_node.findall("hop"):
                    traceroute_hops.append(
                        {
                            "ttl": hop.get("ttl", ""),
                            "ipaddr": hop.get("ipaddr", ""),
                            "rtt": hop.get("rtt", ""),
                            "host": hop.get("host", ""),
                        }
                    )

            # 8. Services / Open Ports + extraports counts
            parsed_services: list[ParsedService] = []
            closed_port_count = 0
            filtered_port_count = 0
            ports_node = host_node.find("ports")
            if ports_node is not None:
                # Extraports (closed/filtered in bulk)
                for extraports in ports_node.findall("extraports"):
                    ep_state = extraports.get("state", "")
                    try:
                        ep_count = int(extraports.get("count", "0"))
                    except (ValueError, TypeError):
                        ep_count = 0
                    if "filtered" in ep_state:
                        filtered_port_count += ep_count
                    elif "closed" in ep_state:
                        closed_port_count += ep_count

                for port_node in ports_node.findall("port"):
                    state_node = port_node.find("state")
                    if state_node is None:
                        continue
                    port_state = state_node.get("state", "")
                    # Include open and open|filtered; skip closed/filtered only
                    if port_state not in ("open", "open|filtered"):
                        continue

                    port_id_str = port_node.get("portid")
                    protocol = port_node.get("protocol")
                    if not port_id_str or not protocol:
                        continue

                    try:
                        port_id = int(port_id_str)
                    except ValueError:
                        continue

                    service_name = "unknown"
                    product = None
                    version = None
                    extra_info = None
                    cpes: list[str] = []

                    service_node = port_node.find("service")
                    if service_node is not None:
                        service_name = service_node.get("name", "unknown")
                        product = service_node.get("product")
                        version = service_node.get("version")
                        extra_info = service_node.get("extrainfo")
                        cpes = [
                            cpe.text or ""
                            for cpe in service_node.findall("cpe")
                            if cpe.text
                        ]

                    # Script outputs per port
                    scripts: dict[str, str] = {}
                    port_vulnerabilities: list[ParsedVulnerability] = []
                    for script_node in port_node.findall("script"):
                        script_id = script_node.get("id", "")
                        script_output = script_node.get("output", "")
                        if script_id:
                            scripts[script_id] = _sanitize_script_output(script_output)
                        port_vulnerabilities.extend(
                            extract_vulnerabilities(
                                script_node, port_id, protocol.lower()
                            )
                        )

                    # Merge script output into extra_info for DB storage
                    if scripts:
                        script_blob = "; ".join(
                            f"[{sid}] {sout}" for sid, sout in scripts.items()
                        )
                        script_blob = _sanitize_script_output(script_blob)
                        if extra_info:
                            merged = f"{extra_info} | scripts: {script_blob}"
                            extra_info = _sanitize_script_output(merged)
                        else:
                            extra_info = script_blob

                    parsed_services.append(
                        ParsedService(
                            port=port_id,
                            protocol=protocol.lower(),
                            service_name=service_name,
                            product=product,
                            version=version,
                            extra_info=extra_info,
                            vulnerabilities=port_vulnerabilities,
                            state=port_state,
                            cpes=cpes,
                            scripts=scripts,
                        )
                    )

            # Host-level scripts (e.g. SMB checks) report under <hostscript>.
            host_vulnerabilities: list[ParsedVulnerability] = []
            hostscript_node = host_node.find("hostscript")
            if hostscript_node is not None:
                for script_node in hostscript_node.findall("script"):
                    host_vulnerabilities.extend(
                        extract_vulnerabilities(script_node, None, None)
                    )

            parsed_hosts.append(
                ParsedHost(
                    ipv4=ipv4_addr,
                    hostname=hostname,
                    operating_system=os_name,
                    services=parsed_services,
                    mac_address=mac_address,
                    mac_vendor=mac_vendor,
                    all_hostnames=all_hostnames,
                    os_matches=os_matches,
                    uptime_seconds=uptime_seconds,
                    uptime_last_boot=uptime_last_boot,
                    network_distance=network_distance,
                    traceroute_hops=traceroute_hops,
                    closed_port_count=closed_port_count,
                    filtered_port_count=filtered_port_count,
                    host_vulnerabilities=host_vulnerabilities,
                )
            )

        # Extract execution metadata
        execution_metadata: dict = {}
        scanner_version = root.get("version")
        if scanner_version:
            execution_metadata["scanner_version"] = scanner_version

        args = root.get("args")
        if args:
            execution_metadata["arguments"] = args

        return AssessmentPackage(
            scan_id=artifact.scan_id,
            scanner_type=ScannerType.NMAP,
            parsed_hosts=parsed_hosts,
            execution_metadata=execution_metadata,
        )
