import hmac
import ipaddress
import re
from collections.abc import Sequence

from app.core.constants import HOSTNAME_MAX_LABEL_LENGTH, HOSTNAME_MAX_LENGTH

# Regex for validating a single hostname label
# Must start and end with alphanumeric, can contain hyphens
_LABEL_REGEX = re.compile(
    rf"^[a-zA-Z0-9]([a-zA-Z0-9-]{{0,{HOSTNAME_MAX_LABEL_LENGTH - 2}}}[a-zA-Z0-9])?$"
)


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate if a string is a valid IPv4 address.

    Args:
        ip_str: The string to validate.

    Returns:
        True if valid IPv4 address, False otherwise.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return not (ip.is_multicast or ip.is_loopback or ip.is_unspecified)
    except ipaddress.AddressValueError:
        return False


def is_valid_ipv4_cidr(cidr_str: str) -> bool:
    """Validate if a string is a valid IPv4 CIDR network.

    Args:
        cidr_str: The string to validate.

    Returns:
        True if valid IPv4 network, False otherwise.
    """
    try:
        network = ipaddress.IPv4Network(cidr_str, strict=False)
        return not (
            network.is_multicast or network.is_loopback or network.is_unspecified
        )
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False


def cidr_exceeds_scope(cidr_str: str, min_prefix_length: int) -> bool:
    """Return True if a valid IPv4 CIDR is broader than the allowed prefix.

    Args:
        cidr_str: An IPv4 CIDR string already accepted by is_valid_ipv4_cidr.
        min_prefix_length: The smallest prefix length (largest range) allowed.

    Returns:
        True when the network's prefix length is below the minimum.
    """
    network = ipaddress.IPv4Network(cidr_str, strict=False)
    return network.prefixlen < min_prefix_length


def is_valid_hostname(hostname: str) -> bool:
    """Validate if a string is an RFC-compliant hostname.

    Args:
        hostname: The string to validate.

    Returns:
        True if valid hostname, False otherwise.
    """
    if not hostname or len(hostname) > HOSTNAME_MAX_LENGTH:
        return False

    # Remove trailing dot if present (FQDN)
    if hostname.endswith("."):
        hostname = hostname[:-1]

    labels = hostname.split(".")

    # "localhost" and every "*.localhost" name always resolve to loopback
    # (RFC 6761 §6.3), which is refused for IP targets; refuse it here too so
    # a user cannot point the scanner at the server itself by name.
    if labels[-1].lower() == "localhost":
        return False

    # Needs at least one label, though usually we expect a TLD (2+)
    # For flexibility in internal networks, we allow single labels
    if not labels:
        return False

    for label in labels:
        if not _LABEL_REGEX.match(label):
            return False

    # A multi-label value where every label is purely numeric (e.g.
    # "999.999.999.999" or "1.2.3.4.5") is always an attempted IP address,
    # never a hostname — even when it has an invalid octet count or range.
    # Such values must be rejected outright rather than falling through to
    # hostname classification just because IPv4 parsing failed on them.
    return not (len(labels) > 1 and all(label.isdigit() for label in labels))


def normalize_target_value(value: str) -> str:
    """Normalize a target value for consistent storage and comparison.

    - Strips leading/trailing whitespace
    - Converts to lowercase

    Args:
        value: The raw target string.

    Returns:
        The normalized target string.
    """
    return value.strip().lower()


# Headers a trusted reverse proxy (Caddy in docker-compose.prod.yml) adds to
# every request it forwards. The client IP is believed only when the shared
# secret matches; a client can never set either header usefully on its own.
PROXY_SECRET_HEADER = "X-AVAP-Proxy-Secret"  # noqa: S105 # nosec B105 -- header name
CLIENT_IP_HEADER = "X-AVAP-Client-IP"
_MAX_IP_LENGTH = 45

ALLOWLIST_REJECTION_MESSAGE = "This target isn't on this deployment's approved list."


def resolve_client_ip(
    peer: str | None,
    forwarded_ip: str | None,
    presented_secret: str | None,
    expected_secret: str,
) -> str | None:
    """Return the client IP to use for throttling and audit records.

    The proxy-supplied IP is used only when a secret is configured, the
    request presents exactly that secret, and the value is a valid IP
    address. In every other case the direct connection address is used.
    """
    if not expected_secret or not presented_secret or not forwarded_ip:
        return peer
    if not hmac.compare_digest(
        presented_secret.encode("utf-8"), expected_secret.encode("utf-8")
    ):
        return peer
    candidate = forwarded_ip.strip()
    if len(candidate) > _MAX_IP_LENGTH:
        return peer
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer


def normalize_allowlist_entry(entry: str) -> str:
    """Lower-case an allowlist entry and drop a trailing FQDN dot."""
    return normalize_target_value(entry).rstrip(".")


def is_valid_allowlist_entry(entry: str) -> bool:
    """An allowlist entry is an IPv4 address, an IPv4 CIDR or a hostname."""
    return (
        is_valid_ipv4(entry) or is_valid_ipv4_cidr(entry) or is_valid_hostname(entry)
    )


def is_target_allowed(target: str, allowlist: Sequence[str]) -> bool:
    """Whether a scan target falls inside the configured allowlist.

    An empty allowlist allows everything. A hostname matches only an equal
    hostname entry: no DNS lookup happens, so a hostname entry never
    authorizes the addresses it resolves to. An IPv4 address or CIDR must
    lie entirely inside an IPv4 or CIDR entry.
    """
    if not allowlist:
        return True
    candidate = normalize_allowlist_entry(target)
    candidate_network = _as_ipv4_network(candidate)
    for entry in allowlist:
        entry_network = _as_ipv4_network(entry)
        if candidate_network is None:
            if entry_network is None and entry == candidate:
                return True
        elif entry_network is not None and candidate_network.subnet_of(entry_network):
            return True
    return False


def _as_ipv4_network(value: str) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return None
