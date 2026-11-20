"""Application enumerations.

All enums use PascalCase names with UPPER_CASE members
per development standards.
"""

import enum


class TargetType(str, enum.Enum):
    """Classification of scan target types."""

    IPV4 = "IPV4"
    CIDR = "CIDR"
    HOSTNAME = "HOSTNAME"


class ScanStatus(str, enum.Enum):
    """Execution status of a scan job."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScannerType(str, enum.Enum):
    """Supported scanner implementations."""

    NMAP = "NMAP"


class ScanProfile(str, enum.Enum):
    """Predefined scan profiles controlling scanner behavior."""

    QUICK = "QUICK"  # top 1000 TCP ports, versions, OS (~1 min per host)
    FULL = "FULL"  # all 65535 TCP ports, versions, OS, traceroute, safe NSE


class ExecutionStatus(str, enum.Enum):
    """Outcome status of a scanner execution."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"


class RiskScope(str, enum.Enum):
    """Explicit scope of a persisted risk assessment record."""

    VULNERABILITY = "VULNERABILITY"
    ASSET = "ASSET"
    SCAN = "SCAN"
    ASSESSMENT = "ASSESSMENT"


class RiskLevel(str, enum.Enum):
    """Standardized deterministic risk categorization."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuditEventCategory(str, enum.Enum):
    """High-level domain grouping for an audit event, independent of the
    specific event_type. Enables coarse filtering without enumerating every
    event type. SYSTEM is reserved for future platform lifecycle events
    (startup/shutdown) and is not currently emitted by any integration.
    """

    SYSTEM = "SYSTEM"
    TARGET = "TARGET"
    SCAN = "SCAN"
    INVENTORY = "INVENTORY"
    RISK = "RISK"
    AI = "AI"
    REPORT = "REPORT"
    AUTH = "AUTH"


class AuditEventType(str, enum.Enum):
    """Centralized, stable audit event taxonomy.

    Every persisted AuditEvent uses exactly one of these values. Event names
    are deliberately specific (resource + action) rather than generic, so
    they remain meaningful for future SOC review, SIEM forwarding, and
    filtering without re-deriving meaning from free-text descriptions.
    """

    TARGET_CREATED = "TARGET_CREATED"
    TARGET_UPDATED = "TARGET_UPDATED"
    TARGET_DELETED = "TARGET_DELETED"

    SCAN_CREATED = "SCAN_CREATED"
    SCAN_DELETED = "SCAN_DELETED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_CANCELLED = "SCAN_CANCELLED"

    AI_VULNERABILITY_DISCOVERY_COMPLETED = "AI_VULNERABILITY_DISCOVERY_COMPLETED"
    AI_VULNERABILITY_DISCOVERY_FAILED = "AI_VULNERABILITY_DISCOVERY_FAILED"

    INVENTORY_PROCESSED = "INVENTORY_PROCESSED"
    INVENTORY_PROCESSING_FAILED = "INVENTORY_PROCESSING_FAILED"

    RISK_CALCULATION_COMPLETED = "RISK_CALCULATION_COMPLETED"
    RISK_CALCULATION_FAILED = "RISK_CALCULATION_FAILED"

    AI_RECOMMENDATION_GENERATED = "AI_RECOMMENDATION_GENERATED"
    AI_RECOMMENDATION_FAILED = "AI_RECOMMENDATION_FAILED"

    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_GENERATION_FAILED = "REPORT_GENERATION_FAILED"
    REPORT_DOWNLOADED = "REPORT_DOWNLOADED"
    REPORT_DELETED = "REPORT_DELETED"

    USER_REGISTERED = "USER_REGISTERED"
    USER_LOGIN_SUCCEEDED = "USER_LOGIN_SUCCEEDED"
    USER_LOGIN_FAILED = "USER_LOGIN_FAILED"
    USER_LOGGED_OUT = "USER_LOGGED_OUT"
    USER_PASSWORD_CHANGED = "USER_PASSWORD_CHANGED"  # noqa: S105 # nosec B105
    REFRESH_TOKEN_REUSE_DETECTED = "REFRESH_TOKEN_REUSE_DETECTED"  # noqa: S105 # nosec B105
    API_KEY_SAVED = "API_KEY_SAVED"
    API_KEY_DELETED = "API_KEY_DELETED"


class AuditOutcome(str, enum.Enum):
    """Structured outcome of an audited business action.

    Only SUCCESS/FAILURE are used by the current integrations; no audited
    operation in this implementation has DENIED/PARTIAL/CANCELLED semantics.
    """

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class AuditActorType(str, enum.Enum):
    """Actor classification for an audit event.

    SYSTEM is internal orchestration with no HTTP caller (e.g. the
    background scan worker). ANONYMOUS is an HTTP request without a
    verified identity (e.g. a failed login). USER is an authenticated
    user; actor_id then holds the user's id.
    """

    SYSTEM = "SYSTEM"
    ANONYMOUS = "ANONYMOUS"
    USER = "USER"


class AuditResourceType(str, enum.Enum):
    """The kind of resource an audit event's resource_id refers to.

    Stored without a foreign key: audit evidence must survive deletion of
    the referenced business resource.
    """

    TARGET = "TARGET"
    SCAN = "SCAN"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    AI_RECOMMENDATION = "AI_RECOMMENDATION"
    REPORT = "REPORT"
    USER = "USER"
    API_KEY = "API_KEY"


class AIKeyProvider(str, enum.Enum):
    """AI providers a user can store a key for."""

    HUGGINGFACE = "huggingface"
