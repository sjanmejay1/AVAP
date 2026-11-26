"""Extract scanner-confirmed vulnerabilities from Nmap NSE structured output.

Scripts built on Nmap's `vulns` library emit one <table> per check inside
their <script> element. Observed in real Nmap XML:

    <table key="CVE-2007-6750">
      <elem key="title">Slowloris DOS attack</elem>
      <elem key="state">NOT VULNERABLE</elem>
      <table key="ids"><elem>CVE:CVE-2007-6750</elem></table>
      <table key="refs"><elem>https://...</elem></table>
    </table>

The library also documents `risk_factor`, `scores` and `description`
fields; they are read when present. Only VULNERABLE-family states become
findings; "NOT VULNERABLE" entries (emitted only with vulns.showall) never do.
"""

import re
import xml.etree.ElementTree as ET  # nosec B405 -- operates on an already-parsed tree

from app.parsers.models import ParsedVulnerability

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_MAX_NAME = 200
_MAX_DESCRIPTION = 3000
_MAX_REFERENCES = 10
_RISK_FACTORS = {"low": "Low", "medium": "Medium", "high": "High"}
# Preference order when a check reports several CVSS versions.
_SCORE_KEYS = ("CVSSv3", "CVSSv2", "CVSS")


def extract_vulnerabilities(
    script_node: ET.Element, port: int | None, protocol: str | None
) -> list[ParsedVulnerability]:
    """Every VULNERABLE / LIKELY VULNERABLE check reported by one script."""
    findings = []
    for check in script_node.findall("table"):
        state = _elem(check, "state")
        if not _is_vulnerable(state):
            continue
        findings.append(_to_vulnerability(check, state or "", port, protocol))
    return findings


def _is_vulnerable(state: str | None) -> bool:
    if not state:
        return False
    normalized = state.strip().upper()
    return normalized.startswith("VULNERABLE") or normalized == "LIKELY VULNERABLE"


def _to_vulnerability(
    check: ET.Element, state: str, port: int | None, protocol: str | None
) -> ParsedVulnerability:
    title = _elem(check, "title") or check.get("key") or "Nmap vulnerability check"
    score = _score(check)
    references = _list(check, "refs")[:_MAX_REFERENCES]
    description_parts = [f"Nmap reported: {state.strip()}."]
    description = "\n".join(_list(check, "description")) or _elem(check, "description")
    if description:
        description_parts.append(description.strip())
    return ParsedVulnerability(
        name=_clean(title)[:_MAX_NAME],
        severity_score=score if score is not None else 0.0,
        severity_rating=_rating(score, _elem(check, "risk_factor"), state),
        description=_clean(" ".join(description_parts))[:_MAX_DESCRIPTION],
        cve=_cve(check),
        port=port,
        protocol=protocol,
        references=[_clean(ref) for ref in references],
    )


def _cve(check: ET.Element) -> str | None:
    for identifier in _list(check, "ids"):
        match = _CVE_RE.search(identifier.upper())
        if match:
            return match.group(0)
    key_match = _CVE_RE.fullmatch((check.get("key") or "").upper())
    return key_match.group(0) if key_match else None


def _score(check: ET.Element) -> float | None:
    scores = _table(check, "scores")
    if scores is None:
        return None
    for key in _SCORE_KEYS:
        raw = _elem(scores, key)
        if raw is None:
            continue
        try:
            value = float(raw.split()[0])
        except (ValueError, IndexError):
            continue
        if 0.0 <= value <= 10.0:
            return value
    return None


def _rating(score: float | None, risk_factor: str | None, state: str) -> str:
    """CVSS v3 bands when a score exists, else the script's risk factor.

    With neither, a confirmed VULNERABLE result is rated Medium and a
    LIKELY VULNERABLE one Low.
    """
    if score is not None:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low" if score > 0.0 else "None"
    if risk_factor and risk_factor.strip().lower() in _RISK_FACTORS:
        return _RISK_FACTORS[risk_factor.strip().lower()]
    return "Low" if state.strip().upper() == "LIKELY VULNERABLE" else "Medium"


def _elem(node: ET.Element, key: str) -> str | None:
    for child in node.findall("elem"):
        if child.get("key") == key:
            return child.text
    return None


def _table(node: ET.Element, key: str) -> ET.Element | None:
    for child in node.findall("table"):
        if child.get("key") == key:
            return child
    return None


def _list(node: ET.Element, key: str) -> list[str]:
    table = _table(node, key)
    if table is None:
        return []
    return [elem.text.strip() for elem in table.findall("elem") if elem.text]


def _clean(text: str) -> str:
    """Strip control characters from remote-supplied text."""
    return re.sub(r"[\x00-\x08\x0b-\x1f]", "", text).strip()
