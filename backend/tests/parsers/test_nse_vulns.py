"""Scanner-confirmed findings from Nmap NSE `vulns`-library output."""

import xml.etree.ElementTree as ET  # nosec B405 -- trusted test fixtures

from app.parsers.nse_vulns import extract_vulnerabilities

# Captured verbatim from Nmap 7.x (`--script http-slowloris-check
# --script-args vulns.showall`) against an httpd:2.4 container.
NOT_VULNERABLE = """<script id="http-slowloris-check" output="...">
<table key="CVE-2007-6750">
<elem key="title">Slowloris DOS attack</elem>
<elem key="state">NOT VULNERABLE</elem>
<table key="ids"><elem>CVE:CVE-2007-6750</elem></table>
<table key="refs">
<elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750</elem>
<elem>http://ha.ckers.org/slowloris/</elem>
</table>
</table>
</script>"""

# Same structure in a VULNERABLE state, plus the fields the vulns library
# documents (risk_factor, scores, description).
VULNERABLE = """<script id="ssl-heartbleed" output="...">
<table key="CVE-2014-0160">
<elem key="title">The Heartbleed Bug is a serious vulnerability</elem>
<elem key="state">VULNERABLE</elem>
<table key="ids"><elem>CVE:CVE-2014-0160</elem></table>
<elem key="risk_factor">High</elem>
<table key="scores"><elem key="CVSSv2">7.5</elem></table>
<table key="description"><elem>OpenSSL 1.0.1 through 1.0.1f leak memory.</elem></table>
<table key="refs"><elem>https://www.openssl.org/news/secadv_20140407.txt</elem></table>
</table>
</script>"""


def _script(xml: str) -> ET.Element:
    return ET.fromstring(xml)  # noqa: S314 -- trusted test fixture


def test_not_vulnerable_checks_are_ignored():
    assert extract_vulnerabilities(_script(NOT_VULNERABLE), 80, "tcp") == []


def test_vulnerable_check_becomes_a_finding():
    [finding] = extract_vulnerabilities(_script(VULNERABLE), 443, "tcp")
    assert finding.name == "The Heartbleed Bug is a serious vulnerability"
    assert finding.cve == "CVE-2014-0160"
    assert finding.severity_score == 7.5
    assert finding.severity_rating == "High"
    assert finding.port == 443
    assert finding.protocol == "tcp"
    assert finding.description.startswith("Nmap reported: VULNERABLE.")
    assert "leak memory" in finding.description
    assert finding.references == ["https://www.openssl.org/news/secadv_20140407.txt"]


def _state_variant(state: str, extra: str = "") -> ET.Element:
    return _script(
        NOT_VULNERABLE.replace(
            '<elem key="state">NOT VULNERABLE</elem>',
            f'<elem key="state">{state}</elem>{extra}',
        )
    )


def test_every_vulnerable_state_counts():
    for state in (
        "VULNERABLE",
        "LIKELY VULNERABLE",
        "VULNERABLE (Exploitable)",
        "VULNERABLE (DoS)",
    ):
        assert len(extract_vulnerabilities(_state_variant(state), 80, "tcp")) == 1


def test_rating_falls_back_to_risk_factor_then_state():
    [by_factor] = extract_vulnerabilities(
        _state_variant("VULNERABLE", '<elem key="risk_factor">HIGH</elem>'), 80, "tcp"
    )
    assert (by_factor.severity_rating, by_factor.severity_score) == ("High", 0.0)

    [confirmed] = extract_vulnerabilities(_state_variant("VULNERABLE"), 80, "tcp")
    [likely] = extract_vulnerabilities(_state_variant("LIKELY VULNERABLE"), 80, "tcp")
    assert confirmed.severity_rating == "Medium"
    assert likely.severity_rating == "Low"


def test_invalid_scores_and_missing_ids_are_tolerated():
    xml = """<script id="x"><table key="Some check">
    <elem key="state">VULNERABLE</elem>
    <table key="scores"><elem key="CVSSv2">not-a-number</elem></table>
    </table></script>"""
    [finding] = extract_vulnerabilities(_script(xml), None, None)
    assert finding.name == "Some check"
    assert finding.cve is None
    assert finding.severity_score == 0.0


def test_control_characters_are_stripped_from_remote_text():
    xml = """<script id="x"><table key="k">
    <elem key="title">Bad&#xd; title</elem>
    <elem key="state">VULNERABLE</elem>
    </table></script>"""
    [finding] = extract_vulnerabilities(_script(xml), 80, "tcp")
    assert "\r" not in finding.name
    assert finding.name == "Bad title"
