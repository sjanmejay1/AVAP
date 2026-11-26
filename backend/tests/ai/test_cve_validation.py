"""AI-inferred CVE IDs are untrusted: only well-formed IDs survive."""

import pytest

from app.schemas.ai import InferredVulnerabilityItem


def _item(cve: str | None) -> InferredVulnerabilityItem:
    return InferredVulnerabilityItem(
        host="10.0.0.1",
        port=80,
        protocol="tcp",
        name="Example",
        cve=cve,
        severity_rating="High",
        severity_score=7.5,
        description="Example finding.",
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2021-41773", "CVE-2021-41773"),
        ("cve-2021-123456", "CVE-2021-123456"),
        (" CVE-2023-0001 ", "CVE-2023-0001"),
        (None, None),
    ],
)
def test_well_formed_cve_is_kept_and_normalized(raw, expected):
    assert _item(raw).cve == expected


@pytest.mark.parametrize(
    "raw", ["CVE-21-1234", "CVE-2021-123", "N/A", "CVE-2021-1234x", "<b>CVE</b>"]
)
def test_malformed_cve_is_dropped_without_rejecting_the_finding(raw):
    item = _item(raw)
    assert item.cve is None
    assert item.name == "Example"
