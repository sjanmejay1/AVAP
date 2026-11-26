"""Public-deployment hardening: the secret-gated client IP behind a trusted
reverse proxy, and the optional scan-target allowlist."""

import uuid
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.core.enums import AuditEventType, ScannerType, ScanProfile
from app.core.exceptions import ValidationException
from app.core.security import (
    ALLOWLIST_REJECTION_MESSAGE,
    CLIENT_IP_HEADER,
    PROXY_SECRET_HEADER,
    is_target_allowed,
    resolve_client_ip,
)
from app.models.audit_event import AuditEvent
from app.scanners.execution_validator import ExecutionValidator
from app.schemas.target import CreateTargetRequest, UpdateTargetRequest
from app.services.target_service import TargetService
from tests.auth_helpers import TEST_USER_ID

SECRET = "s" * 40


# --- resolve_client_ip ------------------------------------------------------


def test_proxy_ip_used_when_secret_matches():
    assert resolve_client_ip("10.0.0.2", "198.51.100.7", SECRET, SECRET) == (
        "198.51.100.7"
    )


def test_proxy_ipv6_is_normalized():
    assert resolve_client_ip("10.0.0.2", "2001:DB8::1", SECRET, SECRET) == "2001:db8::1"


@pytest.mark.parametrize(
    ("forwarded", "presented", "expected_secret"),
    [
        ("198.51.100.7", SECRET, ""),  # feature off
        ("198.51.100.7", None, SECRET),  # no secret presented
        ("198.51.100.7", "wrong" * 8, SECRET),  # wrong secret
        ("198.51.100.7", SECRET[:-1], SECRET),  # prefix of the secret
        (None, SECRET, SECRET),  # no client IP header
        ("not-an-ip", SECRET, SECRET),
        ("198.51.100.7, 203.0.113.1", SECRET, SECRET),  # a list, not one IP
        ("1" * 46, SECRET, SECRET),  # oversized
    ],
)
def test_peer_used_otherwise(forwarded, presented, expected_secret):
    assert resolve_client_ip("10.0.0.2", forwarded, presented, expected_secret) == (
        "10.0.0.2"
    )


def test_settings_reject_short_proxy_secret():
    settings = Settings(
        _env_file=None,
        jwt_secret_key="j" * 64,
        app_encryption_key="dGVzdC1vbmx5LWZlcm5ldC1rZXktMzItYnl0ZXMhISE=",
        trusted_proxy_secret="too-short",
    )
    with pytest.raises(ValueError, match="TRUSTED_PROXY_SECRET"):
        settings.validate_security_settings()


def _source_ip_of_latest_target_event(db_session) -> str | None:
    stmt = (
        select(AuditEvent.source_ip)
        .where(AuditEvent.event_type == AuditEventType.TARGET_CREATED)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .limit(1)
    )
    return db_session.execute(stmt).scalar_one()


def test_api_records_proxy_ip_only_with_the_secret(
    client: TestClient, db_session, monkeypatch
):
    monkeypatch.setenv("TRUSTED_PROXY_SECRET", SECRET)
    get_settings.cache_clear()  # the client fixture already cached settings

    trusted = client.post(
        "/api/v1/targets",
        json={"target": "203.0.113.230"},
        headers={PROXY_SECRET_HEADER: SECRET, CLIENT_IP_HEADER: "198.51.100.7"},
    )
    assert trusted.status_code == 201
    assert _source_ip_of_latest_target_event(db_session) == "198.51.100.7"

    spoofed = client.post(
        "/api/v1/targets",
        json={"target": "203.0.113.231"},
        headers={PROXY_SECRET_HEADER: "x" * 40, CLIENT_IP_HEADER: "198.51.100.8"},
    )
    assert spoofed.status_code == 201
    assert _source_ip_of_latest_target_event(db_session) != "198.51.100.8"


# --- is_target_allowed ------------------------------------------------------

ALLOWLIST = ["scanme.nmap.org", "demo-web", "203.0.113.10", "10.20.0.0/24"]


@pytest.mark.parametrize(
    "target",
    [
        "scanme.nmap.org",
        "SCANME.nmap.org.",
        "demo-web",
        "203.0.113.10",
        "10.20.0.5",
        "10.20.0.128/25",
        "10.20.0.0/24",
    ],
)
def test_allowlisted_targets_pass(target):
    assert is_target_allowed(target, ALLOWLIST) is True


@pytest.mark.parametrize(
    "target",
    [
        "nmap.org",
        "evil.scanme.nmap.org",
        "db",
        "203.0.113.11",
        "10.20.1.5",
        "10.20.0.0/23",  # wider than the entry
        "169.254.169.254",
        "45.33.32.156",  # scanme's IP: a hostname entry never authorizes IPs
    ],
)
def test_other_targets_are_refused(target):
    assert is_target_allowed(target, ALLOWLIST) is False


def test_empty_allowlist_allows_everything():
    assert is_target_allowed("198.51.100.1", []) is True


def test_settings_normalize_allowlist_entries():
    settings = Settings(
        _env_file=None, scan_target_allowlist=" Scanme.Nmap.org. , 10.0.0.0/24,,"
    )
    assert settings.scan_target_allowlist_entries == ["scanme.nmap.org", "10.0.0.0/24"]


@pytest.mark.parametrize("bad", ["not a host", "10.0.0.0/33", "127.0.0.1", "a;b"])
def test_settings_reject_invalid_allowlist_entry(bad):
    with pytest.raises(ValidationError, match="SCAN_TARGET_ALLOWLIST"):
        Settings(_env_file=None, scan_target_allowlist=f"scanme.nmap.org,{bad}")


# --- enforcement points -----------------------------------------------------


def _target_service() -> tuple[TargetService, Mock]:
    repo = Mock()
    repo.get_by_value.return_value = None
    return TargetService(repository=repo, audit_service=Mock()), repo


def test_create_target_refuses_target_off_the_allowlist(monkeypatch):
    monkeypatch.setenv("SCAN_TARGET_ALLOWLIST", "scanme.nmap.org")
    service, repo = _target_service()
    with pytest.raises(ValidationException, match="approved list"):
        service.create_target(TEST_USER_ID, CreateTargetRequest(target="example.com"))
    repo.create.assert_not_called()


def test_create_target_accepts_allowlisted_target(monkeypatch):
    monkeypatch.setenv("SCAN_TARGET_ALLOWLIST", "scanme.nmap.org")
    service, repo = _target_service()
    service.create_target(TEST_USER_ID, CreateTargetRequest(target="scanme.nmap.org"))
    repo.create.assert_called_once()


def test_update_target_refuses_target_off_the_allowlist(monkeypatch):
    monkeypatch.setenv("SCAN_TARGET_ALLOWLIST", "scanme.nmap.org")
    service, repo = _target_service()
    with pytest.raises(ValidationException, match="approved list"):
        service.update_target(
            TEST_USER_ID, uuid.uuid4(), UpdateTargetRequest(target="198.51.100.1")
        )
    repo.update.assert_not_called()


def test_execution_validator_refuses_target_off_the_allowlist(monkeypatch):
    monkeypatch.setenv("SCAN_TARGET_ALLOWLIST", "demo-web")
    with pytest.raises(ValidationException, match="approved list"):
        ExecutionValidator().validate_request(
            "demo-cache", ScannerType.NMAP, ScanProfile.QUICK
        )


def test_api_allowlist_error_reveals_nothing(client: TestClient, monkeypatch):
    monkeypatch.setenv("SCAN_TARGET_ALLOWLIST", "scanme.nmap.org,203.0.113.10")
    get_settings.cache_clear()  # the client fixture already cached settings
    response = client.post("/api/v1/targets", json={"target": "example.com"})
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["message"] == ALLOWLIST_REJECTION_MESSAGE
    assert "scanme" not in response.text
