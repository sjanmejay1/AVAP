"""Security hardening: CIDR scope limit, config bounds, and log formatting."""

import json
import logging
import uuid
from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.enums import ScannerType, ScanProfile
from app.core.exceptions import ValidationException
from app.core.logging import JSONFormatter
from app.core.security import cidr_exceeds_scope
from app.scanners.execution_validator import ExecutionValidator
from app.schemas.target import CreateTargetRequest, UpdateTargetRequest
from app.services.target_service import TargetService
from tests.auth_helpers import TEST_USER_ID


@pytest.mark.parametrize(
    ("cidr", "min_prefix", "expected"),
    [
        ("0.0.0.0/0", 16, True),
        ("10.0.0.0/8", 16, True),
        ("10.0.0.0/16", 16, False),
        ("192.168.1.0/24", 16, False),
        ("10.0.0.0/8", 8, False),
    ],
)
def test_cidr_exceeds_scope(cidr, min_prefix, expected):
    assert cidr_exceeds_scope(cidr, min_prefix) is expected


def _target_service() -> tuple[TargetService, Mock]:
    repo = Mock()
    repo.get_by_value.return_value = None
    return TargetService(repository=repo, audit_service=Mock()), repo


def test_create_target_rejects_cidr_broader_than_limit():
    service, repo = _target_service()
    with pytest.raises(ValidationException, match="too broad"):
        service.create_target(TEST_USER_ID, CreateTargetRequest(target="0.0.0.0/0"))
    repo.create.assert_not_called()


def test_create_target_accepts_cidr_at_the_limit():
    service, repo = _target_service()
    service.create_target(TEST_USER_ID, CreateTargetRequest(target="172.16.0.0/16"))
    repo.create.assert_called_once()


def test_update_target_rejects_cidr_broader_than_limit():
    service, repo = _target_service()
    with pytest.raises(ValidationException, match="too broad"):
        service.update_target(
            TEST_USER_ID, uuid.uuid4(), UpdateTargetRequest(target="10.0.0.0/8")
        )
    repo.update.assert_not_called()


def test_cidr_limit_is_configurable(monkeypatch):
    monkeypatch.setenv("MIN_CIDR_PREFIX_LENGTH", "8")
    service, repo = _target_service()
    service.create_target(TEST_USER_ID, CreateTargetRequest(target="10.0.0.0/8"))
    repo.create.assert_called_once()


def test_execution_validator_rejects_cidr_broader_than_limit():
    with pytest.raises(ValidationException, match="too broad"):
        ExecutionValidator().validate_request(
            "10.0.0.0/8", ScannerType.NMAP, ScanProfile.QUICK
        )


@pytest.mark.parametrize(
    "field",
    ["max_concurrent_scans", "scan_timeout", "full_scan_timeout", "ai_max_tokens"],
)
def test_settings_reject_non_positive_limits(field):
    overrides: dict[str, Any] = {field: 0}
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **overrides)


def test_settings_reject_out_of_range_cidr_prefix():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, min_cidr_prefix_length=33)


def test_json_formatter_survives_non_serializable_context():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "msg", None, None)
    record.context = {"error": ValueError("boom")}

    payload = json.loads(JSONFormatter().format(record))

    assert payload["context"]["error"] == "boom"
