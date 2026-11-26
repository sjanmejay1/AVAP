"""Cross-user isolation: one user's targets, scans, assets, reports and keys
are invisible to another user (404, never 403, so existence isn't leaked)."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.enums import ScanStatus, TargetType
from app.models.asset import Asset
from app.models.scan_job import ScanJob
from app.models.target import Target
from app.models.user_api_key import UserApiKey

PASSWORD = "correct horse battery"


def _register(client: TestClient, email: str) -> tuple[uuid.UUID, dict]:
    response = client.post(
        "/api/v1/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 201, response.text
    data = response.json()["data"]
    return uuid.UUID(data["user"]["id"]), {
        "Authorization": f"Bearer {data['access_token']}"
    }


@pytest.fixture
def two_users(anonymous_client, db_session):
    """Alice owns a target, a completed scan and an asset; Bob owns nothing."""
    alice_id, alice = _register(anonymous_client, "alice@example.test")
    _, bob = _register(anonymous_client, "bob@example.test")

    target = Target(user_id=alice_id, target="10.20.0.1", target_type=TargetType.IPV4)
    db_session.add(target)
    db_session.flush()
    scan = ScanJob(
        user_id=alice_id,
        target_id=target.id,
        scan_type="FULL",
        status=ScanStatus.COMPLETED,
    )
    asset = Asset(user_id=alice_id, ipv4="10.20.0.1")
    db_session.add_all([scan, asset])
    db_session.flush()
    return {"alice": alice, "bob": bob, "target": target, "scan": scan, "asset": asset}


def test_owner_sees_their_resources(anonymous_client, two_users):
    alice, target = two_users["alice"], two_users["target"]
    assert (
        anonymous_client.get(f"/api/v1/targets/{target.id}", headers=alice).status_code
        == 200
    )
    listed = anonymous_client.get("/api/v1/targets", headers=alice).json()["data"]
    assert listed["total"] == 1


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/targets/{target}",
        "/api/v1/scans/{scan}",
        "/api/v1/scans/{scan}/status",
        "/api/v1/assets/{asset}",
        "/api/v1/risk/scans/{scan}",
        "/api/v1/risk?scan_id={scan}",
        "/api/v1/risk/assets/{asset}",
    ],
)
def test_other_user_gets_404_for_reads(anonymous_client, two_users, path):
    url = path.format(
        target=two_users["target"].id,
        scan=two_users["scan"].id,
        asset=two_users["asset"].id,
    )
    response = anonymous_client.get(url, headers=two_users["bob"])
    assert response.status_code == 404


def test_other_user_lists_are_empty(anonymous_client, two_users):
    bob = two_users["bob"]
    for path, key in [
        ("/api/v1/targets", "total"),
        ("/api/v1/assets", "total"),
        ("/api/v1/vulnerabilities", "total"),
        ("/api/v1/reports", "total"),
    ]:
        response = anonymous_client.get(path, headers=bob)
        assert response.status_code == 200, path
        assert response.json()["data"][key] == 0, path
    scans = anonymous_client.get("/api/v1/scans", headers=bob).json()["data"]
    assert scans["total"] == 0


def test_other_user_cannot_modify_or_scan(anonymous_client, two_users):
    bob, target = two_users["bob"], two_users["target"]
    scan = two_users["scan"]
    assert (
        anonymous_client.put(
            f"/api/v1/targets/{target.id}", json={"target": "10.20.0.2"}, headers=bob
        ).status_code
        == 404
    )
    assert (
        anonymous_client.delete(f"/api/v1/targets/{target.id}", headers=bob).status_code
        == 404
    )
    assert (
        anonymous_client.delete(f"/api/v1/scans/{scan.id}", headers=bob).status_code
        == 404
    )
    assert (
        anonymous_client.post(
            "/api/v1/scans", json={"target_id": str(target.id)}, headers=bob
        ).status_code
        == 404
    )
    assert (
        anonymous_client.post(
            "/api/v1/reports", json={"scan_id": str(scan.id)}, headers=bob
        ).status_code
        == 404
    )


def test_two_users_can_register_the_same_target(anonymous_client, two_users):
    response = anonymous_client.post(
        "/api/v1/targets", json={"target": "10.20.0.1"}, headers=two_users["bob"]
    )
    assert response.status_code == 201


def test_api_keys_are_per_user_and_write_only(anonymous_client, two_users, db_session):
    alice, bob = two_users["alice"], two_users["bob"]
    secret = "hf_SECRETVALUE1234abcd"
    saved = anonymous_client.put(
        "/api/v1/users/me/api-keys/openrouter",
        json={"api_key": secret},
        headers=alice,
    )
    assert saved.status_code == 200
    assert secret not in saved.text
    assert saved.json()["data"]["last4"] == "abcd"

    stored = db_session.execute(select(UserApiKey)).scalar_one()
    assert secret not in stored.encrypted_key

    listed = anonymous_client.get("/api/v1/users/me/api-keys", headers=alice)
    assert secret not in listed.text
    assert len(listed.json()["data"]["keys"]) == 1
    bob_keys = anonymous_client.get("/api/v1/users/me/api-keys", headers=bob)
    assert bob_keys.json()["data"]["keys"] == []

    assert (
        anonymous_client.delete(
            "/api/v1/users/me/api-keys/openrouter", headers=bob
        ).status_code
        == 404
    )
    assert (
        anonymous_client.delete(
            "/api/v1/users/me/api-keys/openrouter", headers=alice
        ).status_code
        == 204
    )


def test_unknown_key_provider_is_rejected(anonymous_client, two_users):
    response = anonymous_client.put(
        "/api/v1/users/me/api-keys/openai",
        json={"api_key": "sk-something-long"},
        headers=two_users["alice"],
    )
    assert response.status_code == 422
    assert "sk-something-long" not in response.text
