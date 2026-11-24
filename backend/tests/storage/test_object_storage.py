"""Local and S3 object storage adapters."""

import uuid
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError

from app.core.config import Settings
from app.storage.base import StorageError, raw_output_key, validate_key
from app.storage.factory import build_object_storage
from app.storage.local import LocalObjectStorage
from app.storage.s3 import S3ObjectStorage


def _file(tmp_path: Path, content: bytes = b"<nmaprun/>") -> Path:
    path = tmp_path / "source.xml"
    path.write_bytes(content)
    return path


def test_raw_output_key_is_scoped_by_user_and_scan():
    user_id, scan_id = uuid.uuid4(), uuid.uuid4()
    assert raw_output_key(user_id, scan_id) == f"scans/{user_id}/{scan_id}/nmap.xml"


@pytest.mark.parametrize(
    "key", ["../etc/passwd", "scans/../../x", "/abs/path", "Scans/UPPER", "", "a b"]
)
def test_unsafe_keys_are_rejected(key):
    with pytest.raises(StorageError):
        validate_key(key)


class TestLocalObjectStorage:
    def test_put_open_delete_round_trip(self, tmp_path):
        store = LocalObjectStorage(tmp_path / "store")
        store.put_file("scans/a/b/nmap.xml", _file(tmp_path), "application/xml")

        assert b"".join(store.open_stream("scans/a/b/nmap.xml")) == b"<nmaprun/>"

        store.delete("scans/a/b/nmap.xml")
        with pytest.raises(StorageError):
            store.open_stream("scans/a/b/nmap.xml")

    def test_missing_object_and_repeat_delete(self, tmp_path):
        store = LocalObjectStorage(tmp_path)
        with pytest.raises(StorageError):
            store.open_stream("scans/missing.xml")
        store.delete("scans/missing.xml")

    def test_traversal_key_never_writes_outside_root(self, tmp_path):
        store = LocalObjectStorage(tmp_path / "store")
        with pytest.raises(StorageError):
            store.put_file("../escape.xml", _file(tmp_path), "application/xml")
        assert not (tmp_path / "escape.xml").exists()


class _FakeBody:
    def __init__(self, data: bytes):
        self._data = data

    def iter_chunks(self, chunk_size: int):
        yield self._data


class _FakeS3Client:
    def __init__(self, error: ClientError | None = None):
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.objects: dict[str, bytes] = {}
        self._error = error

    def _maybe_fail(self):
        if self._error:
            raise self._error

    def upload_file(self, **kwargs):
        self._maybe_fail()
        self.calls.append(("upload_file", kwargs))
        self.objects[kwargs["Key"]] = Path(kwargs["Filename"]).read_bytes()

    def get_object(self, **kwargs):
        self._maybe_fail()
        return {"Body": _FakeBody(self.objects[kwargs["Key"]])}

    def delete_object(self, **kwargs):
        self._maybe_fail()
        self.calls.append(("delete_object", kwargs))


def _client_error(code: str = "AccessDenied") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "secret detail"}}, "Op")


class TestS3ObjectStorage:
    def test_upload_sets_encryption_and_content_type(self, tmp_path):
        client = _FakeS3Client()
        store = S3ObjectStorage(client, "avap-bucket", "AES256")
        store.put_file("scans/u/s/nmap.xml", _file(tmp_path), "application/xml")

        name, kwargs = client.calls[0]
        assert name == "upload_file"
        assert kwargs["Bucket"] == "avap-bucket"
        assert kwargs["ExtraArgs"] == {
            "ContentType": "application/xml",
            "ServerSideEncryption": "AES256",
        }
        assert b"".join(store.open_stream("scans/u/s/nmap.xml")) == b"<nmaprun/>"

    def test_encryption_header_can_be_disabled(self, tmp_path):
        client = _FakeS3Client()
        S3ObjectStorage(client, "b", None).put_file(
            "scans/k.xml", _file(tmp_path), "application/xml"
        )
        assert "ServerSideEncryption" not in client.calls[0][1]["ExtraArgs"]

    def test_errors_become_storage_errors_without_detail(self, tmp_path):
        store = S3ObjectStorage(_FakeS3Client(error=_client_error()), "b", None)
        with pytest.raises(StorageError) as exc:
            store.put_file("scans/k.xml", _file(tmp_path), "application/xml")
        assert "AccessDenied" in str(exc.value)
        assert "secret detail" not in str(exc.value)
        with pytest.raises(StorageError):
            store.open_stream("scans/k.xml")
        with pytest.raises(StorageError):
            store.delete("scans/k.xml")


class TestStorageSettings:
    def test_local_directory_defaults_to_its_own_storage_folder(self, monkeypatch):
        # conftest points the suite at a temp dir; clear it to see the default.
        monkeypatch.delenv("STORAGE_LOCAL_DIRECTORY", raising=False)
        settings = Settings(_env_file=None)
        assert settings.storage_local_path == Path("storage")

    def test_local_is_the_default(self, tmp_path):
        settings = Settings(_env_file=None, storage_local_directory=str(tmp_path))
        assert isinstance(build_object_storage(settings), LocalObjectStorage)

    def test_s3_requires_a_bucket(self):
        settings = Settings(_env_file=None, storage_backend="s3")
        with pytest.raises(ValueError, match="S3_BUCKET"):
            settings.validate_storage_settings()

    def test_s3_backend_is_built_with_bucket(self):
        settings = Settings(
            _env_file=None,
            storage_backend="s3",
            s3_bucket="avap-bucket",
            s3_region="us-east-1",
        )
        settings.validate_storage_settings()
        assert isinstance(build_object_storage(settings), S3ObjectStorage)

    @pytest.mark.parametrize(
        ("field", "value"),
        [("storage_backend", "ftp"), ("s3_endpoint_url", "file:///etc")],
    )
    def test_invalid_storage_settings_are_rejected(self, field, value):
        with pytest.raises(ValueError):
            Settings(_env_file=None, **{field: value})
