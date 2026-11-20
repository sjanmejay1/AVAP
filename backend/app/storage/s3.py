from collections.abc import Iterator
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from app.storage.base import ObjectStorage, StorageError, validate_key

_CHUNK_SIZE = 64 * 1024


class S3ObjectStorage(ObjectStorage):
    """Stores objects in one S3 (or S3-compatible) bucket.

    The boto3 client is injected: credentials come from boto3's standard
    chain (environment, shared config or an IAM role), never from AVAP's
    own settings, so they can't appear in config dumps or logs.
    """

    def __init__(self, client: Any, bucket: str, server_side_encryption: str | None):
        self._client = client
        self._bucket = bucket
        self._sse = server_side_encryption

    def put_file(self, key: str, path: Path, content_type: str) -> None:
        extra: dict[str, str] = {"ContentType": content_type}
        if self._sse:
            extra["ServerSideEncryption"] = self._sse
        try:
            self._client.upload_file(
                Filename=str(path),
                Bucket=self._bucket,
                Key=validate_key(key),
                ExtraArgs=extra,
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageError(f"S3 upload failed: {_error_code(exc)}") from exc

    def open_stream(self, key: str) -> Iterator[bytes]:
        try:
            response = self._client.get_object(
                Bucket=self._bucket, Key=validate_key(key)
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageError(f"S3 download failed: {_error_code(exc)}") from exc
        return response["Body"].iter_chunks(chunk_size=_CHUNK_SIZE)

    def delete(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=validate_key(key))
        except (BotoCoreError, ClientError) as exc:
            raise StorageError(f"S3 delete failed: {_error_code(exc)}") from exc


def _error_code(exc: Exception) -> str:
    """A short, credential-free description of a boto error."""
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", "ClientError"))
    return type(exc).__name__
