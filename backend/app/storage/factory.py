import boto3
from botocore.config import Config

from app.core.config import Settings
from app.storage.base import ObjectStorage
from app.storage.local import LocalObjectStorage
from app.storage.s3 import S3ObjectStorage

_S3_TIMEOUT_SECONDS = 30


def build_object_storage(settings: Settings) -> ObjectStorage:
    """Return the configured storage backend."""
    if settings.storage_backend == "s3":
        client = boto3.client(
            "s3",
            region_name=settings.s3_region or None,
            endpoint_url=settings.s3_endpoint_url or None,
            config=Config(
                connect_timeout=_S3_TIMEOUT_SECONDS,
                read_timeout=_S3_TIMEOUT_SECONDS,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )
        return S3ObjectStorage(
            client=client,
            bucket=settings.s3_bucket,
            server_side_encryption=settings.s3_server_side_encryption or None,
        )
    return LocalObjectStorage(settings.storage_local_path)
