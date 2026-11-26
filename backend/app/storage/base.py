import re
import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

# Keys are generated server-side only; this pattern is a second line of
# defense against path traversal or odd characters reaching a backend.
_KEY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9/_.-]{0,1000}$")


class StorageError(Exception):
    """A storage backend failed. The message never contains credentials."""


def raw_output_key(user_id: uuid.UUID, scan_id: uuid.UUID) -> str:
    """The object key for a scan's raw Nmap XML."""
    return f"scans/{user_id}/{scan_id}/nmap.xml"


def validate_key(key: str) -> str:
    """Reject keys that are not plain, relative, lower-case paths."""
    if not _KEY_PATTERN.fullmatch(key) or ".." in key.split("/"):
        raise StorageError("Invalid object key.")
    return key


class ObjectStorage(ABC):
    """Where raw scan output lives after a scan finishes."""

    @abstractmethod
    def put_file(self, key: str, path: Path, content_type: str) -> None:
        """Upload a local file under `key`, replacing any existing object."""

    @abstractmethod
    def open_stream(self, key: str) -> Iterator[bytes]:
        """Stream an object's bytes.

        Raises:
            StorageError: if it doesn't exist or can't be read.
        """

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete an object. Deleting a missing object is not an error."""
