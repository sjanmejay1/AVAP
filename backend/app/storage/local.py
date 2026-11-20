import shutil
from collections.abc import Iterator
from pathlib import Path

from app.storage.base import ObjectStorage, StorageError, validate_key

_CHUNK_SIZE = 64 * 1024


class LocalObjectStorage(ObjectStorage):
    """Stores objects as files under one root directory."""

    def __init__(self, root: Path):
        self._root = root.resolve()

    def _path_for(self, key: str) -> Path:
        candidate = (self._root / validate_key(key)).resolve()
        if not candidate.is_relative_to(self._root):
            raise StorageError("Invalid object key.")
        return candidate

    def put_file(self, key: str, path: Path, content_type: str) -> None:
        destination = self._path_for(key)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            tmp = destination.with_suffix(destination.suffix + ".tmp")
            shutil.copyfile(path, tmp)
            tmp.replace(destination)
        except OSError as exc:
            raise StorageError("Could not write object to local storage.") from exc

    def open_stream(self, key: str) -> Iterator[bytes]:
        source = self._path_for(key)
        if not source.is_file():
            raise StorageError("Object not found.")
        return self._read_chunks(source)

    @staticmethod
    def _read_chunks(source: Path) -> Iterator[bytes]:
        with source.open("rb") as handle:
            while chunk := handle.read(_CHUNK_SIZE):
                yield chunk

    def delete(self, key: str) -> None:
        try:
            self._path_for(key).unlink(missing_ok=True)
        except OSError as exc:
            raise StorageError("Could not delete object from local storage.") from exc
