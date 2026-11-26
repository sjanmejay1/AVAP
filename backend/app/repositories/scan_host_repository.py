import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan_host import ScanHost


class ScanHostRepository:
    """Persistence for per-scan host snapshots. Flushes only; services commit."""

    def __init__(self, session: Session):
        self.session = session

    def upsert(
        self, scan_id: uuid.UUID, asset_id: uuid.UUID, details: dict[str, Any]
    ) -> ScanHost:
        stmt = select(ScanHost).where(
            ScanHost.scan_id == scan_id, ScanHost.asset_id == asset_id
        )
        record = self.session.execute(stmt).scalar_one_or_none()
        if record is None:
            record = ScanHost(scan_id=scan_id, asset_id=asset_id, details=details)
            self.session.add(record)
        else:
            record.details = details
        self.session.flush()
        return record

    def list_for_scan(self, scan_id: uuid.UUID) -> Sequence[ScanHost]:
        stmt = (
            select(ScanHost)
            .where(ScanHost.scan_id == scan_id)
            .order_by(ScanHost.created_at)
        )
        return self.session.execute(stmt).scalars().all()
