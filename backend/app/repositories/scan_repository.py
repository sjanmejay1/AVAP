import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.enums import ScanStatus
from app.models.scan_job import ScanJob


class ScanRepository:
    """Repository for managing scan job persistence."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, scan_job: ScanJob) -> ScanJob:
        """Add a new scan job to the session and flush, without committing."""
        self.session.add(scan_job)
        self.session.flush()
        return scan_job

    def get_by_id(self, scan_id: uuid.UUID) -> ScanJob | None:
        """Retrieve a scan job by its ID regardless of owner.

        For internal orchestration only (background worker, pipelines that
        already hold a scan id). User-facing paths use get_owned().
        """
        stmt = select(ScanJob).where(ScanJob.id == scan_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_owned(self, scan_id: uuid.UUID, user_id: uuid.UUID) -> ScanJob | None:
        """Retrieve one of the user's scan jobs by its ID."""
        stmt = select(ScanJob).where(ScanJob.id == scan_id, ScanJob.user_id == user_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_all(
        self,
        user_id: uuid.UUID,
        skip: int = 0,
        limit: int = 100,
        target_id: uuid.UUID | None = None,
    ) -> Sequence[ScanJob]:
        """Retrieve the user's scan jobs, optionally scoped to one target."""
        stmt = (
            select(ScanJob)
            .where(ScanJob.user_id == user_id)
            .order_by(ScanJob.created_at.desc())
        )
        if target_id is not None:
            stmt = stmt.where(ScanJob.target_id == target_id)
        stmt = stmt.offset(skip).limit(limit)
        return self.session.execute(stmt).scalars().all()

    def count(self, user_id: uuid.UUID, target_id: uuid.UUID | None = None) -> int:
        """Count the user's scan jobs, optionally scoped to one target."""
        stmt = select(func.count(ScanJob.id)).where(ScanJob.user_id == user_id)
        if target_id is not None:
            stmt = stmt.where(ScanJob.target_id == target_id)
        return self.session.execute(stmt).scalar() or 0

    def update(self, scan_job: ScanJob) -> ScanJob:
        """Flush pending changes to an existing scan job, without committing."""
        self.session.flush()
        return scan_job

    def delete(self, scan_job: ScanJob) -> None:
        """Mark a scan job for deletion and flush, without committing."""
        self.session.delete(scan_job)
        self.session.flush()

    def get_running_scans_for_target(self, target_id: uuid.UUID) -> Sequence[ScanJob]:
        """Retrieve all active (not yet finished) scans for a specific target.

        Includes PENDING alongside RUNNING: a scan job is created as
        PENDING and only flips to RUNNING once its background execution
        thread picks it up, so checking RUNNING alone would let a second
        scan slip in during that brief window.
        """
        stmt = select(ScanJob).where(
            ScanJob.target_id == target_id,
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
        return self.session.execute(stmt).scalars().all()

    def get_active_scans(self) -> Sequence[ScanJob]:
        """Return all scan jobs globally that are currently PENDING or RUNNING."""
        stmt = select(ScanJob).where(
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING])
        )
        return self.session.execute(stmt).scalars().all()

    def count_active_scans(self) -> int:
        """Count all scan jobs globally that are currently PENDING or RUNNING."""
        stmt = select(func.count(ScanJob.id)).where(
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING])
        )
        return self.session.execute(stmt).scalar() or 0
