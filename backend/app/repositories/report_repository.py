import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.report import Report
from app.models.scan_job import ScanJob


class ReportRepository:
    """Repository for managing Report metadata database operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, report: Report) -> Report:
        """Add a new report record to the session without committing."""
        self.session.add(report)
        self.session.flush()
        return report

    def get_owned(self, report_id: uuid.UUID, user_id: uuid.UUID) -> Report | None:
        """Retrieve a report whose scan belongs to the user."""
        stmt = (
            select(Report)
            .join(ScanJob, Report.scan_id == ScanJob.id)
            .where(Report.id == report_id, ScanJob.user_id == user_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_all(
        self,
        user_id: uuid.UUID,
        skip: int = 0,
        limit: int = 50,
        scan_id: uuid.UUID | None = None,
    ) -> tuple[Sequence[Report], int]:
        """Retrieve the user's reports, optionally filtered to one scan."""
        owned = Report.scan_id.in_(select(ScanJob.id).where(ScanJob.user_id == user_id))
        stmt = select(Report).where(owned)
        count_stmt = select(func.count(Report.id)).where(owned)

        if scan_id is not None:
            stmt = stmt.where(Report.scan_id == scan_id)
            count_stmt = count_stmt.where(Report.scan_id == scan_id)

        total = self.session.execute(count_stmt).scalar() or 0
        stmt = stmt.offset(skip).limit(limit).order_by(Report.generated_at.desc())
        items = self.session.execute(stmt).scalars().all()

        return items, total

    def get_latest_by_scan(self, scan_id: uuid.UUID) -> Report | None:
        """Retrieve the most recently generated report for a scan."""
        stmt = (
            select(Report)
            .where(Report.scan_id == scan_id)
            .order_by(Report.generated_at.desc())
        )
        return self.session.execute(stmt).scalars().first()

    def delete(self, report: Report) -> None:
        """Delete a report record from the session without committing."""
        self.session.delete(report)
        self.session.flush()
