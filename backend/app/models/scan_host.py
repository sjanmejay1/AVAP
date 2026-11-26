import uuid
from typing import Any

from sqlalchemy import JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin
from app.models.asset import Asset


class ScanHost(Base, TimestampMixin):
    """What one scan saw on one host (OS matches, MAC, uptime, traceroute,
    per-port scripts).

    Assets are reused across scans, so this snapshot keeps each scan's view
    intact even after later scans update the asset.
    """

    __tablename__ = "scan_hosts"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    asset: Mapped[Asset] = relationship(lazy="joined")

    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", name="uq_scan_hosts_scan_asset"),
    )
