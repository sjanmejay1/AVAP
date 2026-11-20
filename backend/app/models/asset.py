import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.service import NetworkService


class Asset(Base, TimestampMixin):
    """Database model for discovered assets."""

    __tablename__ = "assets"

    # Inventory identity: IPv4 address, unique per owning user
    ipv4: Mapped[str] = mapped_column(String(45), index=True, nullable=False)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Optional hostname
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # Optional operating system details
    operating_system: Mapped[str | None] = mapped_column(String(253), nullable=True)

    # Relationships
    services: Mapped[list["NetworkService"]] = relationship(
        "NetworkService",
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_assets_created_at", "created_at"),
        UniqueConstraint("user_id", "ipv4", name="uq_assets_user_ipv4"),
    )
