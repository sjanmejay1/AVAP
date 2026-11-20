import uuid

from sqlalchemy import Enum, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import TargetType
from app.database.base import Base, TimestampMixin


class Target(Base, TimestampMixin):
    """Database model for scan targets.

    A target is an entity (IP, CIDR, Hostname) that can be scanned.
    Owned by one user; the normalized value is unique per user.
    """

    __tablename__ = "targets"

    # The actual string representation of the target
    # (e.g. "192.168.1.10", "example.com").
    # This must be stored in its normalized form.
    target: Mapped[str] = mapped_column(String(253), index=True, nullable=False)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Classification of the target to aid in validation and scanner configuration
    target_type: Mapped[TargetType] = mapped_column(Enum(TargetType), nullable=False)

    __table_args__ = (
        Index("ix_targets_created_at", "created_at"),
        UniqueConstraint("user_id", "target", name="uq_targets_user_target"),
    )
