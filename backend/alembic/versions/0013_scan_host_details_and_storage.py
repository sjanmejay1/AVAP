"""scan_host_details_and_storage

- scan_hosts: per-scan JSON snapshot of everything Nmap reported about a
  host (OS matches, MAC/vendor, uptime, traceroute, per-port CPEs and NSE
  script output). Previously parsed but discarded.
- scan_jobs.output_object_key: where the raw Nmap XML was stored (S3 or the
  local store).

Additive only; no data is removed.

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-20 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_hosts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Uuid(),
            sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.Uuid(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("scan_id", "asset_id", name="uq_scan_hosts_scan_asset"),
    )
    op.create_index(op.f("ix_scan_hosts_id"), "scan_hosts", ["id"])
    op.create_index(op.f("ix_scan_hosts_scan_id"), "scan_hosts", ["scan_id"])
    op.create_index(op.f("ix_scan_hosts_asset_id"), "scan_hosts", ["asset_id"])

    op.add_column(
        "scan_jobs",
        sa.Column("output_object_key", sa.String(length=1024), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_jobs", "output_object_key")
    op.drop_table("scan_hosts")
