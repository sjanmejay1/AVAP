"""users_auth_and_ownership

Adds accounts and per-user ownership (owner decision 2026-11-20, see
audit/final-goal-plan.md):

- users, refresh_tokens (hashed, rotating) and user_api_keys (Fernet
  ciphertext) tables.
- user_id on targets, assets and scan_jobs. Target and asset values become
  unique per user instead of globally.
- New audit enum values for authentication and key-vault events.

Owner chose "start fresh": all scan, inventory, risk, AI and report rows are
deleted before the NOT NULL ownership columns are added, because they have
no owner. audit_events are kept (append-only, protected by a trigger).
Report PDF files on disk are not removed by this migration.

Downgrade restores the previous schema but cannot restore deleted rows, and
leaves the added Postgres enum values in place (unused values are harmless).

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-20 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Children first, so the deletes never depend on ON DELETE CASCADE.
_TABLES_CLEARED_IN_ORDER = (
    "reports",
    "ai_recommendations",
    "risk_assessments",
    "scan_findings",
    "services",
    "assets",
    "scan_jobs",
    "targets",
    "vulnerabilities",
)

_NEW_ENUM_VALUES = {
    "auditeventtype": (
        "USER_REGISTERED",
        "USER_LOGIN_SUCCEEDED",
        "USER_LOGIN_FAILED",
        "USER_LOGGED_OUT",
        "USER_PASSWORD_CHANGED",
        "REFRESH_TOKEN_REUSE_DETECTED",
        "API_KEY_SAVED",
        "API_KEY_DELETED",
    ),
    "auditeventcategory": ("AUTH",),
    "auditactortype": ("USER",),
    "auditresourcetype": ("USER", "API_KEY"),
}


def _timestamps() -> list[sa.Column]:
    return [
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
    ]


def _owner_column() -> sa.Column:
    return sa.Column(
        "user_id",
        sa.Uuid(),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )


def upgrade() -> None:
    with op.get_context().autocommit_block():
        for enum_name, values in _NEW_ENUM_VALUES.items():
            for value in values:
                op.execute(
                    f"ALTER TYPE {enum_name} ADD VALUE IF NOT EXISTS '{value}'"
                )

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.true(), nullable=False
        ),
        *_timestamps(),
    )
    op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _owner_column(),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
    )
    op.create_index(op.f("ix_refresh_tokens_id"), "refresh_tokens", ["id"])
    op.create_index(op.f("ix_refresh_tokens_user_id"), "refresh_tokens", ["user_id"])
    op.create_index(
        op.f("ix_refresh_tokens_family_id"), "refresh_tokens", ["family_id"]
    )
    op.create_index(
        op.f("ix_refresh_tokens_token_hash"),
        "refresh_tokens",
        ["token_hash"],
        unique=True,
    )

    op.create_table(
        "user_api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        _owner_column(),
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("encrypted_key", sa.Text(), nullable=False),
        sa.Column("last4", sa.String(length=4), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint(
            "user_id", "provider", name="uq_user_api_keys_user_provider"
        ),
    )
    op.create_index(op.f("ix_user_api_keys_id"), "user_api_keys", ["id"])
    op.create_index(op.f("ix_user_api_keys_user_id"), "user_api_keys", ["user_id"])

    for table in _TABLES_CLEARED_IN_ORDER:
        op.execute(sa.text(f"DELETE FROM {table}"))  # noqa: S608 -- fixed names

    op.drop_index(op.f("ix_targets_target"), table_name="targets")
    op.create_index(op.f("ix_targets_target"), "targets", ["target"])
    op.drop_index(op.f("ix_assets_ipv4"), table_name="assets")
    op.create_index(op.f("ix_assets_ipv4"), "assets", ["ipv4"])

    for table in ("targets", "assets", "scan_jobs"):
        op.add_column(table, _owner_column())
        op.create_index(op.f(f"ix_{table}_user_id"), table, ["user_id"])

    op.create_unique_constraint(
        "uq_targets_user_target", "targets", ["user_id", "target"]
    )
    op.create_unique_constraint("uq_assets_user_ipv4", "assets", ["user_id", "ipv4"])


def downgrade() -> None:
    op.drop_constraint("uq_assets_user_ipv4", "assets", type_="unique")
    op.drop_constraint("uq_targets_user_target", "targets", type_="unique")
    for table in ("scan_jobs", "assets", "targets"):
        op.drop_index(op.f(f"ix_{table}_user_id"), table_name=table)
        op.drop_column(table, "user_id")

    # Rows from different users may now collide on the old global uniques.
    for table in _TABLES_CLEARED_IN_ORDER:
        op.execute(sa.text(f"DELETE FROM {table}"))  # noqa: S608 -- fixed names

    op.drop_index(op.f("ix_assets_ipv4"), table_name="assets")
    op.create_index(op.f("ix_assets_ipv4"), "assets", ["ipv4"], unique=True)
    op.drop_index(op.f("ix_targets_target"), table_name="targets")
    op.create_index(op.f("ix_targets_target"), "targets", ["target"], unique=True)

    op.drop_table("user_api_keys")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
