import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.refresh_token import RefreshToken


class RefreshTokenRepository:
    """Persistence for hashed refresh tokens. Flushes only; services commit."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, token: RefreshToken) -> RefreshToken:
        self.session.add(token)
        self.session.flush()
        return token

    def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        return self.session.execute(stmt).scalar_one_or_none()

    def revoke(self, token: RefreshToken, revoked_at: datetime) -> None:
        token.revoked_at = revoked_at
        self.session.add(token)
        self.session.flush()

    def revoke_family(self, family_id: uuid.UUID, revoked_at: datetime) -> None:
        """Revoke every still-active token issued in one rotation chain."""
        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.family_id == family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=revoked_at)
        )
        self.session.execute(stmt)
        self.session.flush()

    def revoke_all_for_user(self, user_id: uuid.UUID, revoked_at: datetime) -> None:
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=revoked_at)
        )
        self.session.execute(stmt)
        self.session.flush()
