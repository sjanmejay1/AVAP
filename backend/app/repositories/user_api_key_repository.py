import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user_api_key import UserApiKey


class UserApiKeyRepository:
    """Persistence for encrypted provider keys. Flushes only; services commit."""

    def __init__(self, session: Session):
        self.session = session

    def get(self, user_id: uuid.UUID, provider: str) -> UserApiKey | None:
        stmt = select(UserApiKey).where(
            UserApiKey.user_id == user_id, UserApiKey.provider == provider
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_for_user(self, user_id: uuid.UUID) -> Sequence[UserApiKey]:
        stmt = (
            select(UserApiKey)
            .where(UserApiKey.user_id == user_id)
            .order_by(UserApiKey.provider)
        )
        return self.session.execute(stmt).scalars().all()

    def save(self, key: UserApiKey) -> UserApiKey:
        self.session.add(key)
        self.session.flush()
        return key

    def delete(self, key: UserApiKey) -> None:
        self.session.delete(key)
        self.session.flush()
