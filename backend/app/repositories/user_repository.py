import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictException
from app.models.user import User


class UserRepository:
    """Persistence for user accounts. Flushes only; services commit."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, user: User) -> User:
        """Add and flush a user.

        Raises:
            ConflictException: if the email is already registered.
        """
        try:
            self.session.add(user)
            self.session.flush()
            return user
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictException("This email cannot be registered.") from exc

    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self.session.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        return self.session.execute(stmt).scalar_one_or_none()

    def update(self, user: User) -> User:
        self.session.add(user)
        self.session.flush()
        return user
