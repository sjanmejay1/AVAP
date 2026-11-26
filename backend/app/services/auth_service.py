"""Account registration, login, token rotation and password changes."""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.audit.context import ActorContext, AuditContext
from app.auth.passwords import (
    burn_verification_time,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.auth.throttle import SlidingWindowThrottle
from app.auth.tokens import (
    InvalidAccessTokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from app.core.config import Settings
from app.core.enums import (
    AuditEventCategory,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
)
from app.core.exceptions import (
    AuthenticationException,
    TooManyRequestsException,
    ValidationException,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

_INVALID_CREDENTIALS = "Invalid email or password."
_SESSION_EXPIRED = "Your session has expired. Please log in again."
_IP_FAILURE_MULTIPLIER = 4


@dataclass(frozen=True)
class IssuedTokens:
    """A new access token plus the raw refresh token for the cookie."""

    user: User
    access_token: str
    refresh_token: str
    access_expires_in: int


class AuthThrottles:
    """Process-wide throttles shared by every AuthService instance."""

    def __init__(self, settings: Settings):
        window = settings.login_failure_window_minutes * 60
        self.login_by_account = SlidingWindowThrottle(
            settings.login_max_failures, window
        )
        self.login_by_ip = SlidingWindowThrottle(
            settings.login_max_failures * _IP_FAILURE_MULTIPLIER, window
        )
        self.registration_by_ip = SlidingWindowThrottle(
            settings.registrations_per_ip_per_hour, 3600
        )


class AuthService:
    """Owns the auth transactions; repositories only flush."""

    def __init__(
        self,
        session: Session,
        users: UserRepository,
        refresh_tokens: RefreshTokenRepository,
        audit_service: AuditService,
        settings: Settings,
        throttles: AuthThrottles,
    ):
        self.session = session
        self.users = users
        self.refresh_tokens = refresh_tokens
        self.audit_service = audit_service
        self.settings = settings
        self.throttles = throttles

    # Public API

    def register(
        self, email: str, password: str, context: AuditContext
    ) -> IssuedTokens:
        """Create an account and log it in."""
        ip_key = self._ip_key(context)
        if self.throttles.registration_by_ip.is_blocked(ip_key):
            raise TooManyRequestsException(
                "Too many registrations from this address. Try again later."
            )
        self.throttles.registration_by_ip.record(ip_key)
        _ensure_password_not_email(email, password)

        user = self.users.create(
            User(email=email, password_hash=hash_password(password))
        )
        tokens = self._issue_tokens(user, family_id=uuid.uuid4())
        self._audit(
            AuditEventType.USER_REGISTERED,
            AuditOutcome.SUCCESS,
            _as_user(context, user.id),
            user.id,
        )
        self.session.commit()
        return tokens

    def login(self, email: str, password: str, context: AuditContext) -> IssuedTokens:
        """Verify credentials and start a new token family.

        Failures are throttled per (email, IP) and, more loosely, per IP, so
        one address can't spray many accounts either.
        """
        ip_key = self._ip_key(context)
        account_key = f"{email}|{ip_key}"
        if self.throttles.login_by_account.is_blocked(
            account_key
        ) or self.throttles.login_by_ip.is_blocked(ip_key):
            raise TooManyRequestsException(
                "Too many failed login attempts. Try again later."
            )

        user = self.users.get_by_email(email)
        if user is None:
            burn_verification_time(password)
        if (
            user is None
            or not user.is_active
            or not verify_password(user.password_hash, password)
        ):
            self.throttles.login_by_account.record(account_key)
            self.throttles.login_by_ip.record(ip_key)
            self._audit(
                AuditEventType.USER_LOGIN_FAILED,
                AuditOutcome.FAILURE,
                context,
                user.id if user else None,
            )
            self.session.commit()
            raise AuthenticationException(_INVALID_CREDENTIALS)

        self.throttles.login_by_account.reset(account_key)
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            self.users.update(user)
        tokens = self._issue_tokens(user, family_id=uuid.uuid4())
        self._audit(
            AuditEventType.USER_LOGIN_SUCCEEDED,
            AuditOutcome.SUCCESS,
            _as_user(context, user.id),
            user.id,
        )
        self.session.commit()
        return tokens

    def refresh(self, raw_token: str | None, context: AuditContext) -> IssuedTokens:
        """Rotate a refresh token: the presented one is spent, a new one issued.

        Presenting an already-spent token means it was copied. The whole
        family is revoked and the request fails.
        """
        stored = self._find_refresh_token(raw_token)
        now = datetime.now(UTC)
        if stored.revoked_at is not None:
            self.refresh_tokens.revoke_family(stored.family_id, now)
            self._audit(
                AuditEventType.REFRESH_TOKEN_REUSE_DETECTED,
                AuditOutcome.FAILURE,
                _as_user(context, stored.user_id),
                stored.user_id,
            )
            self.session.commit()
            logger.warning(
                "Refresh token reuse detected; token family revoked.",
                extra={
                    "context": {
                        "operation": "refresh",
                        "user_id": str(stored.user_id),
                    }
                },
            )
            raise AuthenticationException(_SESSION_EXPIRED)
        if _as_aware(stored.expires_at) <= now:
            raise AuthenticationException(_SESSION_EXPIRED)

        user = self.users.get_by_id(stored.user_id)
        if user is None or not user.is_active:
            raise AuthenticationException(_SESSION_EXPIRED)

        self.refresh_tokens.revoke(stored, now)
        tokens = self._issue_tokens(user, family_id=stored.family_id)
        self.session.commit()
        return tokens

    def logout(self, raw_token: str | None, context: AuditContext) -> None:
        """Revoke the presented token's family. Unknown tokens are ignored."""
        if not raw_token:
            return
        stored = self.refresh_tokens.get_by_hash(hash_refresh_token(raw_token))
        if stored is None:
            return
        self.refresh_tokens.revoke_family(stored.family_id, datetime.now(UTC))
        self._audit(
            AuditEventType.USER_LOGGED_OUT,
            AuditOutcome.SUCCESS,
            _as_user(context, stored.user_id),
            stored.user_id,
        )
        self.session.commit()

    def change_password(
        self, user: User, current: str, new: str, context: AuditContext
    ) -> None:
        """Change the password and sign out every other session."""
        if not verify_password(user.password_hash, current):
            raise ValidationException("Current password is incorrect.")
        if current == new:
            raise ValidationException("New password must differ from the current one.")
        _ensure_password_not_email(user.email, new)
        user.password_hash = hash_password(new)
        self.users.update(user)
        self.refresh_tokens.revoke_all_for_user(user.id, datetime.now(UTC))
        self._audit(
            AuditEventType.USER_PASSWORD_CHANGED, AuditOutcome.SUCCESS, context, user.id
        )
        self.session.commit()

    def authenticate_access_token(self, token: str) -> User:
        """Resolve a bearer token to an active user.

        Raises:
            AuthenticationException: for any invalid token or inactive user.
        """
        try:
            user_id = decode_access_token(
                token, self.settings.jwt_secret_key.get_secret_value()
            )
        except InvalidAccessTokenError as exc:
            raise AuthenticationException() from exc
        user = self.users.get_by_id(user_id)
        if user is None or not user.is_active:
            raise AuthenticationException()
        return user

    # Helpers

    def _issue_tokens(self, user: User, family_id: uuid.UUID) -> IssuedTokens:
        raw_refresh = generate_refresh_token()
        self.refresh_tokens.create(
            RefreshToken(
                user_id=user.id,
                family_id=family_id,
                token_hash=hash_refresh_token(raw_refresh),
                expires_at=datetime.now(UTC)
                + timedelta(days=self.settings.refresh_token_days),
            )
        )
        ttl_minutes = self.settings.access_token_minutes
        return IssuedTokens(
            user=user,
            access_token=create_access_token(
                user.id, self.settings.jwt_secret_key.get_secret_value(), ttl_minutes
            ),
            refresh_token=raw_refresh,
            access_expires_in=ttl_minutes * 60,
        )

    def _find_refresh_token(self, raw_token: str | None) -> RefreshToken:
        if not raw_token:
            raise AuthenticationException(_SESSION_EXPIRED)
        stored = self.refresh_tokens.get_by_hash(hash_refresh_token(raw_token))
        if stored is None:
            raise AuthenticationException(_SESSION_EXPIRED)
        return stored

    def _audit(
        self,
        event_type: AuditEventType,
        outcome: AuditOutcome,
        context: AuditContext,
        user_id: uuid.UUID | None,
    ) -> None:
        self.audit_service.append_event(
            event_type=event_type,
            category=AuditEventCategory.AUTH,
            outcome=outcome,
            context=context,
            resource_type=AuditResourceType.USER if user_id else None,
            resource_id=user_id,
        )

    @staticmethod
    def _ip_key(context: AuditContext) -> str:
        return context.request.source_ip or "unknown"


def _ensure_password_not_email(email: str, password: str) -> None:
    if password.strip().lower() == email:
        raise ValidationException("Password must not be your email address.")


def _as_user(context: AuditContext, user_id: uuid.UUID) -> AuditContext:
    return AuditContext(actor=ActorContext.user(user_id), request=context.request)


def _as_aware(value: datetime) -> datetime:
    """SQLite returns naive datetimes; treat them as UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)
