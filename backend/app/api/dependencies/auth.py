from functools import lru_cache

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.api.dependencies.database import get_db
from app.auth.key_cipher import KeyCipher
from app.core.config import get_settings
from app.core.exceptions import AuthenticationException
from app.models.user import User
from app.repositories.audit_repository import AuditRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_api_key_repository import UserApiKeyRepository
from app.repositories.user_repository import UserRepository
from app.services.api_key_service import ApiKeyService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService, AuthThrottles

_bearer = HTTPBearer(auto_error=False)


@lru_cache
def get_auth_throttles() -> AuthThrottles:
    """One set of throttles per process, shared by every request."""
    return AuthThrottles(get_settings())


def get_auth_service(db: Session = Depends(get_db)) -> AuthService:
    return AuthService(
        session=db,
        users=UserRepository(db),
        refresh_tokens=RefreshTokenRepository(db),
        audit_service=AuditService(AuditRepository(db)),
        settings=get_settings(),
        throttles=get_auth_throttles(),
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Resolve the Bearer access token to the calling user, or 401."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationException()
    return auth_service.authenticate_access_token(credentials.credentials)


def get_api_key_service(db: Session = Depends(get_db)) -> ApiKeyService:
    return ApiKeyService(
        session=db,
        keys=UserApiKeyRepository(db),
        audit_service=AuditService(AuditRepository(db)),
        cipher=KeyCipher(get_settings().app_encryption_key.get_secret_value()),
    )
