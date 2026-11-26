"""Registration, login, token refresh and logout.

The access token is returned in the body and kept in memory by the
frontend. The refresh token travels only in an httpOnly, SameSite=Strict
cookie scoped to this router's path, so page scripts can never read it.
"""

from fastapi import APIRouter, Cookie, Depends, Request, Response, status

from app.api.dependencies.audit import get_anonymous_audit_context
from app.api.dependencies.auth import get_auth_service, get_current_user
from app.api.responses.api_response import SuccessResponse
from app.audit.context import AuditContext
from app.core.config import get_settings
from app.core.exceptions import AuthenticationException
from app.models.user import User
from app.schemas.auth import (
    CredentialsRequest,
    LoginRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth_service import AuthService, IssuedTokens

router = APIRouter()

REFRESH_COOKIE_NAME = "avap_refresh"


def _cookie_path() -> str:
    return f"{get_settings().api_v1_prefix}/auth"


def _token_body(tokens: IssuedTokens, response: Response) -> dict:
    settings = get_settings()
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=tokens.refresh_token,
        max_age=settings.refresh_token_days * 24 * 3600,
        path=_cookie_path(),
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="strict",
    )
    return {
        "data": TokenResponse(
            access_token=tokens.access_token,
            expires_in=tokens.access_expires_in,
            user=UserResponse.model_validate(tokens.user),
        )
    }


def _require_allowed_origin(request: Request) -> None:
    """CSRF defense for the cookie-authenticated endpoints.

    Browsers send Origin on cross-site POSTs, and SameSite=Strict already
    withholds the cookie. This is a second, independent check.
    """
    origin = request.headers.get("origin")
    if origin not in get_settings().cors_allowed_origins_list:
        raise AuthenticationException("Request origin is not allowed.")


@router.post(
    "/register",
    response_model=SuccessResponse[TokenResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create an account and log in",
)
def register(
    body: CredentialsRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
    context: AuditContext = Depends(get_anonymous_audit_context),
) -> dict:
    tokens = service.register(body.email, body.password, context)
    return _token_body(tokens, response)


@router.post(
    "/login",
    response_model=SuccessResponse[TokenResponse],
    summary="Log in with email and password",
)
def login(
    body: LoginRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
    context: AuditContext = Depends(get_anonymous_audit_context),
) -> dict:
    tokens = service.login(body.email, body.password, context)
    return _token_body(tokens, response)


@router.post(
    "/refresh",
    response_model=SuccessResponse[TokenResponse],
    summary="Exchange the refresh cookie for a new access token",
)
def refresh(
    request: Request,
    response: Response,
    avap_refresh: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service),
    context: AuditContext = Depends(get_anonymous_audit_context),
) -> dict:
    _require_allowed_origin(request)
    tokens = service.refresh(avap_refresh, context)
    return _token_body(tokens, response)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="End this session",
)
def logout(
    request: Request,
    response: Response,
    avap_refresh: str | None = Cookie(default=None),
    service: AuthService = Depends(get_auth_service),
    context: AuditContext = Depends(get_anonymous_audit_context),
) -> None:
    _require_allowed_origin(request)
    service.logout(avap_refresh, context)
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=_cookie_path(),
        httponly=True,
        secure=get_settings().refresh_cookie_secure,
        samesite="strict",
    )


@router.get(
    "/me",
    response_model=SuccessResponse[UserResponse],
    summary="The logged-in user",
)
def me(current_user: User = Depends(get_current_user)) -> dict:
    return {"data": UserResponse.model_validate(current_user)}
